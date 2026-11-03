//! The `http` section: the redirect chains from `http://<domain>/` and `https://<domain>/`,
//! followed by hand one GET at a time. Only headers are read, never a body.

use std::time::Instant;

use serde::Serialize;
use url::Url;

use crate::check::{Cx, Facts};
use crate::net::{Failed, Net};
use crate::report::{Check, Finding, Keyed, Section, Severity, Status};
use crate::sections::tls::private;

/// Redirects followed before a chain is given up.
const MAX_REDIRECTS: usize = 10;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Web {
    pub http: Chain,
    pub https: Chain,
    /// The graded headers of the https chain's last response, when it ended on https.
    pub headers: Option<Keyed<Option<String>>>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Chain {
    pub start: String,
    pub hops: Vec<Hop>,
    /// The URL that answered without redirecting; `None` when the chain broke off.
    #[serde(rename = "final")]
    pub end: Option<String>,
    pub final_status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Hop {
    pub url: String,
    pub status: u16,
    pub location: Option<String>,
    /// `Strict-Transport-Security` as sent over https; over http it means nothing (RFC 6797
    /// §8.1).
    pub hsts: Option<String>,
}

/// How a chain ended, beyond what [`Chain`] shows.
enum End {
    Done(Keyed<Option<String>>),
    Failed(Failed),
    /// The URLs from the first visit of the repeated one, and it again.
    Loop(Vec<String>),
    TooMany,
}

fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Http, severity, code, message, hint)
}

/// The chain from `start`, one hop per GET; `tls` when the tls check reports the first
/// connection's certificate.
fn follow(net: &Net, start: &str, until: Instant, tls: bool) -> (Chain, End) {
    let mut chain = Chain {
        start: start.to_string(),
        ..Chain::default()
    };
    let Ok(mut url) = Url::parse(start) else {
        return (chain, End::Done(Keyed::default()));
    };
    loop {
        let response = match net.get(url.as_str(), until) {
            Ok(r) => r,
            Err(f) => {
                chain.error = Some(match (&f, chain.hops.is_empty()) {
                    (Failed::Certificate(_), true) if tls => {
                        "Certificate not trusted; see Certificate.".into()
                    }
                    (Failed::Certificate(_), _) => format!(
                        "the certificate of {} isn't trusted",
                        url.host_str().unwrap_or_default()
                    ),
                    _ => f.to_string(),
                });
                return (chain, End::Failed(f));
            }
        };
        let status = response.status().as_u16();
        let header = |name| {
            let value = response.headers().get(name)?;
            Some(String::from_utf8_lossy(value.as_bytes()).into_owned())
        };
        let location = header("location");
        let hsts = header("strict-transport-security").filter(|_| url.scheme() == "https");
        chain.hops.push(Hop {
            url: url.to_string(),
            status,
            location: location.clone(),
            hsts,
        });
        let next = location
            .filter(|_| matches!(status, 301 | 302 | 303 | 307 | 308))
            .and_then(|l| url.join(&l).ok())
            .filter(|n| matches!(n.scheme(), "http" | "https"));
        let Some(next) = next else {
            chain.end = Some(url.to_string());
            chain.final_status = Some(status);
            return (chain, End::Done(graded(response.headers())));
        };
        if let Some(i) = chain.hops.iter().position(|h| h.url == next.as_str()) {
            let mut urls: Vec<_> = chain.hops[i..].iter().map(|h| h.url.clone()).collect();
            urls.push(next.to_string());
            chain.error = Some("the redirects loop".into());
            return (chain, End::Loop(urls));
        }
        if chain.hops.len() > MAX_REDIRECTS {
            chain.error = Some(format!("more than {MAX_REDIRECTS} redirects"));
            return (chain, End::TooMany);
        }
        url = next;
    }
}

/// The headers graded, as browsers and the OWASP Secure Headers Project name them.
const HEADERS: [&str; 16] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "X-XSS-Protection",
    "Expect-CT",
    "Public-Key-Pins",
    "Feature-Policy",
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
];

/// Each graded header's value as sent (repeated ones joined with `, `), keyed in lower case.
fn graded(sent: &ureq::http::HeaderMap) -> Keyed<Option<String>> {
    let value = |name: &str| {
        let values = sent.get_all(name).iter();
        let values: Vec<_> = values
            .map(|v| String::from_utf8_lossy(v.as_bytes()))
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    };
    Keyed(
        HEADERS
            .iter()
            .map(|h| (h.to_ascii_lowercase(), value(h)))
            .collect(),
    )
}

/// The directive `name` of a policy like `default-src 'self'; frame-ancestors 'none'`.
fn directive<'a>(policy: &'a str, name: &str) -> Option<&'a str> {
    policy.split(';').map(str::trim).find_map(|d| {
        let (key, rest) = d.split_once(' ').unwrap_or((d, ""));
        key.eq_ignore_ascii_case(name).then_some(rest)
    })
}

/// The header rules (spec §8.7), from the OWASP Secure Headers Project's recommendations.
fn grade(h: &Keyed<Option<String>>) -> Vec<Finding> {
    let get = |name: &str| h.get(&name.to_ascii_lowercase()).cloned().flatten();
    let mut found = Vec::new();
    let mut add = |severity, code, message: String, hint: &str| {
        found.push(finding(severity, code, message, hint));
    };
    use Severity::{Info, Warning};
    match get("Strict-Transport-Security") {
        None => add(
            Warning,
            "hsts_missing",
            "No Strict-Transport-Security header.".into(),
            "Add \"Strict-Transport-Security: max-age=63072000; includeSubDomains\".",
        ),
        Some(v) => {
            let spaced = v.replace('=', " ");
            let age = directive(&spaced, "max-age");
            let names: Vec<_> = spaced
                .split(';')
                .filter_map(|d| d.split_whitespace().next())
                .collect();
            // RFC 6797 §6.1, §8.1: each directive appears once, or browsers ignore the header.
            let twice = (1..names.len())
                .find(|&i| names[..i].iter().any(|n| n.eq_ignore_ascii_case(names[i])));
            let age = age.and_then(|a| a.trim().trim_matches('"').parse::<u64>().ok());
            match (twice.map(|i| names[i]), age) {
                (Some(name), _) => add(
                    Warning,
                    "hsts_invalid",
                    format!(
                        "The Strict-Transport-Security header has {name} twice, so browsers ignore it."
                    ),
                    "",
                ),
                (None, None) => add(
                    Warning,
                    "hsts_invalid",
                    "The Strict-Transport-Security header has no valid max-age.".into(),
                    "",
                ),
                (None, Some(n)) if n < 15_552_000 => add(
                    Warning,
                    "hsts_short",
                    format!("HSTS max-age is {n} s; at least 15552000 (180 days) is recommended."),
                    "Use max-age=63072000 (2 years).",
                ),
                _ => {}
            }
        }
    }
    let csp = get("Content-Security-Policy");
    match &csp {
        None => add(
            Warning,
            "csp_missing",
            "No Content-Security-Policy header.".into(),
            "Start with \"default-src 'self'; object-src 'none'; frame-ancestors 'none'\" and adjust.",
        ),
        Some(policy) => {
            let scripts = directive(policy, "script-src").or(directive(policy, "default-src"));
            let unsafe_: Vec<_> = ["'unsafe-inline'", "'unsafe-eval'"]
                .into_iter()
                .filter(|u| scripts.is_some_and(|s| s.to_ascii_lowercase().contains(u)))
                .collect();
            if !unsafe_.is_empty() {
                let message = format!(
                    "The Content-Security-Policy allows {} scripts.",
                    unsafe_.join(" and ")
                );
                add(Info, "csp_unsafe", message, "");
            }
        }
    }
    if !get("X-Content-Type-Options").is_some_and(|v| v.trim().eq_ignore_ascii_case("nosniff")) {
        let message = "No \"X-Content-Type-Options: nosniff\" header.".into();
        add(Warning, "xcto_missing", message, "Add it.");
    }
    let ancestors = csp.as_deref().and_then(|p| directive(p, "frame-ancestors"));
    if get("X-Frame-Options").is_none() && ancestors.is_none() {
        add(
            Warning,
            "frame_protection_missing",
            "Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page.".into(),
            "Add \"Content-Security-Policy: frame-ancestors 'self'\" or \"X-Frame-Options: DENY\".",
        );
    }
    let missing = [
        (
            "Referrer-Policy",
            "referrer_policy_missing",
            "Add \"Referrer-Policy: strict-origin-when-cross-origin\" or stricter.",
        ),
        ("Permissions-Policy", "permissions_policy_missing", ""),
        (
            "Cross-Origin-Opener-Policy",
            "coop_missing",
            "Add \"Cross-Origin-Opener-Policy: same-origin\" if the site doesn't need cross-origin popups.",
        ),
    ];
    for (name, code, hint) in missing {
        if get(name).is_none() {
            add(Info, code, format!("No {name} header."), hint);
        }
    }
    for name in [
        "X-XSS-Protection",
        "Expect-CT",
        "Public-Key-Pins",
        "Feature-Policy",
    ] {
        let obsolete = get(name).filter(|v| name != "X-XSS-Protection" || v.trim() != "0");
        if obsolete.is_some() {
            let message = format!("{name} is obsolete; browsers ignore it.");
            add(Info, "deprecated_header", message, "Remove it.");
        }
    }
    for name in [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    ] {
        let leak = get(name).filter(|v| name != "Server" || v.bytes().any(|b| b.is_ascii_digit()));
        if let Some(value) = leak {
            let message = format!("The {name} header reveals software details ({value}).");
            add(Info, "version_leak", message, "Remove or shorten it.");
        }
    }
    found
}

pub fn run(cx: &Cx, facts: &Facts) -> (Section<Web>, Vec<Finding>) {
    let d = cx.domain.as_str();
    let ips = match facts.web_addresses(d) {
        Ok(ips) => ips,
        Err((status, why)) => return (Section::not(status, why), Vec::new()),
    };
    if !ips.iter().any(|&ip| cx.net.allowed(ip)) {
        let why = format!("{d} resolves to {}, a private address.", ips[0]);
        let found = vec![private(Check::Http, d, ips[0])];
        return (Section::not(Status::Skipped, why), found);
    }
    let until = cx.until(Check::Http);
    let net = &cx.net;
    let ((http, http_end), (https, https_end)) = std::thread::scope(|s| {
        let plain = s.spawn(|| follow(net, &format!("http://{d}/"), until, cx.tls));
        let secure = follow(net, &format!("https://{d}/"), until, cx.tls);
        let plain = plain
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        (plain, secure)
    });
    let mut found = Vec::new();
    for (chain, end) in [(&http, &http_end), (&https, &https_end)] {
        match end {
            End::Loop(urls) => {
                let message = format!("The redirects loop: {}.", urls.join(" → "));
                let hint = "Fix the redirect rules on the server.";
                found.push(finding(Severity::Error, "redirect_loop", message, hint));
            }
            End::TooMany => {
                let message = format!("More than {MAX_REDIRECTS} redirects from {}.", chain.start);
                found.push(finding(
                    Severity::Error,
                    "redirect_too_many",
                    message,
                    "Shorten the redirect chain.",
                ));
            }
            End::Failed(Failed::Private { host, address }) => {
                found.push(private(Check::Http, host, *address));
            }
            _ => {}
        }
    }
    match &http_end {
        End::Failed(f) if http.hops.is_empty() => {
            let message = format!("Nothing answers on port 80 ({f}).");
            found.push(finding(Severity::Info, "http_unavailable", message, ""));
        }
        End::Done(_) if http.end.as_deref().is_some_and(|u| u.starts_with("http:")) => {
            let message = format!(
                "http://{d}/ doesn't redirect to HTTPS (it answers {}).",
                http.final_status.unwrap_or_default()
            );
            let hint = "Redirect every HTTP request to https://.";
            found.push(finding(
                Severity::Warning,
                "http_no_https_redirect",
                message,
                hint,
            ));
        }
        _ => {}
    }
    let first = http.hops.first().and_then(|h| h.location.as_deref());
    let first = first.and_then(|l| Url::parse(&http.start).ok()?.join(l).ok());
    let reaches_https = http.hops.iter().any(|h| h.url.starts_with("https:"));
    if let Some(host) = first.as_ref().and_then(Url::host_str)
        && host != d
        && reaches_https
    {
        let message = format!(
            "http://{d}/ redirects to {host} before switching to HTTPS; HSTS preloading needs an HTTPS redirect on the same host first."
        );
        found.push(finding(
            Severity::Info,
            "http_redirect_offhost",
            message,
            "",
        ));
    }
    if let End::Failed(f) = &https_end {
        // The first connection is the certificate check's to report, when it runs.
        let first_hop = https.hops.is_empty() && cx.tls;
        let theirs = matches!(
            f,
            Failed::Connect(_) | Failed::Certificate(_) | Failed::Tls(_)
        );
        if !(first_hop && theirs) && !matches!(f, Failed::Private { .. }) {
            let why = https.error.as_deref().unwrap_or_default();
            let message = format!("Couldn't load https://{d}/: {why}.");
            found.push(finding(Severity::Warning, "https_failed", message, ""));
        }
    }
    if let Some(status @ 400..) = https.final_status {
        let n = https.hops.len() - 1;
        let message = format!(
            "https://{d}/ ends with HTTP {status} after {n} redirect{}.",
            if n == 1 { "" } else { "s" }
        );
        found.push(finding(Severity::Info, "https_status", message, ""));
    }
    let headers = match https_end {
        End::Done(h)
            if https
                .end
                .as_deref()
                .is_some_and(|u| u.starts_with("https:")) =>
        {
            found.extend(grade(&h));
            Some(h)
        }
        _ => None,
    };
    let web = Web {
        http,
        https,
        headers,
    };
    (Section::ok(web), found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(sent: &[(&'static str, &str)]) -> Vec<String> {
        let mut map = ureq::http::HeaderMap::new();
        for (name, value) in sent {
            map.append(*name, value.parse().unwrap());
        }
        let found = grade(&graded(&map));
        found
            .iter()
            .map(|f| format!("{} {}", f.code, f.message))
            .collect()
    }

    const GOOD: [(&str, &str); 6] = [
        (
            "strict-transport-security",
            "max-age=63072000; includeSubDomains",
        ),
        (
            "content-security-policy",
            "default-src 'self'; frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("permissions-policy", "camera=()"),
        ("cross-origin-opener-policy", "same-origin"),
    ];

    fn with(extra: &[(&'static str, &'static str)], drop: &str) -> Vec<String> {
        let sent: Vec<_> = GOOD
            .iter()
            .filter(|(n, _)| *n != drop)
            .chain(extra)
            .copied()
            .collect();
        codes(&sent)
    }

    #[test]
    fn good_headers_pass() {
        assert_eq!(codes(&GOOD), Vec::<String>::new());
        assert_eq!(
            with(&[("server", "nginx"), ("x-xss-protection", "0")], ""),
            Vec::<String>::new()
        );
    }

    #[test]
    fn hsts_needs_a_long_valid_max_age() {
        let hsts = |v: &'static str| {
            with(
                &[("strict-transport-security", v)],
                "strict-transport-security",
            )
        };
        assert_eq!(hsts("max-age=\"31536000\""), Vec::<String>::new());
        assert_eq!(
            hsts("MAX-AGE = 300"),
            ["hsts_short HSTS max-age is 300 s; at least 15552000 (180 days) is recommended."]
        );
        assert_eq!(
            hsts("includeSubDomains"),
            ["hsts_invalid The Strict-Transport-Security header has no valid max-age."]
        );
        assert_eq!(
            hsts("max-age=soon"),
            ["hsts_invalid The Strict-Transport-Security header has no valid max-age."]
        );
        assert_eq!(
            with(&[], "strict-transport-security"),
            ["hsts_missing No Strict-Transport-Security header."]
        );
    }

    #[test]
    fn csp_and_framing() {
        let csp =
            |v: &'static str| with(&[("content-security-policy", v)], "content-security-policy");
        assert_eq!(
            csp("default-src 'self' 'unsafe-inline'; frame-ancestors 'self'"),
            ["csp_unsafe The Content-Security-Policy allows 'unsafe-inline' scripts."]
        );
        assert_eq!(
            csp(
                "script-src 'unsafe-eval' 'UNSAFE-INLINE'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            ),
            [
                "csp_unsafe The Content-Security-Policy allows 'unsafe-inline' and 'unsafe-eval' scripts."
            ]
        );
        // script-src replaces default-src for scripts.
        assert_eq!(
            csp("default-src 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"),
            Vec::<String>::new()
        );
        let frame = "frame_protection_missing Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page.";
        assert_eq!(csp("default-src 'self'"), [frame]);
        assert_eq!(
            with(&[("x-frame-options", "DENY")], "content-security-policy"),
            ["csp_missing No Content-Security-Policy header."]
        );
        assert_eq!(
            with(&[], "content-security-policy"),
            ["csp_missing No Content-Security-Policy header.", frame]
        );
    }

    #[test]
    fn missing_obsolete_and_revealing_headers() {
        assert_eq!(codes(&[("x-content-type-options", "sniff")]).len(), 7);
        let none = codes(&[]);
        let names: Vec<_> = none.iter().map(|f| f.split(' ').next().unwrap()).collect();
        assert_eq!(
            names,
            [
                "hsts_missing",
                "csp_missing",
                "xcto_missing",
                "frame_protection_missing",
                "referrer_policy_missing",
                "permissions_policy_missing",
                "coop_missing"
            ]
        );
        assert!(
            none.contains(&"xcto_missing No \"X-Content-Type-Options: nosniff\" header.".into())
        );
        assert!(none.contains(&"coop_missing No Cross-Origin-Opener-Policy header.".into()));
        let extra = [
            ("x-xss-protection", "1; mode=block"),
            ("expect-ct", "max-age=0"),
            ("public-key-pins", "pin-sha256=\"x\""),
            ("feature-policy", "camera 'none'"),
            ("server", "nginx/1.25.3"),
            ("x-powered-by", "PHP/8.3"),
            ("x-aspnet-version", "4.0.30319"),
            ("x-aspnetmvc-version", "5.2"),
        ];
        assert_eq!(
            with(&extra, ""),
            [
                "deprecated_header X-XSS-Protection is obsolete; browsers ignore it.",
                "deprecated_header Expect-CT is obsolete; browsers ignore it.",
                "deprecated_header Public-Key-Pins is obsolete; browsers ignore it.",
                "deprecated_header Feature-Policy is obsolete; browsers ignore it.",
                "version_leak The Server header reveals software details (nginx/1.25.3).",
                "version_leak The X-Powered-By header reveals software details (PHP/8.3).",
                "version_leak The X-AspNet-Version header reveals software details (4.0.30319).",
                "version_leak The X-AspNetMvc-Version header reveals software details (5.2).",
            ]
        );
        let twice = [("server", "a"), ("server", "b")];
        let mut map = ureq::http::HeaderMap::new();
        for (name, value) in twice {
            map.append(name, value.parse().unwrap());
        }
        assert_eq!(graded(&map).get("server"), Some(&Some("a, b".to_string())));
    }
}
