//! The `http` section: the redirect chains from `http://<domain>/` and `https://<domain>/`,
//! followed by hand one GET at a time. Only headers are read, never a body.

use std::time::Instant;

use serde::Serialize;
use url::Url;

use crate::check::{Cx, Facts};
use crate::net::{Failed, Net};
use crate::report::{Check, Finding, Section, Severity, Status};
use crate::sections::tls::private;

/// Redirects followed before a chain is given up.
const MAX_REDIRECTS: usize = 10;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Web {
    pub http: Chain,
    pub https: Chain,
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
    Done,
    Failed(Failed),
    /// The URLs from the first visit of the repeated one, and it again.
    Loop(Vec<String>),
    TooMany,
}

fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Http, severity, code, message, hint)
}

/// The chain from `start`, one hop per GET.
fn follow(net: &Net, start: &str, until: Instant) -> (Chain, End) {
    let mut chain = Chain {
        start: start.to_string(),
        ..Chain::default()
    };
    let Ok(mut url) = Url::parse(start) else {
        return (chain, End::Done);
    };
    loop {
        let response = match net.get(url.as_str(), until) {
            Ok(r) => r,
            Err(f) => {
                chain.error = Some(match (&f, chain.hops.is_empty()) {
                    (Failed::Certificate(_), true) => {
                        "Certificate not trusted; see Certificate.".into()
                    }
                    (Failed::Certificate(_), false) => format!(
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
            return (chain, End::Done);
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
        let plain = s.spawn(|| follow(net, &format!("http://{d}/"), until));
        let secure = follow(net, &format!("https://{d}/"), until);
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
        End::Done if http.end.as_deref().is_some_and(|u| u.starts_with("http:")) => {
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
        // The first connection is the certificate check's to report.
        let first_hop = https.hops.is_empty();
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
    (Section::ok(Web { http, https }), found)
}
