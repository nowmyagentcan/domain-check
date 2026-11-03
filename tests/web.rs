mod common;

use common::web::{Hit, Web};
use common::{DnsStub, json};
use serde_json::{Value, json as j};

/// `check <domain> --checks http` against the stub and the web mock, trusting the test root,
/// plus `extra`: the exit code and the report.
fn http(stub: &DnsStub, web: &Web, domain: &str, extra: &[&str]) -> (i32, Value) {
    let dns = stub.addr();
    let args = [domain, "-c", "http", "--dns", &dns, "--ca-file", &web.ca];
    let ports = web.ports(stub);
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let (code, v) = json(&[&args[..], extra].concat(), &env);
    (code, v["reports"][0].clone())
}

fn allowed(stub: &DnsStub, web: &Web, domain: &str) -> (i32, Value) {
    http(stub, web, domain, &["--allow-private"])
}

/// The findings as `code: message`.
fn found(report: &Value) -> Vec<String> {
    let findings = report["findings"].as_array().unwrap();
    let line = |f: &Value| {
        format!(
            "{}: {}",
            f["code"].as_str().unwrap(),
            f["message"].as_str().unwrap()
        )
    };
    findings.iter().map(line).collect()
}

/// Each hop as `status url [-> location]`.
fn hops(chain: &Value) -> Vec<String> {
    let hops = chain["hops"].as_array().unwrap();
    let hop = |h: &Value| match h["location"].as_str() {
        Some(to) => format!("{} {} -> {to}", h["status"], h["url"].as_str().unwrap()),
        None => format!("{} {}", h["status"], h["url"].as_str().unwrap()),
    };
    hops.iter().map(hop).collect()
}

#[test]
fn both_chains_are_followed_to_their_end() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = allowed(&stub, &web, "web.example.com");
    assert_eq!(code, 0, "{r}");
    let h = &r["http"];
    assert_eq!(h["status"], "ok");
    assert_eq!(
        h["http"],
        j!({ "start": "http://web.example.com/", "final": "https://web.example.com/",
             "final_status": 200, "error": null, "hops": [
            { "url": "http://web.example.com/", "status": 301, "location": "https://web.example.com/", "hsts": null },
            { "url": "https://web.example.com/", "status": 200, "location": null, "hsts": "max-age=63072000; includeSubDomains" },
        ]})
    );
    assert_eq!(hops(&h["https"]), ["200 https://web.example.com/"]);
    assert_eq!(found(&r), Vec::<String>::new());
    let hit = |https, path: &str| Hit {
        https,
        host: "web.example.com".into(),
        path: path.into(),
    };
    let mut hits = web.hits();
    hits.sort_by_key(|h| h.https);
    assert_eq!(hits, [hit(false, "/"), hit(true, "/"), hit(true, "/")]);
}

#[test]
fn relative_and_scheme_relative_locations_resolve_against_the_hop() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "relative.example.com");
    assert_eq!(
        hops(&r["http"]["http"]),
        [
            "302 http://relative.example.com/ -> /next",
            "301 http://relative.example.com/next -> https://relative.example.com/",
            "200 https://relative.example.com/",
        ]
    );
    assert_eq!(found(&r), Vec::<String>::new());
    let (_, r) = allowed(&stub, &web, "schemerel.example.com");
    assert_eq!(
        hops(&r["http"]["http"]),
        [
            "301 http://schemerel.example.com/ -> //web.example.com/x",
            "301 http://web.example.com/x -> https://web.example.com/",
            "200 https://web.example.com/",
        ]
    );
    let want = "http_redirect_offhost: http://schemerel.example.com/ redirects to web.example.com before switching to HTTPS; HSTS preloading needs an HTTPS redirect on the same host first.";
    assert_eq!(found(&r), [want]);
}

#[test]
fn loops_and_long_chains_are_stopped() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = allowed(&stub, &web, "circle.example.com");
    assert_eq!(code, 1);
    let (plain, secure) = (&r["http"]["http"], &r["http"]["https"]);
    assert_eq!(
        (&plain["final"], &plain["error"]),
        (&Value::Null, &j!("the redirects loop"))
    );
    assert_eq!(plain["hops"].as_array().unwrap().len(), 3);
    assert_eq!(
        found(&r),
        [
            "redirect_loop: The redirects loop: http://circle.example.com/a → http://circle.example.com/b → http://circle.example.com/a.",
            "redirect_loop: The redirects loop: https://circle.example.com/ → https://circle.example.com/.",
        ]
    );
    assert_eq!(secure["hops"].as_array().unwrap().len(), 1);
    let (code, r) = allowed(&stub, &web, "far.example.com");
    assert_eq!(code, 1);
    for scheme in ["http", "https"] {
        let chain = &r["http"][scheme];
        assert_eq!(chain["hops"].as_array().unwrap().len(), 11);
        assert_eq!(chain["error"], "more than 10 redirects");
    }
    assert_eq!(
        found(&r),
        [
            "redirect_too_many: More than 10 redirects from http://far.example.com/.",
            "redirect_too_many: More than 10 redirects from https://far.example.com/.",
        ]
    );
    let far = web
        .hits()
        .into_iter()
        .filter(|h| h.host == "far.example.com");
    assert_eq!(far.count(), 22);
}

#[test]
fn bodies_are_never_read() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let started = std::time::Instant::now();
    let (code, r) = allowed(&stub, &web, "endless.example.com");
    assert!(started.elapsed().as_secs() < 8, "{:?}", started.elapsed());
    assert_eq!(code, 0);
    assert_eq!(r["http"]["https"]["final_status"], 200);
}

#[test]
fn what_the_chains_end_with_is_reported() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "status.example.com");
    assert_eq!(
        found(&r),
        [
            "http_no_https_redirect: http://status.example.com/ doesn't redirect to HTTPS (it answers 200).",
            "https_status: https://status.example.com/ ends with HTTP 404 after 1 redirect.",
        ]
    );
    let (_, r) = allowed(&stub, &web, "closed.example.com");
    assert_eq!(
        found(&r),
        [
            "https_failed: Couldn't load https://closed.example.com/: connection refused.",
            "http_unavailable: Nothing answers on port 80 (connection refused)."
        ]
    );
    assert_eq!(r["http"]["https"]["error"], "connection refused");
    let (_, r) = allowed(&stub, &web, "garbage.example.com");
    let want = "https_failed: Couldn't load https://garbage.example.com/: the answer isn't HTTP.";
    assert!(found(&r).contains(&want.to_string()), "{:?}", found(&r));
    // With the tls check the first connection is its finding, not a second one here.
    let both = ["--allow-private", "-c", "tls"];
    let (_, r) = http(&stub, &web, "selfsigned.example.com", &both);
    assert_eq!(
        r["http"]["https"]["error"],
        "Certificate not trusted; see Certificate."
    );
    let http_found: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["check"] == "http")
        .collect();
    let want = "doesn't redirect to HTTPS (it answers 200).";
    assert!(
        http_found.len() == 1 && http_found[0]["message"].as_str().unwrap().ends_with(want),
        "{http_found:?}"
    );
    let (_, r) = http(&stub, &web, "closed.example.com", &both);
    assert!(
        !found(&r).iter().any(|f| f.starts_with("https_failed")),
        "{:?}",
        found(&r)
    );
}

#[test]
fn private_addresses_and_proxies_change_nothing_they_shouldnt() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = http(&stub, &web, "web.example.com", &[]);
    assert_eq!(code, 0);
    assert_eq!(r["http"]["status"], "skipped");
    assert_eq!(
        r["http"]["reason"],
        "web.example.com resolves to 127.0.0.1, a private address."
    );
    let want = "private_address: web.example.com resolves to 127.0.0.1, a private address, so the http check didn't connect to it.";
    assert_eq!(found(&r), [want]);
    assert_eq!(web.connections(), 0);
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let args = [
        "web.example.com",
        "-c",
        "http",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let dead = "http://127.0.0.1:9";
    let env = [
        ("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str()),
        ("HTTPS_PROXY", dead),
        ("HTTP_PROXY", dead),
        ("ALL_PROXY", dead),
        ("https_proxy", dead),
    ];
    let (code, v) = json(&args, &env);
    assert_eq!(code, 0);
    assert_eq!(v["reports"][0]["http"]["http"]["final_status"], 200);
}

#[test]
fn only_ports_53_80_and_443_are_used() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let args = [
        "web.example.com",
        "--dns",
        &dns,
        "--resolver",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
        "--debug",
        "--json",
    ];
    let (_, _, err) = common::run(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", &ports)]);
    let used: std::collections::BTreeSet<u16> = err
        .split_whitespace()
        .filter_map(|w| w.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.port())
        .collect();
    let want = std::collections::BTreeSet::from([stub.port, web.http, web.https]);
    assert_eq!(used, want, "{err}");
    assert!(
        err.contains("debug: http GET http://web.example.com/ 301 "),
        "{err}"
    );
    assert!(err.contains("debug: tls connect 127.0.0.1:"), "{err}");
}

#[test]
fn the_text_report_shows_the_chains() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let args = [
        "relative.example.com",
        "-c",
        "http",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let (code, out, err) = common::run(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", &ports)]);
    assert_eq!((code, err.as_str()), (0, ""));
    let line = out.lines().find(|l| l.starts_with("Web")).unwrap();
    assert_eq!(
        line,
        "Web          http → 302 /next → 301 https://relative.example.com/ → 200 · HSTS yes · CSP yes"
    );
}

#[test]
fn headers_of_the_last_https_answer_are_graded() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "web.example.com");
    let headers = &r["http"]["headers"];
    assert_eq!(
        headers["strict-transport-security"],
        "max-age=63072000; includeSubDomains"
    );
    assert_eq!(
        (&headers["server"], &headers["x-aspnetmvc-version"]),
        (&Value::Null, &Value::Null)
    );
    assert_eq!(headers.as_object().unwrap().len(), 16);
    let (code, r) = allowed(&stub, &web, "headers.example.com");
    assert_eq!(code, 0);
    let mut found = found(&r);
    found.retain(|f| !f.starts_with("http_no_https_redirect"));
    assert_eq!(
        found,
        [
            "frame_protection_missing: Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page.",
            "hsts_short: HSTS max-age is 300 s; at least 15552000 (180 days) is recommended.",
            "xcto_missing: No \"X-Content-Type-Options: nosniff\" header.",
            "coop_missing: No Cross-Origin-Opener-Policy header.",
            "csp_unsafe: The Content-Security-Policy allows 'unsafe-inline' scripts.",
            "deprecated_header: X-XSS-Protection is obsolete; browsers ignore it.",
            "deprecated_header: Expect-CT is obsolete; browsers ignore it.",
            "permissions_policy_missing: No Permissions-Policy header.",
            "referrer_policy_missing: No Referrer-Policy header.",
            "version_leak: The Server header reveals software details (nginx/1.25.3).",
            "version_leak: The X-Powered-By header reveals software details (PHP/8.3).",
        ]
    );
    let (_, r) = allowed(&stub, &web, "bare.example.com");
    let codes: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(
        codes.contains(&"hsts_missing") && codes.contains(&"csp_missing"),
        "{codes:?}"
    );
    // An https chain that fails or ends on http has nothing to grade.
    let (_, r) = allowed(&stub, &web, "selfsigned.example.com");
    assert_eq!(r["http"]["headers"], Value::Null);
}

#[test]
fn https_that_fails_is_a_finding_without_the_tls_check() {
    let (stub, web) = (DnsStub::new(), Web::new());
    for domain in [
        "selfsigned.example.com",
        "expired.example.com",
        "wrongname.example.com",
        "closed.example.com",
    ] {
        let (_, r) = allowed(&stub, &web, domain);
        let error = r["http"]["https"]["error"].as_str().unwrap();
        assert!(!error.contains("see Certificate"), "{error}");
        // tls isn't requested, so only http can tell the user that https doesn't load or
        // isn't served at all.
        let findings = r["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["check"] == "http"
                && f["severity"] != "info"
                && f["message"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("https://{domain}"))),
            "{domain}: {:?}",
            found(&r)
        );
    }
}

#[test]
fn a_repeated_hsts_directive_is_invalid() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "hstsdup.example.com");
    // RFC 6797 §6.1: each directive appears once; browsers ignore a header that breaks this.
    let codes = found(&r);
    assert!(
        codes.iter().any(|c| c.starts_with("hsts_invalid")),
        "{codes:?}"
    );
}

/// The http findings that aren't info.
fn http_problems(report: &Value) -> Vec<String> {
    let findings = report["findings"].as_array().unwrap();
    let problem = |f: &&Value| f["check"] == "http" && f["severity"] != "info";
    findings
        .iter()
        .filter(problem)
        .map(|f| f.to_string())
        .collect()
}

#[test]
#[ignore = "known bug: DC18"]
fn a_redirect_that_fails_after_the_first_hop_is_a_finding() {
    let (stub, web) = (DnsStub::new(), Web::new());
    // http:// sends visitors to a host whose certificate isn't trusted; https:// itself loads.
    for extra in [&["--allow-private"][..], &["--allow-private", "-c", "tls"]] {
        let (_, r) = http(&stub, &web, "offhost.example.com", extra);
        assert_eq!(r["http"]["https"]["final_status"], 200);
        assert!(r["http"]["http"]["error"].is_string(), "{}", r["http"]);
        assert!(!http_problems(&r).is_empty(), "{extra:?}: {:?}", found(&r));
    }
}

#[test]
#[ignore = "known bug: DC23"]
fn an_https_chain_that_ends_on_http_is_a_finding() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "downgrade.example.com");
    assert_eq!(
        r["http"]["https"]["final"],
        "http://downgrade.example.com/plain"
    );
    assert!(!http_problems(&r).is_empty(), "{:?}", found(&r));
}

#[test]
#[ignore = "known bug: DC21"]
fn csp_directives_separated_by_tabs_are_read() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "tabcsp.example.com");
    // CSP3 §2.2.1: a directive's name and value are split on ASCII whitespace, tab included.
    let codes = found(&r);
    assert!(
        codes.iter().any(|c| c.starts_with("csp_unsafe"))
            && !codes
                .iter()
                .any(|c| c.starts_with("frame_protection_missing")),
        "{codes:?}"
    );
}

#[test]
#[ignore = "known bug: DC22"]
fn an_x_frame_options_value_browsers_ignore_protects_nothing() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "badframe.example.com");
    // RFC 7034 §2.1: DENY or SAMEORIGIN; browsers ignore ALLOWALL and frame the page.
    let codes = found(&r);
    assert!(
        codes
            .iter()
            .any(|c| c.starts_with("frame_protection_missing")),
        "{codes:?}"
    );
}

#[test]
fn addresses_that_fail_to_resolve_make_the_web_checks_unavailable() {
    let (stub, web) = (DnsStub::new(), Web::new());
    for (domain, rcode) in [
        ("servfail.example.com", "SERVFAIL"),
        ("refused.example.com", "REFUSED"),
    ] {
        let (code, r) = http(&stub, &web, domain, &["--allow-private", "-c", "tls"]);
        for check in ["tls", "http"] {
            // A failed lookup says nothing about whether the domain has an address.
            assert_eq!(r[check]["status"], "unavailable", "{domain}: {}", r[check]);
            let reason = r[check]["reason"].as_str().unwrap();
            assert!(reason.contains(rcode), "{reason}");
        }
        assert_eq!(code, 3, "{domain}");
    }
}

#[test]
#[ignore = "known bug: DC31"]
fn unsafe_inline_beside_a_nonce_allows_no_inline_script() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "cspnonce.example.com");
    // CSP3 §6.7.3.3: browsers ignore 'unsafe-inline' in a list that holds a nonce or a hash.
    let codes = found(&r);
    assert!(
        !codes.iter().any(|c| c.starts_with("csp_unsafe")),
        "{codes:?}"
    );
}

#[test]
#[ignore = "known bug: DC33"]
fn hsts_max_age_is_read_as_rfc_6797_writes_it() {
    let (stub, web) = (DnsStub::new(), Web::new());
    // §6.1: whitespace may surround "=", and max-age is digits only.
    let (_, r) = allowed(&stub, &web, "tabhsts.example.com");
    let codes = found(&r);
    assert!(!codes.iter().any(|c| c.starts_with("hsts_")), "{codes:?}");
    let (_, r) = allowed(&stub, &web, "signedhsts.example.com");
    let codes = found(&r);
    assert!(
        codes.iter().any(|c| c.starts_with("hsts_invalid")),
        "{codes:?}"
    );
}

#[test]
#[ignore = "known bug: DC35"]
fn headers_sent_twice_are_graded_as_browsers_read_them() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "twiceheaders.example.com");
    // Fetch reads the first X-Content-Type-Options value, each CSP header is a policy of its
    // own, and RFC 6797 §8.1 keeps the first Strict-Transport-Security.
    assert_eq!(http_problems(&r), Vec::<String>::new());
}
