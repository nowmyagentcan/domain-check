mod common;

use common::web::Web;
use common::{DnsStub, json};
use serde_json::{Value, json as j};

/// `check <domain> --checks tls` against the stub and the web mock, trusting the test root
/// and allowing loopback, plus `extra`: the exit code and the report.
fn tls(stub: &DnsStub, web: &Web, domain: &str, extra: &[&str]) -> (i32, Value) {
    let dns = stub.addr();
    let args = [domain, "-c", "tls", "--dns", &dns, "--ca-file", &web.ca];
    let ports = web.ports(stub);
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let (code, v) = json(&[&args[..], extra].concat(), &env);
    (code, v["reports"][0].clone())
}

fn allowed(stub: &DnsStub, web: &Web, domain: &str) -> (i32, Value) {
    tls(stub, web, domain, &["--allow-private"])
}

/// The findings: code, severity, message.
fn found(report: &Value) -> Vec<(String, String, String)> {
    let findings = report["findings"].as_array().unwrap();
    let text = |f: &Value, k: &str| f[k].as_str().unwrap().to_string();
    let found = findings
        .iter()
        .map(|f| (text(f, "code"), text(f, "severity"), text(f, "message")));
    found.collect()
}

fn one(code: &str, severity: &str, message: &str) -> Vec<(String, String, String)> {
    vec![(code.into(), severity.into(), message.into())]
}

#[test]
fn the_handshake_reports_the_chain_and_what_was_negotiated() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = allowed(&stub, &web, "tls.example.com");
    assert_eq!(code, 0, "{r}");
    let t = &r["tls"];
    assert_eq!(t["status"], "ok");
    assert_eq!((&t["address"], &t["port"]), (&j!("127.0.0.1"), &j!(443)));
    assert_eq!(
        (&t["protocol"], &t["alpn"]),
        (&j!("TLSv1.3"), &j!("http/1.1"))
    );
    assert!(t["cipher"].as_str().unwrap().starts_with("TLS13_"), "{t}");
    let chain = t["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 2);
    let leaf = &chain[0];
    assert_eq!(leaf["subject"], "CN=tls.example.com");
    assert_eq!(leaf["issuer"], "CN=Test Intermediate");
    assert_eq!(leaf["sans"], j!(["tls.example.com"]));
    assert_eq!(
        (&leaf["key"], &leaf["signature"]),
        (&j!("EC P-256"), &j!("ecdsa-with-SHA256"))
    );
    assert_eq!(
        (&leaf["self_signed"], &leaf["ca"]),
        (&j!(false), &j!(false))
    );
    let serial = leaf["serial"].as_str().unwrap();
    assert!(
        serial
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "{serial}"
    );
    for at in ["not_before", "not_after"] {
        let t = leaf[at].as_str().unwrap();
        assert!(t.len() == 20 && t.ends_with('Z'), "{t}");
    }
    let inter = &chain[1];
    assert_eq!(
        (&inter["subject"], &inter["issuer"]),
        (&j!("CN=Test Intermediate"), &j!("CN=Test Root"))
    );
    assert_eq!((&inter["ca"], &inter["sans"]), (&j!(true), &j!([])));
    let verdict = [
        "trusted",
        "trust_error",
        "trust_detail",
        "names_match",
        "lifetime_days",
    ];
    let verdict = verdict.map(|k| &t[k]);
    assert_eq!(
        verdict,
        [&j!(true), &j!(null), &j!(null), &j!(true), &j!(90)]
    );
    assert_eq!(
        (&t["not_before"], &t["not_after"]),
        (&leaf["not_before"], &leaf["not_after"])
    );
    let days = t["days_left"].as_i64().unwrap();
    assert!((88..=89).contains(&days), "{days}");
    assert_eq!(r["findings"], j!([]));
    // The handshake sends no request.
    assert_eq!((web.connections(), web.hits()), (1, Vec::new()));
}

#[test]
fn old_and_broken_servers_are_told_apart() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = allowed(&stub, &web, "tls12.example.com");
    assert_eq!((code, &r["tls"]["protocol"]), (0, &j!("TLSv1.2")));
    let want = "The server negotiated TLS 1.2; TLS 1.3 is preferred.";
    assert_eq!(found(&r), one("tls_12", "info", want));
    let (code, r) = allowed(&stub, &web, "old.example.com");
    assert_eq!(code, 1);
    let want = "old.example.com offers only TLS 1.1 or older, which current clients refuse.";
    assert_eq!(found(&r), one("tls_old_protocol", "error", want));
    assert_eq!(
        r["findings"][0]["hint"],
        "Enable TLS 1.2 and 1.3 on the server."
    );
    assert_eq!(
        (&r["tls"]["protocol"], &r["tls"]["chain"]),
        (&Value::Null, &j!([]))
    );
    let (code, r) = allowed(&stub, &web, "hangup.example.com");
    assert_eq!(code, 1);
    let want = "The TLS handshake with 127.0.0.1 failed: the server closed the connection.";
    assert_eq!(found(&r), one("tls_handshake_failed", "error", want));
}

#[test]
fn nothing_on_port_443_is_a_warning() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, r) = allowed(&stub, &web, "closed.example.com");
    assert_eq!(code, 0);
    assert_eq!(
        (&r["tls"]["status"], &r["tls"]["address"]),
        (&j!("ok"), &j!("::1"))
    );
    let want = "Nothing accepts connections on port 443 at ::1.";
    assert_eq!(found(&r), one("https_refused", "warning", want));
}

#[test]
fn private_addresses_get_no_connection_without_allow_private() {
    let (stub, web) = (DnsStub::new(), Web::new());
    for (domain, address) in [
        ("tls.example.com", "127.0.0.1"),
        ("ten.example.com", "10.0.0.1"),
        ("ula.example.com", "fc00::1"),
        ("mapped.example.com", "::ffff:127.0.0.1"),
    ] {
        let (code, r) = tls(&stub, &web, domain, &[]);
        assert_eq!(code, 0, "{domain}");
        let reason = format!("{domain} resolves to {address}, a private address.");
        assert_eq!(r["tls"]["status"], "skipped");
        assert_eq!(r["tls"]["reason"], reason);
        let want = format!(
            "{domain} resolves to {address}, a private address, so the tls check didn't connect to it."
        );
        assert_eq!(found(&r), one("private_address", "warning", &want));
        let hint = "Add --allow-private (or the page option) to check an internal host.";
        assert_eq!(r["findings"][0]["hint"], hint);
    }
    assert_eq!(web.connections(), 0);
}

#[test]
fn names_without_an_address_are_skipped() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "nomail.example.net");
    assert_eq!(r["tls"]["status"], "skipped");
    assert_eq!(
        r["tls"]["reason"],
        "nomail.example.net has no A or AAAA record."
    );
    let (_, r) = allowed(&stub, &web, "gone.example.com");
    assert_eq!(r["tls"]["reason"], "gone.example.com doesn't exist in DNS.");
    assert_eq!(web.connections(), 0);
}

/// The `tls` findings of `domain`: code and message, with every other report field ignored.
fn judged(stub: &DnsStub, web: &Web, domain: &str) -> (Value, Vec<(String, String)>) {
    let (_, r) = allowed(stub, web, domain);
    let found = found(&r)
        .into_iter()
        .map(|(code, _, message)| (code, message));
    (r["tls"].clone(), found.collect())
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(c, m)| (c.to_string(), m.to_string()))
        .collect()
}

#[test]
fn certificate_dates_are_judged_from_the_certificate() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (t, found) = judged(&stub, &web, "expired.example.com");
    assert_eq!(
        (&t["trusted"], &t["trust_error"]),
        (&j!(false), &j!("expired"))
    );
    let until = &t["not_after"].as_str().unwrap()[..10];
    let days = -t["days_left"].as_i64().unwrap();
    assert!((9..=10).contains(&days), "{t}");
    let want = format!("The certificate expired on {until} ({days} days ago).");
    assert_eq!(found, pairs(&[("cert_expired", &want)]));
    assert_eq!(t["chain"].as_array().unwrap().len(), 2);

    let (t, found) = judged(&stub, &web, "future.example.com");
    assert_eq!(t["trust_error"], "not_yet_valid");
    let from = &t["not_before"].as_str().unwrap()[..10];
    let want = format!("The certificate isn't valid until {from}.");
    assert_eq!(found, pairs(&[("cert_not_yet_valid", &want)]));

    let (t, found) = judged(&stub, &web, "expiring.example.com");
    assert_eq!((&t["trusted"], &t["lifetime_days"]), (&j!(true), &j!(90)));
    let until = &t["not_after"].as_str().unwrap()[..10];
    let days = t["days_left"].as_i64().unwrap();
    let want = format!("The certificate expires in {days} days ({until}); renewal is due.");
    assert_eq!(found, pairs(&[("cert_expiring", &want)]));

    let (t, found) = judged(&stub, &web, "lifetime.example.com");
    assert_eq!((&t["trusted"], &t["lifetime_days"]), (&j!(true), &j!(300)));
    let from = &t["not_before"].as_str().unwrap()[..10];
    let want = format!(
        "The certificate's lifetime is 300 days, more than the 200 days allowed for certificates issued on {from}."
    );
    assert_eq!(found, pairs(&[("cert_lifetime_over_limit", &want)]));
}

#[test]
fn names_issuers_and_keys_are_judged_with_the_full_chain_shown() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (t, found) = judged(&stub, &web, "wrongname.example.com");
    assert_eq!(
        (&t["names_match"], &t["trust_error"]),
        (&j!(false), &j!("not_valid_for_name"))
    );
    let want = "The certificate is for other.example.net, not wrongname.example.com.";
    assert_eq!(found, pairs(&[("cert_name_mismatch", want)]));

    let (t, found) = judged(&stub, &web, "selfsigned.example.com");
    assert_eq!(t["trust_error"], "unknown_issuer");
    assert_eq!(
        (&t["chain"][0]["self_signed"], &t["chain"][1]),
        (&j!(true), &Value::Null)
    );
    let want = "This computer doesn't trust the certificate: self-signed.";
    assert_eq!(found, pairs(&[("cert_untrusted", want)]));

    let (t, found) = judged(&stub, &web, "leafonly.example.com");
    assert_eq!(
        (&t["trusted"], &t["trust_error"]),
        (&j!(false), &j!("incomplete_chain"))
    );
    let want = "The server sent only its own certificate, not the intermediate from Test Intermediate; some clients will refuse it.";
    assert_eq!(found, pairs(&[("chain_incomplete", want)]));

    let (t, found) = judged(&stub, &web, "weak.example.com");
    assert_eq!(t["chain"][1]["key"], "RSA 1024");
    assert_eq!(t["chain"][1]["subject"], "CN=Weak Intermediate");
    let codes: Vec<_> = found.iter().map(|(c, _)| c.as_str()).collect();
    assert_eq!(codes, ["cert_untrusted", "cert_weak_key"], "{found:?}");
    let want = "The certificate uses an RSA 1024-bit key; 2048 is the minimum CAs issue.";
    assert_eq!(found[1].1, want);
}

#[test]
fn the_text_report_names_the_certificate() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let args = [
        "tls.example.com",
        "-c",
        "tls",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let (code, out, err) = common::run(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", &ports)]);
    assert_eq!((code, err.as_str()), (0, ""));
    let line = out.lines().find(|l| l.starts_with("Certificate")).unwrap();
    let (head, tail) = line.split_once(" · until ").unwrap();
    assert_eq!(head, "Certificate  tls.example.com · Test Intermediate");
    assert!(tail.ends_with(" days) · TLS 1.3 · trusted"), "{line}");
}

#[test]
#[ignore = "known bug: DC19"]
fn the_second_ipv4_address_is_tried_when_the_first_refuses() {
    // macOS has no 127.0.0.2, so a connection there doesn't get a quick refusal.
    if cfg!(target_os = "macos") {
        return;
    }
    let (stub, web) = (DnsStub::new(), Web::new());
    let (_, r) = allowed(&stub, &web, "twoaddr.example.com");
    // Spec: the first address that accepts, A records first, then AAAA, at most 2 tried.
    assert_eq!(r["tls"]["address"], "127.0.0.1", "{}", r["tls"]);
    assert_eq!(r["tls"]["trusted"], true);
    assert!(found(&r).is_empty(), "{:?}", found(&r));
}
