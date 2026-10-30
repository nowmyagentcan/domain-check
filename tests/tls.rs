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
