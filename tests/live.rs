//! Checks against real services. They are ignored by default, so CI never runs them; run them
//! by hand with `cargo test --test live -- --ignored`. A failure here can mean the service
//! changed rather than a bug.

mod common;

use serde_json::Value;

/// `domain-check <args> --json` with this computer's resolver and the bundled RDAP bootstrap:
/// the exit code and the first report.
fn live(args: &[&str]) -> (i32, Value) {
    let mut cmd = common::command(&[args, &["--json"]].concat(), &[]);
    cmd.env_remove("DOMAIN_CHECK_RDAP_BOOTSTRAP");
    let out = cmd.output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    (out.status.code().unwrap(), v["reports"][0].clone())
}

fn codes(report: &Value) -> Vec<String> {
    let findings = report["findings"].as_array().unwrap();
    findings
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
#[ignore = "real network"]
fn example_com_resolves_agrees_and_is_registered_at_verisign() {
    let (_, r) = live(&["example.com"]);
    for section in ["dns", "propagation", "rdap", "tls"] {
        assert_eq!(r[section]["status"], "ok", "{section}: {}", r[section]);
    }
    assert!(
        r["dns"]["records"]["A"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    );
    assert_eq!(r["propagation"]["consistent"], true, "{}", r["propagation"]);
    let rdap = &r["rdap"];
    assert_eq!(rdap["server"], "https://rdap.verisign.com/com/v1/");
    assert_eq!(rdap["found"], true);
    assert_eq!(rdap["registrar"]["iana_id"], "376");
    assert_eq!(rdap["bootstrap"], "bundled 2026-10-28");
    assert!(rdap["expires"].is_string());
    assert_eq!(r["tls"]["trusted"], true, "{}", r["tls"]);
}

#[test]
#[ignore = "real network"]
fn gmail_com_has_mx_spf_within_the_limit_and_dmarc() {
    let (_, r) = live(&["gmail.com", "--checks", "email"]);
    let email = &r["email"];
    assert_eq!(email["status"], "ok");
    assert_eq!(email["mx"]["kind"], "mx");
    let lookups = email["spf"]["lookups"].as_u64().unwrap();
    assert!((1..=10).contains(&lookups), "{lookups}");
    assert_eq!(email["dmarc"]["found_at"], "_dmarc.gmail.com");
}

#[test]
#[ignore = "real network"]
fn github_com_publishes_an_rsa_dkim_key_under_google() {
    let (_, r) = live(&["github.com", "--checks", "email", "-s", "google"]);
    let key = &r["email"]["dkim"]["keys"][0];
    assert_eq!(
        (&key["selector"], &key["key_type"]),
        (&"google".into(), &"rsa".into())
    );
    assert!(key["bits"].as_u64().is_some_and(|b| b >= 1024), "{key}");
}

#[test]
#[ignore = "real network"]
fn dnssec_failed_org_is_bogus() {
    let (code, r) = live(&["dnssec-failed.org", "--checks", "dns"]);
    assert_eq!(code, 1);
    assert!(
        codes(&r).contains(&"dnssec_bogus".into()),
        "{:?}",
        codes(&r)
    );
    assert_eq!(r["dns"]["dnssec"]["bogus"], true);
}

#[test]
#[ignore = "real network"]
fn badssl_certificates_get_their_findings() {
    for (host, code) in [
        ("expired.badssl.com", "cert_expired"),
        ("self-signed.badssl.com", "cert_untrusted"),
        ("wrong.host.badssl.com", "cert_name_mismatch"),
        ("incomplete-chain.badssl.com", "chain_incomplete"),
    ] {
        let (exit, r) = live(&[host, "--checks", "tls"]);
        assert_eq!(exit, 1, "{host}");
        assert!(codes(&r).contains(&code.into()), "{host}: {:?}", codes(&r));
        assert!(!r["tls"]["chain"].as_array().unwrap().is_empty(), "{host}");
    }
}
