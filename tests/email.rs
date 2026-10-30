mod common;

use common::{DnsStub, json};
use serde_json::{Value, json as j};

/// `check <domain> --checks email` against the stub, plus `extra`: the exit code and the report.
fn email(stub: &DnsStub, domain: &str, extra: &[&str]) -> (i32, Value) {
    let dns = stub.addr();
    let args = [
        domain,
        "--checks",
        "email",
        "--dns",
        &dns,
        "--resolver",
        &dns,
    ];
    let (code, v) = json(&[&args[..], extra].concat(), &[]);
    (code, v["reports"][0].clone())
}

/// The findings' codes, in report order.
fn codes(report: &Value) -> Vec<&str> {
    let findings = report["findings"].as_array().unwrap();
    findings
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect()
}

/// The finding with this code: its severity, message and hint.
fn finding<'a>(report: &'a Value, code: &str) -> (&'a str, &'a str, &'a Value) {
    let findings = report["findings"].as_array().unwrap();
    let f = findings.iter().find(|f| f["code"] == code).unwrap();
    let text = |k: &str| f[k].as_str().unwrap();
    (text("severity"), text("message"), &f["hint"])
}

#[test]
fn mx_hosts_are_listed_with_their_addresses() {
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "mx.example.net", &[]);
    assert_eq!(code, 1);
    assert_eq!(r["email"]["status"], "ok");
    let host = |preference, host: &str, addresses: Value, cname, error: Value| j!({ "preference": preference, "host": host, "addresses": addresses, "cname": cname, "error": error });
    assert_eq!(
        r["email"]["mx"],
        j!({ "kind": "mx", "error": null, "hosts": [
            host(10, "mx1.example.net", j!(["192.0.2.25"]), false, j!(null)),
            host(20, "alias.example.net", j!(["192.0.2.26", "2001:db8::26"]), true, j!(null)),
            host(30, "192.0.2.25", j!([]), false, j!(null)),
            host(40, "gone.example.net", j!([]), false, j!(null)),
            host(50, "noaddr.example.net", j!([]), false, j!(null)),
            host(60, "servfail.example.net", j!([]), false, j!("SERVFAIL")),
        ]})
    );
    assert_eq!(
        codes(&r),
        ["mx_ip", "mx_unresolvable", "mx_unresolvable", "mx_cname"]
    );
    assert_eq!(
        finding(&r, "mx_ip"),
        (
            "error",
            "An MX record holds an IP address (192.0.2.25) instead of a host name.",
            &j!("Create a host name for that address and use it in the MX record.")
        )
    );
    let unresolvable: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "mx_unresolvable")
        .map(|f| f["message"].as_str().unwrap())
        .collect();
    assert_eq!(
        unresolvable,
        [
            "MX host gone.example.net has no A or AAAA record, so mail can't be delivered to it.",
            "MX host noaddr.example.net has no A or AAAA record, so mail can't be delivered to it."
        ]
    );
    assert_eq!(
        finding(&r, "mx_cname"),
        (
            "warning",
            "MX host alias.example.net is a CNAME; MX records must name a host with its own address (RFC 2181 §10.3).",
            &j!("Point the MX at the CNAME's target.")
        )
    );
}

#[test]
fn null_implicit_and_missing_mx_are_told_apart() {
    let stub = DnsStub::new();
    let kind = |domain| {
        let (_, r) = email(&stub, domain, &[]);
        let mx = &r["email"]["mx"];
        assert_eq!(mx["hosts"], j!([]), "{domain}");
        (mx["kind"].clone(), codes(&r)[0].to_string(), r)
    };
    let (k, code, r) = kind("nullmx.example.net");
    assert_eq!((k, code.as_str()), (j!("null_mx"), "null_mx"));
    assert_eq!(
        finding(&r, "null_mx"),
        (
            "info",
            "nullmx.example.net says it accepts no email (null MX).",
            &j!(null)
        )
    );
    let (k, code, r) = kind("implicit.example.net");
    assert_eq!((k, code.as_str()), (j!("implicit"), "mx_implicit"));
    assert_eq!(
        finding(&r, "mx_implicit"),
        (
            "info",
            "No MX record: mail for implicit.example.net would go to its A/AAAA address.",
            &j!("Publish MX records, or a null MX (0 .) if the domain takes no email.")
        )
    );
    let (k, code, r) = kind("nomail.example.net");
    assert_eq!((k, code.as_str()), (j!("none"), "mx_none"));
    assert_eq!(
        finding(&r, "mx_none"),
        (
            "info",
            "No MX record and no address: nomail.example.net can't receive email.",
            &j!("If that's intended, publish a null MX (0 .) so senders stop trying.")
        )
    );
    let (_, r) = email(&stub, "servfail.example.net", &[]);
    assert_eq!(
        r["email"]["mx"],
        j!({ "kind": null, "hosts": [], "error": "SERVFAIL" })
    );
}

#[test]
fn email_waits_for_a_name_that_exists() {
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "nope.example.net", &[]);
    assert_eq!(code, 0);
    assert_eq!(
        (&r["email"]["status"], &r["email"]["reason"]),
        (
            &j!("skipped"),
            &j!("nope.example.net doesn't exist in DNS.")
        )
    );
    assert_eq!(r["email"]["mx"], j!(null));
}
