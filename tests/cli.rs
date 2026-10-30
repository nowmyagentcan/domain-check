mod common;

use common::{DnsStub, closed_udp_port, json, run};
use serde_json::{Value, json as j};

fn lookup(stub: &DnsStub, args: &[&str]) -> (i32, String, String) {
    let dns = stub.addr();
    run(&[&["lookup"], args, &["--dns", &dns]].concat(), &[])
}

fn lookup_json(stub: &DnsStub, args: &[&str]) -> (i32, Value) {
    let dns = stub.addr();
    json(&[&["lookup"], args, &["--dns", &dns]].concat(), &[])
}

#[test]
fn lookup_gives_presentation_values_for_every_type() {
    let stub = DnsStub::new();
    let soa = "ns1.example.com hostmaster.example.com 2026103001 7200 3600 1209600 300";
    for (name, t, values) in [
        ("example.com", "A", vec!["192.0.2.10"]),
        ("example.com", "AAAA", vec!["2001:db8::10"]),
        ("www.example.com", "CNAME", vec!["example.com"]),
        (
            "example.com",
            "MX",
            vec!["20 mx2.example.net", "10 mx1.example.net"],
        ),
        (
            "example.com",
            "NS",
            vec!["ns1.example.net", "ns2.example.net"],
        ),
        ("example.com", "TXT", vec!["v=spf1 ip4:192.0.2.0/24 -all"]),
        ("example.com", "CAA", vec!["0 issue \"letsencrypt.org\""]),
        ("example.com", "SOA", vec![soa]),
        (
            "_sip._tcp.example.com",
            "SRV",
            vec!["10 5 5060 sip.example.com"],
        ),
        ("192.0.2.10", "PTR", vec!["www.example.com"]),
        ("example.com", "DS", vec!["12345 13 2 abcd"]),
        ("example.com", "DNSKEY", vec!["257 3 13 AQID"]),
        ("_443._tcp.example.com", "TLSA", vec!["3 1 1 abcd"]),
        ("example.com", "HTTPS", vec!["1 . alpn=h2,h3"]),
        (
            "_dns.example.com",
            "SVCB",
            vec!["1 dns.example.com alpn=h2,h3"],
        ),
    ] {
        let (code, v) = lookup_json(&stub, &[name, t]);
        assert_eq!(code, 0, "{name} {t}");
        let r = &v["results"][0];
        assert_eq!(
            (r["type"].as_str(), r["rcode"].as_str()),
            (Some(t), Some("NOERROR"))
        );
        let records = r["records"].as_array().unwrap();
        let got: Vec<_> = records
            .iter()
            .map(|x| x["value"].as_str().unwrap())
            .collect();
        assert_eq!(got, values, "{name} {t}");
    }
    let (_, v) = lookup_json(&stub, &["example.com", "mx"]);
    let first = &v["results"][0]["records"][0];
    assert_eq!(first, &j!({ "value": "20 mx2.example.net", "ttl": 3600 }));
}

#[test]
fn lookup_json_has_the_documented_shape() {
    let stub = DnsStub::new();
    let (code, v) = lookup_json(&stub, &["Example.COM."]);
    assert_eq!(code, 0);
    let answer = |t, value| {
        j!({ "type": t, "rcode": "NOERROR", "authoritative": false, "authenticated": true,
             "records": [{ "value": value, "ttl": 300 }], "error": null })
    };
    let results = [answer("A", "192.0.2.10"), answer("AAAA", "2001:db8::10")];
    let want = j!({ "name": "example.com", "server": stub.addr(), "results": results });
    assert_eq!(v, want);
    let (_, v) = lookup_json(&stub, &["example.net", "SOA"]);
    assert_eq!(v["results"][0]["authenticated"], false);
    let (_, v) = lookup_json(&stub, &["bücher.example.org"]);
    assert_eq!(v["name"], "xn--bcher-kva.example.org");
}

#[test]
fn lookup_text_lines_up_records_and_empty_answers() {
    let stub = DnsStub::new();
    let (code, out, err) = lookup(&stub, &["example.com", "MX", "TXT", "CNAME"]);
    assert_eq!((code, err.as_str()), (0, ""));
    let want = [
        "example.com  3600  MX   20 mx2.example.net",
        "example.com  3600  MX   10 mx1.example.net",
        "example.com  300   TXT  v=spf1 ip4:192.0.2.0/24 -all",
        "example.com  ; NODATA CNAME",
        "",
    ];
    assert_eq!(out, want.join("\n"));
    let (code, out, _) = lookup(&stub, &["www.example.com", "A"]);
    assert_eq!(
        (code, out.as_str()),
        (0, "example.com  300  A  192.0.2.10\n")
    );
    let (code, out, _) = lookup(&stub, &["192.0.2.10"]);
    let ptr = "10.2.0.192.in-addr.arpa  3600  PTR  www.example.com\n";
    assert_eq!((code, out.as_str()), (0, ptr));
    let (code, out, _) = lookup(&stub, &["2001:db8::10"]);
    assert_eq!(code, 0);
    let ptr = ".8.b.d.0.1.0.0.2.ip6.arpa  3600  PTR  www.example.com\n";
    assert!(out.starts_with("0.1.0.0.") && out.ends_with(ptr), "{out}");
}

#[test]
fn lookup_exit_codes_follow_the_answers() {
    let stub = DnsStub::new();
    let (code, out, _) = lookup(&stub, &["_dmarc.example.org", "TXT", "A"]);
    assert_eq!(
        (code, out.as_str()),
        (1, "_dmarc.example.org  ; NXDOMAIN\n")
    );
    let (code, out, _) = lookup(&stub, &["servfail.example.com", "A", "MX"]);
    let want = "servfail.example.com  ; SERVFAIL A\nservfail.example.com  ; SERVFAIL MX\n";
    assert_eq!((code, out.as_str()), (3, want));
    let (code, v) = lookup_json(&stub, &["refused.example.com", "TXT"]);
    assert_eq!((code, &v["results"][0]["rcode"]), (3, &j!("REFUSED")));
    let (code, v) = lookup_json(&stub, &["example.com", "SRV"]);
    assert_eq!((code, &v["results"][0]["records"]), (0, &j!([])));
}

#[test]
fn lookup_retries_truncated_answers_over_tcp() {
    let stub = DnsStub::new();
    let (code, v) = lookup_json(&stub, &["big.example.com", "TXT"]);
    let n = v["results"][0]["records"].as_array().unwrap().len();
    assert_eq!((code, n), (0, 40));
    let tcp: Vec<_> = stub.queries().iter().map(|q| q.tcp).collect();
    assert_eq!(tcp, [false, true]);
}

#[test]
fn a_resolver_that_never_answers_is_exit_3() {
    let stub = DnsStub::new();
    let (code, out, err) = lookup(&stub, &["silent.example.com", "A"]);
    assert_eq!((code, out.as_str()), (3, ""));
    let what = format!("Couldn't reach the DNS resolver {}: timeout.", stub.addr());
    let how = "Check the network connection, or pass --dns with a resolver you can reach.";
    assert_eq!(err, format!("✗ {what}\n  {how}\n"));
    let (code, v) = lookup_json(&stub, &["silent.example.com", "A"]);
    let r = &v["results"][0];
    assert_eq!(
        (code, &r["rcode"], &r["error"]),
        (3, &Value::Null, &j!("timeout"))
    );
    let closed = closed_udp_port().to_string();
    let (code, _, err) = run(&["lookup", "example.com", "--dns", &closed], &[]);
    assert_eq!(code, 3);
    let what = format!("✗ Couldn't reach the DNS resolver {closed}: ");
    assert!(err.starts_with(&what), "{err}");
}

#[test]
fn invalid_names_are_exit_1_without_a_query() {
    let stub = DnsStub::new();
    let (code, out, err) = lookup(&stub, &["exa mple.com"]);
    assert_eq!((code, out.as_str()), (1, ""));
    let what = "exa mple.com isn't a valid domain name: it contains a character not allowed in domain names.";
    assert_eq!(err, format!("✗ {what}\n  Check the spelling.\n"));
    let (code, v) = lookup_json(&stub, &[""]);
    assert_eq!(code, 1);
    let hint = "Pass a domain, e.g. example.com.";
    let want = j!({ "error": { "code": "empty", "message": "Empty input.", "hint": hint } });
    assert_eq!(v, want);
    assert!(stub.queries().is_empty());
}

#[test]
fn usage_errors_are_exit_2_with_what_and_how() {
    let stub = DnsStub::new();
    let dns = stub.addr();
    let two = |args: &[&str], env: &[(&str, &str)], what: &str, how: &str| {
        let (code, out, err) = run(args, env);
        assert_eq!((code, out.as_str()), (2, ""), "{args:?}");
        assert_eq!(err, format!("✗ {what}\n  {how}\n"), "{args:?}");
    };
    two(
        &["lookup", "example.com", "AXFR", "--dns", &dns],
        &[],
        "Unknown record type 'AXFR'.",
        "Use A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, PTR, DS, DNSKEY, TLSA, HTTPS or SVCB.",
    );
    two(
        &["lookup", "192.0.2.1", "MX", "--dns", &dns],
        &[],
        "192.0.2.1 is an IP address, so it can only be looked up as PTR.",
        "Try: domain-check lookup 192.0.2.1",
    );
    two(
        &["lookup", "example.com", "--dns", "dns.example"],
        &[],
        "--dns dns.example isn't an IP address.",
        "Pass an IP address, with a port if it isn't 53, e.g. 1.1.1.1 or 127.0.0.1:5353.",
    );
    two(
        &["lookup", "example.com", "--dns", &dns],
        &[("DOMAIN_CHECK_LOOPBACK_PORTS", "dns=0")],
        "DOMAIN_CHECK_LOOPBACK_PORTS=dns=0 isn't valid.",
        "Use dns=N,http=N,https=N with ports from 1 to 65535, or unset it.",
    );
    assert!(stub.queries().is_empty());
    for args in [
        &["lookup", "example.com", "--nope"][..],
        &["frobnicate"],
        &["lookup"],
    ] {
        let (code, _, err) = run(args, &[]);
        assert_eq!(code, 2, "{args:?}");
        assert!(err.contains("--help"), "{err}");
    }
}

#[test]
fn version_and_help() {
    let (code, out, _) = run(&["--version"], &[]);
    let want = "domain-check 0.1.0 (RDAP bootstrap 2026-10-28)\n";
    assert_eq!((code, out.as_str()), (0, want));
    let (code, out, _) = run(&["lookup", "--help"], &[]);
    assert_eq!(code, 0);
    for line in [
        "  domain-check lookup _dmarc.example.com TXT",
        "  domain-check lookup 8.8.8.8",
        "  DOMAIN_CHECK_LOOPBACK_PORTS ",
    ] {
        assert!(out.contains(line), "{out}");
    }
}
