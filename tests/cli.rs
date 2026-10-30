mod common;

use common::{DnsStub, closed_udp_port, json, run};
use domain_check::dns::RecordType;
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
        &["example.com", "--frobnicate"],
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

#[test]
fn debug_shows_each_query_with_its_server_code_flags_and_time() {
    let stub = DnsStub::new();
    let (code, out, err) = lookup(&stub, &["big.example.com", "TXT", "--debug"]);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 40);
    let lines: Vec<_> = err.lines().collect();
    assert_eq!(lines.len(), 2, "{err}");
    let udp = format!(
        "debug: dns udp {} big.example.com TXT NOERROR tc rd ra ad ",
        stub.addr()
    );
    let tcp = format!(
        "debug: dns tcp {} big.example.com TXT NOERROR rd ra ad ",
        stub.addr()
    );
    for (line, start) in lines.iter().zip([udp, tcp]) {
        let ms = line
            .strip_prefix(&start)
            .and_then(|l| l.strip_suffix(" ms"));
        assert!(ms.is_some_and(|ms| ms.parse::<u64>().is_ok()), "{line}");
    }
    let (code, _, err) = lookup(&stub, &["silent.example.com", "--debug", "A"]);
    assert_eq!(code, 3);
    let silent = format!(
        "debug: dns udp {} silent.example.com A timeout ",
        stub.addr()
    );
    assert_eq!(err.matches(&silent).count(), 2, "{err}");
}

#[test]
fn the_loopback_port_swap_applies_to_port_53_only() {
    let stub = DnsStub::new();
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", stub.ports())];
    let env: Vec<_> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let args = [
        "lookup",
        "example.com",
        "A",
        "--dns",
        "127.0.0.1",
        "--debug",
    ];
    let (code, _, err) = run(&args, &env);
    assert_eq!(code, 0, "{err}");
    let to = format!("debug: dns udp {} example.com A NOERROR", stub.addr());
    assert!(err.starts_with(&to), "{err}");
    let (_, v) = json(&["lookup", "example.com", "--dns", "::1"], &env);
    assert_eq!(v["server"], "::1");
    assert_eq!(stub.queries().last().unwrap().at.to_string(), "::1");
}

#[test]
fn closed_pipes_end_quietly() {
    let stub = DnsStub::new();
    let dns = stub.addr();
    let base = ["lookup", "example.com", "MX", "--dns", &dns];
    let lookup = |extra: &[&'static str]| [&base[..], extra].concat();
    for extra in [&[][..], &["--json"], &["--debug"], &["--json", "--debug"]] {
        let (code, err) = common::closed(&lookup(extra), true);
        assert_eq!(code, 0, "{extra:?}: {err}");
        assert!(err.lines().all(|l| l.starts_with("debug: ")), "{err}");
        let (code, out) = common::closed(&lookup(extra), false);
        assert_eq!(code, 0, "{extra:?}");
        assert!(out.contains("mx1.example.net"), "{out}");
    }
    let silent = ["lookup", "silent.example.com", "--dns", &dns, "--debug"];
    assert_eq!(common::closed(&silent, false), (3, String::new()));
    for args in [&["--help"][..], &["lookup", "--help"], &["--version"]] {
        assert_eq!(common::closed(args, true), (0, String::new()), "{args:?}");
    }
    let usage = ["lookup", "example.com", "AXFR"];
    assert_eq!(common::closed(&usage, false), (2, String::new()));
}

/// `check` against the stub, which also plays the zones' nameservers and the resolvers.
fn check(stub: &DnsStub, args: &[&str]) -> (i32, Value) {
    let (dns, ports) = (stub.addr(), stub.ports());
    let base = ["--dns", dns.as_str(), "--resolver", dns.as_str()];
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    json(&[args, &base].concat(), &env)
}

#[test]
fn more_than_20_domains_is_a_usage_error() {
    let stub = DnsStub::new();
    let names: Vec<String> = (0..21).map(|i| format!("d{i}.example.com")).collect();
    let mut args: Vec<&str> = names.iter().map(String::as_str).collect();
    let dns = stub.addr();
    args.extend(["--dns", &dns]);
    let (code, out, err) = run(&args, &[]);
    assert_eq!((code, out.as_str()), (2, ""));
    let want = "✗ Too many domains: 21 given, at most 20 per run.\n  Split them into runs of 20 or fewer.\n";
    assert_eq!(err, want);
    assert!(stub.queries().is_empty());
    let (code, out, err) = run(&["check", "--json"], &[]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert_eq!(err, "✗ No domain given.\n  Try: domain-check example.com\n");
}

#[test]
fn invalid_inputs_get_their_error_and_no_query() {
    let stub = DnsStub::new();
    let (code, v) = check(&stub, &["printer.test", "192.0.2.1", "intranet", ""]);
    assert_eq!(code, 1);
    let errors: Vec<_> = v["reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["error"]["code"].as_str().unwrap())
        .collect();
    assert_eq!(
        errors,
        ["special_use", "ip_address", "single_label", "empty"]
    );
    let r = &v["reports"][0];
    assert_eq!(
        (&r["domain"], &r["dns"], &r["propagation"], &r["findings"]),
        (&Value::Null, &Value::Null, &Value::Null, &j!([]))
    );
    assert!(stub.queries().is_empty());
    let summary = j!({ "domains": 4, "errors": 0, "warnings": 0, "info": 0, "unavailable": 0 });
    assert_eq!(v["summary"], summary);
}

#[test]
fn a_domain_given_twice_is_checked_once() {
    let stub = DnsStub::new();
    let inputs = ["example.com", "Example.COM.", "https://example.com:8443/"];
    let (code, v) = check(&stub, &[&inputs[..], &["-c", "dns"]].concat());
    assert_eq!(code, 0);
    let reports = v["reports"].as_array().unwrap();
    let got: Vec<_> = reports
        .iter()
        .map(|r| (r["input"].as_str().unwrap(), r["domain"].as_str().unwrap()))
        .collect();
    assert_eq!(
        got,
        inputs
            .iter()
            .map(|i| (*i, "example.com"))
            .collect::<Vec<_>>()
    );
    assert_eq!(reports[0]["dns"], reports[2]["dns"]);
    assert_eq!(reports[1]["findings"], j!([]));
    let port = j!([{ "code": "port_ignored", "severity": "info", "check": "dns",
        "message": "The port in https://example.com:8443/ was ignored; checks use ports 53, 80 and 443.",
        "hint": null }]);
    assert_eq!(reports[2]["findings"], port);
    let a = stub
        .queries()
        .into_iter()
        .filter(|q| q.name == "example.com" && q.qtype == RecordType::A)
        .count();
    assert_eq!(a, 1);
    assert_eq!(
        (&v["summary"]["domains"], &v["summary"]["info"]),
        (&j!(3), &j!(1))
    );
    let at = reports[0]["checked_at"].as_str().unwrap();
    assert!(
        at.len() == 20 && at.ends_with('Z') && at.as_bytes()[10] == b'T',
        "{at}"
    );
}

#[test]
fn slow_answers_keep_each_section_inside_its_budget() {
    let slow = DnsStub::start(|a| {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        common::fixtures(a)
    });
    let started = std::time::Instant::now();
    let (code, v) = check(&slow, &["example.com"]);
    let took = started.elapsed().as_secs_f64();
    assert!(took < 15.0, "{took} s");
    assert_eq!(code, 0, "{v}");
    let r = &v["reports"][0];
    assert_eq!(
        (&r["dns"]["status"], &r["propagation"]["status"]),
        (&j!("ok"), &j!("ok"))
    );
    assert_eq!(r["propagation"]["consistent"], true);
}

#[test]
fn a_silent_resolver_makes_every_section_unavailable_quickly() {
    let silent = DnsStub::start(|_| None);
    let started = std::time::Instant::now();
    let (code, v) = check(&silent, &["example.com"]);
    assert!(started.elapsed().as_secs() < 15);
    assert_eq!(code, 3);
    let r = &v["reports"][0];
    let reason = format!(
        "Couldn't reach the DNS resolver {}: timeout.",
        silent.addr()
    );
    assert_eq!(
        (&r["dns"]["status"], &r["dns"]["reason"]),
        (&j!("unavailable"), &j!(reason))
    );
    let reason = j!("No DNS answer, so this check couldn't run.");
    assert_eq!(r["propagation"]["reason"], reason);
    assert_eq!(v["summary"]["unavailable"], 2);
}

/// The text report, with each `checked HH:MM UTC` turned into `checked T`.
fn text(stub: &DnsStub, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let (dns, ports) = (stub.addr(), stub.ports());
    let base = ["--dns", dns.as_str(), "--resolver", dns.as_str()];
    let env = [&[("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())][..], env].concat();
    let (code, out, err) = run(&[args, &base].concat(), &env);
    assert_eq!(err, "");
    let lines: Vec<String> = out
        .lines()
        .map(|l| match l.split_once(" · checked ") {
            Some((head, at)) if at.len() == 9 && at.ends_with(" UTC") => {
                format!("{head} · checked T")
            }
            _ => l.to_string(),
        })
        .collect();
    (code, lines.join("\n") + "\n")
}

#[test]
fn the_text_report_puts_findings_first_then_one_line_per_section() {
    let stub = DnsStub::new();
    let (code, out) = text(&stub, &["example.com"], &[]);
    assert_eq!(code, 0);
    let want = "example.com  No problems found · checked T

DNS          A 192.0.2.10 · AAAA 2001:db8::10 · MX 20 mx2.example.net, 10 mx1.example.net · NS ns1.example.net, ns2.example.net · DNSSEC signed, validated
Propagation  consistent: 2 nameserver addresses, 2 resolvers agree on A, AAAA, MX, TXT
";
    assert_eq!(out, want);

    let (code, out) = text(
        &stub,
        &[
            "example.com",
            "printer.test",
            "nope.example.com",
            "-c",
            "dns",
        ],
        &[],
    );
    assert_eq!(code, 1);
    let want = "example.com  No problems found · checked T

DNS          A 192.0.2.10 · AAAA 2001:db8::10 · MX 20 mx2.example.net, 10 mx1.example.net · NS ns1.example.net, ns2.example.net · DNSSEC signed, validated
Propagation  skipped: not requested

✗ printer.test  printer.test is a special-use name (RFC 6761); it never resolves on the public internet.
                Use domain-check lookup to ask your own resolver about it.

nope.example.com  1 error · checked T
✗ dns  nope.example.com doesn't exist in DNS (NXDOMAIN).
       Check the spelling; Registration shows whether it is registered.

DNS          doesn't exist (NXDOMAIN)
Propagation  skipped: not requested

3 domains: 2 with errors, 1 clean
";
    assert_eq!(out, want);
}

#[test]
fn findings_line_up_and_sections_that_couldnt_run_say_why() {
    let stub = DnsStub::new();
    let (_, out) = text(&stub, &["slow.example.org", "-t", "A"], &[]);
    let want = "slow.example.org  1 warning · 2 info · checked T
! propagation  Nameserver ns2.example.net (::1) didn't answer within 4 s.
               It may be down, or your network may block DNS to outside servers.
i dns          slow.example.org isn't signed with DNSSEC (no DS record at the parent).
i dns          No CAA record: any certificate authority may issue certificates for slow.example.org.
               Add one naming your CA, e.g. 0 issue \"letsencrypt.org\".

DNS          A 192.0.2.30 · NS ns1.example.net, ns2.example.net · DNSSEC unsigned
Propagation  consistent: 1 nameserver addresses, 2 resolvers agree on A · 1 nameserver address didn't answer
";
    assert_eq!(out, want);

    let silent = DnsStub::start(|_| None);
    let (code, out) = text(&silent, &["xn--bcher-kva.example.com"], &[]);
    assert_eq!(code, 3);
    let want = format!(
        "xn--bcher-kva.example.com (bücher.example.com)  2 checks couldn't run · checked T

DNS          unavailable: Couldn't reach the DNS resolver {}: timeout.
Propagation  unavailable: No DNS answer, so this check couldn't run.
",
        silent.addr()
    );
    assert_eq!(out, want);
}

#[test]
fn colour_only_when_asked_and_never_with_no_color() {
    let stub = DnsStub::new();
    let run_with = |no_color: Option<&str>| {
        let dns = stub.addr();
        let args = [
            "nope.example.com",
            "-c",
            "dns",
            "--dns",
            &dns,
            "--resolver",
            &dns,
        ];
        let mut cmd = common::command(&args, &[("CLICOLOR_FORCE", "1")]);
        match no_color {
            Some(v) => cmd.env("NO_COLOR", v),
            None => cmd.env_remove("NO_COLOR"),
        };
        String::from_utf8(cmd.output().unwrap().stdout).unwrap()
    };
    let coloured = run_with(None);
    for styled in [
        "\x1b[1mnope.example.com\x1b[0m",
        "\x1b[31m✗\x1b[0m dns",
        "\x1b[2mCheck the spelling;",
        "\x1b[1mDNS          \x1b[0m",
    ] {
        assert!(coloured.contains(styled), "{styled:?} in {coloured:?}");
    }
    assert!(!run_with(Some("1")).contains('\x1b'));
    // An empty NO_COLOR doesn't turn colour off.
    assert!(run_with(Some("")).contains('\x1b'));
}
