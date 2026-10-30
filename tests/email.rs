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

/// The codes of the findings about MX, in report order.
fn mx_codes(report: &Value) -> Vec<&str> {
    let findings = report["findings"].as_array().unwrap();
    let codes = findings.iter().map(|f| f["code"].as_str().unwrap());
    codes
        .filter(|c| c.starts_with("mx_") || *c == "null_mx")
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
        mx_codes(&r),
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
        (mx["kind"].clone(), mx_codes(&r)[0].to_string(), r)
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

/// The findings whose code starts with `prefix`: code, severity and message.
fn found<'a>(report: &'a Value, prefix: &str) -> Vec<(&'a str, &'a str, &'a str)> {
    let findings = report["findings"].as_array().unwrap();
    let text = |f: &'a Value, k: &str| f[k].as_str().unwrap();
    findings
        .iter()
        .filter(|f| text(f, "code").starts_with(prefix))
        .map(|f| (text(f, "code"), text(f, "severity"), text(f, "message")))
        .collect()
}

fn node(term: &str, record: Value, error: Value, children: Value) -> Value {
    j!({ "term": term, "lookups": 1, "record": record, "error": error, "children": children })
}

fn leaf(term: &str) -> Value {
    node(term, j!(null), j!(null), j!([]))
}

#[test]
fn the_spf_walk_follows_includes_and_counts_each_lookup() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "spf.example.net", &[]);
    let inner = node(
        "include:_inner.example.net",
        j!("v=spf1 ip4:198.51.100.0/24 -all"),
        j!(null),
        j!([]),
    );
    let spf = j!({
        "record": "v=spf1 include:_spf.example.net a mx ip4:192.0.2.0/24 ptr exists:%{i}.exists.example.net -all",
        "lookups": 6, "lookups_capped": false, "void_lookups": 0, "all": "-all", "redirect": null, "result": null,
        "tree": [
            node("include:_spf.example.net", j!("v=spf1 include:_inner.example.net ip6:2001:db8::/32 ~all"), j!(null), j!([inner])),
            leaf("a"),
            leaf("mx"),
            leaf("ptr"),
            node("exists:%{i}.exists.example.net", j!(null), j!("macro"), j!([])),
        ]
    });
    assert_eq!(r["email"]["spf"], spf);
    assert_eq!(
        found(&r, "spf_"),
        [
            (
                "spf_ptr",
                "warning",
                "The SPF record uses ptr, which RFC 7208 §5.5 says not to use."
            ),
            (
                "spf_macro",
                "info",
                "exists:%{i}.exists.example.net uses macros that depend on the sender; it was counted but not followed."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "spf_macro").2,
        "Pass --spf-ip to evaluate it for one sending IP."
    );
    // The macro's name is never asked for.
    assert!(stub.queries().iter().all(|q| !q.name.contains("exists")));
}

#[test]
fn more_than_10_lookups_is_an_error_and_the_walk_stops_at_20() {
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "many.example.net", &[]);
    assert_eq!(code, 1);
    let spf = &r["email"]["spf"];
    assert_eq!(
        (&spf["lookups"], &spf["lookups_capped"]),
        (&j!(12), &j!(false))
    );
    assert_eq!(spf["tree"][5]["children"], j!([leaf("a:mx1.example.net")]));
    assert_eq!(
        finding(&r, "spf_too_many_lookups"),
        (
            "error",
            "The SPF record needs 12 DNS lookups; the limit is 10 (RFC 7208 §4.6.4).",
            &j!("Remove unused includes, or replace some with ip4:/ip6: ranges.")
        )
    );
    let (_, r) = email(&stub, "capped.example.net", &[]);
    let spf = &r["email"]["spf"];
    assert_eq!(
        (&spf["lookups"], &spf["lookups_capped"]),
        (&j!(20), &j!(true))
    );
    assert_eq!(
        finding(&r, "spf_too_many_lookups").1,
        "The SPF record needs more than 20 DNS lookups; the limit is 10 (RFC 7208 §4.6.4)."
    );
    // The second include stops after 6 of its 13 lookups.
    let second = spf["tree"][1]["children"].as_array().unwrap();
    let counted: usize = second
        .iter()
        .map(|n| 1 + n["children"].as_array().unwrap().len())
        .sum();
    assert_eq!(counted, 6);
}

#[test]
fn void_lookups_and_missing_includes_are_permanent_errors() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "void.example.net", &[]);
    let spf = &r["email"]["spf"];
    assert_eq!((&spf["lookups"], &spf["void_lookups"]), (&j!(5), &j!(4)));
    let errors: Vec<_> = spf["tree"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["error"].clone())
        .collect();
    assert_eq!(
        errors,
        [
            j!(null),
            j!(null),
            j!(null),
            j!("no SPF record"),
            j!("NXDOMAIN")
        ]
    );
    assert_eq!(
        found(&r, "spf_"),
        [
            (
                "spf_include_missing",
                "error",
                "include:nomail.example.net points to nomail.example.net, which has no SPF record (no record); that is a permanent error."
            ),
            (
                "spf_include_missing",
                "error",
                "include:gone.example.net points to gone.example.net, which has no SPF record (NXDOMAIN); that is a permanent error."
            ),
            (
                "spf_too_many_void",
                "error",
                "4 SPF lookups return no records; the limit is 2."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "spf_include_missing").2,
        "Fix the name or remove the term."
    );
}

#[test]
fn includes_that_loop_back_are_stopped() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "loop.example.net", &[]);
    let back = node("include:LOOP.example.net.", j!(null), j!("loop"), j!([]));
    let tree = j!([node(
        "include:_loop.example.net",
        j!("v=spf1 include:LOOP.example.net. ~all"),
        j!(null),
        j!([back])
    )]);
    assert_eq!(r["email"]["spf"]["tree"], tree);
    assert_eq!(r["email"]["spf"]["lookups"], 2);
    assert_eq!(
        finding(&r, "spf_loop"),
        (
            "error",
            "The SPF includes loop back to loop.example.net.",
            &j!("Remove the include that points back.")
        )
    );
}

#[test]
fn all_and_redirect_decide_what_other_senders_get() {
    let stub = DnsStub::new();
    let spf = |domain| {
        let (_, r) = email(&stub, domain, &[]);
        let s = &r["email"]["spf"];
        let codes: Vec<String> = found(&r, "spf_").iter().map(|f| f.0.to_string()).collect();
        (
            s["all"].clone(),
            s["redirect"].clone(),
            s["lookups"].clone(),
            codes,
        )
    };
    let none = Vec::<String>::new();
    assert_eq!(
        spf("redirect.example.net"),
        (j!(null), j!("_spf.example.net"), j!(2), none)
    );
    // A redirect next to an all is ignored (RFC 7208 §6.1).
    let one = |code: &str| vec![code.to_string()];
    assert_eq!(
        spf("redirected.example.net"),
        (j!("?all"), j!(null), j!(0), one("spf_neutral_all"))
    );
    assert_eq!(
        spf("plusall.example.net"),
        (j!("+all"), j!(null), j!(0), one("spf_plus_all"))
    );
    assert_eq!(
        spf("noall.example.net"),
        (j!(null), j!(null), j!(0), one("spf_no_all"))
    );
    let (_, r) = email(&stub, "plusall.example.net", &[]);
    assert_eq!(
        finding(&r, "spf_plus_all"),
        (
            "error",
            "The SPF record ends in +all, which lets anyone send mail as plusall.example.net.",
            &j!("Use -all, or ~all while testing.")
        )
    );
    let (_, r) = email(&stub, "redirected.example.net", &[]);
    assert_eq!(
        finding(&r, "spf_neutral_all"),
        (
            "warning",
            "The SPF record ends in ?all, which says nothing about other senders.",
            &j!("Use -all or ~all once every sender is listed.")
        )
    );
    let (_, r) = email(&stub, "noall.example.net", &[]);
    assert_eq!(
        finding(&r, "spf_no_all"),
        (
            "warning",
            "The SPF record has no \"all\" term or redirect, so mail from other senders gets \"neutral\".",
            &j!("End it with -all or ~all.")
        )
    );
}

#[test]
fn spf_records_that_are_missing_doubled_broken_or_too_long() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "nomail.example.net", &[]);
    assert_eq!(r["email"]["spf"], j!(null));
    assert_eq!(
        finding(&r, "spf_none"),
        (
            "warning",
            "No SPF record for nomail.example.net.",
            &j!(
                "Publish one, e.g. \"v=spf1 include:<your mail provider> -all\", or \"v=spf1 -all\" if it sends no mail."
            )
        )
    );
    let (_, r) = email(&stub, "multi.example.net", &[]);
    assert_eq!(r["email"]["spf"]["record"], "v=spf1 -all");
    assert_eq!(
        found(&r, "spf_"),
        [
            (
                "spf_multiple",
                "error",
                "multi.example.net has 2 SPF records; that is a permanent error (RFC 7208 §4.5)."
            ),
            (
                "spf_sender_id",
                "info",
                "An old Sender ID (spf2.0) record was ignored; nothing uses it now."
            ),
        ]
    );
    let (_, r) = email(&stub, "syntax.example.net", &[]);
    assert_eq!(
        found(&r, "spf_"),
        [
            (
                "spf_syntax",
                "error",
                "The SPF record has an error: unknown mechanism (\"inlcude:_spf.example.net\")."
            ),
            (
                "spf_syntax",
                "error",
                "The SPF record has an error: invalid IP address (\"ip4:192.0.2.300\")."
            ),
        ]
    );
    let (_, r) = email(&stub, "long.example.net", &[]);
    assert_eq!(
        finding(&r, "spf_long"),
        (
            "warning",
            "The SPF record is 577 bytes; over 450 may not fit in a DNS answer over UDP (RFC 7208 §3.4).",
            &j!("Shorten it, e.g. by moving ranges into an include.")
        )
    );
    let (_, r) = email(&stub, "mxmany.example.net", &[]);
    assert_eq!(
        finding(&r, "spf_mx_too_many"),
        (
            "error",
            "\"mx\" in the SPF record finds 11 hosts; the limit is 10.",
            &j!("List the senders with ip4:/ip6: instead.")
        )
    );
    let (_, r) = email(&stub, "failing.example.net", &[]);
    let errors: Vec<_> = r["email"]["spf"]["tree"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["error"].clone())
        .collect();
    assert_eq!(errors, [j!("SERVFAIL"), j!("SERVFAIL")]);
    assert_eq!(
        found(&r, "spf_"),
        [
            (
                "spf_lookup_failed",
                "warning",
                "Couldn't look up servfail.example.net for SPF (SERVFAIL); the lookup count may be incomplete."
            ),
            (
                "spf_lookup_failed",
                "warning",
                "Couldn't look up servfail.example.org for SPF (SERVFAIL); the lookup count may be incomplete."
            ),
        ]
    );
}

#[test]
fn spf_is_evaluated_for_a_sending_address() {
    let stub = DnsStub::new();
    let cases = [
        (
            "eval.example.net",
            "192.0.2.66",
            "fail",
            "-ip4:192.0.2.66",
            j!([]),
        ),
        (
            "eval.example.net",
            "192.0.2.27",
            "pass",
            "a:mx1.example.net/30",
            j!([]),
        ),
        ("eval.example.net", "192.0.2.200", "pass", "mx/24", j!([])),
        (
            "eval.example.net",
            "2001:db8:1::5",
            "pass",
            "ip6:2001:db8:1::/48",
            j!([]),
        ),
        (
            "eval.example.net",
            "198.51.100.20",
            "pass",
            "exists:%{l}.%{ir}.%{v}._ok.%{d2}",
            j!([]),
        ),
        (
            "eval.example.net",
            "203.0.113.5",
            "pass",
            "ip4:203.0.113.0/24",
            j!(["include:soft.example.net"]),
        ),
        (
            "eval.example.net",
            "2001:db8::99",
            "neutral",
            "?all",
            j!([]),
        ),
        ("soft.example.net", "192.0.2.1", "softfail", "~all", j!([])),
        (
            "spf.example.net",
            "198.51.100.7",
            "pass",
            "ip4:198.51.100.0/24",
            j!(["include:_spf.example.net", "include:_inner.example.net"]),
        ),
        (
            "spf.example.net",
            "::ffff:192.0.2.5",
            "pass",
            "ip4:192.0.2.0/24",
            j!([]),
        ),
        (
            "redirect.example.net",
            "198.51.100.7",
            "pass",
            "ip4:198.51.100.0/24",
            j!(["redirect=_spf.example.net", "include:_inner.example.net"]),
        ),
        (
            "ptr.example.net",
            "192.0.2.10",
            "pass",
            "ptr:example.com",
            j!([]),
        ),
        (
            "ptr.example.net",
            "198.51.100.30",
            "pass",
            "exists:%{i}._ip.%{d}",
            j!([]),
        ),
        ("ptr.example.net", "198.51.100.31", "fail", "-all", j!([])),
        (
            "many.example.net",
            "203.0.113.1",
            "permerror",
            "include:_n6.example.net",
            j!([]),
        ),
        (
            "void.example.net",
            "203.0.113.1",
            "permerror",
            "exists:gone.example.org",
            j!([]),
        ),
        (
            "syntax.example.net",
            "203.0.113.1",
            "permerror",
            "inlcude:_spf.example.net",
            j!([]),
        ),
        (
            "failing.example.net",
            "203.0.113.1",
            "temperror",
            "include:servfail.example.net",
            j!([]),
        ),
    ];
    for (domain, ip, result, matched, via) in cases {
        let (_, r) = email(&stub, domain, &["--spf-ip", ip]);
        let want = j!({ "ip": ip, "result": result, "matched": matched, "via": via });
        assert_eq!(r["email"]["spf"]["result"], want, "{domain} {ip}");
    }
    let message = |domain, ip| {
        let (_, r) = email(&stub, domain, &["--spf-ip", ip]);
        let (severity, message, hint) = finding(&r, "spf_ip_result");
        (severity.to_string(), message.to_string(), hint.clone())
    };
    let none = j!(null);
    let says = |s: &str, m: &str, h: &Value| (s.to_string(), m.to_string(), h.clone());
    assert_eq!(
        message("spf.example.net", "198.51.100.7"),
        says(
            "info",
            "SPF for 198.51.100.7: pass (matched ip4:198.51.100.0/24 via include:_spf.example.net → include:_inner.example.net).",
            &none
        )
    );
    assert_eq!(
        message("eval.example.net", "192.0.2.66"),
        says(
            "error",
            "SPF for 192.0.2.66: fail (matched -ip4:192.0.2.66).",
            &j!("Add this sender to the SPF record if it is yours.")
        )
    );
    assert_eq!(
        message("soft.example.net", "192.0.2.1"),
        says(
            "warning",
            "SPF for 192.0.2.1: softfail (matched ~all).",
            &none
        )
    );
    assert_eq!(
        message("many.example.net", "203.0.113.1"),
        says(
            "error",
            "SPF for 203.0.113.1: permerror at include:_n6.example.net.",
            &none
        )
    );
    assert_eq!(
        message("failing.example.net", "203.0.113.1"),
        says(
            "warning",
            "SPF for 203.0.113.1: temperror at include:servfail.example.net.",
            &none
        )
    );
    assert_eq!(
        message("noall.example.net", "203.0.113.1"),
        says(
            "warning",
            "SPF for 203.0.113.1: neutral; no term matched.",
            &none
        )
    );
    let (_, r) = email(&stub, "nomail.example.net", &["--spf-ip", "192.0.2.1"]);
    assert_eq!(r["email"]["spf"], j!(null));
    assert_eq!(
        finding(&r, "spf_ip_result"),
        (
            "warning",
            "SPF for 192.0.2.1: none; no term matched.",
            &none
        )
    );
    let (_, r) = email(&stub, "multi.example.net", &["--spf-ip", "192.0.2.1"]);
    assert_eq!(r["email"]["spf"]["result"]["result"], "permerror");
}

#[test]
fn spf_ip_must_be_an_address() {
    let (code, out, err) = common::run(&["example.com", "--spf-ip", "mail.example.com"], &[]);
    assert_eq!((code, out.as_str()), (2, ""));
    assert_eq!(
        err,
        "✗ --spf-ip mail.example.com isn't an IP address.\n  Pass the sending server's address, e.g. --spf-ip 192.0.2.10.\n"
    );
}
