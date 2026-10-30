mod common;

use common::web::Web;
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

/// The DMARC names the stub was asked for, in order.
fn dmarc_queries(stub: &DnsStub) -> Vec<String> {
    let asked = stub.queries().into_iter().map(|q| q.name);
    asked.filter(|n| n.starts_with("_dmarc.")).collect()
}

#[test]
fn dmarc_is_found_at_the_domain_or_up_the_tree() {
    let walks = [
        (
            "three.example.org",
            vec!["three.example.org", "example.org", "org"],
        ),
        (
            "a.b.c.d.e.f.example.org",
            vec![
                "a.b.c.d.e.f.example.org",
                "b.c.d.e.f.example.org",
                "c.d.e.f.example.org",
                "d.e.f.example.org",
                "e.f.example.org",
                "f.example.org",
                "example.org",
                "org",
            ],
        ),
        (
            "a.b.c.d.e.f.g.h.i.example.org",
            vec![
                "a.b.c.d.e.f.g.h.i.example.org",
                "e.f.g.h.i.example.org",
                "f.g.h.i.example.org",
                "g.h.i.example.org",
                "h.i.example.org",
                "i.example.org",
                "example.org",
                "org",
            ],
        ),
        (
            "a.b.c.d.e.f.g.h.i.example.net",
            vec![
                "a.b.c.d.e.f.g.h.i.example.net",
                "e.f.g.h.i.example.net",
                "f.g.h.i.example.net",
                "g.h.i.example.net",
                "h.i.example.net",
                "i.example.net",
                "example.net",
            ],
        ),
    ];
    for (domain, names) in walks {
        let stub = DnsStub::new();
        let (_, r) = email(&stub, domain, &[]);
        let want: Vec<_> = names.iter().map(|n| format!("_dmarc.{n}")).collect();
        assert_eq!(dmarc_queries(&stub), want, "{domain}");
        let found = !r["email"]["dmarc"].is_null();
        assert_eq!(found, domain.ends_with(".net"), "{domain}");
    }
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "three.example.org", &[]);
    assert_eq!(code, 1);
    assert_eq!(
        finding(&r, "dmarc_none"),
        (
            "error",
            "No DMARC record for three.example.org.",
            &j!(
                "Publish _dmarc.three.example.org TXT \"v=DMARC1; p=none; rua=mailto:<you>\", then tighten p."
            )
        )
    );
    let (_, r) = email(&stub, "a.b.c.d.e.f.g.h.i.example.net", &[]);
    let dmarc = &r["email"]["dmarc"];
    assert_eq!(
        (&dmarc["found_at"], &dmarc["inherited"]),
        (&j!("_dmarc.example.net"), &j!(true))
    );
    assert_eq!(
        found(&r, "dmarc_"),
        [
            (
                "dmarc_sp_none",
                "warning",
                "sp=none leaves subdomains unprotected while p=quarantine."
            ),
            (
                "dmarc_inherited",
                "info",
                "No DMARC record at _dmarc.a.b.c.d.e.f.g.h.i.example.net; the policy at _dmarc.example.net applies."
            ),
        ]
    );
}

#[test]
fn dmarc_tags_report_addresses_and_their_authorisation() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "dmarc.example.net", &[]);
    let rua = [
        "mailto:a@example.net",
        "https://dmarc.example.net/r",
        "mailto:b@example.org!10m",
        "mailto:c@example.com",
    ];
    assert_eq!(
        r["email"]["dmarc"],
        j!({
            "record": "v=DMARC1; p=none; t=y; pct=50; rf=afrf; ri=86400; adkim=x; fo=1:d; rua=mailto:a@example.net,https://dmarc.example.net/r,mailto:b@example.org!10m,mailto:c@example.com; ruf=mailto:f@dmarc.example.net",
            "found_at": "_dmarc.dmarc.example.net",
            "inherited": false,
            "tags": { "p": "none", "sp": null, "np": null, "adkim": null, "aspf": null, "t": "y", "psd": null, "fo": "1:d", "rua": rua, "ruf": ["mailto:f@dmarc.example.net"] },
            "historic_tags": ["pct", "rf", "ri"],
            "rua_authorized": [
                { "uri": rua[0], "authorized": null },
                { "uri": rua[1], "authorized": null },
                { "uri": rua[2], "authorized": true },
                { "uri": rua[3], "authorized": false },
            ]
        })
    );
    assert_eq!(
        found(&r, "dmarc_"),
        [
            (
                "dmarc_syntax",
                "error",
                "The DMARC record at _dmarc.dmarc.example.net is invalid: adkim=x isn't valid."
            ),
            (
                "dmarc_p_none",
                "warning",
                "The DMARC policy is p=none, so receivers take no action on mail that fails."
            ),
            (
                "dmarc_rua_scheme",
                "warning",
                "rua= entry https://dmarc.example.net/r isn't a mailto: address."
            ),
            (
                "dmarc_rua_unauthorized",
                "warning",
                "Reports to mailto:c@example.com won't be sent: example.com hasn't published dmarc.example.net._report._dmarc.example.com (RFC 9990 §4)."
            ),
            (
                "dmarc_historic_tag",
                "info",
                "pct= is no longer part of DMARC (RFC 9989); receivers ignore it."
            ),
            (
                "dmarc_historic_tag",
                "info",
                "rf= is no longer part of DMARC (RFC 9989); receivers ignore it."
            ),
            (
                "dmarc_historic_tag",
                "info",
                "ri= is no longer part of DMARC (RFC 9989); receivers ignore it."
            ),
            (
                "dmarc_testing",
                "info",
                "t=y: the DMARC policy is in test mode, so receivers may apply one step less (RFC 9989)."
            ),
        ]
    );
    let hints: Vec<_> = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["code"] == "dmarc_historic_tag")
        .map(|f| f["hint"].clone())
        .collect();
    assert_eq!(
        hints,
        [j!("Use t=y for a test phase instead."), j!(null), j!(null)]
    );
    // Asked together, so in any order.
    let mut asked: Vec<_> = stub
        .queries()
        .into_iter()
        .map(|q| q.name)
        .filter(|n| n.contains("._report."))
        .collect();
    asked.sort();
    assert_eq!(
        asked,
        [
            "dmarc.example.net._report._dmarc.example.com",
            "dmarc.example.net._report._dmarc.example.org"
        ]
    );
}

#[test]
fn broken_and_doubled_dmarc_records() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "twodmarc.example.net", &[]);
    assert_eq!(r["email"]["dmarc"]["found_at"], "_dmarc.example.net");
    assert_eq!(
        finding(&r, "dmarc_multiple"),
        (
            "error",
            "_dmarc.twodmarc.example.net has 2 DMARC records, so receivers ignore all of them.",
            &j!("Keep exactly one.")
        )
    );
    let (_, r) = email(&stub, "baddmarc.example.net", &[]);
    assert_eq!(r["email"]["dmarc"]["found_at"], "_dmarc.example.net");
    assert_eq!(
        finding(&r, "dmarc_syntax"),
        (
            "error",
            "The DMARC record at _dmarc.baddmarc.example.net is invalid: it doesn't start with v=DMARC1.",
            &j!("Fix it; e.g. \"v=DMARC1; p=quarantine; rua=mailto:<you>\".")
        )
    );
    let (_, r) = email(&stub, "badp.example.net", &[]);
    assert_eq!(r["email"]["dmarc"]["tags"]["p"], "none");
    let codes: Vec<_> = found(&r, "dmarc_").iter().map(|f| f.2).collect();
    assert_eq!(
        codes,
        [
            "The DMARC record at _dmarc.badp.example.net is invalid: p=block isn't none, quarantine or reject.",
            "The DMARC policy is p=none, so receivers take no action on mail that fails."
        ]
    );
    let (_, r) = email(&stub, "nop.example.net", &[]);
    assert_eq!(r["email"]["dmarc"]["tags"]["p"], j!(null));
    assert_eq!(
        found(&r, "dmarc_"),
        [
            (
                "dmarc_syntax",
                "error",
                "The DMARC record at _dmarc.nop.example.net is invalid: p= is missing."
            ),
            (
                "dmarc_no_rua",
                "info",
                "No rua= address, so nobody receives DMARC aggregate reports."
            ),
        ]
    );
    let (_, r) = email(&stub, "servfail.example.net", &[]);
    assert_eq!(r["email"]["dmarc"], j!(null));
    assert_eq!(r["email"]["errors"]["dmarc"], "SERVFAIL");
    assert!(found(&r, "dmarc_").is_empty());
}

/// The DKIM keys found for these selectors at dkim.example.net: selector, type and bits.
fn keys(stub: &DnsStub, selectors: &[&str]) -> (Vec<(String, String, Value)>, Value) {
    let args: Vec<_> = selectors.iter().flat_map(|s| ["-s", s]).collect();
    let (_, r) = email(stub, "dkim.example.net", &args);
    let keys = r["email"]["dkim"]["keys"].as_array().unwrap();
    let text = |k: &Value, f: &str| k[f].as_str().unwrap_or_default().to_string();
    let got = keys
        .iter()
        .map(|k| (text(k, "selector"), text(k, "key_type"), k["bits"].clone()))
        .collect();
    (got, r)
}

#[test]
fn dkim_keys_have_their_type_and_size() {
    let stub = DnsStub::new();
    let selectors = [
        "rsa1024", "rsa2048", "rsa4096", "bare1024", "bare2048", "bare4096", "ed",
    ];
    let (got, r) = keys(&stub, &selectors);
    let want = [1024, 2048, 4096, 1024, 2048, 4096, 256];
    let want: Vec<_> = selectors
        .iter()
        .zip(want)
        .map(|(s, bits)| {
            let t = if *s == "ed" { "ed25519" } else { "rsa" };
            (s.to_string(), t.to_string(), j!(bits))
        })
        .collect();
    assert_eq!(got, want);
    let dkim = &r["email"]["dkim"];
    assert_eq!(
        (&dkim["given"], &dkim["selectors"]),
        (&j!(true), &j!(selectors))
    );
    let key = &dkim["keys"][0];
    assert_eq!(
        (
            &key["name"],
            &key["revoked"],
            &key["testing"],
            &key["error"]
        ),
        (
            &j!("rsa1024._domainkey.dkim.example.net"),
            &j!(false),
            &j!(false),
            &j!(null)
        )
    );
    assert!(
        key["record"]
            .as_str()
            .unwrap()
            .starts_with("v=DKIM1; k=rsa; p=MI")
    );
    assert_eq!(
        found(&r, "dkim_"),
        [
            (
                "dkim_weak_key",
                "warning",
                "The DKIM key at rsa1024._domainkey.dkim.example.net is RSA 1024 bits; 2048 is recommended (RFC 8301)."
            ),
            (
                "dkim_weak_key",
                "warning",
                "The DKIM key at bare1024._domainkey.dkim.example.net is RSA 1024 bits; 2048 is recommended (RFC 8301)."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "dkim_weak_key").2,
        "Generate a 2048-bit key under a new selector and switch to it."
    );
}

#[test]
fn dkim_records_that_are_weak_revoked_testing_broken_or_missing() {
    let stub = DnsStub::new();
    let selectors = [
        "small", "revoked", "testing", "badb64", "other", "nothere", "servfail",
    ];
    let (got, r) = keys(&stub, &selectors);
    let t = |s: &str, k: &str, b: Value| (s.to_string(), k.to_string(), b);
    assert_eq!(
        got,
        [
            t("small", "rsa", j!(512)),
            t("revoked", "rsa", j!(null)),
            t("testing", "rsa", j!(2048)),
            t("badb64", "rsa", j!(null)),
            t("servfail", "unknown", j!(null)),
        ]
    );
    let failed = &r["email"]["dkim"]["keys"][4];
    assert_eq!(
        (&failed["record"], &failed["error"]),
        (&j!(null), &j!("SERVFAIL"))
    );
    assert_eq!(
        found(&r, "dkim_"),
        [
            (
                "dkim_syntax",
                "error",
                "The DKIM record at badb64._domainkey.dkim.example.net is invalid: p= isn't valid base64."
            ),
            (
                "dkim_weak_key",
                "error",
                "The DKIM key at small._domainkey.dkim.example.net is RSA 512 bits; receivers reject keys under 1024 (RFC 8301)."
            ),
            (
                "dkim_not_found",
                "warning",
                "No DKIM key at other._domainkey.dkim.example.net."
            ),
            (
                "dkim_not_found",
                "warning",
                "No DKIM key at nothere._domainkey.dkim.example.net."
            ),
            (
                "dkim_revoked",
                "info",
                "The DKIM key at revoked._domainkey.dkim.example.net is revoked (empty p=)."
            ),
            (
                "dkim_testing",
                "info",
                "The DKIM key at testing._domainkey.dkim.example.net has t=y (testing)."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "dkim_not_found").2,
        "Pass --dkim-selector with the s= value from a DKIM-Signature header of your mail."
    );
    assert_eq!(
        finding(&r, "dkim_syntax").2,
        "Copy the record again from your mail provider."
    );
}

#[test]
fn without_selectors_the_8_common_ones_are_tried() {
    let stub = DnsStub::new();
    let (got, r) = keys(&stub, &[]);
    assert_eq!(got, [("google".to_string(), "rsa".to_string(), j!(2048))]);
    let common = [
        "default",
        "google",
        "selector1",
        "selector2",
        "k1",
        "s1",
        "s2",
        "dkim",
    ];
    let dkim = &r["email"]["dkim"];
    assert_eq!(
        (&dkim["given"], &dkim["selectors"]),
        (&j!(false), &j!(common))
    );
    assert!(found(&r, "dkim_").is_empty());
    let (_, r) = email(&stub, "nomail.example.net", &[]);
    assert_eq!(
        found(&r, "dkim_"),
        [(
            "dkim_not_found",
            "info",
            "No DKIM key under the 8 common selectors; this doesn't mean DKIM is missing."
        )]
    );
    let (code, _, err) = common::run(&["example.com", "-s", "a b"], &[]);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        "✗ 'a b' isn't a valid DKIM selector.\n  Use the s= value from a DKIM-Signature header.\n"
    );
}

/// `check <domain> --checks email` with the web mock serving MTA-STS policies and BIMI files.
fn fetched(stub: &DnsStub, web: &Web, domain: &str) -> Value {
    let dns = stub.addr();
    let args = [
        domain,
        "-c",
        "email",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let ports = web.ports(stub);
    let (_, v) = json(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())]);
    v["reports"][0].clone()
}

#[test]
fn mta_sts_tls_rpt_and_bimi_records_are_read() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let r = fetched(&stub, &web, "sts.example.net");
    let e = &r["email"];
    let policy = j!({ "url": "https://mta-sts.sts.example.net/.well-known/mta-sts.txt",
        "mode": "enforce", "mx": ["mx1.example.net"], "max_age": 604800, "error": null });
    assert_eq!(
        (&e["mta_sts"], &e["tls_rpt"], &e["bimi"]),
        (
            &j!({ "record": "v=STSv1; id=20261030", "id": "20261030", "policy": policy }),
            &j!({ "record": "v=TLSRPTv1; rua=mailto:tls@sts.example.net,https://report.example.net/tls",
                  "rua": ["mailto:tls@sts.example.net", "https://report.example.net/tls"] }),
            &j!({ "record": "v=BIMI1; l=https://sts.example.net/logo.svg; a=https://sts.example.net/vmc.pem",
                  "logo": "https://sts.example.net/logo.svg", "certificate": "https://sts.example.net/vmc.pem",
                  "logo_check": { "fetched": true, "content_type": "image/svg+xml", "tiny_ps": true, "error": null },
                  "certificate_check": { "fetched": true, "pem": true, "error": null } }),
        )
    );
    for prefix in ["mta_sts", "tls_rpt", "bimi"] {
        assert_eq!(found(&r, prefix), [], "{prefix}");
    }
    assert_eq!(e["errors"], j!({}));
    let hits: Vec<_> = web.hits().into_iter().map(|h| (h.host, h.path)).collect();
    assert_eq!(hits.len(), 3, "{hits:?}");
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let args = [
        "sts.example.net",
        "-c",
        "email",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let (_, out, _) = common::run(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", &ports)]);
    let line = out.lines().find(|l| l.starts_with("Email")).unwrap();
    assert_eq!(
        line,
        "Email        SPF none · DMARC p=reject · DKIM none of 8 common selectors · MTA-STS enforce · TLS-RPT yes · BIMI logo"
    );
}

#[test]
fn mta_sts_policies_load_only_as_rfc_8461_allows() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let unavailable = |domain: &str| {
        let r = fetched(&stub, &web, domain);
        let found = found(&r, "mta_sts_policy");
        assert_eq!(found.len(), 1, "{domain}: {found:?}");
        assert_eq!(found[0].0, "mta_sts_policy_unavailable");
        assert_eq!(r["email"]["mta_sts"]["policy"]["mode"], Value::Null);
        found[0].2.to_string()
    };
    let at = |d: &str, why: &str| {
        format!(
            "The MTA-STS policy at https://mta-sts.{d}/.well-known/mta-sts.txt couldn't be loaded: {why}."
        )
    };
    let cases = [
        (
            "stsredirect.example.net",
            "it redirects, which MTA-STS forbids".to_string(),
        ),
        ("sts404.example.net", "HTTP 404".into()),
        ("stsbig.example.net", "it's larger than 64 KB".into()),
        (
            "stsname.example.net",
            "the certificate isn't valid for mta-sts.stsname.example.net".into(),
        ),
        (
            "stsonly.example.net",
            "connection failed: mta-sts.stsonly.example.net has no A or AAAA record".into(),
        ),
    ];
    for (domain, why) in cases {
        assert_eq!(unavailable(domain), at(domain, &why));
    }
    let r = fetched(&stub, &web, "sts404.example.net");
    assert_eq!(
        finding(&r, "mta_sts_policy_unavailable").2,
        "Senders that already cached the policy keep using it; fix the policy host."
    );
    let r = fetched(&stub, &web, "stssyntax.example.net");
    let problems: Vec<_> = found(&r, "mta_sts_policy")
        .into_iter()
        .map(|f| f.2)
        .collect();
    assert_eq!(
        problems,
        [
            "The MTA-STS policy is invalid: version isn't STSv1.",
            "The MTA-STS policy is invalid: max_age forever isn't a number from 0 to 31557600.",
            "The MTA-STS policy is invalid: mode block isn't enforce, testing or none.",
            "The MTA-STS policy is invalid: it has no mx line.",
        ]
    );
    assert_eq!(
        finding(&r, "mta_sts_policy_syntax").2,
        "See RFC 8461 §3.2 for the format."
    );
    // Every MX host must match an mx line; testing mode is reported.
    let r = fetched(&stub, &web, "stsmx.example.net");
    assert_eq!(
        r["email"]["mta_sts"]["policy"]["mx"],
        j!(["mx1.example.net", "*.mail.example.net"])
    );
    assert_eq!(
        found(&r, "mta_sts"),
        [
            (
                "mta_sts_mx_not_covered",
                "error",
                "MX host mx2.example.net doesn't match the MTA-STS policy's mx lines, so senders in enforce mode will refuse it."
            ),
            (
                "mta_sts_testing",
                "info",
                "MTA-STS is in testing mode: failures are reported, not enforced."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "mta_sts_mx_not_covered").2,
        "Add \"mx: mx2.example.net\" (or a matching *. pattern) to the policy and change its id."
    );
    // Without --allow-private the loopback policy host isn't contacted.
    let dns = stub.addr();
    let before = web.connections();
    let (_, v) = json(&["sts.example.net", "-c", "email", "--dns", &dns], &[]);
    let r = &v["reports"][0];
    assert_eq!(found(r, "mta_sts"), []);
    let private: Vec<_> = found(r, "private_address")
        .into_iter()
        .map(|f| f.2)
        .collect();
    assert_eq!(
        private,
        [
            "mta-sts.sts.example.net resolves to 127.0.0.1, a private address, so the email check didn't connect to it.",
            "sts.example.net resolves to 127.0.0.1, a private address, so the email check didn't connect to it.",
        ]
    );
    assert_eq!(web.connections(), before);
}

#[test]
fn bimi_logos_and_certificates_are_fetched() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let r = fetched(&stub, &web, "logo.example.org");
    assert_eq!(
        r["email"]["bimi"]["logo_check"],
        j!({ "fetched": true, "content_type": "image/svg+xml", "tiny_ps": false, "error": null })
    );
    assert_eq!(
        finding(&r, "bimi_logo_format"),
        (
            "warning",
            "The BIMI logo isn't SVG Tiny PS (no baseProfile=\"tiny-ps\").",
            &j!("Export it as SVG Tiny Portable/Secure.")
        )
    );
    let r = fetched(&stub, &web, "stsmx.example.net");
    let b = &r["email"]["bimi"];
    assert_eq!(
        b["logo_check"],
        j!({ "fetched": false, "content_type": null, "tiny_ps": false, "error": "HTTP 404" })
    );
    assert_eq!(
        b["certificate_check"],
        j!({ "fetched": true, "pem": false, "error": "it holds no PEM certificate" })
    );
    assert_eq!(
        found(&r, "bimi_")[..2],
        [
            (
                "bimi_certificate_unavailable",
                "warning",
                "The BIMI certificate at https://stsmx.example.net/vmc.txt couldn't be loaded or isn't PEM: it holds no PEM certificate."
            ),
            (
                "bimi_dmarc_not_enforced",
                "warning",
                "BIMI logos need DMARC p=quarantine or p=reject without test mode; the policy is p=quarantine; sp=none."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "bimi_logo_unavailable").1,
        "The BIMI logo at https://stsmx.example.net/missing.svg couldn't be loaded: HTTP 404."
    );
}

#[test]
fn broken_policy_records_say_what_is_wrong() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "stsbad.example.net", &[]);
    let e = &r["email"];
    assert_eq!(
        (&e["mta_sts"]["id"], &e["bimi"]["logo"]),
        (&j!(null), &j!(null))
    );
    assert_eq!(e["tls_rpt"]["rua"], j!(["ftp://x.example.net"]));
    let mut all = found(&r, "mta_sts");
    all.extend(found(&r, "tls_rpt"));
    all.extend(found(&r, "bimi"));
    assert_eq!(
        all,
        [
            (
                "mta_sts_syntax",
                "error",
                "The _mta-sts record is invalid: it doesn't start with v=STSv1."
            ),
            (
                "mta_sts_syntax",
                "error",
                "The _mta-sts record is invalid: it has no valid id= (1 to 32 letters and digits)."
            ),
            (
                "tls_rpt_syntax",
                "error",
                "The TLS-RPT record is invalid: there are 2 v=TLSRPTv1 records."
            ),
            (
                "tls_rpt_syntax",
                "error",
                "The TLS-RPT record is invalid: ftp://x.example.net isn't a mailto: or https: address."
            ),
            (
                "bimi_syntax",
                "error",
                "The BIMI record is invalid: l= isn't https."
            ),
            (
                "bimi_dmarc_not_enforced",
                "warning",
                "BIMI logos need DMARC p=quarantine or p=reject without test mode; the policy is p=quarantine; sp=none."
            ),
            (
                "bimi_no_certificate",
                "info",
                "No mark certificate (a=); some mailbox providers show BIMI logos only with a VMC or CMC."
            ),
        ]
    );
    assert_eq!(
        finding(&r, "mta_sts_syntax").2,
        "It should look like \"v=STSv1; id=20261030\"."
    );
    assert_eq!(
        finding(&r, "bimi_dmarc_not_enforced").2,
        "Tighten the DMARC policy first."
    );
    let (_, r) = email(&stub, "logo.example.org", &[]);
    assert_eq!(
        finding(&r, "bimi_dmarc_not_enforced").1,
        "BIMI logos need DMARC p=quarantine or p=reject without test mode; the policy is missing."
    );
}

#[test]
fn missing_policies_are_info_unless_mta_sts_needs_reports() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "declined.example.net", &[]);
    assert_eq!(
        found(&r, "mta_sts"),
        [(
            "mta_sts_none",
            "info",
            "No MTA-STS policy, so servers sending mail to declined.example.net may fall back to unencrypted delivery."
        )]
    );
    assert_eq!(
        finding(&r, "mta_sts_none").2,
        "Publish _mta-sts.declined.example.net TXT and a policy at https://mta-sts.declined.example.net/.well-known/mta-sts.txt."
    );
    assert_eq!(
        finding(&r, "tls_rpt_none"),
        (
            "info",
            "No TLS-RPT record, so nobody hears about failed encrypted deliveries.",
            &j!("Publish _smtp._tls.declined.example.net TXT \"v=TLSRPTv1; rua=mailto:<you>\".")
        )
    );
    assert_eq!(
        found(&r, "bimi"),
        [(
            "bimi_declined",
            "info",
            "The BIMI record declines a logo (empty l=)."
        )]
    );
    let (_, r) = email(&stub, "stsonly.example.net", &[]);
    assert_eq!(finding(&r, "tls_rpt_none").0, "warning");
    // A domain that takes no mail needs neither.
    let (_, r) = email(&stub, "nullmx.example.net", &[]);
    assert_eq!(found(&r, "mta_sts"), []);
    assert_eq!(found(&r, "tls_rpt"), []);
    assert_eq!(found(&r, "bimi"), []);
}

#[test]
fn email_stays_within_its_budget_when_answers_go_missing() {
    // Names whose hash falls on 0 never get an answer: about a third of the lookups.
    let lossy = DnsStub::start(|a| {
        let seed = u32::from(u16::from(a.qtype));
        let h = a
            .name
            .bytes()
            .fold(seed, |h, b| h.wrapping_mul(31).wrapping_add(b.into()));
        if h % 3 == 0 {
            None
        } else {
            common::fixtures(a)
        }
    });
    let started = std::time::Instant::now();
    let (_, r) = email(
        &lossy,
        "spf.example.net",
        &["-s", "a", "-s", "b", "-s", "c"],
    );
    let took = started.elapsed().as_secs_f64();
    assert!(took < 20.0, "{took} s");
    assert_eq!(r["email"]["status"], "ok", "{r}");
    let e = &r["email"];
    let failed: usize = [
        e["errors"].as_object().unwrap().len(),
        e["dkim"]["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|k| k["error"] == "timeout")
            .count(),
        e["mx"]["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|h| h["error"] == "timeout")
            .count(),
        found(&r, "spf_lookup_failed").len(),
    ]
    .iter()
    .sum();
    assert!(failed > 0, "{r}");
}

/// The severities of the findings whose code starts with `prefix`.
fn severities<'a>(report: &'a Value, prefix: &str) -> Vec<&'a str> {
    found(report, prefix).into_iter().map(|f| f.1).collect()
}

#[test]
#[ignore = "known bug: DC03"]
fn mx_hosts_without_addresses_are_void_lookups() {
    let stub = DnsStub::new();
    // Three mx terms whose hosts have no address: three void lookups before the ip4 match.
    let (_, r) = email(&stub, "voidmx.example.net", &["--spf-ip", "192.0.2.1"]);
    let spf = &r["email"]["spf"];
    assert!(spf["void_lookups"].as_u64().unwrap() > 2, "{spf}");
    assert_eq!(spf["result"]["result"], "permerror", "{spf}");
    assert_eq!(
        severities(&r, "spf_too_many_void"),
        ["error"],
        "{:?}",
        found(&r, "spf")
    );
}

#[test]
fn terms_after_all_are_never_evaluated() {
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "afterall.example.net", &[]);
    let spf = &r["email"]["spf"];
    assert_eq!(spf["lookups"], 0, "{spf}");
    assert!(
        !severities(&r, "spf").contains(&"error"),
        "{:?}",
        found(&r, "spf")
    );
    assert_ne!(code, 1);
}

#[test]
#[ignore = "known bug: DC06"]
fn a_repeated_dmarc_tag_is_invalid() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "dupdmarc.example.net", &[]);
    assert_eq!(
        severities(&r, "dmarc_syntax"),
        ["error"],
        "{:?}",
        found(&r, "dmarc")
    );
}

#[test]
fn a_record_with_rua_and_no_p_is_read_as_p_none() {
    let stub = DnsStub::new();
    let (code, r) = email(&stub, "ruaonly.example.net", &[]);
    assert_eq!(r["email"]["dmarc"]["tags"]["p"], "none");
    // RFC 9989 §4.7: p is RECOMMENDED; §4.10.1 reads the record as p=none.
    assert!(
        found(&r, "dmarc_syntax").is_empty(),
        "{:?}",
        found(&r, "dmarc")
    );
    assert_eq!(severities(&r, "dmarc_p_none"), ["warning"]);
    assert_eq!(code, 0, "{:?}", found(&r, ""));
}

#[test]
#[ignore = "known bug: DC08"]
fn two_keys_at_one_selector_are_flagged() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "twokeys.example.net", &["-s", "s"]);
    // RFC 6376 §3.6.2.2: with more than one key record the verifier may pick either one.
    assert!(
        severities(&r, "dkim").iter().any(|s| *s != "info"),
        "{:?} {}",
        found(&r, "dkim"),
        r["email"]["dkim"]
    );
}

#[test]
#[ignore = "known bug: DC09"]
fn a_repeated_dkim_tag_makes_the_record_invalid() {
    let stub = DnsStub::new();
    let (_, r) = email(&stub, "duptag.example.net", &["-s", "s"]);
    // RFC 6376 §3.2: a tag name that occurs twice makes the whole tag-list invalid.
    assert_eq!(
        severities(&r, "dkim_syntax"),
        ["error"],
        "{}",
        r["email"]["dkim"]
    );
}

#[test]
#[ignore = "known bug: DC05"]
fn a_repeated_mta_sts_mode_is_a_policy_error() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let r = fetched(&stub, &web, "stsdup.example.net");
    assert!(
        r["email"]["mta_sts"]["policy"]["error"].is_string(),
        "{}",
        r["email"]["mta_sts"]
    );
    assert_eq!(severities(&r, "mta_sts_policy_syntax"), ["error"]);
}
