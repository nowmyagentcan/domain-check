mod common;

use std::net::SocketAddr;

use common::{DnsStub, closed_udp_port, json};
use domain_check::Ports;
use domain_check::dns::{
    Ask, Failure, Message, RECURSIVE, RecordType, Resolver, ResponseCode, records, value,
};
use serde_json::{Value, json as j};

const AUTHORITATIVE: Ask = Ask {
    rd: false,
    cd: false,
    dnssec_ok: true,
};

fn block_on<T>(f: impl Future<Output = T>) -> T {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(f)
}

fn via(stub: &DnsStub) -> Resolver {
    Resolver::new(Some(stub.addr().parse().unwrap()), Ports::default(), false).unwrap()
}

fn values(m: &Message, t: RecordType) -> Vec<String> {
    records(m, t).map(|r| value(&r.data)).collect()
}

#[test]
fn raw_queries_reach_loopback_servers_only_through_the_port_swap() {
    let stub = DnsStub::new();
    let ports = Ports::parse(&stub.ports()).unwrap();
    let r = Resolver::new(Some(stub.addr().parse().unwrap()), ports, false).unwrap();
    for server in ["127.0.0.1:53", "[::1]:53"] {
        let server: SocketAddr = server.parse().unwrap();
        let m = block_on(r.query(server, "example.com", RecordType::A, AUTHORITATIVE)).unwrap();
        assert!(m.metadata.authoritative && !m.metadata.recursion_desired);
        assert_eq!(values(&m, RecordType::A), ["192.0.2.10"]);
        let asked = stub.queries().pop().unwrap();
        assert_eq!(
            (asked.at, asked.rd, asked.dnssec_ok),
            (server.ip(), false, true)
        );
    }
    let n = stub.queries().len();
    let unswapped = via(&stub);
    let to53 = "127.0.0.1:53".parse().unwrap();
    let _ = block_on(unswapped.query(to53, "example.com", RecordType::A, AUTHORITATIVE));
    assert_eq!(
        stub.queries().len(),
        n,
        "a query without the swap went to port 53"
    );
}

#[test]
fn resolver_lookups_set_rd_and_ask_for_ad() {
    let stub = DnsStub::new();
    let m = block_on(via(&stub).lookup("example.com", RecordType::MX)).unwrap();
    let h = &m.metadata;
    assert!(h.recursion_desired && h.authentic_data && !h.authoritative);
    assert_eq!(
        values(&m, RecordType::MX),
        ["20 mx2.example.net", "10 mx1.example.net"]
    );
    let asked = &stub.queries()[0];
    assert!(asked.rd && asked.ad && !asked.cd && !asked.dnssec_ok && !asked.tcp);
}

#[test]
fn checking_disabled_is_sent_when_asked() {
    let stub = DnsStub::new();
    let cd = Ask {
        cd: true,
        ..RECURSIVE
    };
    let server = stub.addr().parse().unwrap();
    let m = block_on(via(&stub).query(server, "example.com", RecordType::SOA, cd)).unwrap();
    assert!(m.metadata.checking_disabled);
    assert!(stub.queries()[0].cd);
}

#[test]
fn truncated_answers_are_asked_again_over_tcp() {
    let stub = DnsStub::new();
    let m = block_on(via(&stub).lookup("big.example.com", RecordType::TXT)).unwrap();
    assert_eq!(values(&m, RecordType::TXT).len(), 40);
    let tcp: Vec<_> = stub.queries().iter().map(|q| q.tcp).collect();
    assert_eq!(tcp, [false, true]);
}

#[test]
fn response_codes_come_back_as_answers() {
    let stub = DnsStub::new();
    let r = via(&stub);
    for (name, code) in [
        ("nope.example.com", ResponseCode::NXDomain),
        ("servfail.example.com", ResponseCode::ServFail),
        ("refused.example.com", ResponseCode::Refused),
        ("example.com", ResponseCode::NoError),
    ] {
        let m = block_on(r.lookup(name, RecordType::CNAME)).unwrap();
        assert_eq!(m.metadata.response_code, code, "{name}");
    }
    let nodata = block_on(r.lookup("example.com", RecordType::CNAME)).unwrap();
    assert!(nodata.answers.is_empty());
    assert_eq!(nodata.authorities[0].record_type(), RecordType::SOA);
}

#[test]
fn a_silent_server_is_a_timeout_after_two_tries() {
    let stub = DnsStub::new();
    let started = std::time::Instant::now();
    let e = block_on(via(&stub).lookup("silent.example.com", RecordType::A)).unwrap_err();
    assert_eq!(e, Failure::Timeout);
    assert_eq!(stub.queries().len(), 2);
    let took = started.elapsed().as_secs_f64();
    assert!((3.9..6.0).contains(&took), "{took} s");
}

#[test]
fn a_closed_port_fails_without_an_answer() {
    let r = Resolver::new(Some(closed_udp_port()), Ports::default(), false).unwrap();
    let e = block_on(r.lookup("example.com", RecordType::A)).unwrap_err();
    assert!(matches!(e, Failure::Timeout | Failure::Refused), "{e:?}");
}

/// `check <domain> --checks dns` against the stub: the exit code and the domain's report.
fn dns_report(stub: &DnsStub, domain: &str) -> (i32, Value) {
    let (code, v) = json(&[domain, "--checks", "dns", "--dns", &stub.addr()], &[]);
    (code, v["reports"][0].clone())
}

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
fn the_dns_section_lists_every_record_type_with_ttls() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "example.com");
    assert_eq!(code, 0, "{r}");
    let dns = &r["dns"];
    let rr = |value: &str, ttl| j!({ "value": value, "ttl": ttl });
    let soa = "ns1.example.com hostmaster.example.com 2026103001 7200 3600 1209600 300";
    let records = j!({
        "A": [rr("192.0.2.10", 300)],
        "AAAA": [rr("2001:db8::10", 300)],
        "CNAME": [],
        "MX": [rr("20 mx2.example.net", 3600), rr("10 mx1.example.net", 3600)],
        "NS": [rr("ns1.example.net", 86400), rr("ns2.example.net", 86400)],
        "TXT": [rr("v=spf1 ip4:192.0.2.0/24 -all", 300)],
        "CAA": [rr("0 issue \"letsencrypt.org\"", 3600)],
        "SOA": [rr(soa, 3600)],
        "HTTPS": [rr("1 . alpn=h2,h3", 300)],
        "DS": [rr("12345 13 2 abcd", 86400)],
        "DNSKEY": [rr("257 3 13 AQID", 3600)],
    });
    assert_eq!(dns["records"], records);
    assert_eq!((&dns["status"], &dns["reason"]), (&j!("ok"), &Value::Null));
    assert_eq!(dns["resolver"], stub.addr());
    assert_eq!(
        (&dns["exists"], &dns["zone"], &dns["errors"]),
        (&j!(true), &j!("example.com"), &j!({}))
    );
    assert_eq!(dns["cname_chain"], j!([]));
    let caa = j!({ "found_at": "example.com", "records": ["0 issue \"letsencrypt.org\""] });
    assert_eq!(dns["caa"], caa);
    assert!(codes(&r).is_empty());
    // The JSON keeps the record types in the documented order.
    let args = ["example.com", "-c", "dns", "--dns", &stub.addr(), "--json"];
    let (_, out, _) = common::run(&args, &[]);
    let order = [
        "\"A\":",
        "\"AAAA\":",
        "\"CNAME\":",
        "\"MX\":",
        "\"DNSKEY\":",
    ];
    let at: Vec<_> = order.iter().map(|k| out.find(k).unwrap()).collect();
    assert!(at.is_sorted(), "{out}");
}

#[test]
fn cname_chains_are_followed_and_caa_found_at_a_parent() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "www.example.com");
    assert_eq!(code, 0);
    let dns = &r["dns"];
    assert_eq!(dns["cname_chain"], j!(["www.example.com", "example.com"]));
    assert_eq!(dns["zone"], "example.com");
    assert_eq!(dns["caa"]["found_at"], "example.com");
    assert_eq!(dns["records"]["CNAME"][0]["value"], "example.com");
    assert_eq!(dns["records"]["A"][0]["value"], "192.0.2.10");
    assert!(codes(&r).is_empty());

    let (code, r) = dns_report(&stub, "c1.example.com");
    assert_eq!(code, 0, "warnings don't change the exit code");
    let chain = r["dns"]["cname_chain"].as_array().unwrap();
    assert_eq!((chain.len(), &chain[8]), (9, &j!("c9.example.com")));
    let message =
        "The CNAME chain for c1.example.com has more than 8 steps; some resolvers stop at 8.";
    let hint = j!("Point the name closer to its final target.");
    assert_eq!(finding(&r, "cname_chain_long"), ("warning", message, &hint));
    let (_, r) = dns_report(&stub, "c3.example.com");
    assert_eq!(r["dns"]["cname_chain"].as_array().unwrap().len(), 8);
    assert!(codes(&r).is_empty());
}

#[test]
fn broken_cnames_are_errors_or_warnings() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "loop1.example.com");
    assert_eq!(code, 1);
    let message =
        "The CNAME chain loops: loop1.example.com → loop2.example.com → loop1.example.com.";
    let hint = j!("Point one of the names at a real address.");
    assert_eq!(finding(&r, "cname_loop"), ("error", message, &hint));

    let (code, r) = dns_report(&stub, "dangling.example.com");
    assert_eq!(code, 0);
    assert_eq!(r["dns"]["exists"], true);
    let message =
        "dangling.example.com is a CNAME for gone.example.net, which doesn't exist (NXDOMAIN).";
    let hint = j!(
        "If you no longer use that service, delete the CNAME: someone else could claim gone.example.net."
    );
    assert_eq!(finding(&r, "dangling_cname"), ("warning", message, &hint));
    let chain = j!(["dangling.example.com", "gone.example.net"]);
    assert_eq!(r["dns"]["cname_chain"], chain);

    let (code, r) = dns_report(&stub, "apex.example.net");
    assert_eq!((code, &r["dns"]["zone"]), (1, &j!("apex.example.net")));
    let message = "apex.example.net is the zone apex and also has a CNAME, which DNS doesn't allow (RFC 1034 §3.6.2).";
    let hint = j!("Use A/AAAA records, or your DNS host's ALIAS/flattening feature.");
    assert_eq!(finding(&r, "cname_at_apex"), ("error", message, &hint));
}

#[test]
fn missing_names_records_and_caa_are_reported() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "nope.example.com");
    assert_eq!(code, 1);
    let dns = &r["dns"];
    assert_eq!(
        (&dns["exists"], &dns["zone"], &dns["caa"]),
        (&j!(false), &j!("example.com"), &Value::Null)
    );
    let records = dns["records"].as_object().unwrap();
    assert_eq!(records.len(), 11);
    assert!(records.values().all(|v| v == &j!([])));
    let message = "nope.example.com doesn't exist in DNS (NXDOMAIN).";
    let hint = j!("Check the spelling; Registration shows whether it is registered.");
    assert_eq!(finding(&r, "nxdomain"), ("error", message, &hint));
    assert_eq!(codes(&r), ["nxdomain"]);

    let (code, r) = dns_report(&stub, "noaddr.example.com");
    assert_eq!(code, 0);
    let message = "noaddr.example.com has no A or AAAA record, so it has no website address.";
    assert_eq!(finding(&r, "no_address"), ("info", message, &Value::Null));
    assert_eq!(r["dns"]["caa"]["found_at"], "example.com");

    let before = stub.queries().len();
    let (code, r) = dns_report(&stub, "example.net");
    assert_eq!(code, 0);
    let message =
        "No CAA record: any certificate authority may issue certificates for example.net.";
    let hint = j!("Add one naming your CA, e.g. 0 issue \"letsencrypt.org\".");
    assert_eq!(finding(&r, "no_caa"), ("info", message, &hint));
    let caa: Vec<_> = stub.queries()[before..]
        .iter()
        .filter(|q| q.qtype == RecordType::CAA)
        .map(|q| q.name.clone())
        .collect();
    assert_eq!(caa, ["example.net"], "the climb stops before the TLD");
}

#[test]
fn servfail_is_an_error_with_the_failed_types() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "servfail.example.com");
    assert_eq!(code, 1);
    let dns = &r["dns"];
    assert_eq!((&dns["status"], &dns["zone"]), (&j!("ok"), &Value::Null));
    let errors = dns["errors"].as_object().unwrap();
    assert_eq!(errors.len(), 11);
    assert!(errors.values().all(|e| e == "SERVFAIL"));
    let message = "The resolver couldn't get an answer for servfail.example.com (SERVFAIL).";
    let hint = j!("Its nameservers may be down or its DNSSEC broken; see Propagation and DNSSEC.");
    assert_eq!(finding(&r, "dns_servfail"), ("error", message, &hint));
}

#[test]
fn a_silent_resolver_makes_the_section_unavailable() {
    let stub = DnsStub::start(|_| None);
    let (code, r) = dns_report(&stub, "example.com");
    assert_eq!(code, 3);
    let reason = format!("Couldn't reach the DNS resolver {}: timeout.", stub.addr());
    let dns = &r["dns"];
    assert_eq!(
        (&dns["status"], &dns["reason"]),
        (&j!("unavailable"), &j!(reason))
    );
    assert_eq!(dns["records"], Value::Null);
    assert!(codes(&r).is_empty());
}
