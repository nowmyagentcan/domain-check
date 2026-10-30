mod common;

use std::collections::BTreeSet;
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
    let dns = stub.addr();
    let args = [domain, "--checks", "dns", "--dns", &dns, "--resolver", &dns];
    let (code, v) = json(&args, &[]);
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
    let dns = stub.addr();
    let args = [
        "example.com",
        "-c",
        "dns",
        "--dns",
        &dns,
        "--resolver",
        &dns,
        "--json",
    ];
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

#[test]
fn dnssec_shows_keys_and_which_resolvers_validated() {
    let stub = DnsStub::new();
    let (_, r) = dns_report(&stub, "example.com");
    let ds = j!({ "key_tag": 12345, "algorithm": 13, "algorithm_name": "ECDSAP256SHA256", "digest_type": 2 });
    let want = j!({ "signed": true, "ds": [ds], "dnskey_algorithms": [13],
                    "validated_by": [stub.addr()], "bogus": false });
    assert_eq!(r["dns"]["dnssec"], want);
    // A second resolver that never answers leaves the first's verdict standing.
    let silent = DnsStub::start(|_| None);
    let args = [
        "example.com",
        "-c",
        "dns",
        "--dns",
        &stub.addr(),
        "--resolver",
        &stub.addr(),
        "--resolver",
        &silent.addr(),
    ];
    let (_, v) = json(&args, &[]);
    assert_eq!(
        v["reports"][0]["dns"]["dnssec"]["validated_by"],
        j!([stub.addr()])
    );
    let soa: Vec<_> = stub
        .queries()
        .into_iter()
        .filter(|q| q.qtype == RecordType::SOA && q.rd)
        .collect();
    assert!(soa.iter().all(|q| q.ad && !q.cd), "{soa:?}");

    // A name below the zone apex reports the zone's keys.
    let (_, r) = dns_report(&stub, "www.example.com");
    assert_eq!(r["dns"]["dnssec"]["signed"], true);
    assert!(
        stub.queries()
            .iter()
            .any(|q| q.name == "example.com" && q.qtype == RecordType::DS)
    );
}

#[test]
fn unsigned_and_weakly_signed_zones_are_reported() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "example.net");
    assert_eq!(code, 0);
    let dnssec = &r["dns"]["dnssec"];
    assert_eq!(
        (&dnssec["signed"], &dnssec["validated_by"]),
        (&j!(false), &j!([]))
    );
    let message = "example.net isn't signed with DNSSEC (no DS record at the parent).";
    assert_eq!(
        finding(&r, "dnssec_unsigned"),
        ("info", message, &Value::Null)
    );

    let (code, r) = dns_report(&stub, "example.org");
    assert_eq!(code, 0);
    assert_eq!(r["dns"]["dnssec"]["ds"][0]["algorithm_name"], "RSASHA1");
    assert_eq!(r["dns"]["dnssec"]["dnskey_algorithms"], j!([5]));
    let message = "example.org is signed with RSASHA1 (algorithm 5), which RFC 8624 says not to use for signing.";
    let hint = j!("Re-sign with ECDSAP256SHA256 (13) or ED25519 (15).");
    assert_eq!(
        finding(&r, "dnssec_weak_algorithm"),
        ("warning", message, &hint)
    );
    assert_eq!(
        codes(&r)
            .iter()
            .filter(|c| **c == "dnssec_weak_algorithm")
            .count(),
        1
    );
    assert!(!codes(&r).contains(&"dnssec_unsigned"));
}

#[test]
fn a_bogus_zone_fails_validation_and_loads_with_checking_disabled() {
    let stub = DnsStub::new();
    let (code, r) = dns_report(&stub, "bogus.example.com");
    assert_eq!(code, 1);
    assert_eq!(r["dns"]["dnssec"]["bogus"], true);
    let message = "DNSSEC validation fails for bogus.example.com: validating resolvers answer SERVFAIL, and the records load only with checking disabled.";
    let hint = j!(
        "The DS record at your registrar probably doesn't match the zone's keys; update or remove it."
    );
    assert_eq!(finding(&r, "dnssec_bogus"), ("error", message, &hint));
    assert!(codes(&r).contains(&"dns_servfail"));
    let cd = stub.queries().into_iter().filter(|q| q.cd).count();
    assert_eq!(cd, 1, "one retry with checking disabled");
    // A plain SERVFAIL (it fails with CD=1 too) isn't bogus.
    let (_, r) = dns_report(&stub, "servfail.example.com");
    assert_eq!(r["dns"]["dnssec"]["bogus"], false);
    assert!(!codes(&r).contains(&"dnssec_bogus"));
}

/// `check <domain> --checks propagation` with 127.0.0.1 and ::1 as the zone's nameservers.
fn propagation(stub: &DnsStub, domain: &str, extra: &[&str]) -> (i32, Value) {
    let (dns, ports) = (stub.addr(), stub.ports());
    let base = [
        domain,
        "-c",
        "propagation",
        "--dns",
        &dns,
        "--resolver",
        &dns,
    ];
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let (code, v) = json(&[&base[..], extra].concat(), &env);
    (code, v["reports"][0].clone())
}

#[test]
fn each_authoritative_nameserver_is_asked_directly() {
    let stub = DnsStub::new();
    let (code, r) = propagation(&stub, "example.com", &[]);
    assert_eq!(code, 0, "{r}");
    let p = &r["propagation"];
    assert_eq!((&p["status"], &p["zone"]), (&j!("ok"), &j!("example.com")));
    assert_eq!(p["types"], j!(["A", "AAAA", "MX", "TXT"]));
    assert_eq!(p["varies"], j!([]));
    let got = |values: &[&str], ttl| j!({ "rcode": "NOERROR", "values": values, "ttl": ttl });
    let answers = j!({
        "A": got(&["192.0.2.10"], 300),
        "AAAA": got(&["2001:db8::10"], 300),
        "MX": got(&["20 mx2.example.net", "10 mx1.example.net"], 3600),
        "TXT": got(&["v=spf1 ip4:192.0.2.0/24 -all"], 300),
    });
    let server = |name: &str, address: &str| j!({ "server": name, "address": address, "status": "ok", "soa_serial": 2026103001, "answers": answers });
    let want = j!([
        server("ns1.example.net", "127.0.0.1"),
        server("ns2.example.net", "::1")
    ]);
    assert_eq!(p["authoritative"], want);
    assert!(codes(&r).is_empty());
    let direct: Vec<_> = stub.queries().into_iter().filter(|q| !q.rd).collect();
    assert_eq!(
        direct.len(),
        11,
        "SOA and four types at each address, and the probe"
    );
    assert!(direct.iter().all(|q| q.dnssec_ok));
    let at: BTreeSet<_> = direct.iter().map(|q| q.at.to_string()).collect();
    assert_eq!(
        at,
        BTreeSet::from(["127.0.0.1".to_string(), "::1".to_string()])
    );
    let soa: Vec<_> = direct
        .iter()
        .filter(|q| q.qtype == RecordType::SOA)
        .collect();
    assert!(soa.iter().all(|q| q.name == "example.com"));

    let (_, r) = propagation(&stub, "www.example.com", &["-t", "a,CNAME"]);
    let p = &r["propagation"];
    assert_eq!(
        (&p["zone"], &p["types"]),
        (&j!("example.com"), &j!(["A", "CNAME"]))
    );
    let a = &p["authoritative"][0]["answers"];
    assert_eq!(a["A"]["values"], j!(["CNAME example.com"]));
    assert_eq!(a["CNAME"]["values"], j!(["example.com"]));

    let (code, r) = propagation(&stub, "nope.example.com", &["-t", "A"]);
    assert_eq!(code, 0, "only the dns section reports a missing name");
    let a = &r["propagation"]["authoritative"][1]["answers"]["A"];
    assert_eq!(a, &j!({ "rcode": "NXDOMAIN", "values": [], "ttl": 3600 }));
}

#[test]
fn lame_silent_and_single_nameservers_are_flagged() {
    let stub = DnsStub::new();
    for (zone, why) in [
        ("noaa.example.org", "no AA flag"),
        ("lamefail.example.org", "SERVFAIL"),
        ("lamerefused.example.org", "REFUSED"),
    ] {
        let (code, r) = propagation(&stub, zone, &[]);
        assert_eq!(code, 1, "{zone}");
        let message = format!(
            "Nameserver ns2.example.net (::1) doesn't answer authoritatively for {zone} ({why})."
        );
        let hint =
            j!("Fix it at your DNS host, or remove it from the NS records and at your registrar.");
        assert_eq!(finding(&r, "ns_lame"), ("error", message.as_str(), &hint));
        let servers = &r["propagation"]["authoritative"];
        assert_eq!(
            (&servers[0]["status"], &servers[1]["status"]),
            (&j!("ok"), &j!("lame"))
        );
    }

    let started = std::time::Instant::now();
    let (code, r) = propagation(&stub, "slow.example.org", &["-t", "A"]);
    assert!(started.elapsed().as_secs() < 8);
    assert_eq!(code, 0);
    let message = "Nameserver ns2.example.net (::1) didn't answer within 4 s.";
    let hint = j!("It may be down, or your network may block DNS to outside servers.");
    assert_eq!(finding(&r, "ns_timeout"), ("warning", message, &hint));
    let silent = &r["propagation"]["authoritative"][1];
    assert_eq!(
        (&silent["status"], &silent["soa_serial"], &silent["answers"]),
        (&j!("timeout"), &Value::Null, &j!({}))
    );

    let (_, r) = propagation(&stub, "single.example.org", &[]);
    let hint = j!("Use at least two, on different networks (RFC 2182).");
    let message = "single.example.org has only one nameserver.";
    assert_eq!(finding(&r, "ns_single"), ("warning", message, &hint));
    assert_eq!(
        r["propagation"]["authoritative"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn nameservers_that_disagree_are_named() {
    let stub = DnsStub::new();
    let (code, r) = propagation(&stub, "serial.example.org", &[]);
    assert_eq!(code, 0);
    let message = "The nameservers serve different versions of serial.example.org: serial 2026103001 on ns1.example.net, 2026103002 on ns2.example.net.";
    let hint = j!("A change may still be reaching the secondaries, or one stopped updating.");
    assert_eq!(
        finding(&r, "soa_serial_mismatch"),
        ("warning", message, &hint)
    );

    let (code, r) = propagation(&stub, "geo.example.org", &[]);
    assert_eq!(code, 0);
    assert_eq!(r["propagation"]["varies"], j!(["A"]));
    let message = "The nameservers give different A answers for geo.example.org (normal for geo-DNS or load balancing), so resolvers aren't compared for A.";
    assert_eq!(
        finding(&r, "propagation_varies"),
        ("info", message, &Value::Null)
    );
    assert_eq!(codes(&r), ["propagation_varies"]);
}

#[test]
fn propagation_needs_the_zone() {
    let stub = DnsStub::new();
    let (code, r) = propagation(&stub, "servfail.example.com", &[]);
    assert_eq!(code, 3);
    let p = &r["propagation"];
    let reason = j!("No DNS answer, so this check couldn't run.");
    assert_eq!((&p["status"], &p["reason"]), (&j!("unavailable"), &reason));
    assert_eq!(r["dns"]["status"], "skipped");
}

#[test]
fn resolvers_are_compared_with_the_nameservers() {
    let stub = DnsStub::new();
    let (code, r) = propagation(&stub, "example.com", &["-t", "A,MX"]);
    assert_eq!(code, 0);
    let p = &r["propagation"];
    assert_eq!(
        (&p["consistent"], &p["wildcard"], &p["rewrites_nxdomain"]),
        (&j!(true), &j!(false), &j!(false))
    );
    let seen = |values: &[&str], ttl| j!({ "rcode": "NOERROR", "values": values, "ttl": ttl, "agrees": true });
    let answers = j!({
        "A": seen(&["192.0.2.10"], 300),
        "MX": seen(&["20 mx2.example.net", "10 mx1.example.net"], 3600),
    });
    let view = |name: &str| j!({ "name": name, "address": stub.addr(), "status": "ok", "answers": answers });
    assert_eq!(p["resolvers"], j!([view("Custom"), view("System")]));
    // The probe: one random name under the domain, at the first nameserver and the resolver.
    let probes: Vec<_> = stub
        .queries()
        .into_iter()
        .filter(|q| q.name.starts_with("dc-"))
        .collect();
    assert_eq!(probes.len(), 2, "{probes:?}");
    let label = probes[0].name.strip_suffix(".example.com").unwrap();
    assert_eq!(label.len(), 19);
    assert!(
        label[3..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    );
    assert_eq!(
        (probes[0].rd, probes[0].at.to_string()),
        (false, "127.0.0.1".into())
    );
    assert!(probes[1].rd && probes[1].name == probes[0].name);
}

#[test]
fn a_stale_resolver_and_an_unreachable_one_are_info() {
    let stub = DnsStub::new();
    let stale = DnsStub::start(|a| match (a.name.as_str(), a.qtype, a.rd) {
        ("example.com", RecordType::A, true) => Some(common::Reply {
            answers: vec![common::record(
                "example.com",
                1840,
                domain_check::dns::RData::A("192.0.2.9".parse().unwrap()),
            )],
            ..common::Reply::default()
        }),
        _ => common::fixtures(a),
    });
    let closed = closed_udp_port().to_string();
    let (dns, ports) = (stub.addr(), stub.ports());
    let args = [
        "example.com",
        "-c",
        "propagation",
        "-t",
        "A,TXT",
        "--dns",
        &dns,
        "--resolver",
        &stale.addr(),
        "--resolver",
        &closed,
    ];
    let (code, v) = json(&args, &[("DOMAIN_CHECK_LOOPBACK_PORTS", &ports)]);
    assert_eq!(code, 0, "{v}");
    let r = &v["reports"][0];
    let p = &r["propagation"];
    assert_eq!(p["consistent"], false);
    let custom = &p["resolvers"][0];
    assert_eq!(custom["answers"]["A"]["agrees"], false);
    assert_eq!(custom["answers"]["TXT"]["agrees"], true);
    let message = format!(
        "Custom ({}) still answers A 192.0.2.9 for example.com; the nameservers say 192.0.2.10. Its copy expires within 1840 s.",
        stale.addr()
    );
    assert_eq!(
        finding(r, "propagation_stale"),
        ("info", message.as_str(), &Value::Null)
    );
    let down = &p["resolvers"][1];
    assert_eq!(down["answers"], j!({}));
    assert!(
        matches!(down["status"].as_str(), Some("refused" | "timeout")),
        "{down}"
    );
    let (_, message, hint) = finding(r, "resolver_unreachable");
    let port = closed.rsplit(':').next().unwrap();
    let start = format!("Couldn't reach Custom (127.0.0.1) on port {port}: ");
    assert!(message.starts_with(&start), "{message}");
    let hint_text =
        "Your network may block DNS to outside resolvers; the other results still stand.";
    assert_eq!(hint, &j!(hint_text));
    assert_eq!(p["resolvers"][2]["name"], "System");
}

#[test]
fn wildcards_and_rewritten_nxdomain_answers_are_detected() {
    let stub = DnsStub::new();
    let (code, r) = propagation(&stub, "wild.example.org", &["-t", "A"]);
    assert_eq!(code, 0);
    assert_eq!(
        (
            &r["propagation"]["wildcard"],
            &r["propagation"]["rewrites_nxdomain"]
        ),
        (&j!(true), &j!(false))
    );
    let message =
        "wild.example.org has a wildcard record: any name under wild.example.org resolves.";
    assert_eq!(finding(&r, "wildcard"), ("info", message, &Value::Null));

    let rewriting = DnsStub::start(|a| match a.rd && a.name.starts_with("dc-") {
        true => Some(common::Reply {
            answers: vec![common::record(
                &a.name,
                60,
                domain_check::dns::RData::A("192.0.2.99".parse().unwrap()),
            )],
            ..common::Reply::default()
        }),
        false => common::fixtures(a),
    });
    let (code, r) = propagation(&rewriting, "example.com", &["-t", "A"]);
    assert_eq!(code, 0);
    let p = &r["propagation"];
    assert_eq!(
        (&p["wildcard"], &p["rewrites_nxdomain"]),
        (&j!(false), &j!(true))
    );
    let message = format!(
        "Your DNS resolver ({}) answers for names that don't exist, so what you see may differ from the internet.",
        rewriting.addr()
    );
    let hint =
        j!("Your ISP or network may be redirecting typos; compare with the public resolvers.");
    assert_eq!(
        finding(&r, "resolver_rewrites_nxdomain"),
        ("warning", message.as_str(), &hint)
    );
}

#[test]
fn varying_types_and_silent_servers_leave_nothing_to_compare() {
    let stub = DnsStub::new();
    let (_, r) = propagation(&stub, "geo.example.org", &["-t", "A,MX"]);
    let custom = &r["propagation"]["resolvers"][0]["answers"];
    assert_eq!(
        (&custom["A"]["agrees"], &custom["MX"]["agrees"]),
        (&Value::Null, &j!(true))
    );
    assert_eq!(r["propagation"]["consistent"], true);

    // Nameservers and resolvers that never answer: the section can't say anything.
    let mute = DnsStub::start(|a| match !a.rd || a.qtype == RecordType::MX {
        true => None,
        false => common::fixtures(a),
    });
    let started = std::time::Instant::now();
    let (code, r) = propagation(&mute, "example.com", &["-t", "MX"]);
    assert!(started.elapsed().as_secs() < 15);
    assert_eq!(code, 3);
    let p = &r["propagation"];
    let reason = j!("None of the nameservers or resolvers answered.");
    assert_eq!((&p["status"], &p["reason"]), (&j!("unavailable"), &reason));
}

/// No client port is one another program bound on 127.0.0.1 only: on Windows that socket would
/// take the loopback server's answer.
#[cfg(windows)]
#[test]
fn answers_arrive_while_other_programs_hold_loopback_ports() {
    let stub = DnsStub::new();
    let held: Vec<_> = (20000..32000)
        .filter_map(|port| std::net::UdpSocket::bind(("127.0.0.1", port)).ok())
        .collect();
    assert!(held.len() > 10_000, "{}", held.len());
    let dns = stub.addr();
    let types = "A AAAA CNAME MX NS TXT CAA SOA SRV PTR DS DNSKEY TLSA HTTPS SVCB";
    let mut args = vec!["lookup", "example.com", "--dns", &dns, "--debug"];
    args.extend(types.split(' '));
    for _ in 0..3 {
        let (_, _, err) = common::run(&args, &[]);
        assert!(!err.contains(" timeout "), "{err}");
    }
}
