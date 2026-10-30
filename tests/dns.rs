mod common;

use std::net::SocketAddr;

use common::{DnsStub, closed_udp_port};
use domain_check::Ports;
use domain_check::dns::{
    Ask, Failure, Message, RECURSIVE, RecordType, Resolver, ResponseCode, records, value,
};

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
