//! Local stand-ins for the network. No test reaches a real service: DNS goes to a stub that
//! listens on 127.0.0.1 and ::1 on one port (UDP and TCP), serving hand-written zones.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;

use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{
    A, AAAA, CAA, CNAME, HTTPS, MX, NS, NULL, PTR, SOA, SRV, SVCB, TLSA, TXT,
};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// One query as the stub received it.
#[derive(Clone, Debug)]
pub struct Asked {
    /// Lower case, without the trailing dot.
    pub name: String,
    pub qtype: RecordType,
    pub rd: bool,
    pub cd: bool,
    pub ad: bool,
    pub dnssec_ok: bool,
    pub tcp: bool,
    /// The stub address that received it: 127.0.0.1 or ::1.
    pub at: IpAddr,
}

/// What the stub sends back; `None` from a zone is silence.
#[derive(Default)]
pub struct Reply {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub aa: bool,
    pub ad: bool,
    pub tc: bool,
}

pub type Zone = dyn Fn(&Asked) -> Option<Reply> + Send + Sync;

pub struct DnsStub {
    pub port: u16,
    log: Arc<Mutex<Vec<Asked>>>,
}

impl DnsStub {
    /// The stub serving `fixtures`.
    pub fn new() -> DnsStub {
        DnsStub::start(fixtures)
    }

    pub fn start(zone: impl Fn(&Asked) -> Option<Reply> + Send + Sync + 'static) -> DnsStub {
        let zone: Arc<Zone> = Arc::new(zone);
        let log = Arc::new(Mutex::new(Vec::new()));
        // One port free on both loopback addresses, for UDP and TCP.
        let (port, sockets) = (0..50)
            .find_map(|_| {
                let udp4 = UdpSocket::bind("127.0.0.1:0").ok()?;
                let port = udp4.local_addr().ok()?.port();
                let udp6 = UdpSocket::bind(("::1", port)).ok()?;
                let tcp4 = TcpListener::bind(("127.0.0.1", port)).ok()?;
                let tcp6 = TcpListener::bind(("::1", port)).ok()?;
                Some((port, (udp4, udp6, tcp4, tcp6)))
            })
            .expect("a free port on 127.0.0.1 and ::1");
        let (udp4, udp6, tcp4, tcp6) = sockets;
        for udp in [udp4, udp6] {
            let (zone, log) = (Arc::clone(&zone), Arc::clone(&log));
            thread::spawn(move || serve_udp(udp, &*zone, &log));
        }
        for tcp in [tcp4, tcp6] {
            let (zone, log) = (Arc::clone(&zone), Arc::clone(&log));
            thread::spawn(move || {
                for stream in tcp.incoming().flatten() {
                    let (zone, log) = (Arc::clone(&zone), Arc::clone(&log));
                    thread::spawn(move || serve_tcp(stream, &*zone, &log));
                }
            });
        }
        DnsStub { port, log }
    }

    /// `127.0.0.1:<port>`, for `--dns`.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// `dns=<port>`, for `DOMAIN_CHECK_LOOPBACK_PORTS`.
    pub fn ports(&self) -> String {
        format!("dns={}", self.port)
    }

    pub fn queries(&self) -> Vec<Asked> {
        self.log.lock().unwrap().clone()
    }
}

fn serve_udp(socket: UdpSocket, zone: &Zone, log: &Mutex<Vec<Asked>>) {
    let at = socket.local_addr().unwrap().ip();
    let mut buf = [0; 4096];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        if let Some(out) = answer(&buf[..n], at, false, zone, log) {
            let _ = socket.send_to(&out, from);
        }
    }
}

fn serve_tcp(mut stream: TcpStream, zone: &Zone, log: &Mutex<Vec<Asked>>) {
    let at = stream.local_addr().unwrap().ip();
    loop {
        let mut len = [0; 2];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut buf = vec![0; u16::from_be_bytes(len).into()];
        if stream.read_exact(&mut buf).is_err() {
            return;
        }
        if let Some(out) = answer(&buf, at, true, zone, log) {
            let len = (out.len() as u16).to_be_bytes();
            if stream.write_all(&[&len[..], &out].concat()).is_err() {
                return;
            }
        }
    }
}

fn answer(
    bytes: &[u8],
    at: IpAddr,
    tcp: bool,
    zone: &Zone,
    log: &Mutex<Vec<Asked>>,
) -> Option<Vec<u8>> {
    let query = Message::from_vec(bytes).ok()?;
    let q = query.queries.first()?.clone();
    let h = &query.metadata;
    let asked = Asked {
        name: q.name.to_ascii().trim_end_matches('.').to_ascii_lowercase(),
        qtype: q.query_type,
        rd: h.recursion_desired,
        cd: h.checking_disabled,
        ad: h.authentic_data,
        dnssec_ok: query.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
        tcp,
        at,
    };
    log.lock().unwrap().push(asked.clone());
    let reply = zone(&asked)?;
    let mut m = Message::response(h.id, OpCode::Query);
    m.metadata.recursion_desired = asked.rd;
    m.metadata.recursion_available = asked.rd;
    m.metadata.checking_disabled = asked.cd;
    m.metadata.authoritative = reply.aa;
    m.metadata.authentic_data = reply.ad;
    m.metadata.truncation = reply.tc;
    m.metadata.response_code = reply.rcode;
    m.add_query(q);
    m.answers = reply.answers;
    m.authorities = reply.authorities;
    m.to_vec().ok()
}

pub fn name(s: &str) -> Name {
    Name::from_str(&format!("{s}.")).unwrap()
}

pub fn record(owner: &str, ttl: u32, data: RData) -> Record {
    Record::from_rdata(name(owner), ttl, data)
}

fn soa(zone: &str) -> Record {
    let soa = SOA::new(
        name(&format!("ns1.{zone}")),
        name(&format!("hostmaster.{zone}")),
        2026103001,
        7200,
        3600,
        1209600,
        300,
    );
    record(zone, 3600, RData::SOA(soa))
}

fn raw(t: RecordType, bytes: &[u8]) -> RData {
    RData::Unknown {
        code: t,
        rdata: NULL::with(bytes.to_vec()),
    }
}

/// The names under example.com, example.net and example.org and their records: one of each
/// `lookup` type, a CNAME, a TXT set too big for UDP, and names that fail every way.
pub fn records(owner: &str, t: RecordType) -> Option<Vec<Record>> {
    use RecordType as T;
    let rec = |ttl, data| vec![record(owner, ttl, data)];
    let svcb = |priority, target: &str| {
        let alpn = SvcParamValue::Alpn(Alpn(vec!["h2".into(), "h3".into()]));
        SVCB::new(priority, name(target), vec![(SvcParamKey::Alpn, alpn)])
    };
    let found = match (owner, t) {
        ("example.com", T::A) => rec(300, RData::A(A(Ipv4Addr::new(192, 0, 2, 10)))),
        ("example.com", T::AAAA) => rec(
            300,
            RData::AAAA(AAAA(Ipv6Addr::from_str("2001:db8::10").unwrap())),
        ),
        ("example.com", T::MX) => vec![
            record(owner, 3600, RData::MX(MX::new(20, name("mx2.example.net")))),
            record(owner, 3600, RData::MX(MX::new(10, name("mx1.example.net")))),
        ],
        ("example.com", T::NS) => vec![
            record(owner, 86400, RData::NS(NS(name("ns1.example.net")))),
            record(owner, 86400, RData::NS(NS(name("ns2.example.net")))),
        ],
        ("example.com", T::TXT) => rec(
            300,
            RData::TXT(TXT::new(vec![
                "v=spf1 ip4:192.0.2.0/24 ".into(),
                "-all".into(),
            ])),
        ),
        ("example.com", T::CAA) => rec(
            3600,
            RData::CAA(CAA::new_issue(false, Some(name("letsencrypt.org")), vec![])),
        ),
        ("example.com", T::SOA) => vec![soa("example.com")],
        ("example.com", T::HTTPS) => rec(300, RData::HTTPS(HTTPS(svcb(1, ".")))),
        ("example.com", T::DS) => rec(86400, raw(T::DS, &[0x30, 0x39, 13, 2, 0xab, 0xcd])),
        ("example.com", T::DNSKEY) => rec(3600, raw(T::DNSKEY, &[1, 1, 3, 13, 1, 2, 3])),
        ("www.example.com", T::CNAME) => rec(300, RData::CNAME(CNAME(name("example.com")))),
        ("www.example.com", T::A) => vec![
            record(owner, 300, RData::CNAME(CNAME(name("example.com")))),
            record(
                "example.com",
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
            ),
        ],
        ("_sip._tcp.example.com", T::SRV) => rec(
            300,
            RData::SRV(SRV::new(10, 5, 5060, name("sip.example.com"))),
        ),
        ("_443._tcp.example.com", T::TLSA) => rec(
            300,
            RData::TLSA(TLSA::new(3.into(), 1.into(), 1.into(), vec![0xab, 0xcd])),
        ),
        ("_dns.example.com", T::SVCB) => rec(300, RData::SVCB(svcb(1, "dns.example.com"))),
        ("10.2.0.192.in-addr.arpa", T::PTR) => rec(3600, RData::PTR(PTR(name("www.example.com")))),
        ("0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", T::PTR) => {
            rec(3600, RData::PTR(PTR(name("www.example.com"))))
        }
        ("big.example.com", T::TXT) => (0..40)
            .map(|i| {
                record(
                    owner,
                    300,
                    RData::TXT(TXT::new(vec![format!("{i:02}-{}", "x".repeat(60))])),
                )
            })
            .collect(),
        (
            "example.com"
            | "www.example.com"
            | "_sip._tcp.example.com"
            | "_443._tcp.example.com"
            | "_dns.example.com"
            | "big.example.com"
            | "example.net"
            | "example.org"
            | "10.2.0.192.in-addr.arpa",
            _,
        ) => Vec::new(),
        _ => return None,
    };
    Some(found)
}

/// The fixture zones, answered as a resolver (RD on: AD for example.com) or as their
/// authoritative server (RD off: AA). `servfail.`, `refused.` and `silent.` names fail.
pub fn fixtures(a: &Asked) -> Option<Reply> {
    let zone = [
        "example.com",
        "example.net",
        "example.org",
        "in-addr.arpa",
        "ip6.arpa",
    ]
    .into_iter()
    .find(|z| a.name == *z || a.name.ends_with(&format!(".{z}")))
    .unwrap_or("example.com");
    let failed = |rcode| Reply {
        rcode,
        ..Reply::default()
    };
    match a.name.split('.').next() {
        Some("silent") => return None,
        Some("servfail") => return Some(failed(ResponseCode::ServFail)),
        Some("refused") => return Some(failed(ResponseCode::Refused)),
        _ => {}
    }
    let base = Reply {
        aa: !a.rd,
        ad: a.rd && zone == "example.com",
        ..Reply::default()
    };
    Some(match records(&a.name, a.qtype) {
        Some(_) if a.name == "big.example.com" && !a.tcp => Reply { tc: true, ..base },
        Some(answers) if answers.is_empty() => Reply {
            authorities: vec![soa(zone)],
            ..base
        },
        Some(answers) => Reply { answers, ..base },
        None => Reply {
            rcode: ResponseCode::NXDomain,
            authorities: vec![soa(zone)],
            ..base
        },
    })
}

/// A loopback UDP address where nothing listens.
pub fn closed_udp_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
