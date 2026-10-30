//! Local stand-ins for the network. No test reaches a real service: DNS goes to a stub that
//! listens on 127.0.0.1 and ::1 on one port (UDP and TCP), serving hand-written zones.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
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
            thread::spawn(move || serve_udp(udp, zone, log));
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

/// One thread per query, so a zone that takes its time doesn't hold up the others.
fn serve_udp(socket: UdpSocket, zone: Arc<Zone>, log: Arc<Mutex<Vec<Asked>>>) {
    let at = socket.local_addr().unwrap().ip();
    let socket = Arc::new(socket);
    let mut buf = [0; 4096];
    while let Ok((n, from)) = socket.recv_from(&mut buf) {
        let (socket, zone, log) = (Arc::clone(&socket), Arc::clone(&zone), Arc::clone(&log));
        let query = buf[..n].to_vec();
        thread::spawn(move || {
            if let Some(out) = answer(&query, at, false, &*zone, &log) {
                let _ = socket.send_to(&out, from);
            }
        });
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
    match s {
        "." => Name::root(),
        _ => Name::from_str(&format!("{s}.")).unwrap(),
    }
}

pub fn record(owner: &str, ttl: u32, data: RData) -> Record {
    Record::from_rdata(name(owner), ttl, data)
}

/// The zones the stub serves; a name belongs to the longest one it ends in. The ones under
/// example.org each show one way a zone's nameservers can go wrong.
pub const ZONES: [&str; 14] = [
    "example.com",
    "example.net",
    "example.org",
    "apex.example.net",
    "wild.example.org",
    "serial.example.org",
    "geo.example.org",
    "noaa.example.org",
    "lamefail.example.org",
    "lamerefused.example.org",
    "slow.example.org",
    "single.example.org",
    "in-addr.arpa",
    "ip6.arpa",
];

pub fn zone_of(name: &str) -> Option<&'static str> {
    ZONES
        .into_iter()
        .filter(|z| name == *z || name.ends_with(&format!(".{z}")))
        .max_by_key(|z| z.len())
}

pub fn soa(zone: &str, serial: u32) -> Record {
    let soa = SOA::new(
        name(&format!("ns1.{zone}")),
        name(&format!("hostmaster.{zone}")),
        serial,
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

/// The mail fixtures: owner, type, value. A listed owner exists and has no records of the
/// types not listed for it; an owner `*.x` stands for every name under x that isn't listed.
#[rustfmt::skip]
pub const MAIL: &[(&str, RecordType, &str)] = {
    use RecordType::*;
    &[
        ("mx1.example.net", A, "192.0.2.25"),
        ("mx2.example.net", A, "192.0.2.26"),
        ("mx2.example.net", AAAA, "2001:db8::26"),
        ("mx.example.net", MX, "10 mx1.example.net"),
        ("mx.example.net", MX, "20 alias.example.net"),
        ("mx.example.net", MX, "30 192.0.2.25"),
        ("mx.example.net", MX, "40 gone.example.net"),
        ("mx.example.net", MX, "50 noaddr.example.net"),
        ("mx.example.net", MX, "60 servfail.example.net"),
        ("alias.example.net", CNAME, "mx2.example.net"),
        ("noaddr.example.net", TXT, "no address here"),
        ("nullmx.example.net", MX, "0 ."),
        ("implicit.example.net", A, "192.0.2.27"),
        ("nomail.example.net", TXT, "no mail here"),
        // SPF
        ("spf.example.net", A, "192.0.2.30"),
        ("spf.example.net", MX, "10 mx1.example.net"),
        ("spf.example.net", TXT, "v=spf1 include:_spf.example.net a mx ip4:192.0.2.0/24 ptr exists:%{i}.exists.example.net -all"),
        ("_spf.example.net", TXT, "v=spf1 include:_inner.example.net ip6:2001:db8::/32 ~all"),
        ("_inner.example.net", TXT, "v=spf1 ip4:198.51.100.0/24 -all"),
        ("many.example.net", TXT, "v=spf1 include:_n1.example.net include:_n2.example.net include:_n3.example.net include:_n4.example.net include:_n5.example.net include:_n6.example.net -all"),
        ("_n1.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("_n2.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("_n3.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("_n4.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("_n5.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("_n6.example.net", TXT, "v=spf1 a:mx1.example.net ~all"),
        ("capped.example.net", TXT, "v=spf1 include:many.example.net include:many.example.net -all"),
        ("void.example.net", TXT, "v=spf1 a:gone.example.net mx:noaddr.example.net exists:gone.example.org include:nomail.example.net include:gone.example.net ~all"),
        ("loop.example.net", TXT, "v=spf1 include:_loop.example.net -all"),
        ("_loop.example.net", TXT, "v=spf1 include:LOOP.example.net. ~all"),
        ("redirect.example.net", TXT, "v=spf1 redirect=_spf.example.net"),
        ("redirected.example.net", TXT, "v=spf1 ip4:192.0.2.1 redirect=_spf.example.net ?all"),
        ("plusall.example.net", TXT, "v=spf1 all"),
        ("noall.example.net", TXT, "v=spf1 ip4:192.0.2.1"),
        ("multi.example.net", TXT, "v=spf1 -all"),
        ("multi.example.net", TXT, "v=spf1 ~all"),
        ("multi.example.net", TXT, "spf2.0/mfrom,pra -all"),
        ("syntax.example.net", TXT, "v=spf1 inlcude:_spf.example.net ip4:192.0.2.300 -all"),
        ("failing.example.net", TXT, "v=spf1 include:servfail.example.net a:servfail.example.org -all"),
        // SPF evaluated for one address
        ("eval.example.net", MX, "10 mx2.example.net"),
        ("eval.example.net", TXT, "v=spf1 -ip4:192.0.2.66 a:mx1.example.net/30 mx/24 ip6:2001:db8:1::/48 exists:%{l}.%{ir}.%{v}._ok.%{d2} include:soft.example.net ?all"),
        ("postmaster.20.100.51.198.in-addr._ok.example.net", A, "127.0.0.2"),
        ("soft.example.net", TXT, "v=spf1 ip4:203.0.113.0/24 ~all"),
        ("ptr.example.net", TXT, "v=spf1 ptr:example.com exists:%{i}._ip.%{d} -all"),
        ("198.51.100.30._ip.ptr.example.net", A, "127.0.0.2"),
        // DMARC
        ("_dmarc.example.com", TXT, "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
        ("_dmarc.example.net", TXT, "v=DMARC1; p=quarantine; sp=none; rua=mailto:reports@example.net"),
        ("dmarc.example.net", A, "192.0.2.31"),
        ("_dmarc.dmarc.example.net", TXT, "v=DMARC1; p=none; t=y; pct=50; rf=afrf; ri=86400; adkim=x; fo=1:d; rua=mailto:a@example.net,https://dmarc.example.net/r,mailto:b@example.org!10m,mailto:c@example.com; ruf=mailto:f@dmarc.example.net"),
        ("*._report._dmarc.example.org", TXT, "v=DMARC1"),
        ("twodmarc.example.net", A, "192.0.2.32"),
        ("_dmarc.twodmarc.example.net", TXT, "v=DMARC1; p=reject"),
        ("_dmarc.twodmarc.example.net", TXT, "v=DMARC1; p=none"),
        ("baddmarc.example.net", A, "192.0.2.33"),
        ("_dmarc.baddmarc.example.net", TXT, "v=dmarc1; p=reject"),
        ("badp.example.net", A, "192.0.2.34"),
        ("_dmarc.badp.example.net", TXT, "v=DMARC1; p=block; rua=mailto:d@badp.example.net"),
        ("nop.example.net", A, "192.0.2.35"),
        ("_dmarc.nop.example.net", TXT, "v=DMARC1; sp=reject"),
        ("three.example.org", A, "192.0.2.36"),
        ("a.b.c.d.e.f.example.org", A, "192.0.2.37"),
        ("a.b.c.d.e.f.g.h.i.example.org", A, "192.0.2.38"),
        ("a.b.c.d.e.f.g.h.i.example.net", A, "192.0.2.39"),
    ]
};

/// `owner`'s records of `t` from [`MAIL`]; `None` when the table doesn't list the owner.
fn mail(owner: &str, t: RecordType) -> Option<Vec<Record>> {
    let listed = |o: &str| o == owner;
    let wild = |o: &str| {
        o.strip_prefix('*')
            .is_some_and(|zone| owner.ends_with(zone))
    };
    let rows: Vec<_> = match MAIL.iter().any(|(o, _, _)| listed(o)) {
        true => MAIL.iter().filter(|(o, _, _)| listed(o)).collect(),
        false => MAIL.iter().filter(|(o, _, _)| wild(o)).collect(),
    };
    if rows.is_empty() {
        return None;
    }
    let data = |t: RecordType, v: &str| match t {
        RecordType::A => RData::A(A(v.parse().unwrap())),
        RecordType::AAAA => RData::AAAA(AAAA(v.parse().unwrap())),
        RecordType::CNAME => RData::CNAME(CNAME(name(v))),
        RecordType::MX => {
            let (preference, host) = v.split_once(' ').unwrap();
            RData::MX(MX::new(preference.parse().unwrap(), name(host)))
        }
        // Strings of at most 255 bytes, as a long TXT record is published.
        _ => RData::TXT(TXT::new(
            v.as_bytes()
                .chunks(255)
                .map(|c| String::from_utf8(c.to_vec()).unwrap())
                .collect(),
        )),
    };
    let rows = rows.into_iter().filter(|(_, rt, _)| *rt == t);
    Some(
        rows.map(|(_, rt, v)| record(owner, 300, data(*rt, v)))
            .collect(),
    )
}

/// `owner`'s records of type `t` as the server at `at` holds them (`None`: as a resolver sees
/// them); `None` when the name doesn't exist, `[]` when it has no such records.
pub fn records(owner: &str, t: RecordType, at: Option<IpAddr>) -> Option<Vec<Record>> {
    use RecordType as T;
    if let Some(found) = mail(owner, t) {
        return Some(found);
    }
    let rec = |ttl, data| vec![record(owner, ttl, data)];
    let a = |ip: [u8; 4]| rec(300, RData::A(A(Ipv4Addr::from(ip))));
    let cname = |target: &str| rec(300, RData::CNAME(CNAME(name(target))));
    let svcb = |priority, target: &str| {
        let alpn = SvcParamValue::Alpn(Alpn(vec!["h2".into(), "h3".into()]));
        SVCB::new(priority, name(target), vec![(SvcParamKey::Alpn, alpn)])
    };
    let zone = zone_of(owner);
    let apex = zone == Some(owner);
    let v6 = at.is_some_and(|ip| ip.is_ipv6());
    let chain = owner
        .strip_prefix('c')
        .and_then(|rest| rest.strip_suffix(".example.com"))
        .and_then(|n| n.parse::<u8>().ok())
        .filter(|n| (1..=10).contains(n));
    let found = match (owner, t) {
        ("example.com", T::A) => a([192, 0, 2, 10]),
        ("example.com", T::AAAA) => rec(
            300,
            RData::AAAA(AAAA(Ipv6Addr::from_str("2001:db8::10").unwrap())),
        ),
        ("example.com", T::MX) => vec![
            record(owner, 3600, RData::MX(MX::new(20, name("mx2.example.net")))),
            record(owner, 3600, RData::MX(MX::new(10, name("mx1.example.net")))),
        ],
        ("example.com", T::TXT) => rec(
            300,
            RData::TXT(TXT::new(vec![
                "v=spf1 ip4:192.0.2.0/24 ".into(),
                "-all".into(),
            ])),
        ),
        // CAA issuer values are text: no trailing dot.
        ("example.com", T::CAA) => rec(
            3600,
            RData::CAA(CAA::new_issue(
                false,
                Some(Name::from_str("letsencrypt.org").unwrap()),
                vec![],
            )),
        ),
        ("example.com", T::HTTPS) => rec(300, RData::HTTPS(HTTPS(svcb(1, ".")))),
        ("example.com", T::DS) => rec(86400, raw(T::DS, &[0x30, 0x39, 13, 2, 0xab, 0xcd])),
        ("example.com", T::DNSKEY) => rec(3600, raw(T::DNSKEY, &[1, 1, 3, 13, 1, 2, 3])),
        ("example.org", T::DS) => rec(86400, raw(T::DS, &[0x01, 0x02, 5, 1, 0xab])),
        ("example.org", T::DNSKEY) => rec(3600, raw(T::DNSKEY, &[1, 1, 3, 5, 1, 2, 3])),
        ("www.example.com" | "apex.example.net", T::CNAME) => cname("example.com"),
        ("loop1.example.com", T::CNAME) => cname("loop2.example.com"),
        ("loop2.example.com", T::CNAME) => cname("loop1.example.com"),
        ("dangling.example.com", T::CNAME) => cname("gone.example.net"),
        (_, T::CNAME) if chain.is_some_and(|n| n < 10) => {
            cname(&format!("c{}.example.com", chain.unwrap_or(0) + 1))
        }
        ("bogus.example.com", T::A) => a([192, 0, 2, 50]),
        (_, T::A) if chain == Some(10) => a([192, 0, 2, 10]),
        ("ns1.example.net", T::A) => rec(3600, RData::A(A(Ipv4Addr::LOCALHOST))),
        ("ns2.example.net", T::AAAA) => rec(3600, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
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
        ("mxmany.example.net", T::TXT) => {
            rec(300, RData::TXT(TXT::new(vec!["v=spf1 mx -all".into()])))
        }
        ("mxmany.example.net", T::MX) => (1..=11)
            .map(|p| record(owner, 300, RData::MX(MX::new(p, name("mx1.example.net")))))
            .collect(),
        ("long.example.net", T::TXT) => {
            let ranges: String = (0..32).map(|i| format!("ip4:198.51.100.{i} ")).collect();
            let spf = format!("v=spf1 {ranges}-all");
            let chunks = spf
                .as_bytes()
                .chunks(255)
                .map(|c| String::from_utf8(c.to_vec()).unwrap());
            rec(300, RData::TXT(TXT::new(chunks.collect())))
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
        (_, T::SOA) if apex => {
            let serial = match owner == "serial.example.org" && v6 {
                true => 2026103002,
                false => 2026103001,
            };
            vec![soa(owner, serial)]
        }
        ("single.example.org", T::NS) => rec(86400, RData::NS(NS(name("ns1.example.net")))),
        (_, T::NS) if apex => vec![
            record(owner, 86400, RData::NS(NS(name("ns1.example.net")))),
            record(owner, 86400, RData::NS(NS(name("ns2.example.net")))),
        ],
        ("geo.example.org", T::A) if v6 => a([192, 0, 2, 42]),
        ("geo.example.org", T::A) => a([192, 0, 2, 41]),
        (_, T::A) if apex && owner.ends_with(".example.org") => a([192, 0, 2, 30]),
        (_, T::A) if zone == Some("wild.example.org") => a([192, 0, 2, 30]),
        // A wildcard: every name under wild.example.org exists.
        _ if zone == Some("wild.example.org") || apex || chain.is_some() => Vec::new(),
        (
            "www.example.com"
            | "loop1.example.com"
            | "loop2.example.com"
            | "dangling.example.com"
            | "bogus.example.com"
            | "noaddr.example.com"
            | "ns1.example.net"
            | "ns2.example.net"
            | "_sip._tcp.example.com"
            | "_443._tcp.example.com"
            | "_dns.example.com"
            | "big.example.com"
            | "mxmany.example.net"
            | "long.example.net"
            | "10.2.0.192.in-addr.arpa",
            _,
        ) => Vec::new(),
        _ => return None,
    };
    Some(found)
}

/// The answer to `t` at `name`: its records, or the CNAME chain to them when `chase` is set
/// (as a resolver does); a loop gives SERVFAIL. Also the last name asked, for the SOA.
fn resolve(
    name: &str,
    t: RecordType,
    at: Option<IpAddr>,
    chase: bool,
) -> (ResponseCode, Vec<Record>, String) {
    let mut answers = Vec::new();
    let mut name = name.to_string();
    for _ in 0..16 {
        let Some(found) = records(&name, t, at) else {
            return (ResponseCode::NXDomain, answers, name);
        };
        if !found.is_empty() || t == RecordType::CNAME {
            answers.extend(found);
            return (ResponseCode::NoError, answers, name);
        }
        let cname = records(&name, RecordType::CNAME, at).unwrap_or_default();
        let Some(RData::CNAME(target)) = cname.first().map(|r| r.data.clone()) else {
            return (ResponseCode::NoError, answers, name);
        };
        answers.extend(cname);
        name = target.0.to_ascii().trim_end_matches('.').to_string();
        if !chase {
            return (ResponseCode::NoError, answers, name);
        }
    }
    (ResponseCode::ServFail, Vec::new(), name)
}

/// The fixture zones, answered as a resolver (RD on: AD for example.com) or as their
/// authoritative servers 127.0.0.1 and ::1 (RD off: AA). Names with a `servfail`, `refused` or
/// `silent` label fail everywhere; the zones under example.org fail at ::1 as named.
pub fn fixtures(a: &Asked) -> Option<Reply> {
    let failed = |rcode| Reply {
        rcode,
        ..Reply::default()
    };
    for label in a.name.split('.') {
        match label {
            "silent" => return None,
            "servfail" => return Some(failed(ResponseCode::ServFail)),
            "refused" => return Some(failed(ResponseCode::Refused)),
            _ => {}
        }
    }
    let zone = zone_of(&a.name).unwrap_or("example.com");
    let at = (!a.rd).then_some(a.at);
    if a.name == "bogus.example.com" && a.rd && !a.cd {
        return Some(failed(ResponseCode::ServFail));
    }
    if at.is_some_and(|ip| ip.is_ipv6()) {
        match zone {
            "slow.example.org" => return None,
            "lamefail.example.org" => return Some(failed(ResponseCode::ServFail)),
            "lamerefused.example.org" => return Some(failed(ResponseCode::Refused)),
            _ => {}
        }
    }
    let (rcode, answers, last) = resolve(&a.name, a.qtype, at, a.rd);
    let tc = a.name == "big.example.com" && !a.tcp && rcode == ResponseCode::NoError;
    let empty = answers.is_empty();
    Some(Reply {
        rcode,
        answers: if tc { Vec::new() } else { answers },
        authorities: match empty {
            true => vec![soa(zone_of(&last).unwrap_or("example.com"), 2026103001)],
            false => Vec::new(),
        },
        aa: !a.rd && !(zone == "noaa.example.org" && a.at.is_ipv6()),
        ad: a.rd && !a.cd && zone == "example.com",
        tc,
    })
}

/// A loopback UDP address where nothing listens.
pub fn closed_udp_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// The binary with no test hook or proxy setting inherited from this machine.
pub fn command(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_domain-check"));
    cmd.args(args).stdin(Stdio::null());
    for (name, _) in std::env::vars() {
        let upper = name.to_ascii_uppercase();
        if upper.starts_with("DOMAIN_CHECK_") || upper.ends_with("_PROXY") {
            cmd.env_remove(name);
        }
    }
    cmd.env("NO_COLOR", "1").envs(env.iter().copied());
    cmd
}

/// Runs the binary; exit code, stdout, stderr.
pub fn run(args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let out = command(args, env).output().unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (
        out.status.code().unwrap(),
        text(out.stdout),
        text(out.stderr),
    )
}

/// The `--json` answer of a run that writes nothing on stderr.
pub fn json(args: &[&str], env: &[(&str, &str)]) -> (i32, serde_json::Value) {
    let (code, out, err) = run(&[args, &["--json"]].concat(), env);
    assert_eq!(err, "", "{args:?}");
    (code, serde_json::from_str(&out).unwrap())
}

/// Runs the binary with stdout (or stderr) a pipe nobody reads; exit code and the other
/// stream. The read end is dropped before the spawn, so no other test's child inherits it.
pub fn closed(args: &[&str], close_stdout: bool) -> (i32, String) {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let mut cmd = command(args, &[]);
    match close_stdout {
        true => cmd.stdout(writer).stderr(Stdio::piped()),
        false => cmd.stderr(writer).stdout(Stdio::piped()),
    };
    let out = cmd.output().unwrap();
    let other = if close_stdout { out.stderr } else { out.stdout };
    (
        out.status.code().unwrap(),
        String::from_utf8(other).unwrap(),
    )
}
