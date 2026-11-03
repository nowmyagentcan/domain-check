//! DNS queries: through this computer's resolver (or `--dns`), or straight to one server with
//! the bits a check needs (RD, CD, DO). UDP first, TCP when the answer comes back truncated;
//! each try waits 2 s (TCP 4 s) and a try that gets no answer is made once more.

use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use hickory_net::NetError;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::{DnsHandle, FirstAnswer};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Query};
pub use hickory_proto::op::{Message, ResponseCode};
pub use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::{Error, Ports};

const UDP_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(4);
const PAYLOAD: u16 = 1232;

/// The header bits a query sets.
#[derive(Clone, Copy, Debug)]
pub struct Ask {
    /// Recursion desired: on for resolvers, off for authoritative servers.
    pub rd: bool,
    /// Checking disabled: the resolver returns data that fails DNSSEC validation.
    pub cd: bool,
    /// DNSSEC OK: send signatures along.
    pub dnssec_ok: bool,
}

pub const RECURSIVE: Ask = Ask {
    rd: true,
    cd: false,
    dnssec_ok: false,
};

/// A query that got no response at all.
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    Timeout,
    Refused,
    NoRoute,
    Other(String),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Failure::Timeout => "timeout",
            Failure::Refused => "connection refused",
            Failure::NoRoute => "network unreachable",
            Failure::Other(why) => why,
        })
    }
}

impl From<NetError> for Failure {
    fn from(e: NetError) -> Failure {
        match e {
            NetError::Timeout => Failure::Timeout,
            NetError::Io(e) => match e.kind() {
                ErrorKind::TimedOut => Failure::Timeout,
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset => Failure::Refused,
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => Failure::NoRoute,
                _ => Failure::Other(e.to_string()),
            },
            e => Failure::Other(e.to_string()),
        }
    }
}

/// `IP[:PORT]` (`[v6]:PORT` with a port) as an address; port 53 when left out.
pub fn server(flag: &str, raw: &str) -> Result<SocketAddr, Error> {
    raw.parse()
        .or_else(|_| raw.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| {
            Error::usage(
                format!("{flag} {raw} isn't an IP address."),
                "Pass an IP address, with a port if it isn't 53, e.g. 1.1.1.1 or 127.0.0.1:5353.",
            )
        })
}

/// An address as people write it: the port only when it isn't 53.
pub fn show(addr: SocketAddr) -> String {
    match addr.port() {
        53 => addr.ip().to_string(),
        _ => addr.to_string(),
    }
}

/// This computer's resolver, or the one `--dns` names, and how queries leave the machine.
#[derive(Debug)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    /// `system (192.168.1.1)` or the `--dns` address.
    pub label: String,
    ports: Ports,
    debug: bool,
}

impl Resolver {
    pub fn new(dns: Option<SocketAddr>, ports: Ports, debug: bool) -> Result<Resolver, Error> {
        let (servers, label) = match dns {
            Some(addr) => (vec![addr], show(addr)),
            None => {
                let servers = system_servers()?;
                let label = format!("system ({})", servers[0].ip());
                (servers, label)
            }
        };
        Ok(Resolver {
            servers,
            label,
            ports,
            debug,
        })
    }

    /// The first server this resolver asks.
    pub fn first(&self) -> SocketAddr {
        self.servers[0]
    }

    /// Asks the resolver with recursion on; the next system server only when one doesn't
    /// answer. Two tries in all.
    pub async fn lookup(&self, name: &str, t: RecordType) -> Result<Message, Failure> {
        let mut last = Failure::Timeout;
        for i in 0..2 {
            let server = self.servers[i % self.servers.len()];
            match self.once(server, name, t, RECURSIVE).await {
                Ok(m) => return Ok(m),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Asks one server directly, tried twice when it doesn't answer.
    pub async fn query(
        &self,
        server: SocketAddr,
        name: &str,
        t: RecordType,
        ask: Ask,
    ) -> Result<Message, Failure> {
        match self.once(server, name, t, ask).await {
            Err(Failure::Timeout) => self.once(server, name, t, ask).await,
            answer => answer,
        }
    }

    async fn once(
        &self,
        server: SocketAddr,
        name: &str,
        t: RecordType,
        ask: Ask,
    ) -> Result<Message, Failure> {
        let to = self.ports.swap(server);
        let udp = self.send(to, name, t, ask, false).await?;
        if !udp.metadata.truncation {
            return Ok(udp);
        }
        self.send(to, name, t, ask, true).await
    }

    async fn send(
        &self,
        to: SocketAddr,
        name: &str,
        t: RecordType,
        ask: Ask,
        tcp: bool,
    ) -> Result<Message, Failure> {
        let start = Instant::now();
        let answer = exchange(to, name, t, ask, tcp).await;
        if self.debug {
            let outcome = match &answer {
                Ok(m) => format!("{} {}", rcode(m.metadata.response_code), flags(m)),
                Err(e) => e.to_string(),
            };
            let ms = start.elapsed().as_millis();
            let via = if tcp { "tcp" } else { "udp" };
            crate::net::debug(&format!("dns {via} {to} {name} {t} {outcome} {ms} ms"));
        }
        answer
    }
}

async fn exchange(
    to: SocketAddr,
    name: &str,
    t: RecordType,
    ask: Ask,
    tcp: bool,
) -> Result<Message, Failure> {
    let fqdn = Name::from_ascii(format!("{name}.")).map_err(|e| Failure::Other(e.to_string()))?;
    let mut options = DnsRequestOptions::default();
    options.recursion_desired = ask.rd;
    options.edns_set_dnssec_ok = ask.dnssec_ok;
    options.edns_payload_len = PAYLOAD;
    let mut request = DnsRequest::from_query(Query::query(fqdn, t), options);
    request.metadata.checking_disabled = ask.cd;
    // RFC 6840 §5.7: a validating resolver sets AD in its answer only when the query does.
    request.metadata.authentic_data = true;
    // The connection's background task lives as long as a clone of the provider does.
    let provider = TokioRuntimeProvider::default();
    let response = if tcp {
        let p = provider.clone();
        TcpClientStream::exchange(to, None, TCP_TIMEOUT, None, p)
            .await?
            .send(request)
            .first_answer()
            .await
    } else {
        // A port of hickory's own random choice can be one another program bound on 127.0.0.1
        // only, and on Windows that socket then takes a loopback server's reply; the OS never
        // hands out such a port.
        UdpClientStream::builder(to, provider.clone())
            .with_timeout(Some(UDP_TIMEOUT))
            .with_os_port_selection(true)
            .with_max_retries(1)
            .exchange()
            .send(request)
            .first_answer()
            .await
    };
    Ok(response?.into_message())
}

/// A response code as dig writes it: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`.
pub fn rcode(code: ResponseCode) -> String {
    let name = match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        other => return format!("RCODE{}", u16::from(other)),
    };
    name.to_string()
}

/// The header flags that are set, as dig shows them: `aa tc rd ra ad cd`.
pub fn flags(m: &Message) -> String {
    let h = &m.metadata;
    let set = [
        (h.authoritative, "aa"),
        (h.truncation, "tc"),
        (h.recursion_desired, "rd"),
        (h.recursion_available, "ra"),
        (h.authentic_data, "ad"),
        (h.checking_disabled, "cd"),
    ];
    let on: Vec<_> = set.iter().filter(|(on, _)| *on).map(|(_, f)| *f).collect();
    on.join(" ")
}

/// The OS's DNS servers, each once, in order.
fn system_servers() -> Result<Vec<SocketAddr>, Error> {
    let fail = |why: String| {
        Error::new(
            "runtime",
            format!("Couldn't read this computer's DNS settings: {why}."),
            "Pass --dns with a resolver, e.g. --dns 1.1.1.1.",
        )
    };
    let (config, _) =
        hickory_resolver::system_conf::read_system_conf().map_err(|e| fail(e.to_string()))?;
    let mut servers = Vec::new();
    for ns in config.name_servers() {
        let port = ns.connections.first().map_or(53, |c| c.port);
        let addr = SocketAddr::new(ns.ip, port);
        if !servers.contains(&addr) {
            servers.push(addr);
        }
    }
    match servers.is_empty() {
        true => Err(fail("no DNS servers are set".into())),
        false => Ok(servers),
    }
}

/// A record's value in presentation format (RFC 1035 §5.1), with names that don't end in a
/// dot, TXT strings joined, and DS and DNSKEY read from their raw data.
pub fn value(data: &RData) -> String {
    match data {
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|s| String::from_utf8_lossy(s))
            .collect(),
        RData::Unknown { code, rdata } => raw(*code, &rdata.anything),
        RData::CNAME(_)
        | RData::NS(_)
        | RData::PTR(_)
        | RData::MX(_)
        | RData::SOA(_)
        | RData::SRV(_)
        | RData::HTTPS(_)
        | RData::SVCB(_) => {
            let text = data.to_string();
            let words = text.split(' ').map(|w| match w.len() {
                1 => w,
                // hickory ends an SVCB alpn list with a comma.
                _ => w.strip_suffix(['.', ',']).unwrap_or(w),
            });
            words.collect::<Vec<_>>().join(" ")
        }
        _ => data.to_string(),
    }
}

/// DS (RFC 4034 §5.3) and DNSKEY (§2.2) from their wire form; any other unknown data in the
/// generic form of RFC 3597 §5.
fn raw(t: RecordType, b: &[u8]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    match (t, b) {
        (RecordType::DS, [t0, t1, alg, digest, rest @ ..]) => {
            let tag = u16::from_be_bytes([*t0, *t1]);
            format!("{tag} {alg} {digest} {}", hex(rest))
        }
        (RecordType::DNSKEY, [f0, f1, protocol, alg, key @ ..]) => {
            let flags = u16::from_be_bytes([*f0, *f1]);
            let key = base64::engine::general_purpose::STANDARD.encode(key);
            format!("{flags} {protocol} {alg} {key}")
        }
        _ => format!("\\# {} {}", b.len(), hex(b)),
    }
}

/// The records of type `t` in an answer.
pub fn records(m: &Message, t: RecordType) -> impl Iterator<Item = &Record> {
    m.answers.iter().filter(move |r| r.record_type() == t)
}

/// A name as reports write it: lower case, no trailing dot.
pub fn name(n: &Name) -> String {
    n.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// The target of `owner`'s CNAME in an answer.
pub fn cname(m: &Message, owner: &str) -> Option<String> {
    m.answers.iter().find_map(|r| match &r.data {
        RData::CNAME(target) if name(&r.name) == owner => Some(name(&target.0)),
        _ => None,
    })
}

/// What a query got: the response, or why none came.
pub type Answer = Result<Message, Failure>;

/// Why nothing came back, when none of the queries got a response.
pub fn unanswered<'a>(answers: impl IntoIterator<Item = &'a Answer>) -> Option<&'a Failure> {
    let mut failures = answers.into_iter().map(|a| a.as_ref().err());
    failures
        .next()
        .flatten()
        .filter(|_| failures.all(|f| f.is_some()))
}

/// Runs the futures together on this thread's runtime; their outputs in order.
pub async fn join<F>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let tasks: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(tasks.len());
    for task in tasks {
        out.push(wait(task).await);
    }
    out
}

/// A spawned task's output.
pub async fn wait<T>(task: tokio::task::JoinHandle<T>) -> T {
    match task.await {
        Ok(v) => v,
        // A task fails only by panicking, and panics abort in release builds.
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// Asks the resolver for several types of one name, up to 8 at a time.
pub async fn lookups(r: &Arc<Resolver>, name: &str, types: &[RecordType]) -> Vec<Answer> {
    let questions: Vec<_> = types.iter().map(|&t| (name.to_string(), t)).collect();
    ask_all(r, None, questions, RECURSIVE).await
}

/// Asks `server` (the resolver when `None`) each question, up to 8 at a time.
pub async fn ask_all(
    r: &Arc<Resolver>,
    server: Option<SocketAddr>,
    questions: Vec<(String, RecordType)>,
    ask: Ask,
) -> Vec<Answer> {
    let mut out = Vec::with_capacity(questions.len());
    for chunk in questions.chunks(8) {
        let asks = chunk.iter().cloned().map(|(name, t)| {
            let r = Arc::clone(r);
            async move {
                match server {
                    Some(at) => r.query(at, &name, t, ask).await,
                    None => r.lookup(&name, t).await,
                }
            }
        });
        out.extend(join(asks).await);
    }
    out
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::rr::rdata::{CAA, MX, NULL, SOA, SRV, TLSA, TXT};

    use super::*;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn servers_are_ip_addresses_with_an_optional_port() {
        let at = |s| server("--dns", s).map(|a| a.to_string());
        assert_eq!(at("1.1.1.1").unwrap(), "1.1.1.1:53");
        assert_eq!(at("127.0.0.1:5353").unwrap(), "127.0.0.1:5353");
        assert_eq!(at("::1").unwrap(), "[::1]:53");
        assert_eq!(at("[::1]:5353").unwrap(), "[::1]:5353");
        let e = server("--dns", "dns.example").unwrap_err();
        assert_eq!(e.code, "usage");
        assert_eq!(e.message, "--dns dns.example isn't an IP address.");
        assert!(server("--dns", "1.1.1.1:99999").is_err());
        assert_eq!(show("1.1.1.1:53".parse().unwrap()), "1.1.1.1");
        assert_eq!(show("[::1]:5353".parse().unwrap()), "[::1]:5353");
    }

    #[test]
    fn values_use_presentation_format() {
        let mx = RData::MX(MX::new(10, name("mx1.example.net.")));
        assert_eq!(value(&mx), "10 mx1.example.net");
        let null_mx = RData::MX(MX::new(0, Name::root()));
        assert_eq!(value(&null_mx), "0 .");
        let txt = RData::TXT(TXT::new(vec!["v=spf1 ".into(), "-all".into()]));
        assert_eq!(value(&txt), "v=spf1 -all");
        let soa = SOA::new(
            name("ns1.example.net."),
            name("hostmaster.example.net."),
            2026103001,
            7200,
            3600,
            1209600,
            300,
        );
        assert_eq!(
            value(&RData::SOA(soa)),
            "ns1.example.net hostmaster.example.net 2026103001 7200 3600 1209600 300"
        );
        let srv = RData::SRV(SRV::new(10, 5, 443, name("www.example.com.")));
        assert_eq!(value(&srv), "10 5 443 www.example.com");
        let caa = CAA::new_issue(false, Some(name("letsencrypt.org")), vec![]);
        assert_eq!(value(&RData::CAA(caa)), "0 issue \"letsencrypt.org\"");
        let tlsa = TLSA::new(3.into(), 1.into(), 1.into(), vec![0xab, 0x01]);
        assert_eq!(value(&RData::TLSA(tlsa)), "3 1 1 ab01");
    }

    #[test]
    fn ds_and_dnskey_come_from_raw_data() {
        let unknown = |code, b: &[u8]| RData::Unknown {
            code,
            rdata: NULL::with(b.to_vec()),
        };
        let ds = unknown(RecordType::DS, &[0x30, 0x39, 13, 2, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(value(&ds), "12345 13 2 deadbeef");
        let key = unknown(RecordType::DNSKEY, &[1, 1, 3, 13, b'k', b'e', b'y']);
        assert_eq!(value(&key), "257 3 13 a2V5");
        let short = unknown(RecordType::DS, &[1, 2]);
        assert_eq!(value(&short), "\\# 2 0102");
    }
}
