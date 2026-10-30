//! `lookup`: one query per record type through the resolver, like dig, as text or JSON.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use serde::Serialize;

use crate::dns::{self, RecordType, Resolver};
use crate::input::Target;
use crate::{Error, text};

pub const TYPES: [RecordType; 15] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::CAA,
    RecordType::SOA,
    RecordType::SRV,
    RecordType::PTR,
    RecordType::DS,
    RecordType::DNSKEY,
    RecordType::TLSA,
    RecordType::HTTPS,
    RecordType::SVCB,
];

/// Record type names, any case, each once in the order given.
pub fn types(raw: &[String]) -> Result<Vec<RecordType>, Error> {
    let mut out = Vec::new();
    for name in raw {
        let t = TYPES
            .into_iter()
            .find(|t| t.to_string().eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                Error::usage(
                    format!("Unknown record type '{name}'."),
                    "Use A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, PTR, DS, DNSKEY, TLSA, HTTPS or SVCB.",
                )
            })?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

/// The name to query and its types: `A AAAA` by default, PTR (and only PTR) for an address.
pub fn question(
    target: Target,
    types: Vec<RecordType>,
) -> Result<(String, Vec<RecordType>), Error> {
    match target {
        Target::Name(name) if types.is_empty() => Ok((name, vec![RecordType::A, RecordType::AAAA])),
        Target::Name(name) => Ok((name, types)),
        Target::Ip(ip) if types.iter().all(|&t| t == RecordType::PTR) => {
            Ok((reverse(ip), vec![RecordType::PTR]))
        }
        Target::Ip(ip) => Err(Error::usage(
            format!("{ip} is an IP address, so it can only be looked up as PTR."),
            format!("Try: domain-check lookup {ip}"),
        )),
    }
}

/// The `in-addr.arpa` or `ip6.arpa` name of an address.
pub fn reverse(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<String> = v6
                .octets()
                .iter()
                .rev()
                .flat_map(|b| [b & 0xf, b >> 4])
                .map(|n| format!("{n:x}"))
                .collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Answer {
    pub name: String,
    pub server: String,
    pub results: Vec<Reply>,
    /// The address named in "Couldn't reach the DNS resolver …".
    #[serde(skip)]
    pub resolver: String,
}

#[derive(Debug, Serialize)]
pub struct Reply {
    #[serde(rename = "type")]
    pub kind: String,
    /// `None` when no answer came back at all; `error` says why.
    pub rcode: Option<String>,
    pub authoritative: bool,
    pub authenticated: bool,
    pub records: Vec<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Value {
    pub value: String,
    pub ttl: u32,
    /// The record's own name, which differs from the query's after a CNAME.
    #[serde(skip)]
    pub owner: String,
}

/// Asks for every type, up to 8 at a time.
pub async fn run(resolver: Arc<Resolver>, name: String, types: Vec<RecordType>) -> Answer {
    let answers = dns::lookups(&resolver, &name, &types).await;
    let results = types.into_iter().zip(answers).map(reply).collect();
    Answer {
        name,
        server: resolver.label.clone(),
        results,
        resolver: dns::show(resolver.first()),
    }
}

fn reply((t, answer): (RecordType, dns::Answer)) -> Reply {
    match answer {
        Ok(m) => Reply {
            kind: t.to_string(),
            rcode: Some(dns::rcode(m.metadata.response_code)),
            authoritative: m.metadata.authoritative,
            authenticated: m.metadata.authentic_data,
            records: dns::records(&m, t)
                .map(|r| Value {
                    value: dns::value(&r.data),
                    ttl: r.ttl,
                    owner: dns::name(&r.name),
                })
                .collect(),
            error: None,
        },
        Err(e) => Reply {
            kind: t.to_string(),
            rcode: None,
            authoritative: false,
            authenticated: false,
            records: Vec::new(),
            error: Some(e.to_string()),
        },
    }
}

impl Answer {
    /// 1 when the name doesn't exist, else 3 when a type got no usable answer, else 0.
    pub fn exit_code(&self) -> u8 {
        fn rcode(r: &Reply) -> Option<&str> {
            r.rcode.as_deref()
        }
        if self.results.iter().any(|r| rcode(r) == Some("NXDOMAIN")) {
            1
        } else if self.results.iter().all(|r| rcode(r) == Some("NOERROR")) {
            0
        } else {
            3
        }
    }

    /// `<name>  <ttl>  <TYPE>  <value>` per record, `; NODATA <TYPE>`, `; SERVFAIL <TYPE>` or
    /// one `; NXDOMAIN` for an empty answer, in columns.
    pub fn text(&self) -> String {
        let mut rows: Vec<[String; 4]> = Vec::new();
        let mut nxdomain = false;
        for r in &self.results {
            let empty = match r.rcode.as_deref() {
                None => continue,
                Some("NXDOMAIN") if nxdomain => continue,
                Some("NXDOMAIN") => {
                    nxdomain = true;
                    "; NXDOMAIN".to_string()
                }
                Some("NOERROR") if !r.records.is_empty() => {
                    for v in &r.records {
                        let row = [&v.owner, &v.ttl.to_string(), &r.kind, &v.value];
                        rows.push(row.map(String::from));
                    }
                    continue;
                }
                Some("NOERROR") => format!("; NODATA {}", r.kind),
                Some(code) => format!("; {code} {}", r.kind),
            };
            rows.push([self.name.clone(), empty, String::new(), String::new()]);
        }
        let records = || rows.iter().filter(|r| !r[2].is_empty());
        let width = |i: usize| records().map(|r| r[i].len()).max().unwrap_or(0);
        let name = rows.iter().map(|r| r[0].len()).max().unwrap_or(0);
        let (ttl, kind) = (width(1), width(2));
        let mut out = String::new();
        for [owner, ttl_or_note, t, value] in &rows {
            let owner = text::dim(&format!("{owner:name$}"));
            let line = match (t.is_empty(), ttl_or_note.starts_with("; SERVFAIL")) {
                (true, true) => format!("{owner}  {}", text::yellow(ttl_or_note)),
                (true, false) => format!("{owner}  {ttl_or_note}"),
                _ => {
                    let t = text::bold(&format!("{t:kind$}"));
                    format!("{owner}  {ttl_or_note:ttl$}  {t}  {value}")
                }
            };
            out += line.trim_end();
            out += "\n";
        }
        out
    }

    /// One line per distinct reason no answer came back.
    pub fn failures(&self) -> Vec<Error> {
        let why: BTreeSet<_> = self
            .results
            .iter()
            .filter_map(|r| r.error.as_deref())
            .collect();
        why.into_iter()
            .map(|w| {
                Error::new(
                    "unreachable",
                    format!("Couldn't reach the DNS resolver {}: {w}.", self.resolver),
                    "Check the network connection, or pass --dns with a resolver you can reach.",
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_turn_into_ptr_names() {
        assert_eq!(
            reverse("192.0.2.10".parse().unwrap()),
            "10.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn types_are_case_insensitive_and_checked() {
        let raw = |s: &[&str]| s.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        let got = types(&raw(&["mx", "TXT", "Mx", "dnskey"])).unwrap();
        assert_eq!(got, [RecordType::MX, RecordType::TXT, RecordType::DNSKEY]);
        let e = types(&raw(&["A", "AXFR"])).unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            ("usage", "Unknown record type 'AXFR'.")
        );
        let ip = || Target::Ip("192.0.2.1".parse().unwrap());
        let (name, t) = question(ip(), Vec::new()).unwrap();
        assert_eq!(
            (name.as_str(), t),
            ("1.2.0.192.in-addr.arpa", vec![RecordType::PTR])
        );
        assert!(question(ip(), vec![RecordType::PTR]).is_ok());
        let e = question(ip(), vec![RecordType::MX]).unwrap_err();
        assert_eq!(
            e.message,
            "192.0.2.1 is an IP address, so it can only be looked up as PTR."
        );
        let name = Target::Name("example.com".into());
        assert_eq!(
            question(name, Vec::new()).unwrap().1,
            [RecordType::A, RecordType::AAAA]
        );
    }
}
