//! The `propagation` section: every authoritative nameserver of the zone asked directly, with
//! recursion off, for the zone's SOA and the compared record types.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use serde::Serialize;

use crate::check::{Cx, Facts};
use crate::dns::{self, Answer, Ask, Failure, Message, RData, RecordType, ResponseCode};
use crate::report::{Check, Finding, Keyed, Section, Severity, Status};

/// Nameserver hosts asked; each gives its first A and first AAAA address.
const MAX_HOSTS: usize = 8;

/// How authoritative servers are asked: no recursion, signatures included.
const AUTHORITATIVE: Ask = Ask {
    rd: false,
    cd: false,
    dnssec_ok: true,
};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Propagation {
    pub types: Vec<String>,
    pub zone: Option<String>,
    pub authoritative: Vec<Server>,
    /// Types the authoritative servers answer differently (geo-DNS, load balancing).
    pub varies: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Server {
    pub server: String,
    pub address: String,
    /// `ok`, `lame`, `timeout`, `refused`, `no_route` or `error`.
    pub status: &'static str,
    pub soa_serial: Option<u32>,
    pub answers: Keyed<Got>,
}

/// One type's answer from one server.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Got {
    pub rcode: String,
    pub values: Vec<String>,
    pub ttl: Option<u32>,
}

impl Got {
    /// The records owned by `name` (a CNAME there as `CNAME <target>`), in answer order.
    fn of(m: &Message, name: &str, t: RecordType) -> Got {
        let own: Vec<_> = m
            .answers
            .iter()
            .filter(|r| dns::name(&r.name) == name)
            .filter(|r| r.record_type() == t || r.record_type() == RecordType::CNAME)
            .collect();
        let values = own.iter().map(|r| match r.record_type() == t {
            true => dns::value(&r.data),
            false => format!("CNAME {}", dns::value(&r.data)),
        });
        // An empty answer is cached for the SOA's TTL (RFC 2308 §5).
        let soa = m
            .authorities
            .iter()
            .find(|r| r.record_type() == RecordType::SOA);
        Got {
            rcode: dns::rcode(m.metadata.response_code),
            values: values.collect(),
            ttl: own.first().copied().or(soa).map(|r| r.ttl),
        }
    }

    /// The answer as compared: its code and its values, lower case and sorted.
    fn key(&self) -> (String, Vec<String>) {
        let mut values: Vec<_> = self.values.iter().map(|v| v.to_lowercase()).collect();
        values.sort();
        (self.rcode.clone(), values)
    }
}

fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Propagation, severity, code, message, hint)
}

pub async fn run(cx: &Cx, facts: &Facts) -> (Section<Propagation>, Vec<Finding>) {
    let Some(zone) = facts.zone.clone() else {
        let reason = "No DNS answer, so this check couldn't run.";
        return (Section::not(Status::Unavailable, reason), Vec::new());
    };
    let (r, d) = (&cx.resolver, cx.domain.as_str());
    let mut hosts: Vec<String> = match r.lookup(&zone, RecordType::NS).await {
        Ok(m) => dns::records(&m, RecordType::NS)
            .filter_map(|x| match &x.data {
                RData::NS(ns) => Some(dns::name(&ns.0)),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    hosts.sort();
    hosts.dedup();
    let named = hosts.len();
    hosts.truncate(MAX_HOSTS);

    let addresses = hosts.iter().map(|host| {
        let (r, host) = (Arc::clone(r), host.clone());
        async move { dns::lookups(&r, &host, &[RecordType::A, RecordType::AAAA]).await }
    });
    let mut targets: Vec<(String, IpAddr)> = Vec::new();
    for (host, answers) in hosts.iter().zip(dns::join(addresses).await) {
        for ip in answers.iter().flatten().filter_map(first_address) {
            if !targets.iter().any(|(_, seen)| *seen == ip) {
                targets.push((host.clone(), ip));
            }
        }
    }

    let mut questions = vec![(zone.clone(), RecordType::SOA)];
    questions.extend(cx.types.iter().map(|&t| (d.to_string(), t)));
    let asks = targets.iter().map(|&(_, ip)| {
        let (r, questions) = (Arc::clone(r), questions.clone());
        let at = SocketAddr::new(ip, 53);
        async move { dns::ask_all(&r, Some(at), questions, AUTHORITATIVE).await }
    });
    let replies = dns::join(asks).await;

    let mut found = Vec::new();
    let mut out = Propagation {
        types: cx.types.iter().map(|t| t.to_string()).collect(),
        zone: Some(zone.clone()),
        ..Propagation::default()
    };
    for ((host, ip), replies) in targets.iter().zip(replies) {
        let (status, why) = status(&replies[0]);
        let server = |text: &str| format!("Nameserver {host} ({ip}) {text}");
        match status {
            "timeout" => {
                let message = server("didn't answer within 4 s.");
                let hint = "It may be down, or your network may block DNS to outside servers.";
                found.push(finding(Severity::Warning, "ns_timeout", message, hint));
            }
            "lame" | "refused" | "error" => {
                let message = server(&format!(
                    "doesn't answer authoritatively for {zone} ({why})."
                ));
                let hint = "Fix it at your DNS host, or remove it from the NS records and at your registrar.";
                found.push(finding(Severity::Error, "ns_lame", message, hint));
            }
            _ => {}
        }
        let soa_serial = replies[0].as_ref().ok().and_then(|m| {
            m.answers.iter().find_map(|x| match &x.data {
                RData::SOA(soa) => Some(soa.serial),
                _ => None,
            })
        });
        let answers = cx.types.iter().zip(&replies[1..]).filter_map(|(t, a)| {
            let m = a.as_ref().ok()?;
            Some((t.to_string(), Got::of(m, d, *t)))
        });
        out.authoritative.push(Server {
            server: host.clone(),
            address: ip.to_string(),
            status,
            soa_serial,
            answers: Keyed(answers.collect()),
        });
    }
    if out
        .authoritative
        .iter()
        .all(|s| matches!(s.status, "timeout" | "no_route" | "refused" | "error"))
    {
        let reason = "None of the nameservers or resolvers answered.";
        return (Section::not(Status::Unavailable, reason), found);
    }

    let ok: Vec<&Server> = out
        .authoritative
        .iter()
        .filter(|s| s.status == "ok")
        .collect();
    if named == 1 {
        let hint = "Use at least two, on different networks (RFC 2182).";
        let message = format!("{zone} has only one nameserver.");
        found.push(finding(Severity::Warning, "ns_single", message, hint));
    }
    let mut serials = ok.iter().filter_map(|s| Some((s.soa_serial?, &s.server)));
    if let Some((first, on)) = serials.next()
        && let Some((other, on_other)) = serials.find(|(s, _)| *s != first)
    {
        let message = format!(
            "The nameservers serve different versions of {zone}: serial {first} on {on}, {other} on {on_other}."
        );
        let hint = "A change may still be reaching the secondaries, or one stopped updating.";
        found.push(finding(
            Severity::Warning,
            "soa_serial_mismatch",
            message,
            hint,
        ));
    }
    for t in &out.types {
        let sets: BTreeSet<_> = ok
            .iter()
            .filter_map(|s| s.answers.get(t))
            .filter(|g| g.rcode == "NOERROR")
            .map(Got::key)
            .collect();
        if sets.len() > 1 {
            out.varies.push(t.clone());
            let message = format!(
                "The nameservers give different {t} answers for {d} (normal for geo-DNS or load balancing), so resolvers aren't compared for {t}."
            );
            found.push(finding(Severity::Info, "propagation_varies", message, ""));
        }
    }
    (Section::ok(out), found)
}

/// The first address in an A or AAAA answer.
fn first_address(m: &Message) -> Option<IpAddr> {
    m.answers.iter().find_map(|r| match &r.data {
        RData::A(a) => Some(IpAddr::V4(a.0)),
        RData::AAAA(a) => Some(IpAddr::V6(a.0)),
        _ => None,
    })
}

/// A nameserver's status from its SOA answer, and why it is lame.
fn status(soa: &Answer) -> (&'static str, String) {
    match soa {
        Err(Failure::Timeout) => ("timeout", String::new()),
        Err(Failure::NoRoute) => ("no_route", String::new()),
        Err(Failure::Refused) => ("refused", "connection refused".into()),
        Err(Failure::Other(why)) => ("error", why.clone()),
        Ok(m) => match m.metadata.response_code {
            ResponseCode::ServFail => ("lame", "SERVFAIL".into()),
            ResponseCode::Refused => ("lame", "REFUSED".into()),
            _ if !m.metadata.authoritative => ("lame", "no AA flag".into()),
            _ => ("ok", String::new()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_follow_the_soa_answer() {
        let reply = |code, aa| {
            let mut m = Message::response(1, hickory_proto::op::OpCode::Query);
            m.metadata.response_code = code;
            m.metadata.authoritative = aa;
            Ok(m)
        };
        let s = |a: Answer| status(&a);
        assert_eq!(s(reply(ResponseCode::NoError, true)).0, "ok");
        assert_eq!(s(reply(ResponseCode::NXDomain, true)).0, "ok");
        assert_eq!(
            s(reply(ResponseCode::NoError, false)),
            ("lame", "no AA flag".into())
        );
        assert_eq!(
            s(reply(ResponseCode::ServFail, true)),
            ("lame", "SERVFAIL".into())
        );
        assert_eq!(
            s(reply(ResponseCode::Refused, true)),
            ("lame", "REFUSED".into())
        );
        assert_eq!(s(Err(Failure::Timeout)).0, "timeout");
        assert_eq!(s(Err(Failure::NoRoute)).0, "no_route");
        assert_eq!(s(Err(Failure::Refused)).0, "refused");
    }
}
