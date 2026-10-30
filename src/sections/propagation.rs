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

/// How the resolvers are asked.
const RECURSIVE: Ask = Ask {
    rd: true,
    ..AUTHORITATIVE
};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Propagation {
    pub types: Vec<String>,
    pub zone: Option<String>,
    /// Every resolver that answered agrees with the nameservers; `None` when there was nothing
    /// to compare.
    pub consistent: Option<bool>,
    pub authoritative: Vec<Server>,
    pub resolvers: Vec<View>,
    /// Types the authoritative servers answer differently (geo-DNS, load balancing).
    pub varies: Vec<String>,
    pub wildcard: bool,
    /// This computer's resolver answers for a name the nameservers say doesn't exist.
    pub rewrites_nxdomain: bool,
}

/// What one resolver has cached.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct View {
    pub name: &'static str,
    pub address: String,
    /// `ok`, `timeout`, `refused` or `error`.
    pub status: &'static str,
    pub answers: Keyed<Seen>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Seen {
    #[serde(flatten)]
    pub got: Got,
    /// Matches an authoritative answer; `None` for a `varies` type or with none to match.
    pub agrees: Option<bool>,
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

    let types: Vec<_> = cx.types.iter().map(|&t| (d.to_string(), t)).collect();
    let questions = [vec![(zone.clone(), RecordType::SOA)], types.clone()].concat();
    let asks: Vec<_> = targets
        .iter()
        .map(|&(_, ip)| {
            let (r, questions) = (Arc::clone(r), questions.clone());
            let at = SocketAddr::new(ip, 53);
            async move { dns::ask_all(&r, Some(at), questions, AUTHORITATIVE).await }
        })
        .collect();
    let auth = tokio::spawn(dns::join(asks));
    // This computer's resolver last, under the name "System".
    let mut views: Vec<_> = cx.resolvers.iter().map(|&(n, at)| (n, Some(at))).collect();
    views.push(("System", None));
    let asks: Vec<_> = views
        .iter()
        .map(|&(_, at)| {
            let (r, types) = (Arc::clone(r), types.clone());
            async move { dns::ask_all(&r, at, types, RECURSIVE).await }
        })
        .collect();
    let seen = tokio::spawn(dns::join(asks));
    let probe = tokio::spawn({
        let first = targets.first().map(|&(_, ip)| SocketAddr::new(ip, 53));
        let (r, name) = (Arc::clone(r), format!("{}.{d}", probe_label()));
        async move {
            let auth = match first {
                Some(at) => Some(r.query(at, &name, RecordType::A, AUTHORITATIVE).await),
                None => None,
            };
            (auth, r.lookup(&name, RecordType::A).await)
        }
    });
    let replies = dns::wait(auth).await;

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
    for (&(name, at), replies) in views.iter().zip(dns::wait(seen).await) {
        let address = at.unwrap_or(r.first());
        let status = view_status(&replies);
        if let (Some(at), Some(why)) = (at, dns::unanswered(&replies)) {
            let (ip, port) = (at.ip(), at.port());
            let message = format!("Couldn't reach {name} ({ip}) on port {port}: {why}.");
            let hint =
                "Your network may block DNS to outside resolvers; the other results still stand.";
            found.push(finding(
                Severity::Info,
                "resolver_unreachable",
                message,
                hint,
            ));
        }
        let answers = cx.types.iter().zip(&replies).filter_map(|(t, a)| {
            let got = Got::of(a.as_ref().ok()?, d, *t);
            Some((t.to_string(), Seen { got, agrees: None }))
        });
        out.resolvers.push(View {
            name,
            address: dns::show(address),
            status,
            answers: Keyed(answers.collect()),
        });
    }
    let (probe_auth, probe_system) = dns::wait(probe).await;
    let silent = |s: &str| matches!(s, "timeout" | "no_route" | "refused" | "error");
    let auth_silent = out.authoritative.iter().all(|s| silent(s.status));
    if auth_silent && out.resolvers.iter().all(|v| v.status != "ok") {
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

    // Each resolver's answer against every authoritative one, for the types that don't vary.
    let mut compared = false;
    for view in out.resolvers.iter_mut().filter(|v| v.status == "ok") {
        for (t, seen) in view.answers.0.iter_mut() {
            let expected: Vec<&Got> = ok.iter().filter_map(|s| s.answers.get(t)).collect();
            if out.varies.contains(t) || expected.is_empty() {
                continue;
            }
            let agrees = expected.iter().any(|g| g.key() == seen.got.key());
            seen.agrees = Some(agrees);
            compared = true;
            if !agrees {
                let (name, address) = (view.name, &view.address);
                let (got, want) = (describe(&seen.got), describe(expected[0]));
                let mut message = format!(
                    "{name} ({address}) still answers {t} {got} for {d}; the nameservers say {want}."
                );
                if let Some(ttl) = seen.got.ttl {
                    message += &format!(" Its copy expires within {ttl} s.");
                }
                found.push(finding(Severity::Info, "propagation_stale", message, ""));
            }
        }
    }
    let mut views = out.resolvers.iter().flat_map(|v| &v.answers.0);
    out.consistent = compared.then(|| views.all(|(_, s)| s.agrees != Some(false)));

    if let Some(Ok(m)) = &probe_auth {
        let code = m.metadata.response_code;
        out.wildcard = code == ResponseCode::NoError && !m.answers.is_empty();
        out.rewrites_nxdomain = code == ResponseCode::NXDomain
            && probe_system
                .as_ref()
                .is_ok_and(|m| first_address(m).is_some());
    }
    if out.wildcard {
        let message = format!("{zone} has a wildcard record: any name under {d} resolves.");
        found.push(finding(Severity::Info, "wildcard", message, ""));
    }
    if out.rewrites_nxdomain {
        let message = format!(
            "Your DNS resolver ({}) answers for names that don't exist, so what you see may differ from the internet.",
            dns::show(r.first())
        );
        let hint =
            "Your ISP or network may be redirecting typos; compare with the public resolvers.";
        found.push(finding(
            Severity::Warning,
            "resolver_rewrites_nxdomain",
            message,
            hint,
        ));
    }
    (Section::ok(out), found)
}

/// An answer as the stale-copy message quotes it.
fn describe(g: &Got) -> String {
    match (g.values.is_empty(), g.rcode.as_str()) {
        (false, _) => g.values.join(", "),
        (true, "NOERROR") => "no records".into(),
        (true, code) => code.into(),
    }
}

/// `dc-` and 16 random letters and digits: a name nobody has created.
fn probe_label() -> String {
    use std::hash::BuildHasher;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let seed = std::collections::hash_map::RandomState::new();
    let pick = |i: u8| char::from(CHARS[(seed.hash_one(i) % 36) as usize]);
    format!("dc-{}", (0..16).map(pick).collect::<String>())
}

/// A resolver's status: `ok` once any query got an answer other than REFUSED.
fn view_status(replies: &[Answer]) -> &'static str {
    let refused = |a: &Answer| match a {
        Ok(m) => m.metadata.response_code == ResponseCode::Refused,
        Err(f) => *f == Failure::Refused,
    };
    if replies.iter().any(|a| a.is_ok() && !refused(a)) {
        "ok"
    } else if replies.iter().any(refused) {
        "refused"
    } else if replies.iter().any(|a| matches!(a, Err(Failure::Timeout))) {
        "timeout"
    } else {
        "error"
    }
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
