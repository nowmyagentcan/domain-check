//! The `dns` section: the domain's records, its CNAME chain and the CAA records in force.

use serde::Serialize;

use crate::check::{Cx, Facts, parent};
use crate::dns::{self, Answer, RecordType, Resolver, ResponseCode};
use crate::report::{Check, Finding, Keyed, Section, Severity, Status};

const TYPES: [RecordType; 11] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::NS,
    RecordType::TXT,
    RecordType::CAA,
    RecordType::SOA,
    RecordType::HTTPS,
    RecordType::DS,
    RecordType::DNSKEY,
];

/// CNAME hops followed; some resolvers give up after this many.
const MAX_HOPS: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Dns {
    pub resolver: String,
    pub exists: bool,
    pub zone: Option<String>,
    pub records: Keyed<Vec<Rr>>,
    pub errors: Keyed<String>,
    pub cname_chain: Vec<String>,
    pub caa: Option<Caa>,
    pub dnssec: Dnssec,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Dnssec {
    /// A DS record at the parent.
    pub signed: bool,
    pub ds: Vec<Ds>,
    pub dnskey_algorithms: Vec<u8>,
    /// The resolvers that set AD: they validated the answer.
    pub validated_by: Vec<String>,
    /// Validating resolvers fail the name, and it loads only with checking disabled.
    pub bogus: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub algorithm_name: &'static str,
    pub digest_type: u8,
}

/// The IANA DNSSEC algorithm registry's mnemonic for `n`.
fn algorithm_name(n: u8) -> &'static str {
    match n {
        1 => "RSAMD5",
        2 => "DH",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        17 => "SM2SM3",
        23 => "ECC-GOST12",
        _ => "unknown",
    }
}

/// Algorithms RFC 8624 §3.1 says not to sign with.
const WEAK: [u8; 6] = [1, 3, 5, 6, 7, 12];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Rr {
    pub value: String,
    pub ttl: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Caa {
    pub found_at: String,
    pub records: Vec<String>,
}

fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Dns, severity, code, message, hint)
}

fn rcode(a: Option<&Answer>) -> Option<ResponseCode> {
    a?.as_ref().ok().map(|m| m.metadata.response_code)
}

pub async fn run(cx: &Cx, facts: &Facts) -> (Section<Dns>, Vec<Finding>) {
    let (r, d) = (&cx.resolver, cx.domain.as_str());
    if let Some(why) = facts.unanswered() {
        let at = dns::show(r.first());
        let reason = format!("Couldn't reach the DNS resolver {at}: {why}.");
        return (Section::not(Status::Unavailable, reason), Vec::new());
    }
    let exists = facts.exists(d);
    let mut answers = facts.answers.clone();
    if exists {
        let rest: Vec<_> = TYPES
            .into_iter()
            .filter(|&t| facts.answer(t).is_none())
            .collect();
        answers.extend(rest.iter().copied().zip(dns::lookups(r, d, &rest).await));
    }
    let get = |t| answers.iter().find(|(x, _)| *x == t).map(|(_, a)| a);
    let mut out = Dns {
        resolver: r.label.clone(),
        exists,
        zone: facts.zone.clone(),
        ..Dns::default()
    };
    for t in TYPES {
        let found = match get(t) {
            Some(Ok(m)) if exists => dns::records(m, t)
                .map(|x| Rr {
                    value: dns::value(&x.data),
                    ttl: x.ttl,
                })
                .collect(),
            _ => Vec::new(),
        };
        out.records.0.push((t.to_string(), found));
        let failed = match get(t) {
            Some(Err(why)) => Some(why.to_string()),
            Some(Ok(m)) => match m.metadata.response_code {
                ResponseCode::NoError | ResponseCode::NXDomain => None,
                code => Some(dns::rcode(code)),
            },
            None => None,
        };
        out.errors.0.extend(failed.map(|e| (t.to_string(), e)));
    }

    let mut found = Vec::new();
    if !exists {
        let message = format!("{d} doesn't exist in DNS (NXDOMAIN).");
        let hint = "Check the spelling; Registration shows whether it is registered.";
        found.push(finding(Severity::Error, "nxdomain", message, hint));
    }
    let servfail = Some(ResponseCode::ServFail);
    if rcode(get(RecordType::SOA)) == servfail || rcode(get(RecordType::A)) == servfail {
        let message = format!("The resolver couldn't get an answer for {d} (SERVFAIL).");
        let hint = "Its nameservers may be down or its DNSSEC broken; see Propagation and DNSSEC.";
        found.push(finding(Severity::Error, "dns_servfail", message, hint));
    }
    let empty = |t| {
        rcode(get(t)) == Some(ResponseCode::NoError)
            && out.records.get(&t.to_string()) == Some(&vec![])
    };
    if exists && empty(RecordType::A) && empty(RecordType::AAAA) {
        let message = format!("{d} has no A or AAAA record, so it has no website address.");
        found.push(finding(Severity::Info, "no_address", message, ""));
    }
    if exists {
        let cname = get(RecordType::CNAME).and_then(|a| a.as_ref().ok());
        if let Some(target) = cname.and_then(|m| dns::cname(m, d)) {
            if facts.zone.as_deref() == Some(d) {
                let message = format!(
                    "{d} is the zone apex and also has a CNAME, which DNS doesn't allow (RFC 1034 §3.6.2)."
                );
                let hint = "Use A/AAAA records, or your DNS host's ALIAS/flattening feature.";
                found.push(finding(Severity::Error, "cname_at_apex", message, hint));
            }
            out.cname_chain = chain(r, d, target, &mut found).await;
        }
        out.caa = caa(r, d, get(RecordType::CAA).cloned(), &mut found).await;
    }
    let apex = facts.zone.as_deref().unwrap_or(d);
    let keys = match apex == d {
        true => [
            get(RecordType::DS).cloned(),
            get(RecordType::DNSKEY).cloned(),
        ],
        false => [None, None],
    };
    out.dnssec = dnssec(cx, apex, keys, &mut found).await;
    (Section::ok(out), found)
}

/// The zone's DS and DNSKEY data (asked unless `keys` has them), and what the validating
/// resolvers make of the domain's SOA.
async fn dnssec(
    cx: &Cx,
    apex: &str,
    keys: [Option<Answer>; 2],
    found: &mut Vec<Finding>,
) -> Dnssec {
    let (r, d) = (&cx.resolver, cx.domain.as_str());
    let [ds, dnskey] = match keys {
        [Some(ds), Some(dnskey)] => [ds, dnskey],
        _ => {
            let mut got = dns::lookups(r, apex, &[RecordType::DS, RecordType::DNSKEY]).await;
            let dnskey = got.pop().unwrap_or(Err(dns::Failure::Timeout));
            [got.pop().unwrap_or(Err(dns::Failure::Timeout)), dnskey]
        }
    };
    let values = |a: &Answer, t| match a {
        Ok(m) => dns::records(m, t).map(|x| dns::value(&x.data)).collect(),
        Err(_) => Vec::new(),
    };
    let field = |v: &str, i| v.split(' ').nth(i).and_then(|f| f.parse::<u16>().ok());
    let ds_values: Vec<String> = values(&ds, RecordType::DS);
    let mut out = Dnssec {
        signed: !ds_values.is_empty(),
        ds: ds_values
            .iter()
            .filter_map(|v| {
                let algorithm = u8::try_from(field(v, 1)?).ok()?;
                Some(Ds {
                    key_tag: field(v, 0)?,
                    algorithm,
                    algorithm_name: algorithm_name(algorithm),
                    digest_type: u8::try_from(field(v, 2)?).ok()?,
                })
            })
            .collect(),
        ..Dnssec::default()
    };
    let mut algorithms: Vec<u8> = values(&dnskey, RecordType::DNSKEY)
        .iter()
        .filter_map(|v| u8::try_from(field(v, 2)?).ok())
        .collect();
    algorithms.sort_unstable();
    algorithms.dedup();
    out.dnskey_algorithms = algorithms;

    let asks = cx.resolvers.iter().map(|&(_, at)| {
        let (r, d) = (std::sync::Arc::clone(r), d.to_string());
        async move { (at, r.query(at, &d, RecordType::SOA, dns::RECURSIVE).await) }
    });
    let replies = dns::join(asks).await;
    let answered: Vec<_> = replies
        .iter()
        .filter_map(|(at, a)| Some((*at, a.as_ref().ok()?)))
        .collect();
    out.validated_by = answered
        .iter()
        .filter(|(_, m)| m.metadata.authentic_data)
        .map(|(at, _)| dns::show(*at))
        .collect();
    let failing = |m: &dns::Message| m.metadata.response_code == ResponseCode::ServFail;
    if let Some((first, _)) = answered
        .first()
        .filter(|_| answered.iter().all(|(_, m)| failing(m)))
    {
        let unchecked = dns::Ask {
            cd: true,
            ..dns::RECURSIVE
        };
        let again = r.query(*first, d, RecordType::SOA, unchecked).await;
        out.bogus = again.is_ok_and(|m| !failing(&m));
    }

    if out.bogus {
        let message = format!(
            "DNSSEC validation fails for {d}: validating resolvers answer SERVFAIL, and the records load only with checking disabled."
        );
        let hint = "The DS record at your registrar probably doesn't match the zone's keys; update or remove it.";
        found.push(finding(Severity::Error, "dnssec_bogus", message, hint));
    } else if !out.signed && rcode(Some(&ds)).is_some_and(|c| c != ResponseCode::ServFail) {
        let message = format!("{apex} isn't signed with DNSSEC (no DS record at the parent).");
        found.push(finding(Severity::Info, "dnssec_unsigned", message, ""));
    }
    let mut used: Vec<u8> = out.ds.iter().map(|x| x.algorithm).collect();
    used.extend(&out.dnskey_algorithms);
    used.sort_unstable();
    used.dedup();
    for n in used.into_iter().filter(|n| WEAK.contains(n)) {
        let message = format!(
            "{apex} is signed with {} (algorithm {n}), which RFC 8624 says not to use for signing.",
            algorithm_name(n)
        );
        let hint = "Re-sign with ECDSAP256SHA256 (13) or ED25519 (15).";
        found.push(finding(
            Severity::Warning,
            "dnssec_weak_algorithm",
            message,
            hint,
        ));
    }
    out
}

/// `domain`, then each CNAME target in turn, for at most [`MAX_HOPS`] hops.
async fn chain(r: &Resolver, domain: &str, first: String, found: &mut Vec<Finding>) -> Vec<String> {
    let mut names = vec![domain.to_string()];
    let mut next = Some(first);
    while let Some(target) = next.take() {
        if let Some(i) = names.iter().position(|n| *n == target) {
            let cycle = [&names[i..], std::slice::from_ref(&target)].concat();
            let message = format!("The CNAME chain loops: {}.", cycle.join(" → "));
            let hint = "Point one of the names at a real address.";
            found.push(finding(Severity::Error, "cname_loop", message, hint));
            break;
        }
        if names.len() > MAX_HOPS {
            let message = format!(
                "The CNAME chain for {domain} has more than {MAX_HOPS} steps; some resolvers stop at {MAX_HOPS}."
            );
            let hint = "Point the name closer to its final target.";
            found.push(finding(
                Severity::Warning,
                "cname_chain_long",
                message,
                hint,
            ));
            break;
        }
        let from = names[names.len() - 1].clone();
        names.push(target.clone());
        match r.lookup(&target, RecordType::CNAME).await {
            Ok(m) if m.metadata.response_code == ResponseCode::NXDomain => {
                let message =
                    format!("{from} is a CNAME for {target}, which doesn't exist (NXDOMAIN).");
                let hint = format!(
                    "If you no longer use that service, delete the CNAME: someone else could claim {target}."
                );
                found.push(finding(Severity::Warning, "dangling_cname", message, &hint));
            }
            Ok(m) => next = dns::cname(&m, &target),
            Err(_) => {}
        }
    }
    names
}

/// The CAA set in force: the domain's, else the closest parent's, stopping before the TLD
/// (RFC 8659 §3). `None` when there is none, or a query failed on the way.
async fn caa(
    r: &Resolver,
    domain: &str,
    first: Option<Answer>,
    found: &mut Vec<Finding>,
) -> Option<Caa> {
    let mut name = domain.to_string();
    let mut answer = first?;
    loop {
        let m = answer.ok()?;
        let code = m.metadata.response_code;
        if code != ResponseCode::NoError && code != ResponseCode::NXDomain {
            return None;
        }
        let set: Vec<_> = dns::records(&m, RecordType::CAA).collect();
        if let Some(first) = set.first() {
            // A CNAME on the way makes its target's set the one in force.
            return Some(Caa {
                found_at: dns::name(&first.name),
                records: set.iter().map(|x| dns::value(&x.data)).collect(),
            });
        }
        match parent(&name).filter(|p| p.contains('.')) {
            Some(p) => name = p.to_string(),
            None => {
                let message = format!(
                    "No CAA record: any certificate authority may issue certificates for {domain}."
                );
                let hint = "Add one naming your CA, e.g. 0 issue \"letsencrypt.org\".";
                found.push(finding(Severity::Info, "no_caa", message, hint));
                return None;
            }
        }
        answer = r.lookup(&name, RecordType::CAA).await;
    }
}
