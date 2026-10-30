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
}

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
    (Section::ok(out), found)
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
