//! `check`: the requested sections for each domain, built on DNS facts asked once and shared.
//! The one engine behind the CLI, the page and the MCP server.

use std::net::SocketAddr;
use std::sync::Arc;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::dns::{self, Answer, Failure, RecordType, Resolver, ResponseCode};
use crate::input::{self, Domain};
use crate::report::{Check, Finding, Output, Report, Section, Sections, Severity, Status};
use crate::{Error, Ports, sections};

/// The checks this version runs, in report order.
pub const CHECKS: [Check; 2] = [Check::Dns, Check::Propagation];

pub struct Options {
    pub checks: Vec<Check>,
    pub dns: Option<SocketAddr>,
    /// `--resolver`: replaces the public resolvers when given.
    pub resolvers: Vec<SocketAddr>,
    /// The record types `propagation` compares.
    pub types: Vec<RecordType>,
    pub ports: Ports,
    pub debug: bool,
}

/// Validating public resolvers with published terms (Quad9's unfiltered address).
const PUBLIC: [(&str, [u8; 4]); 3] = [
    ("Google", [8, 8, 8, 8]),
    ("Cloudflare", [1, 1, 1, 1]),
    ("Quad9", [9, 9, 9, 10]),
];

/// The resolvers to compare and ask for DNSSEC validation, each with its name.
fn resolvers(custom: &[SocketAddr]) -> Vec<(&'static str, SocketAddr)> {
    match custom.is_empty() {
        true => PUBLIC
            .iter()
            .map(|&(name, ip)| (name, SocketAddr::from((ip, 53))))
            .collect(),
        false => custom.iter().map(|&addr| ("Custom", addr)).collect(),
    }
}

/// `--checks` names (`all`, or any of [`CHECKS`]), in report order.
pub fn checks(names: &[String]) -> Result<Vec<Check>, Error> {
    let mut wanted = Vec::new();
    for name in names.iter().map(|n| n.trim()) {
        match CHECKS.iter().find(|c| c.key().eq_ignore_ascii_case(name)) {
            Some(c) => wanted.push(*c),
            None if name.eq_ignore_ascii_case("all") => wanted.extend(CHECKS),
            None => {
                let keys: Vec<_> = CHECKS.iter().map(|c| c.key()).collect();
                return Err(Error::usage(
                    format!("Unknown check '{name}'."),
                    format!("Use {} or all.", keys.join(", ")),
                ));
            }
        }
    }
    Ok(CHECKS.into_iter().filter(|c| wanted.contains(c)).collect())
}

/// What every section of one domain's check works with.
pub struct Cx {
    pub resolver: Arc<Resolver>,
    pub domain: String,
    pub resolvers: Vec<(&'static str, SocketAddr)>,
    pub types: Vec<RecordType>,
}

/// The answers every section starts from, asked once per domain.
pub struct Facts {
    pub answers: Vec<(RecordType, Answer)>,
    /// The zone holding the domain, from the SOA (RFC 1035 §4.3.4); `None` if no answer said.
    pub zone: Option<String>,
}

impl Facts {
    pub async fn gather(cx: &Cx) -> Facts {
        let types = [RecordType::SOA, RecordType::A, RecordType::AAAA];
        let got = dns::lookups(&cx.resolver, &cx.domain, &types).await;
        let answers: Vec<_> = types.into_iter().zip(got).collect();
        let zone = match &answers[0].1 {
            Ok(soa) => zone(&cx.resolver, &cx.domain, soa.clone()).await,
            Err(_) => None,
        };
        Facts { answers, zone }
    }

    pub fn answer(&self, t: RecordType) -> Option<&Answer> {
        self.answers.iter().find(|(x, _)| *x == t).map(|(_, a)| a)
    }

    /// Why nothing came back, when no query got any answer.
    pub fn unanswered(&self) -> Option<&Failure> {
        let mut failures = self.answers.iter().map(|(_, a)| a.as_ref().err());
        failures
            .next()
            .flatten()
            .filter(|_| failures.all(|f| f.is_some()))
    }

    /// False when the resolver said NXDOMAIN for the name itself (not for a CNAME's target).
    pub fn exists(&self, domain: &str) -> bool {
        !self.answers.iter().any(|(_, a)| match a {
            Ok(m) => {
                m.metadata.response_code == ResponseCode::NXDomain
                    && !m.answers.iter().any(|r| dns::name(&r.name) == domain)
            }
            Err(_) => false,
        })
    }
}

/// The owner of the SOA in the answer or authority section, walking up a label when a CNAME
/// led the answer into another zone.
async fn zone(r: &Resolver, domain: &str, mut m: dns::Message) -> Option<String> {
    let mut name = domain.to_string();
    loop {
        let code = m.metadata.response_code;
        if code != ResponseCode::NoError && code != ResponseCode::NXDomain {
            return None;
        }
        let soa = m.answers.iter().chain(&m.authorities);
        let mut owners = soa
            .filter(|r| r.record_type() == RecordType::SOA)
            .map(|r| dns::name(&r.name));
        if let Some(zone) = owners.find(|z| within(domain, z)) {
            return Some(zone);
        }
        name = parent(&name)?.to_string();
        m = r.lookup(&name, RecordType::SOA).await.ok()?;
    }
}

/// `name` is `zone` or below it.
pub fn within(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// The name one label up; `None` for a single label.
pub fn parent(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, p)| p)
}

/// RFC 3339 UTC to the second.
pub fn now() -> String {
    let now = OffsetDateTime::now_utc().truncate_to_second();
    now.format(&Rfc3339).unwrap_or_default()
}

/// One report per input, in input order; invalid inputs make no query.
pub fn run(inputs: &[String], options: &Options) -> Result<Output, Error> {
    let mut resolver = None;
    let mut reports = Vec::with_capacity(inputs.len());
    for input in inputs {
        reports.push(match input::domain(input) {
            Ok(d) => domain(input, &d, shared(&mut resolver, options)?, options)?,
            Err(e) => Report::invalid(input, now(), e),
        });
    }
    Ok(Output::new(reports))
}

/// The run's resolver, set up when the first valid domain needs it.
fn shared(slot: &mut Option<Arc<Resolver>>, o: &Options) -> Result<Arc<Resolver>, Error> {
    if let Some(r) = slot {
        return Ok(Arc::clone(r));
    }
    let r = Arc::new(Resolver::new(o.dns, o.ports, o.debug)?);
    *slot = Some(Arc::clone(&r));
    Ok(r)
}

fn domain(input: &str, d: &Domain, resolver: Arc<Resolver>, o: &Options) -> Result<Report, Error> {
    let checked_at = now();
    let cx = Cx {
        resolver,
        domain: d.ascii.clone(),
        resolvers: resolvers(&o.resolvers),
        types: o.types.clone(),
    };
    let rt = crate::runtime()?;
    let facts = rt.block_on(Facts::gather(&cx));
    let mut findings = Vec::new();
    if d.port_ignored {
        let message = format!(
            "The port in {} was ignored; checks use ports 53, 80 and 443.",
            input.trim()
        );
        let f = Finding::new(Check::Dns, Severity::Info, "port_ignored", message, "");
        findings.push(f);
    }
    fn skipped<T>() -> Section<T> {
        Section::not(Status::Skipped, "not requested")
    }
    let mut sections = Sections {
        dns: Some(skipped()),
        propagation: Some(skipped()),
    };
    if o.checks.contains(&Check::Dns) {
        let (section, found) = rt.block_on(sections::dns::run(&cx, &facts));
        sections.dns = Some(section);
        findings.extend(found);
    }
    if o.checks.contains(&Check::Propagation) {
        let (section, found) = rt.block_on(sections::propagation::run(&cx, &facts));
        sections.propagation = Some(section);
        findings.extend(found);
    }
    Ok(Report::checked(input, d, checked_at, findings, sections))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_names_are_all_or_known_sections() {
        let names = |s: &[&str]| s.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(checks(&names(&["all"])).unwrap(), CHECKS);
        assert_eq!(checks(&names(&[" DNS "])).unwrap(), [Check::Dns]);
        let e = checks(&names(&["dns", "smtp"])).unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            ("usage", "Unknown check 'smtp'.")
        );
        assert_eq!(e.hint.unwrap(), "Use dns, propagation or all.");
    }

    #[test]
    fn resolver_flags_replace_the_public_resolvers() {
        let named = |list: &[(&str, SocketAddr)]| {
            let v: Vec<_> = list.iter().map(|(n, a)| format!("{n} {a}")).collect();
            v.join(", ")
        };
        let public = "Google 8.8.8.8:53, Cloudflare 1.1.1.1:53, Quad9 9.9.9.10:53";
        assert_eq!(named(&resolvers(&[])), public);
        let custom = ["127.0.0.1:5353".parse().unwrap()];
        assert_eq!(named(&resolvers(&custom)), "Custom 127.0.0.1:5353");
    }

    #[test]
    fn names_have_parents_and_zones() {
        assert_eq!(parent("www.example.com"), Some("example.com"));
        assert_eq!(parent("com"), None);
        assert!(within("www.example.com", "example.com"));
        assert!(within("example.com", "example.com"));
        assert!(!within("badexample.com", "example.com"));
        let stamp = now();
        assert_eq!((stamp.len(), &stamp[19..]), (20, "Z"), "{stamp}");
    }
}
