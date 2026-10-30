//! `check`: the requested sections for each domain, built on DNS facts asked once and shared.
//! The one engine behind the CLI, the page and the MCP server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::dns::{self, Answer, Failure, RecordType, Resolver, ResponseCode};
use crate::input::{self, Domain};
use crate::net::Net;
use crate::report::{Check, Finding, Output, Report, Section, Sections, Severity, Status};
use crate::sections::dns::Dns;
use crate::sections::email::Email;
use crate::sections::propagation::Propagation;
use crate::sections::rdap::{self, RdapSection};
use crate::sections::tls::Tls;
use crate::sections::web::Web;
use crate::{Error, Ports, sections};

/// The checks this version runs, in report order.
pub const CHECKS: [Check; 6] = [
    Check::Dns,
    Check::Propagation,
    Check::Email,
    Check::Rdap,
    Check::Tls,
    Check::Http,
];

pub struct Options {
    pub checks: Vec<Check>,
    pub dns: Option<SocketAddr>,
    /// `--resolver`: replaces the public resolvers when given.
    pub resolvers: Vec<SocketAddr>,
    /// The record types `propagation` compares.
    pub types: Vec<RecordType>,
    /// `--dkim-selector`: the DKIM selectors to look up instead of the common ones.
    pub selectors: Vec<String>,
    /// `--spf-ip`: also evaluate SPF for mail sent from this address.
    pub spf_ip: Option<IpAddr>,
    /// `--ca-file`: certificates to trust besides this computer's own.
    pub ca: Vec<CertificateDer<'static>>,
    pub allow_private: bool,
    pub ports: Ports,
    /// `DOMAIN_CHECK_RDAP_BOOTSTRAP`: the bootstrap file to use instead of the bundled one.
    pub bootstrap: Option<String>,
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
    pub net: Arc<Net>,
    pub domain: String,
    pub resolvers: Vec<(&'static str, SocketAddr)>,
    pub types: Vec<RecordType>,
    pub selectors: Vec<String>,
    pub spf_ip: Option<IpAddr>,
    pub rdap: Arc<rdap::Run>,
    /// When the domain's check began: every section's budget counts from here.
    pub started: Instant,
}

impl Cx {
    /// When `check`'s lookups must give up, so the section still reports in time.
    pub fn until(&self, check: Check) -> Instant {
        self.started + deadline(budget(check)).0 - Duration::from_secs(1)
    }
}

/// The answers every section starts from, asked once per domain.
pub struct Facts {
    pub answers: Vec<(RecordType, Answer)>,
    /// The zone holding the domain, from the SOA (RFC 1035 §4.3.4); `None` if no answer said.
    pub zone: Option<String>,
}

impl Facts {
    pub async fn gather(cx: &Cx) -> Facts {
        let types = [
            RecordType::SOA,
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
        ];
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

    /// The domain's first IPv4 and first IPv6 address, for a check that connects to it; or
    /// the section's status and reason when there is none.
    pub fn web_addresses(&self, domain: &str) -> Result<Vec<IpAddr>, (Status, String)> {
        let no_answer = || {
            let why = "No DNS answer, so this check couldn't run.";
            (Status::Unavailable, why.to_string())
        };
        if self.unanswered().is_some() {
            return Err(no_answer());
        }
        if !self.exists(domain) {
            return Err((Status::Skipped, format!("{domain} doesn't exist in DNS.")));
        }
        let types = [RecordType::A, RecordType::AAAA];
        let answers: Vec<_> = types.iter().filter_map(|&t| self.answer(t)).collect();
        let first = |t| {
            let m = self.answer(t)?.as_ref().ok()?;
            dns::value(&dns::records(m, t).next()?.data).parse().ok()
        };
        let ips: Vec<IpAddr> = types.into_iter().filter_map(first).collect();
        match ips.is_empty() {
            false => Ok(ips),
            true if answers.iter().all(|a| a.is_err()) => Err(no_answer()),
            true => Err((
                Status::Skipped,
                format!("{domain} has no A or AAAA record."),
            )),
        }
    }

    /// Why nothing came back, when no query got any answer.
    pub fn unanswered(&self) -> Option<&Failure> {
        dns::unanswered(self.answers.iter().map(|(_, a)| a))
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

/// Domains one run may check: RDAP servers forbid bulk lookups (spec §6).
pub const MAX_DOMAINS: usize = 20;

/// One report per input, in input order. A domain given twice is checked once; invalid
/// inputs make no query.
pub fn run(inputs: &[String], options: &Options, progress: &mut Progress) -> Result<Output, Error> {
    if inputs.len() > MAX_DOMAINS {
        return Err(Error::usage(
            format!(
                "Too many domains: {} given, at most {MAX_DOMAINS} per run.",
                inputs.len()
            ),
            format!("Split them into runs of {MAX_DOMAINS} or fewer."),
        ));
    }
    let mut net = None;
    let rdap = Arc::new(rdap::Run::new(options.bootstrap.clone()));
    let mut done: HashMap<String, Checked> = HashMap::new();
    let mut reports = Vec::with_capacity(inputs.len());
    for input in inputs {
        let d = match input::domain(input) {
            Ok(d) => d,
            Err(e) => {
                reports.push(Report::invalid(input, now(), e));
                continue;
            }
        };
        let c = match done.get(&d.ascii) {
            Some(c) => c.clone(),
            None => {
                let net = shared(&mut net, options)?;
                let c = checked(&d, net, Arc::clone(&rdap), options, progress);
                done.insert(d.ascii.clone(), c.clone());
                c
            }
        };
        let mut findings = c.findings;
        if d.port_ignored {
            let message = format!(
                "The port in {} was ignored; checks use ports 53, 80 and 443.",
                input.trim()
            );
            findings.push(Finding::new(
                Check::Dns,
                Severity::Info,
                "port_ignored",
                message,
                "",
            ));
        }
        reports.push(Report::checked(
            input,
            &d,
            c.checked_at,
            findings,
            c.sections,
        ));
    }
    Ok(Output::new(reports))
}

/// The run's resolver and connections, set up when the first valid domain needs them.
fn shared(slot: &mut Option<Arc<Net>>, o: &Options) -> Result<Arc<Net>, Error> {
    if let Some(net) = slot {
        return Ok(Arc::clone(net));
    }
    let resolver = Arc::new(Resolver::new(o.dns, o.ports, o.debug)?);
    let (private, roots) = (o.allow_private, o.ca.clone());
    let net = Arc::new(Net::new(resolver, o.ports, private, roots, o.debug));
    *slot = Some(Arc::clone(&net));
    Ok(net)
}

/// One domain's sections and findings.
#[derive(Clone)]
struct Checked {
    checked_at: String,
    findings: Vec<Finding>,
    sections: Sections,
}

/// The longest one domain's check runs; sections still running then are given up.
const CAP: Duration = Duration::from_secs(30);

/// Each section's time limit (spec §3.1).
fn budget(check: Check) -> Duration {
    Duration::from_secs(match check {
        Check::Email | Check::Rdap | Check::Http => 20,
        Check::Dns | Check::Propagation | Check::Tls => 15,
    })
}

/// When a section still running is given up, and the reason it then gets.
fn deadline(budget: Duration) -> (Duration, String) {
    let limit = budget.min(CAP);
    (limit, format!("Stopped after {} s.", limit.as_secs()))
}

/// One section's result, as its thread sends it.
enum Part {
    Dns(Section<Dns>),
    Propagation(Section<Propagation>),
    Email(Box<Section<Email>>),
    Rdap(Box<RdapSection>),
    Tls(Box<Section<Tls>>),
    Http(Box<Section<Web>>),
    Down(Status, String),
}

struct Outcome {
    check: Check,
    part: Part,
    findings: Vec<Finding>,
}

impl Outcome {
    fn down(check: Check, reason: String) -> Outcome {
        Outcome {
            check,
            part: Part::Down(Status::Unavailable, reason),
            findings: Vec::new(),
        }
    }
}

/// The facts first, then every requested section on its own thread, each within its budget.
fn checked(
    d: &Domain,
    net: Arc<Net>,
    rdap: Arc<rdap::Run>,
    o: &Options,
    progress: &mut Progress,
) -> Checked {
    let start = Instant::now();
    let checked_at = now();
    let cx = Arc::new(Cx {
        resolver: Arc::clone(&net.resolver),
        net,
        domain: d.ascii.clone(),
        resolvers: resolvers(&o.resolvers),
        types: o.types.clone(),
        selectors: o.selectors.clone(),
        spf_ip: o.spf_ip,
        rdap,
        started: start,
    });
    let (tx, rx) = mpsc::channel();
    let wanted = o.checks.clone();
    let sections = wanted.clone();
    // Without a thread nothing is sent, and `collect` marks every section stopped.
    let _ = thread::Builder::new().spawn(move || start_sections(cx, sections, tx));
    let mut sections = Sections::default();
    for check in CHECKS {
        sections.not(check, Status::Skipped, "not requested");
    }
    let mut findings = Vec::new();
    let tick = |marks: &[(Check, Mark)], secs| progress(&d.ascii, marks, secs);
    for outcome in collect(&rx, &wanted, start, budget, tick) {
        match outcome.part {
            Part::Dns(s) => sections.dns = Some(s),
            Part::Propagation(s) => sections.propagation = Some(s),
            Part::Email(s) => sections.email = Some(*s),
            Part::Rdap(s) => sections.rdap = Some(*s),
            Part::Tls(s) => sections.tls = Some(*s),
            Part::Http(s) => sections.http = Some(*s),
            Part::Down(status, why) => sections.not(outcome.check, status, &why),
        }
        findings.extend(outcome.findings);
    }
    Checked {
        checked_at,
        findings,
        sections,
    }
}

fn start_sections(cx: Arc<Cx>, wanted: Vec<Check>, tx: mpsc::Sender<Outcome>) {
    let facts = match crate::runtime() {
        Ok(rt) => Arc::new(rt.block_on(Facts::gather(&cx))),
        Err(e) => {
            for check in wanted {
                let _ = tx.send(Outcome::down(check, e.message.clone()));
            }
            return;
        }
    };
    for check in wanted {
        let (cx, facts, tx) = (Arc::clone(&cx), Arc::clone(&facts), tx.clone());
        let _ = thread::Builder::new().spawn(move || {
            // A report already printed without this section drops it quietly.
            let _ = tx.send(section(check, &cx, &facts));
        });
    }
}

fn section(check: Check, cx: &Cx, facts: &Facts) -> Outcome {
    let rt = match crate::runtime() {
        Ok(rt) => rt,
        Err(e) => return Outcome::down(check, e.message),
    };
    let (part, findings) = match check {
        Check::Dns => {
            let (s, f) = rt.block_on(sections::dns::run(cx, facts));
            (Part::Dns(s), f)
        }
        Check::Propagation => {
            let (s, f) = rt.block_on(sections::propagation::run(cx, facts));
            (Part::Propagation(s), f)
        }
        Check::Email => {
            let (s, f) = rt.block_on(sections::email::run(cx, facts));
            (Part::Email(Box::new(s)), f)
        }
        Check::Tls => {
            let (s, f) = sections::tls::run(cx, facts);
            (Part::Tls(Box::new(s)), f)
        }
        Check::Rdap => {
            let (s, f) = rdap::run(cx, facts);
            (Part::Rdap(Box::new(s)), f)
        }
        Check::Http => {
            let (s, f) = sections::web::run(cx, facts);
            (Part::Http(Box::new(s)), f)
        }
    };
    Outcome {
        check,
        part,
        findings,
    }
}

/// A section's state while its domain is checked.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mark {
    Running,
    Done,
    /// Unavailable or rate limited.
    Down,
}

/// Told the domain, each section's state and the seconds so far: on every change and once a
/// second.
pub type Progress<'a> = dyn FnMut(&str, &[(Check, Mark)], u64) + 'a;

/// Each wanted section's outcome, or `unavailable` once its deadline passes.
fn collect(
    rx: &mpsc::Receiver<Outcome>,
    wanted: &[Check],
    start: Instant,
    budget: impl Fn(Check) -> Duration,
    mut tick: impl FnMut(&[(Check, Mark)], u64),
) -> Vec<Outcome> {
    let mut done: Vec<Outcome> = Vec::new();
    loop {
        let marks: Vec<_> = wanted
            .iter()
            .map(|&c| {
                let status = done.iter().find(|o| o.check == c).map(|o| match &o.part {
                    Part::Dns(s) => s.status,
                    Part::Propagation(s) => s.status,
                    Part::Email(s) => s.status,
                    Part::Rdap(s) => s.section.status,
                    Part::Tls(s) => s.status,
                    Part::Http(s) => s.status,
                    Part::Down(status, _) => *status,
                });
                let mark = match status {
                    None => Mark::Running,
                    Some(Status::Unavailable | Status::RateLimited) => Mark::Down,
                    Some(Status::Ok | Status::Skipped) => Mark::Done,
                };
                (c, mark)
            })
            .collect();
        let elapsed = start.elapsed();
        tick(&marks, elapsed.as_secs());
        let pending: Vec<Check> = marks
            .iter()
            .filter(|(_, m)| *m == Mark::Running)
            .map(|(c, _)| *c)
            .collect();
        let Some(next) = pending.iter().map(|&c| deadline(budget(c)).0).min() else {
            return done;
        };
        let second = Duration::from_millis(1000 - u64::from(elapsed.subsec_millis()));
        match rx.recv_timeout(next.saturating_sub(elapsed).min(second)) {
            Ok(o) if pending.contains(&o.check) => done.push(o),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {
                for check in pending {
                    let (limit, why) = deadline(budget(check));
                    if start.elapsed() >= limit {
                        done.push(Outcome::down(check, why));
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                let why = format!("Stopped after {} s.", start.elapsed().as_secs());
                done.extend(pending.into_iter().map(|c| Outcome::down(c, why.clone())));
            }
        }
    }
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
        assert_eq!(
            e.hint.unwrap(),
            "Use dns, propagation, email, rdap, tls, http or all."
        );
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
    fn sections_past_their_deadline_are_stopped() {
        assert_eq!(
            deadline(Duration::from_secs(15)),
            (Duration::from_secs(15), "Stopped after 15 s.".into())
        );
        assert_eq!(
            deadline(Duration::from_secs(40)),
            (CAP, "Stopped after 30 s.".into())
        );
        let reason = |o: &Outcome| match &o.part {
            Part::Down(status, why) => (o.check, *status, why.clone()),
            _ => (o.check, Status::Ok, String::new()),
        };
        let (tx, rx) = mpsc::channel();
        tx.send(Outcome::down(Check::Propagation, "sent".into()))
            .unwrap();
        let start = Instant::now();
        let quick = |c| match c {
            Check::Dns => Duration::from_secs(1),
            _ => Duration::from_secs(10),
        };
        let both = [Check::Dns, Check::Propagation];
        let done = collect(&rx, &both, start, quick, |_, _| {});
        let took = start.elapsed();
        assert!((1.0..3.0).contains(&took.as_secs_f64()), "{took:?}");
        let mut got: Vec<_> = done.iter().map(reason).collect();
        got.sort_by_key(|g| g.0);
        let down = Status::Unavailable;
        assert_eq!(
            got,
            [
                (Check::Dns, down, "Stopped after 1 s.".into()),
                (Check::Propagation, down, "sent".into())
            ]
        );
        // Every sender gone: nothing more can come, so the rest stop at once.
        drop(tx);
        let done = collect(&rx, &[Check::Dns], Instant::now(), budget, |_, _| {});
        assert_eq!(reason(&done[0]).2, "Stopped after 0 s.");
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
