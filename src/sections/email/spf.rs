//! SPF (RFC 7208): the domain's record, and the walk of its terms with the DNS lookups and void
//! lookups counted the way receivers count them (§4.6.4).

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;

use super::{Found, Mail, Part, finding};
use crate::dns::RecordType;
use crate::report::{Finding, Severity};

/// DNS lookups receivers allow (§4.6.4); past this the result is permerror.
pub const LIMIT: u32 = 10;
/// Lookups the walk makes before it stops counting.
const CAP: u32 = 20;
/// Lookups that find nothing, allowed (§4.6.4).
const VOID_LIMIT: u32 = 2;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Spf {
    pub record: String,
    pub lookups: u32,
    pub lookups_capped: bool,
    pub void_lookups: u32,
    /// The top-level `all` with its qualifier, e.g. `-all`.
    pub all: Option<String>,
    /// The `redirect=` target, when it applies (there is no `all`).
    pub redirect: Option<String>,
    pub tree: Vec<Node>,
    /// What `check_host()` gives the `--spf-ip` address.
    pub result: Option<Verdict>,
}

/// SPF's answer for one sending address (RFC 7208 §2.6).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Verdict {
    pub ip: String,
    /// `pass`, `fail`, `softfail`, `neutral`, `none`, `permerror` or `temperror`.
    pub result: &'static str,
    /// The term that decided it, or where evaluation stopped on an error.
    pub matched: Option<String>,
    /// The `include` and `redirect` terms that led to that record.
    pub via: Vec<String>,
}

/// A term that queries DNS, with what it found.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Node {
    pub term: String,
    pub lookups: u32,
    /// The SPF record an `include` or `redirect` leads to.
    pub record: Option<String>,
    pub error: Option<String>,
    pub children: Vec<Node>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Mech {
    All,
    Include,
    A,
    Mx,
    Ptr,
    Ip4,
    Ip6,
    Exists,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Term<'a> {
    Directive {
        text: &'a str,
        /// `+`, `-`, `~` or `?`.
        qualifier: char,
        mech: Mech,
        domain: Option<&'a str>,
        /// The `ip4:` or `ip6:` network.
        net: Option<IpAddr>,
        /// CIDR prefix lengths (§5.6): IPv4, IPv6.
        cidr: (u8, u8),
    },
    Redirect {
        text: &'a str,
        domain: &'a str,
    },
    /// `exp=` and modifiers receivers ignore (§6).
    Other,
}

/// A record's terms, and the ones that don't parse with what is wrong.
#[derive(Debug, Default)]
pub struct Parsed<'a> {
    pub terms: Vec<Term<'a>>,
    pub errors: Vec<(String, &'a str)>,
}

impl Parsed<'_> {
    pub fn has_all(&self) -> bool {
        self.terms.iter().any(|t| {
            matches!(
                t,
                Term::Directive {
                    mech: Mech::All,
                    ..
                }
            )
        })
    }
}

/// An SPF record starts `v=spf1`, then a space or the end (§4.5).
pub fn is_spf(txt: &str) -> bool {
    let head = txt.get(..6).unwrap_or_default();
    head.eq_ignore_ascii_case("v=spf1") && matches!(txt.as_bytes().get(6), None | Some(b' '))
}

pub fn parse(record: &str) -> Parsed<'_> {
    let mut out = Parsed::default();
    let (mut redirects, mut exps) = (0, 0);
    for text in record.get(6..).unwrap_or_default().split(' ') {
        if text.is_empty() {
            continue;
        }
        match term(text) {
            Ok(t) => {
                let lower = text.to_ascii_lowercase();
                let twice = match &t {
                    Term::Redirect { .. } => bump(&mut redirects),
                    Term::Other if lower.starts_with("exp=") => bump(&mut exps),
                    _ => false,
                };
                match twice {
                    true => {
                        let name = &lower[..lower.find('=').unwrap_or(0)];
                        out.errors
                            .push((format!("{name}= appears more than once"), text));
                    }
                    false => out.terms.push(t),
                }
            }
            Err(what) => out.errors.push((what, text)),
        }
    }
    out
}

fn bump(n: &mut u32) -> bool {
    *n += 1;
    *n > 1
}

fn term(text: &str) -> Result<Term<'_>, String> {
    let (qualifier, rest) = match text.chars().next() {
        Some(q @ ('+' | '-' | '~' | '?')) => (q, &text[1..]),
        _ => ('+', text),
    };
    let end = rest.find([':', '/', '=']).unwrap_or(rest.len());
    let (name, args) = rest.split_at(end);
    let name = name.to_ascii_lowercase();
    if let Some(value) = args.strip_prefix('=') {
        let valid = name.starts_with(|c: char| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c));
        if !valid || qualifier != '+' || text.starts_with('+') {
            return Err("unknown mechanism".into());
        }
        return match name.as_str() {
            "redirect" | "exp" => {
                domain_spec(value)?;
                Ok(match name.as_str() {
                    "redirect" => Term::Redirect {
                        text,
                        domain: value,
                    },
                    _ => Term::Other,
                })
            }
            _ => Ok(Term::Other),
        };
    }
    let mech = match name.as_str() {
        "all" => Mech::All,
        "include" => Mech::Include,
        "a" => Mech::A,
        "mx" => Mech::Mx,
        "ptr" => Mech::Ptr,
        "ip4" => Mech::Ip4,
        "ip6" => Mech::Ip6,
        "exists" => Mech::Exists,
        _ => return Err("unknown mechanism".into()),
    };
    let (mut domain, mut net, mut cidr) = (None, None, (32, 128));
    match mech {
        Mech::All if !args.is_empty() => return Err("all takes no argument".into()),
        Mech::All => {}
        Mech::Include | Mech::Exists => {
            let spec = args.strip_prefix(':').filter(|s| !s.is_empty());
            let spec = spec.ok_or_else(|| format!("{name} needs a domain"))?;
            domain_spec(spec)?;
            domain = Some(spec);
        }
        Mech::A | Mech::Mx | Mech::Ptr => {
            let (spec, lengths) = match mech {
                Mech::Ptr => (args, ""),
                _ => args.split_at(args.find('/').unwrap_or(args.len())),
            };
            if let Some(spec) = spec.strip_prefix(':') {
                domain_spec(spec)?;
                domain = Some(spec);
            } else if !spec.is_empty() {
                return Err("unknown mechanism".into());
            }
            cidr = dual_cidr(lengths).ok_or("invalid CIDR length")?;
        }
        Mech::Ip4 | Mech::Ip6 => {
            let spec = args.strip_prefix(':').unwrap_or_default();
            let (ip, length) = spec.split_once('/').unwrap_or((spec, ""));
            let ip: IpAddr = ip.parse().map_err(|_| "invalid IP address")?;
            let v4 = mech == Mech::Ip4;
            if ip.is_ipv4() != v4 {
                return Err("invalid IP address".into());
            }
            let max = if v4 { 32 } else { 128 };
            let length = match length {
                "" if args.contains('/') => return Err("invalid CIDR length".into()),
                "" => max,
                n => prefix(n, max).ok_or("invalid CIDR length")?,
            };
            net = Some(ip);
            cidr = if v4 { (length, 128) } else { (32, length) };
        }
    }
    Ok(Term::Directive {
        text,
        qualifier,
        mech,
        domain,
        net,
        cidr,
    })
}

/// `/N`, `//M` or `/N//M` (§5.6); full lengths when absent.
fn dual_cidr(s: &str) -> Option<(u8, u8)> {
    let (v4, v6) = match s.split_once("//") {
        Some((v4, v6)) => (v4, Some(v6)),
        None => (s, None),
    };
    let v4 = match v4 {
        "" => 32,
        n => prefix(n.strip_prefix('/')?, 32)?,
    };
    let v6 = match v6 {
        None => 128,
        Some(n) => prefix(n, 128)?,
    };
    Some((v4, v6))
}

/// A prefix length up to `max`, written without leading zeros.
fn prefix(n: &str, max: u8) -> Option<u8> {
    let ok =
        !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'));
    n.parse().ok().filter(|&p| ok && p <= max)
}

/// A domain-spec (§4.6.1): macros that expand, then a host name whose last label isn't numeric.
fn domain_spec(spec: &str) -> Result<(), String> {
    let vars = Vars {
        domain: "example.com",
        current: "example.com",
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let name = expand(spec, &vars).ok_or("invalid macro")?;
    if spec.contains("%{") {
        return Ok(());
    }
    let name = name.strip_suffix('.').unwrap_or(&name);
    let labels: Vec<_> = name.split('.').collect();
    let fine = name.len() <= 253
        && labels.len() > 1
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63)
        && !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit());
    match fine {
        true => Ok(()),
        false => Err("invalid domain".into()),
    }
}

/// What macros expand to (§7.2): the sender is `postmaster@<domain>`, the HELO name the domain.
pub struct Vars<'a> {
    pub domain: &'a str,
    /// The domain whose record is being read (`%{d}`): changes with include and redirect.
    pub current: &'a str,
    pub ip: IpAddr,
}

/// `spec` with its macros expanded; `None` when one is malformed.
pub fn expand(spec: &str, v: &Vars) -> Option<String> {
    let mut out = String::new();
    let mut rest = spec;
    while let Some(i) = rest.find('%') {
        out += &rest[..i];
        let after = &rest[i + 1..];
        match after.chars().next()? {
            '%' => out.push('%'),
            '_' => out.push(' '),
            '-' => out += "%20",
            '{' => {
                let close = after.find('}')?;
                out += &letter(&after[1..close], v)?;
                rest = &after[close + 1..];
                continue;
            }
            _ => return None,
        }
        rest = &after[1..];
    }
    out += rest;
    Some(out)
}

/// One `%{…}` body: a letter, an optional count of right-hand parts, `r` to reverse, and the
/// delimiters to split on (§7.3).
fn letter(body: &str, v: &Vars) -> Option<String> {
    let mut chars = body.chars();
    let l = chars.next()?;
    let value = match l.to_ascii_lowercase() {
        's' => format!("postmaster@{}", v.domain),
        'l' => "postmaster".into(),
        'o' | 'h' => v.domain.into(),
        'd' => v.current.into(),
        'i' => dotted(v.ip),
        'p' => "unknown".into(),
        'v' => match v.ip {
            IpAddr::V4(_) => "in-addr".into(),
            IpAddr::V6(_) => "ip6".into(),
        },
        _ => return None,
    };
    let rest = chars.as_str();
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let keep: Option<usize> = match digits {
        0 => None,
        _ => Some(rest[..digits].parse().ok().filter(|&n| n > 0)?),
    };
    let rest = &rest[digits..];
    let (reverse, delimiters) = match rest.strip_prefix(['r', 'R']) {
        Some(d) => (true, d),
        None => (false, rest),
    };
    if !delimiters.chars().all(|c| ".-+,/_=".contains(c)) {
        return None;
    }
    let split = if delimiters.is_empty() {
        "."
    } else {
        delimiters
    };
    let mut parts: Vec<&str> = value.split(|c| split.contains(c)).collect();
    if reverse {
        parts.reverse();
    }
    if let Some(n) = keep {
        parts = parts.split_off(parts.len().saturating_sub(n));
    }
    let joined = parts.join(".");
    Some(match l.is_ascii_uppercase() {
        true => escape(&joined),
        false => joined,
    })
}

/// `%{i}`: an IPv4 address as written, an IPv6 address as 32 dot-separated nibbles.
fn dotted(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let nibbles = octets.iter().flat_map(|b| [b >> 4, b & 0xf]);
            let nibbles: Vec<_> = nibbles.map(|n| format!("{n:x}")).collect();
            nibbles.join(".")
        }
    }
}

/// URL escaping for upper-case macro letters (§7.3): all but the unreserved characters.
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A name as looked up: lower case, no trailing dot.
fn target(spec: &str, v: &Vars) -> Option<String> {
    let name = expand(spec, v)?.to_ascii_lowercase();
    Some(name.trim_end_matches('.').to_string())
}

/// The record and its walk, plus the verdict for `ip` when one is given.
/// `Err` when the domain's TXT lookup failed.
pub async fn run(mail: Arc<Mail>, ip: Option<IpAddr>) -> Part<Spf> {
    let (mut spf, mut found) = read(Arc::clone(&mail)).await;
    if let Some(ip) = ip {
        let verdict = evaluate(mail, ip).await;
        found.push(verdict_finding(&verdict));
        if let Ok(Some(spf)) = &mut spf {
            spf.result = Some(verdict);
        }
    }
    (spf, found)
}

async fn read(mail: Arc<Mail>) -> Part<Spf> {
    let d = mail.domain.clone();
    let mut found = Vec::new();
    let txts = match mail.values(&d, RecordType::TXT).await {
        Ok(txts) => txts.unwrap_or_default(),
        Err(why) => {
            found.push(lookup_failed(&d, &why));
            return (Err(why), found);
        }
    };
    if txts
        .iter()
        .any(|t| t.to_ascii_lowercase().starts_with("spf2.0/"))
    {
        let message = "An old Sender ID (spf2.0) record was ignored; nothing uses it now.";
        found.push(finding(
            Severity::Info,
            "spf_sender_id",
            message,
            "You can delete it.",
        ));
    }
    let records: Vec<_> = txts.into_iter().filter(|t| is_spf(t)).collect();
    let Some(record) = records.first().cloned() else {
        let message = format!("No SPF record for {d}.");
        let hint = "Publish one, e.g. \"v=spf1 include:<your mail provider> -all\", or \"v=spf1 -all\" if it sends no mail.";
        found.push(finding(Severity::Warning, "spf_none", message, hint));
        return (Ok(None), found);
    };
    if records.len() > 1 {
        found.push(multiple(&d, records.len()));
    }
    if record.len() > 450 {
        let message = format!(
            "The SPF record is {} bytes; over 450 may not fit in a DNS answer over UDP (RFC 7208 §3.4).",
            record.len()
        );
        let hint = "Shorten it, e.g. by moving ranges into an include.";
        found.push(finding(Severity::Warning, "spf_long", message, hint));
    }
    let mut walk = Walk {
        mail,
        lookups: 0,
        capped: false,
        voids: 0,
        ptr: false,
        found,
    };
    let tree = walk
        .record(d.clone(), record.clone(), vec![d.clone()])
        .await;
    let parsed = parse(&record);
    let all = parsed.terms.iter().find_map(|t| match t {
        Term::Directive {
            mech: Mech::All,
            qualifier,
            ..
        } => Some(format!("{qualifier}all")),
        _ => None,
    });
    let redirect = parsed.terms.iter().find_map(|t| match t {
        Term::Redirect { domain, .. } if all.is_none() => Some(domain.to_string()),
        _ => None,
    });
    let Walk {
        lookups,
        capped,
        voids,
        ptr,
        mut found,
        ..
    } = walk;
    match all.as_deref() {
        Some("+all") => {
            let message =
                format!("The SPF record ends in +all, which lets anyone send mail as {d}.");
            found.push(finding(
                Severity::Error,
                "spf_plus_all",
                message,
                "Use -all, or ~all while testing.",
            ));
        }
        Some("?all") => {
            let message = "The SPF record ends in ?all, which says nothing about other senders.";
            let hint = "Use -all or ~all once every sender is listed.";
            found.push(finding(Severity::Warning, "spf_neutral_all", message, hint));
        }
        None if redirect.is_none() => {
            let message = "The SPF record has no \"all\" term or redirect, so mail from other senders gets \"neutral\".";
            found.push(finding(
                Severity::Warning,
                "spf_no_all",
                message,
                "End it with -all or ~all.",
            ));
        }
        _ => {}
    }
    if ptr {
        let message = "The SPF record uses ptr, which RFC 7208 §5.5 says not to use.";
        let hint = "Replace it with ip4:, ip6: or a: terms.";
        found.push(finding(Severity::Warning, "spf_ptr", message, hint));
    }
    if lookups > LIMIT {
        let n = match capped {
            true => format!("more than {CAP}"),
            false => lookups.to_string(),
        };
        let message = format!(
            "The SPF record needs {n} DNS lookups; the limit is {LIMIT} (RFC 7208 §4.6.4)."
        );
        let hint = "Remove unused includes, or replace some with ip4:/ip6: ranges.";
        found.push(finding(
            Severity::Error,
            "spf_too_many_lookups",
            message,
            hint,
        ));
    }
    if voids > VOID_LIMIT {
        let message = format!("{voids} SPF lookups return no records; the limit is {VOID_LIMIT}.");
        let hint = "Remove the include, a or mx terms that point to names without records.";
        found.push(finding(Severity::Error, "spf_too_many_void", message, hint));
    }
    let mut unique = Vec::new();
    for f in found {
        if !unique.contains(&f) {
            unique.push(f);
        }
    }
    let spf = Spf {
        record,
        lookups,
        lookups_capped: capped,
        void_lookups: voids,
        all,
        redirect,
        tree,
        result: None,
    };
    (Ok(Some(spf)), unique)
}

/// `check_host()` (§4) for mail from `ip` with sender `postmaster@<domain>`.
async fn evaluate(mail: Arc<Mail>, ip: IpAddr) -> Verdict {
    let mut e = Eval {
        mail: Arc::clone(&mail),
        ip: ip.to_canonical(),
        lookups: 0,
        voids: 0,
    };
    let (result, matched, via) = e.check(mail.domain.clone(), Vec::new()).await;
    Verdict {
        ip: ip.to_string(),
        result,
        matched,
        via,
    }
}

fn verdict_finding(v: &Verdict) -> Finding {
    let severity = match v.result {
        "pass" => Severity::Info,
        "fail" | "permerror" => Severity::Error,
        _ => Severity::Warning,
    };
    let via = match v.via.as_slice() {
        [] => String::new(),
        path => format!(" via {}", path.join(" → ")),
    };
    let (ip, result) = (&v.ip, v.result);
    let message = match &v.matched {
        None => format!("SPF for {ip}: {result}; no term matched."),
        Some(term) if result.ends_with("error") => {
            format!("SPF for {ip}: {result} at {term}{via}.")
        }
        Some(term) => format!("SPF for {ip}: {result} (matched {term}{via})."),
    };
    let hint = match result {
        "fail" => "Add this sender to the SPF record if it is yours.",
        _ => "",
    };
    finding(severity, "spf_ip_result", message, hint)
}

/// The result, the term it ended at, and the include path to that term's record.
type Outcome = (&'static str, Option<String>, Vec<String>);

/// One evaluation's state: the lookups and void lookups so far, across every record it reads.
struct Eval {
    mail: Arc<Mail>,
    ip: IpAddr,
    lookups: u32,
    voids: u32,
}

impl Eval {
    fn check(&mut self, current: String, via: Vec<String>) -> Boxed<'_, Outcome> {
        Box::pin(async move {
            let txts = match self.mail.values(&current, RecordType::TXT).await {
                Ok(txts) => txts.unwrap_or_default(),
                Err(_) => return ("temperror", None, via),
            };
            let records: Vec<_> = txts.into_iter().filter(|t| is_spf(t)).collect();
            let record = match records.as_slice() {
                [] => return ("none", None, via),
                [one] => one.clone(),
                _ => return ("permerror", None, via),
            };
            let parsed = parse(&record);
            if let Some((_, term)) = parsed.errors.first() {
                return ("permerror", Some(term.to_string()), via);
            }
            let domain = self.mail.domain.clone();
            let vars = Vars {
                domain: &domain,
                current: &current,
                ip: self.ip,
            };
            for t in &parsed.terms {
                let Term::Directive {
                    text,
                    qualifier,
                    mech,
                    domain: spec,
                    net,
                    cidr,
                } = t
                else {
                    continue;
                };
                let stop = |result| (result, Some(text.to_string()), via.clone());
                let hit = match mech {
                    Mech::All => true,
                    Mech::Ip4 | Mech::Ip6 => {
                        let len = if self.ip.is_ipv4() { cidr.0 } else { cidr.1 };
                        net.is_some_and(|net| within(self.ip, net, len))
                    }
                    _ => {
                        self.lookups += 1;
                        if self.lookups > LIMIT {
                            return stop("permerror");
                        }
                        let Some(name) = target(spec.unwrap_or(&current), &vars) else {
                            return stop("permerror");
                        };
                        let hit = match mech {
                            Mech::Include => {
                                let path = [&via[..], &[text.to_string()]].concat();
                                match self.check(name, path).await {
                                    // The term that matched in there decides, with this
                                    // include's qualifier.
                                    ("pass", matched, via) => {
                                        return (result(*qualifier), matched, via);
                                    }
                                    ("fail" | "softfail" | "neutral", ..) => Ok(false),
                                    ("none", ..) => Err("permerror"),
                                    // The record itself failed: it stopped at this term.
                                    (result, None, _) => Err(result),
                                    deeper => return deeper,
                                }
                            }
                            Mech::Ptr => Ok(self.ptr(&name).await),
                            Mech::Exists => self
                                .ask(&name, RecordType::A, true)
                                .await
                                .map(|found| !found.is_empty()),
                            _ => self.addresses(*mech, &name, *cidr).await,
                        };
                        match hit {
                            Ok(hit) => hit,
                            Err(result) => return stop(result),
                        }
                    }
                };
                if hit {
                    return (result(*qualifier), Some(text.to_string()), via);
                }
            }
            let redirect = parsed.terms.iter().find_map(|t| match t {
                Term::Redirect { text, domain } if !parsed.has_all() => Some((*text, *domain)),
                _ => None,
            });
            let Some((text, spec)) = redirect else {
                return ("neutral", None, via);
            };
            self.lookups += 1;
            let here = Some(text.to_string());
            let name = target(spec, &vars).filter(|_| self.lookups <= LIMIT);
            let Some(name) = name else {
                return ("permerror", here, via);
            };
            let path = [&via[..], &[text.to_string()]].concat();
            match self.check(name, path).await {
                ("none", ..) => ("permerror", here, via),
                (result, None, _) if result.ends_with("error") => (result, here, via),
                outcome => outcome,
            }
        })
    }

    /// The values of `t` at `name`; a lookup that finds nothing counts as void when `void`.
    async fn ask(
        &mut self,
        name: &str,
        t: RecordType,
        void: bool,
    ) -> Result<Vec<String>, &'static str> {
        let found = self.mail.values(name, t).await.map_err(|_| "temperror")?;
        let found = found.unwrap_or_default();
        if void && found.is_empty() {
            self.voids += 1;
            if self.voids > VOID_LIMIT {
                return Err("permerror");
            }
        }
        Ok(found)
    }

    fn family(&self) -> RecordType {
        match self.ip {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::AAAA,
        }
    }

    /// `a` and `mx` (§5.3, §5.4): the address is in the network around one of the name's
    /// hosts.
    async fn addresses(
        &mut self,
        mech: Mech,
        name: &str,
        cidr: (u8, u8),
    ) -> Result<bool, &'static str> {
        let hosts = match mech {
            Mech::Mx => {
                let mx = self.ask(name, RecordType::MX, true).await?;
                if mx.len() > 10 {
                    return Err("permerror");
                }
                let hosts = mx.iter().filter_map(|v| v.split_once(' '));
                hosts.map(|(_, host)| host.to_string()).collect()
            }
            _ => vec![name.to_string()],
        };
        let len = if self.ip.is_ipv4() { cidr.0 } else { cidr.1 };
        for host in hosts {
            let found = self.ask(&host, self.family(), mech == Mech::A).await?;
            let mut nets = found.iter().filter_map(|v| v.parse().ok());
            if nets.any(|net| within(self.ip, net, len)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `ptr` (§5.5): a name of the address that maps back to it and ends in `name`. Lookup
    /// errors only make it not match.
    async fn ptr(&mut self, name: &str) -> bool {
        let reverse = crate::lookup::reverse(self.ip);
        let names = self.mail.values(&reverse, RecordType::PTR).await;
        let names = names.ok().flatten().unwrap_or_default();
        for host in names.iter().take(10) {
            let found = self.mail.values(host, self.family()).await;
            let found = found.ok().flatten().unwrap_or_default();
            let back = found.iter().any(|v| v.parse() == Ok(self.ip));
            if back && (host == name || host.ends_with(&format!(".{name}"))) {
                return true;
            }
        }
        false
    }
}

/// What a matching term with this qualifier gives (§4.6.2).
fn result(qualifier: char) -> &'static str {
    match qualifier {
        '-' => "fail",
        '~' => "softfail",
        '?' => "neutral",
        _ => "pass",
    }
}

/// `ip` is in `net`/`len`; addresses of another family never are.
fn within(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    let (a, b, bits): (u128, u128, u32) = match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a).into(), u32::from(b).into(), 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.into(), b.into(), 128),
        _ => return false,
    };
    let shift = bits.saturating_sub(len.into());
    a.checked_shr(shift).unwrap_or(0) == b.checked_shr(shift).unwrap_or(0)
}

fn multiple(name: &str, n: usize) -> Finding {
    let message = format!("{name} has {n} SPF records; that is a permanent error (RFC 7208 §4.5).");
    finding(
        Severity::Error,
        "spf_multiple",
        message,
        "Merge them into one v=spf1 record.",
    )
}

fn lookup_failed(name: &str, why: &str) -> Finding {
    let message =
        format!("Couldn't look up {name} for SPF ({why}); the lookup count may be incomplete.");
    finding(
        Severity::Warning,
        "spf_lookup_failed",
        message,
        "Run the check again.",
    )
}

/// The static walk: every term that queries DNS, in order, without a sending address.
struct Walk {
    mail: Arc<Mail>,
    lookups: u32,
    capped: bool,
    voids: u32,
    ptr: bool,
    found: Vec<Finding>,
}

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl Walk {
    /// The DNS terms of `record`, published at `current`; `path` holds the names from the domain
    /// down to `current`, for loops.
    fn record(
        &mut self,
        current: String,
        record: String,
        path: Vec<String>,
    ) -> Boxed<'_, Vec<Node>> {
        Box::pin(async move {
            let parsed = parse(&record);
            for (what, term) in &parsed.errors {
                let message = format!("The SPF record has an error: {what} (\"{term}\").");
                let hint = "Fix that term; receivers treat the whole record as a permanent error.";
                self.found
                    .push(finding(Severity::Error, "spf_syntax", message, hint));
            }
            let has_all = parsed.has_all();
            let mut nodes = Vec::new();
            for t in &parsed.terms {
                let (text, mech, spec) = match t {
                    Term::Directive {
                        text, mech, domain, ..
                    } if !matches!(mech, Mech::All | Mech::Ip4 | Mech::Ip6) => {
                        (*text, Some(*mech), *domain)
                    }
                    Term::Redirect { text, domain } if !has_all => (*text, None, Some(*domain)),
                    // Terms after `all` are never evaluated (RFC 7208 §5.1).
                    Term::Directive {
                        mech: Mech::All, ..
                    } => break,
                    _ => continue,
                };
                if self.lookups >= CAP || self.capped {
                    self.capped = true;
                    break;
                }
                self.lookups += 1;
                let mut node = Node {
                    term: text.to_string(),
                    lookups: 1,
                    record: None,
                    error: None,
                    children: Vec::new(),
                };
                let spec = spec.unwrap_or(&current);
                if spec.contains("%{") {
                    let message = format!(
                        "{text} uses macros that depend on the sender; it was counted but not followed."
                    );
                    let hint = "Pass --spf-ip to evaluate it for one sending IP.";
                    self.found
                        .push(finding(Severity::Info, "spf_macro", message, hint));
                    node.error = Some("macro".into());
                    nodes.push(node);
                    continue;
                }
                let vars = Vars {
                    domain: &self.mail.domain,
                    current: &current,
                    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                };
                let Some(name) = target(spec, &vars) else {
                    continue;
                };
                match mech {
                    None | Some(Mech::Include) => self.include(&mut node, name, &path).await,
                    Some(Mech::Ptr) => self.ptr = true,
                    Some(Mech::A) => {
                        let both = [RecordType::A, RecordType::AAAA].map(|t| (name.clone(), t));
                        let got = self.mail.all(both.to_vec()).await;
                        self.lookup(&mut node, &name, got);
                    }
                    Some(Mech::Mx) => {
                        let got = self.mail.values(&name, RecordType::MX).await;
                        let hosts = got.as_ref().map_or(0, |v| v.as_ref().map_or(0, Vec::len));
                        if hosts > 10 {
                            let message = format!(
                                "\"mx\" in the SPF record finds {hosts} hosts; the limit is 10."
                            );
                            let hint = "List the senders with ip4:/ip6: instead.";
                            self.found.push(finding(
                                Severity::Error,
                                "spf_mx_too_many",
                                message,
                                hint,
                            ));
                        }
                        self.lookup(&mut node, &name, vec![got]);
                    }
                    Some(_) => {
                        let got = self.mail.values(&name, RecordType::A).await;
                        self.lookup(&mut node, &name, vec![got]);
                    }
                }
                nodes.push(node);
            }
            nodes
        })
    }

    /// Counts a void lookup when every answer is empty, or notes the first that failed.
    fn lookup(&mut self, node: &mut Node, name: &str, got: Vec<Found>) {
        if let Some(why) = got.iter().find_map(|g| g.as_ref().err()) {
            self.found.push(lookup_failed(name, why));
            node.error = Some(why.clone());
        } else if got.iter().all(|g| {
            g.as_ref()
                .is_ok_and(|v| v.as_ref().is_none_or(Vec::is_empty))
        }) {
            self.voids += 1;
        }
    }

    /// An `include` or `redirect`: the target's record, walked in turn.
    async fn include(&mut self, node: &mut Node, name: String, path: &[String]) {
        if path.contains(&name) {
            let message = format!("The SPF includes loop back to {name}.");
            self.found.push(finding(
                Severity::Error,
                "spf_loop",
                message,
                "Remove the include that points back.",
            ));
            node.error = Some("loop".into());
            return;
        }
        let term = node.term.clone();
        let missing = |why: &str| {
            let message = format!(
                "{term} points to {name}, which has no SPF record ({why}); that is a permanent error."
            );
            finding(
                Severity::Error,
                "spf_include_missing",
                message,
                "Fix the name or remove the term.",
            )
        };
        let txts = match self.mail.values(&name, RecordType::TXT).await {
            Err(why) => {
                self.found.push(lookup_failed(&name, &why));
                node.error = Some(why);
                return;
            }
            Ok(None) => {
                self.voids += 1;
                self.found.push(missing("NXDOMAIN"));
                node.error = Some("NXDOMAIN".into());
                return;
            }
            Ok(Some(txts)) => txts,
        };
        let records: Vec<_> = txts.iter().filter(|t| is_spf(t)).collect();
        match records.as_slice() {
            [] => {
                if txts.is_empty() {
                    self.voids += 1;
                }
                self.found.push(missing("no record"));
                node.error = Some("no SPF record".into());
            }
            [one] => {
                node.record = Some(one.to_string());
                let path = [path, std::slice::from_ref(&name)].concat();
                node.children = self.record(name, one.to_string(), path).await;
            }
            many => {
                self.found.push(multiple(&name, many.len()));
                node.error = Some("multiple SPF records".into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(record: &str) -> Vec<(String, &str)> {
        parse(record).errors
    }

    #[test]
    fn networks_hold_addresses_of_their_family() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(within(ip("192.0.2.27"), ip("192.0.2.25"), 30));
        assert!(!within(ip("192.0.2.28"), ip("192.0.2.25"), 30));
        assert!(within(ip("203.0.113.9"), ip("0.0.0.0"), 0));
        assert!(within(ip("2001:db8:1::5"), ip("2001:db8:1::"), 48));
        assert!(!within(ip("2001:db8:2::5"), ip("2001:db8:1::"), 48));
        assert!(within(ip("2001:db8::1"), ip("::"), 0));
        assert!(!within(ip("192.0.2.1"), ip("::ffff:192.0.2.1"), 128));
    }

    #[test]
    fn records_start_with_the_version() {
        assert!(is_spf("v=spf1 -all") && is_spf("V=SPF1") && is_spf("v=spf1"));
        assert!(!is_spf("v=spf10 -all") && !is_spf("spf2.0/mfrom -all") && !is_spf("v=spf"));
    }

    #[test]
    fn terms_parse_with_their_qualifiers_domains_and_lengths() {
        let p = parse(
            "v=spf1 -include:_spf.example.net a mx:mail.example.net/24//64 ~ip4:192.0.2.0/24 ip6:2001:db8::/32 ?exists:%{i}.x.example.net ptr redirect=_r.example.net exp=explain.example.net unknown=x -all",
        );
        assert_eq!(p.errors, []);
        let dir = |t: &Term| match t {
            Term::Directive {
                qualifier,
                mech,
                domain,
                net,
                cidr,
                ..
            } => Some((*qualifier, *mech, domain.map(String::from), *net, *cidr)),
            _ => None,
        };
        let got: Vec<_> = p.terms.iter().filter_map(dir).collect();
        let ip = |s: &str| Some(s.parse().unwrap());
        assert_eq!(
            got,
            [
                (
                    '-',
                    Mech::Include,
                    Some("_spf.example.net".into()),
                    None,
                    (32, 128)
                ),
                ('+', Mech::A, None, None, (32, 128)),
                (
                    '+',
                    Mech::Mx,
                    Some("mail.example.net".into()),
                    None,
                    (24, 64)
                ),
                ('~', Mech::Ip4, None, ip("192.0.2.0"), (24, 128)),
                ('+', Mech::Ip6, None, ip("2001:db8::"), (32, 32)),
                (
                    '?',
                    Mech::Exists,
                    Some("%{i}.x.example.net".into()),
                    None,
                    (32, 128)
                ),
                ('+', Mech::Ptr, None, None, (32, 128)),
                ('-', Mech::All, None, None, (32, 128)),
            ]
        );
        assert!(p.terms.contains(&Term::Redirect {
            text: "redirect=_r.example.net",
            domain: "_r.example.net"
        }));
        assert!(p.has_all());
    }

    #[test]
    fn bad_terms_say_what_is_wrong() {
        let cases = [
            ("inlcude:example.net", "unknown mechanism"),
            ("include", "include needs a domain"),
            ("exists:", "exists needs a domain"),
            ("ip4:192.0.2.300", "invalid IP address"),
            ("ip4:2001:db8::1", "invalid IP address"),
            ("ip6:192.0.2.1", "invalid IP address"),
            ("ip4:192.0.2.0/33", "invalid CIDR length"),
            ("ip4:192.0.2.0/", "invalid CIDR length"),
            ("a/024", "invalid CIDR length"),
            ("mx//129", "invalid CIDR length"),
            ("all:x", "all takes no argument"),
            ("include:192.0.2.1", "invalid domain"),
            ("include:localhost", "invalid domain"),
            ("a:a..example.net", "invalid domain"),
            ("include:%{x}.example.net", "invalid macro"),
            ("include:%{i0}.example.net", "invalid macro"),
            ("exists:%{i.example.net", "invalid macro"),
            ("include:50%.example.net", "invalid macro"),
            ("-redirect=example.net", "unknown mechanism"),
        ];
        for (term, what) in cases {
            assert_eq!(
                errors(&format!("v=spf1 {term}")),
                [(what.to_string(), term)],
                "{term}"
            );
        }
        let twice = errors("v=spf1 redirect=a.example.net redirect=b.example.net");
        assert_eq!(
            twice,
            [(
                "redirect= appears more than once".to_string(),
                "redirect=b.example.net"
            )]
        );
    }

    #[test]
    fn macros_expand_with_transformers_and_escapes() {
        let v4 = Vars {
            domain: "example.com",
            current: "_spf.example.com",
            ip: "192.0.2.3".parse().unwrap(),
        };
        let ex = |s: &str| expand(s, &v4);
        assert_eq!(ex("%{s}").unwrap(), "postmaster@example.com");
        assert_eq!(
            ex("%{l}.%{o}.%{h}.%{d}").unwrap(),
            "postmaster.example.com.example.com._spf.example.com"
        );
        assert_eq!(
            ex("%{ir}.%{v}._spf.%{d2}").unwrap(),
            "3.2.0.192.in-addr._spf.example.com"
        );
        assert_eq!(ex("%{d1r}").unwrap(), "_spf");
        assert_eq!(ex("%{l-}.%{d2.-}").unwrap(), "postmaster.example.com");
        assert_eq!(ex("%{p}").unwrap(), "unknown");
        assert_eq!(ex("%%%_%-").unwrap(), "% %20");
        assert_eq!(ex("%{S}").unwrap(), "postmaster%40example.com");
        // The RFC 7208 §7.4 examples.
        let rfc = Vars {
            domain: "email.example.com",
            current: "email.example.com",
            ip: "192.0.2.3".parse().unwrap(),
        };
        assert_eq!(expand("%{d4}", &rfc).unwrap(), "email.example.com");
        assert_eq!(expand("%{d2}", &rfc).unwrap(), "example.com");
        assert_eq!(expand("%{dr}", &rfc).unwrap(), "com.example.email");
        assert_eq!(expand("%{d2r}", &rfc).unwrap(), "example.email");
        let v6 = Vars {
            ip: "2001:db8::cb01".parse().unwrap(),
            ..rfc
        };
        assert_eq!(
            expand("%{ir}.%{v}._spf.%{d2}", &v6).unwrap(),
            "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
        );
        for bad in ["%{c}", "%{x}", "%{d0}", "%{d", "%{dq}", "%a"] {
            assert_eq!(ex(bad), None, "{bad}");
        }
    }
}
