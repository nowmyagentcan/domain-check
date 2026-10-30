//! The text report: per domain a header, the findings with problems first and each hint under
//! its message, then one line per section.

use crate::report::{Check, Report, Section, Severity};
use crate::sections::dns::Dns;
use crate::sections::propagation::Propagation;

/// Every report, a blank line apart.
pub fn output(reports: &[Report]) -> String {
    let texts: Vec<String> = reports.iter().map(report).collect();
    texts.join("\n")
}

pub fn report(r: &Report) -> String {
    let (Some(domain), Some(unicode)) = (&r.domain, &r.unicode) else {
        return invalid(r);
    };
    let name = match unicode == domain {
        true => domain.clone(),
        false => format!("{domain} ({unicode})"),
    };
    let mut out = format!("{name}  {}\n", summary_line(r));
    let width = r.findings.iter().map(|f| f.check.key().len()).max();
    let width = width.unwrap_or(0);
    for f in &r.findings {
        let mark = match f.severity {
            Severity::Error => "✗",
            Severity::Warning => "!",
            Severity::Info => "i",
        };
        out += &format!("{mark} {:width$}  {}\n", f.check.key(), f.message);
        if let Some(hint) = &f.hint {
            out += &format!("{:pad$}{hint}\n", "", pad = width + 4);
        }
    }
    out += "\n";
    let s = &r.sections;
    let lines = [
        s.dns.as_ref().map(|x| (Check::Dns, line(x, dns))),
        s.propagation
            .as_ref()
            .map(|x| (Check::Propagation, line(x, propagation))),
    ];
    for (check, line) in lines.into_iter().flatten() {
        out += &format!("{:13}{line}\n", check.title());
    }
    out
}

fn invalid(r: &Report) -> String {
    let Some(e) = &r.error else {
        return String::new();
    };
    let mut out = format!("✗ {}  {}\n", r.input, e.message);
    if let Some(hint) = &e.hint {
        out += &format!("{:pad$}{hint}\n", "", pad = r.input.chars().count() + 4);
    }
    out
}

/// `2 errors · 1 warning · 3 info · 1 check couldn't run · checked 15:40 UTC`, zeros left out.
pub fn summary_line(r: &Report) -> String {
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let c = r.counts;
    let mut parts = Vec::new();
    if c.errors > 0 {
        parts.push(plural(c.errors, "error"));
    }
    if c.warnings > 0 {
        parts.push(plural(c.warnings, "warning"));
    }
    if c.info > 0 {
        parts.push(format!("{} info", c.info));
    }
    match r.unavailable {
        0 => {}
        1 => parts.push("1 check couldn't run".into()),
        n => parts.push(format!("{n} checks couldn't run")),
    }
    if parts.is_empty() {
        parts.push("No problems found".into());
    }
    let at = r.checked_at.get(11..16).unwrap_or_default();
    format!("{} · checked {at} UTC", parts.join(" · "))
}

/// A section's line: its summary, or why it has none.
fn line<T>(s: &Section<T>, summary: fn(&T) -> String) -> String {
    match &s.data {
        Some(data) => summary(data),
        None => format!("{}: {}", s.status.text(), s.reason.as_deref().unwrap_or("")),
    }
}

fn dns(d: &Dns) -> String {
    if !d.exists {
        return "doesn't exist (NXDOMAIN)".into();
    }
    let mut parts = Vec::new();
    if !d.cname_chain.is_empty() {
        parts.push(format!("CNAME {}", d.cname_chain.join(" → ")));
    }
    for t in ["A", "AAAA", "MX", "NS"] {
        let values: Vec<_> = d
            .records
            .get(t)
            .into_iter()
            .flatten()
            .map(|r| r.value.as_str())
            .collect();
        match values.join(", ").as_str() {
            "" => {}
            "0 ." => parts.push("MX 0 . (null MX)".into()),
            v => parts.push(format!("{t} {v}")),
        }
    }
    let s = &d.dnssec;
    let dnssec = match (s.bogus, s.signed, s.validated_by.is_empty()) {
        (true, _, _) => "bogus",
        (_, false, _) => "unsigned",
        (_, _, false) => "signed, validated",
        _ => "signed, not validated",
    };
    parts.push(format!("DNSSEC {dnssec}"));
    parts.join(" · ")
}

fn propagation(p: &Propagation) -> String {
    let ok = |status: &str| status == "ok";
    let silent = p
        .authoritative
        .iter()
        .filter(|s| !ok(s.status) && s.status != "no_route")
        .count();
    let mut out = match p.consistent {
        None => "no answers to compare".to_string(),
        Some(true) => format!(
            "consistent: {} nameserver addresses, {} resolvers agree on {}",
            p.authoritative.iter().filter(|s| ok(s.status)).count(),
            p.resolvers.iter().filter(|v| ok(v.status)).count(),
            p.types.join(", ")
        ),
        Some(false) => {
            let differ: Vec<_> = p
                .resolvers
                .iter()
                .flat_map(|v| {
                    let wrong = v.answers.0.iter().filter(|(_, s)| s.agrees == Some(false));
                    wrong.map(|(t, _)| format!("{} differs on {t}", v.name))
                })
                .collect();
            format!("not consistent: {}", differ.join(", "))
        }
    };
    match silent {
        0 => {}
        1 => out += " · 1 nameserver address didn't answer",
        n => out += &format!(" · {n} nameserver addresses didn't answer"),
    }
    out
}
