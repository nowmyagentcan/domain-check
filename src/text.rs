//! The text report: per domain a header, the findings with problems first and each hint under
//! its message, then one line per section. Styles are ANSI codes that anstream drops when
//! the stream isn't a terminal or `NO_COLOR` is set.

use std::io::IsTerminal;

use crate::check::Mark;
use crate::report::{Check, Output, Report, Section, Severity, Status};
use crate::sections::dns::Dns;
use crate::sections::email::Email;
use crate::sections::propagation::Propagation;

fn paint(code: &str, s: &str) -> String {
    format!("\x1b[{code}m{s}\x1b[0m")
}

pub fn bold(s: &str) -> String {
    paint("1", s)
}

pub fn dim(s: &str) -> String {
    paint("2", s)
}

pub fn red(s: &str) -> String {
    paint("31", s)
}

pub fn green(s: &str) -> String {
    paint("32", s)
}

pub fn yellow(s: &str) -> String {
    paint("33", s)
}

/// False only on a Windows console whose code page isn't UTF-8; pipes always get Unicode.
pub fn unicode(stream: &impl IsTerminal) -> bool {
    #[cfg(windows)]
    if stream.is_terminal() {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetConsoleOutputCP() -> u32;
        }
        // SAFETY: no arguments; it only reads the console's output code page.
        return unsafe { GetConsoleOutputCP() } == 65001;
    }
    let _ = stream;
    true
}

/// The text with the ASCII stand-ins for its symbols, arrows and box lines.
pub fn ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '✗' => out.push('x'),
            '✓' => out.push('+'),
            '·' | '─' => out.push('-'),
            '→' => out.push_str("->"),
            '…' => out.push_str("..."),
            '✻' => out.push('*'),
            '›' => out.push('>'),
            '╭' | '╮' | '╰' | '╯' => out.push('+'),
            '│' => out.push('|'),
            c => out.push(c),
        }
    }
    out
}

/// Every report, a blank line apart, and for 2 or more a last line counting them.
pub fn output(out: &Output) -> String {
    let texts: Vec<String> = out.reports.iter().map(report).collect();
    let mut text = texts.join("\n");
    if out.reports.len() > 1 {
        text += &format!("\n{}\n", bold(&summary(&out.reports)));
    }
    text
}

/// `3 domains: 1 with errors, 1 with info, 1 clean`: each domain in the group of its worst
/// finding, an invalid input with the errors.
fn summary(reports: &[Report]) -> String {
    let group = |r: &Report| match r.counts {
        _ if r.error.is_some() => 0,
        c if c.errors > 0 => 0,
        c if c.warnings > 0 => 1,
        c if c.info > 0 => 2,
        _ => 3,
    };
    let names = ["with errors", "with warnings", "with info", "clean"];
    let parts: Vec<_> = (0..4)
        .filter_map(|g| match reports.iter().filter(|r| group(r) == g).count() {
            0 => None,
            n => Some(format!("{n} {}", names[g])),
        })
        .collect();
    format!("{} domains: {}", reports.len(), parts.join(", "))
}

pub fn report(r: &Report) -> String {
    let (Some(domain), Some(unicode)) = (&r.domain, &r.unicode) else {
        return invalid(r);
    };
    let name = match unicode == domain {
        true => domain.clone(),
        false => format!("{domain} ({unicode})"),
    };
    let mut out = format!("{}  {}\n", bold(&name), dim(&summary_line(r)));
    let width = r.findings.iter().map(|f| f.check.key().len()).max();
    let width = width.unwrap_or(0);
    for f in &r.findings {
        let mark = match f.severity {
            Severity::Error => red("✗"),
            Severity::Warning => yellow("!"),
            Severity::Info => dim("i"),
        };
        out += &format!("{mark} {:width$}  {}\n", f.check.key(), f.message);
        if let Some(hint) = &f.hint {
            out += &format!("{:pad$}{}\n", "", dim(hint), pad = width + 4);
        }
    }
    out += "\n";
    let s = &r.sections;
    let lines = [
        s.dns.as_ref().map(|x| (Check::Dns, line(x, dns))),
        s.propagation
            .as_ref()
            .map(|x| (Check::Propagation, line(x, propagation))),
        s.email.as_ref().map(|x| (Check::Email, line(x, email))),
    ];
    for (check, line) in lines.into_iter().flatten() {
        out += &format!("{}{line}\n", bold(&format!("{:13}", check.title())));
    }
    out
}

fn invalid(r: &Report) -> String {
    let Some(e) = &r.error else {
        return String::new();
    };
    let mut out = format!("{} {}  {}\n", red("✗"), r.input, e.message);
    if let Some(hint) = &e.hint {
        let pad = r.input.chars().count() + 4;
        out += &format!("{:pad$}{}\n", "", dim(hint));
    }
    out
}

/// `Checking example.com: dns ✓ propagation …  4 s`
pub fn progress(domain: &str, marks: &[(Check, Mark)], secs: u64) -> String {
    let mut out = dim(&format!("Checking {domain}:"));
    for (check, mark) in marks {
        let mark = match mark {
            Mark::Running => dim("…"),
            Mark::Done => green("✓"),
            Mark::Down => yellow("!"),
        };
        out += &format!(" {} {mark}", dim(check.key()));
    }
    out + &dim(&format!("  {secs} s"))
}

/// How many columns the text takes on a terminal: its characters outside escape codes.
pub fn width(s: &str) -> usize {
    anstream::adapter::strip_str(s).to_string().chars().count()
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
    let why = || format!("{}: {}", s.status.text(), s.reason.as_deref().unwrap_or(""));
    match (&s.data, s.status) {
        (Some(data), _) => summary(data),
        (None, Status::Unavailable | Status::RateLimited) => yellow(&why()),
        (None, _) => why(),
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

fn email(e: &Email) -> String {
    let spf = match &e.spf {
        Some(s) => format!(
            "SPF {}, {}/10 lookups",
            s.all.as_deref().unwrap_or("no all"),
            s.lookups
        ),
        None => "SPF none".into(),
    };
    [spf].join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_replaces_every_symbol_the_report_uses() {
        let text = "✗ ! i ✓ a · b → c … ✻ › ╭─╮│╰╯";
        assert_eq!(ascii(text), "x ! i + a - b -> c ... * > +-+|++");
    }

    #[test]
    fn the_progress_line_marks_each_section() {
        let marks = [
            (Check::Dns, Mark::Done),
            (Check::Propagation, Mark::Running),
        ];
        let line = progress("example.com", &marks, 4);
        assert!(line.contains(&green("✓")) && line.contains(&dim("…")));
        let down = progress("example.com", &[(Check::Dns, Mark::Down)], 0);
        assert!(down.contains(&yellow("!")));
        let plain = "Checking example.com: dns ✓ propagation …  4 s";
        assert_eq!(width(&line), plain.chars().count());
        assert_eq!(width(&bold("ab")), 2);
    }
}
