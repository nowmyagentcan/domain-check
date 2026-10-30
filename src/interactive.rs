//! Interactive mode: a banner, then a prompt where each line is a domain (a pasted block checks
//! them all) or a session command.

use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::Error;
use crate::check::{self, CHECKS, Options};
use crate::report::Check;
use crate::sections::email::dkim;
use crate::text::{bold, dim, red};

/// Lines arriving within this long of each other were pasted together.
const PASTE: Duration = Duration::from_millis(50);

/// Checks domains with the session's options: the text report, or why it couldn't run.
pub type Checker<'a> = dyn FnMut(&[String], &Options) -> Result<String, Error> + 'a;

const HINT: &str = "  Type a domain · /checks · /selector · /help · /quit";

/// The box with the name, version and sentence, then the hint line.
pub fn banner(version: &str, sentence: &str) -> String {
    let name = format!("✻ domain-check {version}");
    let width = name.chars().count().max(sentence.chars().count());
    let rule = "─".repeat(width + 2);
    let row = |text: &str, styled: String| {
        let pad = width - text.chars().count();
        format!("{} {styled}{:pad$} {}\n", dim("│"), "", dim("│"))
    };
    let mut out = dim(&format!("╭{rule}╮")) + "\n";
    out += &row(&name, bold(&name));
    out += &row(sentence, sentence.to_string());
    out += &(dim(&format!("╰{rule}╯")) + "\n");
    out + HINT + "\n\n"
}

/// The session's checks when not all, then its DKIM selectors, then `›`.
fn prompt(o: &Options) -> String {
    let mut parts = Vec::new();
    if o.checks != CHECKS {
        let keys: Vec<_> = o.checks.iter().map(|c| c.key()).collect();
        parts.push(keys.join(","));
    }
    if !o.selectors.is_empty() {
        parts.push(o.selectors.join(","));
    }
    parts.push(bold("›"));
    parts.join(" ") + " "
}

fn checks_now(checks: &[Check]) -> String {
    match checks == CHECKS {
        true => "all".into(),
        false => checks
            .iter()
            .map(|c| c.key())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn selectors_now(selectors: &[String]) -> String {
    match selectors.is_empty() {
        true => "the 8 common ones".into(),
        false => selectors.join(", "),
    }
}

/// An error's two lines, indented like every answer.
fn failed(e: &Error) -> String {
    let mut out = format!("  {} {}\n", red("✗"), e.message);
    if let Some(hint) = &e.hint {
        out += &format!("    {}\n", dim(hint));
    }
    out
}

/// What a session command answers; `None` for `/quit`.
fn command(line: &str, o: &mut Options) -> Option<String> {
    let (name, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();
    let answer = match name {
        "/quit" => return None,
        "/help" => format!(
            "  Type a domain (a URL or an email address works too), or paste up to 20, one per line.
  /checks LIST   dns, propagation, email, rdap, tls, http or all (now {})
  /selector S    add a DKIM selector; /selector alone clears (now {})
  /quit          leave (Ctrl+C works too)
  For one DNS query, or options such as --spf-ip, run domain-check with arguments.\n",
            checks_now(&o.checks),
            selectors_now(&o.selectors)
        ),
        "/checks" => {
            let names: Vec<String> = match rest {
                "" => vec!["all".into()],
                list => list.split(',').map(String::from).collect(),
            };
            match check::checks(&names) {
                Ok(checks) => {
                    o.checks = checks;
                    format!("  Checks: {}\n", checks_now(&o.checks))
                }
                Err(e) => failed(&e),
            }
        }
        "/selector" if rest.is_empty() => {
            o.selectors.clear();
            format!("  DKIM selectors: {}\n", selectors_now(&o.selectors))
        }
        "/selector" => match dkim::selector(rest) {
            Ok(s) => {
                if !o.selectors.contains(&s) {
                    o.selectors.push(s);
                }
                format!("  DKIM selectors: {}\n", selectors_now(&o.selectors))
            }
            Err(e) => failed(&e),
        },
        _ => failed(&Error::usage(
            format!("Unknown command '{name}'."),
            "Try /help.",
        )),
    };
    Some(answer)
}

/// Every line indented by two spaces, then a blank line.
fn indented(text: &str) -> String {
    let lines = text.lines().map(|l| match l {
        "" => "\n".to_string(),
        l => format!("  {l}\n"),
    });
    lines.collect::<String>() + "\n"
}

/// The session: `lines` until `/quit` or the end of input, each answer through `say`, each
/// group of domains through `check` (the text report, or why it couldn't run).
pub fn run(
    lines: Receiver<String>,
    o: &mut Options,
    say: &mut dyn FnMut(&str),
    check: &mut Checker,
) {
    say(&prompt(o));
    while let Ok(first) = lines.recv() {
        let mut block = vec![first];
        while let Ok(line) = lines.recv_timeout(PASTE) {
            block.push(line);
        }
        let mut domains: Vec<String> = Vec::new();
        for line in block.iter().map(|l| l.trim()).filter(|l| !l.is_empty()) {
            if !line.starts_with('/') {
                domains.push(line.to_string());
                continue;
            }
            flush(&mut domains, o, say, check);
            match command(line, o) {
                Some(answer) => say(&(answer + "\n")),
                None => return,
            }
        }
        flush(&mut domains, o, say, check);
        say(&prompt(o));
    }
    // The end of input (Ctrl+D, Ctrl+Z): finish the prompt's line.
    say("\n");
}

/// Checks the domains gathered so far, if any.
fn flush(domains: &mut Vec<String>, o: &Options, say: &mut dyn FnMut(&str), check: &mut Checker) {
    if domains.is_empty() {
        return;
    }
    match check(domains, o) {
        Ok(text) => say(&indented(&text)),
        Err(e) => say(&(failed(&e) + "\n")),
    }
    domains.clear();
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;
    use crate::Ports;
    use crate::text::width;

    fn options() -> Options {
        Options {
            checks: CHECKS.to_vec(),
            dns: None,
            resolvers: Vec::new(),
            types: Vec::new(),
            selectors: Vec::new(),
            spf_ip: None,
            ca: Vec::new(),
            allow_private: false,
            ports: Ports::default(),
            bootstrap: None,
            debug: false,
        }
    }

    /// The session's output for `input` (each item one burst of lines), with styles removed,
    /// and the domains each check was asked about.
    fn session(input: &[&[&str]]) -> (String, Vec<Vec<String>>) {
        let (tx, rx) = mpsc::channel();
        let input: Vec<Vec<String>> = input
            .iter()
            .map(|burst| burst.iter().map(|l| l.to_string()).collect())
            .collect();
        std::thread::spawn(move || {
            for burst in input {
                burst.into_iter().for_each(|l| tx.send(l).unwrap());
                std::thread::sleep(PASTE * 4);
            }
        });
        let (mut out, mut asked) = (String::new(), Vec::new());
        let mut o = options();
        run(
            rx,
            &mut o,
            &mut |s| out += &anstream::adapter::strip_str(s).to_string(),
            &mut |domains, o| {
                asked.push(domains.to_vec());
                let checks: Vec<_> = o.checks.iter().map(|c| c.key()).collect();
                Ok(format!(
                    "{} [{}]\n\nDNS  ok\n",
                    domains.join(" "),
                    checks.join(",")
                ))
            },
        );
        (out, asked)
    }

    #[test]
    fn the_banner_fits_80_columns() {
        let sentence =
            "Check a domain's DNS, email security, registration, certificate and headers.";
        let b = banner("0.1.0", sentence);
        let lines: Vec<_> = b.lines().collect();
        assert_eq!(lines.len(), 6);
        assert!(lines[..4].iter().all(|l| width(l) == 80), "{b}");
        assert_eq!(
            anstream::adapter::strip_str(lines[1]).to_string(),
            format!("│ ✻ domain-check 0.1.0{:57}│", "")
        );
        assert_eq!(lines[4], HINT);
        assert_eq!(lines[5], "");
    }

    #[test]
    fn domains_are_checked_and_pasted_blocks_together() {
        let (out, asked) = session(&[&["example.com"], &["a.example", " ", "b.example"]]);
        assert_eq!(asked, [vec!["example.com"], vec!["a.example", "b.example"]]);
        let all = "[dns,propagation,email,rdap,tls,http]";
        let want = [
            "› ",
            &format!("  example.com {all}\n\n  DNS  ok\n\n"),
            "› ",
            &format!("  a.example b.example {all}\n\n  DNS  ok\n\n"),
            "› \n",
        ];
        assert_eq!(out, want.concat());
    }

    #[test]
    fn commands_change_the_session_and_say_so() {
        let (out, asked) = session(&[
            &["/checks email,TLS"],
            &["/selector google"],
            &["/selector s1"],
            &["example.com"],
            &["/checks smtp"],
            &["/selector x y"],
            &["/frobnicate"],
            &["/help"],
            &["/selector"],
            &["/checks"],
            &["/quit"],
            &["never.example"],
        ]);
        assert_eq!(asked, [vec!["example.com"]]);
        let set = "email,tls google,s1 › ";
        let want = [
            "› ",
            "  Checks: email, tls\n\n",
            "email,tls › ",
            "  DKIM selectors: google\n\n",
            "email,tls google › ",
            "  DKIM selectors: google, s1\n\n",
            set,
            "  example.com [email,tls]\n\n  DNS  ok\n\n",
            set,
            "  ✗ Unknown check 'smtp'.\n    Use dns, propagation, email, rdap, tls, http or all.\n\n",
            set,
            "  ✗ 'x y' isn't a valid DKIM selector.\n    Use the s= value from a DKIM-Signature header.\n\n",
            set,
            "  ✗ Unknown command '/frobnicate'.\n    Try /help.\n\n",
            set,
            "  Type a domain (a URL or an email address works too), or paste up to 20, one per line.\n",
            "  /checks LIST   dns, propagation, email, rdap, tls, http or all (now email, tls)\n",
            "  /selector S    add a DKIM selector; /selector alone clears (now google, s1)\n",
            "  /quit          leave (Ctrl+C works too)\n",
            "  For one DNS query, or options such as --spf-ip, run domain-check with arguments.\n\n",
            set,
            "  DKIM selectors: the 8 common ones\n\n",
            "email,tls › ",
            "  Checks: all\n\n",
            "› ",
        ];
        assert_eq!(out, want.concat());
    }

    #[test]
    fn a_check_that_cant_run_says_why_and_the_session_goes_on() {
        let (tx, rx) = mpsc::channel();
        tx.send("example.com".to_string()).unwrap();
        drop(tx);
        let mut out = String::new();
        run(
            rx,
            &mut options(),
            &mut |s| out += &anstream::adapter::strip_str(s).to_string(),
            &mut |_, _| Err(Error::usage("Too many domains.", "Split them.")),
        );
        let want = ["› ", "  ✗ Too many domains.\n    Split them.\n\n", "› \n"];
        assert_eq!(out, want.concat());
    }
}
