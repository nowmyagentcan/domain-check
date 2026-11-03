//! Every command in README.md runs as written, against the DNS stub instead of the internet.

mod common;

use common::{DnsStub, command};

const README: &str = include_str!("../README.md");

/// The words of an example, without its `  # comment`.
fn words(line: &str) -> Vec<&str> {
    line.split("  #")
        .next()
        .unwrap()
        .split_whitespace()
        .collect()
}

#[test]
fn every_example_runs_against_the_stub() {
    let stub = DnsStub::new();
    let dns = stub.addr();
    // The zones' nameservers are 127.0.0.1 and ::1: their port 53 is the stub's.
    let ports = stub.ports();
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let mut examples = 0;
    for block in README.split("```").skip(1).step_by(2) {
        let (lang, body) = block.split_once('\n').unwrap();
        let lines: Vec<&str> = match lang {
            "sh" => body.lines().collect(),
            "text" => body
                .lines()
                .take(1)
                .map(|l| l.trim_start_matches("$ "))
                .collect(),
            _ => continue,
        };
        for line in lines.into_iter().filter(|l| l.starts_with("domain-check ")) {
            let words = words(line);
            let local: &[&str] = match words[1] {
                "lookup" => &["--dns", &dns],
                _ => &["--dns", &dns, "--resolver", &dns],
            };
            let out = command(&[&words[1..], local].concat(), &env)
                .output()
                .unwrap();
            let code = out.status.code().unwrap();
            let err = String::from_utf8_lossy(&out.stderr);
            // 2 would be a usage error: the example doesn't parse.
            assert!([0, 1, 3].contains(&code), "{line}: exit {code}: {err}");
            if words.contains(&"--json") {
                serde_json::from_slice::<serde_json::Value>(&out.stdout).expect(line);
            }
            examples += 1;
        }
    }
    assert_eq!(examples, 8);
}

#[test]
fn never_points_at_the_unrelated_crate() {
    assert!(!README.contains("cargo install domain-check"));
    assert!(README.contains("This is not the crates.io crate of the same name"));
    let lines = README.lines().count();
    assert!(lines <= 150, "{lines} lines");
}

#[test]
fn the_help_the_readme_points_to_lists_the_options() {
    assert!(README.contains("`domain-check check --help` lists every option"));
    let (code, out, _) = common::run(&["check", "--help"], &[]);
    assert_eq!(code, 0);
    for flag in ["--checks", "--json", "--dns", "--allow-private"] {
        assert!(out.contains(flag), "{flag} isn't in check --help:\n{out}");
    }
}

#[test]
#[ignore = "known bug: DC28"]
fn what_goes_online_names_the_sending_ip() {
    // SPF macros such as %{i} put the --spf-ip address into DNS names the tool looks up.
    let section = README.split("### What goes online").nth(1).unwrap();
    let section = section.split("\n#").next().unwrap();
    assert!(section.contains("--spf-ip"), "{section}");
}
