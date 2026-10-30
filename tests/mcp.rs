//! Talks to `domain-check mcp` over stdio the way MCP clients do, against the DNS stub and
//! the web and RDAP mock.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;

use common::web::Web;
use common::{DnsStub, command};
use serde_json::{Value, json};

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

/// Starts `mcp <args>`, initializes, sends each message, reads an answer to each, closes
/// stdin, and returns the responses by id and the exit code.
fn session(args: &[&str], messages: &[Value], env: &[(&str, &str)]) -> (Vec<Value>, i32) {
    let mut child = command(&[&["mcp"], args].concat(), env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "{INITIALIZE}\n{INITIALIZED}").unwrap();
    for m in messages {
        writeln!(stdin, "{m}").unwrap();
    }
    let lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut responses: Vec<Value> = lines
        .take(messages.len() + 1)
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(String::from_utf8(out.stderr).unwrap(), "");
    responses.sort_by_key(|r| r["id"].as_u64());
    (responses, out.status.code().unwrap())
}

fn call(id: u64, tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}})
}

/// `value` without the times that differ between two runs: `checked_at` and the RDAP
/// mock's dates, which it makes relative to now.
fn unstamped(mut value: Value) -> Value {
    for r in value["reports"].as_array_mut().into_iter().flatten() {
        r.as_object_mut().unwrap().remove("checked_at");
        let dated = |v: &mut Value| {
            if let Some(o) = v.as_object_mut() {
                o.retain(|k, _| !["created", "expires", "updated"].contains(&k.as_str()));
            }
        };
        dated(&mut r["rdap"]["registrar_data"]);
        dated(&mut r["rdap"]);
    }
    value
}

/// The CLI's `--json` answer for the same question.
fn cli(args: &[&str], env: &[(&str, &str)]) -> Value {
    let out = command(&[args, &["--json"]].concat(), env)
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

/// A successful call: structured content and its one text block both the CLI's JSON.
fn same_as_cli(response: &Value, args: &[&str], env: &[(&str, &str)]) {
    let result = &response["result"];
    assert_eq!(result["isError"], false, "{args:?}: {result}");
    let want = unstamped(cli(args, env));
    assert_eq!(
        unstamped(result["structuredContent"].clone()),
        want,
        "{args:?}"
    );
    let content = result["content"].as_array().unwrap();
    assert_eq!(content.len(), 1);
    let text: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(unstamped(text), want);
}

#[test]
fn lists_both_tools_with_their_schemas() {
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let (responses, code) = session(&[], &[list], &[]);
    assert_eq!(code, 0);
    let init = &responses[0]["result"];
    assert_eq!(
        init["serverInfo"],
        json!({"name": "domain-check", "version": "0.1.0"})
    );
    assert!(
        init["instructions"]
            .as_str()
            .unwrap()
            .starts_with("Check a domain from this computer: DNS records and propagation")
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["check_domain", "dns_lookup"]);
    let types = json!([
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA", "SRV", "PTR", "DS", "DNSKEY",
        "TLSA", "HTTPS", "SVCB"
    ]);
    for t in tools {
        assert_eq!(
            t["annotations"],
            json!({"readOnlyHint": true, "idempotentHint": true, "openWorldHint": true})
        );
        assert!(!t.to_string().contains("\"format\":"), "{t}");
        let input = &t["inputSchema"];
        assert_eq!(
            (&input["type"], &input["additionalProperties"]),
            (&json!("object"), &json!(false))
        );
        assert_eq!(input["properties"]["types"]["items"]["enum"], types);
        assert_eq!(t["outputSchema"]["type"], "object");
    }
    let check = &tools[0];
    assert!(
        check["description"]
            .as_str()
            .unwrap()
            .starts_with("Check one domain and return a report with problems first:")
    );
    let p = &check["inputSchema"]["properties"];
    let mut keys: Vec<&String> = p.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "allow_private",
            "checks",
            "dkim_selectors",
            "dns_server",
            "domain",
            "spf_ip",
            "types"
        ]
    );
    assert_eq!(check["inputSchema"]["required"], json!(["domain"]));
    assert_eq!(
        (&p["domain"]["minLength"], &p["domain"]["maxLength"]),
        (&json!(1), &json!(1024))
    );
    assert_eq!(
        p["checks"]["items"]["enum"],
        json!(["dns", "propagation", "email", "rdap", "tls", "http"])
    );
    assert_eq!(p["dkim_selectors"]["maxItems"], 10);
    assert_eq!(p["types"]["default"], json!(["A", "AAAA", "MX", "TXT"]));
    assert_eq!(p["spf_ip"]["type"], json!(["string", "null"]));
    assert_eq!(p["allow_private"]["default"], false);
    assert_eq!(
        check["outputSchema"]["required"],
        json!(["reports", "summary", "data"])
    );
    let lookup = &tools[1];
    assert!(
        lookup["description"]
            .as_str()
            .unwrap()
            .starts_with("Run one DNS query and return the records with TTLs")
    );
    assert_eq!(lookup["inputSchema"]["required"], json!(["name"]));
    assert_eq!(
        lookup["outputSchema"]["required"],
        json!(["name", "server", "results"])
    );
}

#[test]
fn answers_like_the_cli_through_the_stub_and_the_mock() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let server = ["--resolver", &dns, "--ca-file", &web.ca];
    let calls = [
        (
            "check_domain",
            json!({"domain": "https://web.example.com/a", "dns_server": dns, "allow_private": true}),
            vec![
                "https://web.example.com/a",
                "--dns",
                &dns,
                "--allow-private",
            ],
        ),
        (
            "check_domain",
            json!({"domain": "example.net", "checks": ["email", "dns"], "dkim_selectors": ["s1"],
                   "spf_ip": "192.0.2.10", "types": ["MX"], "dns_server": dns}),
            vec![
                "example.net",
                "-c",
                "email,dns",
                "-s",
                "s1",
                "--spf-ip",
                "192.0.2.10",
                "-t",
                "MX",
                "--dns",
                &dns,
            ],
        ),
        (
            "dns_lookup",
            json!({"name": "example.com", "types": ["MX", "TXT"], "server": dns}),
            vec!["lookup", "example.com", "MX", "TXT", "--dns", &dns],
        ),
        (
            "dns_lookup",
            json!({"name": "nx.example.com", "server": dns}),
            vec!["lookup", "nx.example.com", "--dns", &dns],
        ),
    ];
    let messages: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(i, (tool, args, _))| call(i as u64 + 2, tool, args.clone()))
        .collect();
    let (responses, code) = session(&server, &messages, &env);
    assert_eq!(code, 0);
    let rdap_hits = web.hits().len();
    assert!(rdap_hits > 0 && !stub.queries().is_empty());
    for (i, (_, _, args)) in calls.iter().enumerate() {
        let check = !args.contains(&"lookup");
        let cli_args = match check {
            true => [&args[..], &["--resolver", &dns, "--ca-file", &web.ca]].concat(),
            false => args.clone(),
        };
        same_as_cli(&responses[i + 1], &cli_args, &env);
    }
    let first = &responses[1]["result"]["structuredContent"]["reports"][0];
    for section in ["dns", "propagation", "email", "rdap", "tls", "http"] {
        assert_eq!(first[section]["status"], "ok", "{section}: {first}");
    }
}

#[test]
fn refuses_bad_arguments_with_the_error_object() {
    let unknown = "Can't read the arguments: unknown field `foo`, expected one of `domain`, `checks`, `dkim_selectors`, `spf_ip`, `types`, `dns_server`, `allow_private`.";
    let calls = [
        (
            "check_domain",
            json!({"domain": "example.com", "foo": 1}),
            "bad_request",
            unknown,
        ),
        ("check_domain", json!({}), "bad_request", ""),
        ("check_domain", json!({"domain": 7}), "bad_request", ""),
        (
            "check_domain",
            json!({"domain": "example.com", "allow_private": "yes"}),
            "bad_request",
            "",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "checks": []}),
            "usage",
            "checks is empty.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "checks": ["smtp"]}),
            "usage",
            "Unknown check 'smtp'.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "types": ["XX"]}),
            "usage",
            "Unknown record type 'XX'.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "spf_ip": "nope"}),
            "usage",
            "spf_ip nope isn't an IP address.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "dns_server": "x"}),
            "usage",
            "dns_server x isn't an IP address.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "dkim_selectors": vec!["s"; 11]}),
            "usage",
            "11 DKIM selectors; at most 10.",
        ),
        (
            "check_domain",
            json!({"domain": "example.com", "dkim_selectors": ["a b"]}),
            "usage",
            "'a b' isn't a valid DKIM selector.",
        ),
        (
            "check_domain",
            json!({"domain": "printer.test"}),
            "special_use",
            "printer.test is a special-use name (RFC 6761); it never resolves on the public internet.",
        ),
        (
            "check_domain",
            json!({"domain": "192.0.2.1"}),
            "ip_address",
            "",
        ),
        (
            "check_domain",
            json!({"domain": ""}),
            "empty",
            "Empty input.",
        ),
        (
            "dns_lookup",
            json!({"name": "192.0.2.1", "types": ["MX"]}),
            "usage",
            "192.0.2.1 is an IP address, so it can only be looked up as PTR.",
        ),
        ("dns_lookup", json!({"name": "a..b"}), "domain_invalid", ""),
        (
            "dns_lookup",
            json!({"name": "example.com", "types": []}),
            "usage",
            "types is empty.",
        ),
        (
            "dns_lookup",
            json!({"name": "example.com", "type": "A"}),
            "bad_request",
            "",
        ),
    ];
    let messages: Vec<Value> = calls
        .iter()
        .enumerate()
        .map(|(i, (tool, args, _, _))| call(i as u64 + 2, tool, args.clone()))
        .collect();
    let (responses, code) = session(&[], &messages, &[]);
    assert_eq!(code, 0);
    for (i, (_, args, code, message)) in calls.iter().enumerate() {
        let result = &responses[i + 1]["result"];
        assert_eq!(result["isError"], true, "{args}: {result}");
        assert!(result.get("structuredContent").is_none(), "{args}");
        let content = result["content"].as_array().unwrap();
        assert_eq!(content.len(), 1, "{args}");
        let error: Value = serde_json::from_str(content[0]["text"].as_str().unwrap()).unwrap();
        let mut keys: Vec<&String> = error["error"].as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["code", "hint", "message"], "{args}");
        assert_eq!(error["error"]["code"], *code, "{args}: {error}");
        if !message.is_empty() {
            assert_eq!(error["error"]["message"], *message, "{args}");
        }
    }
}

#[test]
fn ends_when_stdin_closes() {
    let (responses, code) = session(&[], &[], &[]);
    assert_eq!((responses.len(), code), (1, 0));
    let out = command(&["mcp"], &[]).output().unwrap();
    assert_eq!(
        (out.status.code(), out.stdout.len(), out.stderr.len()),
        (Some(0), 0, 0)
    );
}

#[test]
fn bad_server_flags_are_usage_errors() {
    let out = command(&["mcp", "--resolver", "nope"], &[])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("--resolver nope isn't an IP address."),
        "{err}"
    );
}
