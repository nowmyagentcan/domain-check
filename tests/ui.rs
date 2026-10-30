//! The local page: the HTML itself, and `domain-check ui` answering over HTTP on 127.0.0.1.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::web::Web;
use common::{DnsStub, command};
use serde_json::{Value, json};

const PAGE: &str = include_str!("../src/ui.html");

#[test]
fn page_reaches_no_other_host() {
    let allowed = [
        "https://nowmyagentcan.com",
        "https://github.com/nowmyagentcan/domain-check",
        "https://x.com/chayp05",
        "http://www.w3.org/2000/svg",
    ];
    for (i, _) in PAGE.match_indices("://") {
        let start = PAGE[..i]
            .rfind(|c: char| !c.is_ascii_alphanumeric())
            .map_or(0, |p| p + 1);
        let url = &PAGE[start..];
        assert!(
            allowed.iter().any(|a| url.starts_with(a)),
            "unexpected URL: {}",
            &url[..url.len().min(60)]
        );
    }
    for loader in ["<script src", "<link rel=\"stylesheet\"", "@import", "url("] {
        assert!(!PAGE.contains(loader), "page loads a file: {loader}");
    }
    assert_eq!(PAGE.matches("fetch(").count(), 1);
    assert!(PAGE.contains(
        "fetch(\"/api\", { method: \"POST\", headers: { \"content-type\": \"application/json\" }"
    ));
}

#[test]
fn page_has_the_title_and_one_button() {
    assert!(PAGE.contains("<title>Check a domain</title>"));
    assert_eq!(
        PAGE.matches("<button class=\"go\">Check</button>").count(),
        1
    );
    let markup = &PAGE[..PAGE.find("<script>").unwrap()];
    assert_eq!(markup.matches("<button").count(), 1);
}

#[test]
fn page_sends_only_check_domain_arguments() {
    let known = [
        "domain",
        "checks",
        "dkim_selectors",
        "spf_ip",
        "types",
        "dns_server",
        "allow_private",
    ];
    for (i, _) in PAGE.match_indices("body.") {
        let key: String = PAGE[i + 5..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        assert!(known.contains(&key.as_str()), "unknown argument: {key}");
    }
    for check in ["dns", "propagation", "email", "rdap", "tls", "http"] {
        assert!(PAGE.contains(&format!("name=\"checks\" value=\"{check}\" checked")));
    }
    assert!(PAGE.contains("<input id=\"allow_private\" type=\"checkbox\">"));
}

/// `domain-check ui --no-open <args>` on a free port, stopped when dropped.
struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start(args: &[&str], env: &[(&str, &str)]) -> Server {
        let mut child = command(&[&["ui", "--no-open"], args].concat(), env)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let port = line
            .strip_prefix("Open http://127.0.0.1:")
            .and_then(|rest| rest.strip_suffix("  (Ctrl+C to stop)\n"))
            .unwrap_or_else(|| panic!("{line:?}"))
            .parse()
            .unwrap();
        Server { child, port }
    }

    /// Sends `head` (request line and headers, `{port}` filled in) and `body`; returns the
    /// status, the headers and the body.
    fn send(&self, head: &str, body: &[u8]) -> (u16, String, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        let head = head.replace("{port}", &self.port.to_string());
        stream
            .write_all(format!("{head}\r\n\r\n").as_bytes())
            .unwrap();
        // A server that refused the head may close before the body is all sent.
        let _ = stream.write_all(body);
        let _ = stream.shutdown(Shutdown::Write);
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        let (headers, body) = response.split_once("\r\n\r\n").unwrap();
        let status = headers[9..12].parse().unwrap();
        (status, headers.to_owned(), body.to_owned())
    }

    /// The status of a request with request line `line` and one more header line, raw bytes.
    fn status(&self, line: &[u8], header: &[u8]) -> String {
        let body = r#"{"domain":"printer.test"}"#;
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        let host = format!(
            "\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            self.port,
            body.len()
        );
        let request = [line, host.as_bytes(), header, b"\r\n\r\n", body.as_bytes()].concat();
        stream.write_all(&request).unwrap();
        let mut response = Vec::new();
        // A server that drops the request may reset the connection; that reads as no status.
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(response.get(9..12).unwrap_or_default()).into_owned()
    }

    fn post(&self, request: &Value) -> (u16, Value) {
        let body = request.to_string();
        let head = format!(
            "POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nOrigin: http://127.0.0.1:{{port}}\r\nContent-Type: application/json\r\nContent-Length: {}",
            body.len()
        );
        let (status, _, body) = self.send(&head, body.as_bytes());
        (status, serde_json::from_str(&body).unwrap())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }
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

/// The CLI's `--json` answer for the same check.
fn cli(args: &[&str], env: &[(&str, &str)]) -> Value {
    let out = command(&[args, &["--json"]].concat(), env)
        .output()
        .unwrap();
    unstamped(serde_json::from_slice(&out.stdout).unwrap())
}

#[test]
fn answers_like_the_cli() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let dns = stub.addr();
    let ports = web.ports(&stub);
    let env = [("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str())];
    let server = Server::start(&["--resolver", &dns, "--ca-file", &web.ca], &env);
    let (status, headers, body) = server.send("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}", b"");
    assert_eq!(status, 200);
    assert_eq!(body, PAGE);
    assert!(headers.contains("Content-Type: text/html; charset=utf-8\r\n"));
    assert!(headers.contains("Content-Security-Policy: default-src 'none';"));
    let common = ["--dns", &dns, "--resolver", &dns, "--ca-file", &web.ca];
    for (request, args) in [
        (
            json!({"domain": "web.example.com", "dns_server": dns, "allow_private": true}),
            vec!["web.example.com", "--allow-private"],
        ),
        (
            json!({"domain": "postmaster@example.net", "checks": ["dns", "email"], "dkim_selectors": ["s1", "s2"],
                   "spf_ip": "192.0.2.10", "types": ["A", "MX"], "dns_server": dns}),
            vec![
                "postmaster@example.net",
                "-c",
                "dns,email",
                "-s",
                "s1",
                "-s",
                "s2",
                "--spf-ip",
                "192.0.2.10",
                "-t",
                "A,MX",
            ],
        ),
    ] {
        let (status, answer) = server.post(&request);
        assert_eq!(status, 200, "{answer}");
        let want = cli(&[&args[..], &common].concat(), &env);
        assert_eq!(unstamped(answer), want, "{request}");
    }
    for (request, code, message) in [
        (json!({"domain": ""}), "empty", "Empty input."),
        (
            json!({"domain": "printer.test"}),
            "special_use",
            "printer.test is a special-use name (RFC 6761); it never resolves on the public internet.",
        ),
        (
            json!({"domain": "example.com", "spf_ip": "x"}),
            "usage",
            "spf_ip x isn't an IP address.",
        ),
        (
            json!({"domain": "example.com", "checks": ["web"]}),
            "usage",
            "Unknown check 'web'.",
        ),
        (
            json!({"domain": "example.com", "types": []}),
            "usage",
            "types is empty.",
        ),
    ] {
        let (status, answer) = server.post(&request);
        assert_eq!(status, 422, "{request}");
        assert_eq!(
            (&answer["error"]["code"], &answer["error"]["message"]),
            (&json!(code), &json!(message)),
            "{request}"
        );
        assert!(answer["error"]["hint"].is_string(), "{answer}");
    }
    for request in [
        json!({"domain": ["example.com"]}),
        json!({"domain": "example.com", "selector": "s1"}),
        json!({}),
        json!(["example.com"]),
    ] {
        let (status, error) = server.post(&request);
        assert_eq!(
            (status, &error["error"]["code"]),
            (400, &json!("bad_request")),
            "{request}"
        );
    }
}

#[test]
fn a_second_request_waits_for_the_first() {
    let fast = DnsStub::new();
    let slow = DnsStub::start(|a| {
        thread::sleep(Duration::from_millis(300));
        common::fixtures(a)
    });
    let server = Server::start(&["--resolver", &fast.addr()], &[]);
    let started = Instant::now();
    let ask = |dns: String| {
        let server = &server;
        move || {
            let request = json!({"domain": "example.com", "checks": ["dns"], "dns_server": dns});
            let (status, _) = server.post(&request);
            (status, started.elapsed())
        }
    };
    let (first, second) = thread::scope(|s| {
        let first = s.spawn(ask(slow.addr()));
        thread::sleep(Duration::from_millis(100));
        let second = s.spawn(ask(fast.addr()));
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!((first.0, second.0), (200, 200));
    assert!(first.1 < second.1, "{first:?} {second:?}");
}

#[test]
fn refuses_other_hosts_origins_routes_types_and_large_requests() {
    let server = Server::start(&[], &[]);
    let other = server.port.wrapping_add(1);
    for (head, status) in [
        ("GET / HTTP/1.1\r\nHost: localhost:{port}".to_owned(), 200),
        (
            "GET /?from=bookmark HTTP/1.1\r\nHost: localhost:{port}".into(),
            200,
        ),
        ("GET /api?x HTTP/1.1\r\nHost: localhost:{port}".into(), 404),
        ("GET / HTTP/1.1".into(), 403),
        ("GET / HTTP/1.1\r\nHost: evil.example".into(), 403),
        ("GET / HTTP/1.1\r\nHost: evil.example:{port}".into(), 403),
        (format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{other}"), 403),
        (
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example".into(),
            403,
        ),
        (
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: https://127.0.0.1:{port}".into(),
            403,
        ),
        (
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: null".into(),
            403,
        ),
        (
            "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1:{port}".into(),
            404,
        ),
        (
            "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0".into(),
            404,
        ),
        ("DELETE /api HTTP/1.1\r\nHost: 127.0.0.1:{port}".into(), 404),
    ] {
        assert_eq!(server.send(&head, b"").0, status, "{head}");
    }
    let (_, _, body) = server.send("GET / HTTP/1.1\r\nHost: evil.example", b"");
    assert_eq!(
        body,
        r#"{"error":{"code":"forbidden","hint":null,"message":"Only this computer's page can use domain-check ui."}}"#
    );
    let body = r#"{"domain":"printer.test"}"#;
    for kind in [
        "",
        "\r\nContent-Type: text/plain",
        "\r\nContent-Type: application/x-www-form-urlencoded",
        "\r\nContent-Type: multipart/form-data; boundary=x",
        "\r\nContent-Type: application/jsonx",
    ] {
        let head = format!(
            "POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}{kind}\r\nContent-Length: {}",
            body.len()
        );
        let (status, _, answer) = server.send(&head, body.as_bytes());
        assert_eq!(status, 415, "{kind}");
        assert_eq!(
            answer,
            r#"{"error":{"code":"unsupported_media_type","hint":null,"message":"Send the request as application/json."}}"#
        );
    }
    let head = format!(
        "POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Length: {}",
        body.len()
    );
    assert_eq!(server.send(&head, body.as_bytes()).0, 422);
    let big = json!({ "domain": "a".repeat(65 * 1024) }).to_string();
    let head = format!(
        "POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nContent-Type: application/json\r\nContent-Length: {}",
        big.len()
    );
    let (status, _, answer) = server.send(&head, big.as_bytes());
    assert_eq!(status, 413);
    assert_eq!(
        answer,
        r#"{"error":{"code":"too_large","hint":null,"message":"The request is larger than 64 KB."}}"#
    );
    let head = format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nX-Pad: {}",
        "a".repeat(17 * 1024)
    );
    assert_eq!(server.send(&head, b"").0, 413);
}

#[test]
fn refuses_repeated_headers_and_short_bodies() {
    let server = Server::start(&[], &[]);
    let body = r#"{"domain":"printer.test"}"#;
    let post = |headers: &str, length: usize| {
        let head = format!(
            "POST /api HTTP/1.1\r\n{headers}\r\nContent-Type: application/json\r\nContent-Length: {length}"
        );
        server.send(&head, body.as_bytes()).0
    };
    let local = "Host: 127.0.0.1:{port}";
    assert_eq!(post(local, body.len()), 422);
    for headers in [
        "Host: evil.example\r\nHost: 127.0.0.1:{port}",
        "Host: 127.0.0.1:{port}\r\nHost: 127.0.0.1:{port}",
        "Host: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\nOrigin: http://127.0.0.1:{port}",
        "Host: 127.0.0.1:{port}\r\nContent-Length: 0",
        "Host: 127.0.0.1:{port}\r\nContent-Type: text/plain",
    ] {
        assert_eq!(post(headers, body.len()), 400, "{headers}");
    }
    assert_eq!(post(local, body.len() + 10), 400);
    let hidden =
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nNoColon\r\nOrigin: http://evil.example";
    assert_eq!(server.send(hidden, b"").0, 400);
}

#[test]
fn refuses_malformed_headers_framing_and_request_lines() {
    let server = Server::start(&[], &[]);
    let body = r#"{"domain":"printer.test"}"#;
    let length = format!(
        "Content-Type: application/json\r\nContent-Length: {}",
        body.len()
    );
    let head = format!("POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\n{length}");
    for head in [
        format!("{head}\r\nOrigin : http://evil.example"),
        format!("{head}\r\nBad Header: value"),
        format!("{head}\r\nTransfer-Encoding: chunked"),
        format!("{head}\r\nTransfer-Encoding: identity"),
        head.replace("Length: ", "Length: +"),
        head.replace("Length: ", "Length: -"),
        head.replace(" HTTP/1.1", ""),
        head.replace("HTTP/1.1", "XYZ"),
        head.replace("POST /api", "POST  /api"),
    ] {
        assert_eq!(server.send(&head, body.as_bytes()).0, 400, "{head}");
    }
    let status = |line: &[u8], header: &[u8]| server.status(line, header);
    let post = b"POST /api HTTP/1.1".as_slice();
    // RFC 9110 §5.5: field values may carry opaque bytes 80-FF; an unknown field is ignored.
    for byte in [0x80, 0xe9, 0xff] {
        assert_eq!(status(post, &[b"X-Other: ", &[byte][..]].concat()), "422");
    }
    assert_eq!(status(post, b"\xe9: x"), "400");
    // Control bytes are neither field content nor part of a target (RFC 9110 §5.5, RFC 9112 §3).
    for header in [
        &b"X-Other: a\0b"[..],
        b"X-Other: a\rb",
        b"X-Other: \x0ca",
        b"X-Other: a\x0c",
    ] {
        assert_eq!(status(post, header), "400", "{header:?}");
    }
    assert_eq!(status(post, b"X-Other: \ta\t"), "422");
    assert_eq!(status(b"POST /api\tx HTTP/1.1", b"X-Other: a"), "400");
    assert_eq!(status(b"POST /api\xe9 HTTP/1.1", b"X-Other: a"), "400");
    let raw = b"{\"domain\":\"\xff.com\"}";
    let head = format!(
        "POST /api HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\nContent-Type: application/json\r\nContent-Length: {}",
        raw.len()
    );
    assert_eq!(server.send(&head, raw).0, 400);
}

#[test]
fn reports_a_busy_port() {
    let taken = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let out = command(&["ui", "--no-open", "--port", &port], &[])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        String::from_utf8(out.stderr).unwrap(),
        format!("✗ Port {port} is in use.\n  Use --port 0 for a free port.\n")
    );
}

/// A stand-in for xdg-open and open that writes down the address it was given.
#[cfg(unix)]
#[test]
fn opens_the_browser_unless_told_not_to() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("domain-check-browser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opened = dir.join("opened");
    for opener in ["xdg-open", "open"] {
        let script = dir.join(opener);
        let body = format!("#!/bin/sh\necho \"$1\" > '{}'\n", opened.display());
        std::fs::write(&script, body).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap());
    let start = |args: &[&str]| {
        let mut child = command(&[&["ui"], args].concat(), &[("PATH", &path)])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        thread::sleep(Duration::from_millis(500));
        child.kill().unwrap();
        child.wait().unwrap();
        line.trim_end().trim_end_matches("  (Ctrl+C to stop)")[5..].to_string()
    };
    start(&["--no-open"]);
    assert_eq!(std::fs::read_to_string(&opened).ok(), None);
    let url = start(&[]);
    assert_eq!(
        std::fs::read_to_string(&opened).unwrap(),
        format!("{url}\n")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
