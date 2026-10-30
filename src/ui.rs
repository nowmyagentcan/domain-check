//! The local page on 127.0.0.1: `GET /` serves it and `POST /api` checks a domain for it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::Error;
use crate::mcp::{self, CheckDomain, Defaults, arguments, failure};

const PAGE: &str = include_str!("ui.html");
/// The most a request may send in headers.
const HEAD_LIMIT: u64 = 16 * 1024;
/// The most a request may send in its body.
const BODY_LIMIT: u64 = 64 * 1024;
/// The page reaches nothing but its own server.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'";
const JSON: &str = "application/json";

type Response = (u16, &'static str, String);

/// Serves on 127.0.0.1:`port` (0 picks a free port) until the process is stopped, and opens
/// the page in the default browser when `open` is set.
pub fn serve(port: u16, open: bool, defaults: Defaults) -> Result<(), Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).map_err(|e| {
        let message = match e.kind() {
            io::ErrorKind::AddrInUse => format!("Port {port} is in use."),
            _ => format!("Couldn't start the page on port {port}: {e}."),
        };
        Error::new("runtime", message, "Use --port 0 for a free port.")
    })?;
    let port = listener.local_addr().map_or(port, |a| a.port());
    let url = format!("http://127.0.0.1:{port}");
    // With stdout closed nobody learns the address, so end quietly as other commands do.
    match writeln!(io::stdout(), "Open {url}  (Ctrl+C to stop)") {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
        Err(e) => {
            let message = format!("Couldn't write output: {e}.");
            return Err(Error::new("runtime", message, "Try again."));
        }
        Ok(()) => {}
    }
    if open {
        browse(url);
    }
    let defaults = Arc::new(defaults);
    for stream in listener.incoming().flatten() {
        let defaults = Arc::clone(&defaults);
        // A client that hangs up or stalls loses only its own connection.
        thread::spawn(move || handle(&stream, port, &defaults));
    }
    Ok(())
}

/// Asks the OS to open `url`; when it can't, the printed address is enough.
fn browse(url: String) {
    let mut command = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else if cfg!(target_os = "macos") {
        Command::new("open")
    } else {
        Command::new("xdg-open")
    };
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Some openers wait for the browser to close, so they run beside the server.
    thread::spawn(move || command.status());
}

/// One request, one response, then the connection closes.
fn handle(stream: &TcpStream, port: u16, defaults: &Defaults) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let reader = &mut BufReader::new(stream.take(HEAD_LIMIT));
    let (status, kind, body) = respond(reader, port, defaults)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        _ => "Unprocessable Content",
    };
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: {CSP}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.shutdown(Shutdown::Write)?;
    // Read what the client still sends, so closing doesn't reset the connection before it
    // has read the answer.
    io::copy(&mut stream.take(1 << 20), &mut io::sink()).map(drop)
}

fn respond(
    reader: &mut BufReader<io::Take<&TcpStream>>,
    port: u16,
    defaults: &Defaults,
) -> io::Result<Response> {
    // Lines are bytes: a header value may carry opaque ones (RFC 9110 §5.5).
    let (mut request, mut line) = (Vec::new(), Vec::new());
    reader.read_until(b'\n', &mut request)?;
    let (mut host, mut origin, mut length, mut kind) = (None, None, None, None);
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            return Ok(match reader.get_ref().limit() {
                0 => refuse(
                    413,
                    "too_large",
                    "The request headers are larger than 16 KB.",
                ),
                _ => refuse(400, "bad_request", "The request ended early."),
            });
        }
        if line.iter().all(|b| b"\r\n".contains(b)) {
            break;
        }
        let token = |n: &[u8]| {
            !n.is_empty()
                && n.iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
        };
        // Field values are visible bytes, spaces and tabs (RFC 9110 §5.5), checked before the
        // spaces and tabs around them are trimmed, so no other control hides at an edge.
        let content = |v: &[u8]| v.iter().all(|&b| b == b'\t' || b >= b' ' && b != 0x7f);
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line
            .iter()
            .position(|&b| b == b':')
            .filter(|&i| token(&line[..i]) && content(&line[i + 1..]))
        else {
            return Ok(refuse(400, "bad_request", "Can't read a request header."));
        };
        let field = match line[..colon].to_ascii_lowercase().as_slice() {
            b"host" => &mut host,
            b"origin" => &mut origin,
            b"content-length" => &mut length,
            b"content-type" => &mut kind,
            // Bodies come only with a Content-Length; chunked ones aren't read.
            b"transfer-encoding" => {
                let message = "Send the body with a Content-Length.";
                return Ok(refuse(400, "bad_request", message));
            }
            _ => continue,
        };
        let value = String::from_utf8_lossy(line[colon + 1..].trim_ascii());
        // A second value could disagree with the first one checked (RFC 9112 §3.2, §6.3).
        if field.replace(value.into_owned()).is_some() {
            return Ok(refuse(400, "bad_request", "A request header is repeated."));
        }
    }
    // RFC 9112 §3: the request line is visible ASCII parted by spaces.
    let request = std::str::from_utf8(&request)
        .map(|r| r.trim_end_matches(['\r', '\n']))
        .ok()
        .filter(|r| r.bytes().all(|b| b == b' ' || b.is_ascii_graphic()));
    let mut parts = request.unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some("HTTP/1.1" | "HTTP/1.0"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Ok(refuse(400, "bad_request", "Can't read the request line."));
    };
    let local = |scheme: &str, value: &str| {
        ["127.0.0.1", "localhost"]
            .iter()
            .any(|h| value.eq_ignore_ascii_case(&format!("{scheme}{h}:{port}")))
    };
    if !host.is_some_and(|h| local("", &h)) || origin.is_some_and(|o| !local("http://", &o)) {
        let message = "Only this computer's page can use domain-check ui.";
        return Ok(refuse(403, "forbidden", message));
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    match (method, path) {
        ("GET", "/") => Ok((200, "text/html; charset=utf-8", PAGE.into())),
        ("POST", "/api") => {
            // Only a JSON body: its content type needs a CORS preflight, which no other site
            // gets an answer to.
            let media = kind
                .as_deref()
                .map(|k| k.split(';').next().unwrap_or(k).trim());
            if !media.is_some_and(|m| m.eq_ignore_ascii_case(JSON)) {
                let message = "Send the request as application/json.";
                return Ok(refuse(415, "unsupported_media_type", message));
            }
            // Digits only: Rust would also read a leading `+`.
            let digits = |l: &String| l.bytes().all(|b| b.is_ascii_digit());
            let Some(length) = length.map_or(Some(0), |l| l.parse().ok().filter(|_| digits(&l)))
            else {
                return Ok(refuse(400, "bad_request", "Can't read the request length."));
            };
            if length > BODY_LIMIT {
                return Ok(refuse(
                    413,
                    "too_large",
                    "The request is larger than 64 KB.",
                ));
            }
            let buffered = reader.buffer().len() as u64;
            reader.get_mut().set_limit(length.saturating_sub(buffered));
            let mut body = Vec::new();
            reader.take(length).read_to_end(&mut body)?;
            if (body.len() as u64) < length {
                return Ok(refuse(400, "bad_request", "The request ended early."));
            }
            Ok(match answer(&body, defaults) {
                Ok(answer) => (200, JSON, answer),
                Err(e) if e.code == "bad_request" => (400, JSON, failure(&e)),
                Err(e) => (422, JSON, failure(&e)),
            })
        }
        _ => Ok(refuse(404, "not_found", "There's nothing here.")),
    }
}

/// The CLI's `--json` object for the request, one check at a time.
fn answer(body: &[u8], defaults: &Defaults) -> Result<String, Error> {
    let json = serde_json::from_slice(body).map_err(|e| {
        let message = format!("Can't read the request: {e}.");
        Error::new(
            "bad_request",
            message,
            "Send the check_domain arguments as JSON.",
        )
    })?;
    let request = arguments::<CheckDomain>(json)?;
    let _one = mcp::ONE.lock().unwrap_or_else(|e| e.into_inner());
    let output = request.run(defaults)?;
    serde_json::to_string(&output).map_err(|e| {
        Error::new(
            "runtime",
            format!("Couldn't write JSON: {e}."),
            "Try again.",
        )
    })
}

/// A refusal with no hint: the page's own requests never get one.
fn refuse(status: u16, code: &'static str, message: &str) -> Response {
    let error = Error {
        code,
        message: message.into(),
        hint: None,
    };
    (status, JSON, failure(&error))
}
