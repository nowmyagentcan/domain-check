//! The domains' web servers, played on 127.0.0.1: plain HTTP on one port and HTTPS on another,
//! with certificates made at test time under one test root and picked by the name the client
//! asks for (SNI). Every connection and request is counted.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Instant;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, PublicKeyData, SignatureAlgorithm,
};
use rustls::StreamOwned;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{Acceptor, ServerConfig};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use super::DnsStub;

/// One request as the mock received it.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub https: bool,
    pub host: String,
    pub path: String,
}

/// What the mock answers.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    /// `None`: a body that never ends.
    pub body: Option<Vec<u8>>,
}

impl Reply {
    pub fn new(status: u16, headers: &[(&'static str, &str)], body: &str) -> Reply {
        Reply {
            status,
            headers: headers.iter().map(|&(k, v)| (k, v.to_string())).collect(),
            body: Some(body.as_bytes().to_vec()),
        }
    }
}

/// The headers every https site sends unless its route says otherwise.
const GOOD: [(&str, &str); 7] = [
    ("Content-Type", "text/html"),
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    ),
    (
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
];

/// A 200 with [`GOOD`]'s headers, `changed` replacing or adding some.
fn good_with(changed: &[(&'static str, &str)]) -> Reply {
    let kept = GOOD
        .iter()
        .filter(|(k, _)| !changed.iter().any(|(c, _)| c == k));
    let headers: Vec<_> = kept.chain(changed).copied().collect();
    Reply::new(
        200, &headers, "ok
",
    )
}

/// The MTA-STS policy of `mta-sts.<domain>`, by the domain's first label.
fn sts_policy(host: &str) -> Reply {
    let text = |body: &str| Reply::new(200, &[("Content-Type", "text/plain")], body);
    match host.split('.').nth(1).unwrap_or_default() {
        "stsmx" => text(
            "version: STSv1\nmode: testing\nmx: mx1.example.net\nmx: *.mail.example.net\nmax_age: 86400\n",
        ),
        "stsredirect" => Reply::new(
            301,
            &[(
                "Location",
                "https://mta-sts.sts.example.net/.well-known/mta-sts.txt",
            )],
            "",
        ),
        "sts404" => Reply::new(404, &[], "not found\n"),
        "stsbig" => text(&format!("version: STSv1\n{}", "#".repeat(70 * 1024))),
        "stssyntax" => text("version: STSv2\nmode: block\nmax_age: forever\n"),
        "stsdup" => {
            text("version: STSv1\nmode: enforce\nmode: none\nmx: mx1.example.net\nmax_age: 86400\n")
        }
        _ => text("version: STSv1\r\nmode: enforce\r\nmx: mx1.example.net\r\nmax_age: 604800\r\n"),
    }
}

/// An RFC 3339 time `n` days from now.
pub fn days(n: i64) -> String {
    (OffsetDateTime::now_utc() + Duration::days(n))
        .format(&Rfc3339)
        .unwrap()
}

fn rdap_json(status: u16, value: Value) -> Reply {
    let kind = [("Content-Type", "application/rdap+json")];
    Reply::new(status, &kind, &value.to_string())
}

/// A bootstrap file naming each TLD's service URLs.
fn bootstrap(services: Value) -> Reply {
    let file = json!({ "version": "1.0", "publication": "2026-10-30T12:00:00Z",
        "description": "test bootstrap", "services": services });
    Reply::new(
        200,
        &[("Content-Type", "application/json")],
        &file.to_string(),
    )
}

/// A registry's domain object: expiry `expires` days from now, the statuses and nameservers,
/// and the registrar link when `related`.
fn domain(name: &str, expires: Option<i64>, status: &[&str], ns: &[&str], related: bool) -> Value {
    let mut events = vec![
        json!({ "eventAction": "registration", "eventDate": days(-3650) }),
        json!({ "eventAction": "last changed", "eventDate": days(-30) }),
    ];
    if let Some(n) = expires {
        events.push(json!({ "eventAction": "expiration", "eventDate": days(n) }));
    }
    let mut links = vec![
        json!({ "rel": "self", "href": format!("https://rdap.example.net/rdap/domain/{name}") }),
    ];
    if related {
        links.push(json!({ "rel": "related", "type": "application/rdap+json",
            "href": format!("https://registrar.example.net/domain/{name}") }));
    }
    let servers: Vec<Value> = ns.iter().map(|n| json!({ "ldhName": n })).collect();
    json!({
        "objectClassName": "domain", "ldhName": name.to_uppercase(),
        "events": events, "status": status, "nameservers": servers, "links": links,
        "secureDNS": { "delegationSigned": false },
        "entities": [{ "objectClassName": "entity", "roles": ["registrar"],
            "publicIds": [{ "type": "IANA Registrar ID", "identifier": "9999" }],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]] }],
        "notices": [{ "title": "Terms of Use", "links": [{ "rel": "terms-of-service", "href": "https://rdap.example.net/terms" }] }]
    })
}

/// The registry's answer for `name`, asked `nth` times before.
fn registry(name: &str, nth: usize) -> Reply {
    let lock = [
        "client delete prohibited",
        "client transfer prohibited",
        "client update prohibited",
    ];
    let ns = ["NS1.EXAMPLE.NET.", "ns2.example.net"];
    let record = |expires, status: &[&str], related| {
        rdap_json(200, domain(name, expires, status, &ns, related))
    };
    match name {
        "example.com" => record(Some(300), &lock, true),
        "example.org" | "single.example.org" => record(Some(300), &lock[1..2], false),
        "wild.example.org" => Reply::new(404, &[], ""),
        "limited.example.com" => Reply::new(429, &[("Retry-After", "42")], ""),
        "busy.example.com" => Reply::new(503, &[], ""),
        "flaky.example.com" if nth == 0 => Reply::new(502, &[], ""),
        "flaky.example.com" => record(Some(300), &lock, false),
        "html.example.com" => Reply::new(200, &[("Content-Type", "text/html")], "<html>hi</html>"),
        "bad.example.com" => Reply::new(400, &[], ""),
        "moved.example.com" => Reply::new(301, &[("Location", "/rdap/domain/example.com")], ""),
        "away.example.com" => Reply::new(302, &[("Location", "http://rdap.example.org/x")], ""),
        "lapsed.example.com" => record(Some(-5), &[], false),
        "soon.example.com" => record(Some(10), &lock[1..2], false),
        "held.example.com" => record(
            Some(300),
            &["client hold", "client transfer prohibited"],
            false,
        ),
        "deleting.example.com" => record(Some(300), &["pending delete"], true),
        "noexpiry.example.com" => record(None, &lock, true),
        "nolock.uk" => record(Some(300), &[], false),
        "wrongobj.example.com" => rdap_json(
            200,
            domain("someone-else.example.net", Some(300), &[], &ns, false),
        ),
        "emptyobj.example.com" => rdap_json(200, json!({})),
        _ => rdap_json(404, json!({ "errorCode": 404, "title": "Not Found" })),
    }
}

/// The registrar's answer for `name`.
fn registrar(name: &str) -> Reply {
    let dates = |expires| {
        let events = json!([{ "eventAction": "expiration", "eventDate": days(expires) },
            { "eventAction": "last changed", "eventDate": days(-1) }]);
        rdap_json(
            200,
            json!({ "objectClassName": "domain", "ldhName": name, "events": events }),
        )
    };
    match name {
        "example.com" => dates(400),
        "noexpiry.example.com" => dates(200),
        _ => rdap_json(404, json!({ "errorCode": 404 })),
    }
}

/// RDAP: bootstrap files over plain http on any host, the registry `rdap.example.net` and the
/// registrar `registrar.example.net` over https. `/fallback/dns.json` first names a server that
/// hangs up, then the real one.
fn rdap(site: &str, path: &str, https: bool, nth: usize) -> Option<Reply> {
    let services = json!([
        [["com"], ["https://rdap.example.net/rdap"]],
        [
            ["org", "uk"],
            ["http://rdap.example.org/", "https://rdap.example.net/rdap/"]
        ],
        [["net"], ["https://rdap.example.net/"]],
    ]);
    let name = path.rsplit('/').next().unwrap_or_default();
    Some(match (site, https, path) {
        (_, false, "/dns.json") => bootstrap(services),
        (_, false, "/fallback/dns.json") if nth == 0 => {
            bootstrap(json!([[["com"], ["https://hangup.example.com/"]]]))
        }
        (_, false, "/fallback/dns.json") => bootstrap(services),
        ("rdap", true, _) => registry(name, nth),
        ("registrar", true, _) => registrar(name),
        _ => return None,
    })
}

/// The answer to `path` on `host`, asked `nth` times before: the first label of the host picks
/// the site. Status 0 sends bytes that aren't HTTP.
pub fn route(host: &str, path: &str, https: bool, nth: usize) -> Reply {
    let to = |status, location: &str| Reply::new(status, &[("Location", location)], "");
    let site = host.split('.').next().unwrap_or_default();
    if let Some(reply) = rdap(site, path, https, nth) {
        return reply;
    }
    match (site, https, path) {
        ("web", false, _) => Reply::new(
            301,
            &[
                ("Location", "https://web.example.com/"),
                ("Strict-Transport-Security", "max-age=63072000"),
            ],
            "",
        ),
        ("relative", false, "/") => to(302, "/next"),
        ("relative", false, "/next") => to(301, "https://relative.example.com/"),
        ("schemerel", false, _) => to(301, "//web.example.com/x"),
        ("circle", false, "/") => to(301, "/a"),
        ("circle", false, "/a") => to(301, "/b"),
        ("circle", false, _) => to(301, "/a"),
        ("circle", true, _) => to(302, "https://circle.example.com/"),
        ("far", _, p) => {
            let n: u32 = p.trim_start_matches('/').parse().unwrap_or(0);
            to(301, &format!("/{}", n + 1))
        }
        ("endless", false, _) => to(301, "https://endless.example.com/"),
        ("endless", true, _) => Reply {
            body: None,
            ..Reply::new(200, &[("Content-Type", "text/plain")], "")
        },
        ("status", true, "/") => to(301, "/missing"),
        ("status", true, _) => Reply::new(404, &GOOD, "not found\n"),
        ("garbage", true, _) => Reply::new(0, &[], ""),
        ("mta-sts", true, "/.well-known/mta-sts.txt") => sts_policy(host),
        ("sts", true, "/logo.svg") => Reply::new(
            200,
            &[("Content-Type", "image/svg+xml")],
            "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.2\" baseProfile=\"tiny-ps\"/>",
        ),
        ("sts", true, "/vmc.pem") => Reply::new(
            200,
            &[("Content-Type", "application/x-pem-file")],
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ),
        ("logo", true, "/l.svg") => Reply::new(
            200,
            &[("Content-Type", "image/svg+xml")],
            "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.2\"/>",
        ),
        ("stsmx", true, "/missing.svg") => Reply::new(404, &GOOD, ""),
        ("stsmx", true, "/vmc.txt") => Reply::new(200, &[], "not a certificate\n"),
        ("headers", true, _) => Reply::new(
            200,
            &[
                ("Strict-Transport-Security", "max-age=300"),
                (
                    "Content-Security-Policy",
                    "script-src 'self' 'unsafe-inline'",
                ),
                ("X-XSS-Protection", "1; mode=block"),
                ("Expect-CT", "max-age=0"),
                ("Server", "nginx/1.25.3"),
                ("X-Powered-By", "PHP/8.3"),
            ],
            "ok\n",
        ),
        ("bare", true, _) => Reply::new(200, &[("Content-Type", "text/plain")], "ok\n"),
        ("offhost", false, _) => to(301, "https://selfsigned.example.com/"),
        ("downgrade", false, "/") => to(301, "https://downgrade.example.com/good"),
        ("downgrade", true, "/") => to(302, "http://downgrade.example.com/plain"),
        ("tabcsp", true, _) => good_with(&[(
            "Content-Security-Policy",
            "default-src	'unsafe-inline'; frame-ancestors	'none'",
        )]),
        ("badframe", true, _) => good_with(&[
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "ALLOWALL"),
        ]),
        ("hstsdup", true, _) => Reply::new(
            200,
            &[("Strict-Transport-Security", "max-age=63072000; max-age=0")],
            "ok\n",
        ),
        (_, true, _) => Reply::new(200, &GOOD, "ok\n"),
        _ => Reply::new(200, &[("Content-Type", "text/plain")], "ok\n"),
    }
}

pub struct Web {
    pub http: u16,
    pub https: u16,
    /// The PEM file of the test root, for `--ca-file`.
    pub ca: String,
    connections: Arc<Mutex<usize>>,
    hits: Arc<Mutex<Vec<(Hit, Instant)>>>,
}

impl Web {
    pub fn new() -> Web {
        let pki = pki();
        let connections = Arc::new(Mutex::new(0));
        let hits = Arc::new(Mutex::new(Vec::new()));
        let listen = |https: bool| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let (connections, hits) = (Arc::clone(&connections), Arc::clone(&hits));
            thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    *connections.lock().unwrap() += 1;
                    let hits = Arc::clone(&hits);
                    thread::spawn(move || match https {
                        true => serve_tls(stream, &hits),
                        false => serve(&mut stream, false, &hits),
                    });
                }
            });
            port
        };
        Web {
            http: listen(false),
            https: listen(true),
            ca: pki.ca.to_str().unwrap().to_string(),
            connections,
            hits,
        }
    }

    /// `DOMAIN_CHECK_LOOPBACK_PORTS` for the stub and this mock.
    pub fn ports(&self, dns: &DnsStub) -> String {
        format!("{},http={},https={}", dns.ports(), self.http, self.https)
    }

    /// The TCP connections accepted so far, on either port.
    pub fn connections(&self) -> usize {
        *self.connections.lock().unwrap()
    }

    pub fn hits(&self) -> Vec<Hit> {
        self.timed().into_iter().map(|(hit, _)| hit).collect()
    }

    /// Each request and when it arrived.
    pub fn timed(&self) -> Vec<(Hit, Instant)> {
        self.hits.lock().unwrap().clone()
    }
}

fn serve_tls(mut stream: TcpStream, hits: &Mutex<Vec<(Hit, Instant)>>) {
    let mut acceptor = Acceptor::default();
    let accepted = loop {
        match acceptor.read_tls(&mut stream) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => break accepted,
            Ok(None) => {}
            Err(_) => return,
        }
    };
    let hello = accepted.client_hello();
    let sni = hello.server_name().unwrap_or_default().to_string();
    match sni.split('.').next() {
        // A fatal protocol_version alert, as a server limited to TLS 1.1 sends.
        Some("old") => {
            let _ = stream.write_all(&[0x15, 3, 1, 0, 2, 2, 70]);
            return;
        }
        Some("hangup") => return,
        _ => {}
    }
    let config = pki().config(&sni);
    let Ok(conn) = accepted.into_connection(config) else {
        return;
    };
    serve(&mut StreamOwned::new(conn, stream), true, hits);
}

/// Reads one request head and answers it; the connection closes after.
fn serve(stream: &mut (impl Read + Write), https: bool, hits: &Mutex<Vec<(Hit, Instant)>>) {
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) if head.len() < 16384 => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/");
    let host = lines
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("host").then(|| value.trim())
        })
        .unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h).to_string();
    let hit = Hit {
        https,
        host: host.clone(),
        path: path.to_string(),
    };
    let nth = {
        let mut hits = hits.lock().unwrap();
        let nth = hits.iter().filter(|(h, _)| *h == hit).count();
        hits.push((hit, Instant::now()));
        nth
    };
    let reply = route(&host, path, https, nth);
    if reply.status == 0 {
        let _ = stream.write_all(b"this is not http\r\n\r\n");
        return;
    }
    let mut out = format!("HTTP/1.1 {} Mock\r\nConnection: close\r\n", reply.status);
    for (name, value) in &reply.headers {
        out += &format!("{name}: {value}\r\n");
    }
    match reply.body {
        Some(body) => {
            out += &format!("Content-Length: {}\r\n\r\n", body.len());
            let _ = stream.write_all(&[out.as_bytes(), &body].concat());
        }
        None => {
            out += "\r\n";
            let mut sent = stream.write_all(out.as_bytes());
            while sent.is_ok() {
                sent = stream.write_all(&[b'x'; 1024]);
            }
        }
    }
    let _ = stream.flush();
}

/// The test root and intermediate, and each name's server configuration once made.
struct Pki {
    root: (CertificateParams, KeyPair),
    intermediate: (CertificateParams, KeyPair),
    intermediate_der: CertificateDer<'static>,
    ca: PathBuf,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn params(names: &[&str], cn: &str, days: (i64, i64), ca: bool) -> CertificateParams {
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let mut p = CertificateParams::new(names).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    // Half a day back: a check that reads the clock just before the certificate is made
    // still counts the same whole days as one just after.
    let now = OffsetDateTime::now_utc() - Duration::hours(12);
    p.not_before = now + Duration::days(days.0);
    p.not_after = now + Duration::days(days.1);
    match ca {
        true => {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        }
        false => {
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
    }
    p
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let root_key = KeyPair::generate().unwrap();
        let root = params(&[], "Test Root", (-1, 3650), true);
        let root_cert = root.self_signed(&root_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let intermediate = params(&[], "Test Intermediate", (-1, 1825), true);
        let issuer = Issuer::from_params(&root, &root_key);
        let intermediate_der = intermediate.signed_by(&key, &issuer).unwrap().der().clone();
        let dir = std::env::temp_dir().join(format!("domain-check-tests-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ca = dir.join("root.pem");
        std::fs::write(&ca, root_cert.pem()).unwrap();
        Pki {
            root: (root, root_key),
            intermediate: (intermediate, key),
            intermediate_der,
            ca,
            configs: Mutex::new(HashMap::new()),
        }
    })
}

/// An RSA public key without its private half: only a certificate can carry it.
struct Rsa(Vec<u8>);

impl PublicKeyData for Rsa {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_RSA_SHA256
    }
}

impl Pki {
    /// The server configuration for `sni`: the first label says which certificate it gets.
    fn config(&self, sni: &str) -> Arc<ServerConfig> {
        let mut configs = self.configs.lock().unwrap();
        let made = configs
            .entry(sni.to_string())
            .or_insert_with(|| self.make(sni));
        Arc::clone(made)
    }

    fn make(&self, sni: &str) -> Arc<ServerConfig> {
        let label = sni.split('.').next().unwrap_or_default();
        let days = match label {
            "expired" => (-100, -10),
            "future" => (5, 95),
            "expiring" => (-80, 10),
            "lifetime" => (-1, 299),
            _ => (-1, 89),
        };
        let names = match (label, sni) {
            ("wrongname", _) | (_, "mta-sts.stsname.example.net") => ["other.example.net"],
            _ => [sni],
        };
        let leaf = params(&names, names[0], days, false);
        let key = KeyPair::generate().unwrap();
        let (inter, inter_key) = &self.intermediate;
        let signed = |issuer| leaf.signed_by(&key, &issuer).unwrap().der().clone();
        let chain = match label {
            "selfsigned" => vec![leaf.self_signed(&key).unwrap().der().clone()],
            "leafonly" => vec![signed(Issuer::from_params(inter, inter_key))],
            // An intermediate with an RSA 1024 key, which can't sign: the chain doesn't verify.
            "weak" => {
                let weak = params(&[], "Weak Intermediate", (-1, 365), true);
                let (root, root_key) = &self.root;
                let rsa = Rsa(super::rsa_public_key(1024));
                let weak_der = weak.signed_by(&rsa, &Issuer::from_params(root, root_key));
                let other = KeyPair::generate().unwrap();
                let leaf_der = signed(Issuer::from_params(&weak, &other));
                vec![leaf_der, weak_der.unwrap().der().clone()]
            }
            _ => vec![
                signed(Issuer::from_params(inter, inter_key)),
                self.intermediate_der.clone(),
            ],
        };
        let versions: &[_] = match label {
            "tls12" => &[&rustls::version::TLS12],
            _ => &[&rustls::version::TLS13, &rustls::version::TLS12],
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}
