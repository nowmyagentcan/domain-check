//! The domains' web servers, played on 127.0.0.1: plain HTTP on one port and HTTPS on another,
//! with certificates made at test time under one test root and picked by the name the client
//! asks for (SNI). Every connection and request is counted.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_RSA_SHA256, PublicKeyData, SignatureAlgorithm,
};
use rustls::StreamOwned;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{Acceptor, ServerConfig};
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

/// The answer to `path` on `host`.
pub fn route(_host: &str, _path: &str, _https: bool) -> Reply {
    Reply::new(200, &[("Content-Type", "text/plain")], "ok\n")
}

pub struct Web {
    pub http: u16,
    pub https: u16,
    /// The PEM file of the test root, for `--ca-file`.
    pub ca: String,
    connections: Arc<Mutex<usize>>,
    hits: Arc<Mutex<Vec<Hit>>>,
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
        self.hits.lock().unwrap().clone()
    }
}

fn serve_tls(mut stream: TcpStream, hits: &Mutex<Vec<Hit>>) {
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
fn serve(stream: &mut (impl Read + Write), https: bool, hits: &Mutex<Vec<Hit>>) {
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
    hits.lock().unwrap().push(Hit {
        https,
        host: host.clone(),
        path: path.to_string(),
    });
    let reply = route(&host, path, https);
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
    let now = OffsetDateTime::now_utc();
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
