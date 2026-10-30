//! The `tls` section: one handshake with port 443 of the domain's first address, recording
//! the certificates the server presents and what it negotiated. No data is sent.

use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use x509_parser::extensions::GeneralName;
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::oid_registry::{OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521};
use x509_parser::public_key::PublicKey;

use crate::check::{Cx, Facts};
use crate::net::{self, Failed, Net};
use crate::report::{Check, Finding, Section, Severity, Status};
use crate::sections::email::dkim;

const HANDSHAKE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Tls {
    pub address: Option<String>,
    pub port: u16,
    /// `TLSv1.3` or `TLSv1.2`; `None` when no handshake finished.
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub alpn: Option<String>,
    /// The certificates as the server presented them, its own first.
    pub chain: Vec<Cert>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Cert {
    pub subject: String,
    pub issuer: String,
    /// Lower-case hex.
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    /// DNS and IP subject alternative names.
    pub sans: Vec<String>,
    /// `RSA 2048`, `EC P-256`, `Ed25519`, …
    pub key: String,
    pub signature: String,
    pub self_signed: bool,
    pub ca: bool,
}

fn text_time(unix: i64) -> String {
    let t = OffsetDateTime::from_unix_timestamp(unix).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    t.format(&Rfc3339).unwrap_or_default()
}

/// A certificate's fields; `None` when it isn't DER X.509.
pub fn parse(der: &[u8]) -> Option<Cert> {
    let (_, x) = x509_parser::parse_x509_certificate(der).ok()?;
    let sans = match x.subject_alternative_name() {
        Ok(Some(ext)) => ext.value.general_names.iter().filter_map(san).collect(),
        _ => Vec::new(),
    };
    let spki = x.public_key();
    let key = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            format!("RSA {}", dkim::bits(rsa.modulus).unwrap_or_default())
        }
        Ok(PublicKey::EC(_)) => {
            let curve = spki.algorithm.parameters.as_ref();
            let curve = curve.and_then(|p| p.as_oid().ok());
            match curve {
                Some(c) if c == OID_EC_P256 => "EC P-256".into(),
                Some(c) if c == OID_NIST_EC_P384 => "EC P-384".into(),
                Some(c) if c == OID_NIST_EC_P521 => "EC P-521".into(),
                Some(c) => format!("EC {c}"),
                None => "EC".into(),
            }
        }
        _ => match oid2sn(&spki.algorithm.algorithm, oid_registry()) {
            Ok("ed25519") => "Ed25519".into(),
            Ok(name) => name.to_string(),
            Err(_) => spki.algorithm.algorithm.to_id_string(),
        },
    };
    let alg = &x.signature_algorithm.algorithm;
    let signature = oid2sn(alg, oid_registry()).map_or(alg.to_id_string(), String::from);
    let validity = x.validity();
    Some(Cert {
        subject: x.subject().to_string(),
        issuer: x.issuer().to_string(),
        serial: x.serial.to_str_radix(16),
        not_before: text_time(validity.not_before.timestamp()),
        not_after: text_time(validity.not_after.timestamp()),
        sans,
        key,
        signature,
        self_signed: x.subject().as_raw() == x.issuer().as_raw(),
        ca: x.is_ca(),
    })
}

fn san(name: &GeneralName) -> Option<String> {
    match name {
        GeneralName::DNSName(dns) => Some(dns.to_string()),
        GeneralName::IPAddress(b) => match b.len() {
            4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
            16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
            _ => None,
        },
        _ => None,
    }
}

/// The chain as presented, and the OS verifier's verdict on it.
type Seen = (Vec<CertificateDer<'static>>, Result<(), rustls::Error>);

/// The OS verifier's verdict on the presented chain, kept while the handshake goes on, so the
/// chain of an expired or untrusted certificate can still be reported.
#[derive(Debug)]
struct Recorder {
    inner: Arc<rustls_platform_verifier::Verifier>,
    seen: Mutex<Option<Seen>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verdict = self
            .inner
            .verify_server_cert(end_entity, intermediates, name, ocsp, now);
        let chain = std::iter::once(end_entity).chain(intermediates);
        let chain = chain.map(|c| c.clone().into_owned()).collect();
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some((chain, verdict.map(|_| ())));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Tls, severity, code, message, hint)
}

/// The `private_address` finding for a check that didn't connect.
pub fn private(check: Check, host: &str, address: IpAddr) -> Finding {
    let message = format!(
        "{host} resolves to {address}, a private address, so the {} check didn't connect to it.",
        check.key()
    );
    let hint = "Add --allow-private (or the page option) to check an internal host.";
    Finding::new(check, Severity::Warning, "private_address", message, hint)
}

/// Why the handshake failed, in words; `true` when the server speaks only old TLS versions.
fn handshake_error(e: &io::Error) -> (String, bool) {
    use rustls::{AlertDescription, PeerIncompatible};
    let tls = e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>());
    match tls {
        Some(
            rustls::Error::PeerIncompatible(PeerIncompatible::ServerDoesNotSupportTls12Or13)
            | rustls::Error::AlertReceived(AlertDescription::ProtocolVersion),
        ) => (String::new(), true),
        Some(rustls::Error::AlertReceived(alert)) => {
            (format!("the server refused it ({alert:?})"), false)
        }
        Some(rustls::Error::InvalidMessage(_)) => ("the server's answer isn't TLS".into(), false),
        Some(e) => (e.to_string(), false),
        None => match e.kind() {
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                ("the server closed the connection".into(), false)
            }
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
                ("no answer within 10 s".into(), false)
            }
            _ => (e.to_string(), false),
        },
    }
}

pub fn run(cx: &Cx, facts: &Facts) -> (Section<Tls>, Vec<Finding>) {
    let d = cx.domain.as_str();
    let ips = match facts.web_addresses(d) {
        Ok(ips) => ips,
        Err((status, why)) => return (Section::not(status, why), Vec::new()),
    };
    let net = &cx.net;
    let allowed: Vec<_> = ips.iter().copied().filter(|&ip| net.allowed(ip)).collect();
    if allowed.is_empty() {
        let why = format!("{d} resolves to {}, a private address.", ips[0]);
        let found = vec![private(Check::Tls, d, ips[0])];
        return (Section::not(Status::Skipped, why), found);
    }
    let mut failures = Vec::new();
    for ip in allowed {
        match connect(net, ip) {
            Ok(sock) => return handshake(net, d, ip, sock),
            Err(why) => failures.push((ip, why)),
        }
    }
    let refused = failures.iter().find(|(_, f)| f == "connection refused");
    if let Some((ip, _)) = refused {
        let message = format!("Nothing accepts connections on port 443 at {ip}.");
        let hint = "If the site should serve HTTPS, check the web server and firewall.";
        let tls = Tls {
            address: Some(ip.to_string()),
            port: 443,
            ..Tls::default()
        };
        let found = vec![finding(Severity::Warning, "https_refused", message, hint)];
        return (Section::ok(tls), found);
    }
    let (ip, why) = &failures[0];
    let reason = format!("Couldn't connect to {ip} on port 443: {why}.");
    (Section::not(Status::Unavailable, reason), Vec::new())
}

fn connect(net: &Net, ip: IpAddr) -> Result<TcpStream, String> {
    let to = net.ports.swap(SocketAddr::new(ip, 443));
    let start = Instant::now();
    let got = TcpStream::connect_timeout(&to, net::CONNECT);
    let got = got.map_err(|e| match net::Failed::from_io(&e) {
        Failed::Connect(why) => why,
        f => f.to_string(),
    });
    if net.debug {
        let outcome = got
            .as_ref()
            .map_or_else(Clone::clone, |_| "connected".into());
        let ms = start.elapsed().as_millis();
        net::debug(&format!("tls connect {to} {outcome} {ms} ms"));
    }
    got
}

fn handshake(net: &Net, d: &str, ip: IpAddr, mut sock: TcpStream) -> (Section<Tls>, Vec<Finding>) {
    let mut tls = Tls {
        address: Some(ip.to_string()),
        port: 443,
        ..Tls::default()
    };
    let mut found = Vec::new();
    let inner = match net.verifier() {
        Ok(v) => v,
        Err(why) => {
            let reason = format!("Couldn't load this computer's trusted certificates: {why}.");
            return (Section::not(Status::Unavailable, reason), found);
        }
    };
    let recorder = Arc::new(Recorder {
        inner,
        seen: Mutex::new(None),
    });
    let config = ClientConfig::builder_with_provider(net::provider())
        .with_safe_default_protocol_versions()
        .map(|b| {
            b.dangerous()
                .with_custom_certificate_verifier(recorder.clone())
                .with_no_client_auth()
        });
    let (Ok(mut config), Ok(name)) = (config, ServerName::try_from(d.to_string())) else {
        let reason = "Couldn't set up TLS for this name.";
        return (Section::not(Status::Unavailable, reason), found);
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let Ok(mut conn) = ClientConnection::new(Arc::new(config), name) else {
        let reason = "Couldn't set up TLS for this name.";
        return (Section::not(Status::Unavailable, reason), found);
    };
    let _ = sock.set_read_timeout(Some(HANDSHAKE));
    let _ = sock.set_write_timeout(Some(HANDSHAKE));
    let start = Instant::now();
    let mut outcome = Ok(());
    while conn.is_handshaking() && outcome.is_ok() {
        outcome = conn.complete_io(&mut sock).map(|_| ());
    }
    if net.debug {
        let how = outcome
            .as_ref()
            .map_or_else(|e| e.to_string(), |_| "done".into());
        let ms = start.elapsed().as_millis();
        net::debug(&format!("tls handshake {d} {how} {ms} ms"));
    }
    let seen = recorder.seen.lock().ok().and_then(|mut s| s.take());
    let chain: Vec<Cert> = seen
        .iter()
        .flat_map(|(chain, _)| chain.iter().filter_map(|c| parse(c)))
        .collect();
    match outcome {
        Ok(()) => {
            conn.send_close_notify();
            let _ = conn.complete_io(&mut sock);
            let version = conn.protocol_version().map(|v| match v {
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
                v => format!("{v:?}"),
            });
            if version.as_deref() == Some("TLSv1.2") {
                let message = "The server negotiated TLS 1.2; TLS 1.3 is preferred.".into();
                found.push(finding(Severity::Info, "tls_12", message, ""));
            }
            tls.protocol = version;
            let suite = conn.negotiated_cipher_suite();
            tls.cipher = suite.map(|s| format!("{:?}", s.suite()));
            let alpn = conn.alpn_protocol();
            tls.alpn = alpn.map(|a| String::from_utf8_lossy(a).into_owned());
        }
        Err(e) => match handshake_error(&e) {
            (_, true) => {
                let message =
                    format!("{d} offers only TLS 1.1 or older, which current clients refuse.");
                let hint = "Enable TLS 1.2 and 1.3 on the server.";
                found.push(finding(Severity::Error, "tls_old_protocol", message, hint));
            }
            (why, false) => {
                let message = format!("The TLS handshake with {ip} failed: {why}.");
                found.push(finding(
                    Severity::Error,
                    "tls_handshake_failed",
                    message,
                    "",
                ));
            }
        },
    }
    tls.chain = chain;
    (Section::ok(tls), found)
}
