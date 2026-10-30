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
    /// No trust problem: the OS verifier accepts the chain and our own checks agree.
    pub trusted: Option<bool>,
    /// `expired`, `not_yet_valid`, `not_valid_for_name`, `incomplete_chain` (our own
    /// checks first), then the OS verifier's `unknown_issuer`, `revoked` or `other`.
    pub trust_error: Option<&'static str>,
    /// The OS verifier's own words for `other`.
    pub trust_detail: Option<String>,
    pub names_match: Option<bool>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    /// Whole days until `not_after`, negative once expired.
    pub days_left: Option<i64>,
    pub lifetime_days: Option<i64>,
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

/// A presented certificate, with what judging it needs.
pub struct Parsed {
    pub cert: Cert,
    /// Its validity, in Unix seconds.
    pub from: i64,
    pub until: i64,
    pub rsa_bits: Option<usize>,
    pub issuer_cn: Option<String>,
}

/// A certificate's fields; `None` when it isn't DER X.509.
pub fn parse(der: &[u8]) -> Option<Parsed> {
    let (_, x) = x509_parser::parse_x509_certificate(der).ok()?;
    let sans = match x.subject_alternative_name() {
        Ok(Some(ext)) => ext.value.general_names.iter().filter_map(san).collect(),
        _ => Vec::new(),
    };
    let spki = x.public_key();
    let mut rsa_bits = None;
    let key = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            rsa_bits = dkim::bits(rsa.modulus);
            format!("RSA {}", rsa_bits.unwrap_or_default())
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
    let (from, until) = (x.validity().not_before, x.validity().not_after);
    let (from, until) = (from.timestamp(), until.timestamp());
    let cert = Cert {
        subject: x.subject().to_string(),
        issuer: x.issuer().to_string(),
        serial: x.serial.to_str_radix(16),
        not_before: text_time(from),
        not_after: text_time(until),
        sans,
        key,
        signature,
        self_signed: x.subject().as_raw() == x.issuer().as_raw(),
        ca: x.is_ca(),
    };
    let issuer_cn = x.issuer().iter_common_name().next();
    let issuer_cn = issuer_cn.and_then(|cn| cn.as_str().ok()).map(String::from);
    Some(Parsed {
        cert,
        from,
        until,
        rsa_bits,
        issuer_cn,
    })
}

/// RFC 6125 §6.4: `host` equals a DNS name, or a `*.` name covers its first label.
pub fn names_match(host: &str, sans: &[String]) -> bool {
    sans.iter().any(|san| {
        let san = san.trim_end_matches('.').to_ascii_lowercase();
        match san.strip_prefix("*.") {
            Some(rest) => host.split_once('.').is_some_and(|(first, tail)| {
                !first.is_empty() && tail == rest && rest.contains('.')
            }),
            None => san == host,
        }
    })
}

/// The longest lifetime the CA/Browser Forum Baseline Requirements (§6.3.2) allow for a
/// certificate issued on `day` (`YYYY-MM-DD`).
fn max_lifetime(day: &str) -> i64 {
    match day {
        d if d < "2026-03-15" => 398,
        d if d < "2027-03-15" => 200,
        d if d < "2029-03-15" => 100,
        _ => 47,
    }
}

const DAY: i64 = 86400;

/// How the OS verifier's refusal is reported: the trust error and, for `other`, its words.
fn os_error(e: &rustls::Error) -> (&'static str, Option<String>) {
    use rustls::CertificateError as C;
    match e {
        rustls::Error::InvalidCertificate(c) => match c {
            C::Expired | C::ExpiredContext { .. } => ("expired", None),
            C::NotValidYet | C::NotValidYetContext { .. } => ("not_yet_valid", None),
            C::NotValidForName | C::NotValidForNameContext { .. } => ("not_valid_for_name", None),
            C::UnknownIssuer => ("unknown_issuer", None),
            C::Revoked => ("revoked", None),
            C::Other(e) => ("other", Some(e.to_string())),
            c => ("other", Some(format!("{c:?}"))),
        },
        e => ("other", Some(e.to_string())),
    }
}

/// Fills in the verdict on the presented chain at `now` (Unix seconds), with its findings.
fn judge(
    d: &str,
    tls: &mut Tls,
    chain: &[Parsed],
    verdict: &Result<(), rustls::Error>,
    now: i64,
) -> Vec<Finding> {
    let mut found = Vec::new();
    let Some(leaf) = chain.first() else {
        return found;
    };
    let c = &leaf.cert;
    let matched = names_match(d, &c.sans);
    let left = leaf.until - now;
    let life = leaf.until - leaf.from;
    let days_left = left / DAY;
    let (expired, early) = (left < 0, now < leaf.from);
    let incomplete = chain.len() == 1 && !c.self_signed;
    // macOS words a self-signed certificate as its own error; it is an unknown issuer.
    let os =
        verdict
            .as_ref()
            .err()
            .map(os_error)
            .map(|(code, detail)| match (code, c.self_signed) {
                ("other", true) => ("unknown_issuer", None),
                _ => (code, detail),
            });
    let ours = [
        (expired, "expired"),
        (early, "not_yet_valid"),
        (!matched, "not_valid_for_name"),
        (incomplete, "incomplete_chain"),
    ];
    let trust_error = match ours.iter().find(|(problem, _)| *problem) {
        Some((_, code)) => Some(*code),
        None => os.as_ref().map(|(code, _)| *code),
    };
    let detail = os.and_then(|(_, detail)| detail);
    tls.trusted = Some(trust_error.is_none());
    tls.trust_error = trust_error;
    tls.trust_detail = detail.clone().filter(|_| trust_error == Some("other"));
    tls.names_match = Some(matched);
    tls.not_before = Some(c.not_before.clone());
    tls.not_after = Some(c.not_after.clone());
    tls.days_left = Some(days_left);
    tls.lifetime_days = Some((life + DAY / 2) / DAY);
    let issuer = leaf.issuer_cn.clone().unwrap_or_else(|| c.issuer.clone());
    let (until, from) = (&c.not_after[..10], &c.not_before[..10]);
    let plural = |n: i64| format!("{n} day{}", if n == 1 { "" } else { "s" });
    if expired {
        let message = format!(
            "The certificate expired on {until} ({} ago).",
            plural(-days_left)
        );
        let hint = "Renew it and reload the web server.";
        found.push(finding(Severity::Error, "cert_expired", message, hint));
    } else if early {
        let message = format!("The certificate isn't valid until {from}.");
        let hint = "Check the server's clock and this computer's clock.";
        found.push(finding(
            Severity::Error,
            "cert_not_yet_valid",
            message,
            hint,
        ));
    } else if left
        < if life < 10 * DAY {
            life / 2
        } else {
            (life / 3).min(30 * DAY)
        }
    {
        let message = format!(
            "The certificate expires in {} ({until}); renewal is due.",
            plural(days_left)
        );
        let hint = "Check that automatic renewal is running.";
        found.push(finding(Severity::Warning, "cert_expiring", message, hint));
    }
    if !matched {
        let names = match c.sans.is_empty() {
            true => c.subject.clone(),
            false => c.sans.join(", "),
        };
        let message = format!("The certificate is for {names}, not {d}.");
        let hint = format!("Issue a certificate that includes {d}.");
        found.push(finding(
            Severity::Error,
            "cert_name_mismatch",
            message,
            &hint,
        ));
    }
    match trust_error {
        Some("incomplete_chain") => {
            let message = format!(
                "The server sent only its own certificate, not the intermediate from {issuer}; some clients will refuse it."
            );
            let hint = "Configure the server with the full chain (e.g. fullchain.pem).";
            found.push(finding(Severity::Error, "chain_incomplete", message, hint));
        }
        Some("revoked") => {
            let message = "The certificate has been revoked by its issuer.".into();
            found.push(finding(
                Severity::Error,
                "cert_revoked",
                message,
                "Replace it.",
            ));
        }
        Some(code @ ("unknown_issuer" | "other")) => {
            let why = match (c.self_signed, code) {
                (true, _) => "self-signed".to_string(),
                (false, "unknown_issuer") => format!("issuer {issuer} is unknown"),
                _ => detail.unwrap_or_default(),
            };
            let message = format!("This computer doesn't trust the certificate: {why}.");
            let hint = "Use a certificate from a public CA, or pass --ca-file for an internal CA.";
            found.push(finding(Severity::Error, "cert_untrusted", message, hint));
        }
        _ => {}
    }
    // The leaf and the intermediates; a root sent along is the client's to judge.
    let issued = chain
        .iter()
        .enumerate()
        .filter(|(i, p)| *i == 0 || !p.cert.self_signed);
    let mut weak: Vec<usize> = issued.clone().filter_map(|(_, p)| p.rsa_bits).collect();
    weak.retain(|&bits| bits < 2048);
    weak.dedup();
    for bits in weak {
        let message =
            format!("The certificate uses an RSA {bits}-bit key; 2048 is the minimum CAs issue.");
        found.push(finding(Severity::Warning, "cert_weak_key", message, ""));
    }
    let sha1 = |s: &str| s.to_ascii_lowercase().contains("sha1") || s == "1.2.840.10045.4.1";
    if issued.clone().any(|(_, p)| sha1(&p.cert.signature)) {
        let message = "The certificate is signed with SHA-1, which clients reject.".into();
        found.push(finding(
            Severity::Error,
            "cert_sha1",
            message,
            "Reissue it.",
        ));
    }
    let max = max_lifetime(from);
    if verdict.is_ok() && life > max * DAY {
        let message = format!(
            "The certificate's lifetime is {} days, more than the {max} days allowed for certificates issued on {from}.",
            (life + DAY / 2) / DAY
        );
        found.push(finding(
            Severity::Info,
            "cert_lifetime_over_limit",
            message,
            "",
        ));
    }
    found
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
    let (presented, verdict) = recorder.seen.lock().ok().and_then(|mut s| s.take()).unzip();
    let chain: Vec<Parsed> = presented
        .iter()
        .flatten()
        .filter_map(|c| parse(c))
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
    if let Some(verdict) = &verdict {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        found.extend(judge(d, &mut tls, &chain, verdict, now));
    }
    tls.chain = chain.into_iter().map(|p| p.cert).collect();
    (Section::ok(tls), found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_000_000; // 2026-10-26

    fn cert(subject: &str, self_signed: bool, signature: &str) -> Parsed {
        Parsed {
            cert: Cert {
                subject: format!("CN={subject}"),
                issuer: "CN=Example CA".into(),
                not_before: text_time(NOW - 10 * DAY),
                not_after: text_time(NOW + 80 * DAY),
                sans: vec![subject.into()],
                key: "EC P-256".into(),
                signature: signature.into(),
                self_signed,
                ..Cert::default()
            },
            from: NOW - 10 * DAY,
            until: NOW + 80 * DAY,
            rsa_bits: None,
            issuer_cn: Some("Example CA".into()),
        }
    }

    fn codes(chain: &[Parsed], verdict: Result<(), rustls::Error>) -> (Tls, Vec<String>) {
        let mut tls = Tls::default();
        let found = judge("www.example.com", &mut tls, chain, &verdict, NOW);
        let found = found.iter().map(|f| format!("{} {}", f.code, f.message));
        (tls, found.collect())
    }

    fn pair() -> Vec<Parsed> {
        let ca = cert("Example CA", false, "sha256WithRSAEncryption");
        vec![cert("www.example.com", false, "ecdsa-with-SHA256"), ca]
    }

    #[test]
    fn names_match_exactly_or_by_one_wildcard_label() {
        let m = |host, san: &str| names_match(host, &[san.to_string()]);
        assert!(m("www.example.com", "www.example.com"));
        assert!(m("www.example.com", "WWW.Example.com."));
        assert!(m("www.example.com", "*.example.com"));
        assert!(!m("example.com", "*.example.com"));
        assert!(!m("a.www.example.com", "*.example.com"));
        assert!(!m("www.example.com", "w*.example.com"));
        assert!(!m("example.com", "*.com"));
        assert!(!names_match("www.example.com", &[]));
    }

    #[test]
    fn lifetimes_follow_the_baseline_requirements_schedule() {
        let max: Vec<_> = [
            "2025-12-01",
            "2026-03-15",
            "2027-03-15",
            "2029-03-14",
            "2029-03-15",
        ]
        .map(max_lifetime)
        .into();
        assert_eq!(max, [398, 200, 100, 100, 47]);
    }

    #[test]
    fn a_trusted_chain_has_its_dates_and_no_findings() {
        let (tls, found) = codes(&pair(), Ok(()));
        assert_eq!(found, Vec::<String>::new());
        assert_eq!((tls.trusted, tls.trust_error), (Some(true), None));
        assert_eq!((tls.days_left, tls.lifetime_days), (Some(80), Some(90)));
        assert_eq!(tls.not_after.as_deref(), Some("2027-01-14T07:33:20Z"));
    }

    #[test]
    fn renewal_is_due_with_a_third_of_the_lifetime_or_30_days_left() {
        let left = |life: i64, left: i64| {
            let mut chain = pair();
            (chain[0].from, chain[0].until) = (NOW + left - life, NOW + left);
            chain[0].cert.not_after = text_time(NOW + left);
            let (_, found) = codes(&chain, Ok(()));
            found.iter().any(|f| f.starts_with("cert_expiring"))
        };
        assert!(left(90 * DAY, 29 * DAY + 3600));
        assert!(!left(90 * DAY, 31 * DAY));
        assert!(!left(398 * DAY, 31 * DAY));
        assert!(left(398 * DAY, 29 * DAY));
        assert!(left(30 * DAY, 9 * DAY));
        assert!(left(6 * DAY, 2 * DAY));
        assert!(!left(6 * DAY, 4 * DAY));
        let (_, found) = {
            let mut chain = pair();
            chain[0].until = NOW + 4 * DAY + 60;
            chain[0].cert.not_after = text_time(chain[0].until);
            codes(&chain, Ok(()))
        };
        assert_eq!(
            found,
            ["cert_expiring The certificate expires in 4 days (2026-10-30); renewal is due."]
        );
    }

    #[test]
    fn our_own_checks_name_the_trust_error_before_the_os() {
        let unknown = || Err(rustls::CertificateError::UnknownIssuer.into());
        let mut chain = pair();
        chain[0].until = NOW - DAY - 60;
        chain[0].cert.not_after = text_time(chain[0].until);
        let (tls, found) = codes(&chain, Err(rustls::CertificateError::Expired.into()));
        assert_eq!(
            (tls.trust_error, tls.days_left),
            (Some("expired"), Some(-1))
        );
        assert_eq!(
            found,
            ["cert_expired The certificate expired on 2026-10-25 (1 day ago)."]
        );
        let (tls, found) = codes(&[cert("www.example.com", false, "x")], unknown());
        assert_eq!(tls.trust_error, Some("incomplete_chain"));
        let want = "chain_incomplete The server sent only its own certificate, not the intermediate from Example CA; some clients will refuse it.";
        assert_eq!(found, [want]);
        let (tls, found) = codes(&[cert("www.example.com", true, "x")], unknown());
        assert_eq!(
            (tls.trusted, tls.trust_error),
            (Some(false), Some("unknown_issuer"))
        );
        let want = "cert_untrusted This computer doesn't trust the certificate: self-signed.";
        assert_eq!(found, [want]);
        let apple = rustls::CertificateError::Other(rustls::OtherError(Arc::new(
            io::Error::other("“selfsigned.example.com” certificate is not trusted"),
        )));
        let (tls, again) = codes(&[cert("www.example.com", true, "x")], Err(apple.into()));
        assert_eq!(
            (tls.trust_error, tls.trust_detail),
            (Some("unknown_issuer"), None)
        );
        assert_eq!(again, found);
        let (_, found) = codes(&pair(), unknown());
        let want = "cert_untrusted This computer doesn't trust the certificate: issuer Example CA is unknown.";
        assert_eq!(found, [want]);
        let other = rustls::CertificateError::Other(rustls::OtherError(Arc::new(
            io::Error::other("CSSMERR_TP_NOT_TRUSTED"),
        )));
        let (tls, found) = codes(&pair(), Err(other.into()));
        assert_eq!(tls.trust_detail.as_deref(), Some("CSSMERR_TP_NOT_TRUSTED"));
        let want =
            "cert_untrusted This computer doesn't trust the certificate: CSSMERR_TP_NOT_TRUSTED.";
        assert_eq!(found, [want]);
        let (_, found) = codes(&pair(), Err(rustls::CertificateError::Revoked.into()));
        assert_eq!(
            found,
            ["cert_revoked The certificate has been revoked by its issuer."]
        );
        let mut chain = pair();
        chain[0].cert.sans = vec!["*.example.net".into(), "example.net".into()];
        let (tls, found) = codes(&chain, Ok(()));
        assert_eq!(tls.names_match, Some(false));
        let want = "cert_name_mismatch The certificate is for *.example.net, example.net, not www.example.com.";
        assert_eq!(found, [want]);
    }

    #[test]
    fn weak_keys_sha1_and_long_lifetimes_skip_the_root() {
        let mut chain = pair();
        chain[1].rsa_bits = Some(1024);
        chain[1].cert.signature = "sha1WithRSAEncryption".into();
        let mut root = cert("Old Root", true, "sha1WithRSAEncryption");
        root.rsa_bits = Some(1024);
        chain.push(root);
        let (_, found) = codes(&chain, Ok(()));
        assert_eq!(
            found,
            [
                "cert_weak_key The certificate uses an RSA 1024-bit key; 2048 is the minimum CAs issue.",
                "cert_sha1 The certificate is signed with SHA-1, which clients reject."
            ]
        );
        // A self-signed certificate sent alone is the server's own, so it is judged.
        let (_, found) = codes(&[chain.remove(2)], Ok(()));
        assert!(
            found.iter().any(|f| f.starts_with("cert_weak_key")),
            "{found:?}"
        );
        let mut chain = pair();
        chain[0].from = NOW - 150 * DAY;
        chain[0].cert.not_before = text_time(chain[0].from);
        let (_, found) = codes(&chain, Ok(()));
        let want = "cert_lifetime_over_limit The certificate's lifetime is 230 days, more than the 200 days allowed for certificates issued on 2026-05-29.";
        assert_eq!(found, [want]);
        let unknown = Err(rustls::CertificateError::UnknownIssuer.into());
        let (_, found) = codes(&chain, unknown);
        assert!(
            found[0].starts_with("cert_untrusted") && found.len() == 1,
            "{found:?}"
        );
    }
}
