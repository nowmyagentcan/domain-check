//! Connections to web servers: HTTP and HTTPS through ureq, and the TLS check's own handshake.
//! Names resolve through our DNS layer, only ports 80 and 443 are used (swapped for loopback
//! test servers), no proxy, and non-public addresses are refused unless `--allow-private`.

use std::fmt;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls_platform_verifier::Verifier;
use ureq::config::Config;
use ureq::http::{Response, Uri};
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver as Resolve};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use ureq::{Agent, Body};

use crate::dns::{self, RecordType, Resolver};
use crate::{Error, Ports};

pub const USER_AGENT: &str = concat!(
    "domain-check/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/nowmyagentcan/domain-check)"
);

/// How long one request may take, connect included.
pub const REQUEST: Duration = Duration::from_secs(10);
pub const CONNECT: Duration = Duration::from_secs(5);

/// Whether a connection to `ip` may reach the public internet. Everything else (loopback,
/// RFC 1918, link-local, CGNAT, unique-local, documentation, reserved, multicast and the
/// IPv4-mapped forms of these) needs `--allow-private`.
pub fn public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || (s[0] == 0x2001 && s[1] == 0xdb8))
        }
    }
}

/// The PEM certificates in `--ca-file`.
pub fn ca_file(path: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::new(
            "runtime",
            format!("Couldn't read --ca-file {path}: {e}."),
            "Check the path and that this account may read it.",
        )
    })?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&bytes)
        .filter_map(Result::ok)
        .collect();
    match certs.is_empty() {
        true => Err(Error::usage(
            format!("--ca-file {path} holds no PEM certificate."),
            "Pass a file with -----BEGIN CERTIFICATE----- blocks.",
        )),
        false => Ok(certs),
    }
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Why a request got no response.
#[derive(Clone, Debug, PartialEq)]
pub enum Failed {
    /// Every address of the host needs `--allow-private`.
    Private { host: String, address: IpAddr },
    /// The server's certificate didn't verify.
    Certificate(String),
    /// No connection was made: no address, refused, unreachable, timed out.
    Connect(String),
    /// Connected, then something else went wrong.
    Other(String),
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failed::Private { host, address } => {
                write!(f, "{host} resolves to {address}, a private address")
            }
            Failed::Certificate(why) | Failed::Connect(why) | Failed::Other(why) => {
                f.write_str(why)
            }
        }
    }
}

impl Failed {
    pub fn from_io(e: &io::Error) -> Failed {
        if let Some(inner) = e.get_ref() {
            if let Some(f) = inner.downcast_ref::<Failed>() {
                return f.clone();
            }
            if let Some(e) = inner.downcast_ref::<rustls::Error>() {
                return Failed::from_tls(e);
            }
        }
        match e.kind() {
            io::ErrorKind::ConnectionRefused => Failed::Connect("connection refused".into()),
            io::ErrorKind::TimedOut => Failed::Connect("timeout".into()),
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                Failed::Connect("network unreachable".into())
            }
            io::ErrorKind::ConnectionReset => Failed::Other("the connection was reset".into()),
            io::ErrorKind::UnexpectedEof => Failed::Other("the connection closed early".into()),
            _ => Failed::Other(e.to_string()),
        }
    }

    pub fn from_tls(e: &rustls::Error) -> Failed {
        match e {
            rustls::Error::InvalidCertificate(c) => Failed::Certificate(format!("{c:?}")),
            e => Failed::Other(e.to_string()),
        }
    }

    fn from_ureq(e: ureq::Error) -> Failed {
        match e {
            ureq::Error::Io(e) => Failed::from_io(&e),
            ureq::Error::Rustls(e) => Failed::from_tls(&e),
            ureq::Error::Timeout(ureq::Timeout::Connect | ureq::Timeout::Resolve) => {
                Failed::Connect("timeout".into())
            }
            ureq::Error::Timeout(_) => Failed::Other("timeout".into()),
            e => Failed::Other(e.to_string()),
        }
    }
}

impl std::error::Error for Failed {}

/// How a check reaches web servers.
pub struct Net {
    pub resolver: Arc<Resolver>,
    pub ports: Ports,
    pub allow_private: bool,
    /// `--ca-file`'s certificates, trusted besides this computer's own.
    pub roots: Vec<CertificateDer<'static>>,
    pub debug: bool,
    agent: Agent,
    verifier: OnceLock<Result<Arc<Verifier>, String>>,
}

impl Net {
    pub fn new(
        resolver: Arc<Resolver>,
        ports: Ports,
        allow_private: bool,
        roots: Vec<CertificateDer<'static>>,
        debug: bool,
    ) -> Net {
        let trust = match roots.is_empty() {
            true => RootCerts::PlatformVerifier,
            false => {
                let native = rustls_native_certs::load_native_certs().certs;
                let all = roots.iter().chain(&native);
                all.map(|c| Certificate::from_der(c).to_owned()).into()
            }
        };
        let tls = TlsConfig::builder()
            .root_certs(trust)
            .unversioned_rustls_crypto_provider(provider())
            .build();
        let config = Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_connect(Some(CONNECT))
            .timeout_global(Some(REQUEST))
            .user_agent(USER_AGENT)
            .accept("*/*")
            .tls_config(tls)
            .build();
        let lookup = Lookup {
            resolver: Arc::clone(&resolver),
            ports,
            allow_private,
            debug,
        };
        Net {
            agent: Agent::with_parts(config, DefaultConnector::new(), lookup),
            resolver,
            ports,
            allow_private,
            roots,
            debug,
            verifier: OnceLock::new(),
        }
    }

    /// The OS's certificate verifier, with `--ca-file`'s roots added.
    pub fn verifier(&self) -> Result<Arc<Verifier>, String> {
        let make = || {
            let made = match self.roots.is_empty() {
                true => Verifier::new(provider()),
                false => Verifier::new_with_extra_roots(self.roots.clone(), provider()),
            };
            made.map(Arc::new).map_err(|e| e.to_string())
        };
        self.verifier.get_or_init(make).clone()
    }

    /// Whether a connection to `ip` is allowed.
    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.allow_private || public(ip)
    }

    /// One GET of `url`, never following a redirect, given up at `until` at the latest.
    pub fn get(&self, url: &str, until: Instant) -> Result<Response<Body>, Failed> {
        let start = Instant::now();
        let left = until.saturating_duration_since(start).min(REQUEST);
        let request = self.agent.get(url).config().timeout_global(Some(left));
        let got = request.build().call().map_err(Failed::from_ureq);
        if self.debug {
            let outcome = match &got {
                Ok(r) => r.status().as_u16().to_string(),
                Err(e) => e.to_string(),
            };
            let ms = start.elapsed().as_millis();
            debug(&format!("http GET {url} {outcome} {ms} ms"));
        }
        got
    }
}

/// `host`'s addresses, A records first; why there are none when the lookups failed.
fn addresses(resolver: &Arc<Resolver>, host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse() {
        return Ok(vec![ip]);
    }
    let types = [RecordType::A, RecordType::AAAA];
    let answers = crate::runtime()
        .map_err(|e| e.message)?
        .block_on(dns::lookups(resolver, host, &types));
    if let Some(why) = dns::unanswered(&answers) {
        return Err(format!("couldn't look up {host}: {why}"));
    }
    let ips = answers.iter().zip(types).flat_map(|(a, t)| {
        let records = a.iter().flat_map(move |m| dns::records(m, t));
        records.filter_map(|r| dns::value(&r.data).parse().ok())
    });
    Ok(ips.collect())
}

/// The body, read up to `limit` bytes.
pub fn body(r: &mut Response<Body>, limit: u64) -> Result<Vec<u8>, Failed> {
    let read = r.body_mut().with_config().limit(limit).read_to_vec();
    read.map_err(|e| match e {
        ureq::Error::BodyExceedsLimit(_) => {
            Failed::Other(format!("it's larger than {limit} bytes"))
        }
        e => Failed::from_ureq(e),
    })
}

/// A `--debug` line on stderr; a closed stderr loses it quietly.
pub fn debug(line: &str) {
    let _ = io::stderr().write_all(format!("debug: {line}\n").as_bytes());
}

/// Resolves the hosts ureq connects to through [`Net`]'s rules.
#[derive(Debug)]
struct Lookup {
    resolver: Arc<Resolver>,
    ports: Ports,
    allow_private: bool,
    debug: bool,
}

impl Resolve for Lookup {
    fn resolve(
        &self,
        uri: &Uri,
        _: &Config,
        _: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let fail = |f: Failed| ureq::Error::Io(io::Error::other(f));
        let host = uri.host().unwrap_or_default();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port = match (uri.port_u16(), uri.scheme_str()) {
            (Some(port @ (80 | 443)), _) => port,
            (None, Some("http")) => 80,
            (None, Some("https")) => 443,
            (port, _) => {
                let port = port.map_or("another".into(), |p| p.to_string());
                return Err(fail(Failed::Connect(format!(
                    "port {port} isn't 80 or 443, the only web ports domain-check uses"
                ))));
            }
        };
        let ips = addresses(&self.resolver, host).map_err(|why| fail(Failed::Connect(why)))?;
        let Some(&first) = ips.first() else {
            return Err(fail(Failed::Connect(format!(
                "{host} has no A or AAAA record"
            ))));
        };
        let mut out = self.empty();
        let allowed = ips.iter().filter(|&&ip| self.allow_private || public(ip));
        // ureq keeps at most 16 addresses.
        for &ip in allowed.take(16) {
            out.push(self.ports.swap(SocketAddr::new(ip, port)));
        }
        if self.debug {
            let addrs: Vec<_> = out.iter().map(|a| a.to_string()).collect();
            debug(&format!("http resolve {host} {}", addrs.join(" ")));
        }
        match out.is_empty() {
            true => Err(fail(Failed::Private {
                host: host.to_string(),
                address: first,
            })),
            false => Ok(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_are_public() {
        let public = |s: &str| public(s.parse().unwrap());
        for ip in [
            "93.184.215.14",
            "8.8.8.8",
            "2606:2800:21f:cb07::1",
            "100.128.0.1",
        ] {
            assert!(public(ip), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "192.0.2.10",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "192.0.0.8",
            "240.0.0.1",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::10",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
        ] {
            assert!(!public(ip), "{ip}");
        }
    }

    #[test]
    fn failures_read_as_reasons() {
        let private = Failed::Private {
            host: "www.example.com".into(),
            address: "10.0.0.1".parse().unwrap(),
        };
        assert_eq!(
            private.to_string(),
            "www.example.com resolves to 10.0.0.1, a private address"
        );
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(
            Failed::from_io(&refused),
            Failed::Connect("connection refused".into())
        );
        let wrapped = io::Error::other(private.clone());
        assert_eq!(Failed::from_io(&wrapped), private);
        let cert = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        let tls = io::Error::new(io::ErrorKind::InvalidData, cert);
        assert_eq!(
            Failed::from_io(&tls),
            Failed::Certificate("UnknownIssuer".into())
        );
    }
}
