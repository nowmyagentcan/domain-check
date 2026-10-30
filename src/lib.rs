use std::net::SocketAddr;

pub mod check;
pub mod dns;
pub mod input;
pub mod lookup;
pub mod report;
pub mod sections {
    pub mod dns;
    pub mod propagation;
}
pub mod text;

/// The `publication` stamp of the bundled IANA RDAP bootstrap file, `data/rdap-dns.json`.
pub const RDAP_BOOTSTRAP: &str = "2026-10-28T22:00:04Z";
pub const RDAP_BOOTSTRAP_JSON: &str = include_str!("../data/rdap-dns.json");

pub fn version() -> String {
    format!(
        "domain-check {} (RDAP bootstrap {})",
        env!("CARGO_PKG_VERSION"),
        &RDAP_BOOTSTRAP[..10]
    )
}

/// What went wrong and how to fix it: an input's error in a report, or a usage error.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>, hint: impl Into<String>) -> Error {
        Error {
            code,
            message: message.into(),
            hint: Some(hint.into()),
        }
    }

    /// A mistake on the command line: exit 2.
    pub fn usage(message: impl Into<String>, hint: impl Into<String>) -> Error {
        Error::new("usage", message, hint)
    }
}

/// A runtime for this thread's network work.
pub fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::new("runtime", format!("Couldn't start: {e}."), "Try again."))
}

/// The ports used instead of 53, 80 and 443 when the destination is a loopback address
/// (`DOMAIN_CHECK_LOOPBACK_PORTS=dns=N,http=N,https=N`), so tests and local mirrors can
/// stand in for real servers. Any other address keeps its port.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Ports {
    pub dns: Option<u16>,
    pub http: Option<u16>,
    pub https: Option<u16>,
}

const PORTS_VAR: &str = "DOMAIN_CHECK_LOOPBACK_PORTS";

impl Ports {
    pub fn from_env() -> Result<Ports, Error> {
        Ports::parse(&std::env::var(PORTS_VAR).unwrap_or_default())
    }

    pub fn parse(raw: &str) -> Result<Ports, Error> {
        let bad = || {
            Error::usage(
                format!("{PORTS_VAR}={raw} isn't valid."),
                "Use dns=N,http=N,https=N with ports from 1 to 65535, or unset it.",
            )
        };
        let mut ports = Ports::default();
        for part in raw.split(',').filter(|p| !p.trim().is_empty()) {
            let (key, port) = part.split_once('=').ok_or_else(bad)?;
            let port = port
                .trim()
                .parse()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(bad)?;
            let slot = match key.trim() {
                "dns" => &mut ports.dns,
                "http" => &mut ports.http,
                "https" => &mut ports.https,
                _ => return Err(bad()),
            };
            if slot.replace(port).is_some() {
                return Err(bad());
            }
        }
        Ok(ports)
    }

    pub fn swap(&self, addr: SocketAddr) -> SocketAddr {
        let swapped = match addr.port() {
            53 => self.dns,
            80 => self.http,
            443 => self.https,
            _ => None,
        };
        match swapped {
            Some(port) if addr.ip().is_loopback() => SocketAddr::new(addr.ip(), port),
            _ => addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ports_swap_only_loopback_destinations() {
        let ports = Ports::parse("dns=5353, https=8443").unwrap();
        let swap = |a: &str| ports.swap(a.parse().unwrap()).to_string();
        assert_eq!(swap("127.0.0.1:53"), "127.0.0.1:5353");
        assert_eq!(swap("[::1]:53"), "[::1]:5353");
        assert_eq!(swap("127.0.0.1:443"), "127.0.0.1:8443");
        assert_eq!(swap("127.0.0.1:80"), "127.0.0.1:80");
        assert_eq!(swap("127.0.0.1:5300"), "127.0.0.1:5300");
        assert_eq!(swap("192.0.2.53:53"), "192.0.2.53:53");
        assert_eq!(swap("[2001:db8::53]:53"), "[2001:db8::53]:53");
        assert_eq!(Ports::parse("").unwrap(), Ports::default());
        for bad in [
            "dns",
            "dns=0",
            "dns=65536",
            "dns=x",
            "smtp=25",
            "dns=1,dns=2",
            "dns=-1",
        ] {
            let e = Ports::parse(bad).unwrap_err();
            assert_eq!(e.code, "usage");
            assert_eq!(
                e.message,
                format!("DOMAIN_CHECK_LOOPBACK_PORTS={bad} isn't valid.")
            );
        }
    }

    #[test]
    fn the_bootstrap_stamp_matches_the_bundled_file() {
        let field = format!("\"publication\": \"{RDAP_BOOTSTRAP}\"");
        assert!(
            RDAP_BOOTSTRAP_JSON.contains(&field),
            "update RDAP_BOOTSTRAP to the file's publication"
        );
    }

    #[test]
    fn version_names_the_bootstrap_date() {
        assert_eq!(version(), "domain-check 0.1.0 (RDAP bootstrap 2026-10-28)");
    }
}
