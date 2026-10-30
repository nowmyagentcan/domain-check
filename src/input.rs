//! What counts as a domain: URLs and email addresses give their host, a port is dropped,
//! IP addresses, single labels and special-use names are refused, and the rest goes
//! through UTS 46 to its A-label form.

use std::net::IpAddr;

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use percent_encoding::percent_decode_str;

use crate::Error;

/// Longest input accepted, in bytes, before normalisation.
pub const MAX_INPUT: usize = 1024;

/// Letters, digits and hyphens for `check`; `lookup` also takes `_` (`_dmarc`) and `*`.
const LOOKUP_DENY: AsciiDenyList = AsciiDenyList::new(true, "!\"#$%&'()+,/:;<=>?@[\\]^`{|}~");

/// Names that never resolve on the public internet, and where that is written down.
const SPECIAL_USE: [(&str, &str); 9] = [
    ("localhost", "RFC 6761"),
    ("test", "RFC 6761"),
    ("invalid", "RFC 6761"),
    ("example", "RFC 6761"),
    ("local", "RFC 6762"),
    ("onion", "RFC 7686"),
    ("home.arpa", "RFC 8375"),
    ("alt", "RFC 9476"),
    ("internal", "reserved by ICANN for private use"),
];

#[derive(Debug, PartialEq)]
pub struct Domain {
    /// The A-label form, lower case, as queried.
    pub ascii: String,
    /// The U-label form, as people read it.
    pub unicode: String,
    /// The input named a port, which the checks don't use.
    pub port_ignored: bool,
}

/// A domain to check, from a name, a URL or an email address.
pub fn domain(input: &str) -> Result<Domain, Error> {
    let s = trimmed(input)?;
    let url = s.split_once("://");
    let host = match url {
        Some((_, rest)) => {
            let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
            authority.rsplit_once('@').map_or(authority, |(_, h)| h)
        }
        None => s.rsplit_once('@').map_or(s, |(_, h)| h),
    };
    let (host, port_ignored) = without_port(host);
    // A URL's host may be percent-encoded, as browsers read it (WHATWG URL host parsing).
    let decoded = percent_decode_str(host).decode_utf8();
    let host = match (url, &decoded) {
        (Some(_), Ok(d)) => d,
        _ => host,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Some(ip) = ip(host) {
        return Err(Error::new(
            "ip_address",
            format!("{s} is an IP address; domain-check checks domain names."),
            format!("For reverse DNS, try: domain-check lookup {ip}"),
        ));
    }
    let ascii = to_ascii(host, s, AsciiDenyList::STD3)?;
    if !ascii.contains('.') {
        return Err(Error {
            code: "single_label",
            message: format!("{s} has no dot; a domain looks like example.com."),
            hint: None,
        });
    }
    let unicode = Uts46::new()
        .to_unicode(ascii.as_bytes(), AsciiDenyList::EMPTY, Hyphens::Allow)
        .0
        .into_owned();
    if let Some((_, source)) = SPECIAL_USE
        .iter()
        .find(|(suffix, _)| ascii == *suffix || ascii.ends_with(&format!(".{suffix}")))
    {
        return Err(Error::new(
            "special_use",
            format!(
                "{unicode} is a special-use name ({source}); it never resolves on the public internet."
            ),
            "Use domain-check lookup to ask your own resolver about it.",
        ));
    }
    Ok(Domain {
        ascii,
        unicode,
        port_ignored,
    })
}

/// What `lookup` asks about: a name in A-label form, or an address for its PTR record.
#[derive(Debug, PartialEq)]
pub enum Target {
    Name(String),
    Ip(IpAddr),
}

/// Any DNS name (`_dmarc.example.com`, `printer.local`, `com`) or an IP address.
pub fn target(input: &str) -> Result<Target, Error> {
    let s = trimmed(input)?;
    let host = s.strip_suffix('.').unwrap_or(s);
    match ip(host) {
        Some(ip) => Ok(Target::Ip(ip)),
        None => to_ascii(host, s, LOOKUP_DENY).map(Target::Name),
    }
}

fn trimmed(input: &str) -> Result<&str, Error> {
    if input.len() > MAX_INPUT {
        return Err(Error::new(
            "too_long",
            "Input is longer than 1024 characters.",
            "Pass one domain per argument.",
        ));
    }
    match input.trim() {
        "" => Err(Error::new(
            "empty",
            "Empty input.",
            "Pass a domain, e.g. example.com.",
        )),
        s => Ok(s),
    }
}

/// `host` without a `:port` suffix, and whether it had one.
fn without_port(host: &str) -> (&str, bool) {
    let split = match host.strip_prefix('[') {
        Some(_) => host
            .split_once("]:")
            .map(|(h, p)| (&host[..h.len() + 1], p)),
        None if host.matches(':').count() == 1 => host.split_once(':'),
        None => None,
    };
    match split {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (h, true)
        }
        _ => (host, false),
    }
}

fn ip(host: &str) -> Option<IpAddr> {
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    bare.unwrap_or(host).parse().ok()
}

/// UTS 46 ToASCII (non-transitional), with the reason in our words when it fails.
fn to_ascii(host: &str, input: &str, deny: AsciiDenyList) -> Result<String, Error> {
    let lenient = Uts46::new().to_ascii(host.as_bytes(), deny, Hyphens::Allow, DnsLength::Ignore);
    let reason = match &lenient {
        Err(_)
            if host
                .split('.')
                .any(|l| l.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("xn--"))) =>
        {
            "xn-- label isn't valid punycode"
        }
        Err(_) => "it contains a character not allowed in domain names",
        Ok(a) if a.split('.').any(str::is_empty) => "it has an empty label",
        Ok(a) if a.split('.').any(|l| l.len() > 63) => "a label is longer than 63 characters",
        Ok(a) if a.len() > 253 => "the name is longer than 253 characters",
        Ok(a) if a.split('.').any(|l| l.starts_with('-') || l.ends_with('-')) => {
            "a label starts or ends with a hyphen"
        }
        Ok(a) => return Ok(a.to_string()),
    };
    Err(Error::new(
        "domain_invalid",
        format!("{input} isn't a valid domain name: {reason}."),
        "Check the spelling.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(input: &str) -> (String, String, bool) {
        let d = domain(input).unwrap();
        (d.ascii, d.unicode, d.port_ignored)
    }

    fn err(input: &str) -> (&'static str, String, Option<String>) {
        let e = domain(input).unwrap_err();
        (e.code, e.message, e.hint)
    }

    fn reason(input: &str) -> String {
        let (code, message, hint) = err(input);
        assert_eq!(
            (code, hint.as_deref()),
            ("domain_invalid", Some("Check the spelling."))
        );
        let prefix = format!("{} isn't a valid domain name: ", input.trim());
        message
            .strip_prefix(&prefix)
            .unwrap()
            .strip_suffix(".")
            .unwrap()
            .to_string()
    }

    #[test]
    fn urls_and_email_addresses_give_their_host() {
        let www = (
            "www.example.com".to_string(),
            "www.example.com".to_string(),
            true,
        );
        assert_eq!(ok("https://www.example.com:8443/a?b"), www);
        assert_eq!(ok("  https://user:pw@WWW.Example.COM:8443#x "), www);
        assert_eq!(
            ok("http://www.example.com/"),
            (www.0.clone(), www.1.clone(), false)
        );
        let apex = ("example.com".to_string(), "example.com".to_string(), false);
        assert_eq!(ok("postmaster@example.com"), apex);
        assert_eq!(ok("a@b@example.com"), apex);
        assert_eq!(ok("Example.COM."), apex);
        assert!(ok("example.com:25").2);
    }

    #[test]
    fn idn_names_get_both_forms() {
        let (ascii, unicode, _) = ok("Bücher.DE.");
        assert_eq!(
            (ascii.as_str(), unicode.as_str()),
            ("xn--bcher-kva.de", "bücher.de")
        );
        assert_eq!(ok("faß.de").0, "xn--fa-hia.de");
        let (ascii, unicode, _) = ok("аpple.com");
        assert_eq!(
            (ascii.as_str(), unicode.as_str()),
            ("xn--pple-43d.com", "аpple.com")
        );
        assert_eq!(ok("xn--bcher-kva.de").1, "bücher.de");
        assert_eq!(ok("https://Bücher.de/x").0, "xn--bcher-kva.de");
        // Hyphens in the third and fourth places are real names (CDN nodes).
        assert_eq!(ok("r3---sn-abc.example.com").0, "r3---sn-abc.example.com");
    }

    #[test]
    fn ip_addresses_point_to_lookup() {
        for (input, ip) in [
            ("192.0.2.1", "192.0.2.1"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("http://[2001:db8::1]:8080/x", "2001:db8::1"),
            ("http://192.0.2.1:80", "192.0.2.1"),
            ("root@[192.0.2.1]", "192.0.2.1"),
        ] {
            let (code, message, hint) = err(input);
            assert_eq!(code, "ip_address");
            assert_eq!(
                message,
                format!("{input} is an IP address; domain-check checks domain names.")
            );
            assert_eq!(
                hint.unwrap(),
                format!("For reverse DNS, try: domain-check lookup {ip}")
            );
        }
    }

    #[test]
    fn single_labels_are_refused() {
        for input in ["com", "localhost", "https://intranet/", "test."] {
            let (code, message, hint) = err(input);
            assert_eq!(code, "single_label", "{input}");
            assert_eq!(
                message,
                format!("{input} has no dot; a domain looks like example.com.")
            );
            assert_eq!(hint, None);
        }
    }

    #[test]
    fn special_use_names_are_refused() {
        for (name, rfc) in [
            ("printer.localhost", "RFC 6761"),
            ("printer.test", "RFC 6761"),
            ("a.b.invalid", "RFC 6761"),
            ("shop.example", "RFC 6761"),
            ("nas.local", "RFC 6762"),
            ("abc.onion", "RFC 7686"),
            ("home.arpa", "RFC 8375"),
            ("router.home.arpa", "RFC 8375"),
            ("x.alt", "RFC 9476"),
            ("wiki.corp.internal", "reserved by ICANN for private use"),
        ] {
            let (code, message, hint) = err(name);
            assert_eq!(code, "special_use");
            assert_eq!(
                message,
                format!(
                    "{name} is a special-use name ({rfc}); it never resolves on the public internet."
                )
            );
            assert_eq!(
                hint.unwrap(),
                "Use domain-check lookup to ask your own resolver about it."
            );
        }
        for name in [
            "example.com",
            "example.net",
            "example.org",
            "test.com",
            "local.example.org",
            "arpa.net",
        ] {
            assert_eq!(ok(name).0, name);
        }
    }

    #[test]
    fn invalid_names_say_why() {
        let long = "a".repeat(64);
        assert_eq!(
            reason(&format!("{long}.com")),
            "a label is longer than 63 characters"
        );
        assert!(domain(&format!("{}.com", "a".repeat(63))).is_ok());
        let name = format!("{}.com", vec!["a".repeat(62); 4].join("."));
        assert_eq!(name.len(), 255);
        assert_eq!(reason(&name), "the name is longer than 253 characters");
        let fits = format!(
            "{}.{}.com",
            vec!["a".repeat(62); 3].join("."),
            "a".repeat(60)
        );
        assert_eq!(fits.len(), 253);
        assert!(domain(&fits).is_ok());
        assert_eq!(
            reason("-example.com"),
            "a label starts or ends with a hyphen"
        );
        assert_eq!(
            reason("example-.com"),
            "a label starts or ends with a hyphen"
        );
        for bad in [
            "exa mple.com",
            "exa_mple.com",
            "example.com:abc",
            "ex!ample.com",
        ] {
            assert_eq!(
                reason(bad),
                "it contains a character not allowed in domain names"
            );
        }
        assert_eq!(reason("xn--zz-.com"), "xn-- label isn't valid punycode");
        assert_eq!(reason("example..com"), "it has an empty label");
        assert_eq!(reason("example.com.."), "it has an empty label");
        assert_eq!(reason("https://"), "it has an empty label");
    }

    #[test]
    fn empty_and_long_inputs() {
        let empty = (
            "empty",
            "Empty input.".into(),
            Some("Pass a domain, e.g. example.com.".into()),
        );
        assert_eq!(err(""), empty);
        assert_eq!(err("  \t"), empty);
        let long = format!("{}.com", "a".repeat(1021));
        assert_eq!(long.len(), 1025);
        let (code, message, hint) = err(&long);
        assert_eq!(code, "too_long");
        assert_eq!(message, "Input is longer than 1024 characters.");
        assert_eq!(hint.unwrap(), "Pass one domain per argument.");
        assert_eq!(err(&long[1..]).0, "domain_invalid");
    }

    #[test]
    fn lookup_takes_any_dns_name_or_an_ip() {
        let name = |s: &str| Target::Name(s.to_string());
        assert_eq!(
            target("_dmarc.Example.com.").unwrap(),
            name("_dmarc.example.com")
        );
        assert_eq!(
            target("_443._tcp.example.com").unwrap(),
            name("_443._tcp.example.com")
        );
        assert_eq!(target("printer.local").unwrap(), name("printer.local"));
        assert_eq!(target("com").unwrap(), name("com"));
        assert_eq!(target("Bücher.de").unwrap(), name("xn--bcher-kva.de"));
        assert_eq!(
            target("8.8.8.8").unwrap(),
            Target::Ip("8.8.8.8".parse().unwrap())
        );
        assert_eq!(target("[::1]").unwrap(), Target::Ip("::1".parse().unwrap()));
        let e = target("exa mple.com").unwrap_err();
        assert_eq!(
            e.message,
            "exa mple.com isn't a valid domain name: it contains a character not allowed in domain names."
        );
        assert_eq!(target(" ").unwrap_err().code, "empty");
    }
}
