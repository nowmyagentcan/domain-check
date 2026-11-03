//! DKIM (RFC 6376 §3.6.1): the public keys at `<selector>._domainkey.<domain>`, their type and
//! size, for the selectors given or the 8 common ones.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD_INDIFFERENT as BASE64;
use serde::Serialize;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::{PublicKey, RSAPublicKey};
use x509_parser::x509::SubjectPublicKeyInfo;

use super::{Mail, finding, repeated};
use crate::Error;
use crate::dns::RecordType;
use crate::report::{Finding, Severity};

/// Selectors mail providers commonly use, tried when none is given.
pub const COMMON: [&str; 8] = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "s2",
    "dkim",
];

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Dkim {
    pub selectors: Vec<String>,
    /// The selectors came from `--dkim-selector`.
    pub given: bool,
    /// The selectors with a key, or whose lookup failed.
    pub keys: Vec<Key>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Key {
    pub selector: String,
    pub name: String,
    pub record: Option<String>,
    /// `rsa`, `ed25519` or `unknown`.
    pub key_type: &'static str,
    pub bits: Option<usize>,
    /// `p=` is empty.
    pub revoked: bool,
    /// `t=y`.
    pub testing: bool,
    pub error: Option<String>,
}

/// A `--dkim-selector`: labels of letters, digits, `-` and `_`, in lower case.
pub fn selector(raw: &str) -> Result<String, Error> {
    let s = raw.trim().to_ascii_lowercase();
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    match s.split('.').all(label) {
        true => Ok(s),
        false => Err(Error::usage(
            format!("'{raw}' isn't a valid DKIM selector."),
            "Use the s= value from a DKIM-Signature header.",
        )),
    }
}

/// The selectors given, each checked and lower-cased, each once.
pub fn selectors(raw: &[String]) -> Result<Vec<String>, Error> {
    let mut selectors: Vec<String> = Vec::new();
    for raw in raw {
        let s = selector(raw)?;
        if !selectors.contains(&s) {
            selectors.push(s);
        }
    }
    Ok(selectors)
}

/// `tag=value` pairs; values lose their folding whitespace (RFC 6376 §3.2).
fn pairs(record: &str) -> Vec<(String, String)> {
    let pairs = record.split(';').filter_map(|p| p.split_once('='));
    let bare = |v: &str| v.chars().filter(|c| !c.is_whitespace()).collect();
    pairs
        .map(|(t, v)| (t.trim().to_ascii_lowercase(), bare(v)))
        .collect()
}

/// A TXT record reads as a key record when its `v=` names DKIM, or without one when it has
/// a `p=` or `k=` tag (so an SPF or DMARC record a wildcard puts there is no key).
fn is_key(txt: &str) -> bool {
    let tags = pairs(txt);
    match tags.iter().find(|(t, _)| t == "v") {
        Some((_, v)) => v.to_ascii_lowercase().starts_with("dkim"),
        None => tags.iter().any(|(t, _)| t == "p" || t == "k"),
    }
}

/// What a key record says, and what is wrong with it.
fn key(selector: &str, name: String, record: String) -> (Key, Option<String>) {
    let tags = pairs(&record);
    let tag = |t: &str| tags.iter().find(|(n, _)| n == t).map(|(_, v)| v.as_str());
    let k = tag("k").unwrap_or("rsa").to_ascii_lowercase();
    let mut out = Key {
        selector: selector.to_string(),
        name,
        record: None,
        key_type: match k.as_str() {
            "rsa" => "rsa",
            "ed25519" => "ed25519",
            _ => "unknown",
        },
        bits: None,
        revoked: tag("p") == Some(""),
        testing: tag("t").is_some_and(|t| t.split(':').any(|f| f.eq_ignore_ascii_case("y"))),
        error: None,
    };
    let v_first = tags.first().is_some_and(|(t, _)| t == "v");
    let problem = if let Some(t) = repeated(&tags) {
        Some(format!("{t}= appears more than once"))
    } else if tag("v").is_some_and(|v| v != "DKIM1" || !v_first) {
        Some("v= isn't DKIM1".to_string())
    } else if out.key_type == "unknown" {
        Some(format!("k={k} is unknown"))
    } else {
        match tag("p") {
            None => Some("p= is missing".into()),
            Some("") => None,
            Some(p) => match BASE64.decode(p) {
                Err(_) => Some("p= isn't valid base64".into()),
                Ok(der) => {
                    out.bits = match out.key_type {
                        "ed25519" => (der.len() == 32).then_some(256),
                        _ => rsa_bits(&der),
                    };
                    out.bits.is_none().then(|| "p= isn't a public key".into())
                }
            },
        }
    };
    out.record = Some(record);
    (out, problem)
}

/// The modulus size of an RSA key, as SubjectPublicKeyInfo or a bare RSAPublicKey (RFC 6376
/// erratum 3017).
fn rsa_bits(der: &[u8]) -> Option<usize> {
    let spki = SubjectPublicKeyInfo::from_der(der).ok().map(|(_, k)| k);
    let modulus = match spki.as_ref().map(|k| k.parsed()) {
        Some(Ok(PublicKey::RSA(rsa))) => rsa.modulus,
        Some(_) => return None,
        None => RSAPublicKey::from_der(der).ok()?.1.modulus,
    };
    bits(modulus)
}

/// The bit length of an RSA modulus, leading zero bytes dropped.
pub fn bits(modulus: &[u8]) -> Option<usize> {
    let m = &modulus[modulus.iter().position(|&b| b != 0)?..];
    Some(m.len() * 8 - m[0].leading_zeros() as usize)
}

pub async fn run(mail: Arc<Mail>, given: Vec<String>) -> (Dkim, Vec<Finding>) {
    let d = mail.domain.clone();
    let (selectors, given) = match given.is_empty() {
        true => (COMMON.map(String::from).to_vec(), false),
        false => (given, true),
    };
    let names: Vec<_> = selectors
        .iter()
        .map(|s| format!("{s}._domainkey.{d}"))
        .collect();
    let questions = names.iter().map(|n| (n.clone(), RecordType::TXT)).collect();
    let answers = mail.all(questions).await;
    let mut found = Vec::new();
    let mut keys = Vec::new();
    let mut missing = Vec::new();
    for ((selector, name), answer) in selectors.iter().zip(names).zip(answers) {
        let txts = match answer {
            Ok(txts) => txts.unwrap_or_default(),
            Err(why) => {
                keys.push(Key {
                    selector: selector.clone(),
                    name,
                    record: None,
                    key_type: "unknown",
                    bits: None,
                    revoked: false,
                    testing: false,
                    error: Some(why),
                });
                continue;
            }
        };
        let Some(record) = txts.into_iter().find(|t| is_key(t)) else {
            missing.push(selector.clone());
            continue;
        };
        let (k, problem) = key(selector, name.clone(), record);
        if let Some(what) = problem {
            let message = format!("The DKIM record at {name} is invalid: {what}.");
            let hint = "Copy the record again from your mail provider.";
            found.push(finding(Severity::Error, "dkim_syntax", message, hint));
        }
        if k.revoked {
            let message = format!("The DKIM key at {name} is revoked (empty p=).");
            found.push(finding(Severity::Info, "dkim_revoked", message, ""));
        }
        if let (Some(bits @ ..2048), "rsa") = (k.bits, k.key_type) {
            let (severity, why) = match bits {
                ..1024 => (Severity::Error, "receivers reject keys under 1024"),
                _ => (Severity::Warning, "2048 is recommended"),
            };
            let message = format!("The DKIM key at {name} is RSA {bits} bits; {why} (RFC 8301).");
            let hint = "Generate a 2048-bit key under a new selector and switch to it.";
            found.push(finding(severity, "dkim_weak_key", message, hint));
        }
        if k.testing {
            let message = format!("The DKIM key at {name} has t=y (testing).");
            found.push(finding(Severity::Info, "dkim_testing", message, ""));
        }
        keys.push(k);
    }
    let hint = "Pass --dkim-selector with the s= value from a DKIM-Signature header of your mail.";
    if given {
        for s in &missing {
            let message = format!("No DKIM key at {s}._domainkey.{d}.");
            found.push(finding(Severity::Warning, "dkim_not_found", message, hint));
        }
    } else if keys.is_empty() {
        let message =
            "No DKIM key under the 8 common selectors; this doesn't mean DKIM is missing.";
        found.push(finding(Severity::Info, "dkim_not_found", message, hint));
    }
    let dkim = Dkim {
        selectors,
        given,
        keys,
    };
    (dkim, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(record: &str) -> (Key, Option<String>) {
        key("s", "s._domainkey.example.com".into(), record.into())
    }

    #[test]
    fn selectors_are_dns_labels() {
        assert_eq!(selector(" Google ").unwrap(), "google");
        assert_eq!(selector("s1.2024_a").unwrap(), "s1.2024_a");
        for bad in ["a b", "", "a..b", "-a", "a/b"] {
            let e = selector(bad).unwrap_err();
            assert_eq!(e.message, format!("'{bad}' isn't a valid DKIM selector."));
        }
    }

    #[test]
    fn key_records_say_what_is_wrong() {
        let problem = |r| read(r).1;
        assert_eq!(problem("v=DKIM2; p=AAAA"), Some("v= isn't DKIM1".into()));
        assert_eq!(problem("k=rsa; v=DKIM1; p="), Some("v= isn't DKIM1".into()));
        assert_eq!(
            problem("v=DKIM1; k=dsa; p=AAAA"),
            Some("k=dsa is unknown".into())
        );
        assert_eq!(
            problem("v=DKIM1; p=not base64!"),
            Some("p= isn't valid base64".into())
        );
        assert_eq!(
            problem("v=DKIM1; p=aGVsbG8="),
            Some("p= isn't a public key".into())
        );
        assert_eq!(
            problem("v=DKIM1; k=ed25519; p=aGVsbG8"),
            Some("p= isn't a public key".into())
        );
        assert_eq!(problem("v=DKIM1; k=rsa"), Some("p= is missing".into()));
        let ed = format!("v=DKIM1; k=ed25519; p={}", BASE64.encode([7; 32]));
        let (k, problem) = read(&ed);
        assert_eq!((k.key_type, k.bits, problem), ("ed25519", Some(256), None));
        let (k, problem) = read("v=DKIM1; t=s:y; p=");
        assert!(k.revoked && k.testing && problem.is_none());
        assert!(is_key("p=") && is_key("v=DKIM1") && is_key("v=DKIM2; p=AAAA"));
        assert!(!is_key("v=spf1 -all") && !is_key("v=DMARC1; p=none") && !is_key("hello"));
    }
}
