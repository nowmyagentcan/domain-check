//! DMARC (RFC 9989): the policy for the domain, found at `_dmarc.<domain>` or up the tree, its
//! tags, and whether outside report addresses agreed to take reports (RFC 9990 §4).

use std::sync::Arc;

use serde::Serialize;

use super::{Mail, Part, finding};
use crate::check::within;
use crate::dns::RecordType;
use crate::report::{Finding, Severity};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Dmarc {
    pub record: String,
    pub found_at: String,
    /// Found above `_dmarc.<domain>`.
    pub inherited: bool,
    pub tags: Tags,
    /// Tags RFC 9989 dropped that the record still has: `pct`, `rf`, `ri`.
    pub historic_tags: Vec<&'static str>,
    pub rua_authorized: Vec<Authorized>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Tags {
    pub p: Option<String>,
    pub sp: Option<String>,
    pub np: Option<String>,
    pub adkim: Option<String>,
    pub aspf: Option<String>,
    pub t: Option<String>,
    pub psd: Option<String>,
    pub fo: Option<String>,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Authorized {
    pub uri: String,
    /// `None` when no check is needed (the same organisation) or none could be made.
    pub authorized: Option<bool>,
}

const HISTORIC: [&str; 3] = ["pct", "rf", "ri"];

/// The names a policy is looked for at, in order (RFC 9989 §4.10): the domain, then from at
/// most 7 labels one label shorter each time, down to the TLD.
pub fn walk(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain.split('.').collect();
    let first = labels.len().min(8) - 1;
    let shorter = (1..=first)
        .rev()
        .map(|n| labels[labels.len() - n..].join("."));
    std::iter::once(domain.to_string())
        .chain(shorter)
        .map(|name| format!("_dmarc.{name}"))
        .collect()
}

/// `tag=value` pairs, tag names in lower case.
fn pairs(record: &str) -> Vec<(String, &str)> {
    let pairs = record.split(';').filter_map(|p| p.split_once('='));
    pairs
        .map(|(t, v)| (t.trim().to_ascii_lowercase(), v.trim()))
        .collect()
}

/// Whether a TXT record is a DMARC record: `Some(true)` when it starts `v=DMARC1`, `Some(false)`
/// when it starts with some other `v=DMARC`, `None` when it isn't one at all.
fn version(txt: &str) -> Option<bool> {
    let (tag, value) = pairs(txt).into_iter().next()?;
    let dmarc = tag == "v" && value.to_ascii_lowercase().starts_with("dmarc");
    dmarc.then_some(value == "DMARC1")
}

/// The policy that applies to the domain, or why there is none. `Err` when a lookup failed.
pub async fn run(mail: Arc<Mail>) -> Part<Dmarc> {
    let d = mail.domain.clone();
    let mut found = Vec::new();
    for name in walk(&d) {
        let txts = match mail.values(&name, RecordType::TXT).await {
            Ok(txts) => txts.unwrap_or_default(),
            Err(why) => return (Err(why), found),
        };
        let mut valid = Vec::new();
        for txt in txts {
            match version(&txt) {
                Some(true) => valid.push(txt),
                Some(false) => found.push(syntax(&name, "it doesn't start with v=DMARC1")),
                None => {}
            }
        }
        match valid.as_slice() {
            [] => continue,
            [record] => {
                let dmarc = read(&mail, &name, record, &mut found).await;
                return (Ok(Some(dmarc)), found);
            }
            many => {
                let message = format!(
                    "{name} has {} DMARC records, so receivers ignore all of them.",
                    many.len()
                );
                found.push(finding(
                    Severity::Error,
                    "dmarc_multiple",
                    message,
                    "Keep exactly one.",
                ));
            }
        }
    }
    let message = format!("No DMARC record for {d}.");
    let hint =
        format!("Publish _dmarc.{d} TXT \"v=DMARC1; p=none; rua=mailto:<you>\", then tighten p.");
    found.push(finding(Severity::Error, "dmarc_none", message, &hint));
    (Ok(None), found)
}

fn syntax(name: &str, what: &str) -> Finding {
    let message = format!("The DMARC record at {name} is invalid: {what}.");
    let hint = "Fix it; e.g. \"v=DMARC1; p=quarantine; rua=mailto:<you>\".";
    finding(Severity::Error, "dmarc_syntax", message, hint)
}

/// The record's tags (RFC 9989 §4.7) and the findings they make.
async fn read(mail: &Arc<Mail>, name: &str, record: &str, found: &mut Vec<Finding>) -> Dmarc {
    let d = &mail.domain;
    let mut tags = Tags::default();
    let mut historic = Vec::new();
    for (tag, value) in pairs(record) {
        let lower = value.to_ascii_lowercase();
        let one_of = |options: &[&str]| options.contains(&lower.as_str()).then(|| lower.clone());
        let policy = ["none", "quarantine", "reject"];
        let field = match tag.as_str() {
            "p" => &mut tags.p,
            "sp" => &mut tags.sp,
            "np" => &mut tags.np,
            "adkim" => &mut tags.adkim,
            "aspf" => &mut tags.aspf,
            "t" => &mut tags.t,
            "psd" => &mut tags.psd,
            "fo" => &mut tags.fo,
            "rua" | "ruf" => {
                let uris: Vec<String> = value.split(',').map(|u| u.trim().to_string()).collect();
                if uris.iter().any(|u| !u.contains(':')) {
                    found.push(syntax(name, &format!("{tag}={value} isn't valid")));
                } else if tag == "rua" {
                    tags.rua = uris;
                } else {
                    tags.ruf = uris;
                }
                continue;
            }
            _ => {
                if let Some(h) = HISTORIC.iter().find(|h| **h == tag) {
                    historic.push(*h);
                }
                continue;
            }
        };
        let checked = match tag.as_str() {
            "p" | "sp" | "np" => one_of(&policy),
            "adkim" | "aspf" => one_of(&["r", "s"]),
            "t" => one_of(&["y", "n"]),
            "psd" => one_of(&["y", "n", "u"]),
            _ => lower
                .split(':')
                .all(|o| ["0", "1", "d", "s"].contains(&o.trim()))
                .then(|| lower.clone()),
        };
        if checked.is_none() {
            let what = match tag.as_str() {
                "p" => format!("p={value} isn't none, quarantine or reject"),
                _ => format!("{tag}={value} isn't valid"),
            };
            found.push(syntax(name, &what));
        }
        *field = checked;
    }
    if tags.p.is_none() {
        // A record with report addresses but no usable policy reads as p=none (RFC 9989 §4.7).
        if !tags.rua.is_empty() {
            tags.p = Some("none".into());
        }
        if !pairs(record).iter().any(|(t, _)| t == "p") {
            found.push(syntax(name, "p= is missing"));
        }
    }

    let found_at = name.to_string();
    let inherited = found_at != format!("_dmarc.{d}");
    if inherited {
        let message = format!("No DMARC record at _dmarc.{d}; the policy at {found_at} applies.");
        found.push(finding(Severity::Info, "dmarc_inherited", message, ""));
    }
    let p = tags.p.clone().unwrap_or_default();
    if p == "none" {
        let message = "The DMARC policy is p=none, so receivers take no action on mail that fails.";
        let hint = "Move to p=quarantine, then p=reject, once the reports look clean.";
        found.push(finding(
            Severity::Warning,
            "dmarc_p_none",
            message.into(),
            hint,
        ));
    }
    if tags.sp.as_deref() == Some("none") && !p.is_empty() && p != "none" {
        let message = format!("sp=none leaves subdomains unprotected while p={p}.");
        let hint = "Remove sp, or set it to quarantine or reject.";
        found.push(finding(Severity::Warning, "dmarc_sp_none", message, hint));
    }
    if tags.t.as_deref() == Some("y") {
        let message = "t=y: the DMARC policy is in test mode, so receivers may apply one step less (RFC 9989).";
        found.push(finding(
            Severity::Info,
            "dmarc_testing",
            message.into(),
            "Remove t=y when you're ready.",
        ));
    }
    for tag in &historic {
        let message = format!("{tag}= is no longer part of DMARC (RFC 9989); receivers ignore it.");
        let hint = match *tag {
            "pct" => "Use t=y for a test phase instead.",
            _ => "",
        };
        found.push(finding(Severity::Info, "dmarc_historic_tag", message, hint));
    }
    if tags.rua.is_empty() {
        let message = "No rua= address, so nobody receives DMARC aggregate reports.";
        let hint = "Add rua=mailto:<an address you read>.";
        found.push(finding(
            Severity::Info,
            "dmarc_no_rua",
            message.into(),
            hint,
        ));
    }
    let policy_domain = found_at.trim_start_matches("_dmarc.").to_string();
    let rua_authorized = authorize(mail, &policy_domain, &tags.rua, found).await;
    Dmarc {
        record: record.to_string(),
        found_at,
        inherited,
        tags,
        historic_tags: historic,
        rua_authorized,
    }
}

/// Each report address, and whether its domain agreed to take reports for `policy` when it is
/// another organisation's: `<policy>._report._dmarc.<its domain>` (RFC 9990 §4).
async fn authorize(
    mail: &Arc<Mail>,
    policy: &str,
    rua: &[String],
    found: &mut Vec<Finding>,
) -> Vec<Authorized> {
    let outside = |uri: &str| {
        let address = uri
            .get(..7)?
            .eq_ignore_ascii_case("mailto:")
            .then(|| &uri[7..])?;
        let host = address.rsplit('@').next()?.split('!').next()?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let same = within(&host, policy) || within(policy, &host);
        (!same).then_some(host)
    };
    let hosts: Vec<_> = rua.iter().map(|u| outside(u)).collect();
    let questions = hosts
        .iter()
        .flatten()
        .map(|h| (format!("{policy}._report._dmarc.{h}"), RecordType::TXT))
        .collect();
    let mut answers = mail.all(questions).await.into_iter();
    let mut out = Vec::new();
    for (uri, host) in rua.iter().zip(hosts) {
        if !uri.to_ascii_lowercase().starts_with("mailto:") {
            let message = format!("rua= entry {uri} isn't a mailto: address.");
            found.push(finding(
                Severity::Warning,
                "dmarc_rua_scheme",
                message,
                "Use mailto:.",
            ));
        }
        let authorized = match host {
            None => None,
            Some(host) => {
                let txts = answers.next().and_then(Result::ok);
                let ok = txts.map(|t| {
                    t.unwrap_or_default()
                        .iter()
                        .any(|t| version(t) == Some(true))
                });
                if ok == Some(false) {
                    let message = format!(
                        "Reports to {uri} won't be sent: {host} hasn't published {policy}._report._dmarc.{host} (RFC 9990 §4)."
                    );
                    let hint = "Ask the report receiver to publish that record, or use an address in your own domain.";
                    found.push(finding(
                        Severity::Warning,
                        "dmarc_rua_unauthorized",
                        message,
                        hint,
                    ));
                }
                ok
            }
        };
        out.push(Authorized {
            uri: uri.clone(),
            authorized,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tree_walk_asks_at_most_8_names() {
        assert_eq!(walk("com"), ["_dmarc.com"]);
        assert_eq!(
            walk("mail.example.com"),
            [
                "_dmarc.mail.example.com",
                "_dmarc.example.com",
                "_dmarc.com"
            ]
        );
        let eight = walk("a.b.c.d.e.f.example.com");
        assert_eq!(eight.len(), 8);
        assert_eq!(eight[1], "_dmarc.b.c.d.e.f.example.com");
        // The example of RFC 9989 §4.10.
        assert_eq!(
            walk("a.b.c.d.e.f.g.h.i.j.mail.example.com"),
            [
                "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
                "_dmarc.g.h.i.j.mail.example.com",
                "_dmarc.h.i.j.mail.example.com",
                "_dmarc.i.j.mail.example.com",
                "_dmarc.j.mail.example.com",
                "_dmarc.mail.example.com",
                "_dmarc.example.com",
                "_dmarc.com",
            ]
        );
    }

    #[test]
    fn only_v_dmarc1_first_makes_a_dmarc_record() {
        assert_eq!(version("v=DMARC1; p=none"), Some(true));
        assert_eq!(version(" v = DMARC1 ;p=none"), Some(true));
        assert_eq!(version("v=dmarc1; p=none"), Some(false));
        assert_eq!(version("v=DMARC2; p=none"), Some(false));
        assert_eq!(version("p=none; v=DMARC1"), None);
        assert_eq!(version("v=spf1 -all"), None);
    }
}
