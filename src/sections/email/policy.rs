//! The records that ask senders for more: MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and BIMI
//! (draft-brand-indicators-for-message-identification-14).

use std::sync::Arc;

use serde::Serialize;

use super::{Email, Mail, Part, finding};
use crate::dns::RecordType;
use crate::net::{self, Failed};
use crate::report::{Check, Finding, Severity};
use crate::sections::tls::private;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MtaSts {
    pub record: String,
    /// The policy's `id=`, when valid.
    pub id: Option<String>,
    /// Fetched only when the record is valid.
    pub policy: Option<Policy>,
}

/// The policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` (RFC 8461 §3.2).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Policy {
    pub url: String,
    /// `enforce`, `testing` or `none`.
    pub mode: Option<String>,
    pub mx: Vec<String>,
    pub max_age: Option<u64>,
    /// Why it couldn't be loaded, or what is wrong with it.
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TlsRpt {
    pub record: String,
    pub rua: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Bimi {
    pub record: String,
    /// The `l=` logo URL; `None` when empty (declined) or not https.
    pub logo: Option<String>,
    /// The `a=` mark certificate URL.
    pub certificate: Option<String>,
    pub logo_check: Option<LogoCheck>,
    pub certificate_check: Option<CertificateCheck>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LogoCheck {
    pub fetched: bool,
    pub content_type: Option<String>,
    /// SVG with `baseProfile="tiny-ps"`, the profile BIMI asks for.
    pub tiny_ps: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CertificateCheck {
    pub fetched: bool,
    pub pem: bool,
    pub error: Option<String>,
}

/// Why a fetch got no body.
enum Fetch {
    Status(u16),
    Failed(Failed),
}

/// One GET on a blocking thread, given up with the section: the content type and the body up
/// to `limit` bytes. A redirect isn't followed; it is its status.
async fn fetch(mail: &Mail, url: &str, limit: u64) -> Result<(Option<String>, Vec<u8>), Fetch> {
    let (net, url, until) = (
        Arc::clone(&mail.net),
        url.to_string(),
        mail.until.into_std(),
    );
    let task = tokio::task::spawn_blocking(move || {
        let mut r = net.get(&url, until).map_err(Fetch::Failed)?;
        match r.status().as_u16() {
            200 => {}
            status => return Err(Fetch::Status(status)),
        }
        let kind = r.headers().get("content-type");
        let kind = kind.map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
        let body = net::body(&mut r, limit).map_err(Fetch::Failed)?;
        Ok((kind, body))
    });
    crate::dns::wait(task).await
}

impl Fetch {
    /// The reason in words.
    fn why(&self) -> String {
        match self {
            Fetch::Status(status) => format!("HTTP {status}"),
            Fetch::Failed(f) => f.to_string(),
        }
    }

    /// The `private_address` finding when the host was refused for its address.
    fn refused(&self) -> Option<Finding> {
        match self {
            Fetch::Failed(Failed::Private { host, address }) => {
                Some(private(Check::Email, host, *address))
            }
            _ => None,
        }
    }
}

/// RFC 8461 §4.1: an `mx` pattern names the host, or `*.` covers exactly its first label.
fn covers(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(rest) => host.split_once('.').is_some_and(|(_, tail)| tail == rest),
        None => pattern == host,
    }
}

/// The policy file's fields, and what is wrong with them.
fn read_policy(policy: &mut Policy, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut version = None;
    let mut seen = Vec::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        // Only mx may repeat (RFC 8461 §3.2): a second mode or max_age leaves the policy unclear.
        if matches!(key, "version" | "mode" | "max_age") && seen.contains(&key) {
            problems.push(format!("it has more than one {key} line"));
        }
        seen.push(key);
        match key {
            "version" => version = Some(value.to_string()),
            "mode" => policy.mode = Some(value.to_string()),
            "mx" => policy.mx.push(value.to_string()),
            "max_age" => match value.parse().ok().filter(|&n| n <= 31_557_600) {
                Some(n) => policy.max_age = Some(n),
                None => problems.push(format!("max_age {value} isn't a number from 0 to 31557600")),
            },
            _ => {}
        }
    }
    if version.as_deref() != Some("STSv1") {
        problems.insert(0, "version isn't STSv1".into());
    }
    match policy.mode.as_deref() {
        Some("enforce" | "testing" | "none") => {}
        Some(mode) => problems.push(format!("mode {mode} isn't enforce, testing or none")),
        None => problems.push("it has no mode line".into()),
    }
    if policy.mx.is_empty() && policy.mode.as_deref() != Some("none") {
        problems.push("it has no mx line".into());
    }
    if policy.max_age.is_none() && !problems.iter().any(|p| p.starts_with("max_age")) {
        problems.push("it has no max_age line".into());
    }
    problems
}

/// The MTA-STS policy for the domain, loaded as RFC 8461 §3.3 says: https, no redirects,
/// 200 only, a certificate valid for the policy host, at most 64 KB.
async fn policy(mail: &Mail, found: &mut Vec<Finding>) -> Policy {
    let host = format!("mta-sts.{}", mail.domain);
    let url = format!("https://{host}/.well-known/mta-sts.txt");
    let mut policy = Policy {
        url: url.clone(),
        ..Policy::default()
    };
    let text = match fetch(mail, &url, 64 * 1024).await {
        Ok((_, body)) => String::from_utf8_lossy(&body).into_owned(),
        Err(f) => {
            let why = match &f {
                Fetch::Status(300..400) => "it redirects, which MTA-STS forbids".into(),
                Fetch::Failed(Failed::Certificate(_)) => {
                    format!("the certificate isn't valid for {host}")
                }
                Fetch::Failed(Failed::Connect(why) | Failed::Tls(why)) => {
                    format!("connection failed: {why}")
                }
                f => f.why(),
            };
            let message = format!("The MTA-STS policy at {url} couldn't be loaded: {why}.");
            let hint = "Senders that already cached the policy keep using it; fix the policy host.";
            let unavailable = finding(Severity::Error, "mta_sts_policy_unavailable", message, hint);
            found.push(f.refused().unwrap_or(unavailable));
            policy.error = Some(why);
            return policy;
        }
    };
    let problems = read_policy(&mut policy, &text);
    for what in &problems {
        let message = format!("The MTA-STS policy is invalid: {what}.");
        let hint = "See RFC 8461 §3.2 for the format.";
        found.push(finding(
            Severity::Error,
            "mta_sts_policy_syntax",
            message,
            hint,
        ));
    }
    if problems.is_empty() && policy.mode.as_deref() == Some("testing") {
        let message = "MTA-STS is in testing mode: failures are reported, not enforced.";
        found.push(finding(Severity::Info, "mta_sts_testing", message, ""));
    }
    policy.error = (!problems.is_empty()).then(|| problems.join("; "));
    policy
}

/// Adds `f` unless the same finding is there already (the logo and the certificate on one
/// refused host).
fn once(found: &mut Vec<Finding>, f: Finding) {
    if !found.contains(&f) {
        found.push(f);
    }
}

/// The logo (SVG Tiny PS, at most 1 MiB) and the mark certificate (PEM, at most 64 KB).
async fn bimi_files(mail: &Mail, bimi: &mut Bimi, found: &mut Vec<Finding>) {
    if let Some(url) = bimi.logo.clone() {
        let check = match fetch(mail, &url, 1 << 20).await {
            Ok((kind, body)) => {
                let svg = kind.as_deref().is_some_and(|k| k.contains("svg"));
                let tiny = String::from_utf8_lossy(&body).contains("baseProfile=\"tiny-ps\"");
                LogoCheck {
                    fetched: true,
                    content_type: kind,
                    tiny_ps: svg && tiny,
                    error: None,
                }
            }
            Err(f) => {
                let why = f.why();
                let message = format!("The BIMI logo at {url} couldn't be loaded: {why}.");
                let unavailable = finding(Severity::Warning, "bimi_logo_unavailable", message, "");
                once(found, f.refused().unwrap_or(unavailable));
                LogoCheck {
                    fetched: false,
                    content_type: None,
                    tiny_ps: false,
                    error: Some(why),
                }
            }
        };
        if check.fetched && !check.tiny_ps {
            let message = "The BIMI logo isn't SVG Tiny PS (no baseProfile=\"tiny-ps\").";
            let hint = "Export it as SVG Tiny Portable/Secure.";
            found.push(finding(
                Severity::Warning,
                "bimi_logo_format",
                message,
                hint,
            ));
        }
        bimi.logo_check = Some(check);
    }
    if let Some(url) = bimi.certificate.clone() {
        let got = fetch(mail, &url, 64 * 1024).await;
        let pem = got.as_ref().is_ok_and(|(_, body)| {
            String::from_utf8_lossy(body).contains("-----BEGIN CERTIFICATE-----")
        });
        let why = match &got {
            Ok(_) => (!pem).then(|| "it holds no PEM certificate".to_string()),
            Err(f) => Some(f.why()),
        };
        if let Some(why) = &why {
            let message =
                format!("The BIMI certificate at {url} couldn't be loaded or isn't PEM: {why}.");
            let unavailable = finding(
                Severity::Warning,
                "bimi_certificate_unavailable",
                message,
                "",
            );
            let refused = got.as_ref().err().and_then(Fetch::refused);
            once(found, refused.unwrap_or(unavailable));
        }
        bimi.certificate_check = Some(CertificateCheck {
            fetched: got.is_ok(),
            pem,
            error: why,
        });
    }
}

/// The TXT records at `name` that start with `version`; one that only looks like it (another
/// case, another version) is reported as `what is wrong` in a finding.
async fn records(
    mail: &Mail,
    name: &str,
    version: &str,
    syntax: impl Fn(String) -> Finding,
    found: &mut Vec<Finding>,
) -> Result<Vec<String>, String> {
    let txts = mail
        .values(name, RecordType::TXT)
        .await?
        .unwrap_or_default();
    let prefix = &version[..version.len() - 1];
    let mut kept = Vec::new();
    for txt in txts {
        if txt.starts_with(version) {
            kept.push(txt);
        } else if txt
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            found.push(syntax(format!("it doesn't start with {version}")));
        }
    }
    if kept.len() > 1 {
        found.push(syntax(format!(
            "there are {} {version} records",
            kept.len()
        )));
    }
    Ok(kept)
}

/// `tag=value` pairs after the version, tag names in lower case.
fn pairs(record: &str) -> Vec<(String, &str)> {
    let pairs = record.split(';').skip(1).filter_map(|p| p.split_once('='));
    pairs
        .map(|(t, v)| (t.trim().to_ascii_lowercase(), v.trim()))
        .collect()
}

fn tag<'a>(pairs: &[(String, &'a str)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(t, _)| t == name).map(|(_, v)| *v)
}

pub async fn mta_sts(mail: Arc<Mail>) -> Part<MtaSts> {
    let mut found = Vec::new();
    let syntax = |what: String| {
        let message = format!("The _mta-sts record is invalid: {what}.");
        let hint = "It should look like \"v=STSv1; id=20261030\".";
        finding(Severity::Error, "mta_sts_syntax", message, hint)
    };
    let name = format!("_mta-sts.{}", mail.domain);
    let kept = match records(&mail, &name, "v=STSv1", &syntax, &mut found).await {
        Ok(kept) => kept,
        Err(why) => return (Err(why), found),
    };
    let Some(record) = kept.into_iter().next() else {
        return (Ok(None), found);
    };
    let id = tag(&pairs(&record), "id")
        .filter(|id| (1..=32).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric()));
    if id.is_none() {
        found.push(syntax(
            "it has no valid id= (1 to 32 letters and digits)".into(),
        ));
    }
    let id = id.map(String::from);
    let policy = match id {
        Some(_) => Some(policy(&mail, &mut found).await),
        None => None,
    };
    (Ok(Some(MtaSts { record, id, policy })), found)
}

pub async fn tls_rpt(mail: Arc<Mail>) -> Part<TlsRpt> {
    let mut found = Vec::new();
    let syntax = |what: String| {
        let message = format!("The TLS-RPT record is invalid: {what}.");
        finding(Severity::Error, "tls_rpt_syntax", message, "")
    };
    let name = format!("_smtp._tls.{}", mail.domain);
    let kept = match records(&mail, &name, "v=TLSRPTv1", &syntax, &mut found).await {
        Ok(kept) => kept,
        Err(why) => return (Err(why), found),
    };
    let Some(record) = kept.into_iter().next() else {
        return (Ok(None), found);
    };
    let rua: Vec<String> = match tag(&pairs(&record), "rua") {
        Some(rua) => rua.split(',').map(|u| u.trim().to_string()).collect(),
        None => {
            found.push(syntax("rua= is missing".into()));
            Vec::new()
        }
    };
    for uri in &rua {
        let lower = uri.to_ascii_lowercase();
        if !lower.starts_with("mailto:") && !lower.starts_with("https:") {
            found.push(syntax(format!("{uri} isn't a mailto: or https: address")));
        }
    }
    (Ok(Some(TlsRpt { record, rua })), found)
}

pub async fn bimi(mail: Arc<Mail>) -> Part<Bimi> {
    let mut found = Vec::new();
    let syntax = |what: String| {
        let message = format!("The BIMI record is invalid: {what}.");
        finding(Severity::Error, "bimi_syntax", message, "")
    };
    let name = format!("default._bimi.{}", mail.domain);
    let kept = match records(&mail, &name, "v=BIMI1", &syntax, &mut found).await {
        Ok(kept) => kept,
        Err(why) => return (Err(why), found),
    };
    let Some(record) = kept.into_iter().next() else {
        return (Ok(None), found);
    };
    let tags = pairs(&record);
    let mut url = |t: &str| match tag(&tags, t).unwrap_or_default() {
        "" => None,
        v if v
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://")) =>
        {
            Some(v.to_string())
        }
        _ => {
            found.push(syntax(format!("{t}= isn't https")));
            None
        }
    };
    let (logo, certificate) = (url("l"), url("a"));
    let mut bimi = Bimi {
        record,
        logo,
        certificate,
        logo_check: None,
        certificate_check: None,
    };
    bimi_files(&mail, &mut bimi, &mut found).await;
    (Ok(Some(bimi)), found)
}

/// The findings that need several parts: what is missing given the MX and MTA-STS, and
/// whether DMARC is strict enough for a BIMI logo.
pub fn across(e: &Email, d: &str) -> Vec<Finding> {
    let mut found = Vec::new();
    let receives = !matches!(e.mx.kind, Some("null_mx" | "none"));
    let looked = |part: &str| e.errors.get(part).is_none();
    if receives && e.mta_sts.is_none() && looked("mta_sts") {
        let message = format!(
            "No MTA-STS policy, so servers sending mail to {d} may fall back to unencrypted delivery."
        );
        let hint = format!(
            "Publish _mta-sts.{d} TXT and a policy at https://mta-sts.{d}/.well-known/mta-sts.txt."
        );
        found.push(finding(Severity::Info, "mta_sts_none", message, &hint));
    }
    if receives && e.tls_rpt.is_none() && looked("tls_rpt") {
        let severity = match e.mta_sts {
            Some(_) => Severity::Warning,
            None => Severity::Info,
        };
        let message = "No TLS-RPT record, so nobody hears about failed encrypted deliveries.";
        let hint = format!("Publish _smtp._tls.{d} TXT \"v=TLSRPTv1; rua=mailto:<you>\".");
        found.push(finding(severity, "tls_rpt_none", message, &hint));
    }
    let policy = e.mta_sts.as_ref().and_then(|m| m.policy.as_ref());
    let enforced = policy
        .filter(|p| p.error.is_none() && matches!(p.mode.as_deref(), Some("enforce" | "testing")));
    if let Some(p) = enforced {
        let hosts =
            e.mx.hosts
                .iter()
                .filter(|h| h.host.parse::<std::net::IpAddr>().is_err());
        for h in hosts.filter(|h| !p.mx.iter().any(|m| covers(m, &h.host))) {
            let host = &h.host;
            let message = format!(
                "MX host {host} doesn't match the MTA-STS policy's mx lines, so senders in enforce mode will refuse it."
            );
            let hint = format!(
                "Add \"mx: {host}\" (or a matching *. pattern) to the policy and change its id."
            );
            found.push(finding(
                Severity::Error,
                "mta_sts_mx_not_covered",
                message,
                &hint,
            ));
        }
    }
    let Some(bimi) = &e.bimi else {
        return found;
    };
    if tag(&pairs(&bimi.record), "l").is_none_or(str::is_empty) {
        let message = "The BIMI record declines a logo (empty l=).";
        found.push(finding(Severity::Info, "bimi_declined", message, ""));
        return found;
    }
    let policy = match &e.dmarc {
        None if looked("dmarc") => Some("missing".to_string()),
        None => None,
        Some(dmarc) => {
            let t = &dmarc.tags;
            let p = t.p.as_deref().unwrap_or("none");
            let mut weak = vec![format!("p={p}")];
            if t.sp.as_deref() == Some("none") {
                weak.push("sp=none".into());
            }
            if t.t.as_deref() == Some("y") {
                weak.push("t=y".into());
            }
            let enforced = matches!(p, "quarantine" | "reject") && weak.len() == 1;
            (!enforced).then(|| weak.join("; "))
        }
    };
    if let Some(policy) = policy {
        let message = format!(
            "BIMI logos need DMARC p=quarantine or p=reject without test mode; the policy is {policy}."
        );
        let hint = "Tighten the DMARC policy first.";
        found.push(finding(
            Severity::Warning,
            "bimi_dmarc_not_enforced",
            message,
            hint,
        ));
    }
    if bimi.certificate.is_none() {
        let message = "No mark certificate (a=); some mailbox providers show BIMI logos only with a VMC or CMC.";
        found.push(finding(Severity::Info, "bimi_no_certificate", message, ""));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mx_patterns_cover_a_host_or_one_first_label() {
        assert!(covers("mx1.example.net", "mx1.example.net"));
        assert!(covers("MX1.Example.net.", "mx1.example.net"));
        assert!(covers("*.example.net", "mx1.example.net"));
        assert!(!covers("*.example.net", "a.mx1.example.net"));
        assert!(!covers("*.example.net", "example.net"));
        assert!(!covers("mx1.example.net", "mx2.example.net"));
    }

    #[test]
    fn policy_files_say_what_is_wrong() {
        let read = |text: &str| {
            let mut p = Policy::default();
            let problems = read_policy(&mut p, text);
            (p, problems)
        };
        let (p, problems) = read("version: STSv1\nmode: none\nmax_age: 0\n");
        assert_eq!(
            (p.mode.as_deref(), p.max_age, problems.len()),
            (Some("none"), Some(0), 0)
        );
        let (_, problems) = read("mode: enforce\nmx: a.example.net\nmax_age: 31557601\n");
        assert_eq!(
            problems,
            [
                "version isn't STSv1",
                "max_age 31557601 isn't a number from 0 to 31557600"
            ]
        );
        let (_, problems) = read("version: STSv1\nmx: a.example.net\n");
        assert_eq!(problems, ["it has no mode line", "it has no max_age line"]);
    }
}
