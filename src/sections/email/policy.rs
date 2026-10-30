//! The records that ask senders for more: MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and BIMI
//! (draft-brand-indicators-for-message-identification-14).

use std::sync::Arc;

use serde::Serialize;

use super::{Email, Mail, Part, finding};
use crate::dns::RecordType;
use crate::report::{Finding, Severity};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MtaSts {
    pub record: String,
    /// The policy's `id=`, when valid.
    pub id: Option<String>,
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
    (Ok(Some(MtaSts { record, id })), found)
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
    let bimi = Bimi {
        record,
        logo,
        certificate,
    };
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
