//! The `email` section: where mail for the domain goes (MX), and the records that say who may
//! send it and how it must travel.

use std::net::IpAddr;
use std::sync::Arc;

use serde::Serialize;

use crate::check::{Cx, Facts};
use crate::dns::{self, Answer, Failure, RecordType, Resolver, ResponseCode};
use crate::report::{Check, Finding, Section, Severity, Status};

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Email {
    pub mx: Mx,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Mx {
    /// `mx`, `null_mx`, `implicit` or `none`; `None` when the MX lookup failed.
    pub kind: Option<&'static str>,
    pub hosts: Vec<MxHost>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MxHost {
    pub preference: u16,
    pub host: String,
    pub addresses: Vec<String>,
    /// The host name is itself a CNAME (RFC 2181 §10.3).
    pub cname: bool,
    pub error: Option<String>,
}

/// The section's lookups: through the resolver, each given up once the budget runs out.
pub struct Mail {
    pub resolver: Arc<Resolver>,
    pub domain: String,
    until: tokio::time::Instant,
}

/// The values of one type at a name: `None` for NXDOMAIN, `Err` with why the lookup failed.
pub type Found = Result<Option<Vec<String>>, String>;

impl Mail {
    pub async fn ask(&self, name: &str, t: RecordType) -> Answer {
        let lookup = self.resolver.lookup(name, t);
        tokio::time::timeout_at(self.until, lookup)
            .await
            .unwrap_or(Err(Failure::Timeout))
    }

    pub async fn values(&self, name: &str, t: RecordType) -> Found {
        got(&self.ask(name, t).await, t)
    }
}

pub fn got(a: &Answer, t: RecordType) -> Found {
    let m = a.as_ref().map_err(|e| e.to_string())?;
    match m.metadata.response_code {
        ResponseCode::NoError => Ok(Some(
            dns::records(m, t).map(|r| dns::value(&r.data)).collect(),
        )),
        ResponseCode::NXDomain => Ok(None),
        code => Err(dns::rcode(code)),
    }
}

pub fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    Finding::new(Check::Email, severity, code, message, hint)
}

pub async fn run(cx: &Cx, facts: &Facts) -> (Section<Email>, Vec<Finding>) {
    let d = cx.domain.as_str();
    if facts.unanswered().is_some() {
        let reason = "No DNS answer, so this check couldn't run.";
        return (Section::not(Status::Unavailable, reason), Vec::new());
    }
    if !facts.exists(d) {
        let reason = format!("{d} doesn't exist in DNS.");
        return (Section::not(Status::Skipped, reason), Vec::new());
    }
    let mail = Arc::new(Mail {
        resolver: Arc::clone(&cx.resolver),
        domain: d.to_string(),
        until: cx.until(Check::Email).into(),
    });
    let mut found = Vec::new();
    let mx = mx(&mail, facts, &mut found).await;
    (Section::ok(Email { mx }), found)
}

/// The MX hosts and their addresses; a domain without MX records gets mail at its own
/// address (RFC 5321 §5.1), unless it publishes the null MX (RFC 7505).
async fn mx(mail: &Arc<Mail>, facts: &Facts, found: &mut Vec<Finding>) -> Mx {
    let d = mail.domain.as_str();
    let has = |t| {
        let a = facts.answer(t);
        a.is_some_and(|a| {
            a.as_ref()
                .is_ok_and(|m| dns::records(m, t).next().is_some())
        })
    };
    let answer = facts.answer(RecordType::MX).cloned();
    let answer = answer.unwrap_or(Err(Failure::Timeout));
    let values = match got(&answer, RecordType::MX).map(Option::unwrap_or_default) {
        Ok(v) => v,
        Err(why) => {
            return Mx {
                error: Some(why),
                ..Mx::default()
            };
        }
    };
    let mut records: Vec<(u16, String)> = values
        .iter()
        .filter_map(|v| {
            let (pref, host) = v.split_once(' ')?;
            Some((pref.parse().ok()?, host.to_string()))
        })
        .collect();
    records.sort();
    let kind = match records.as_slice() {
        [(0, host)] if host == "." => {
            let message = format!("{d} says it accepts no email (null MX).");
            found.push(finding(Severity::Info, "null_mx", message, ""));
            return Mx {
                kind: Some("null_mx"),
                ..Mx::default()
            };
        }
        [_, ..] => "mx",
        [] if has(RecordType::A) || has(RecordType::AAAA) => {
            let message = format!("No MX record: mail for {d} would go to its A/AAAA address.");
            let hint = "Publish MX records, or a null MX (0 .) if the domain takes no email.";
            found.push(finding(Severity::Info, "mx_implicit", message, hint));
            "implicit"
        }
        [] => {
            let message = format!("No MX record and no address: {d} can't receive email.");
            let hint = "If that's intended, publish a null MX (0 .) so senders stop trying.";
            found.push(finding(Severity::Info, "mx_none", message, hint));
            "none"
        }
    };
    let names: Vec<_> = records
        .iter()
        .filter(|(_, host)| host.parse::<IpAddr>().is_err())
        .flat_map(|(_, host)| [RecordType::A, RecordType::AAAA].map(|t| (host.clone(), t)))
        .collect();
    let answers = dns::join(names.iter().cloned().map(|(name, t)| {
        let m = Arc::clone(mail);
        async move { m.ask(&name, t).await }
    }))
    .await;
    let mut hosts = Vec::new();
    for (preference, host) in records {
        if host.parse::<IpAddr>().is_ok() {
            let message =
                format!("An MX record holds an IP address ({host}) instead of a host name.");
            let hint = "Create a host name for that address and use it in the MX record.";
            found.push(finding(Severity::Error, "mx_ip", message, hint));
            hosts.push(MxHost {
                preference,
                host,
                addresses: Vec::new(),
                cname: false,
                error: None,
            });
            continue;
        }
        let mine = names.iter().zip(&answers).filter(|((n, _), _)| *n == host);
        let mut addresses = Vec::new();
        let (mut cname, mut error) = (false, None);
        for ((_, t), a) in mine {
            cname |= a.as_ref().is_ok_and(|m| dns::cname(m, &host).is_some());
            match got(a, *t) {
                Ok(v) => addresses.extend(v.into_iter().flatten()),
                Err(why) => error = error.or(Some(why)),
            }
        }
        if cname {
            let message = format!(
                "MX host {host} is a CNAME; MX records must name a host with its own address (RFC 2181 §10.3)."
            );
            let hint = "Point the MX at the CNAME's target.";
            found.push(finding(Severity::Warning, "mx_cname", message, hint));
        }
        if addresses.is_empty() && error.is_none() {
            let message = format!(
                "MX host {host} has no A or AAAA record, so mail can't be delivered to it."
            );
            let hint = "Fix the host name or add its address records.";
            found.push(finding(Severity::Error, "mx_unresolvable", message, hint));
        }
        hosts.push(MxHost {
            preference,
            host,
            addresses,
            cname,
            error,
        });
    }
    Mx {
        kind: Some(kind),
        hosts,
        error: None,
    }
}
