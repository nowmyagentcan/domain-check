//! The report every face prints: findings sorted problems first, each section's status,
//! the counts, and the exit code they make.

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::input::Domain;
use crate::sections::dns::Dns;
use crate::sections::propagation::Propagation;
use crate::{Error, RDAP_BOOTSTRAP};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// The sections, in report order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Check {
    Dns,
    Propagation,
    Email,
    Rdap,
    Tls,
    Http,
}

impl Check {
    /// The name `--checks` takes.
    pub fn key(self) -> &'static str {
        match self {
            Check::Dns => "dns",
            Check::Propagation => "propagation",
            Check::Email => "email",
            Check::Rdap => "rdap",
            Check::Tls => "tls",
            Check::Http => "http",
        }
    }

    /// The section's name in the text report.
    pub fn title(self) -> &'static str {
        match self {
            Check::Dns => "DNS",
            Check::Propagation => "Propagation",
            Check::Email => "Email",
            Check::Rdap => "Registration",
            Check::Tls => "Certificate",
            Check::Http => "Web",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub check: Check,
    pub message: String,
    pub hint: Option<String>,
}

impl Finding {
    /// A finding; an empty `hint` means it has none.
    pub fn new(
        check: Check,
        severity: Severity,
        code: &'static str,
        message: impl Into<String>,
        hint: impl Into<String>,
    ) -> Finding {
        let hint = hint.into();
        Finding {
            code,
            severity,
            check,
            message: message.into(),
            hint: (!hint.is_empty()).then_some(hint),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Unavailable,
    RateLimited,
    Skipped,
}

impl Status {
    /// How the text report names it.
    pub fn text(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Unavailable => "unavailable",
            Status::RateLimited => "rate limited",
            Status::Skipped => "skipped",
        }
    }
}

/// A section's status, why it isn't `ok`, and its fields: all `null` unless it is `ok`.
#[derive(Clone, Debug, PartialEq)]
pub struct Section<T> {
    pub status: Status,
    pub reason: Option<String>,
    pub data: Option<T>,
}

impl<T> Section<T> {
    pub fn ok(data: T) -> Section<T> {
        Section {
            status: Status::Ok,
            reason: None,
            data: Some(data),
        }
    }

    pub fn not(status: Status, reason: impl Into<String>) -> Section<T> {
        Section {
            status,
            reason: Some(reason.into()),
            data: None,
        }
    }
}

impl<T: Serialize + Default> Serialize for Section<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Out<'a, D> {
            status: Status,
            reason: &'a Option<String>,
            #[serde(flatten)]
            data: D,
        }
        let (status, reason) = (self.status, &self.reason);
        match &self.data {
            Some(data) => Out {
                status,
                reason,
                data,
            }
            .serialize(s),
            None => {
                let fields =
                    serde_json::to_value(T::default()).map_err(serde::ser::Error::custom)?;
                let nulls: Map<String, Value> = match fields {
                    Value::Object(m) => m.into_iter().map(|(k, _)| (k, Value::Null)).collect(),
                    _ => Map::new(),
                };
                Out {
                    status,
                    reason,
                    data: nulls,
                }
                .serialize(s)
            }
        }
    }
}

/// A JSON object whose keys keep their order (record types in the order the spec lists).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Keyed<T>(pub Vec<(String, T)>);

impl<T> Keyed<T> {
    pub fn get(&self, key: &str) -> Option<&T> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

impl<T: Serialize> Serialize for Keyed<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(self.0.iter().map(|(k, v)| (k, v)))
    }
}

/// Every section of a report; all `null` for an invalid input.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Sections {
    pub dns: Option<Section<Dns>>,
    pub propagation: Option<Section<Propagation>>,
}

impl Sections {
    /// Marks `check`'s section as not run, and why.
    pub fn not(&mut self, check: Check, status: Status, reason: &str) {
        match check {
            Check::Dns => self.dns = Some(Section::not(status, reason)),
            Check::Propagation => self.propagation = Some(Section::not(status, reason)),
            Check::Email | Check::Rdap | Check::Tls | Check::Http => {}
        }
    }

    /// Sections that came back `unavailable` or `rate_limited`.
    pub fn unavailable(&self) -> usize {
        let statuses = [
            self.dns.as_ref().map(|s| s.status),
            self.propagation.as_ref().map(|s| s.status),
        ];
        statuses
            .into_iter()
            .filter(|s| matches!(s, Some(Status::Unavailable | Status::RateLimited)))
            .count()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize)]
pub struct Counts {
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
}

impl Counts {
    fn of(findings: &[Finding]) -> Counts {
        let n = |s| findings.iter().filter(|f| f.severity == s).count();
        Counts {
            errors: n(Severity::Error),
            warnings: n(Severity::Warning),
            info: n(Severity::Info),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub input: String,
    pub domain: Option<String>,
    pub unicode: Option<String>,
    pub checked_at: String,
    pub error: Option<Error>,
    pub counts: Counts,
    pub findings: Vec<Finding>,
    #[serde(flatten)]
    pub sections: Sections,
    /// Requested sections that came back `unavailable` or `rate_limited`.
    #[serde(skip)]
    pub unavailable: usize,
}

impl Report {
    pub fn invalid(input: &str, checked_at: String, error: Error) -> Report {
        Report {
            input: input.to_string(),
            domain: None,
            unicode: None,
            checked_at,
            error: Some(error),
            counts: Counts::default(),
            findings: Vec::new(),
            sections: Sections::default(),
            unavailable: 0,
        }
    }

    /// A checked domain's report, its findings sorted by severity, then check, then code.
    pub fn checked(
        input: &str,
        domain: &Domain,
        checked_at: String,
        mut findings: Vec<Finding>,
        sections: Sections,
    ) -> Report {
        findings.sort_by_key(|f| (f.severity, f.check, f.code));
        Report {
            input: input.to_string(),
            domain: Some(domain.ascii.clone()),
            unicode: Some(domain.unicode.clone()),
            checked_at,
            error: None,
            counts: Counts::of(&findings),
            findings,
            unavailable: sections.unavailable(),
            sections,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Summary {
    pub domains: usize,
    pub errors: usize,
    pub warnings: usize,
    pub info: usize,
    pub unavailable: usize,
}

#[derive(Debug, PartialEq, Serialize)]
pub struct Data {
    pub version: &'static str,
    pub rdap_bootstrap: &'static str,
}

/// What `check --json` prints, the page's API answers and the MCP tool returns.
#[derive(Debug, PartialEq, Serialize)]
pub struct Output {
    pub reports: Vec<Report>,
    pub summary: Summary,
    pub data: Data,
}

impl Output {
    pub fn new(reports: Vec<Report>) -> Output {
        let sum = |f: fn(&Report) -> usize| reports.iter().map(f).sum();
        let summary = Summary {
            domains: reports.len(),
            errors: sum(|r| r.counts.errors),
            warnings: sum(|r| r.counts.warnings),
            info: sum(|r| r.counts.info),
            unavailable: sum(|r| r.unavailable),
        };
        let data = Data {
            version: env!("CARGO_PKG_VERSION"),
            rdap_bootstrap: RDAP_BOOTSTRAP,
        };
        Output {
            reports,
            summary,
            data,
        }
    }

    /// 1 for an error finding or an invalid input, else 3 when a section couldn't run, else
    /// 0; warnings and info never change it.
    pub fn exit_code(&self) -> u8 {
        if self
            .reports
            .iter()
            .any(|r| r.error.is_some() || r.counts.errors > 0)
        {
            1
        } else if self.summary.unavailable > 0 {
            3
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn finding(code: &'static str, severity: Severity, check: Check) -> Finding {
        Finding {
            code,
            severity,
            check,
            message: format!("{code} message."),
            hint: None,
        }
    }

    fn example() -> Domain {
        crate::input::domain("https://Example.COM/shop").unwrap()
    }

    /// A report whose dns section is unavailable when `down` is set.
    fn report(findings: Vec<Finding>, down: bool) -> Report {
        let at = "2026-10-30T15:40:12Z".to_string();
        let sections = Sections {
            dns: down.then(|| Section::not(Status::Unavailable, "Stopped after 30 s.")),
            ..Sections::default()
        };
        Report::checked(
            "https://Example.COM/shop",
            &example(),
            at,
            findings,
            sections,
        )
    }

    #[test]
    fn findings_sort_by_severity_then_check_then_code() {
        use Check::*;
        use Severity::*;
        let r = report(
            vec![
                finding("no_caa", Info, Dns),
                finding("cert_expiring", Warning, Tls),
                finding("spf_none", Warning, Email),
                finding("dmarc_none", Error, Email),
                finding("csp_missing", Warning, Http),
                finding("cname_loop", Error, Dns),
                finding("dmarc_p_none", Warning, Email),
            ],
            false,
        );
        let order: Vec<_> = r.findings.iter().map(|f| f.code).collect();
        assert_eq!(
            order,
            [
                "cname_loop",
                "dmarc_none",
                "dmarc_p_none",
                "spf_none",
                "cert_expiring",
                "csp_missing",
                "no_caa"
            ]
        );
        assert_eq!(
            r.counts,
            Counts {
                errors: 2,
                warnings: 4,
                info: 1
            }
        );
    }

    #[test]
    fn the_output_has_the_documented_shape() {
        let mut dmarc = finding("dmarc_none", Severity::Error, Check::Email);
        dmarc.hint = Some("Publish one.".into());
        let at = "2026-10-30T15:40:13Z".to_string();
        let empty = crate::input::domain("").unwrap_err();
        let out = Output::new(vec![
            report(vec![dmarc], false),
            Report::invalid("", at, empty),
        ]);
        assert_eq!(
            serde_json::to_value(&out).unwrap(),
            json!({
                "reports": [
                    {
                        "input": "https://Example.COM/shop",
                        "domain": "example.com",
                        "unicode": "example.com",
                        "checked_at": "2026-10-30T15:40:12Z",
                        "error": null,
                        "counts": { "errors": 1, "warnings": 0, "info": 0 },
                        "findings": [{
                            "code": "dmarc_none", "severity": "error", "check": "email",
                            "message": "dmarc_none message.", "hint": "Publish one."
                        }],
                        "dns": null,
                        "propagation": null
                    },
                    {
                        "input": "",
                        "domain": null,
                        "unicode": null,
                        "checked_at": "2026-10-30T15:40:13Z",
                        "error": {
                            "code": "empty", "message": "Empty input.",
                            "hint": "Pass a domain, e.g. example.com."
                        },
                        "counts": { "errors": 0, "warnings": 0, "info": 0 },
                        "findings": [],
                        "dns": null,
                        "propagation": null
                    }
                ],
                "summary": { "domains": 2, "errors": 1, "warnings": 0, "info": 0, "unavailable": 0 },
                "data": { "version": "0.1.0", "rdap_bootstrap": "2026-10-28T22:00:04Z" }
            })
        );
    }

    #[test]
    fn sections_not_ok_keep_their_fields_as_null() {
        #[derive(Default, Serialize)]
        struct Web {
            final_status: Option<u16>,
            hops: Vec<String>,
        }
        let ok = Section::ok(Web {
            final_status: Some(200),
            hops: vec!["http://example.com/".into()],
        });
        let s = serde_json::to_string(&ok).unwrap();
        assert_eq!(
            s,
            r#"{"status":"ok","reason":null,"final_status":200,"hops":["http://example.com/"]}"#
        );
        let down: Section<Web> = Section::not(Status::Unavailable, "Stopped after 30 s.");
        assert_eq!(
            serde_json::to_value(&down).unwrap(),
            json!({ "status": "unavailable", "reason": "Stopped after 30 s.", "final_status": null, "hops": null })
        );
        let skipped: Section<Web> = Section::not(Status::Skipped, "not requested");
        assert_eq!(serde_json::to_value(&skipped).unwrap()["status"], "skipped");
        let limited: Section<Web> = Section::not(Status::RateLimited, "wait");
        assert_eq!(
            serde_json::to_value(&limited).unwrap()["status"],
            "rate_limited"
        );
    }

    #[test]
    fn the_exit_code_follows_errors_then_unavailable_sections() {
        use Severity::*;
        let exit = |reports| Output::new(reports).exit_code();
        let warn = || finding("no_caa", Warning, Check::Dns);
        assert_eq!(exit(vec![report(vec![], false)]), 0);
        let quiet = vec![warn(), finding("x", Info, Check::Http)];
        assert_eq!(exit(vec![report(quiet, false)]), 0);
        let error = || finding("x", Error, Check::Tls);
        assert_eq!(exit(vec![report(vec![error()], false)]), 1);
        assert_eq!(exit(vec![report(vec![warn()], true)]), 3);
        let mixed = vec![report(vec![], true), report(vec![error()], false)];
        assert_eq!(exit(mixed), 1);
        let invalid = Report::invalid("a", String::new(), crate::input::domain("a").unwrap_err());
        assert_eq!(exit(vec![report(vec![], true), invalid]), 1);
        let two = Output::new(vec![report(vec![], true), report(vec![], true)]);
        assert_eq!(two.summary.unavailable, 2);
    }

    #[test]
    fn findings_without_a_hint_say_null_and_keyed_maps_keep_order() {
        let f = Finding::new(Check::Dns, Severity::Info, "x", "m", "");
        assert_eq!(f.hint, None);
        let keyed = Keyed(vec![("b".to_string(), 1), ("a".to_string(), 2)]);
        assert_eq!(serde_json::to_string(&keyed).unwrap(), r#"{"b":1,"a":2}"#);
        assert_eq!(keyed.get("a"), Some(&2));
    }
}
