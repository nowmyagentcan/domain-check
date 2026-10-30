//! The report every face prints: findings sorted problems first, each section's status,
//! the counts, and the exit code they make.

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::input::Domain;
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    pub check: Check,
    pub message: String,
    pub hint: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Unavailable,
    RateLimited,
    Skipped,
}

/// A section's status, why it isn't `ok`, and its fields: all `null` unless it is `ok`.
#[derive(Debug, PartialEq)]
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

#[derive(Debug, PartialEq, Serialize)]
pub struct Report {
    pub input: String,
    pub domain: Option<String>,
    pub unicode: Option<String>,
    pub checked_at: String,
    pub error: Option<Error>,
    pub counts: Counts,
    pub findings: Vec<Finding>,
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
            unavailable: 0,
        }
    }

    /// A checked domain's report, its findings sorted by severity, then check, then code.
    pub fn checked(
        input: &str,
        domain: &Domain,
        checked_at: String,
        mut findings: Vec<Finding>,
        unavailable: usize,
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
            unavailable,
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

    fn report(findings: Vec<Finding>, unavailable: usize) -> Report {
        let at = "2026-10-30T15:40:12Z".to_string();
        Report::checked(
            "https://Example.COM/shop",
            &example(),
            at,
            findings,
            unavailable,
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
            0,
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
        let out = Output::new(vec![report(vec![dmarc], 0), Report::invalid("", at, empty)]);
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
                        }]
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
                        "findings": []
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
        assert_eq!(exit(vec![report(vec![], 0)]), 0);
        assert_eq!(
            exit(vec![report(
                vec![warn(), finding("x", Info, Check::Http)],
                0
            )]),
            0
        );
        assert_eq!(
            exit(vec![report(vec![finding("x", Error, Check::Tls)], 0)]),
            1
        );
        assert_eq!(exit(vec![report(vec![warn()], 1)]), 3);
        assert_eq!(
            exit(vec![
                report(vec![], 2),
                report(vec![finding("x", Error, Check::Dns)], 0)
            ]),
            1
        );
        let invalid = Report::invalid("a", String::new(), crate::input::domain("a").unwrap_err());
        assert_eq!(exit(vec![report(vec![], 1), invalid]), 1);
        assert_eq!(
            Output::new(vec![report(vec![], 2), report(vec![], 1)])
                .summary
                .unavailable,
            3
        );
    }
}
