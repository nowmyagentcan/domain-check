//! The `rdap` section: the registration record from the registry's RDAP server (RFC 9083),
//! found through IANA's bootstrap file (RFC 9224), starting at the zone apex instead of
//! guessing the registered name from a suffix list.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};
use ureq::Body;
use ureq::http::Response;
use url::{Host, Url};

use crate::check::{Cx, Facts, parent, within};
use crate::dns::{self, RecordType};
use crate::net::{self, Failed, Net};
use crate::report::{Check, Finding, Section, Severity, Status};
use crate::{Error, RDAP_BOOTSTRAP_JSON};

/// IANA's bootstrap file, fetched only when the bundled copy can't answer.
const LIVE: &str = "https://data.iana.org/rdap/dns.json";
const VAR: &str = "DOMAIN_CHECK_RDAP_BOOTSTRAP";
const RDAP_JSON: &str = "application/rdap+json";
/// Requests to the registry for one domain, retries and redirects included.
const REGISTRY_REQUESTS: usize = 3;
const REDIRECTS: usize = 3;
const RETRY: Duration = Duration::from_secs(2);
const TIMEOUT: Duration = Duration::from_secs(15);
const LIMIT: u64 = 1 << 20;
/// The least time between requests to one host (the registries' terms forbid bulk lookups).
const PACE: Duration = Duration::from_secs(1);

/// The section, with the wait a rate-limiting server asked for next to its status.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RdapSection {
    #[serde(flatten)]
    pub section: Section<Rdap>,
    pub retry_after: Option<u64>,
}

impl RdapSection {
    pub fn not(status: Status, reason: impl Into<String>) -> RdapSection {
        RdapSection {
            section: Section::not(status, reason),
            retry_after: None,
        }
    }

    fn ok(rdap: Rdap) -> RdapSection {
        RdapSection {
            section: Section::ok(rdap),
            retry_after: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Rdap {
    /// The base URL asked.
    pub server: Option<String>,
    /// The name that answered, or the last one tried.
    pub queried: Option<String>,
    pub found: bool,
    pub registrar: Option<Registrar>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub updated: Option<String>,
    pub domain_status: Vec<String>,
    pub nameservers: Vec<String>,
    pub dnssec_delegation: Option<bool>,
    pub registrar_data: Option<RegistrarData>,
    pub terms: Option<String>,
    pub bootstrap: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Registrar {
    pub name: Option<String>,
    pub iana_id: Option<String>,
    pub rdap: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RegistrarData {
    pub server: String,
    pub status: &'static str,
    pub expires: Option<String>,
    pub updated: Option<String>,
}

/// `DOMAIN_CHECK_RDAP_BOOTSTRAP`: a bootstrap file to use instead of the bundled one, over
/// https, or over http only from this computer.
pub fn from_env() -> Result<Option<String>, Error> {
    let raw = std::env::var(VAR).unwrap_or_default();
    if raw.trim().is_empty() {
        return Ok(None);
    }
    match Url::parse(raw.trim()) {
        Ok(url) if usable(&url) => Ok(Some(url.to_string())),
        Ok(url) if url.scheme() == "http" => Err(Error::usage(
            format!("{VAR}={raw} uses http:// for a host that isn't this computer."),
            "Use https://, or http:// only for 127.0.0.1 or ::1.",
        )),
        _ => Err(Error::usage(
            format!("{VAR}={raw} isn't an https:// URL."),
            "Use the URL of an RDAP bootstrap file, or unset it.",
        )),
    }
}

/// RDAP goes over https; plain http only to a loopback address (tests and local mirrors).
fn usable(url: &Url) -> bool {
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(Host::Ipv4(ip))) => ip.is_loopback(),
        ("http", Some(Host::Ipv6(ip))) => ip.is_loopback(),
        _ => false,
    }
}

fn host(url: &str) -> String {
    let host = Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from));
    host.unwrap_or_else(|| url.to_string())
}

/// An RDAP bootstrap file (RFC 9224 §4): service URLs by top-level domain.
#[derive(Deserialize)]
struct Bootstrap {
    publication: String,
    services: Vec<(Vec<String>, Vec<String>)>,
    /// Where it came from, as the report names it.
    #[serde(skip)]
    label: String,
}

impl Bootstrap {
    /// The service URLs of the longest suffix of `domain` the file lists.
    fn urls(&self, domain: &str) -> Option<&[String]> {
        let mut name = Some(domain);
        while let Some(suffix) = name {
            let listed = self
                .services
                .iter()
                .find(|(tlds, _)| tlds.iter().any(|t| t.eq_ignore_ascii_case(suffix)));
            if let Some((_, urls)) = listed {
                return Some(urls);
            }
            name = parent(suffix);
        }
        None
    }
}

/// The URL to use from a service's list: https first.
fn pick(urls: &[String]) -> Option<String> {
    let parsed: Vec<Url> = urls.iter().filter_map(|u| Url::parse(u).ok()).collect();
    let https = parsed.iter().find(|u| u.scheme() == "https");
    let url = https.or(parsed.iter().find(|u| usable(u)))?;
    Some(url.to_string())
}

type File = Result<Arc<Bootstrap>, String>;

/// What the domains of one run share: the bootstrap files, each read at most once, and when
/// each RDAP host last answered.
pub struct Run {
    /// `DOMAIN_CHECK_RDAP_BOOTSTRAP`, standing in for the bundled file and the live one.
    url: Option<String>,
    first: Mutex<Option<File>>,
    live: Mutex<Option<File>>,
    last: Mutex<HashMap<String, Instant>>,
}

impl Run {
    pub fn new(url: Option<String>) -> Run {
        Run {
            url,
            first: Mutex::new(None),
            live: Mutex::new(None),
            last: Mutex::new(HashMap::new()),
        }
    }

    /// The bundled file, or the one `DOMAIN_CHECK_RDAP_BOOTSTRAP` names.
    fn first(&self, net: &Net, until: Instant) -> File {
        let mut slot = self.first.lock().unwrap_or_else(|e| e.into_inner());
        let read = || match &self.url {
            None => {
                let mut b: Bootstrap = serde_json::from_str(RDAP_BOOTSTRAP_JSON)
                    .map_err(|e| format!("The bundled RDAP bootstrap file is broken: {e}."))?;
                b.label = format!("bundled {}", b.publication.get(..10).unwrap_or_default());
                Ok(Arc::new(b))
            }
            Some(url) => self.fetch(net, url, until, "override"),
        };
        slot.get_or_insert_with(read).clone()
    }

    /// IANA's current file (or the override again), fetched once per run.
    fn live(&self, net: &Net, until: Instant) -> File {
        let mut slot = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let url = self.url.as_deref().unwrap_or(LIVE);
        slot.get_or_insert_with(|| self.fetch(net, url, until, "live"))
            .clone()
    }

    fn fetch(&self, net: &Net, url: &str, until: Instant, label: &str) -> File {
        let host = host(url);
        match self.get(net, url, "application/json", until, &mut 1, false) {
            Got::Json(v) => {
                let mut b: Bootstrap = serde_json::from_value(v).map_err(|_| unreadable(&host))?;
                b.label = match label {
                    "live" => "live".into(),
                    _ => format!("{label} {}", b.publication.get(..10).unwrap_or_default()),
                };
                Ok(Arc::new(b))
            }
            got => Err(got.why(&host)),
        }
    }

    /// One GET with its redirects (at most 3, to usable URLs) and, when `retry` is set, one
    /// more try 2 s after a 5xx or a failed connection. Every request takes one of `left` and
    /// starts at least 1 s after the last answer from its host.
    fn get(
        &self,
        net: &Net,
        start: &str,
        accept: &str,
        until: Instant,
        left: &mut usize,
        retry: bool,
    ) -> Got {
        let mut url = start.to_string();
        let (mut redirects, mut retry) = (0, retry);
        loop {
            *left = left.saturating_sub(1);
            let host = host(&url);
            let answered = |status| Got::Down(format!("{host} answered HTTP {status}."), None);
            let last = self
                .last
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&host)
                .copied();
            if let Some(at) = last {
                thread::sleep(PACE.saturating_sub(at.elapsed()));
            }
            let response = net.get_as(&url, until, accept, TIMEOUT);
            let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
            last.insert(host.clone(), Instant::now());
            drop(last);
            let got = match response {
                Err(f) => Got::Down(format!("Couldn't reach {host}: {f}."), Some(f)),
                Ok(mut r) => match r.status().as_u16() {
                    200 => return json(&mut r, &host),
                    404 => return Got::NotFound,
                    429 => {
                        let after = header(&r, "retry-after").and_then(|v| v.parse().ok());
                        return Got::Limited(after);
                    }
                    status @ (301 | 302 | 303 | 307 | 308) => {
                        let base = Url::parse(&url).ok();
                        let next = header(&r, "location").and_then(|l| base?.join(&l).ok());
                        match next.filter(usable) {
                            Some(next) if redirects < REDIRECTS && *left > 0 => {
                                (url, redirects) = (next.to_string(), redirects + 1);
                                continue;
                            }
                            _ => return answered(status),
                        }
                    }
                    status @ 500.. => answered(status),
                    status => return answered(status),
                },
            };
            let private = matches!(got, Got::Down(_, Some(Failed::Private { .. })));
            if !retry || private || *left == 0 || Instant::now() + RETRY >= until {
                return got;
            }
            retry = false;
            thread::sleep(RETRY);
        }
    }
}

fn unreadable(host: &str) -> String {
    format!("{host} sent a response we couldn't read.")
}

/// What a GET came to.
enum Got {
    Json(Value),
    NotFound,
    /// HTTP 429, with the seconds `Retry-After` asked for.
    Limited(Option<u64>),
    /// No usable answer: why, and how the request failed when no HTTP answer came.
    Down(String, Option<Failed>),
}

impl Got {
    fn why(self, host: &str) -> String {
        match self {
            Got::Json(_) => String::new(),
            Got::NotFound => format!("{host} answered HTTP 404."),
            Got::Limited(after) => limited(host, after),
            Got::Down(why, _) => why,
        }
    }
}

fn limited(host: &str, after: Option<u64>) -> String {
    match after {
        Some(n) => format!("{host} limits lookups and asked us to wait {n} s."),
        None => format!("{host} limits lookups; try again later."),
    }
}

fn header(r: &Response<Body>, name: &str) -> Option<String> {
    let value = r.headers().get(name)?.to_str().ok()?;
    Some(value.trim().to_string())
}

fn json(r: &mut Response<Body>, host: &str) -> Got {
    let body = net::body(r, LIMIT).ok();
    let value = body.and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    match value.filter(Value::is_object) {
        Some(v) => Got::Json(v),
        None => Got::Down(unreadable(host), None),
    }
}

/// An RFC 3339 date as reports write it: UTC, to the second.
fn date(s: &str) -> Option<String> {
    let at = OffsetDateTime::parse(s.trim(), &Rfc3339).ok()?;
    let at = at.to_offset(UtcOffset::UTC).truncate_to_second();
    at.format(&Rfc3339).ok()
}

fn strings(v: &Value) -> Vec<String> {
    let items = v.as_array().into_iter().flatten();
    items.filter_map(|s| s.as_str().map(String::from)).collect()
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// The date of the event named `action` (RFC 9083 §4.5).
fn event(v: &Value, action: &str) -> Option<String> {
    let events = v["events"].as_array()?;
    let e = events.iter().find(|e| {
        let name = e["eventAction"].as_str().unwrap_or_default();
        name.eq_ignore_ascii_case(action)
    })?;
    date(e["eventDate"].as_str()?)
}

/// The registrar's own RDAP record of the domain: the top-level `related` link, an RDAP one
/// first (RFC 9083 §4.2; ICANN gTLD response profile 2.2 §2.2).
fn related(v: &Value) -> Option<String> {
    let links: Vec<&Value> = v["links"]
        .as_array()?
        .iter()
        .filter(|l| l["rel"] == "related")
        .collect();
    let href = |l: &&Value| l["href"].as_str().map(String::from);
    let rdap = links
        .iter()
        .filter(|l| l["type"] == RDAP_JSON)
        .find_map(href);
    let any = || {
        links
            .iter()
            .filter_map(href)
            .find(|h| h.contains("/domain/"))
    };
    rdap.or_else(any)
        .filter(|h| Url::parse(h).is_ok_and(|u| usable(&u)))
}

/// The registrar entity's name (vCard `fn`) and IANA ID.
fn registrar(v: &Value) -> Option<Registrar> {
    let entities = v["entities"].as_array()?;
    let e = entities
        .iter()
        .find(|e| strings(&e["roles"]).iter().any(|r| r == "registrar"))?;
    let card = e["vcardArray"][1].as_array().into_iter().flatten();
    let name = card
        .filter(|p| p[0] == "fn")
        .find_map(|p| p[3].as_str().map(String::from));
    let ids = e["publicIds"].as_array().into_iter().flatten();
    let iana_id = ids
        .filter(|p| p["type"] == "IANA Registrar ID")
        .find_map(|p| text(&p["identifier"]));
    Some(Registrar {
        name,
        iana_id,
        rdap: None,
    })
}

/// The fields of an RDAP domain object (RFC 9083 §5.3; ICANN gTLD response profile 2.2).
fn read(v: &Value, rdap: &mut Rdap) {
    rdap.created = event(v, "registration");
    rdap.expires = event(v, "expiration");
    rdap.updated = event(v, "last changed");
    rdap.registrar = match (registrar(v), related(v)) {
        (Some(r), link) => Some(Registrar { rdap: link, ..r }),
        (None, Some(link)) => Some(Registrar {
            name: None,
            iana_id: None,
            rdap: Some(link),
        }),
        (None, None) => None,
    };
    rdap.domain_status = strings(&v["status"]);
    let servers = v["nameservers"].as_array().into_iter().flatten();
    rdap.nameservers = servers
        .filter_map(|n| n["ldhName"].as_str())
        .map(|n| n.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    rdap.dnssec_delegation = v["secureDNS"]["delegationSigned"].as_bool();
    let notices = v["notices"].as_array().into_iter().flatten();
    let links = notices.flat_map(|n| n["links"].as_array().into_iter().flatten());
    rdap.terms = links
        .filter(|l| l["rel"] == "terms-of-service")
        .find_map(|l| l["href"].as_str().map(String::from));
}

/// A finding; a hint that ends on a registrar name like `Example, Inc.` keeps one period.
fn finding(severity: Severity, code: &'static str, message: String, hint: &str) -> Finding {
    let hint = hint
        .strip_suffix("..")
        .map_or(hint.to_string(), |h| format!("{h}."));
    Finding::new(Check::Rdap, severity, code, message, hint)
}

pub fn run(cx: &Cx, facts: &Facts) -> (RdapSection, Vec<Finding>) {
    let (net, d, until) = (&cx.net, cx.domain.as_str(), cx.until(Check::Rdap));
    let down = |why: String| (RdapSection::not(Status::Unavailable, why), Vec::new());
    let first = match cx.rdap.first(net, until) {
        Ok(b) => b,
        Err(why) => return down(why),
    };
    let mut source = first.label.clone();
    let mut urls = first.urls(d).map(<[String]>::to_vec);
    if urls.is_none()
        && let Ok(live) = cx.rdap.live(net, until)
        && let Some(listed) = live.urls(d)
    {
        (urls, source) = (Some(listed.to_vec()), live.label.clone());
    }
    let tld = d.rsplit('.').next().unwrap_or(d);
    let Some(urls) = urls else {
        let message = format!(
            "IANA lists no RDAP service for .{tld}, so registration data can't be checked here."
        );
        let hint = "The registry may offer WHOIS or a web lookup.";
        let rdap = Rdap {
            queried: Some(d.to_string()),
            bootstrap: source,
            ..Rdap::default()
        };
        let found = vec![finding(Severity::Info, "rdap_no_service", message, hint)];
        return (RdapSection::ok(rdap), found);
    };
    let Some(mut base) = pick(&urls) else {
        let why = format!(
            "IANA lists only an http:// RDAP server for .{tld}; domain-check uses https only."
        );
        return down(why);
    };
    // An existing name starts at its zone apex; a name not in DNS is asked about itself only.
    let exists = facts.exists(d);
    let apex = facts.zone.as_deref().filter(|z| exists && within(d, z));
    let mut name = apex.unwrap_or(d).to_string();
    let mut left = REGISTRY_REQUESTS;
    let record = loop {
        let url = format!("{}/domain/{name}", base.trim_end_matches('/'));
        match cx.rdap.get(net, &url, RDAP_JSON, until, &mut left, true) {
            Got::Json(v) => break v,
            Got::NotFound if exists && left > 0 && name.matches('.').count() >= 2 => {
                name = parent(&name).unwrap_or_default().to_string();
            }
            Got::NotFound => {
                let message = format!(
                    "No registration record for {name} at {}; it is probably not registered.",
                    host(&base)
                );
                let rdap = Rdap {
                    server: Some(base),
                    queried: Some(name),
                    bootstrap: source,
                    ..Rdap::default()
                };
                let found = vec![finding(Severity::Info, "rdap_not_found", message, "")];
                return (RdapSection::ok(rdap), found);
            }
            Got::Limited(after) => {
                let section = RdapSection {
                    section: Section::not(Status::RateLimited, limited(&host(&base), after)),
                    retry_after: after,
                };
                return (section, Vec::new());
            }
            // The server is unreachable: IANA's current file may name another one.
            Got::Down(why, Some(f)) if left > 0 && !matches!(f, Failed::Private { .. }) => {
                let live = cx.rdap.live(net, until).ok();
                let other = live.as_ref().and_then(|b| pick(b.urls(d)?));
                match other.filter(|o| *o != base) {
                    Some(other) => (base, source) = (other, "live".into()),
                    None => return down(why),
                }
            }
            Got::Down(why, _) => return down(why),
        }
    };
    let mut rdap = Rdap {
        server: Some(base),
        queried: Some(name),
        found: true,
        bootstrap: source,
        ..Rdap::default()
    };
    read(&record, &mut rdap);
    let link = rdap.registrar.as_ref().and_then(|r| r.rdap.clone());
    if let Some(link) = link {
        let data = registrar_data(cx, &link, until);
        // The registry's dates win; the registrar's expiry fills a gap.
        rdap.expires = rdap.expires.or_else(|| data.expires.clone());
        rdap.registrar_data = Some(data);
    }
    let apex = facts
        .zone
        .as_deref()
        .filter(|z| rdap.queried.as_deref() == Some(*z));
    let zone_ns = apex.and_then(|zone| nameservers(cx, zone));
    let found = judge(&rdap, zone_ns.as_deref(), OffsetDateTime::now_utc());
    (RdapSection::ok(rdap), found)
}

/// The zone's NS records; `None` when the lookup failed or found none.
fn nameservers(cx: &Cx, zone: &str) -> Option<Vec<String>> {
    let m = crate::runtime()
        .ok()?
        .block_on(cx.resolver.lookup(zone, RecordType::NS));
    let m = m.ok()?;
    let ns: Vec<_> = dns::records(&m, RecordType::NS)
        .map(|r| dns::value(&r.data).to_ascii_lowercase())
        .collect();
    (!ns.is_empty()).then_some(ns)
}

/// The registration findings (spec §8.5).
fn judge(r: &Rdap, zone_ns: Option<&[String]>, now: OffsetDateTime) -> Vec<Finding> {
    let mut found = Vec::new();
    if !r.found {
        return found;
    }
    let registrar = r.registrar.as_ref().and_then(|g| g.name.as_deref());
    let registrar = registrar.unwrap_or("your registrar");
    let expires = r.expires.as_deref().unwrap_or_default();
    if let Ok(at) = OffsetDateTime::parse(expires, &Rfc3339) {
        let day = &expires[..10];
        let days = (at - now).whole_days();
        if at <= now {
            found.push(finding(
                Severity::Error,
                "rdap_expired",
                format!("The registration expired on {day}."),
                &format!("Renew it now at {registrar}; it may still be in its grace period."),
            ));
        } else if days < 30 {
            found.push(finding(
                Severity::Warning,
                "rdap_expiring",
                format!("The registration expires in {days} days ({day})."),
                &format!("Renew it, or turn on auto-renew at {registrar}."),
            ));
        }
    }
    let status = |names: &[&str]| {
        let lower = |s: &&String| names.contains(&s.to_ascii_lowercase().as_str());
        r.domain_status.iter().find(lower)
    };
    if let Some(s) = status(&["client hold", "server hold"]) {
        found.push(finding(
            Severity::Error,
            "rdap_hold",
            format!("The registration has status \"{s}\", so the domain is out of the DNS."),
            &format!("Contact {registrar}."),
        ));
    }
    if let Some(s) = status(&["redemption period", "pending delete", "pending restore"]) {
        found.push(finding(
            Severity::Error,
            "rdap_pending_delete",
            format!("The registration has status \"{s}\": it is about to be deleted."),
            &format!("Contact {registrar} at once if the domain is yours."),
        ));
    }
    let tld = r.queried.as_deref().and_then(|q| q.rsplit('.').next());
    if tld.is_some_and(|t| t.len() > 2) && status(&["client transfer prohibited"]).is_none() {
        found.push(finding(
            Severity::Info,
            "rdap_no_transfer_lock",
            "The domain has no transfer lock (client transfer prohibited).".into(),
            "Turn on the registrar lock to block unauthorised transfers.",
        ));
    }
    if let Some(zone) = zone_ns
        && !r.nameservers.is_empty()
    {
        let sorted = |list: &[String]| {
            let mut list = list.to_vec();
            list.sort();
            list.dedup();
            list
        };
        let (listed, zone) = (sorted(&r.nameservers), sorted(zone));
        if listed != zone {
            found.push(finding(
                Severity::Warning,
                "ns_rdap_mismatch",
                format!(
                    "The registry lists nameservers {}, but the zone's NS records are {}.",
                    listed.join(", "),
                    zone.join(", ")
                ),
                "Make them the same at your registrar and DNS host.",
            ));
        }
    }
    found
}

/// One GET of the registrar's record, without a retry.
fn registrar_data(cx: &Cx, link: &str, until: Instant) -> RegistrarData {
    let server =
        Url::parse(link).map_or(link.to_string(), |u| u.origin().ascii_serialization() + "/");
    let mut data = RegistrarData {
        server,
        status: "ok",
        expires: None,
        updated: None,
    };
    match cx.rdap.get(&cx.net, link, RDAP_JSON, until, &mut 1, false) {
        Got::Json(v) => {
            data.expires = event(&v, "expiration");
            data.updated = event(&v, "last changed");
        }
        Got::NotFound => data.status = "not_found",
        Got::Limited(_) => data.status = "rate_limited",
        Got::Down(..) => data.status = "unavailable",
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bootstrap(json: &str) -> Bootstrap {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn the_longest_listed_suffix_names_the_server() {
        let b = bootstrap(
            r#"{"publication":"2026-10-30T00:00:00Z","services":[
                [["uk"],["https://rdap.uk.example/"]],
                [["co.uk","org.uk"],["http://rdap.co.example/","https://rdap.co.example/"]],
                [["kg"],["http://rdap.kg.example/"]],
                [["test"],["http://127.0.0.1/rdap/"]]]}"#,
        );
        let server = |d: &str| b.urls(d).and_then(pick);
        assert_eq!(
            server("www.example.co.uk").unwrap(),
            "https://rdap.co.example/"
        );
        assert_eq!(server("example.UK").unwrap(), "https://rdap.uk.example/");
        assert_eq!(server("example.de"), None);
        assert!(b.urls("example.kg").is_some());
        assert_eq!(server("example.kg"), None);
        assert_eq!(server("example.test").unwrap(), "http://127.0.0.1/rdap/");
        let bundled = bootstrap(RDAP_BOOTSTRAP_JSON);
        assert_eq!(
            bundled.urls("example.com").and_then(pick).unwrap(),
            "https://rdap.verisign.com/com/v1/"
        );
        assert!(bundled.urls("example.de").is_none());
    }

    #[test]
    fn rdap_urls_are_https_or_loopback_http() {
        let ok = |u: &str| usable(&Url::parse(u).unwrap());
        assert!(ok("https://rdap.example.net/"));
        assert!(ok("http://127.0.0.1/dns.json"));
        assert!(ok("http://[::1]:80/dns.json"));
        assert!(!ok("http://rdap.example.net/"));
        assert!(!ok("http://192.0.2.1/"));
        assert!(!ok("ftp://127.0.0.1/"));
    }

    #[test]
    fn registrations_are_judged_by_expiry_status_and_nameservers() {
        let now = OffsetDateTime::parse("2026-10-31T12:00:00Z", &Rfc3339).unwrap();
        let record = |expires: &str, status: &[&str]| Rdap {
            found: true,
            queried: Some("example.com".into()),
            expires: Some(expires.into()),
            domain_status: status.iter().map(|s| s.to_string()).collect(),
            nameservers: vec!["ns2.example.net".into(), "ns1.example.net".into()],
            registrar: Some(Registrar {
                name: Some("Example Registrar".into()),
                iana_id: None,
                rdap: None,
            }),
            ..Rdap::default()
        };
        let codes = |r: &Rdap, ns: Option<&[String]>| {
            let found = judge(r, ns, now);
            found
                .iter()
                .map(|f| format!("{} {}", f.code, f.message))
                .collect::<Vec<_>>()
        };
        let locked = ["client transfer prohibited"];
        assert_eq!(
            codes(&record("2027-10-31T00:00:00Z", &locked), None),
            Vec::<String>::new()
        );
        assert_eq!(
            codes(&record("2026-11-30T11:59:59Z", &locked), None),
            ["rdap_expiring The registration expires in 29 days (2026-11-30)."]
        );
        assert_eq!(
            codes(&record("2026-11-30T12:00:00Z", &locked), None),
            Vec::<String>::new()
        );
        let expired = judge(&record("2026-10-31T12:00:00Z", &locked), None, now);
        assert_eq!(
            (
                expired[0].code,
                expired[0].message.as_str(),
                expired[0].hint.as_deref()
            ),
            (
                "rdap_expired",
                "The registration expired on 2026-10-31.",
                Some("Renew it now at Example Registrar; it may still be in its grace period.")
            )
        );
        assert_eq!(
            codes(
                &record(
                    "2027-10-31T00:00:00Z",
                    &["Server Hold", "redemption period"]
                ),
                None
            ),
            [
                "rdap_hold The registration has status \"Server Hold\", so the domain is out of the DNS.",
                "rdap_pending_delete The registration has status \"redemption period\": it is about to be deleted.",
                "rdap_no_transfer_lock The domain has no transfer lock (client transfer prohibited).",
            ]
        );
        let mut uk = record("2027-10-31T00:00:00Z", &[]);
        uk.queried = Some("example.uk".into());
        assert_eq!(codes(&uk, None), Vec::<String>::new());
        let zone = ["ns1.example.net".to_string(), "ns2.example.net".to_string()];
        let same = record("2027-10-31T00:00:00Z", &locked);
        assert_eq!(codes(&same, Some(&zone)), Vec::<String>::new());
        assert_eq!(
            codes(&same, Some(&zone[..1])),
            [
                "ns_rdap_mismatch The registry lists nameservers ns1.example.net, ns2.example.net, but the zone's NS records are ns1.example.net."
            ]
        );
        let mut unknown = record("2026-10-01T00:00:00Z", &locked);
        unknown.registrar = None;
        assert_eq!(
            judge(&unknown, None, now)[0].hint.as_deref(),
            Some("Renew it now at your registrar; it may still be in its grace period.")
        );
        assert_eq!(judge(&Rdap::default(), Some(&zone), now), Vec::new());
    }

    #[test]
    fn fields_come_from_the_rdap_domain_object() {
        let v: Value = serde_json::from_str(
            r#"{"objectClassName":"domain","ldhName":"EXAMPLE.COM",
              "events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
                        {"eventAction":"expiration","eventDate":"2027-08-13T04:00:00.123Z"},
                        {"eventAction":"last changed","eventDate":"2026-08-14T07:01:39+02:00"}],
              "status":["client delete prohibited","client transfer prohibited"],
              "nameservers":[{"ldhName":"A.IANA-SERVERS.NET."},{"ldhName":"b.iana-servers.net"}],
              "secureDNS":{"delegationSigned":true},
              "entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Tech"]]]},
                          {"roles":["registrar"],"publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],
                           "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}],
              "notices":[{"title":"Status Codes","links":[{"rel":"glossary","href":"https://icann.org/epp"}]},
                         {"title":"Terms of Use","links":[{"rel":"terms-of-service","href":"https://example.net/terms"}]}]}"#,
        )
        .unwrap();
        let mut rdap = Rdap::default();
        read(&v, &mut rdap);
        assert_eq!(rdap.created.as_deref(), Some("1995-08-14T04:00:00Z"));
        assert_eq!(rdap.expires.as_deref(), Some("2027-08-13T04:00:00Z"));
        assert_eq!(rdap.updated.as_deref(), Some("2026-08-14T05:01:39Z"));
        assert_eq!(
            rdap.registrar,
            Some(Registrar {
                name: Some("RESERVED-Internet Assigned Numbers Authority".into()),
                iana_id: Some("376".into()),
                rdap: None
            })
        );
        assert_eq!(
            rdap.nameservers,
            ["a.iana-servers.net", "b.iana-servers.net"]
        );
        assert_eq!(rdap.dnssec_delegation, Some(true));
        assert_eq!(rdap.terms.as_deref(), Some("https://example.net/terms"));
        assert_eq!(rdap.domain_status.len(), 2);
        let mut empty = Rdap::default();
        read(&serde_json::json!({}), &mut empty);
        assert_eq!(empty, Rdap::default());
    }
}
