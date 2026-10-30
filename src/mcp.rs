//! The MCP server on stdio: `check_domain` answers with the CLI's `check --json` object and
//! `dns_lookup` with `lookup --json`'s.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use rmcp::service::ServerInitializeError;
use rmcp::{ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use rustls::pki_types::CertificateDer;
use schemars::generate::{SchemaGenerator, SchemaSettings};
use schemars::transform::RecursiveTransform;
use schemars::{JsonSchema, Schema, json_schema};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::check::{self, Options};
use crate::dns::{self, Resolver};
use crate::report::Output;
use crate::sections::email::dkim;
use crate::sections::rdap;
use crate::{Error, Ports, input, lookup};

/// What every check of a `ui` or `mcp` server starts from: its own flags and the environment.
pub struct Defaults {
    /// `--resolver`: replaces the public resolvers when given.
    pub resolvers: Vec<SocketAddr>,
    /// `--ca-file`: certificates to trust besides this computer's own.
    pub ca: Vec<CertificateDer<'static>>,
    pub ports: Ports,
    pub bootstrap: Option<String>,
}

impl Defaults {
    pub fn new(
        resolvers: Vec<SocketAddr>,
        ca: Vec<CertificateDer<'static>>,
    ) -> Result<Self, Error> {
        Ok(Defaults {
            resolvers,
            ca,
            ports: Ports::from_env()?,
            bootstrap: rdap::from_env()?,
        })
    }
}

/// The `check_domain` arguments, which the page's `POST /api` takes too. A name it doesn't
/// define is refused, so a misspelt option can't change the answer.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckDomain {
    /// A domain, a URL or an email address; its host is checked
    #[schemars(length(min = 1, max = 1024))]
    pub domain: String,
    /// The sections to run; all six when omitted
    #[serde(default = "all")]
    #[schemars(schema_with = "check_list")]
    pub checks: Vec<String>,
    /// DKIM selectors to look up (the s= value of a DKIM-Signature); 8 common ones when omitted
    #[serde(default)]
    #[schemars(length(max = 10))]
    pub dkim_selectors: Vec<String>,
    /// Also evaluate SPF for mail sent from this IPv4 or IPv6 address
    pub spf_ip: Option<String>,
    /// Record types compared across nameservers and resolvers in propagation
    #[serde(default = "compared")]
    #[schemars(schema_with = "type_list")]
    pub types: Vec<String>,
    /// The resolver for every lookup, IP[:PORT]; this computer's when omitted
    pub dns_server: Option<String>,
    /// Allow TLS and HTTP connections to private addresses (internal hosts)
    #[serde(default)]
    pub allow_private: bool,
}

/// The `dns_lookup` arguments.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DnsLookup {
    /// Any DNS name (e.g. _dmarc.example.com), or an IP address for its PTR record
    #[schemars(length(min = 1, max = 1024))]
    name: String,
    /// Record types to ask for; A and AAAA when omitted, PTR for an IP address
    #[serde(default)]
    #[schemars(schema_with = "type_list")]
    types: Option<Vec<String>>,
    /// The resolver to ask, IP[:PORT]; this computer's when omitted
    server: Option<String>,
}

fn strings(s: &[&str]) -> Vec<String> {
    s.iter().map(|s| s.to_string()).collect()
}

fn all() -> Vec<String> {
    strings(&check::CHECKS.map(|c| c.key()))
}

fn compared() -> Vec<String> {
    strings(&["A", "AAAA", "MX", "TXT"])
}

fn check_list(_: &mut SchemaGenerator) -> Schema {
    names(&check::CHECKS.map(|c| c.key().to_string()))
}

fn type_list(_: &mut SchemaGenerator) -> Schema {
    names(&lookup::TYPES.map(|t| t.to_string()))
}

/// A list of at least one of `names`, each once.
fn names(names: &[String]) -> Schema {
    json_schema!({
        "type": "array", "minItems": 1, "uniqueItems": true,
        "items": { "type": "string", "enum": names }
    })
}

impl CheckDomain {
    /// The arguments read from JSON; anything the schema refuses is a `bad_request`.
    pub fn read(json: Value) -> Result<CheckDomain, Error> {
        arguments(json)
    }

    /// The domain's report, the same as `check --json` gives; an invalid domain is the error.
    pub fn run(&self, d: &Defaults) -> Result<Output, Error> {
        let o = self.options(d)?;
        let output = check::run(std::slice::from_ref(&self.domain), &o, &mut |_, _, _| {})?;
        match output.reports[0].error.clone() {
            Some(e) => Err(e),
            None => Ok(output),
        }
    }

    fn options(&self, d: &Defaults) -> Result<Options, Error> {
        listed("checks", &self.checks)?;
        listed("types", &self.types)?;
        if self.dkim_selectors.len() > 10 {
            let message = format!("{} DKIM selectors; at most 10.", self.dkim_selectors.len());
            return Err(Error::usage(message, "Pass the selectors your mail uses."));
        }
        let mut selectors: Vec<String> = Vec::new();
        for raw in &self.dkim_selectors {
            let s = dkim::selector(raw)?;
            if !selectors.contains(&s) {
                selectors.push(s);
            }
        }
        let spf_ip = self.spf_ip.as_deref().map(|ip| {
            ip.trim().parse().map_err(|_| {
                Error::usage(
                    format!("spf_ip {ip} isn't an IP address."),
                    "Pass the sending server's address, e.g. 192.0.2.10.",
                )
            })
        });
        Ok(Options {
            checks: check::checks(&self.checks)?,
            dns: server("dns_server", self.dns_server.as_deref())?,
            resolvers: d.resolvers.clone(),
            types: lookup::types(&self.types)?,
            selectors,
            spf_ip: spf_ip.transpose()?,
            ca: d.ca.clone(),
            allow_private: self.allow_private,
            ports: d.ports,
            bootstrap: d.bootstrap.clone(),
            debug: false,
        })
    }
}

/// An empty list the schema's `minItems` refuses, for clients that don't check it.
fn listed(name: &str, list: &[String]) -> Result<(), Error> {
    match list.is_empty() {
        true => Err(Error::usage(
            format!("{name} is empty."),
            format!("Leave {name} out for the default."),
        )),
        false => Ok(()),
    }
}

fn server(name: &str, raw: Option<&str>) -> Result<Option<SocketAddr>, Error> {
    raw.map(|s| dns::server(name, s.trim())).transpose()
}

/// `args` as `T`; a missing, mistyped or unknown argument is a `bad_request`.
fn arguments<T: DeserializeOwned>(args: Value) -> Result<T, Error> {
    serde_json::from_value(args).map_err(|e| {
        Error::new(
            "bad_request",
            format!("Can't read the arguments: {e}."),
            "Pass the arguments the tool's input schema lists.",
        )
    })
}

/// The error object the page and the MCP server answer with.
pub fn failure(error: &Error) -> String {
    serde_json::to_string(&json!({ "error": error })).unwrap_or_default()
}

/// One call at a time: checks are paced for the services they ask (spec §6).
pub static ONE: Mutex<()> = Mutex::new(());

#[derive(Clone)]
struct Server {
    defaults: Arc<Defaults>,
}

#[tool_router]
impl Server {
    #[tool(
        description = "Check one domain and return a report with problems first: DNS records, DNSSEC and CAA; propagation (each authoritative nameserver compared with Google, Cloudflare, Quad9 and the local resolver); email security (MX, SPF evaluated with its DNS lookup count against the limit of 10, DMARC per RFC 9989, DKIM keys and their size, MTA-STS policy, TLS-RPT, BIMI); RDAP registration (registrar, creation and expiry dates, status); the TLS certificate on port 443 (trust, names, days left, chain); HTTP to HTTPS redirects and security headers. Each finding has a code, severity (error, warning, info), message and fix hint. Sections that couldn't reach the network say unavailable or rate_limited, never a verdict. On bad input the result has isError true and one text block holding {\"error\":{\"code\",\"message\",\"hint\"}}.",
        input_schema = closed::<CheckDomain>(),
        output_schema = output(report_schema()),
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn check_domain(&self, args: JsonObject) -> CallToolResult {
        let d = Arc::clone(&self.defaults);
        answer(move || CheckDomain::read(Value::Object(args))?.run(&d)).await
    }

    #[tool(
        description = "Run one DNS query and return the records with TTLs and the response code (NOERROR, NXDOMAIN, SERVFAIL). Accepts any name (e.g. _dmarc.example.com, selector._domainkey.example.com) and record types A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, PTR, DS, DNSKEY, TLSA, HTTPS, SVCB; an IP address gives its PTR (reverse DNS). Uses this computer's resolver unless server is given.",
        input_schema = closed::<DnsLookup>(),
        output_schema = output(lookup_schema()),
        annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = true)
    )]
    async fn dns_lookup(&self, args: JsonObject) -> CallToolResult {
        let ports = self.defaults.ports;
        answer(move || {
            let a: DnsLookup = arguments(Value::Object(args))?;
            let types = match &a.types {
                Some(types) => listed("types", types).and(lookup::types(types))?,
                None => Vec::new(),
            };
            let (name, types) = lookup::question(input::target(&a.name)?, types)?;
            let resolver = Arc::new(Resolver::new(
                server("server", a.server.as_deref())?,
                ports,
                false,
            )?);
            Ok(crate::runtime()?.block_on(lookup::run(resolver, name, types)))
        })
        .await
    }
}

/// Runs `work` off the protocol's thread, one call at a time, as the tool's result.
async fn answer<T: Serialize + Send + 'static>(
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> CallToolResult {
    let done = tokio::task::spawn_blocking(move || {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        work()
    })
    .await;
    let failed = |e: &Error| CallToolResult::error(vec![ContentBlock::text(failure(e))]);
    match done {
        Ok(Ok(value)) => match serde_json::to_value(value) {
            Ok(v) => CallToolResult::structured(v),
            Err(e) => failed(&Error::new(
                "runtime",
                format!("Couldn't write JSON: {e}."),
                "Try again.",
            )),
        },
        Ok(Err(e)) => failed(&e),
        Err(e) => failed(&Error::new(
            "runtime",
            format!("The check failed: {e}."),
            "Try again.",
        )),
    }
}

#[tool_handler(
    name = "domain-check",
    instructions = "Check a domain from this computer: DNS records and propagation across nameservers and public resolvers, email authentication (SPF with lookup count, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI), RDAP registration, the TLS certificate, and HTTP redirects and security headers. Use check_domain for a ranked report of problems, dns_lookup for one DNS query. No account or API key is needed."
)]
impl ServerHandler for Server {}

/// A tool's arguments, closed to names it doesn't define.
fn closed<T: JsonSchema>() -> Arc<JsonObject> {
    // Rust's number formats (uint8 …) aren't JSON Schema's.
    let no_format = |s: &mut Schema| drop(s.remove("format"));
    let schema = SchemaSettings::draft2020_12()
        .with_transform(RecursiveTransform(no_format))
        .into_generator()
        .into_root_schema_for::<T>();
    let Value::Object(mut schema) = schema.to_value() else {
        unreachable!("a root schema is an object")
    };
    schema.remove("title");
    schema.remove("description");
    schema.insert("additionalProperties".into(), false.into());
    Arc::new(schema)
}

fn output(schema: Value) -> Arc<JsonObject> {
    match schema {
        Value::Object(o) => Arc::new(o),
        _ => unreachable!("written as an object"),
    }
}

/// The `check --json` object's outline: sections are described, not spelt out field by field.
fn report_schema() -> Value {
    let section = |about: &str| json!({ "type": ["object", "null"], "description": about });
    let text = json!({ "type": "string" });
    let maybe = json!({ "type": ["string", "null"] });
    json!({
        "type": "object",
        "required": ["reports", "summary", "data"],
        "properties": {
            "reports": { "type": "array", "items": {
                "type": "object",
                "required": ["input", "domain", "unicode", "checked_at", "error", "counts", "findings",
                             "dns", "propagation", "email", "rdap", "tls", "http"],
                "properties": {
                    "input": text, "domain": maybe, "unicode": maybe, "checked_at": text,
                    "error": { "type": ["object", "null"] },
                    "counts": { "type": "object", "properties": {
                        "errors": { "type": "integer" }, "warnings": { "type": "integer" }, "info": { "type": "integer" } } },
                    "findings": { "type": "array", "items": {
                        "type": "object",
                        "required": ["code", "severity", "check", "message", "hint"],
                        "properties": {
                            "code": text,
                            "severity": { "enum": ["error", "warning", "info"] },
                            "check": { "enum": ["dns", "propagation", "email", "rdap", "tls", "http"] },
                            "message": text, "hint": maybe } } },
                    "dns": section("Records by type with TTLs, zone, CNAME chain, CAA in force, DNSSEC; status ok, unavailable, rate_limited or skipped with a reason"),
                    "propagation": section("Each authoritative nameserver and resolver with its answers per type; agrees, consistent, wildcard"),
                    "email": section("MX, SPF (lookups, voids, tree, evaluation), DMARC, DKIM keys, MTA-STS, TLS-RPT, BIMI"),
                    "rdap": section("Registrar, created, expires, updated, status, nameservers, DNSSEC delegation; retry_after when rate_limited"),
                    "tls": section("The presented chain, trust, names, dates, days left, protocol and cipher"),
                    "http": section("The redirect chains from http and https, and the final page's security headers")
                } } },
            "summary": { "type": "object" },
            "data": { "type": "object", "properties": { "version": text, "rdap_bootstrap": text } }
        }
    })
}

/// The `lookup --json` object.
fn lookup_schema() -> Value {
    let text = json!({ "type": "string" });
    let maybe = json!({ "type": ["string", "null"] });
    json!({
        "type": "object",
        "required": ["name", "server", "results"],
        "properties": {
            "name": text, "server": text,
            "results": { "type": "array", "items": {
                "type": "object",
                "required": ["type", "rcode", "authoritative", "authenticated", "records", "error"],
                "properties": {
                    "type": text, "rcode": maybe,
                    "authoritative": { "type": "boolean" }, "authenticated": { "type": "boolean" },
                    "records": { "type": "array", "items": {
                        "type": "object", "required": ["value", "ttl"],
                        "properties": { "value": text, "ttl": { "type": "integer" } } } },
                    "error": maybe } } }
        }
    })
}

/// Serves until the client closes stdin.
pub fn serve(defaults: Defaults) -> Result<(), Error> {
    let io = |e: &dyn std::fmt::Display| {
        Error::new(
            "runtime",
            format!("Couldn't read input: {e}."),
            "Start it again.",
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| io(&e))?;
    let server = Server {
        defaults: Arc::new(defaults),
    };
    let served = runtime.block_on(async {
        match server.serve(rmcp::transport::stdio()).await {
            Ok(service) => service.waiting().await.map(drop).map_err(|e| io(&e)),
            // stdin closed before the handshake ended: the client left, which is no failure.
            Err(ServerInitializeError::ConnectionClosed(_)) => Ok(()),
            // stdout closed before the answer went out: the client left too.
            Err(ServerInitializeError::TransportError { error, .. })
                if error
                    .error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe) =>
            {
                Ok(())
            }
            Err(e) => Err(io(&e)),
        }
    });
    // A check still running for a client that left isn't waited for.
    runtime.shutdown_background();
    served
}
