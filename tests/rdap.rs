mod common;

use std::time::Instant;

use common::web::Web;
use common::{DnsStub, json, run};
use serde_json::{Value, json as j};

const BOOTSTRAP: &str = "http://127.0.0.1/dns.json";

/// `check <args> --checks rdap` against the stub and the RDAP mock, bootstrapping from
/// `bootstrap` on the mock: the exit code and the reports.
fn rdap(stub: &DnsStub, web: &Web, args: &[&str], bootstrap: &str) -> (i32, Vec<Value>) {
    let dns = stub.addr();
    let base = [
        "-c",
        "rdap",
        "--dns",
        &dns,
        "--ca-file",
        &web.ca,
        "--allow-private",
    ];
    let ports = web.ports(stub);
    let env = [
        ("DOMAIN_CHECK_LOOPBACK_PORTS", ports.as_str()),
        ("DOMAIN_CHECK_RDAP_BOOTSTRAP", bootstrap),
    ];
    let (code, v) = json(&[args, &base].concat(), &env);
    (code, v["reports"].as_array().unwrap().clone())
}

/// The findings as `code: message`.
fn found(report: &Value) -> Vec<String> {
    let findings = report["findings"].as_array().unwrap();
    let line = |f: &Value| {
        format!(
            "{}: {}",
            f["code"].as_str().unwrap(),
            f["message"].as_str().unwrap()
        )
    };
    findings.iter().map(line).collect()
}

/// The registry paths asked, in order.
fn asked(web: &Web) -> Vec<String> {
    let hits = web
        .hits()
        .into_iter()
        .filter(|h| h.host == "rdap.example.net");
    hits.map(|h| h.path).collect()
}

fn fetched(web: &Web, path: &str) -> usize {
    web.hits().iter().filter(|h| h.path == path).count()
}

#[test]
fn the_registry_from_the_bootstrap_answers_for_the_zone_apex() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, reports) = rdap(&stub, &web, &["www.example.com"], BOOTSTRAP);
    assert_eq!(code, 0, "{reports:?}");
    let r = &reports[0]["rdap"];
    let date = |key: &str| r[key].as_str().unwrap().to_string();
    for key in ["created", "expires", "updated"] {
        let at = date(key);
        assert!(at.len() == 20 && at.ends_with('Z'), "{key} {at}");
    }
    let mut fields = r.clone();
    for key in ["created", "expires", "updated"] {
        fields.as_object_mut().unwrap().remove(key);
    }
    let theirs = fields["registrar_data"].as_object_mut().unwrap();
    let (expires, updated) = (
        theirs.remove("expires").unwrap(),
        theirs.remove("updated").unwrap(),
    );
    // The registry's dates win over the registrar's.
    assert!(date("expires").as_str() < expires.as_str().unwrap(), "{r}");
    assert!(date("updated").as_str() < updated.as_str().unwrap(), "{r}");
    assert_eq!(
        fields,
        j!({ "status": "ok", "reason": null, "retry_after": null,
             "server": "https://rdap.example.net/rdap", "queried": "example.com", "found": true,
             "registrar": { "name": "Example Registrar, Inc.", "iana_id": "9999",
                            "rdap": "https://registrar.example.net/domain/example.com" },
             "registrar_data": { "server": "https://registrar.example.net/", "status": "ok" },
             "domain_status": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
             "nameservers": ["ns1.example.net", "ns2.example.net"], "dnssec_delegation": false,
             "terms": "https://rdap.example.net/terms", "bootstrap": "override 2026-10-30" })
    );
    assert_eq!(asked(&web), ["/rdap/domain/example.com"]);
    let theirs = web
        .hits()
        .into_iter()
        .filter(|h| h.host == "registrar.example.net");
    let theirs: Vec<_> = theirs.map(|h| h.path).collect();
    assert_eq!(theirs, ["/domain/example.com"]);
    assert_eq!(found(&reports[0]), Vec::<String>::new());
    let https = web.hits().iter().all(|h| h.https || h.path == "/dns.json");
    assert!(https, "{:?}", web.hits());
}

#[test]
fn the_registrar_fills_a_missing_expiry_and_says_when_it_has_no_record() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let names = ["noexpiry.example.com", "deleting.example.com"];
    let (code, reports) = rdap(&stub, &web, &names, BOOTSTRAP);
    assert_eq!(code, 0, "{reports:?}");
    let r = &reports[0]["rdap"];
    assert_eq!(r["expires"], r["registrar_data"]["expires"]);
    assert!(r["expires"].is_string());
    let theirs = &reports[1]["rdap"]["registrar_data"];
    assert_eq!(
        (&theirs["status"], &theirs["expires"]),
        (&j!("not_found"), &Value::Null)
    );
}

#[test]
fn requests_to_one_host_are_a_second_apart() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let names = ["example.com", "soon.example.com", "lapsed.example.com"];
    let (_, reports) = rdap(&stub, &web, &names, BOOTSTRAP);
    assert!(reports.iter().all(|r| r["rdap"]["found"] == true));
    let times: Vec<_> = web
        .timed()
        .into_iter()
        .filter(|(h, _)| h.host == "rdap.example.net")
        .map(|(_, at)| at)
        .collect();
    assert_eq!(times.len(), 3);
    for pair in times.windows(2) {
        let gap = pair[1].duration_since(pair[0]).as_secs_f64();
        assert!(gap >= 1.0, "{gap} s");
    }
}

#[test]
fn a_missing_name_walks_one_label_up_at_most_three_times() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let names = ["wild.example.org", "serial.example.org", "a.b.example.net"];
    let (code, reports) = rdap(&stub, &web, &names, BOOTSTRAP);
    assert_eq!(code, 0);
    for r in &reports[..2] {
        assert_eq!(
            (&r["rdap"]["queried"], &r["rdap"]["found"]),
            (&j!("example.org"), &j!(true))
        );
    }
    let deep = &reports[2];
    assert_eq!(
        (&deep["rdap"]["queried"], &deep["rdap"]["found"]),
        (&j!("example.net"), &j!(false))
    );
    assert_eq!(
        found(deep),
        [
            "rdap_not_found: No registration record for example.net at rdap.example.net; it is probably not registered."
        ]
    );
    assert_eq!(
        asked(&web),
        [
            "/rdap/domain/wild.example.org",
            "/rdap/domain/example.org",
            "/rdap/domain/serial.example.org",
            "/rdap/domain/example.org",
            "/domain/a.b.example.net",
            "/domain/b.example.net",
            "/domain/example.net",
        ]
    );
    // The bootstrap file is read once per run.
    assert_eq!(fetched(&web, "/dns.json"), 1);
}

#[test]
fn a_name_not_in_dns_is_asked_about_itself_only() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, reports) = rdap(&stub, &web, &["gone.sub.example.com"], BOOTSTRAP);
    assert_eq!(code, 0);
    assert_eq!(reports[0]["rdap"]["queried"], "gone.sub.example.com");
    assert_eq!(asked(&web), ["/rdap/domain/gone.sub.example.com"]);
    assert_eq!(reports[0]["findings"][0]["code"], "rdap_not_found");
}

#[test]
fn http_answers_map_to_statuses_without_retrying_a_rate_limit() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let names = [
        "limited.example.com",
        "busy.example.com",
        "flaky.example.com",
        "html.example.com",
        "bad.example.com",
        "moved.example.com",
        "away.example.com",
    ];
    let started = Instant::now();
    let (code, reports) = rdap(&stub, &web, &names, BOOTSTRAP);
    // busy and flaky each wait 2 s before their second try.
    assert!(started.elapsed().as_secs_f64() >= 4.0);
    assert_eq!(code, 3);
    let status = |r: &Value| {
        let s = &r["rdap"];
        format!(
            "{} {}",
            s["status"].as_str().unwrap(),
            s["reason"].as_str().unwrap_or("-")
        )
    };
    let got: Vec<_> = reports.iter().map(status).collect();
    assert_eq!(
        got,
        [
            "rate_limited rdap.example.net limits lookups and asked us to wait 42 s.",
            "unavailable rdap.example.net answered HTTP 503.",
            "ok -",
            "unavailable rdap.example.net sent a response we couldn't read.",
            "unavailable rdap.example.net answered HTTP 400.",
            "ok -",
            "unavailable rdap.example.net answered HTTP 302.",
        ]
    );
    assert_eq!(reports[0]["rdap"]["retry_after"], 42);
    assert_eq!(reports[0]["rdap"]["registrar"], Value::Null);
    assert_eq!(reports[5]["rdap"]["queried"], "moved.example.com");
    assert_eq!(reports[5]["rdap"]["registrar"]["iana_id"], "9999");
    let times = |name: &str| {
        asked(&web)
            .iter()
            .filter(|p| p.ends_with(&format!("/{name}")))
            .count()
    };
    let counts: Vec<_> = names.iter().map(|n| times(n)).collect();
    assert_eq!(counts, [1, 2, 2, 1, 1, 1, 1]);
    // The redirect's target, and nothing for the http:// one.
    assert_eq!(times("example.com"), 1);
    assert!(web.hits().iter().all(|h| h.host != "rdap.example.org"));
}

#[test]
fn tlds_iana_doesnt_list_have_no_service_after_one_live_try() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, reports) = rdap(&stub, &web, &["example.de", "example.ch"], BOOTSTRAP);
    assert_eq!(code, 0);
    assert_eq!(
        found(&reports[0]),
        [
            "rdap_no_service: IANA lists no RDAP service for .de, so registration data can't be checked here."
        ]
    );
    assert_eq!(
        reports[0]["findings"][0]["hint"],
        "The registry may offer WHOIS or a web lookup."
    );
    let r = &reports[1]["rdap"];
    assert_eq!(
        (&r["status"], &r["found"], &r["server"], &r["queried"]),
        (&j!("ok"), &j!(false), &Value::Null, &j!("example.ch"))
    );
    // The file as given, then once more as the live one: never again in the run.
    assert_eq!(fetched(&web, "/dns.json"), 2);
    assert!(asked(&web).is_empty());
}

#[test]
fn an_unreachable_server_falls_back_to_the_live_bootstrap_once() {
    let (stub, web) = (DnsStub::new(), Web::new());
    let started = Instant::now();
    let fallback = "http://127.0.0.1/fallback/dns.json";
    let (code, reports) = rdap(&stub, &web, &["example.com"], fallback);
    assert_eq!(code, 0, "{reports:?}");
    assert!(started.elapsed().as_secs_f64() >= 2.0);
    let r = &reports[0]["rdap"];
    assert_eq!(
        (&r["found"], &r["bootstrap"], &r["server"]),
        (&j!(true), &j!("live"), &j!("https://rdap.example.net/rdap"))
    );
    assert_eq!(fetched(&web, "/fallback/dns.json"), 2);
    // Two tries at the server that hangs up during the handshake, then the live file's one.
    assert_eq!(asked(&web), ["/rdap/domain/example.com"]);
}

#[test]
fn private_rdap_servers_need_allow_private() {
    let stub = DnsStub::new();
    let dns = stub.addr();
    let (code, v) = json(&["example.com", "-c", "rdap", "--dns", &dns], &[]);
    assert_eq!(code, 3);
    let r = &v["reports"][0]["rdap"];
    assert_eq!(
        (&r["status"], &r["reason"]),
        (
            &j!("unavailable"),
            &j!("Couldn't reach 127.0.0.1: 127.0.0.1 is a private address.")
        )
    );
}

#[test]
fn the_bootstrap_override_is_https_or_loopback_http() {
    let var = "DOMAIN_CHECK_RDAP_BOOTSTRAP";
    for (url, want) in [
        (
            "http://rdap.example.net/dns.json",
            "✗ DOMAIN_CHECK_RDAP_BOOTSTRAP=http://rdap.example.net/dns.json uses http:// for a host that isn't this computer.\n  Use https://, or http:// only for 127.0.0.1 or ::1.\n",
        ),
        (
            "rdap.example.net/dns.json",
            "✗ DOMAIN_CHECK_RDAP_BOOTSTRAP=rdap.example.net/dns.json isn't an https:// URL.\n  Use the URL of an RDAP bootstrap file, or unset it.\n",
        ),
    ] {
        let (code, out, err) = run(&["example.com"], &[(var, url)]);
        assert_eq!((code, out.as_str(), err.as_str()), (2, "", want));
    }
    // IPv6 loopback is this computer too; nothing listens there, so the section can't run.
    let (stub, web) = (DnsStub::new(), Web::new());
    let (code, reports) = rdap(&stub, &web, &["example.com"], "http://[::1]/dns.json");
    assert_eq!(code, 3);
    let reason = reports[0]["rdap"]["reason"].as_str().unwrap();
    assert!(reason.starts_with("Couldn't reach [::1]: "), "{reason}");
}
