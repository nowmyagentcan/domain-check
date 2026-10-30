const PAGE: &str = include_str!("../src/ui.html");

#[test]
fn page_reaches_no_other_host() {
    let allowed = [
        "https://nowmyagentcan.com",
        "https://github.com/nowmyagentcan/domain-check",
        "https://x.com/chayp05",
        "http://www.w3.org/2000/svg",
        "http://${",
        "https://${",
        "https://mta-sts.${",
    ];
    for (i, _) in PAGE.match_indices("://") {
        let start = PAGE[..i]
            .rfind(|c: char| !c.is_ascii_alphanumeric())
            .map_or(0, |p| p + 1);
        let url = &PAGE[start..];
        assert!(
            allowed.iter().any(|a| url.starts_with(a)),
            "unexpected URL: {}",
            &url[..url.len().min(60)]
        );
    }
    for loader in ["<script src", "<link rel=\"stylesheet\"", "@import", "url("] {
        assert!(!PAGE.contains(loader), "page loads a file: {loader}");
    }
}

#[test]
fn page_has_the_title_and_one_button() {
    assert!(PAGE.contains("<title>Check a domain</title>"));
    assert_eq!(
        PAGE.matches("<button class=\"go\">Check</button>").count(),
        1
    );
    let markup = &PAGE[..PAGE.find("<script>").unwrap()];
    assert_eq!(markup.matches("<button").count(), 1);
}

#[test]
fn page_sends_only_check_domain_arguments() {
    let known = [
        "domain",
        "checks",
        "dkim_selectors",
        "spf_ip",
        "types",
        "dns_server",
        "allow_private",
    ];
    for (i, _) in PAGE.match_indices("body.") {
        let key: String = PAGE[i + 5..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        assert!(known.contains(&key.as_str()), "unknown argument: {key}");
    }
    for check in ["dns", "propagation", "email", "rdap", "tls", "http"] {
        assert!(PAGE.contains(&format!("name=\"checks\" value=\"{check}\" checked")));
    }
    assert!(PAGE.contains("<input id=\"allow_private\" type=\"checkbox\">"));
}
