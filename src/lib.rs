pub mod input;

/// The `publication` stamp of the bundled IANA RDAP bootstrap file, `data/rdap-dns.json`.
pub const RDAP_BOOTSTRAP: &str = "2026-10-28T22:00:04Z";
pub const RDAP_BOOTSTRAP_JSON: &str = include_str!("../data/rdap-dns.json");

pub fn version() -> String {
    format!(
        "domain-check {} (RDAP bootstrap {})",
        env!("CARGO_PKG_VERSION"),
        &RDAP_BOOTSTRAP[..10]
    )
}

/// What went wrong and how to fix it: an input's error in a report, or a usage error.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
}

impl Error {
    pub fn new(code: &'static str, message: impl Into<String>, hint: impl Into<String>) -> Error {
        Error {
            code,
            message: message.into(),
            hint: Some(hint.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bootstrap_stamp_matches_the_bundled_file() {
        let field = format!("\"publication\": \"{RDAP_BOOTSTRAP}\"");
        assert!(
            RDAP_BOOTSTRAP_JSON.contains(&field),
            "update RDAP_BOOTSTRAP to the file's publication"
        );
    }

    #[test]
    fn version_names_the_bootstrap_date() {
        assert_eq!(version(), "domain-check 0.1.0 (RDAP bootstrap 2026-10-28)");
    }
}
