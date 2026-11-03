# domain-check

Check a domain's DNS, email security, registration, certificate and headers from your own computer, with problems first.

## Install

Windows (PowerShell, no admin; installs to `%LOCALAPPDATA%\Programs\domain-check` and adds it to your user PATH):

```powershell
irm https://github.com/nowmyagentcan/domain-check/releases/latest/download/install.ps1 | iex
```

macOS and Linux (installs to `~/.local/bin`):

```sh
curl -fsSL https://github.com/nowmyagentcan/domain-check/releases/latest/download/install.sh | sh
```

| System | Download |
|---|---|
| Windows x64 | [domain-check-v0.1.0-windows-x64.zip](https://github.com/nowmyagentcan/domain-check/releases/download/v0.1.0/domain-check-v0.1.0-windows-x64.zip) |
| macOS Apple silicon | [domain-check-v0.1.0-macos-arm64.tar.gz](https://github.com/nowmyagentcan/domain-check/releases/download/v0.1.0/domain-check-v0.1.0-macos-arm64.tar.gz) |
| macOS Intel | [domain-check-v0.1.0-macos-x64.tar.gz](https://github.com/nowmyagentcan/domain-check/releases/download/v0.1.0/domain-check-v0.1.0-macos-x64.tar.gz) |
| Linux x64 | [domain-check-v0.1.0-linux-x64.tar.gz](https://github.com/nowmyagentcan/domain-check/releases/download/v0.1.0/domain-check-v0.1.0-linux-x64.tar.gz) |
| Linux arm64 | [domain-check-v0.1.0-linux-arm64.tar.gz](https://github.com/nowmyagentcan/domain-check/releases/download/v0.1.0/domain-check-v0.1.0-linux-arm64.tar.gz) |

With Rust: `cargo install --git https://github.com/nowmyagentcan/domain-check --tag v0.1.0 --locked`.
This is not the crates.io crate of the same name (a domain availability checker by another author), so installing by name from crates.io gets you that one instead.

## Use

```text
$ domain-check example.com --checks dns,tls,http
example.com  5 warnings · 4 info · checked 21:58 UTC
! http  No Content-Security-Policy header.
        Start with "default-src 'self'; object-src 'none'; frame-ancestors 'none'" and adjust.
! http  Neither X-Frame-Options nor CSP frame-ancestors is set, so other sites can frame this page.
        Add "Content-Security-Policy: frame-ancestors 'self'" or "X-Frame-Options: DENY".
! http  No Strict-Transport-Security header.
        Add "Strict-Transport-Security: max-age=63072000; includeSubDomains".
! http  http://example.com/ doesn't redirect to HTTPS (it answers 200).
        Redirect every HTTP request to https://.
! http  No "X-Content-Type-Options: nosniff" header.
        Add it.
i dns   No CAA record: any certificate authority may issue certificates for example.com.
        Add one naming your CA, e.g. 0 issue "letsencrypt.org".
i http  No Cross-Origin-Opener-Policy header.
        Add "Cross-Origin-Opener-Policy: same-origin" if the site doesn't need cross-origin popups.
i http  No Permissions-Policy header.
i http  No Referrer-Policy header.
        Add "Referrer-Policy: strict-origin-when-cross-origin" or stricter.

DNS          A 104.20.23.154, 172.66.147.243 · AAAA 2606:4700:10::6814:179a, 2606:4700:10::ac42:93f3 · MX 0 . (null MX) · NS hera.ns.cloudflare.com, elliott.ns.cloudflare.com · DNSSEC signed, validated
Propagation  skipped: not requested
Email        skipped: not requested
Registration skipped: not requested
Certificate  example.com · Cloudflare TLS Issuing ECC CA 3 · until 2026-12-25 (56 days) · TLS 1.3 · trusted
Web          http → 200 · HSTS no · CSP no
```

```sh
domain-check example.com                                       # all six checks
domain-check example.com --checks email -s google              # a DKIM selector you know
domain-check example.com --checks email --spf-ip 192.0.2.10    # would mail from this IP pass SPF?
domain-check example.com --checks propagation --types A,MX
domain-check lookup _dmarc.example.com TXT                     # one DNS query, like dig
domain-check lookup 8.8.8.8                                    # reverse DNS
domain-check example.com example.org --json
```

Checks: `dns`, `propagation`, `email`, `rdap` (registration), `tls` (certificate), `http` (redirects and headers).
Exit codes: 0 clean, 1 error findings or bad input, 2 usage error, 3 a check couldn't reach the network.
`domain-check` alone in a terminal asks for domains one at a time; `domain-check check --help` lists every option.

`domain-check ui` opens the same report as a page in your browser, served on 127.0.0.1 only.

### Use with AI agents

`check --json` prints `{reports, summary, data}`: per domain, `findings` (code, severity, message, hint), `counts` and one object per check, or `error` (`{code, message, hint}`) for input it refuses, such as `special_use`.
`lookup --json` prints `{name, server, results}`, with `{type, rcode, authoritative, authenticated, records: [{value, ttl}], error}` per type.
Usage errors (exit 2, such as `--spf-ip nope`) print plain text on stderr and nothing on stdout.
`domain-check mcp` is a local MCP server on stdio with two tools: `check_domain` (one domain's report) and `dns_lookup` (one query); results carry the same JSON.
Bad arguments give `isError: true` and `{"error": {"code", "message", "hint"}}` as text.

| Agent | Setup |
|---|---|
| Claude Code | `claude mcp add domain-check -- domain-check mcp` |
| Codex | `codex mcp add domain-check -- domain-check mcp` |
| Cursor (`~/.cursor/mcp.json`), Claude Desktop | `{"mcpServers":{"domain-check":{"command":"domain-check","args":["mcp"]}}}` |
| VS Code (`.vscode/mcp.json`) | `{"servers":{"domain-check":{"type":"stdio","command":"domain-check","args":["mcp"]}}}` |

## Supported inputs and limits

- A domain, a URL (`https://www.example.com/shop`) or an email address; internationalised names are shown in both forms (`bücher.de`, `xn--bcher-kva.de`). Up to 20 domains per run; IP addresses go to `lookup`.
- `check` refuses special-use names (`.test`, `.local`, `.internal`, `*.localhost` …) without a query (code `special_use`); `lookup` does send them to your resolver or `--dns`.
- Email: MX, SPF with its DNS lookup and void lookup counts (RFC 7208), DMARC discovery (RFC 9989), DKIM keys and sizes for given or 8 common selectors, MTA-STS with its policy, TLS-RPT, BIMI. Registration: RDAP for the top-level domains IANA lists.
- Not in this version: port 25 (STARTTLS, DANE), blocklists, WHOIS, cipher scans, certificate transparency, local DNSSEC validation.
- `ui` and `mcp` take `--resolver` and `--ca-file` for every check they run.

### What goes online

Every check goes online from your computer, straight to these, and to nothing else (only ports 53, 80 and 443; no proxy):

- DNS: your system resolver (or `--dns`), the domain's own nameservers, and Google 8.8.8.8, Cloudflare 1.1.1.1 and Quad9 9.9.9.10 for the comparison (or `--resolver`).
- Registration: the registry's RDAP server from IANA's bootstrap list (bundled; `data.iana.org` only when a domain's server isn't in it), and the registrar's RDAP server it links to.
- The domain's web server on 80 and 443, its MTA-STS policy host and its BIMI files. Your OS may fetch certificate intermediates and revocation lists while checking trust.

It sends the domain name and nothing else, except that with `--spf-ip`, SPF macros such as `%{i}` put that IP address into the DNS names it looks up. There is no account, no API key, no telemetry and no update check.
TLS and HTTP connections to private addresses are refused unless you pass `--allow-private`.
The services keep their own terms: RDAP servers allow lookups you ask for but not bulk or automated sweeps, hence at most 20 domains, 4 RDAP requests per domain and a 1 s pause per server; Google Public DNS falls under the Google APIs Terms of Service and 1.1.1.1 under Cloudflare's terms.
Expiry days use this computer's clock.

## How it works

One Rust binary runs each check in parallel within a time budget and ranks the findings errors first.
DNS uses [hickory-dns](https://github.com/hickory-dns/hickory-dns), asking each nameserver directly for propagation; TLS uses [rustls](https://github.com/rustls/rustls) with the OS trust store via rustls-platform-verifier, certificates are read with [x509-parser](https://github.com/rusticata/x509-parser), and HTTP, RDAP and MTA-STS go through [ureq](https://github.com/algesten/ureq).
RDAP servers come from [IANA's bootstrap data](https://data.iana.org/rdap/dns.json) (CC0), bundled with its date shown in `--version`.

## First run on an unsigned build

Windows: if "Windows protected your PC" appears, choose More info, then Run anyway.
The install script doesn't trigger it; a zip extracted in Explorer may.

macOS: if it says the developer can't be verified, open System Settings, Privacy & Security, and choose Open Anyway.
The install script doesn't trigger it, because curl downloads carry no quarantine flag.

## Licence

Apache-2.0, see [LICENSE](LICENSE). Each release archive includes `THIRD-PARTY-LICENSES.txt` for the bundled dependencies.

---

[nowmyagentcan.com](https://nowmyagentcan.com) · [x.com/chayp05](https://x.com/chayp05)
