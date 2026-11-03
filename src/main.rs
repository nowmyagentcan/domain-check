use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::{Arc, LazyLock, mpsc};
use std::thread;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use domain_check::check::{self, Options};
use domain_check::dns::{self, Resolver};
use domain_check::mcp::{self, Defaults};
use domain_check::report::Output;
use domain_check::sections::email::dkim;
use domain_check::sections::rdap;
use domain_check::{Error, Ports, input, interactive, lookup, net, text, ui};

// clap prints the name itself.
static VERSION: LazyLock<String> =
    LazyLock::new(|| domain_check::version().replacen("domain-check ", "", 1));

const SENTENCE: &str =
    "Check a domain's DNS, email security, registration, certificate and headers.";

const USAGE: &str = "domain-check [check] <DOMAIN>... [OPTIONS]
       domain-check <COMMAND>";

const AFTER_HELP: &str =
    "Checks: dns, propagation, email, rdap (registration), tls (certificate), http (redirects and headers).
Only ports 53, 80 and 443 are contacted; nothing is stored.

\x1b[1;4mEnvironment:\x1b[0m
  NO_COLOR                       no colour
  DOMAIN_CHECK_RDAP_BOOTSTRAP    URL of an RDAP bootstrap file to use instead of the bundled one
  DOMAIN_CHECK_LOOPBACK_PORTS    dns=N,http=N,https=N for loopback destinations (tests, mirrors)

\x1b[1;4mExamples:\x1b[0m
  domain-check example.com
  domain-check example.com --checks email -s google
  domain-check example.com --checks email --spf-ip 192.0.2.10
  domain-check example.com --checks tls,http
  domain-check example.com --checks propagation --types A,MX
  domain-check lookup _dmarc.example.com TXT
  domain-check lookup 8.8.8.8
  domain-check example.com example.org --json";

#[derive(Parser)]
#[command(
    name = "domain-check",
    bin_name = "domain-check",
    about = SENTENCE,
    version = VERSION.as_str(),
    override_usage = USAGE,
    after_help = AFTER_HELP,
    args_conflicts_with_subcommands = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    check: CheckArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Report on 1-20 domains (the default)
    #[command(after_help = AFTER_HELP)]
    Check(CheckArgs),
    /// Run one DNS query (dig-like); an IP address gives its PTR
    #[command(after_help = AFTER_HELP)]
    Lookup(LookupArgs),
    /// Open the local web page
    Ui(UiArgs),
    /// Run the MCP server on stdio
    Mcp(ServerArgs),
}

#[derive(clap::Args)]
struct UiArgs {
    /// port on 127.0.0.1; 0 picks a free one
    #[arg(long, value_name = "N", default_value_t = 0)]
    port: u16,
    /// don't open the browser
    #[arg(long)]
    no_open: bool,
    #[command(flatten)]
    server: ServerArgs,
}

/// What every check a server runs starts from.
#[derive(clap::Args)]
struct ServerArgs {
    /// public resolver for propagation and DNSSEC (repeatable)
    #[arg(long, value_name = "IP[:PORT]")]
    resolver: Vec<String>,
    /// also trust the PEM certificates in FILE
    #[arg(long, value_name = "FILE")]
    ca_file: Option<String>,
}

impl ServerArgs {
    fn defaults(&self) -> Result<Defaults, Error> {
        Defaults::new(resolvers(&self.resolver)?, ca(self.ca_file.as_deref())?)
    }
}

fn resolvers(raw: &[String]) -> Result<Vec<std::net::SocketAddr>, Error> {
    raw.iter().map(|s| dns::server("--resolver", s)).collect()
}

fn ca(file: Option<&str>) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Error> {
    Ok(file.map(net::ca_file).transpose()?.unwrap_or_default())
}

#[derive(clap::Args)]
struct CheckArgs {
    /// a domain, URL or email address
    #[arg(value_name = "DOMAIN")]
    domains: Vec<String>,
    /// sections to run: dns, propagation, email, rdap, tls, http or all
    #[arg(
        short,
        long,
        value_name = "LIST",
        value_delimiter = ',',
        default_value = "all"
    )]
    checks: Vec<String>,
    /// DKIM selector to look up (repeatable)
    #[arg(short = 's', long, value_name = "S")]
    dkim_selector: Vec<String>,
    /// evaluate SPF for this sending IP
    #[arg(long, value_name = "IP")]
    spf_ip: Option<String>,
    /// record types compared in propagation
    #[arg(
        short,
        long,
        value_name = "LIST",
        value_delimiter = ',',
        default_value = "A,AAAA,MX,TXT"
    )]
    types: Vec<String>,
    /// resolver for every lookup except the comparisons
    #[arg(long, value_name = "IP[:PORT]")]
    dns: Option<String>,
    /// public resolver for propagation and DNSSEC (repeatable)
    #[arg(long, value_name = "IP[:PORT]")]
    resolver: Vec<String>,
    /// also trust the PEM certificates in FILE
    #[arg(long, value_name = "FILE")]
    ca_file: Option<String>,
    /// allow TLS and HTTP to private addresses
    #[arg(long)]
    allow_private: bool,
    /// print one JSON object
    #[arg(long)]
    json: bool,
    /// print every query and request on stderr
    #[arg(long)]
    debug: bool,
}

#[derive(clap::Args)]
struct LookupArgs {
    /// a DNS name, or an IP address for its PTR record
    #[arg(value_name = "NAME|IP")]
    name: String,
    /// A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, SRV, PTR, DS, DNSKEY, TLSA, HTTPS or SVCB [default: A AAAA]
    #[arg(value_name = "TYPE")]
    types: Vec<String>,
    /// resolver to ask instead of this computer's
    #[arg(long, value_name = "IP[:PORT]")]
    dns: Option<String>,
    /// print one JSON object
    #[arg(long)]
    json: bool,
    /// print every query on stderr
    #[arg(long)]
    debug: bool,
}

/// What a command prints on stdout, and its exit code.
struct Done {
    out: String,
    code: u8,
}

impl Done {
    fn nothing() -> Done {
        Done {
            out: String::new(),
            code: 0,
        }
    }
}

fn run_lookup(args: LookupArgs) -> Result<Done, Error> {
    let types = lookup::types(&args.types)?;
    let server = args
        .dns
        .as_deref()
        .map(|s| dns::server("--dns", s))
        .transpose()?;
    let ports = Ports::from_env()?;
    let target = match input::target(&args.name) {
        Ok(target) => target,
        Err(error) => {
            #[derive(serde::Serialize)]
            struct Failed {
                error: Error,
            }
            let out = match args.json {
                true => json(&Failed { error })?,
                false => {
                    fail(&error);
                    String::new()
                }
            };
            return Ok(Done { out, code: 1 });
        }
    };
    let (name, types) = lookup::question(target, types)?;
    let resolver = Arc::new(Resolver::new(server, ports, args.debug)?);
    let answer = domain_check::runtime()?.block_on(lookup::run(resolver, name, types));
    let code = answer.exit_code();
    let out = match args.json {
        true => json(&answer)?,
        false => {
            answer.failures().iter().for_each(fail);
            answer.text()
        }
    };
    Ok(Done { out, code })
}

/// The check options the flags ask for.
fn options(args: &CheckArgs) -> Result<Options, Error> {
    Ok(Options {
        checks: check::checks(&args.checks)?,
        dns: args
            .dns
            .as_deref()
            .map(|s| dns::server("--dns", s))
            .transpose()?,
        resolvers: resolvers(&args.resolver)?,
        types: lookup::types(&args.types)?,
        selectors: dkim::selectors(&args.dkim_selector)?,
        spf_ip: args
            .spf_ip
            .as_deref()
            .map(|ip| {
                ip.parse().map_err(|_| {
                    Error::usage(
                        format!("--spf-ip {ip} isn't an IP address."),
                        "Pass the sending server's address, e.g. --spf-ip 192.0.2.10.",
                    )
                })
            })
            .transpose()?,
        ca: ca(args.ca_file.as_deref())?,
        allow_private: args.allow_private,
        ports: Ports::from_env()?,
        bootstrap: rdap::from_env()?,
        debug: args.debug,
    })
}

/// [`check::run`], with the progress line on a terminal's stderr unless `quiet`.
fn checked(domains: &[String], o: &Options, quiet: bool) -> Result<Output, Error> {
    let mut line = Line {
        on: !quiet && !o.debug && io::stderr().is_terminal(),
        width: 0,
    };
    let output = check::run(domains, o, &mut |domain, marks, secs| {
        line.draw(&text::progress(domain, marks, secs))
    });
    line.clear();
    output
}

fn run_check(args: CheckArgs) -> Result<Done, Error> {
    if args.domains.is_empty() {
        return Err(Error::usage(
            "No domain given.",
            "Try: domain-check example.com",
        ));
    }
    let output = checked(&args.domains, &options(&args)?, args.json)?;
    let out = match args.json {
        true => json(&output)?,
        false => text::output(&output),
    };
    let code = output.exit_code();
    Ok(Done { out, code })
}

/// The banner, then a prompt reading domains and session commands until /quit or the end of
/// input.
fn run_interactive(args: CheckArgs) -> Result<Done, Error> {
    let mut options = options(&args)?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in io::stdin().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut say = |text: &str| {
        let mut out = anstream::stdout();
        let _ = out.write_all(fit(&io::stdout(), text).as_bytes());
        let _ = out.flush();
    };
    say(&interactive::banner(env!("CARGO_PKG_VERSION"), SENTENCE));
    interactive::run(rx, &mut options, &mut say, &mut |domains, o| {
        Ok(text::output(&checked(domains, o, false)?))
    });
    Ok(Done::nothing())
}

/// The progress line on a terminal's stderr, redrawn in place.
struct Line {
    on: bool,
    width: usize,
}

impl Line {
    fn draw(&mut self, text: &str) {
        if self.on {
            let width = text::width(text);
            let pad = self.width.saturating_sub(width);
            err(&format!("\r{text}{:pad$}", ""));
            self.width = width;
        }
    }

    fn clear(&mut self) {
        if self.width > 0 {
            err(&format!("\r{:w$}\r", "", w = self.width));
            self.width = 0;
        }
    }
}

/// `text` as `stream` can show it: ASCII stand-ins where Unicode can't show.
fn fit(stream: &impl IsTerminal, text: &str) -> String {
    match text::unicode(stream) {
        true => text.to_string(),
        false => text::ascii(text),
    }
}

/// Writes on stderr, colour only on a terminal; a closed stderr loses it quietly.
fn err(text: &str) {
    let _ = anstream::stderr().write_all(fit(&io::stderr(), text).as_bytes());
}

/// One JSON object on a line.
fn json(value: &impl serde::Serialize) -> Result<String, Error> {
    let text = serde_json::to_string(value).map_err(|e| {
        Error::new(
            "runtime",
            format!("Couldn't write JSON: {e}."),
            "Try again.",
        )
    })?;
    Ok(text + "\n")
}

/// An error's two lines on stderr: what failed, then how to fix it.
fn fail(e: &Error) {
    let mut text = format!("{} {}\n", text::red("✗"), text::escape(&e.message));
    if let Some(hint) = &e.hint {
        text += &format!("  {}\n", text::dim(&text::escape(hint)));
    }
    err(&text);
}

/// The command line, with clap's own flags described in the same lower case as ours.
fn cli() -> clap::Command {
    let mut cli = Cli::command();
    cli.build();
    let lower = |c: clap::Command| c.mut_arg("help", |a| a.help("print help"));
    // `check --help` lists the check options; the top level only -h and -V.
    let top = cli.mut_args(|a| match a.get_id().as_str() {
        "help" | "version" => a,
        _ => a.hide(true),
    });
    lower(top)
        .mut_arg("version", |a| a.help("print version"))
        .mut_subcommand("check", lower)
        .mut_subcommand("lookup", lower)
        .mut_subcommand("ui", lower)
        .mut_subcommand("mcp", lower)
}

fn main() -> ExitCode {
    let parsed = cli()
        .try_get_matches()
        .and_then(|m| Cli::from_arg_matches(&m));
    let cli = match parsed {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let done = match cli.command {
        Some(Command::Check(args)) => run_check(args),
        Some(Command::Lookup(args)) => run_lookup(args),
        Some(Command::Ui(args)) => args
            .server
            .defaults()
            .and_then(|d| ui::serve(args.port, !args.no_open, d))
            .map(|()| Done::nothing()),
        Some(Command::Mcp(args)) => args
            .defaults()
            .and_then(mcp::serve)
            .map(|()| Done::nothing()),
        // No arguments at all, in a terminal: the interactive session.
        None if std::env::args_os().len() == 1
            && io::stdin().is_terminal()
            && io::stdout().is_terminal() =>
        {
            run_interactive(cli.check)
        }
        None => run_check(cli.check),
    };
    match done {
        // A closed stdout (`| head`) means nobody reads the rest: stop quietly.
        Ok(Done { out, code }) => {
            match anstream::stdout().write_all(fit(&io::stdout(), &out).as_bytes()) {
                Ok(()) => ExitCode::from(code),
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
                Err(e) => {
                    fail(&Error::new(
                        "io",
                        format!("Couldn't write output: {e}."),
                        "Try again.",
                    ));
                    ExitCode::from(3)
                }
            }
        }
        Err(e) => {
            fail(&e);
            ExitCode::from(if e.code == "usage" { 2 } else { 3 })
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn checks_the_command_line() {
        super::cli().debug_assert();
    }
}
