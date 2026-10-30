use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::sync::{Arc, LazyLock};

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use domain_check::check::{self, Options};
use domain_check::dns::{self, Resolver};
use domain_check::{Error, Ports, input, lookup, text};

// clap prints the name itself.
static VERSION: LazyLock<String> =
    LazyLock::new(|| domain_check::version().replacen("domain-check ", "", 1));

const SENTENCE: &str =
    "Check a domain's DNS, email security, registration, certificate and headers.";

const USAGE: &str = "domain-check [check] <DOMAIN>... [OPTIONS]
       domain-check <COMMAND>";

const AFTER_HELP: &str = "Checks: dns, propagation, email.
Only ports 53, 80 and 443 are contacted; nothing is stored.

\x1b[1;4mEnvironment:\x1b[0m
  NO_COLOR                       no colour
  DOMAIN_CHECK_LOOPBACK_PORTS    dns=N,http=N,https=N for loopback destinations (tests, mirrors)

\x1b[1;4mExamples:\x1b[0m
  domain-check example.com
  domain-check example.com --checks email --spf-ip 192.0.2.10
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
}

#[derive(clap::Args)]
struct CheckArgs {
    /// a domain, URL or email address
    #[arg(value_name = "DOMAIN")]
    domains: Vec<String>,
    /// sections to run: dns, propagation, email or all
    #[arg(
        short,
        long,
        value_name = "LIST",
        value_delimiter = ',',
        default_value = "all"
    )]
    checks: Vec<String>,
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

fn run_check(args: CheckArgs) -> Result<Done, Error> {
    if args.domains.is_empty() {
        return Err(Error::usage(
            "No domain given.",
            "Try: domain-check example.com",
        ));
    }
    let options = Options {
        checks: check::checks(&args.checks)?,
        dns: args
            .dns
            .as_deref()
            .map(|s| dns::server("--dns", s))
            .transpose()?,
        resolvers: args
            .resolver
            .iter()
            .map(|s| dns::server("--resolver", s))
            .collect::<Result<_, _>>()?,
        types: lookup::types(&args.types)?,
        selectors: Vec::new(),
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
        ports: Ports::from_env()?,
        debug: args.debug,
    };
    let mut line = Line {
        on: !args.json && !args.debug && io::stderr().is_terminal(),
        width: 0,
    };
    let output = check::run(&args.domains, &options, &mut |domain, marks, secs| {
        line.draw(&text::progress(domain, marks, secs))
    });
    line.clear();
    let output = output?;
    let out = match args.json {
        true => json(&output)?,
        false => text::output(&output),
    };
    let code = output.exit_code();
    Ok(Done { out, code })
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
    let mut text = format!("{} {}\n", text::red("✗"), e.message);
    if let Some(hint) = &e.hint {
        text += &format!("  {}\n", text::dim(hint));
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
