use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::{Arc, LazyLock};

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use domain_check::dns::{self, Resolver};
use domain_check::{Error, Ports, input, lookup};

// clap prints the name itself.
static VERSION: LazyLock<String> =
    LazyLock::new(|| domain_check::version().replacen("domain-check ", "", 1));

const SENTENCE: &str =
    "Check a domain's DNS, email security, registration, certificate and headers.";

const AFTER_HELP: &str = "\x1b[1;4mEnvironment:\x1b[0m
  DOMAIN_CHECK_LOOPBACK_PORTS    dns=N,http=N,https=N for loopback destinations (tests, mirrors)

\x1b[1;4mExamples:\x1b[0m
  domain-check lookup _dmarc.example.com TXT
  domain-check lookup 8.8.8.8";

#[derive(Parser)]
#[command(
    name = "domain-check",
    bin_name = "domain-check",
    about = SENTENCE,
    version = VERSION.as_str(),
    after_help = AFTER_HELP,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one DNS query (dig-like); an IP address gives its PTR
    #[command(after_help = AFTER_HELP)]
    Lookup(LookupArgs),
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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::new("runtime", format!("Couldn't start: {e}."), "Try again."))?;
    let answer = runtime.block_on(lookup::run(resolver, name, types));
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
    let mut text = format!("✗ {}\n", e.message);
    if let Some(hint) = &e.hint {
        text += &format!("  {hint}\n");
    }
    let _ = io::stderr().write_all(text.as_bytes());
}

/// The command line, with clap's own flags described in the same lower case as ours.
fn cli() -> clap::Command {
    let mut cli = Cli::command();
    cli.build();
    let lower = |c: clap::Command| c.mut_arg("help", |a| a.help("print help"));
    lower(cli)
        .mut_arg("version", |a| a.help("print version"))
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
        Command::Lookup(args) => run_lookup(args),
    };
    match done {
        // A closed stdout (`| head`) means nobody reads the rest: stop quietly.
        Ok(Done { out, code }) => match io::stdout().write_all(out.as_bytes()) {
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
        },
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
