//! CLI for validating and running Rite ceremonies.

#![allow(clippy::print_stdout, clippy::print_stderr)]

mod check;
mod common;
mod console;
mod headless;
#[cfg(feature = "render")]
mod report;
mod run;
#[cfg(feature = "render")]
mod script;
mod system_info;
mod verify;
mod version;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

#[cfg(feature = "render")]
const TOP_LEVEL_AFTER_HELP: &str = "\
Lifecycle:
  rite check  ceremony.rite.yaml  # validate
  rite script ceremony.rite.yaml  # generate script
  rite run    ceremony.rite.yaml  # execute with transcript
  rite verify <output-dir>        # verify integrity
  rite report <output-dir>        # generate audit report

Exit codes:
  0  Success
  1  A negative result or bad input (invalid ceremony, failed verification)
  2  A usage error, or an unexpected internal fault
";

#[cfg(not(feature = "render"))]
const TOP_LEVEL_AFTER_HELP: &str = "\
Lifecycle:
  rite check  ceremony.rite.yaml  # validate
  rite run    ceremony.rite.yaml  # execute with transcript
  rite verify <output-dir>        # verify integrity

Exit codes:
  0  Success
  1  A negative result or bad input (invalid ceremony, failed verification)
  2  A usage error, or an unexpected internal fault
";

#[derive(Parser)]
#[command(name = "rite")]
#[command(version)]
#[command(about = "A CLI for cryptographic key ceremonies", long_about = None)]
#[command(after_help = TOP_LEVEL_AFTER_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a ceremony definition without running it
    ///
    /// Resolves the ceremony and reports diagnostics (missing references,
    /// undefined roles, schema errors, actions unsupported by this build), or a
    /// summary of what it contains.
    Check(check::Args),
    /// Run a ceremony and record its transcript
    ///
    /// Walks the operator and witnesses through each step, performs the
    /// machine-verifiable actions, and writes a timestamped output directory
    /// with the artifacts and an append-only transcript.
    Run(run::Args),
    /// Verify a ceremony transcript's integrity
    ///
    /// Re-checks the append-only hash chain, re-derives the recorded entropy,
    /// and, for a run directory, re-hashes the artifacts against their recorded
    /// digests.
    Verify(verify::Args),
    /// Render a ceremony as a printable protocol
    ///
    /// Produces a self-contained HTML document that participants follow and
    /// complete by hand during the ceremony.
    #[cfg(feature = "render")]
    Script(script::Args),
    /// Render a post-ceremony report from a transcript
    ///
    /// Produces a self-contained HTML report of a completed run, for
    /// stakeholders and auditors.
    #[cfg(feature = "render")]
    Report(report::Args),
    /// Print version and build information
    Version(version::Args),
    /// Print a shell completion script
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

fn main() {
    match Cli::parse().command {
        Commands::Check(args) => check::run(&args),
        Commands::Run(args) => run::run(args),
        Commands::Verify(args) => verify::run(args),
        #[cfg(feature = "render")]
        Commands::Script(args) => script::run(&args),
        #[cfg(feature = "render")]
        Commands::Report(args) => report::run(&args),
        Commands::Version(args) => version::run(&args),
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn supports_top_level_version_flag() {
        match Cli::try_parse_from(["rite", "--version"]) {
            Ok(_) => panic!("--version should exit"),
            Err(err) => assert_eq!(err.kind(), ErrorKind::DisplayVersion),
        }
    }
}
