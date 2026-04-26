//! CLI for validating and running Rite ceremonies.

#![allow(clippy::print_stdout, clippy::print_stderr)]

mod check;
mod common;
#[cfg(feature = "render")]
mod report;
mod run;
#[cfg(feature = "render")]
mod script;
mod verify;

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
";

#[cfg(not(feature = "render"))]
const TOP_LEVEL_AFTER_HELP: &str = "\
Lifecycle:
  rite check  ceremony.rite.yaml  # validate
  rite run    ceremony.rite.yaml  # execute with transcript
  rite verify <output-dir>        # verify integrity
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
    /// Validate a ceremony definition file
    Check(check::Args),
    /// Execute a ceremony interactively
    Run(run::Args),
    /// Verify a ceremony transcript's integrity
    Verify(verify::Args),
    /// Generate a printable HTML ceremony script
    #[cfg(feature = "render")]
    Script(script::Args),
    /// Generate an HTML post-ceremony report from a transcript
    #[cfg(feature = "render")]
    Report(report::Args),
    /// Generate shell completion scripts
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
        Commands::Report(args) => report::run(args),
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
