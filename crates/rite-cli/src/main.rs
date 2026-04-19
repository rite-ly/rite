//! CLI for validating and running Rite ceremonies.

#![allow(clippy::print_stdout, clippy::print_stderr)]

mod check;
mod common;
mod run;
mod verify;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

#[derive(Parser)]
#[command(name = "rite")]
#[command(about = "A CLI for cryptographic key ceremonies", long_about = None)]
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
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            let bin_name = cmd.get_name().to_string();
            generate(shell, &mut cmd, bin_name, &mut std::io::stdout());
        }
    }
}
