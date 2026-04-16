//! CLI for validating and running Rite ceremonies.

#![allow(clippy::print_stdout, clippy::print_stderr)]

mod check;
mod common;
mod run;
mod verify;

use clap::{Parser, Subcommand};

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
}

fn main() {
    match Cli::parse().command {
        Commands::Check(args) => check::run(&args),
        Commands::Run(args) => run::run(args),
        Commands::Verify(args) => verify::run(args),
    }
}
