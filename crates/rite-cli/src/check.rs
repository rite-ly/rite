//! `rite check` — validate a ceremony definition file.

use crate::common::{InputArgs, build_inputs_or_exit};
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    #[command(flatten)]
    pub input: InputArgs,
}

pub fn run(args: &Args) {
    let inputs = build_inputs_or_exit(&args.input);

    let (resolved_opt, diags) =
        rite_resolver::analyze(&args.file, (!inputs.is_empty()).then_some(&inputs));

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    for d in &diags {
        eprintln!("{d}");
    }

    if has_errors {
        std::process::exit(1);
    }

    // resolved_opt is always Some when no error diagnostics were produced.
    let Some(resolved) = resolved_opt else {
        eprintln!("Internal error: ceremony resolved to None with no errors");
        std::process::exit(1);
    };

    println!("Valid ceremony: {}", resolved.metadata.name);
    println!("  Roles: {}", resolved.roles.len());
    println!("  Steps: {}", resolved.execution_plan.len());
    if !resolved.parameters.is_empty() {
        println!("  Parameters: {}", resolved.parameters.len());
    }
    if !resolved.materials.is_empty() {
        println!("  Materials: {}", resolved.materials.len());
    }
    if !resolved.outputs.is_empty() {
        println!("  Outputs: {}", resolved.outputs.len());
    }
    if !resolved.after.is_empty() {
        println!("  Post-ceremony duties: {}", resolved.after.len());
    }
}
