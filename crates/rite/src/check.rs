//! `rite check`: validate a ceremony definition file.

use crate::common::{InputArgs, build_inputs_or_exit, resolve_or_exit};
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
#[command(after_long_help = crate::common::INPUT_ENV_HELP)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    #[command(flatten)]
    pub input: InputArgs,
}

pub fn run(args: &Args) {
    let inputs = build_inputs_or_exit(&args.input);
    let resolved = resolve_or_exit(&args.file, (!inputs.is_empty()).then_some(&inputs));

    let registry = rite_stdlib::default_registry();
    let unsupported = registry.unsupported_actions(&resolved.execution_plan);
    if !unsupported.is_empty() {
        let names: Vec<_> = unsupported.iter().map(ToString::to_string).collect();
        eprintln!("Validation errors:");
        eprintln!(
            "  - Unsupported action(s) for this build: {}",
            names.join(", ")
        );
        std::process::exit(1);
    }

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
