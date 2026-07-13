//! `rite check`: validate a ceremony definition file.

use crate::common::{InputArgs, build_inputs_or_exit, resolve_or_exit, unsupported_action_names};
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

    // Build-relative, not a definition error: the ceremony is valid, but this
    // binary lacks the feature(s) to run these actions. The machine that
    // executes may be a fuller build, so warn rather than fail. `rite run`
    // makes the same check fatal.
    let unsupported = unsupported_action_names(&resolved);
    if !unsupported.is_empty() {
        eprintln!();
        eprintln!(
            "Note: this build cannot execute {} action(s): {}",
            unsupported.len(),
            unsupported.join(", ")
        );
        eprintln!("Run it with a build that includes the required feature(s).");
    }
}
