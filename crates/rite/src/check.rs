//! `rite check`: validate a ceremony definition file.

use crate::common::{
    InputArgs, build_inputs_or_exit, resolve_with_spans_or_exit, step_param_issues,
    unsupported_action_names,
};
use clap::Args as ClapArgs;
use rite_resolver::{Diagnostic, Severity, SpanMap};
use rite_runtime::{ParamIssueKind, StepParamIssue};
use std::path::{Path, PathBuf};

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
    let (resolved, spans) =
        resolve_with_spans_or_exit(&args.file, (!inputs.is_empty()).then_some(&inputs));

    // Resolution cannot reach these: the resolver keeps `with:` opaque, since
    // only the handler knows what its parameters mean.
    let issues = step_param_issues(&resolved);
    let (definition, unsupported_params): (Vec<_>, Vec<_>) = issues
        .iter()
        .partition(|i| i.kind == ParamIssueKind::Definition);

    for issue in &definition {
        eprintln!(
            "{}",
            param_diagnostic(&args.file, &spans, issue, Severity::Error)
        );
    }
    if !definition.is_empty() {
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

    // Build-relative, not a definition error: the ceremony is valid, but this
    // binary lacks the feature or backend to carry these out. The machine that
    // executes may be a fuller build, so warn rather than fail. `rite run`
    // makes both checks fatal.
    for issue in &unsupported_params {
        eprintln!(
            "{}",
            param_diagnostic(&args.file, &spans, issue, Severity::Warning)
        );
    }

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

/// Present a handler finding in the resolver's diagnostic format, anchored on
/// the step declaration.
///
/// The span map records step declarations, not individual `with:` keys, so the
/// caret lands on the step name and the message carries the field.
fn param_diagnostic(
    path: &Path,
    spans: &SpanMap,
    issue: &StepParamIssue,
    severity: Severity,
) -> Diagnostic {
    Diagnostic {
        path: Some(path.to_owned()),
        span: spans.steps.get(&issue.step).copied(),
        severity,
        message: format!("step '{}': {}", issue.step.as_str(), issue.message),
    }
}
