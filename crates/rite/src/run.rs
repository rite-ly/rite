//! `rite run`: execute a ceremony interactively.

use std::path::{Path, PathBuf};

use clap::{Args as ClapArgs, ValueEnum};
use crossbeam_channel::unbounded;

use rite_runtime::{
    ExecEvent, ExecutionError, ExecutionSummary, Executor, InMemorySink, JsonlFileSink,
    StartupSnapshot, TranscriptSink, UiCommand,
};

use crate::common::{
    InputArgs, build_inputs_or_exit, preflight_check_materials, prompt_missing_params,
};

/// Which frontend drives the ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Frontend {
    /// Interactive terminal UI (TEA-style). Default when stdout is a TTY.
    #[cfg(feature = "tui")]
    Tui,
    /// Plain stdin/stdout driver. Reference implementation of the protocol.
    Console,
    /// Auto-answering driver for CI / smoke tests.
    Headless,
}

#[derive(ClapArgs, Debug)]
#[command(after_long_help = crate::common::INPUT_ENV_HELP)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    #[command(flatten)]
    pub input: InputArgs,
    /// Do not prompt for missing parameters
    #[arg(long)]
    pub no_prompt: bool,
    /// Simulate without performing real operations
    #[arg(long)]
    pub dry_run: bool,
    /// Output directory (default: current directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Do not write a transcript
    #[arg(long)]
    pub no_transcript: bool,
    /// Frontend driver (auto-detected when omitted)
    ///
    /// When omitted, `tui` is used if stdout is a TTY and the `tui` feature is
    /// built in, otherwise `console`.
    #[arg(long, value_enum)]
    pub frontend: Option<Frontend>,
}

pub fn run(args: Args) {
    let mut inputs = build_inputs_or_exit(&args.input);

    if !args.no_prompt {
        let (ceremony_opt, _diags) = rite_resolver::analyze(&args.file, None);
        if let Some(ceremony) = ceremony_opt {
            prompt_missing_params(&mut inputs, &ceremony);
        }
    }

    let result = rite_resolver::resolve_files(&args.file, Some(&inputs));

    if !result.errors.is_empty() {
        eprintln!("Validation errors:");
        for error in &result.errors {
            eprintln!("  - {error}");
        }
        std::process::exit(1);
    }

    let Ok(resolved) = result.into_result() else {
        eprintln!("Internal error: resolution failed with no errors");
        std::process::exit(1);
    };

    // Fail fast if this build lacks a feature the ceremony needs: abort before
    // any hardware is touched, directory created, or transcript opened, rather
    // than partway through when execution reaches the step. `rite check` warns
    // on the same condition instead of failing, since the executing build may
    // differ from the one that validated.
    let unsupported = crate::common::unsupported_action_names(&resolved);
    if !unsupported.is_empty() {
        eprintln!("This build of rite cannot run this ceremony.");
        eprintln!("  Unsupported action(s): {}", unsupported.join(", "));
        eprintln!("  Rebuild rite with the required feature(s) enabled.");
        std::process::exit(1);
    }

    // Fatal here, for the reason the unsupported-action check above is: this
    // process is the executor, so a value it cannot carry out stops the run
    // before the first key exists. `rite check` only warns.
    let unsupported = crate::common::unsupported_step_params(&resolved);
    if !unsupported.is_empty() {
        eprintln!(
            "This build cannot carry out {} step parameter(s):",
            unsupported.len()
        );
        for issue in &unsupported {
            eprintln!("  - step '{}': {}", issue.step.as_str(), issue.message);
        }
        std::process::exit(1);
    }

    if let Err(e) = preflight_check_materials(&resolved) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    let output_config =
        rite_runtime::OutputConfig::for_ceremony(args.output, &resolved.metadata.name);
    let output_dir = output_config.base_dir().to_path_buf();

    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        eprintln!("Failed to create output directory: {e}");
        std::process::exit(1);
    }

    // Backends from resolved configuration (lazy; no hardware touched yet).
    let mut backend_registry =
        rite_runtime::BackendRegistry::with_factory(rite_stdlib::stdlib_backend_factory());
    for (name, config) in &resolved.backends {
        let mut config = config.clone();
        if args.dry_run {
            // Dry-run rehearsal: route every backend through the mock. It
            // performs real (software) crypto, so the ceremony runs end to end
            // without touching the declared provider's hardware.
            config.provider = "mock".to_string();
        }
        backend_registry.declare(name.clone(), config);
    }

    let registry = rite_stdlib::default_registry();

    let sink: Box<dyn TranscriptSink> = if args.no_transcript {
        Box::new(InMemorySink::new())
    } else {
        let file_sink = JsonlFileSink::create(&output_dir).unwrap_or_else(|e| {
            eprintln!("Failed to create transcript: {e}");
            std::process::exit(1);
        });
        Box::new(file_sink)
    };

    // A dry run is a non-interactive rehearsal: default it to the headless
    // driver so prompts are auto-answered. An explicit `--frontend` still wins.
    let frontend = args.frontend.unwrap_or_else(|| {
        if args.dry_run {
            Frontend::Headless
        } else {
            default_frontend()
        }
    });

    let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
    let (event_tx, event_rx) = unbounded::<ExecEvent>();

    let startup = StartupSnapshot {
        system: crate::system_info::gather_system(),
        environment: crate::system_info::gather_environment(),
    };

    let executor = Executor::new(
        resolved,
        registry,
        backend_registry,
        output_config,
        args.dry_run,
        startup,
    );
    let exec_handle = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

    let frontend_result = run_frontend(frontend, &cmd_tx, event_rx);

    // Drop our cmd_tx so the executor's recv unblocks cleanly if the
    // frontend exits before the ceremony completes.
    drop(cmd_tx);

    let Ok(exec_result) = exec_handle.join() else {
        eprintln!("Executor thread panicked");
        std::process::exit(2);
    };

    if let Err(e) = frontend_result {
        eprintln!("Frontend error: {e}");
    }

    report_outcome(exec_result, &output_dir, &args.file, args.no_transcript);
}

/// Print the terminal summary and exit the process with the matching code.
///
/// On success prints the output directory, the transcript fingerprint and the
/// commands that check and keep the record (exit 0). On failure or operator
/// abort, exits non-zero: an abort is a deliberate stop rather than a failure,
/// but the ceremony did not complete either way. The transcript is recorded up
/// to the stopping point in both cases, so the output directory and the same
/// commands are printed so the operator can find and keep the evidence.
fn report_outcome(
    exec_result: Result<ExecutionSummary, ExecutionError>,
    output_dir: &Path,
    ceremony: &Path,
    no_transcript: bool,
) -> ! {
    match exec_result {
        Ok(summary) => {
            if !no_transcript {
                println!("Output directory: {}", output_dir.display());
                println!("Transcript fingerprint: {}", summary.transcript_fingerprint);
                println!();
                println!("{}", next_steps(output_dir, ceremony));
            }
            std::process::exit(0);
        }
        Err(e) => {
            if matches!(e, ExecutionError::Aborted) {
                eprintln!("Ceremony aborted by the operator.");
            } else {
                eprintln!("Ceremony failed: {e}");
            }
            if !no_transcript {
                eprintln!("Output directory: {}", output_dir.display());
                eprintln!();
                eprintln!("{}", next_steps(output_dir, ceremony));
            }
            std::process::exit(1);
        }
    }
}

/// The commands that check the run, render its report, and package it with
/// the ceremony it ran from, ready to copy.
fn next_steps(output_dir: &Path, ceremony: &Path) -> String {
    let run = shell_arg(&output_dir.display().to_string());
    let bundle = shell_arg(&format!("{}-bundle", output_dir.display()));
    let definition = shell_arg(&ceremony.display().to_string());
    format!(
        "Next steps:\n  \
         rite verify {run}\n  \
         rite report {run}\n  \
         rite bundle create {run} --definition {definition} -o {bundle}"
    )
}

/// `arg` as one shell word: unchanged when it holds only characters no shell
/// treats specially, single-quoted otherwise.
fn shell_arg(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:@+,=".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn run_frontend(
    frontend: Frontend,
    cmd_tx: &crossbeam_channel::Sender<UiCommand>,
    event_rx: crossbeam_channel::Receiver<ExecEvent>,
) -> std::io::Result<()> {
    match frontend {
        #[cfg(feature = "tui")]
        Frontend::Tui => rite_tui::run(cmd_tx, event_rx),
        Frontend::Console => crate::console::run(cmd_tx, &event_rx),
        Frontend::Headless => crate::headless::run(cmd_tx, &event_rx),
    }
}

fn default_frontend() -> Frontend {
    #[cfg(feature = "tui")]
    {
        if is_stdout_tty() {
            return Frontend::Tui;
        }
    }
    Frontend::Console
}

fn is_stdout_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_steps_name_the_run_and_the_ceremony() {
        let text = next_steps(
            Path::new("./root-ca-20260924T101500"),
            Path::new("root.rite.yaml"),
        );
        assert_eq!(
            text,
            "Next steps:\n  \
             rite verify ./root-ca-20260924T101500\n  \
             rite report ./root-ca-20260924T101500\n  \
             rite bundle create ./root-ca-20260924T101500 --definition root.rite.yaml \
             -o ./root-ca-20260924T101500-bundle"
        );
    }

    #[test]
    fn shell_arguments_are_quoted_when_needed() {
        assert_eq!(shell_arg("runs/a-1"), "runs/a-1");
        assert_eq!(shell_arg("my runs/a"), "'my runs/a'");
        assert_eq!(shell_arg("it's"), "'it'\\''s'");
    }
}
