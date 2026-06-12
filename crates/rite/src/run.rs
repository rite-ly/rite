//! `rite run`: execute a ceremony interactively.

use std::path::PathBuf;

use clap::{Args as ClapArgs, ValueEnum};
use crossbeam_channel::unbounded;

use rite_runtime::{
    ExecEvent, Executor, InMemorySink, JsonlFileSink, StartupSnapshot, TranscriptSink, UiCommand,
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
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    #[command(flatten)]
    pub input: InputArgs,
    /// Disable interactive parameter prompting
    #[arg(long)]
    pub no_prompt: bool,
    /// Dry run: simulate without actual operations
    #[arg(long)]
    pub dry_run: bool,
    /// Output directory (default: current directory)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Disable transcript generation
    #[arg(long)]
    pub no_transcript: bool,
    /// Frontend driver. Auto-detected when omitted: `tui` if stdout is a
    /// TTY and the `tui` feature is built in, else `console`.
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

    match exec_result {
        Ok(summary) => {
            if !args.no_transcript {
                println!("Output directory: {}", output_dir.display());
                println!("Transcript fingerprint: {}", summary.transcript_fingerprint);
            }
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Ceremony failed: {e}");
            std::process::exit(1);
        }
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
