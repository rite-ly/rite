//! `rite run`: execute a ceremony interactively.

use crate::common::{
    InputArgs, build_inputs_or_exit, preflight_check_materials, prompt_missing_params,
};
use clap::Args as ClapArgs;
use std::path::PathBuf;

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
}

pub fn run(args: Args) {
    let mut inputs = build_inputs_or_exit(&args.input);

    // Interactive prompting for missing required parameters.
    // Parse ceremony with no inputs first (skips required-param validation),
    // so we can discover which parameters need prompting before full resolution.
    if !args.no_prompt {
        let (ceremony_opt, _diags) = rite_resolver::analyze(&args.file, None);
        if let Some(ceremony) = ceremony_opt {
            prompt_missing_params(&mut inputs, &ceremony);
        }
    }

    // Full resolution with all inputs.
    let result = rite_resolver::resolve_files(&args.file, Some(&inputs));

    if !result.errors.is_empty() {
        eprintln!("Validation errors:");
        for error in &result.errors {
            eprintln!("  - {error}");
        }
        std::process::exit(1);
    }

    // errors is empty, so into_result() cannot fail.
    let Ok(resolved) = result.into_result() else {
        eprintln!("Internal error: resolution failed with no errors");
        std::process::exit(1);
    };

    // Preflight: verify material files exist before starting I/O.
    if let Err(e) = preflight_check_materials(&resolved) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }

    // Build output configuration: <base>/<ceremony-slug>-<timestamp>/
    let output_config =
        rite_runtime::OutputConfig::for_ceremony(args.output, &resolved.metadata.name);
    let output_dir = output_config.base_dir().to_path_buf();

    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        eprintln!("Failed to create output directory: {e}");
        std::process::exit(1);
    }

    let transcript_config = if args.no_transcript {
        rite_runtime::TranscriptConfig::disabled()
    } else {
        rite_runtime::TranscriptConfig::from_output_config(&output_config)
            .with_ceremony_file(args.file.clone())
    };

    // Declare backends from resolved configuration (lazy; no hardware touched yet).
    let mut backend_registry =
        rite_runtime::BackendRegistry::with_factory(rite_stdlib::stdlib_backend_factory());
    for (name, config) in &resolved.backends {
        backend_registry.declare(name.clone(), config.clone());
    }

    let registry = rite_stdlib::default_registry();
    let mut executor = rite_runtime::CeremonyExecutor::new_interactive_with_transcript(
        args.dry_run,
        registry,
        output_config,
        transcript_config,
    );

    match executor.execute(&resolved, backend_registry) {
        Ok(_) => {
            println!("Output directory: {}", output_dir.display());
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Ceremony failed: {e}");
            std::process::exit(1);
        }
    }
}
