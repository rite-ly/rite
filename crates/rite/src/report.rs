//! `rite report`: generate an HTML post-ceremony report from a transcript.

use clap::Args as ClapArgs;
use std::fs;
use std::path::{Path, PathBuf};

use rite_render::report::{build_report_data, generate_report_html};
use rite_runtime::read_verified_transcript;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or to the output directory
    /// produced by `rite run` (containing `transcript.jsonl`).
    pub transcript: PathBuf,
    /// Write the report to this file (default: stdout).
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

pub fn run(args: &Args) {
    let jsonl_path = resolve_transcript_path(&args.transcript);

    let loaded = match read_verified_transcript(&jsonl_path) {
        Ok(loaded) => loaded,
        Err(err) => {
            eprintln!(
                "rite report: could not read transcript at {}: {err}",
                jsonl_path.display(),
            );
            std::process::exit(2);
        }
    };

    let data = build_report_data(&loaded.facts, loaded.fingerprint.as_str());
    let html = generate_report_html(&data);

    if let Some(output) = &args.output {
        if let Err(err) = fs::write(output, html.as_bytes()) {
            eprintln!("rite report: failed to write {}: {err}", output.display());
            std::process::exit(2);
        }
        eprintln!("Report written to {}", output.display());
    } else {
        print!("{html}");
    }
}

/// Accept either the JSONL file directly or the parent output directory.
fn resolve_transcript_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        input.join("transcript.jsonl")
    } else {
        input.to_path_buf()
    }
}
