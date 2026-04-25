//! `rite report`: generate an HTML post-ceremony report from a transcript.

use crate::common::resolve_or_exit;
use clap::Args as ClapArgs;
use rite_script::{ReportConfig, ReportInput, generate_report_html};
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or output folder
    pub transcript: PathBuf,
    /// Path to the ceremony YAML file (for role names and post-ceremony duties)
    #[arg(long)]
    pub ceremony: Option<PathBuf>,
    /// Write output to this file (default: stdout)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

pub fn run(args: Args) {
    let transcript_path = if args.transcript.is_dir() {
        rite_runtime::OutputConfig::new(args.transcript.clone()).transcript_path()
    } else {
        args.transcript
    };

    let transcript = match rite_runtime::read_transcript(&transcript_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Failed to read transcript {}: {e}",
                transcript_path.display()
            );
            std::process::exit(1);
        }
    };

    let resolved = args
        .ceremony
        .as_ref()
        .map(|path| resolve_or_exit(path, None));

    let html = generate_report_html(&ReportInput {
        transcript: &transcript,
        ceremony: resolved.as_ref(),
        config: ReportConfig::default(),
    });

    crate::script::write_output(&html, args.output.as_deref());
}
