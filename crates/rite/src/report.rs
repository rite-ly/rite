//! `rite report`: generate an HTML post-ceremony report from a transcript.

use clap::Args as ClapArgs;
use std::path::{Path, PathBuf};

use crate::common::{BrandingArgs, ThemeArg, build_branding_or_exit, write_document};
use rite_render::report::build_report_data;
use rite_runtime::read_verified_transcript;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or to the output directory
    /// produced by `rite run` (containing `transcript.jsonl`).
    pub transcript: PathBuf,
    /// Write to this path. Use `-` for stdout. Defaults to `report.html`
    /// next to the transcript.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Visual theme for the generated document
    #[arg(long, value_enum, default_value_t = ThemeArg::default())]
    pub theme: ThemeArg,
    #[command(flatten)]
    pub branding: BrandingArgs,
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
    let branding = build_branding_or_exit(&args.branding);
    let html =
        rite_render::render_report(&data, &branding, args.theme.into()).unwrap_or_else(|e| {
            eprintln!("rite report: failed to render report: {e}");
            std::process::exit(2);
        });

    let default = jsonl_path.with_file_name("report.html");
    write_document(&html, args.output.as_deref(), &default);
}

/// Accept either the JSONL file directly or the parent output directory.
fn resolve_transcript_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        input.join("transcript.jsonl")
    } else {
        input.to_path_buf()
    }
}
