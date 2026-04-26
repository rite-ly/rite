//! `rite script`: generate a printable HTML ceremony script.

use crate::common::{InputArgs, build_inputs_or_exit, resolve_or_exit};
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    /// Write output to this file (default: stdout)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    #[command(flatten)]
    pub input: InputArgs,
}

pub fn run(args: &Args) {
    let inputs = build_inputs_or_exit(&args.input);
    let resolved = resolve_or_exit(&args.file, (!inputs.is_empty()).then_some(&inputs));

    let html = rite_script::generate_html(&resolved);
    write_output(&html, args.output.as_deref());
}

pub fn write_output(html: &str, path: Option<&std::path::Path>) {
    match path {
        Some(p) => {
            if let Err(e) = std::fs::write(p, html) {
                eprintln!("Failed to write output to {}: {e}", p.display());
                std::process::exit(1);
            }
        }
        None => print!("{html}"),
    }
}
