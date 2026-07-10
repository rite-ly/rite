//! `rite script`: generate a printable HTML ceremony script.

use crate::common::{
    BrandingArgs, InputArgs, ThemeArg, build_branding_or_exit, build_inputs_or_exit,
    default_output_path, resolve_or_exit, write_document,
};
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    /// Output path (`-` for stdout)
    ///
    /// Defaults to the ceremony file name with the document extension, next to
    /// the source.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Document theme
    #[arg(long, value_enum, default_value_t = ThemeArg::default())]
    pub theme: ThemeArg,
    #[command(flatten)]
    pub branding: BrandingArgs,
    #[command(flatten)]
    pub input: InputArgs,
}

pub fn run(args: &Args) {
    let inputs = build_inputs_or_exit(&args.input);
    let resolved = resolve_or_exit(&args.file, (!inputs.is_empty()).then_some(&inputs));
    let branding = build_branding_or_exit(&args.branding);

    let html =
        rite_render::render_script(&resolved, &branding, args.theme.into()).unwrap_or_else(|e| {
            eprintln!("Failed to render script: {e}");
            std::process::exit(1);
        });

    let default = default_output_path(&args.file, "html");
    write_document(&html, args.output.as_deref(), &default);
}
