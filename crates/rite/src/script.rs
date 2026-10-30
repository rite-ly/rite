//! `rite script`: generate a printable HTML ceremony script, and the sheets
//! for the values its steps have written by hand.

use crate::common::{
    BrandingArgs, InputArgs, ThemeArg, build_branding_or_exit, build_inputs_or_exit,
    default_output_path, resolve_or_exit, write_document,
};
use clap::Args as ClapArgs;
use std::path::{Path, PathBuf};

#[derive(ClapArgs, Debug)]
#[command(after_long_help = crate::common::INPUT_ENV_HELP)]
pub struct Args {
    /// Path to the ceremony YAML file
    pub file: PathBuf,
    /// Read the ceremony from stdin instead of FILE
    ///
    /// FILE still names it: diagnostics point at it, material paths resolve
    /// against its directory, and the default script path sits beside it.
    /// The worksheets are written only when `--worksheets` names a path. For
    /// an editor that renders a buffer it has not saved.
    #[arg(long)]
    pub stdin: bool,
    /// Output path (`-` for stdout)
    ///
    /// Defaults to the ceremony file name with the document extension, next to
    /// the source.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Output path of the worksheets, written when a step shows a value to
    /// write down
    ///
    /// One page per such step, printed once and kept with the value.
    /// Defaults to the script's path with `.worksheets.html`, or, when the
    /// script goes to stdout, the ceremony file's.
    #[arg(long, value_name = "PATH")]
    pub worksheets: Option<PathBuf>,
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
    let inputs = (!inputs.is_empty()).then_some(&inputs);
    let (resolved, _) = resolve_or_exit(&args.file, args.stdin, inputs);
    let branding = build_branding_or_exit(&args.branding);

    let html =
        rite_render::render_script(&resolved, &branding, args.theme.into()).unwrap_or_else(|e| {
            eprintln!("Failed to render script: {e}");
            std::process::exit(1);
        });
    // A buffer read from stdin is not saved, so its sheets must not replace
    // the ones beside the saved file.
    let sheets_path = args.worksheets.clone().or_else(|| {
        (!args.stdin).then(|| {
            worksheets_path(
                &args.file,
                args.output.as_deref().filter(|p| *p != Path::new("-")),
            )
        })
    });
    // Rendered before anything is written, so a failure leaves no script
    // without its sheets.
    let sheets = match &sheets_path {
        Some(path) => rite_render::render_worksheets(&resolved, &branding, args.theme.into())
            .unwrap_or_else(|e| {
                eprintln!("Failed to render worksheets: {e}");
                std::process::exit(1);
            })
            .map(|sheets| (sheets, path)),
        None => None,
    };

    let default = default_output_path(&args.file, "html");
    write_document(&html, args.output.as_deref(), &default);

    if let Some((sheets, path)) = sheets {
        write_document(&sheets, Some(path), path);
    }
}

/// Where the worksheets go by default: beside the script, named after it.
fn worksheets_path(ceremony: &Path, script: Option<&Path>) -> PathBuf {
    match script {
        Some(script) => {
            let name = script
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("ceremony");
            let stem = name.strip_suffix(".html").unwrap_or(name);
            script.with_file_name(format!("{stem}.worksheets.html"))
        }
        None => default_output_path(ceremony, "worksheets.html"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worksheets_sit_beside_the_script() {
        assert_eq!(
            worksheets_path(Path::new("c/split.rite.yaml"), None),
            PathBuf::from("c/split.worksheets.html")
        );
        assert_eq!(
            worksheets_path(
                Path::new("c/split.rite.yaml"),
                Some(Path::new("out/day1.html"))
            ),
            PathBuf::from("out/day1.worksheets.html")
        );
        assert_eq!(
            worksheets_path(Path::new("split.rite.yaml"), Some(Path::new("out/day1"))),
            PathBuf::from("out/day1.worksheets.html")
        );
    }
}
