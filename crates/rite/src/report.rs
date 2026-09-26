//! `rite report`: generate an HTML post-ceremony report from a transcript.

use clap::Args as ClapArgs;
use std::path::{Path, PathBuf};

use crate::common::{BrandingArgs, ThemeArg, build_branding_or_exit, write_document};
use rite_render::report::{ReportWithheld, build_report_data};
use rite_runtime::read_verified_transcript;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Transcript file or run output directory
    ///
    /// Accepts a `transcript.jsonl` file or the output directory produced by
    /// `rite run` (which contains `transcript.jsonl`).
    pub transcript: PathBuf,
    /// Output path (`-` for stdout)
    ///
    /// Defaults to `report.html` next to the transcript.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Document theme
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
            std::process::exit(1);
        }
    };

    let mut data = build_report_data(
        loaded.facts.iter().map(|t| (t.at, &t.fact)),
        loaded.fingerprint.as_str(),
    );
    data.withheld = withheld(&loaded);
    let branding = build_branding_or_exit(&args.branding);
    let html =
        rite_render::render_report(&data, &branding, args.theme.into()).unwrap_or_else(|e| {
            eprintln!("rite report: failed to render report: {e}");
            std::process::exit(2);
        });

    let default = jsonl_path.with_file_name("report.html");
    write_document(&html, args.output.as_deref(), &default);
}

/// What a disclosed transcript withholds, by count and by level name, or
/// `None` for a complete one.
fn withheld(loaded: &rite_runtime::LoadedTranscript) -> Option<ReportWithheld> {
    if loaded.withheld.is_empty() {
        return None;
    }
    let levels: std::collections::BTreeSet<_> =
        loaded.withheld.iter().map(|line| line.level).collect();
    let name = |level: rite_model::Level| {
        loaded
            .header
            .levels
            .iter()
            .find(|(_, declared)| **declared == level)
            .map_or_else(|| level.to_string(), |(name, _)| name.clone())
    };
    Some(ReportWithheld {
        facts: loaded.withheld.len(),
        levels: levels.into_iter().map(name).collect(),
    })
}

/// Accept either the JSONL file directly or the parent output directory.
fn resolve_transcript_path(input: &Path) -> PathBuf {
    if input.is_dir() {
        input.join("transcript.jsonl")
    } else {
        input.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::{RoleId, StepFact};
    use rite_runtime::test_support::{ceremony_started, write_transcript};
    use rite_runtime::{disclose_transcript, verify_jsonl};

    #[test]
    fn a_disclosure_states_what_it_withholds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_transcript(
            tmp.path(),
            &[
                ceremony_started("Report test"),
                StepFact::RoleAssigned {
                    role: RoleId::new("operator"),
                    person: "Alice".to_string(),
                },
                StepFact::CeremonyCompleted {},
            ],
        )
        .expect("transcript");
        let complete = std::fs::read_to_string(tmp.path().join("transcript.jsonl")).expect("read");
        assert_eq!(withheld(&verify_jsonl(&complete).expect("verify")), None);

        let public = disclose_transcript(&complete, rite_model::Level::PUBLIC).expect("disclose");
        assert_eq!(
            withheld(&verify_jsonl(&public).expect("verify")),
            Some(ReportWithheld {
                facts: 1,
                levels: vec!["confidential".to_string()],
            })
        );
    }
}
