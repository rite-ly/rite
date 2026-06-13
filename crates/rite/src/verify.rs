//! `rite verify`: check a ceremony transcript's integrity.

use std::path::{Path, PathBuf};

use clap::Args as ClapArgs;
use rite_model::StepFact;
use rite_runtime::{
    TimedFact, VerifyError, compute_file_fingerprint, read_verified_transcript, verify_entropy,
};

/// Entropy-source label the runtime records for a dry run. Such a transcript
/// derives from a fixed, publicly-known sentinel seed and re-derives exactly
/// like a real one, so the verifier must flag it loudly.
const DRY_RUN_SOURCE: &str = "dry-run";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or output folder
    pub file: PathBuf,
    /// Accept a transcript that ends without a terminal fact. By default a
    /// truncated transcript fails verification, because cutting a transcript
    /// at a line boundary leaves the hash chain intact.
    #[arg(long)]
    pub allow_truncated: bool,
}

pub fn run(args: Args) {
    let (transcript_path, source_dir) = if args.file.is_dir() {
        let candidate = args.file.join("transcript.jsonl");
        (candidate, Some(args.file))
    } else {
        (args.file, None)
    };

    let loaded = match read_verified_transcript(&transcript_path) {
        Ok(loaded) => loaded,
        Err(VerifyError::Io(e)) => {
            match (&source_dir, e.kind()) {
                (Some(dir), std::io::ErrorKind::NotFound) => {
                    eprintln!("No transcript found in folder: {}", dir.display());
                    eprintln!("Expected: {}", transcript_path.display());
                }
                _ => {
                    eprintln!("Failed to read transcript: {e}");
                }
            }
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("Verification failed: {err}");
            std::process::exit(1);
        }
    };

    // The hash chain is intact. Now re-derive the entropy source so every
    // recorded random value is proven to come from the recorded seed, not
    // cherry-picked.
    let entropy = match verify_entropy(loaded.facts.iter().map(|t| &t.fact)) {
        Ok(entropy) => entropy,
        Err(err) => {
            eprintln!("Verification failed: {err}");
            std::process::exit(1);
        }
    };

    // When pointed at a run directory, also re-hash the artifact files
    // sitting next to the transcript against the recorded digests.
    let artifact_checks = source_dir
        .as_deref()
        .map(|dir| check_artifacts(dir, loaded.facts.iter().map(|t| &t.fact)));

    println!("Transcript verified.");
    println!("  Facts:       {}", loaded.facts.len());
    if let Some(scheme) = &entropy.derivation {
        println!(
            "  Entropy:     {} value(s) re-derived, {} contribution(s) folded ({scheme})",
            entropy.values_verified, entropy.contributions,
        );
    }
    if let Some(source) = &entropy.source {
        println!("  Seed source: {source}");
    }

    let (artifacts_failed, artifacts_missing) = match &artifact_checks {
        Some(checks) => summarize_artifacts(checks),
        None => (false, false),
    };

    // The chain check proves internal consistency only: a complete substitute
    // transcript verifies just as cleanly. Tying it to the witnessed ceremony
    // takes the out-of-band comparison against the fingerprint the operators
    // wrote down when `rite run` finished, so print it in the same shape.
    println!();
    println!("Transcript fingerprint: {}", loaded.fingerprint);
    println!(
        "The checks above prove the transcript is internally consistent. To confirm\n\
         it is the transcript of the ceremony you witnessed, compare this fingerprint\n\
         against the one written down at the end of the ceremony run."
    );

    let mut failed = false;

    if entropy.source.as_deref() == Some(DRY_RUN_SOURCE) {
        eprintln!();
        eprintln!(
            "WARNING: this transcript was produced by a DRY RUN. Its entropy seed is a\n\
             fixed, publicly-known sentinel, so the checks above prove rehearsal\n\
             consistency only; nothing in it is evidence of a real ceremony."
        );
    }

    if let Some(line) = first_timestamp_regression(&loaded.facts) {
        eprintln!();
        eprintln!(
            "Warning: envelope timestamps are not monotonic: line {line} is earlier \
             than the line before it."
        );
    }

    if artifacts_missing {
        eprintln!();
        eprintln!("Warning: some recorded artifacts are missing from the artifacts/ directory.");
    }

    if artifacts_failed {
        eprintln!();
        eprintln!("Verification failed: artifact contents do not match the recorded digests.");
        failed = true;
    }

    if !loaded.terminated {
        eprintln!();
        if args.allow_truncated {
            eprintln!(
                "Warning: transcript is truncated (no ceremony_completed or \
                 ceremony_failed fact at the end); accepted via --allow-truncated."
            );
        } else {
            eprintln!(
                "Verification failed: transcript is truncated, no ceremony_completed or\n\
                 ceremony_failed fact at the end. Cutting a transcript at a line boundary\n\
                 keeps a valid hash chain, so truncation is rejected by default. Pass\n\
                 --allow-truncated to accept a transcript from an interrupted run."
            );
            failed = true;
        }
    }

    std::process::exit(i32::from(failed));
}

/// Print the per-artifact result lines and fold the statuses into
/// `(any_failed, any_missing)`. A mismatch or an uncheckable artifact fails
/// verification; a missing one only warns, since artifacts are routinely
/// moved to their destination after a ceremony.
fn summarize_artifacts(checks: &[ArtifactCheck]) -> (bool, bool) {
    let mut failed = false;
    let mut missing = false;
    if checks.is_empty() {
        println!("  Artifacts:   none recorded");
        return (failed, missing);
    }
    println!("  Artifacts:");
    for check in checks {
        println!("    {}", check.describe());
        match check.status {
            ArtifactStatus::Match => {}
            ArtifactStatus::Missing => missing = true,
            ArtifactStatus::Mismatch { .. } | ArtifactStatus::Error { .. } => failed = true,
        }
    }
    (failed, missing)
}

/// Result of re-hashing one recorded artifact against the run directory.
#[derive(Debug)]
struct ArtifactCheck {
    /// Artifact name as recorded in the transcript.
    name: String,
    /// Location checked, relative to the run directory.
    location: String,
    /// Outcome of the comparison.
    status: ArtifactStatus,
}

#[derive(Debug, PartialEq, Eq)]
enum ArtifactStatus {
    /// On-disk bytes hash to the recorded digest.
    Match,
    /// File exists but its hash differs from the recorded digest.
    Mismatch {
        /// Fingerprint of the bytes actually on disk.
        actual: String,
    },
    /// No file at the derived location.
    Missing,
    /// The artifact could not be checked at all (unusable recorded path,
    /// read error). Treated as a failure, like a mismatch.
    Error {
        /// Why the check could not run.
        reason: String,
    },
}

impl ArtifactCheck {
    fn describe(&self) -> String {
        match &self.status {
            ArtifactStatus::Match => format!("{}: ok ({})", self.name, self.location),
            ArtifactStatus::Mismatch { actual } => format!(
                "{}: MISMATCH ({}): on-disk bytes hash to {actual}",
                self.name, self.location,
            ),
            ArtifactStatus::Missing => format!("{}: missing ({})", self.name, self.location),
            ArtifactStatus::Error { reason } => format!("{}: ERROR: {reason}", self.name),
        }
    }
}

/// Re-hash every artifact the transcript records against the run directory.
///
/// The transcript is untrusted input, so the recorded path is never followed.
/// Only its final component names the file, anchored under the run
/// directory's `artifacts/` subdirectory; a crafted transcript therefore
/// cannot point the verifier at files outside the directory being verified.
fn check_artifacts<'a>(
    dir: &Path,
    facts: impl IntoIterator<Item = &'a StepFact>,
) -> Vec<ArtifactCheck> {
    facts
        .into_iter()
        .filter_map(|fact| {
            let StepFact::ArtifactWritten {
                name, path, sha256, ..
            } = fact
            else {
                return None;
            };
            Some(check_one_artifact(dir, name, path, sha256))
        })
        .collect()
}

fn check_one_artifact(
    dir: &Path,
    name: &str,
    recorded_path: &Path,
    recorded_sha256: &str,
) -> ArtifactCheck {
    let Some(file_name) = recorded_path.file_name() else {
        return ArtifactCheck {
            name: name.to_string(),
            location: String::new(),
            status: ArtifactStatus::Error {
                reason: format!(
                    "recorded path '{}' has no file name",
                    recorded_path.display(),
                ),
            },
        };
    };
    let location = Path::new("artifacts").join(file_name);
    let on_disk = dir.join(&location);
    let status = if on_disk.is_file() {
        match compute_file_fingerprint(&on_disk) {
            Ok(actual) if digest_hex(&actual) == digest_hex(recorded_sha256) => {
                ArtifactStatus::Match
            }
            Ok(actual) => ArtifactStatus::Mismatch { actual },
            Err(e) => ArtifactStatus::Error {
                reason: format!("could not read {}: {e}", on_disk.display()),
            },
        }
    } else {
        ArtifactStatus::Missing
    };
    ArtifactCheck {
        name: name.to_string(),
        location: location.display().to_string(),
        status,
    }
}

/// Bare hex digest, tolerant of the `sha256:` prefix the runtime records.
fn digest_hex(s: &str) -> &str {
    s.strip_prefix("sha256:").unwrap_or(s)
}

/// 1-based line number of the first fact whose envelope timestamp is earlier
/// than its predecessor's, if any. One fact per transcript line, so a fact's
/// index maps directly to its line number.
fn first_timestamp_regression(facts: &[TimedFact]) -> Option<usize> {
    facts
        .iter()
        .zip(facts.iter().skip(1))
        .position(|(prev, next)| next.at < prev.at)
        .map(|i| i.saturating_add(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use rite_model::StepId;
    use rite_runtime::compute_fingerprint;

    fn artifact_fact(path: &str, sha256: String) -> StepFact {
        StepFact::ArtifactWritten {
            step: StepId::new("s1"),
            name: "root.crt".to_string(),
            path: PathBuf::from(path),
            sha256,
        }
    }

    fn write_artifact(dir: &Path, file_name: &str, bytes: &[u8]) {
        let artifacts = dir.join("artifacts");
        std::fs::create_dir_all(&artifacts).expect("create artifacts dir");
        std::fs::write(artifacts.join(file_name), bytes).expect("write artifact");
    }

    #[test]
    fn artifact_with_matching_bytes_passes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_artifact(tmp.path(), "root.crt", b"cert bytes");
        let fact = artifact_fact(
            "/original/run/artifacts/root.crt",
            compute_fingerprint(b"cert bytes"),
        );
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert_eq!(checks.len(), 1);
        assert_eq!(
            checks.first().expect("one check").status,
            ArtifactStatus::Match
        );
    }

    #[test]
    fn artifact_with_different_bytes_is_a_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_artifact(tmp.path(), "root.crt", b"tampered bytes");
        let fact = artifact_fact(
            "/original/run/artifacts/root.crt",
            compute_fingerprint(b"cert bytes"),
        );
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert!(matches!(
            checks.first().expect("one check").status,
            ArtifactStatus::Mismatch { .. }
        ));
    }

    #[test]
    fn artifact_absent_from_disk_is_reported_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact = artifact_fact(
            "/original/run/artifacts/root.crt",
            compute_fingerprint(b"cert bytes"),
        );
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert_eq!(
            checks.first().expect("one check").status,
            ArtifactStatus::Missing
        );
    }

    #[test]
    fn recorded_path_is_never_followed_outside_the_run_directory() {
        // A crafted transcript records a traversal path; only the file name
        // is used, anchored under artifacts/, so the check looks for
        // artifacts/passwd inside the run directory and nothing else.
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact = artifact_fact("../../../../etc/passwd", compute_fingerprint(b"x"));
        let checks = check_artifacts(tmp.path(), [&fact]);
        let check = checks.first().expect("one check");
        assert_eq!(check.location, "artifacts/passwd");
        assert_eq!(check.status, ArtifactStatus::Missing);
    }

    #[test]
    fn recorded_path_without_a_file_name_is_an_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact = artifact_fact("/", compute_fingerprint(b"x"));
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert!(matches!(
            checks.first().expect("one check").status,
            ArtifactStatus::Error { .. }
        ));
    }

    #[test]
    fn digest_comparison_tolerates_the_sha256_prefix() {
        assert_eq!(digest_hex("sha256:abcd"), "abcd");
        assert_eq!(digest_hex("abcd"), "abcd");
    }

    fn timed(facts_seconds: &[i64]) -> Vec<TimedFact> {
        facts_seconds
            .iter()
            .map(|s| TimedFact {
                at: ts(*s),
                fact: StepFact::CeremonyStarted {
                    name: "t".to_string(),
                },
            })
            .collect()
    }

    fn ts(seconds: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().expect("valid time")
    }

    #[test]
    fn monotonic_timestamps_raise_no_warning() {
        assert_eq!(first_timestamp_regression(&timed(&[10, 10, 20])), None);
    }

    #[test]
    fn a_backwards_timestamp_is_reported_with_its_line_number() {
        // Line 3 (1-based) goes backwards relative to line 2.
        assert_eq!(
            first_timestamp_regression(&timed(&[10, 20, 15, 30])),
            Some(3)
        );
    }

    #[test]
    fn empty_fact_list_raises_no_warning() {
        assert_eq!(first_timestamp_regression(&[]), None);
    }
}
