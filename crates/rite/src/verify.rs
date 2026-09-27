//! `rite verify`: check a ceremony transcript's integrity.

use std::path::{Path, PathBuf};

use crate::container_checks::{ContainerCheck, check_containers};
use clap::Args as ClapArgs;
use rite_model::{Sha256Digest, StepFact};
use rite_runtime::{TimedFact, VerifyError, read_verified_transcript, verify_entropy};

/// Entropy-source label the runtime records for a dry run. The header says
/// whether the run was a dry run; a seed from the public sentinel means the
/// same thing whatever the header says, so either one marks the transcript.
const DRY_RUN_SOURCE: &str = "dry-run";

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Transcript file or run output directory
    pub file: PathBuf,
    /// Accept a transcript with no terminal fact (an interrupted run)
    ///
    /// By default a truncated transcript fails verification: cutting it at a
    /// line boundary leaves the hash chain intact, so truncation must be opted
    /// into.
    #[arg(long)]
    pub allow_truncated: bool,
}

pub fn run(args: &Args) {
    let (loaded, source_dir) = load_or_exit(&args.file);

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

    // A wrap or encrypt fact states what algorithms were used and who the
    // recipient was. The artifact it produced says the same things
    // independently, so where the artifact is at hand the two are compared.
    let facts: Vec<&StepFact> = loaded.facts.iter().map(|t| &t.fact).collect();
    let container_checks = check_containers(source_dir.as_deref(), &facts);

    print_counts(&loaded, &entropy);

    // A bundle directory also holds an index and, usually, the definition
    // the run was resolved from.
    let bundle_failed = source_dir
        .as_deref()
        .and_then(|dir| check_bundle(dir, &loaded))
        .is_some_and(|check| {
            for line in &check.lines {
                println!("  {line}");
            }
            check.failed
        });

    let (artifacts_failed, artifacts_missing) = match &artifact_checks {
        Some(checks) => summarize_artifacts(checks),
        None => (false, false),
    };

    let containers_failed = summarize_containers(&container_checks);

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

    if loaded.header.dry_run || entropy.source.as_deref() == Some(DRY_RUN_SOURCE) {
        eprintln!();
        eprintln!(
            "WARNING: this transcript was produced by a DRY RUN. Its entropy seed is a\n\
             fixed, publicly-known sentinel, so the checks above prove rehearsal\n\
             consistency only; nothing in it is evidence of a real ceremony."
        );
    }

    if let Some(warning) = unstable_format_warning(&loaded.header) {
        eprintln!();
        eprintln!("{warning}");
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

    if bundle_failed {
        eprintln!();
        eprintln!("Verification failed: the bundle does not match its transcript or its index.");
        failed = true;
    }

    if containers_failed {
        eprintln!();
        eprintln!(
            "Verification failed: an artifact contradicts what the transcript records\n\
             about the step that produced it."
        );
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

/// Before 1.0 the format changes between releases under the same number, so
/// only the release that wrote a transcript is sure to read it right.
///
/// Printed only when the checks pass. A transcript whose format changed fails
/// as a chain break or an invalid line, without this hint. The number does not
/// say which releases share a format, so a warning here does not mean the
/// format differs.
fn unstable_format_warning(header: &rite_model::TranscriptHeader) -> Option<String> {
    (header.rite_transcript == 0 && header.producer != rite_runtime::PRODUCER).then(|| {
        format!(
            "Warning: this transcript was written by {}, and this is {}. The transcript\n\
             format is not stable before 1.0; verify it with the release that wrote it.",
            header.producer,
            rite_runtime::PRODUCER
        )
    })
}

/// Chain-verify the transcript the argument points at, exiting on failure.
///
/// The argument may name the transcript itself or the run directory holding
/// it; only the directory form gives the later checks artifacts to read, so it
/// is returned alongside.
fn load_or_exit(file: &Path) -> (rite_runtime::LoadedTranscript, Option<PathBuf>) {
    let (transcript_path, source_dir) = if file.is_dir() {
        (file.join("transcript.jsonl"), Some(file.to_owned()))
    } else {
        (file.to_owned(), None)
    };

    match read_verified_transcript(&transcript_path) {
        Ok(loaded) => (loaded, source_dir),
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
    }
}

/// Print what the transcript contained and what the entropy re-derivation
/// covered.
fn print_counts(loaded: &rite_runtime::LoadedTranscript, entropy: &rite_runtime::EntropyVerified) {
    let header = &loaded.header;
    // A fact of an unknown type may be the one that matters (a refused
    // attestation, a deviation), so its presence qualifies the verdict.
    if loaded.unknown.is_empty() {
        println!("Transcript verified.");
    } else {
        println!(
            "Transcript verified, except {} fact(s) of a type this version cannot read.",
            loaded.unknown.len()
        );
    }
    println!(
        "  Format:      {} (vocabulary {})",
        header.rite_transcript, header.vocabulary
    );
    println!("  Producer:    {}", header.producer);
    println!("  Run:         {}", header.run_id);
    println!("  Facts:       {}", loaded.facts.len());
    if !loaded.withheld.is_empty() {
        println!(
            "  Withheld:    {} line(s), committed but not disclosed",
            loaded.withheld.len()
        );
    }
    for unknown in &loaded.unknown {
        println!(
            "  Unread:      line {}, type '{}', committed but not checked",
            unknown.line, unknown.type_name
        );
    }
    if let Some(scheme) = &entropy.derivation {
        println!(
            "  Entropy:     {} value(s) re-derived, {} contribution(s) folded ({scheme})",
            entropy.values_verified, entropy.contributions,
        );
    }
    if let Some(source) = &entropy.source {
        println!("  Seed source: {source}");
    }
}

/// What checking a bundle's index and definition found.
struct BundleCheck {
    lines: Vec<String>,
    failed: bool,
}

/// Check the index and the definition of a bundle directory, or `None` when
/// `dir` is a plain run directory with no index.
fn check_bundle(dir: &Path, loaded: &rite_runtime::LoadedTranscript) -> Option<BundleCheck> {
    use rite_model::bundle::{BundleKind, DEFINITION_FILE, INDEX_FILE};

    if !dir.join(INDEX_FILE).is_file() {
        return None;
    }
    let mut check = BundleCheck {
        lines: Vec::new(),
        failed: false,
    };
    let index = match crate::bundle::read_index(dir) {
        Ok(index) => index,
        Err(e) => {
            check.lines.push(format!("Bundle:      UNREADABLE: {e}"));
            check.failed = true;
            return Some(check);
        }
    };
    let disclosure = matches!(index.kind, BundleKind::Disclosure { .. });
    match index.kind {
        BundleKind::Complete => {
            check.lines.push(format!(
                "Bundle:      complete, format {}",
                index.rite_bundle
            ));
            if !loaded.withheld.is_empty() {
                check.lines.push(format!(
                    "  FAILED: a complete bundle, but its transcript withholds {} line(s)",
                    loaded.withheld.len()
                ));
                check.failed = true;
            }
        }
        BundleKind::Disclosure { threshold } => {
            check.lines.push(format!(
                "Bundle:      disclosure up to {threshold}, format {}",
                index.rite_bundle
            ));
            check_disclosure_policy(loaded, threshold, &mut check);
        }
        _ => {
            check
                .lines
                .push("Bundle:      of a kind this version does not know".to_string());
            check.failed = true;
        }
    }
    if index.fingerprint != loaded.fingerprint {
        check.lines.push(format!(
            "  MISMATCH: the index names fingerprint {}",
            index.fingerprint
        ));
        check.failed = true;
    }
    check_index_files(dir, &index.files, loaded, &mut check);

    let definition_path = dir.join(DEFINITION_FILE);
    let line = match (
        definition_path.is_file(),
        crate::bundle::create::template_digest(loaded),
    ) {
        (false, _) => "Definition:  not in the bundle".to_string(),
        // The definition can name persons and parameter values, and has no
        // level of its own, so no disclosure carries it.
        (true, _) if disclosure => {
            check.failed = true;
            format!("Definition:  FAILED: a disclosure holds {DEFINITION_FILE}")
        }
        (true, None) => {
            check.failed = true;
            "Definition:  present, but the transcript records no template digest".to_string()
        }
        (true, Some(template)) => match std::fs::read(&definition_path) {
            Ok(bytes) if rite_model::Sha256Digest::of(&bytes) == *template => {
                format!("Definition:  ok ({DEFINITION_FILE})")
            }
            Ok(_) => {
                check.failed = true;
                format!("Definition:  MISMATCH ({DEFINITION_FILE} is not the template {template})")
            }
            Err(e) => {
                check.failed = true;
                format!("Definition:  ERROR: {e}")
            }
        },
    };
    check.lines.push(line);
    Some(check)
}

/// Check the index's file list against the bundle. Every file it lists is
/// there, at the path its role names, and an artifact is one a disclosed fact
/// records under that name. Every file the verifier reads as part of the
/// bundle is listed. Any other file in the directory is bound by nothing: it
/// is named, and fails nothing.
fn check_index_files(
    dir: &Path,
    files: &[rite_model::bundle::BundleFile],
    loaded: &rite_runtime::LoadedTranscript,
    check: &mut BundleCheck,
) {
    use rite_model::bundle::{
        DEFINITION_FILE, FileRole, INDEX_FILE, TRANSCRIPT_FILE, artifact_path,
    };
    use std::collections::{BTreeMap, BTreeSet};

    // Where each disclosed artifact is stored, and the name it is recorded under.
    let recorded: BTreeMap<String, &str> = loaded
        .facts
        .iter()
        .filter_map(|timed| {
            let StepFact::ArtifactWritten { name, file, .. } = &timed.fact else {
                return None;
            };
            artifact_path(file).map(|path| (path, name.as_str()))
        })
        .collect();

    check
        .lines
        .push(format!("Files:       {} listed in the index", files.len()));
    let mut fail = |line: String| {
        check.lines.push(line);
        check.failed = true;
    };

    let mut listed = BTreeSet::new();
    for file in files {
        let path = file.path.as_str();
        let problem = if !listed.insert(path) {
            Some("is listed twice")
        } else if !path.split('/').all(rite_model::is_safe_component) {
            Some("is not a relative path inside the bundle")
        } else if !dir.join(path).is_file() {
            Some("is listed but not in the bundle")
        } else {
            match file.role {
                FileRole::Transcript if path == TRANSCRIPT_FILE => None,
                FileRole::Definition if path == DEFINITION_FILE => None,
                FileRole::Artifact => match recorded.get(path) {
                    Some(name) if file.name.as_deref() == Some(*name) => None,
                    Some(_) => Some("is listed under another artifact's name"),
                    None => Some("is listed as an artifact no disclosed fact records"),
                },
                _ => Some("is listed with a role its path does not have"),
            }
        };
        if let Some(problem) = problem {
            fail(format!("  FAILED: {path} {problem}"));
        }
    }

    let mut required = vec![TRANSCRIPT_FILE.to_string()];
    if dir.join(DEFINITION_FILE).is_file() {
        required.push(DEFINITION_FILE.to_string());
    }
    required.extend(recorded.into_keys().filter(|path| dir.join(path).is_file()));
    for path in required
        .iter()
        .filter(|path| !listed.contains(path.as_str()))
    {
        fail(format!(
            "  FAILED: {path} is in the bundle but not in the index"
        ));
    }

    let mut others = Vec::new();
    collect_files(dir, "", &mut others);
    others.retain(|path| {
        path != INDEX_FILE && !listed.contains(path.as_str()) && !required.contains(path)
    });
    if !others.is_empty() {
        check.lines.push(format!(
            "  Note: not in the index, and not checked: {}",
            others.join(", ")
        ));
    }
}

/// Every file under `dir`, as `/`-separated paths below it, prefixed by
/// `prefix`. Symbolic links are listed, not followed.
fn collect_files(dir: &Path, prefix: &str, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            collect_files(&entry.path(), &format!("{path}/"), out);
        } else {
            out.push(path);
        }
    }
}

/// A disclosure withholds exactly what sits above its threshold. A line
/// withheld at or below it, or disclosed above it, makes the disclosure
/// misstate what it is, which fails. Facts of an unknown type count by the
/// level on their line.
fn check_disclosure_policy(
    loaded: &rite_runtime::LoadedTranscript,
    threshold: rite_model::Level,
    check: &mut BundleCheck,
) {
    for withheld in loaded.withheld.iter().filter(|w| w.level <= threshold) {
        check.lines.push(format!(
            "  FAILED: line {} is withheld at {}, which this disclosure covers",
            withheld.line, withheld.level
        ));
        check.failed = true;
    }
    let known = loaded.facts.iter().map(|fact| (fact.line, fact.level));
    let unknown = loaded.unknown.iter().map(|fact| (fact.line, fact.level));
    let mut above: Vec<_> = known
        .chain(unknown)
        .filter(|(_, level)| *level > threshold)
        .collect();
    above.sort_unstable();
    for (line, level) in above {
        check.lines.push(format!(
            "  FAILED: line {line} is disclosed at {level}, above this disclosure's threshold"
        ));
        check.failed = true;
    }
}

/// Print the per-container result lines, and report whether any artifact
/// contradicts what the transcript says was done to it.
///
/// A container nothing could check prints as unchecked and fails nothing: an
/// artifact carried off to its destination is the normal case, and absence is
/// not evidence either way.
fn summarize_containers(checks: &[ContainerCheck]) -> bool {
    if checks.is_empty() {
        return false;
    }
    println!("  Containers:");
    for check in checks {
        println!("    {}", check.describe());
    }
    checks.iter().any(ContainerCheck::failed)
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
            ArtifactStatus::Match | ArtifactStatus::NoDigest => {}
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
    /// Opened content: the transcript records no digest to check against.
    NoDigest,
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
            ArtifactStatus::NoDigest => format!(
                "{}: not checked, opened content has no recorded digest ({})",
                self.name, self.location,
            ),
            ArtifactStatus::Error { reason } => format!("{}: ERROR: {reason}", self.name),
        }
    }
}

/// Re-hash every artifact the transcript records against the run directory.
fn check_artifacts<'a>(
    dir: &Path,
    facts: impl IntoIterator<Item = &'a StepFact>,
) -> Vec<ArtifactCheck> {
    facts
        .into_iter()
        .filter_map(|fact| {
            let StepFact::ArtifactWritten {
                name, file, digest, ..
            } = fact
            else {
                return None;
            };
            Some(check_one_artifact(dir, name, file, digest.as_ref()))
        })
        .collect()
}

fn check_one_artifact(
    dir: &Path,
    name: &str,
    file: &str,
    recorded: Option<&Sha256Digest>,
) -> ArtifactCheck {
    let Some(location) = rite_model::bundle::artifact_path(file) else {
        return ArtifactCheck {
            name: name.to_string(),
            location: String::new(),
            status: ArtifactStatus::Error {
                reason: format!("recorded file name '{file}' is not a single path component"),
            },
        };
    };
    let Some(recorded) = recorded else {
        return ArtifactCheck {
            name: name.to_string(),
            location,
            status: ArtifactStatus::NoDigest,
        };
    };
    let on_disk = dir.join(&location);
    let status = if on_disk.is_file() {
        match std::fs::read(&on_disk).map(|bytes| Sha256Digest::of(&bytes)) {
            Ok(actual) if actual == *recorded => ArtifactStatus::Match,
            Ok(actual) => ArtifactStatus::Mismatch {
                actual: actual.to_string(),
            },
            Err(e) => ArtifactStatus::Error {
                reason: format!("could not read {}: {e}", on_disk.display()),
            },
        }
    } else {
        ArtifactStatus::Missing
    };
    ArtifactCheck {
        name: name.to_string(),
        location,
        status,
    }
}

/// Bare hex digest, tolerant of the `sha256:` prefix the runtime records.
pub(crate) fn digest_hex(s: &str) -> &str {
    s.strip_prefix("sha256:").unwrap_or(s)
}

/// Line number of the first fact whose time is earlier than the fact before
/// it, if any.
fn first_timestamp_regression(facts: &[TimedFact]) -> Option<usize> {
    facts
        .iter()
        .zip(facts.iter().skip(1))
        .find(|(prev, next)| next.at < prev.at)
        .map(|(_, next)| next.line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use rite_model::StepId;

    fn artifact_fact(file: &str, bytes: &[u8]) -> StepFact {
        StepFact::ArtifactWritten {
            step: StepId::new("s1"),
            name: "root".to_string(),
            file: file.to_string(),
            digest: Some(Sha256Digest::of(bytes)),
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
        let fact = artifact_fact("root.crt", b"cert bytes");
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
        let fact = artifact_fact("root.crt", b"cert bytes");
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert!(matches!(
            checks.first().expect("one check").status,
            ArtifactStatus::Mismatch { .. }
        ));
    }

    #[test]
    fn artifact_absent_from_disk_is_reported_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let fact = artifact_fact("root.crt", b"cert bytes");
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert_eq!(
            checks.first().expect("one check").status,
            ArtifactStatus::Missing
        );
    }

    #[test]
    fn a_recorded_name_that_is_not_one_component_is_an_error() {
        // A crafted transcript cannot point the verifier outside artifacts/.
        let tmp = tempfile::tempdir().expect("tempdir");
        for file in ["../../../../etc/passwd", "/etc/passwd", "a/b", "", ".."] {
            let fact = artifact_fact(file, b"x");
            let checks = check_artifacts(tmp.path(), [&fact]);
            assert!(
                matches!(
                    checks.first().expect("one check").status,
                    ArtifactStatus::Error { .. }
                ),
                "accepted {file:?}"
            );
        }
    }

    #[test]
    fn opened_content_is_reported_unchecked() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_artifact(tmp.path(), "opened.bin", b"plaintext");
        let fact = StepFact::ArtifactWritten {
            step: StepId::new("s1"),
            name: "opened".to_string(),
            file: "opened.bin".to_string(),
            digest: None,
        };
        let checks = check_artifacts(tmp.path(), [&fact]);
        assert_eq!(
            checks.first().expect("one check").status,
            ArtifactStatus::NoDigest
        );
    }

    #[test]
    fn digest_comparison_tolerates_the_sha256_prefix() {
        assert_eq!(digest_hex("sha256:abcd"), "abcd");
        assert_eq!(digest_hex("abcd"), "abcd");
    }

    fn timed(facts_seconds: &[i64]) -> Vec<TimedFact> {
        facts_seconds
            .iter()
            .enumerate()
            .map(|(i, s)| TimedFact {
                // Line 1 is the header.
                line: i.saturating_add(2),
                at: ts(*s),
                level: rite_model::Level::PUBLIC,
                fact: rite_runtime::test_support::ceremony_started("t"),
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
        // The third fact, on line 4 after the header, goes backwards.
        assert_eq!(
            first_timestamp_regression(&timed(&[10, 20, 15, 30])),
            Some(4)
        );
    }

    #[test]
    fn empty_fact_list_raises_no_warning() {
        assert_eq!(first_timestamp_regression(&[]), None);
    }

    /// A transcript of one public fact on line 2, one withheld restricted
    /// line on line 3, and whatever `edit` adds.
    fn disclosure_check(edit: impl FnOnce(&mut rite_runtime::LoadedTranscript)) -> BundleCheck {
        use rite_model::Level;
        let mut loaded = rite_runtime::LoadedTranscript {
            header: rite_model::TranscriptHeader::new("rite test", "0", false),
            facts: timed(&[10]),
            withheld: vec![rite_runtime::WithheldLine {
                line: 3,
                level: Level::RESTRICTED,
            }],
            unknown: Vec::new(),
            fingerprint: Sha256Digest::of(b"fingerprint"),
            terminated: false,
        };
        edit(&mut loaded);
        let mut check = BundleCheck {
            lines: Vec::new(),
            failed: false,
        };
        check_disclosure_policy(&loaded, Level::PUBLIC, &mut check);
        check
    }

    #[test]
    fn a_disclosure_that_withholds_what_is_above_its_threshold_passes() {
        let check = disclosure_check(|_| {});
        assert!(!check.failed, "{:?}", check.lines);
    }

    #[test]
    fn a_line_withheld_at_the_threshold_fails() {
        let check = disclosure_check(|loaded| {
            loaded.withheld.push(rite_runtime::WithheldLine {
                line: 4,
                level: rite_model::Level::PUBLIC,
            });
        });
        assert!(check.failed);
        assert_eq!(
            check.lines,
            ["  FAILED: line 4 is withheld at public, which this disclosure covers"]
        );
    }

    #[test]
    fn a_line_disclosed_above_the_threshold_fails() {
        let check = disclosure_check(|loaded| {
            let fact = loaded.facts.first_mut().expect("one fact");
            fact.level = rite_model::Level::CONFIDENTIAL;
        });
        assert!(check.failed);
        assert_eq!(
            check.lines,
            ["  FAILED: line 2 is disclosed at confidential, above this disclosure's threshold"]
        );
    }

    #[test]
    fn an_unknown_fact_disclosed_above_the_threshold_fails() {
        let check = disclosure_check(|loaded| {
            loaded.unknown.push(rite_runtime::UnknownFact {
                line: 4,
                level: rite_model::Level::RESTRICTED,
                type_name: "future_fact".to_string(),
            });
        });
        assert!(check.failed);
        assert_eq!(
            check.lines,
            ["  FAILED: line 4 is disclosed at restricted, above this disclosure's threshold"]
        );
    }

    #[test]
    fn a_disclosure_holding_the_definition_fails() {
        use rite_model::bundle::{BundleFile, BundleIndex, DEFINITION_FILE};

        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("transcript.jsonl"), b"").expect("transcript");
        std::fs::create_dir_all(tmp.path().join("definition")).expect("definition dir");
        std::fs::write(tmp.path().join(DEFINITION_FILE), b"name: demo").expect("definition");
        let fingerprint = Sha256Digest::of(b"fingerprint");
        let index = BundleIndex::disclosure(
            fingerprint.clone(),
            rite_model::Level::PUBLIC,
            vec![BundleFile::transcript(), BundleFile::definition()],
        );
        std::fs::write(
            tmp.path().join("bundle.json"),
            serde_json::to_vec(&index).expect("index json"),
        )
        .expect("index");
        let loaded = rite_runtime::LoadedTranscript {
            header: rite_model::TranscriptHeader::new("rite test", "0", false),
            facts: Vec::new(),
            withheld: Vec::new(),
            unknown: Vec::new(),
            fingerprint,
            terminated: true,
        };

        let check = check_bundle(tmp.path(), &loaded).expect("a bundle");
        assert!(check.failed, "{:?}", check.lines);
        assert!(
            check.lines.contains(&format!(
                "Definition:  FAILED: a disclosure holds {DEFINITION_FILE}"
            )),
            "{:?}",
            check.lines
        );
    }

    /// A bundle directory holding a transcript and the artifact `root.crt`,
    /// recorded as `root`, with `files` as its index's list.
    fn index_check(
        files: &[rite_model::bundle::BundleFile],
        extra: &[&str],
    ) -> (tempfile::TempDir, BundleCheck) {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("transcript.jsonl"), b"").expect("transcript");
        std::fs::write(tmp.path().join("bundle.json"), b"").expect("index");
        write_artifact(tmp.path(), "root.crt", b"cert");
        for file in extra {
            std::fs::write(tmp.path().join(file), b"").expect("extra");
        }
        let loaded = rite_runtime::LoadedTranscript {
            header: rite_model::TranscriptHeader::new("rite test", "0", false),
            facts: vec![TimedFact {
                line: 2,
                at: ts(10),
                level: rite_model::Level::PUBLIC,
                fact: StepFact::ArtifactWritten {
                    step: StepId::new("s1"),
                    name: "root".to_string(),
                    file: "root.crt".to_string(),
                    digest: Some(Sha256Digest::of(b"cert")),
                },
            }],
            withheld: Vec::new(),
            unknown: Vec::new(),
            fingerprint: Sha256Digest::of(b"fingerprint"),
            terminated: true,
        };
        let mut check = BundleCheck {
            lines: Vec::new(),
            failed: false,
        };
        check_index_files(tmp.path(), files, &loaded, &mut check);
        (tmp, check)
    }

    fn full_list() -> Vec<rite_model::bundle::BundleFile> {
        use rite_model::bundle::BundleFile;
        vec![
            BundleFile::transcript(),
            BundleFile::artifact("root", "artifacts/root.crt"),
        ]
    }

    #[test]
    fn an_index_listing_every_file_passes() {
        let (_tmp, check) = index_check(&full_list(), &[]);
        assert!(!check.failed, "{:?}", check.lines);
    }

    #[test]
    fn an_empty_file_list_fails_for_every_file_it_leaves_out() {
        let (_tmp, check) = index_check(&[], &[]);
        assert!(check.failed);
        assert_eq!(
            check.lines,
            [
                "Files:       0 listed in the index",
                "  FAILED: transcript.jsonl is in the bundle but not in the index",
                "  FAILED: artifacts/root.crt is in the bundle but not in the index",
            ]
        );
    }

    #[test]
    fn a_listed_file_that_is_not_there_fails() {
        let mut files = full_list();
        files.push(rite_model::bundle::BundleFile::definition());
        let (_tmp, check) = index_check(&files, &[]);
        assert!(check.failed);
        assert!(
            check.lines.contains(
                &"  FAILED: definition/ceremony.rite.yaml is listed but not in the bundle"
                    .to_string()
            ),
            "{:?}",
            check.lines
        );
    }

    #[test]
    fn an_artifact_under_another_name_fails() {
        use rite_model::bundle::BundleFile;
        let files = [
            BundleFile::transcript(),
            BundleFile::artifact("other", "artifacts/root.crt"),
        ];
        let (_tmp, check) = index_check(&files, &[]);
        assert!(check.failed);
        assert!(check.lines.contains(
            &"  FAILED: artifacts/root.crt is listed under another artifact's name".to_string()
        ));
    }

    #[test]
    fn a_path_outside_the_bundle_fails() {
        use rite_model::bundle::BundleFile;
        let mut files = full_list();
        files.push(BundleFile::artifact("root", "../outside.crt"));
        let (_tmp, check) = index_check(&files, &[]);
        assert!(check.failed);
        assert!(check.lines.contains(
            &"  FAILED: ../outside.crt is not a relative path inside the bundle".to_string()
        ));
    }

    #[test]
    fn a_file_outside_the_index_is_named_and_fails_nothing() {
        let (_tmp, check) = index_check(&full_list(), &[".DS_Store"]);
        assert!(!check.failed, "{:?}", check.lines);
        assert!(
            check
                .lines
                .contains(&"  Note: not in the index, and not checked: .DS_Store".to_string())
        );
    }

    #[test]
    fn a_pre_1_0_transcript_from_another_release_is_flagged() {
        let mut header = rite_model::TranscriptHeader::new(rite_runtime::PRODUCER, "0", false);
        assert_eq!(unstable_format_warning(&header), None);
        header.producer = "rite 0.0.1".to_string();
        let warning = unstable_format_warning(&header).expect("a warning");
        assert!(warning.contains("written by rite 0.0.1"), "{warning}");
    }
}
