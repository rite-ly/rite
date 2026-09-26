//! `rite bundle create`: package a run directory as an evidence bundle.

use std::path::{Path, PathBuf};

use clap::Args as ClapArgs;
use rite_model::bundle::{BundleFile, BundleIndex, DEFINITION_FILE, TRANSCRIPT_FILE};
use rite_model::{Sha256Digest, StepFact};
use rite_runtime::{LoadedTranscript, read_verified_transcript};

use crate::bundle::{copy_artifact, read, with_new_dir, write_index, write_new};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Run output directory produced by `rite run`
    pub run_dir: PathBuf,
    /// Ceremony YAML the run was resolved from
    ///
    /// Checked against the template digest the transcript records. A file that
    /// does not match is refused, so the bundle always holds the definition
    /// that actually ran.
    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "without_definition",
        conflicts_with = "without_definition"
    )]
    pub definition: Option<PathBuf>,
    /// Leave the ceremony definition out of the bundle
    #[arg(long)]
    pub without_definition: bool,
    /// Bundle directory to create; it must not exist
    #[arg(short, long, value_name = "DIR")]
    pub output: PathBuf,
    /// Accept a transcript with no terminal fact (an interrupted run)
    #[arg(long)]
    pub allow_truncated: bool,
}

pub fn run(args: &Args) {
    match create(args) {
        Ok(created) => {
            println!("Bundle written: {}", args.output.display());
            for file in &created.index.files {
                println!("  {}", file.path);
            }
            for note in &created.left_out {
                println!("  left out: {note}");
            }
            println!();
            println!("Transcript fingerprint: {}", created.index.fingerprint);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// What creating a bundle produced.
#[derive(Debug)]
struct Created {
    index: BundleIndex,
    /// Artifacts the transcript records that the bundle does not hold, with why.
    left_out: Vec<String>,
}

/// Build the bundle in a new output directory.
fn create(args: &Args) -> Result<Created, String> {
    with_new_dir(&args.output, || create_into(args))
}

fn create_into(args: &Args) -> Result<Created, String> {
    let out = &args.output;

    // Every check runs on the bytes that go into the bundle, read once: the
    // transcript is copied first and the copy is what gets verified.
    let transcript = read(&args.run_dir.join(TRANSCRIPT_FILE))?;
    write_new(&out.join(TRANSCRIPT_FILE), &transcript)?;
    let loaded = read_verified_transcript(&out.join(TRANSCRIPT_FILE))
        .map_err(|e| format!("the transcript does not verify: {e}"))?;
    check_complete(&loaded, args.allow_truncated)?;
    let mut files = vec![BundleFile::transcript()];

    if let Some(path) = &args.definition {
        let bytes = read(path)?;
        check_definition(&loaded, &bytes, path)?;
        std::fs::create_dir_all(out.join(DEFINITION_FILE).parent().unwrap_or(out))
            .map_err(|e| format!("cannot create the definition directory: {e}"))?;
        write_new(&out.join(DEFINITION_FILE), &bytes)?;
        files.push(BundleFile::definition());
    }

    let mut left_out = Vec::new();
    for fact in loaded.facts.iter().map(|t| &t.fact) {
        let StepFact::ArtifactWritten {
            name, file, digest, ..
        } = fact
        else {
            continue;
        };
        let Some(digest) = digest else {
            left_out.push(format!("{name}, opened content is never bundled"));
            continue;
        };
        match copy_artifact(&args.run_dir, out, name, file, digest)? {
            Some(copied) => files.push(copied),
            None => left_out.push(format!("{name}, not in the run directory")),
        }
    }

    let index = BundleIndex::complete(loaded.fingerprint, files);
    write_index(out, &index)?;
    Ok(Created { index, left_out })
}

/// A complete bundle needs the whole record: no withheld lines, and a run that
/// reached its end unless the caller accepts an interrupted one.
fn check_complete(loaded: &LoadedTranscript, allow_truncated: bool) -> Result<(), String> {
    if !loaded.withheld.is_empty() {
        return Err(format!(
            "the transcript has {} withheld line(s); a complete bundle needs the complete \
             transcript",
            loaded.withheld.len()
        ));
    }
    if !loaded.terminated && !allow_truncated {
        return Err(
            "the transcript is truncated (no ceremony_completed or ceremony_failed \
                    fact at the end); pass --allow-truncated to bundle an interrupted run"
                .to_string(),
        );
    }
    Ok(())
}

/// The definition must be the one the run was resolved from.
fn check_definition(loaded: &LoadedTranscript, bytes: &[u8], path: &Path) -> Result<(), String> {
    let template = template_digest(loaded)
        .ok_or_else(|| "the transcript records no ceremony_started fact".to_string())?;
    let actual = Sha256Digest::of(bytes);
    if actual == *template {
        Ok(())
    } else {
        Err(format!(
            "{} is not the ceremony this run used: its digest is {actual}, the transcript \
             records {template}",
            path.display()
        ))
    }
}

/// The template digest `CeremonyStarted` records, if the fact is disclosed.
pub(crate) fn template_digest(loaded: &LoadedTranscript) -> Option<&Sha256Digest> {
    loaded.facts.iter().find_map(|t| match &t.fact {
        StepFact::CeremonyStarted { template, .. } => Some(template),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::bundle::{ARTIFACTS_DIR, INDEX_FILE};

    const CEREMONY: &str = r#"
version: "0.3"
name: "Bundle test"
roles:
  operator: {}
sections:
  main:
    role: ${role.operator}
    steps:
      confirm:
        action: attest
        silent: true
        with:
          statement: "I confirm."
"#;

    /// A run directory holding a real transcript of `CEREMONY`, plus one
    /// artifact recorded with `artifact_bytes`, written as `artifact_on_disk`.
    fn run_dir(dir: &Path, artifact_bytes: &[u8], artifact_on_disk: Option<&[u8]>) {
        let ceremony = rite_resolver::resolve(CEREMONY, None)
            .into_result()
            .expect("resolve");
        rite_runtime::test_support::write_transcript(
            dir,
            &[
                StepFact::CeremonyStarted {
                    name: "Bundle test".to_string(),
                    template: ceremony.source_digest.clone(),
                },
                StepFact::ArtifactWritten {
                    step: rite_model::StepId::new("confirm"),
                    name: "cert".to_string(),
                    file: "cert.pem".to_string(),
                    digest: Some(Sha256Digest::of(artifact_bytes)),
                },
                StepFact::CeremonyCompleted {},
            ],
        )
        .expect("transcript");
        if let Some(bytes) = artifact_on_disk {
            std::fs::create_dir_all(dir.join(ARTIFACTS_DIR)).expect("artifacts dir");
            std::fs::write(dir.join(ARTIFACTS_DIR).join("cert.pem"), bytes).expect("artifact");
        }
    }

    fn args(run: &Path, definition: Option<PathBuf>, output: PathBuf) -> Args {
        Args {
            run_dir: run.to_path_buf(),
            without_definition: definition.is_none(),
            definition,
            output,
            allow_truncated: false,
        }
    }

    fn write_ceremony(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("ceremony.rite.yaml");
        std::fs::write(&path, text).expect("write ceremony");
        path
    }

    #[test]
    fn bundles_the_transcript_definition_and_artifacts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).expect("run dir");
        run_dir(&run, b"cert", Some(b"cert"));
        let definition = write_ceremony(tmp.path(), CEREMONY);
        let out = tmp.path().join("bundle");

        let created = create(&args(&run, Some(definition), out.clone())).expect("create");

        let paths: Vec<&str> = created
            .index
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [TRANSCRIPT_FILE, DEFINITION_FILE, "artifacts/cert.pem"]
        );
        assert!(created.left_out.is_empty());
        let index: BundleIndex =
            serde_json::from_str(&std::fs::read_to_string(out.join(INDEX_FILE)).expect("index"))
                .expect("parse index");
        assert_eq!(index, created.index);
        assert_eq!(
            std::fs::read(out.join(TRANSCRIPT_FILE)).expect("bundled transcript"),
            std::fs::read(run.join(TRANSCRIPT_FILE)).expect("run transcript"),
        );
    }

    #[test]
    fn a_different_definition_is_refused_and_nothing_is_left_behind() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).expect("run dir");
        run_dir(&run, b"cert", Some(b"cert"));
        let definition = write_ceremony(tmp.path(), &CEREMONY.replace("I confirm.", "I agree."));
        let out = tmp.path().join("bundle");

        let err = create(&args(&run, Some(definition), out.clone())).expect_err("mismatch");
        assert!(err.contains("not the ceremony this run used"), "{err}");
        assert!(!out.exists(), "a refused bundle leaves no directory behind");
    }

    #[test]
    fn a_tampered_artifact_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).expect("run dir");
        run_dir(&run, b"cert", Some(b"forged"));
        let out = tmp.path().join("bundle");

        let err = create(&args(&run, None, out)).expect_err("tampered artifact");
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn a_missing_artifact_is_left_out_and_said_so() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).expect("run dir");
        run_dir(&run, b"cert", None);
        let out = tmp.path().join("bundle");

        let created = create(&args(&run, None, out)).expect("create");
        assert_eq!(created.index.files.len(), 1);
        assert_eq!(created.left_out, ["cert, not in the run directory"]);
    }

    #[test]
    fn an_existing_output_directory_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = tmp.path().join("run");
        std::fs::create_dir(&run).expect("run dir");
        run_dir(&run, b"cert", Some(b"cert"));
        let out = tmp.path().join("bundle");
        std::fs::create_dir(&out).expect("pre-existing");

        let err = create(&args(&run, None, out.clone())).expect_err("exists");
        assert!(err.contains("cannot create"), "{err}");
        assert!(out.exists(), "a directory it did not create is not removed");
    }
}
