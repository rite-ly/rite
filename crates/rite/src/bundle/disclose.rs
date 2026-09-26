//! `rite bundle disclose`: derive a disclosure from a complete evidence bundle.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use rite_model::StepFact;
use rite_model::bundle::{BundleFile, BundleIndex, BundleKind, INDEX_FILE, TRANSCRIPT_FILE};
use rite_runtime::{disclose_transcript, verify_jsonl};

use crate::bundle::{copy_artifact, read, read_index, with_new_dir, write_index, write_new};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Complete bundle produced by `rite bundle create`
    pub bundle: PathBuf,
    /// Widest audience to disclose to: a level name (`public`, `restricted`,
    /// `confidential`) or its number
    ///
    /// Every fact recorded at this level or below is disclosed; every fact
    /// above it is withheld, keeping its commitment.
    #[arg(long, value_name = "LEVEL")]
    pub level: String,
    /// Disclosure directory to create; it must not exist
    #[arg(short, long, value_name = "DIR")]
    pub output: PathBuf,
}

pub fn run(args: &Args) {
    match with_new_dir(&args.output, || disclose(args)) {
        Ok(disclosed) => {
            let index = &disclosed.index;
            if let BundleKind::Disclosure { threshold } = index.kind {
                println!(
                    "Disclosure written: {} (up to {threshold})",
                    args.output.display()
                );
            }
            println!(
                "  {} fact(s) disclosed, {} withheld",
                disclosed.facts, disclosed.withheld
            );
            for file in &index.files {
                println!("  {}", file.path);
            }
            println!("  left out: the ceremony definition, which can name people");
            for name in &disclosed.missing {
                println!("  left out: {name}, not in the bundle");
            }
            println!();
            println!("Transcript fingerprint: {}", index.fingerprint);
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// What a disclosure produced.
#[derive(Debug)]
struct Disclosed {
    index: BundleIndex,
    facts: usize,
    withheld: usize,
    /// Disclosed artifacts the source bundle does not hold.
    missing: Vec<String>,
}

fn disclose(args: &Args) -> Result<Disclosed, String> {
    let out = &args.output;
    let index = read_index(&args.bundle)?;
    if index.kind != BundleKind::Complete {
        return Err("a disclosure is derived from a complete bundle".to_string());
    }

    // The transcript is read once: the text that is verified is the text
    // that is disclosed.
    let text = String::from_utf8(read(&args.bundle.join(TRANSCRIPT_FILE))?)
        .map_err(|_| "the bundle's transcript is not UTF-8".to_string())?;
    let source =
        verify_jsonl(&text).map_err(|e| format!("the bundle's transcript does not verify: {e}"))?;
    if !source.withheld.is_empty() {
        return Err("the bundle's transcript already has withheld lines".to_string());
    }
    if index.fingerprint != source.fingerprint {
        return Err(format!(
            "{INDEX_FILE} names fingerprint {}, but the transcript folds to {}",
            index.fingerprint, source.fingerprint
        ));
    }
    let threshold = source
        .header
        .level(&args.level)
        .ok_or_else(|| format!("'{}' is not a level this transcript declares", args.level))?;

    // The withheld copy must verify, and fold to the fingerprint of the
    // complete transcript.
    let disclosed = disclose_transcript(&text, threshold).map_err(|e| e.to_string())?;
    let loaded = verify_jsonl(&disclosed)
        .map_err(|e| format!("the disclosed transcript does not verify: {e}"))?;
    if loaded.fingerprint != source.fingerprint {
        return Err("the disclosed transcript does not keep the fingerprint".to_string());
    }
    write_new(&out.join(TRANSCRIPT_FILE), disclosed.as_bytes())?;
    let mut files = vec![BundleFile::transcript()];
    let mut missing = Vec::new();

    // Only artifacts whose facts are disclosed, and only those the bundle
    // holds; each is checked against its digest on the way through.
    for fact in loaded.facts.iter().map(|t| &t.fact) {
        if let StepFact::ArtifactWritten {
            name,
            file,
            digest: Some(digest),
            ..
        } = fact
        {
            match copy_artifact(&args.bundle, out, name, file, digest)? {
                Some(copied) => files.push(copied),
                None => missing.push(name.clone()),
            }
        }
    }

    let index = BundleIndex::disclosure(loaded.fingerprint, threshold, files);
    write_index(out, &index)?;
    Ok(Disclosed {
        index,
        facts: loaded.facts.len(),
        withheld: loaded.withheld.len(),
        missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::Sha256Digest;
    use rite_runtime::test_support::{ceremony_started, write_transcript};

    /// A complete bundle holding one public and one confidential fact, with
    /// `fingerprint` in its index, or the transcript's own when `None`.
    fn bundle(dir: &std::path::Path, fingerprint: Option<Sha256Digest>) -> Sha256Digest {
        let actual = write_transcript(
            dir,
            &[
                ceremony_started("Disclose test"),
                StepFact::RoleAssigned {
                    role: rite_model::RoleId::new("operator"),
                    person: "Alice".to_string(),
                },
                StepFact::CeremonyCompleted {},
            ],
        )
        .expect("transcript");
        let index = BundleIndex::complete(
            fingerprint.unwrap_or_else(|| actual.clone()),
            vec![BundleFile::transcript()],
        );
        write_index(dir, &index).expect("index");
        actual
    }

    fn args(bundle: &std::path::Path, output: PathBuf) -> Args {
        Args {
            bundle: bundle.to_path_buf(),
            level: "public".to_string(),
            output,
        }
    }

    #[test]
    fn discloses_under_the_transcript_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = tmp.path().join("bundle");
        std::fs::create_dir(&source).expect("bundle dir");
        let fingerprint = bundle(&source, None);

        let out = tmp.path().join("out");
        std::fs::create_dir(&out).expect("out dir");

        let disclosed = disclose(&args(&source, out)).expect("disclose");

        assert_eq!(disclosed.withheld, 1);
        assert_eq!(disclosed.index.fingerprint, fingerprint);
        assert!(disclosed.missing.is_empty());
    }

    #[test]
    fn a_disclosed_artifact_the_bundle_lacks_is_named() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = tmp.path().join("bundle");
        std::fs::create_dir(&source).expect("bundle dir");
        let fingerprint = write_transcript(
            &source,
            &[
                ceremony_started("Disclose test"),
                StepFact::ArtifactWritten {
                    step: rite_model::StepId::new("s1"),
                    name: "root_cert".to_string(),
                    file: "root_cert.pem".to_string(),
                    digest: Some(Sha256Digest::of(b"cert")),
                },
                StepFact::CeremonyCompleted {},
            ],
        )
        .expect("transcript");
        write_index(
            &source,
            &BundleIndex::complete(fingerprint, vec![BundleFile::transcript()]),
        )
        .expect("index");
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).expect("out dir");

        let disclosed = disclose(&args(&source, out)).expect("disclose");

        assert_eq!(disclosed.missing, ["root_cert"]);
    }

    #[test]
    fn an_index_naming_another_fingerprint_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = tmp.path().join("bundle");
        std::fs::create_dir(&source).expect("bundle dir");
        bundle(&source, Some(Sha256Digest::of(b"another run")));

        let err = disclose(&args(&source, tmp.path().join("out"))).expect_err("refused");

        assert!(err.contains("fingerprint"), "{err}");
    }
}
