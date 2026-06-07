//! `rite verify`: check a ceremony transcript's integrity.

use std::path::PathBuf;

use clap::Args as ClapArgs;
use rite_runtime::{VerifyError, read_verified_transcript, verify_entropy};

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or output folder
    pub file: PathBuf,
}

pub fn run(args: Args) {
    let (transcript_path, source_dir) = if args.file.is_dir() {
        let candidate = args.file.join("transcript.jsonl");
        (candidate, Some(args.file))
    } else {
        (args.file, None)
    };

    match read_verified_transcript(&transcript_path) {
        Ok(loaded) => {
            // The hash chain is intact. Now re-derive the entropy source so
            // every recorded random value is proven to come from the recorded
            // seed, not cherry-picked.
            let entropy = match verify_entropy(loaded.facts.iter().map(|t| &t.fact)) {
                Ok(entropy) => entropy,
                Err(err) => {
                    eprintln!("Verification failed: {err}");
                    std::process::exit(1);
                }
            };

            println!("Transcript verified.");
            println!("  Facts:       {}", loaded.facts.len());
            println!("  Fingerprint: {}", loaded.fingerprint);
            if let Some(scheme) = entropy.derivation {
                println!(
                    "  Entropy:     {} value(s) re-derived, {} contribution(s) folded ({scheme})",
                    entropy.values_verified, entropy.contributions,
                );
            }
            if !loaded.terminated {
                eprintln!(
                    "  Warning:     transcript is truncated, no CeremonyCompleted or \
                     CeremonyFailed fact at the end."
                );
            }
            std::process::exit(0);
        }
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
