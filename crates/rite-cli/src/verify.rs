//! `rite verify`: check a ceremony transcript's integrity.

use clap::Args as ClapArgs;
use rite_runtime::VerificationResult;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Path to the transcript JSONL file or output folder
    pub file: PathBuf,
    /// Expected nonce (written on paper script during ceremony)
    #[arg(long)]
    pub nonce: Option<String>,
}

pub fn run(args: Args) {
    let (transcript_path, source_dir) = if args.file.is_dir() {
        let candidate = rite_runtime::OutputConfig::new(args.file.clone()).transcript_path();
        (candidate, Some(args.file))
    } else {
        (args.file, None)
    };

    match rite_runtime::verify_transcript(&transcript_path) {
        Ok(result) => match result {
            VerificationResult::Valid {
                ref artifacts,
                ref tpm_nonce,
                ..
            } => {
                println!("{result}");

                let nonce_failed = if let Some(ref expected) = args.nonce {
                    if let Some(found) = tpm_nonce {
                        if expected == found {
                            println!("Nonce check: matches expected");
                            false
                        } else {
                            eprintln!(
                                "Nonce check: MISMATCH (expected: {expected}, found: {found})"
                            );
                            true
                        }
                    } else {
                        eprintln!("Nonce check: MISMATCH (expected: {expected}, found: <missing>)");
                        true
                    }
                } else {
                    false
                };

                if artifacts.iter().any(|a| !a.verified) || nonce_failed {
                    std::process::exit(1);
                }

                std::process::exit(0);
            }
            VerificationResult::Invalid { .. } => {
                eprintln!("{result}");
                std::process::exit(1);
            }
            VerificationResult::Incomplete {
                status,
                events_count,
            } => {
                // TODO: Revisit exit-code policy for Incomplete; currently uses 2 as a
                // special-case status distinct from generic verification failure.
                eprintln!("Incomplete transcript (no final fingerprint).");
                eprintln!("  Status: {status:?}");
                eprintln!("  Events recorded: {events_count}");
                std::process::exit(2);
            }
            // VerificationResult is #[non_exhaustive]; future variants exit with failure.
            _ => std::process::exit(1),
        },
        Err(e) => {
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
    }
}
