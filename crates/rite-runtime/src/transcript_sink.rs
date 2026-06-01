//! Transcript sink, the durable consumer of [`StepFact`]s.
//!
//! The sink is an inline observer in the executor thread. It records each
//! [`StepFact`] synchronously before the executor proceeds to its next action,
//! and the on-disk implementation `fsync`s the line to the storage device
//! before returning. This invariant, *the transcript is durable before the
//! UI sees the fact* , is what makes the on-disk record the authoritative
//! source of evidence and the live UI a tee of the same stream.
//!
//! # On-disk format (`transcript.jsonl`)
//!
//! Each line is a JSON object with two fields:
//!
//! ```jsonc
//! {"prev_hash": "sha256:…", "fact": { "type": "step_started", … }}
//! ```
//!
//! The chain is verified by recomputing each line's SHA-256, accumulating it
//! as the expected `prev_hash` of the next line, starting from
//! [`GENESIS_HASH`]. The final transcript fingerprint is the hash of the
//! last line; the JSONL is self-identifying and no sidecar file is written.
//!
//! # Implementations
//!
//! - [`JsonlFileSink`], writes to disk, flushes after every line.
//! - [`InMemorySink`], collects facts in a `Vec` for tests and tooling.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::transcript::compute_fingerprint;
use rite_model::StepFact;

/// SHA-256 fingerprint produced by a [`TranscriptSink::finalize`] call.
///
/// Encoded as `sha256:<lowercase-hex>`, matching the convention used
/// throughout the runtime for artifact and transcript fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptFingerprint(String);

impl TranscriptFingerprint {
    /// Build a fingerprint from an already-formatted `sha256:<hex>` string.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self(s)
    }

    /// `sha256:<hex>` representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TranscriptFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Genesis `prev_hash` value used on the very first line of every transcript.
///
/// `sha256:` followed by 64 zero hex digits.
pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Synchronous, durable observer of [`StepFact`]s.
///
/// Implementations must record each fact, including syncing it to the
/// underlying storage where applicable, before returning. The executor
/// relies on this to maintain the invariant that the UI never sees a fact
/// that has not been durably persisted.
pub trait TranscriptSink: Send {
    /// Record a single fact. Must persist before returning, the file-backed
    /// implementation calls `sync_data` so a power loss after `record`
    /// returns cannot drop the fact.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the sink cannot persist the fact.
    fn record(&mut self, fact: &StepFact) -> io::Result<()>;

    /// Finalize the transcript and return its fingerprint.
    ///
    /// Calling `finalize` more than once is implementation-defined; the
    /// default expectation is that the second call returns the cached
    /// fingerprint.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if any pending state cannot be
    /// persisted.
    fn finalize(&mut self) -> io::Result<TranscriptFingerprint>;
}

/// JSONL file sink with SHA-256 chain integrity.
///
/// Writes `transcript.jsonl` to a target directory. Every `record` call
/// serializes the fact, prepends the current chain head as `prev_hash`,
/// writes one line, flushes, and advances the chain head. The transcript
/// is self-identifying: `SHA-256` of the last line *is* the cryptographic
/// fingerprint; no sidecar file is written.
#[derive(Debug)]
pub struct JsonlFileSink {
    jsonl_path: PathBuf,
    writer: BufWriter<File>,
    current_hash: String,
    finalized: Option<TranscriptFingerprint>,
}

impl JsonlFileSink {
    /// Create a new sink in `dir`. Writes `transcript.jsonl` next to it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the JSONL file cannot be created.
    pub fn create(dir: &Path) -> io::Result<Self> {
        let jsonl_path = dir.join("transcript.jsonl");
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&jsonl_path)?;
        Ok(Self {
            jsonl_path,
            writer: BufWriter::new(file),
            current_hash: GENESIS_HASH.to_string(),
            finalized: None,
        })
    }

    /// Path to the JSONL file this sink is writing to.
    #[must_use]
    pub fn jsonl_path(&self) -> &Path {
        &self.jsonl_path
    }
}

impl TranscriptSink for JsonlFileSink {
    fn record(&mut self, fact: &StepFact) -> io::Result<()> {
        if self.finalized.is_some() {
            return Err(io::Error::other("transcript already finalized"));
        }
        let line = ChainedFact {
            prev_hash: &self.current_hash,
            fact,
        };
        let bytes = serde_json::to_vec(&line).map_err(io::Error::other)?;
        self.current_hash = compute_fingerprint(&bytes);
        self.writer.write_all(&bytes)?;
        self.writer.write_all(b"\n")?;
        // `flush` drains the BufWriter into the File; `sync_data` then
        // forces the kernel to push the page-cache pages to the storage
        // device before we return. Without the sync, a power loss between
        // `record` and the OS's next writeback would drop already-reported
        // facts even though the executor moved on. Cost at ceremony pace
        // (one record every few seconds of human pace) is negligible.
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<TranscriptFingerprint> {
        if let Some(existing) = &self.finalized {
            return Ok(existing.clone());
        }
        let fingerprint = TranscriptFingerprint(self.current_hash.clone());
        self.finalized = Some(fingerprint.clone());
        Ok(fingerprint)
    }
}

/// In-memory sink that collects every recorded [`StepFact`].
///
/// Useful for tests and for tooling that wants to inspect the fact stream
/// without going through disk.
#[derive(Debug, Default)]
pub struct InMemorySink {
    facts: Vec<StepFact>,
    current_hash: String,
    finalized: Option<TranscriptFingerprint>,
}

impl InMemorySink {
    /// Create an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            facts: Vec::new(),
            current_hash: GENESIS_HASH.to_string(),
            finalized: None,
        }
    }

    /// Recorded facts in the order they arrived.
    #[must_use]
    pub fn facts(&self) -> &[StepFact] {
        &self.facts
    }

    /// Number of facts recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether any fact has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

impl TranscriptSink for InMemorySink {
    fn record(&mut self, fact: &StepFact) -> io::Result<()> {
        if self.finalized.is_some() {
            return Err(io::Error::other("transcript already finalized"));
        }
        let line = ChainedFact {
            prev_hash: &self.current_hash,
            fact,
        };
        let bytes = serde_json::to_vec(&line).map_err(io::Error::other)?;
        self.current_hash = compute_fingerprint(&bytes);
        self.facts.push(fact.clone());
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<TranscriptFingerprint> {
        if let Some(existing) = &self.finalized {
            return Ok(existing.clone());
        }
        let fingerprint = TranscriptFingerprint(self.current_hash.clone());
        self.finalized = Some(fingerprint.clone());
        Ok(fingerprint)
    }
}

#[derive(Serialize)]
struct ChainedFact<'a> {
    prev_hash: &'a str,
    fact: &'a StepFact,
}

#[derive(Deserialize)]
struct OwnedChainedFact {
    prev_hash: String,
    fact: StepFact,
}

/// Outcome of verifying a transcript on disk.
#[derive(Debug, Clone)]
pub struct TranscriptVerified {
    /// Number of facts read and verified.
    pub fact_count: usize,
    /// Final transcript fingerprint (hash of the last line).
    pub fingerprint: TranscriptFingerprint,
    /// `true` if the last fact is a terminal one (`CeremonyCompleted` or
    /// `CeremonyFailed`). `false` means the transcript was cut off
    /// before the executor reached its finalize step, a truncated run.
    pub terminated: bool,
}

/// Verification failure modes.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Underlying I/O error reading the transcript.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A line did not parse as a [`ChainedFact`].
    #[error("line {line} is not a valid chained fact: {reason}")]
    InvalidLine {
        /// 1-indexed line number.
        line: usize,
        /// Parse error.
        reason: String,
    },
    /// The chain is broken: a line's `prev_hash` did not match the
    /// expected value computed from the previous line.
    #[error("broken chain at line {line}: expected prev_hash {expected}, got {actual}")]
    BrokenChain {
        /// 1-indexed line number where the break was detected.
        line: usize,
        /// The expected `prev_hash` (= hash of the previous line).
        expected: String,
        /// The `prev_hash` actually recorded on the line.
        actual: String,
    },
    /// The transcript file has zero lines.
    #[error("transcript is empty")]
    Empty,
    /// A value was drawn (or a contribution folded) before any
    /// `EntropySeeded` fact established the source.
    #[error("entropy source used before it was seeded")]
    SeedMissing,
    /// The seed fact declares a derivation scheme the verifier does not
    /// recognise. Never trust an unknown scheme (the JWT-`alg` lesson).
    #[error("unknown entropy derivation scheme: {0}")]
    UnknownDerivation(String),
    /// A recorded hex value (the seed `m` or a drawn value) did not decode.
    #[error("malformed entropy value: {0}")]
    MalformedEntropy(String),
    /// A drawn value does not match what re-derivation from the recorded
    /// seed and path produces: the source was tampered with.
    #[error("entropy draw at path '{path}' does not match re-derived value")]
    DrawMismatch {
        /// Derivation path of the mismatched draw.
        path: String,
    },
}

/// Verify a JSONL transcript file produced by [`JsonlFileSink`].
///
/// Reads the file line-by-line, recomputes each line's SHA-256, and
/// checks that `prev_hash` matches the previous line's hash.
///
/// # Errors
///
/// Returns [`VerifyError`] for any I/O failure, malformed line, or
/// chain break.
pub fn verify_transcript(jsonl_path: &Path) -> Result<TranscriptVerified, VerifyError> {
    let loaded = read_verified_transcript(jsonl_path)?;
    Ok(TranscriptVerified {
        fact_count: loaded.facts.len(),
        fingerprint: loaded.fingerprint,
        terminated: loaded.terminated,
    })
}

/// Verified transcript contents, chain-walked facts plus the final
/// fingerprint and a flag for whether the run reached a terminal fact.
#[derive(Debug, Clone)]
pub struct LoadedTranscript {
    /// Facts in the order they were recorded.
    pub facts: Vec<StepFact>,
    /// Final transcript fingerprint (hash of the last line).
    pub fingerprint: TranscriptFingerprint,
    /// `true` if the last fact is `CeremonyCompleted` or `CeremonyFailed`.
    pub terminated: bool,
}

/// Verify a JSONL transcript and return its facts.
///
/// Same chain check as [`verify_transcript`], plus returns the
/// deserialized [`StepFact`] stream and whether the last line is a
/// terminal fact.
///
/// # Errors
///
/// Same as [`verify_transcript`].
pub fn read_verified_transcript(jsonl_path: &Path) -> Result<LoadedTranscript, VerifyError> {
    let file = File::open(jsonl_path)?;
    let reader = BufReader::new(file);

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut last_hash = expected_prev.clone();
    let mut facts: Vec<StepFact> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line_no = idx.saturating_add(1);
        let parsed: OwnedChainedFact =
            serde_json::from_str(&line).map_err(|e| VerifyError::InvalidLine {
                line: line_no,
                reason: e.to_string(),
            })?;
        if parsed.prev_hash != expected_prev {
            return Err(VerifyError::BrokenChain {
                line: line_no,
                expected: expected_prev,
                actual: parsed.prev_hash,
            });
        }
        last_hash = compute_fingerprint(line.as_bytes());
        expected_prev.clone_from(&last_hash);
        facts.push(parsed.fact);
    }

    if facts.is_empty() {
        return Err(VerifyError::Empty);
    }

    let terminated = matches!(
        facts.last(),
        Some(StepFact::CeremonyCompleted { .. } | StepFact::CeremonyFailed { .. }),
    );

    Ok(LoadedTranscript {
        facts,
        fingerprint: TranscriptFingerprint(last_hash),
        terminated,
    })
}

/// Outcome of re-deriving a transcript's entropy source.
#[derive(Debug, Clone, Default)]
pub struct EntropyVerified {
    /// Derivation-scheme tag declared by the seed fact, if the ceremony used
    /// the source at all.
    pub derivation: Option<String>,
    /// Number of human contributions folded into the ratchet.
    pub contributions: usize,
    /// Number of drawn values that re-derived to their recorded value.
    pub values_verified: usize,
}

/// Re-derive a transcript's entropy source and confirm every drawn value.
///
/// Replays the `rite-kdf/v1` ratchet over the recorded facts: it rebuilds
/// `seed_0` from the recorded machine entropy, folds each human contribution
/// in chain order, and for every [`StepFact::EntropyDrawn`] re-derives the
/// value from the recorded path and checks it against the recorded value. A
/// tampered seed, contribution, path, or value fails the check.
///
/// The caller is expected to have chain-verified the facts first (via
/// [`read_verified_transcript`]); this function only re-derives.
///
/// # Errors
///
/// Returns a [`VerifyError`] variant describing the first inconsistency:
/// [`VerifyError::SeedMissing`], [`VerifyError::UnknownDerivation`],
/// [`VerifyError::MalformedEntropy`], or [`VerifyError::DrawMismatch`].
pub fn verify_entropy(facts: &[StepFact]) -> Result<EntropyVerified, VerifyError> {
    let mut seed: Option<[u8; 32]> = None;
    let mut result = EntropyVerified::default();

    for fact in facts {
        match fact {
            StepFact::EntropySeeded { m, derivation, .. } => {
                if derivation != crate::entropy::DERIVATION_V1 {
                    return Err(VerifyError::UnknownDerivation(derivation.clone()));
                }
                let m_bytes = base16ct::lower::decode_vec(m)
                    .map_err(|e| VerifyError::MalformedEntropy(format!("seed m: {e}")))?;
                seed = Some(crate::entropy::initial_seed(&m_bytes));
                result.derivation = Some(derivation.clone());
            }
            StepFact::EntropyContributed { contribution, .. } => {
                let current = seed.as_ref().ok_or(VerifyError::SeedMissing)?;
                seed = Some(crate::entropy::fold_seed(current, contribution.as_bytes()));
                result.contributions = result.contributions.saturating_add(1);
            }
            StepFact::EntropyDrawn { path, value, .. } => {
                let current = seed.as_ref().ok_or(VerifyError::SeedMissing)?;
                // The recorded value's own length fixes how many bytes to
                // re-derive; decoding it also rejects a malformed hex record.
                let recorded = base16ct::lower::decode_vec(value)
                    .map_err(|e| VerifyError::MalformedEntropy(format!("draw {path}: {e}")))?;
                let expected = crate::entropy::derive_value(current, path, recorded.len());
                if expected != recorded {
                    return Err(VerifyError::DrawMismatch { path: path.clone() });
                }
                result.values_verified = result.values_verified.saturating_add(1);
            }
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn sample_fact() -> StepFact {
        StepFact::CeremonyStarted {
            name: "Test".to_string(),
            started_at: Utc::now(),
        }
    }

    #[test]
    fn in_memory_sink_records_and_finalizes() {
        let mut sink = InMemorySink::new();
        assert!(sink.is_empty());
        sink.record(&sample_fact()).expect("record");
        assert_eq!(sink.len(), 1);
        let fp = sink.finalize().expect("finalize");
        assert!(fp.as_str().starts_with("sha256:"));
    }

    #[test]
    fn in_memory_sink_rejects_record_after_finalize() {
        let mut sink = InMemorySink::new();
        sink.record(&sample_fact()).expect("record");
        sink.finalize().expect("finalize");
        let err = sink.record(&sample_fact()).expect_err("should fail");
        assert!(err.to_string().contains("already finalized"));
    }

    #[test]
    fn in_memory_sink_chain_advances() {
        let mut sink = InMemorySink::new();
        let initial = sink.current_hash.clone();
        sink.record(&sample_fact()).expect("record");
        assert_ne!(sink.current_hash, initial);
        let after_first = sink.current_hash.clone();
        sink.record(&sample_fact()).expect("record");
        assert_ne!(sink.current_hash, after_first);
    }

    #[test]
    fn jsonl_file_sink_writes_and_chains() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = JsonlFileSink::create(tmp.path()).expect("create");
        sink.record(&sample_fact()).expect("record");
        sink.record(&sample_fact()).expect("record");
        let fp = sink.finalize().expect("finalize");

        let jsonl = std::fs::read_to_string(sink.jsonl_path()).expect("read jsonl");
        let mut lines = jsonl.lines();
        let raw_first = lines.next().expect("first line");
        let raw_second = lines.next().expect("second line");
        assert!(lines.next().is_none(), "expected exactly two lines");

        let first: serde_json::Value = serde_json::from_str(raw_first).expect("parse first");
        let second: serde_json::Value = serde_json::from_str(raw_second).expect("parse second");
        assert_eq!(
            first.get("prev_hash").and_then(serde_json::Value::as_str),
            Some(GENESIS_HASH),
        );
        let first_hash = compute_fingerprint(raw_first.as_bytes());
        assert_eq!(
            second.get("prev_hash").and_then(serde_json::Value::as_str),
            Some(first_hash.as_str()),
        );
        let second_hash = compute_fingerprint(raw_second.as_bytes());
        assert_eq!(fp.as_str(), second_hash);
    }

    #[test]
    fn jsonl_file_sink_refuses_existing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _first = JsonlFileSink::create(tmp.path()).expect("first");
        let err = JsonlFileSink::create(tmp.path()).expect_err("second should fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn verify_round_trip_succeeds_on_well_formed_transcript() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = JsonlFileSink::create(tmp.path()).expect("create");
        sink.record(&sample_fact()).expect("record");
        sink.record(&sample_fact()).expect("record");
        sink.record(&sample_fact()).expect("record");
        let written = sink.finalize().expect("finalize");

        let verified = verify_transcript(sink.jsonl_path()).expect("verify");
        assert_eq!(verified.fact_count, 3);
        assert_eq!(verified.fingerprint, written);
        // Sample fact isn't a terminal one; the transcript is open-ended.
        assert!(!verified.terminated);
    }

    #[test]
    fn verify_detects_chain_break() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = JsonlFileSink::create(tmp.path()).expect("create");
        sink.record(&sample_fact()).expect("record");
        sink.record(&sample_fact()).expect("record");
        let _ = sink.finalize().expect("finalize");

        let path = sink.jsonl_path().to_path_buf();
        let content = std::fs::read_to_string(&path).expect("read");
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        if let Some(second) = lines.get_mut(1) {
            *second = second.replace("prev_hash\":\"sha256:", "prev_hash\":\"sha256:ff");
        }
        std::fs::write(&path, lines.join("\n") + "\n").expect("write");

        let err = verify_transcript(&path).expect_err("should detect tamper");
        assert!(matches!(err, VerifyError::BrokenChain { .. }));
    }

    #[test]
    fn verify_empty_transcript_returns_empty_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("transcript.jsonl");
        std::fs::write(&path, "").expect("write empty");
        let err = verify_transcript(&path).expect_err("empty");
        assert!(matches!(err, VerifyError::Empty));
    }

    use rite_model::StepId;

    fn seeded_fact(m: &[u8]) -> StepFact {
        StepFact::EntropySeeded {
            m: base16ct::lower::encode_string(m),
            source: "os".to_string(),
            derivation: crate::entropy::DERIVATION_V1.to_string(),
        }
    }

    fn drawn_fact(seed: &[u8; 32], step: &str, path: &str, len: usize) -> StepFact {
        StepFact::EntropyDrawn {
            step: StepId::new(step),
            path: path.to_string(),
            value: base16ct::lower::encode_string(&crate::entropy::derive_value(seed, path, len)),
        }
    }

    #[test]
    fn verify_entropy_re_derives_a_clean_draw() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = vec![
            seeded_fact(m),
            drawn_fact(&seed, "issue", "0/issue/cert-serial", 9),
        ];
        let v = verify_entropy(&facts).expect("verify");
        assert_eq!(v.values_verified, 1);
        assert_eq!(v.contributions, 0);
        assert_eq!(v.derivation.as_deref(), Some("rite-kdf/v1"));
    }

    #[test]
    fn verify_entropy_follows_the_ratchet_through_a_contribution() {
        let m = b"machine entropy bytes";
        let seed0 = crate::entropy::initial_seed(m);
        let seed1 = crate::entropy::fold_seed(&seed0, b"3 1 6 4 2 5");
        let facts = vec![
            seeded_fact(m),
            StepFact::EntropyContributed {
                step: StepId::new("roll"),
                epoch: 1,
                contribution: "3 1 6 4 2 5".to_string(),
            },
            // Drawn after the fold, so it must derive from the epoch-1 seed.
            drawn_fact(&seed1, "issue", "1/issue/cert-serial", 9),
        ];
        let v = verify_entropy(&facts).expect("verify");
        assert_eq!(v.contributions, 1);
        assert_eq!(v.values_verified, 1);
    }

    #[test]
    fn verify_entropy_detects_a_tampered_value() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let mut drawn = drawn_fact(&seed, "issue", "0/issue/cert-serial", 9);
        if let StepFact::EntropyDrawn { value, .. } = &mut drawn {
            *value = "deadbeefdeadbeefdead".to_string();
        }
        let facts = vec![seeded_fact(m), drawn];
        let err = verify_entropy(&facts).expect_err("tamper");
        assert!(matches!(err, VerifyError::DrawMismatch { .. }));
    }

    #[test]
    fn verify_entropy_rejects_unknown_derivation() {
        let facts = vec![StepFact::EntropySeeded {
            m: "00".to_string(),
            source: "os".to_string(),
            derivation: "rite-kdf/v99".to_string(),
        }];
        let err = verify_entropy(&facts).expect_err("unknown scheme");
        assert!(matches!(err, VerifyError::UnknownDerivation(_)));
    }

    #[test]
    fn verify_entropy_rejects_draw_before_seed() {
        let seed = crate::entropy::initial_seed(b"x");
        let facts = vec![drawn_fact(&seed, "issue", "0/issue/cert-serial", 9)];
        let err = verify_entropy(&facts).expect_err("unseeded");
        assert!(matches!(err, VerifyError::SeedMissing));
    }
}
