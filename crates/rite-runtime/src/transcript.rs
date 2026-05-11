//! Ceremony transcript writing and verification.
//!
//! Transcript **types** (events, metadata, results) are defined in
//! `rite_model::transcript` and re-exported here for convenience. This module
//! adds the write side (traits and implementations) and the read/verify functions.

use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::Path;

use rite_model::StepId;

use crate::executor::StepOutcome;

pub use rite_model::transcript::{
    ArtifactVerification, BinaryInfo, CeremonyInfo, ChainedEvent, EventData, EventOutcome,
    GENESIS_HASH, ImageManifest, InitrdMeasurements, InstanceInfo, ParsedTranscript,
    ParticipantRecord, StepEvidence, TRANSCRIPT_SCHEMA_VERSION, TranscriptStatus,
    VerificationResult,
};

/// An internal pre-serialization execution event.
///
/// Intermediate representation used by the executor to build transcript entries
/// before they are recorded via [`TranscriptWriter::record_event`].
#[derive(Debug, Clone)]
pub struct ExecutionEvent {
    /// Step identifier.
    pub step_id: String,
    /// Action type executed.
    pub action: rite_model::ActionType,
    /// Role performing the step (if any).
    pub role: Option<String>,
    /// When the step started.
    pub started_at: chrono::DateTime<Utc>,
    /// When the step completed.
    pub completed_at: chrono::DateTime<Utc>,
    /// Step outcome.
    pub outcome: EventOutcome,
    /// Action-specific evidence.
    pub evidence: StepEvidence,
}

/// Convert a [`StepOutcome`] into a transcript [`EventOutcome`].
pub(crate) fn step_outcome_to_event_outcome(outcome: &StepOutcome) -> EventOutcome {
    match outcome {
        StepOutcome::Completed { message } => EventOutcome {
            status: "completed".to_string(),
            message: Some(message.clone()),
        },
        StepOutcome::Skipped { reason } => EventOutcome {
            status: "skipped".to_string(),
            message: Some(reason.clone()),
        },
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 fingerprint of a byte slice.
///
/// Returns `"sha256:{lowercase_hex}"`.
pub fn compute_fingerprint(data: &[u8]) -> String {
    let hash = sha256_bytes(data);
    format!("sha256:{}", base16ct::lower::encode_string(&hash))
}

/// Compute SHA-256 fingerprint of a file.
pub fn compute_file_fingerprint(path: &Path) -> io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(compute_fingerprint(&data))
}

/// Compute hash chain link using standard construction: H(H(prev) || H(data)).
fn compute_chain_hash(prev: &[u8], data: &[u8]) -> String {
    let prev_hash = sha256_bytes(prev);
    let data_hash = sha256_bytes(data);
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&prev_hash);
    combined[32..].copy_from_slice(&data_hash);
    compute_fingerprint(&combined)
}

fn compute_event_hash(prev: &str, data: &EventData) -> String {
    // EventData is always serializable: composed of primitive types, strings, and
    // Serialize-derived structs. A failure here indicates a programming error.
    #[allow(clippy::expect_used)]
    let data_json = serde_json::to_string(data).expect("Event serialization failed");
    compute_chain_hash(prev.as_bytes(), data_json.as_bytes())
}

fn new_chained_event(prev: String, data: EventData) -> ChainedEvent {
    let hash = compute_event_hash(&prev, &data);
    ChainedEvent { prev, data, hash }
}

#[cfg(test)]
fn verify_chained_event_hash(event: &ChainedEvent) -> bool {
    let computed = compute_event_hash(&event.prev, &event.data);
    computed == event.hash
}

/// Trait for writing ceremony transcripts.
///
/// Implementations handle streaming writes for crash recovery.
pub trait TranscriptWriter: Send {
    /// Initialize the transcript with ceremony context.
    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        ceremony: CeremonyInfo,
        instance: Option<InstanceInfo>,
        binary: BinaryInfo,
        image: Option<ImageManifest>,
        initrd: Option<InitrdMeasurements>,
        environment: Option<HashMap<String, String>>,
        participants: Vec<ParticipantRecord>,
        dry_run: bool,
    ) -> io::Result<()>;

    /// Record a step execution event.
    fn record_event(&mut self, event: ExecutionEvent) -> io::Result<()>;

    /// Finalize the transcript with completion status.
    ///
    /// Returns the final fingerprint.
    fn finalize(&mut self, status: TranscriptStatus) -> io::Result<String>;

    /// Mark the transcript as interrupted (for crash recovery).
    fn mark_interrupted(&mut self) -> io::Result<()>;

    /// Record a deviation from expected procedure.
    fn record_deviation(&mut self, reason: &str, step_id: Option<&StepId>) -> io::Result<()>;

    /// Record an artifact file being written.
    fn record_artifact(
        &mut self,
        source: &str,
        path: &Path,
        hash: String,
        size: u64,
        mime: Option<String>,
    ) -> io::Result<()>;
}

/// JSONL transcript writer with hash-chained events.
pub struct JsonlTranscriptWriter {
    writer: BufWriter<File>,
    path: std::path::PathBuf,
    last_hash: String,
}

impl JsonlTranscriptWriter {
    /// Create a new JSONL transcript writer.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            writer: BufWriter::new(file),
            path,
            last_hash: GENESIS_HASH.to_string(),
        })
    }

    /// Get the path to the transcript file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_event(&mut self, event: &ChainedEvent) -> io::Result<()> {
        let json = serde_json::to_string(event).map_err(io::Error::other)?;
        writeln!(self.writer, "{json}")?;
        self.writer.flush()?;
        self.last_hash.clone_from(&event.hash);
        Ok(())
    }

    fn append(&mut self, data: EventData) -> io::Result<()> {
        let event = new_chained_event(self.last_hash.clone(), data);
        self.write_event(&event)
    }
}

impl TranscriptWriter for JsonlTranscriptWriter {
    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        ceremony: CeremonyInfo,
        instance: Option<InstanceInfo>,
        binary: BinaryInfo,
        image: Option<ImageManifest>,
        initrd: Option<InitrdMeasurements>,
        environment: Option<HashMap<String, String>>,
        participants: Vec<ParticipantRecord>,
        dry_run: bool,
    ) -> io::Result<()> {
        self.append(EventData::CeremonyStart {
            schema_version: TRANSCRIPT_SCHEMA_VERSION.to_string(),
            dry_run,
            ceremony,
            instance,
            binary,
            image,
            initrd,
            environment,
            participants,
            started_at: Utc::now(),
        })
    }

    fn record_event(&mut self, event: ExecutionEvent) -> io::Result<()> {
        self.append(EventData::Step {
            step_id: event.step_id,
            action: event.action,
            role: event.role,
            started_at: event.started_at,
            completed_at: event.completed_at,
            outcome: event.outcome,
            evidence: event.evidence,
        })
    }

    fn finalize(&mut self, status: TranscriptStatus) -> io::Result<String> {
        self.append(EventData::CeremonyComplete {
            completed_at: Utc::now(),
            status,
        })?;
        Ok(self.last_hash.clone())
    }

    fn mark_interrupted(&mut self) -> io::Result<()> {
        self.append(EventData::CeremonyComplete {
            completed_at: Utc::now(),
            status: TranscriptStatus::Interrupted,
        })
    }

    fn record_deviation(&mut self, reason: &str, step_id: Option<&StepId>) -> io::Result<()> {
        self.append(EventData::Deviation {
            reason: reason.to_string(),
            step_id: step_id.map(|id| id.as_str().to_string()),
            recorded_at: Utc::now(),
        })
    }

    fn record_artifact(
        &mut self,
        source: &str,
        path: &Path,
        hash: String,
        size: u64,
        mime: Option<String>,
    ) -> io::Result<()> {
        // Store path relative to the transcript file's directory so verification
        // works regardless of where `rite verify` is invoked from.
        let transcript_dir = self
            .path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let relative_path = path.strip_prefix(transcript_dir).unwrap_or(path);
        let path_str = relative_path
            .to_str()
            .ok_or_else(|| io::Error::other("Invalid UTF-8 in path"))?
            .to_string();

        self.append(EventData::ArtifactProduce {
            source: source.to_string(),
            path: path_str,
            hash,
            size,
            mime,
        })
    }
}

/// A no-op transcript writer that discards all events.
pub struct NullTranscriptWriter;

impl TranscriptWriter for NullTranscriptWriter {
    #[allow(clippy::too_many_arguments)]
    fn begin(
        &mut self,
        _ceremony: CeremonyInfo,
        _instance: Option<InstanceInfo>,
        _binary: BinaryInfo,
        _image: Option<ImageManifest>,
        _initrd: Option<InitrdMeasurements>,
        _environment: Option<HashMap<String, String>>,
        _participants: Vec<ParticipantRecord>,
        _dry_run: bool,
    ) -> io::Result<()> {
        Ok(())
    }

    fn record_event(&mut self, _event: ExecutionEvent) -> io::Result<()> {
        Ok(())
    }

    fn finalize(&mut self, _status: TranscriptStatus) -> io::Result<String> {
        Ok("(transcript disabled)".to_string())
    }

    fn mark_interrupted(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn record_deviation(&mut self, _reason: &str, _step_id: Option<&StepId>) -> io::Result<()> {
        Ok(())
    }

    fn record_artifact(
        &mut self,
        _source: &str,
        _path: &Path,
        _hash: String,
        _size: u64,
        _mime: Option<String>,
    ) -> io::Result<()> {
        Ok(())
    }
}

/// Verify a JSONL transcript file's integrity.
pub fn verify_transcript(path: &Path) -> io::Result<VerificationResult> {
    verify_jsonl_transcript(path)
}

/// Helper to deserialize only `prev` and raw `data` bytes for hash verification.
///
/// Re-serializing `EventData` could reorder fields or change formatting, producing
/// different bytes and breaking hash checks on valid transcripts.
#[derive(Deserialize)]
struct RawChainedEvent<'a> {
    prev: String,
    #[serde(borrow)]
    data: &'a serde_json::value::RawValue,
    #[allow(dead_code)]
    hash: String,
}

fn verify_event_hash_from_json(json_line: &str) -> Result<String, String> {
    let raw: RawChainedEvent =
        serde_json::from_str(json_line).map_err(|e| format!("JSON parse error: {e}"))?;
    Ok(compute_chain_hash(
        raw.prev.as_bytes(),
        raw.data.get().as_bytes(),
    ))
}

#[allow(clippy::too_many_lines)]
fn verify_jsonl_transcript(path: &Path) -> io::Result<VerificationResult> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut events: Vec<ChainedEvent> = Vec::new();
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut dry_run = false;
    let mut image: Option<ImageManifest> = None;
    let mut initrd: Option<InitrdMeasurements> = None;
    let mut tpm_nonce: Option<String> = None;
    let mut tpm_pcrs: BTreeMap<String, String> = BTreeMap::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line_num = line_num.saturating_add(1);
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let event: ChainedEvent = serde_json::from_str(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;

        if event.prev != prev_hash {
            return Ok(VerificationResult::Invalid {
                expected: prev_hash,
                computed: event.prev.clone(),
            });
        }

        let computed_hash = verify_event_hash_from_json(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;

        if event.hash != computed_hash {
            return Ok(VerificationResult::Invalid {
                expected: event.hash.clone(),
                computed: computed_hash,
            });
        }

        if let EventData::CeremonyStart {
            dry_run: is_dry_run,
            image: img,
            initrd: imd,
            ..
        } = &event.data
        {
            dry_run = *is_dry_run;
            image.clone_from(img);
            initrd.clone_from(imd);
        }

        if tpm_nonce.is_none()
            && let EventData::Step {
                action: rite_model::ActionType::TpmAttest,
                evidence: ev,
                ..
            } = &event.data
        {
            tpm_nonce = ev
                .data
                .get("nonce")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            if let Some(pcrs_val) = ev.data.get("pcrs") {
                tpm_pcrs = serde_json::from_value(pcrs_val.clone()).unwrap_or_default();
            }
        }

        prev_hash.clone_from(&event.hash);
        events.push(event);
    }

    if events.is_empty() {
        return Ok(VerificationResult::Incomplete {
            status: TranscriptStatus::InProgress,
            events_count: 0,
        });
    }

    let artifacts = verify_artifacts(path, &events);

    match events.last().map(|e| &e.data) {
        Some(EventData::CeremonyComplete { status, .. }) => Ok(VerificationResult::Valid {
            fingerprint: prev_hash,
            status: status.clone(),
            dry_run,
            artifacts,
            image,
            initrd,
            tpm_nonce,
            tpm_pcrs,
        }),
        _ => Ok(VerificationResult::Incomplete {
            status: TranscriptStatus::InProgress,
            events_count: events.len(),
        }),
    }
}

fn verify_artifacts(transcript_path: &Path, events: &[ChainedEvent]) -> Vec<ArtifactVerification> {
    let base_dir = transcript_path.parent().unwrap_or_else(|| Path::new("."));

    events
        .iter()
        .filter_map(|event| {
            if let EventData::ArtifactProduce {
                source,
                path: artifact_path,
                hash: expected_hash,
                ..
            } = &event.data
            {
                let full_path = base_dir.join(artifact_path);
                let verification = match compute_file_fingerprint(&full_path) {
                    Ok(computed_hash) if &computed_hash == expected_hash => ArtifactVerification {
                        source: source.clone(),
                        path: artifact_path.clone(),
                        expected_hash: expected_hash.clone(),
                        verified: true,
                        error: None,
                    },
                    Ok(computed_hash) => ArtifactVerification {
                        source: source.clone(),
                        path: artifact_path.clone(),
                        expected_hash: expected_hash.clone(),
                        verified: false,
                        error: Some(format!(
                            "Hash mismatch (expected: {expected_hash}, computed: {computed_hash})"
                        )),
                    },
                    Err(e) => ArtifactVerification {
                        source: source.clone(),
                        path: artifact_path.clone(),
                        expected_hash: expected_hash.clone(),
                        verified: false,
                        error: Some(format!("Failed to read file: {e}")),
                    },
                };
                Some(verification)
            } else {
                None
            }
        })
        .collect()
}

/// Read, verify, and return all events from a JSONL transcript.
///
/// Returns an error if the file is malformed, tampered, or incomplete.
pub fn read_transcript(path: &Path) -> io::Result<ParsedTranscript> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut events: Vec<ChainedEvent> = Vec::new();
    let mut prev_hash = GENESIS_HASH.to_string();
    let mut dry_run = false;

    for (line_num, line) in reader.lines().enumerate() {
        let line_num = line_num.saturating_add(1);
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let event: ChainedEvent = serde_json::from_str(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;

        if event.prev != prev_hash {
            return Err(io::Error::other(format!(
                "Line {line_num}: hash chain broken (expected prev={prev_hash}, got prev={})",
                event.prev
            )));
        }

        let computed_hash = verify_event_hash_from_json(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;
        if event.hash != computed_hash {
            return Err(io::Error::other(format!(
                "Line {line_num}: event hash mismatch (expected={}, computed={computed_hash})",
                event.hash
            )));
        }

        if let EventData::CeremonyStart {
            dry_run: is_dry_run,
            ..
        } = &event.data
        {
            dry_run = *is_dry_run;
        }

        prev_hash.clone_from(&event.hash);
        events.push(event);
    }

    if events.is_empty() {
        return Err(io::Error::other("Transcript is empty"));
    }

    let status = match events.last().map(|e| &e.data) {
        Some(EventData::CeremonyComplete { status, .. }) => status.clone(),
        _ => {
            return Err(io::Error::other(
                "Transcript is incomplete (no CeremonyComplete event)",
            ));
        }
    };

    let artifact_results = verify_artifacts(path, &events);
    let failed: Vec<_> = artifact_results.iter().filter(|a| !a.verified).collect();
    if !failed.is_empty() {
        let paths: Vec<&str> = failed.iter().map(|a| a.path.as_str()).collect();
        return Err(io::Error::other(format!(
            "Artifact verification failed: {}",
            paths.join(", ")
        )));
    }

    Ok(ParsedTranscript {
        events,
        fingerprint: prev_hash,
        dry_run,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::ActionType;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    #[test]
    fn test_fingerprint_computation() {
        let fingerprint = compute_fingerprint(b"hello world");
        assert!(fingerprint.starts_with("sha256:"));
        assert!(
            fingerprint
                .contains("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );
    }

    #[test]
    fn test_step_evidence() {
        let evidence = StepEvidence::new()
            .with("algorithm", "ed25519")
            .with("key_fingerprint", "sha256:abc123");
        assert_eq!(
            evidence.data.get("algorithm"),
            Some(&serde_json::json!("ed25519"))
        );
    }

    #[test]
    fn test_jsonl_transcript_writer() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("test-transcript.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:ceremony123".to_string(),
                name: "Test Ceremony".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: Some("sha256:binary456".to_string()),
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;

        writer.record_event(ExecutionEvent {
            step_id: "step1".to_string(),
            action: ActionType::Confirm,
            role: None,
            started_at: Utc::now(),
            completed_at: Utc::now(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("All present".to_string()),
            },
            evidence: StepEvidence::new().with("roles_confirmed", vec!["operator", "witness"]),
        })?;

        let fingerprint = writer.finalize(TranscriptStatus::Completed)?;
        assert!(fingerprint.starts_with("sha256:"));

        let result = verify_transcript(&path)?;
        assert!(matches!(result, VerificationResult::Valid { .. }));

        let content = std::fs::read_to_string(&path)?;
        assert!(
            content.lines().count() >= 2,
            "JSONL should have multiple lines"
        );

        Ok(())
    }

    #[test]
    fn test_jsonl_hash_chain() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("hash-chain-test.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:test".to_string(),
                name: "Hash Chain Test".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;

        for i in 1..=3 {
            writer.record_event(ExecutionEvent {
                step_id: format!("step{i}"),
                action: ActionType::Confirm,
                role: None,
                started_at: Utc::now(),
                completed_at: Utc::now(),
                outcome: EventOutcome {
                    status: "completed".to_string(),
                    message: Some(format!("Step {i} done")),
                },
                evidence: StepEvidence::new(),
            })?;
        }
        writer.finalize(TranscriptStatus::Completed)?;

        let file = File::open(&path)?;
        let reader = io::BufReader::new(file);
        let mut prev_hash = GENESIS_HASH.to_string();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: ChainedEvent = serde_json::from_str(&line)?;
            assert_eq!(event.prev, prev_hash, "Hash chain broken");
            assert!(
                verify_chained_event_hash(&event),
                "Event hash verification failed"
            );
            prev_hash = event.hash;
        }

        Ok(())
    }

    #[test]
    fn test_jsonl_tamper_detection() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("tampered-jsonl.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:abc".to_string(),
                name: "Test".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;
        writer.finalize(TranscriptStatus::Completed)?;

        let mut content = std::fs::read_to_string(&path)?;
        content = content.replace("Test", "Tampered");
        std::fs::write(&path, content)?;

        let result = verify_transcript(&path)?;
        assert!(matches!(result, VerificationResult::Invalid { .. }));
        Ok(())
    }

    #[test]
    fn test_dry_run_verification() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("dry-run-transcript.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:abc".to_string(),
                name: "Dry Run Test".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            true,
        )?;
        writer.finalize(TranscriptStatus::Completed)?;

        match verify_transcript(&path)? {
            VerificationResult::Valid { dry_run, .. } => {
                assert!(dry_run, "Expected dry_run to be true");
            }
            _ => panic!("Expected Valid result"),
        }
        Ok(())
    }

    #[test]
    fn test_read_transcript_success() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("read-test.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:abc".to_string(),
                name: "Read Test".to_string(),
            },
            Some(InstanceInfo {
                fingerprint: "sha256:inst".to_string(),
                parameters: BTreeMap::from([("key".to_string(), serde_json::json!("value"))]),
                materials: BTreeMap::new(),
            }),
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;
        writer.record_event(ExecutionEvent {
            step_id: "step1".to_string(),
            action: ActionType::Confirm,
            role: Some("operator".to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("Done".to_string()),
            },
            evidence: StepEvidence::new(),
        })?;
        writer.finalize(TranscriptStatus::Completed)?;

        let parsed = read_transcript(&path)?;
        assert_eq!(parsed.events.len(), 3); // start + step + complete
        assert_eq!(parsed.status, TranscriptStatus::Completed);
        assert!(!parsed.dry_run);
        assert!(parsed.fingerprint.starts_with("sha256:"));
        Ok(())
    }

    #[test]
    fn test_read_transcript_tampered() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("tampered-read.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:abc".to_string(),
                name: "Test".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;
        writer.finalize(TranscriptStatus::Completed)?;

        let mut content = std::fs::read_to_string(&path)?;
        content = content.replace("Test", "Tampered");
        std::fs::write(&path, content)?;

        assert!(read_transcript(&path).is_err());
        Ok(())
    }

    #[test]
    fn test_read_transcript_incomplete() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("incomplete-read.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint: "sha256:abc".to_string(),
                name: "Test".to_string(),
            },
            None,
            BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            None,
            None,
            None,
            vec![],
            false,
        )?;
        // Don't call finalize: transcript is incomplete
        assert!(read_transcript(&path).is_err());
        Ok(())
    }

    /// Verify a fully-populated ceremony transcript round-trips through write → verify.
    ///
    /// Covers all optional fields that have historically caused "missing field" errors
    /// when a struct was changed without a corresponding `#[serde(default)]`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_verify_fully_populated_transcript() -> io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("full-transcript.jsonl");

        let mut writer = JsonlTranscriptWriter::new(&path)?;
        writer.begin(
            CeremonyInfo {
                fingerprint:
                    "sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                        .to_string(),
                name: "Root CA Key Generation".to_string(),
            },
            Some(InstanceInfo {
                fingerprint:
                    "sha256:inst234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
                        .to_string(),
                parameters: BTreeMap::from([
                    ("ceremony_date".to_string(), serde_json::json!("2026-03-28")),
                    ("key_label".to_string(), serde_json::json!("ROOT-CA-PROD")),
                ]),
                materials: BTreeMap::from([(
                    "transport_pubkey".to_string(),
                    "sha256:897fc6eb64792722d78047f621a8cb9e7d2bb068f6d49b4150c2f28427fb5cd9"
                        .to_string(),
                )]),
            }),
            BinaryInfo {
                fingerprint: Some(
                    "sha256:cb1653096e691015d578db708a6bfd07439a9d7e76ceecff1ed89a0d38e7df61"
                        .to_string(),
                ),
                version: "0.1.0-rc.6".to_string(),
            },
            None,
            None,
            None,
            vec![
                ParticipantRecord {
                    role_id: "crypto_officer".to_string(),
                    role_name: "Crypto Officer".to_string(),
                    person: Some("Alice Smith".to_string()),
                },
                ParticipantRecord {
                    role_id: "witness__1".to_string(),
                    role_name: "Witness 1".to_string(),
                    person: Some("Bob Jones".to_string()),
                },
                ParticipantRecord {
                    role_id: "witness__2".to_string(),
                    role_name: "Witness 2".to_string(),
                    person: Some("Carol White".to_string()),
                },
            ],
            false,
        )?;

        writer.record_event(ExecutionEvent {
            step_id: "generate_root_ca".to_string(),
            action: ActionType::GenerateKeypair,
            role: Some("crypto_officer".to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("RSA-4096 keypair generated".to_string()),
            },
            evidence: StepEvidence::new()
                .with("algorithm", "RSA-4096")
                .with("backend", "openssl")
                .with("key_id", "key-generate_root_ca")
                .with(
                    "public_key_fingerprint",
                    "sha256:def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                ),
        })?;

        writer.record_event(ExecutionEvent {
            step_id: "witness1_attest".to_string(),
            action: ActionType::Attest,
            role: Some("witness__1".to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("I witnessed the key generation.".to_string()),
            },
            evidence: StepEvidence::new().with(
                "statement",
                "I witnessed the key generation and confirm the fingerprint.",
            ),
        })?;

        writer.finalize(TranscriptStatus::Completed)?;

        match verify_transcript(&path)? {
            VerificationResult::Valid {
                status,
                dry_run,
                artifacts,
                ..
            } => {
                assert_eq!(status, TranscriptStatus::Completed);
                assert!(!dry_run);
                assert!(artifacts.is_empty());
            }
            other => panic!("Expected Valid, got: {other:?}"),
        }

        Ok(())
    }

    /// Deserialize a `ChainedEvent` from a real ceremony transcript JSON line.
    ///
    /// Guards against struct changes that would break reading existing transcripts:
    /// if a required field is added or renamed without a migration, this test catches it
    /// before the format ships.
    #[test]
    fn test_deserialize_real_ceremony_start() {
        // JSON captured from an actual `rite run` of the root CA software ceremony.
        // Manually update this fixture when the transcript format changes intentionally.
        let json = r#"{"prev":"sha256:0000000000000000000000000000000000000000000000000000000000000000","data":{"type":"ceremony_start","schema_version":"0.1","ceremony":{"fingerprint":"sha256:6196d5c6451e1a4f61fada4ec588ea4544e849734e2e04058fc07d7aa5bb4e4d","name":"Root CA Key Generation (Software)"},"instance":{"fingerprint":"sha256:040d40115c9dcc9ad3f70a26e49817f144c9370b6c9ccd4fc908e367939b2069","parameters":{"ceremony_date":"2026-03-28"},"materials":{"transport_pubkey":"sha256:897fc6eb64792722d78047f621a8cb9e7d2bb068f6d49b4150c2f28427fb5cd9"}},"binary":{"fingerprint":"sha256:cb1653096e691015d578db708a6bfd07439a9d7e76ceecff1ed89a0d38e7df61","version":"0.1.0-rc.6"},"participants":[{"role_id":"crypto_officer","role_name":"Crypto Officer","person":"Alice Smith"},{"role_id":"witness__1","role_name":"Witness 1","person":"Bob Jones"},{"role_id":"witness__2","role_name":"Witness 2","person":"Carol White"}],"started_at":"2026-05-11T19:38:40.499354Z"},"hash":"sha256:ebbd63d6339b45ccd1924ce9b709e03979f7e595d8586820f2c3199640206b59"}"#;

        let event: ChainedEvent =
            serde_json::from_str(json).expect("Failed to deserialize CeremonyStart event");

        assert_eq!(event.prev, GENESIS_HASH);
        assert_eq!(
            event.hash,
            "sha256:ebbd63d6339b45ccd1924ce9b709e03979f7e595d8586820f2c3199640206b59"
        );

        match &event.data {
            EventData::CeremonyStart {
                schema_version,
                binary,
                participants,
                ..
            } => {
                assert_eq!(schema_version, "0.1");
                assert_eq!(binary.version, "0.1.0-rc.6");
                assert_eq!(participants.len(), 3);
                assert_eq!(
                    participants.first().map(|p| p.role_id.as_str()),
                    Some("crypto_officer")
                );
            }
            other => panic!("Expected CeremonyStart, got: {other:?}"),
        }
    }

    /// Generate the deterministic test fixture at examples/test-fixtures/sample-transcript.jsonl.
    ///
    /// Run with: cargo test -p rite-runtime `generate_sample_transcript` -- --ignored
    #[test]
    #[ignore = "manual fixture regeneration; run explicitly when sample transcript format changes"]
    #[allow(clippy::too_many_lines)]
    fn generate_sample_transcript() -> io::Result<()> {
        use chrono::TimeZone;

        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/test-fixtures");
        std::fs::create_dir_all(&fixture_dir)?;
        let path = fixture_dir.join("sample-transcript.jsonl");

        let mut prev = GENESIS_HASH.to_string();
        let mut events: Vec<ChainedEvent> = Vec::new();

        let mut push = |data: EventData| {
            let event = new_chained_event(prev.clone(), data);
            prev.clone_from(&event.hash);
            events.push(event);
        };

        push(EventData::CeremonyStart {
            schema_version: TRANSCRIPT_SCHEMA_VERSION.to_string(),
            dry_run: false,
            ceremony: CeremonyInfo {
                fingerprint:
                    "sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                        .to_string(),
                name: "Sub-CA Key Ceremony".to_string(),
            },
            instance: Some(InstanceInfo {
                fingerprint:
                    "sha256:inst234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                        .to_string(),
                parameters: BTreeMap::from([
                    ("ceremony_date".to_string(), serde_json::json!("2025-06-15")),
                    ("key_label".to_string(), serde_json::json!("SUB-CA-PROD")),
                ]),
                materials: BTreeMap::new(),
            }),
            binary: BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            image: None,
            initrd: None,
            environment: None,
            participants: vec![
                ParticipantRecord {
                    role_id: "crypto_officer".to_string(),
                    role_name: "Crypto Officer".to_string(),
                    person: Some("Alice Smith".to_string()),
                },
                ParticipantRecord {
                    role_id: "witness".to_string(),
                    role_name: "Witness".to_string(),
                    person: Some("Bob Jones".to_string()),
                },
            ],
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 0).unwrap(),
        });

        push(EventData::Step {
            step_id: "step_1".to_string(),
            action: ActionType::Confirm,
            role: Some("operator".to_string()),
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 10).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 0, 20).unwrap(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("All participants present".to_string()),
            },
            evidence: StepEvidence::new(),
        });

        push(EventData::Step {
            step_id: "step_2".to_string(),
            action: ActionType::GenerateKeypair,
            role: Some("crypto_officer".to_string()),
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 1, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 1, 5).unwrap(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("RSA-4096 keypair generated".to_string()),
            },
            evidence: StepEvidence::new(),
        });

        push(EventData::Step {
            step_id: "step_3".to_string(),
            action: ActionType::Confirm,
            role: Some("witness".to_string()),
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 2, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 2, 2).unwrap(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("Key fingerprint confirmed".to_string()),
            },
            evidence: StepEvidence::new(),
        });

        push(EventData::Deviation {
            reason: "Witness requested re-verification of key fingerprint".to_string(),
            step_id: Some("step_3".to_string()),
            recorded_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 2, 30).unwrap(),
        });

        push(EventData::Step {
            step_id: "step_4".to_string(),
            action: ActionType::ExportPublic,
            role: Some("crypto_officer".to_string()),
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 3, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 3, 1).unwrap(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("Public key exported".to_string()),
            },
            evidence: StepEvidence::new(),
        });

        push(EventData::ArtifactProduce {
            source: "step_4".to_string(),
            path: "sub_ca_public_key.pem".to_string(),
            hash: "sha256:def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            size: 272,
            mime: Some("application/x-pem-file".to_string()),
        });

        push(EventData::Step {
            step_id: "step_5".to_string(),
            action: ActionType::Attest,
            role: Some("witness".to_string()),
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 4, 0).unwrap(),
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 4, 3).unwrap(),
            outcome: EventOutcome {
                status: "completed".to_string(),
                message: Some("Ceremony attested".to_string()),
            },
            evidence: StepEvidence::new(),
        });

        push(EventData::CeremonyComplete {
            completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 5, 0).unwrap(),
            status: TranscriptStatus::Completed,
        });

        let mut file = File::create(&path)?;
        for event in &events {
            let json = serde_json::to_string(event).map_err(io::Error::other)?;
            writeln!(file, "{json}")?;
        }

        eprintln!("Generated fixture: {}", path.display());
        Ok(())
    }

    #[test]
    fn test_chained_event() {
        let data = EventData::CeremonyStart {
            schema_version: TRANSCRIPT_SCHEMA_VERSION.to_string(),
            dry_run: false,
            ceremony: CeremonyInfo {
                fingerprint: "sha256:test".to_string(),
                name: "Test".to_string(),
            },
            instance: None,
            binary: BinaryInfo {
                fingerprint: None,
                version: "0.1.0".to_string(),
            },
            image: None,
            initrd: None,
            environment: None,
            participants: vec![],
            started_at: Utc::now(),
        };

        let event = new_chained_event(GENESIS_HASH.to_string(), data);
        assert_eq!(event.prev, GENESIS_HASH);
        assert!(verify_chained_event_hash(&event));
    }
}
