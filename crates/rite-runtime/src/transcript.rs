//! Ceremony transcript generation for audit trails.
//!
//! This module provides types and traits for generating cryptographically-fingerprinted
//! transcripts of ceremony execution. Transcripts capture:
//! - Ceremony context (fingerprints of ceremony, parameters, and binary)
//! - Execution events (one per step with timing and evidence)
//! - Final completion status and fingerprint for tamper detection

use chrono::{DateTime, Utc};
use rite_model::ActionType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufWriter, Write};
use std::path::Path;

use crate::executor::StepOutcome;
use rite_model::StepId;

/// Schema version for the JSONL transcript format.
///
/// This version should be incremented when the transcript format changes
/// in a way that would break existing verification tools or parsers.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1";

/// Genesis hash for the first event in the hash chain.
///
/// Uses all-zeros (standard in cryptographic chains like blockchain and Git).
/// This is a valid SHA-256 hash that cannot collide with any real hash.
///
/// Example: The first event has `prev: GENESIS_HASH`
pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Information about the ceremony definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyInfo {
    /// SHA-256 fingerprint of the ceremony YAML file
    pub fingerprint: String,
    /// Ceremony name
    pub name: String,
    /// Ceremony version from the DSL
    pub version: String,
}

/// Information about resolved ceremony inputs (parameters, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// SHA-256 fingerprint of resolved parameter values.
    pub fingerprint: String,
    /// Resolved parameters (names, dates, labels)
    ///
    /// Uses `BTreeMap` for deterministic serialization order in JSONL transcripts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, serde_json::Value>,
}

/// A participant assigned to a role for this ceremony execution.
///
/// Recorded in `CeremonyStart` so the transcript is self-contained — a verifier
/// can identify every participant without consulting external sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRecord {
    /// Role identifier (e.g. `crypto_officer`, `witness__1`)
    pub role_id: String,
    /// Human-readable role name (e.g. "Crypto Officer")
    pub role_name: String,
    /// Named individual assigned to this role, if specified via ceremony YAML or CLI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
}

/// A single component in the release manifest (filesystem or binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageComponent {
    pub hash: String,
}

/// Release manifest, inlined from `/run/live/medium/live/rite-manifest.json`.
///
/// Build-time values with stronger provenance than self-reported hashes:
/// computed outside the running binary and embedded in the ISO at build time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Image version string.
    pub version: String,
    /// Filesystem (squashfs) component measurements.
    pub filesystem: ImageComponent,
    /// Binary component measurements.
    pub binary: ImageComponent,
    // External data from the ISO — keep HashMap as-is (not transcript-serialized output)
    /// PCR measurements from the TPM (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr: Option<HashMap<String, String>>,
}

/// A single component measured by the initrd hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitrdComponent {
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

/// Measurements written by the initrd hook before squashfs was mounted.
/// Read from `/run/rite/initrd-measurements.json` at runtime startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitrdMeasurements {
    /// Filesystem image measurements.
    pub filesystem: InitrdComponent,
    /// Ceremony file measurements.
    pub ceremony: InitrdComponent,
}

/// Information about the rite binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// SHA-256 fingerprint of the binary (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Binary version
    pub version: String,
}

/// Transcript completion status.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    /// Ceremony completed successfully
    Completed,
    /// Ceremony was interrupted (crash, abort, error)
    Interrupted,
    /// Ceremony is still in progress
    InProgress,
}

/// A single execution event in the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    /// Step identifier
    pub step_id: String,
    /// Action type executed
    pub action: ActionType,
    /// Role performing the step (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// When the step started
    pub started_at: DateTime<Utc>,
    /// When the step completed
    pub completed_at: DateTime<Utc>,
    /// Step outcome
    pub outcome: EventOutcome,
    /// Action-specific evidence
    pub evidence: StepEvidence,
}

/// Outcome of a step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventOutcome {
    /// Status: completed or skipped
    pub status: String,
    /// Message or reason
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl From<&StepOutcome> for EventOutcome {
    fn from(outcome: &StepOutcome) -> Self {
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
}

/// Evidence produced by a step execution.
///
/// Uses `BTreeMap` for deterministic serialization order in JSONL transcripts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepEvidence {
    /// Generic key-value evidence data
    #[serde(flatten)]
    pub data: BTreeMap<String, serde_json::Value>,
}

impl StepEvidence {
    /// Create a new empty evidence set.
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
        }
    }

    /// Insert a key-value pair into the evidence.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) {
        self.data.insert(key.into(), value.into());
    }

    /// Insert a key-value pair and return self (builder pattern).
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.insert(key, value);
        self
    }
}

/// Compute raw SHA-256 hash bytes.
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 fingerprint of a byte slice.
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
///
/// This is the standard cryptographic pattern for hash chains:
/// 1. Hash both inputs to fixed 32-byte values
/// 2. Concatenate the hashes (64 bytes)
/// 3. Hash the result
fn compute_chain_hash(prev: &[u8], data: &[u8]) -> String {
    let prev_hash = sha256_bytes(prev);
    let data_hash = sha256_bytes(data);

    // Concatenate the two 32-byte hashes
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&prev_hash);
    combined[32..].copy_from_slice(&data_hash);

    compute_fingerprint(&combined)
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

/// A hash-chained event in the JSONL transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedEvent {
    /// Hash of the previous event (`GENESIS_HASH` for first event)
    pub prev: String,
    /// Event data
    pub data: EventData,
    /// SHA-256 hash of this event (hash of prev + data)
    pub hash: String,
}

/// Event data types for JSONL transcript.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    /// Ceremony started
    CeremonyStart {
        /// Transcript format version.
        schema_version: String,
        /// Whether this is a dry run.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        dry_run: bool,
        /// Ceremony identity and fingerprint.
        ceremony: CeremonyInfo,
        /// Instance-specific parameters (absent if ceremony has no parameters).
        #[serde(skip_serializing_if = "Option::is_none")]
        instance: Option<InstanceInfo>,
        /// Binary identity and version.
        binary: BinaryInfo,
        /// Live USB image manifest (absent when not running from a live image).
        #[serde(skip_serializing_if = "Option::is_none")]
        image: Option<ImageManifest>,
        /// Initrd measurements (absent when not running from a live image).
        #[serde(skip_serializing_if = "Option::is_none")]
        initrd: Option<InitrdMeasurements>,
        // environment is passed to OS, order irrelevant — keep HashMap
        /// OS environment variables at ceremony start (if captured).
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<HashMap<String, String>>,
        /// Participants assigned to roles for this execution.
        /// Makes the transcript self-contained — role names and person
        /// assignments are recorded here for self-contained audit records.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        participants: Vec<ParticipantRecord>,
        /// Timestamp when the ceremony started.
        started_at: DateTime<Utc>,
    },
    /// Step execution
    Step {
        /// Step identifier from the ceremony definition.
        step_id: String,
        /// Action type performed.
        action: ActionType,
        /// Role that performed this step (if role-bound).
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        /// When the step started.
        started_at: DateTime<Utc>,
        /// When the step completed.
        completed_at: DateTime<Utc>,
        /// Whether the step completed or was skipped.
        outcome: EventOutcome,
        /// Action-specific evidence collected during execution.
        evidence: StepEvidence,
    },
    /// Evidence file added (photo, document, etc.)
    EvidenceAdd {
        /// Path to the evidence file.
        path: String,
        /// SHA-256 fingerprint of the file.
        hash: String,
        /// File size in bytes.
        size: u64,
        /// MIME type (if known).
        #[serde(skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
    },
    /// Artifact produced by ceremony
    ArtifactProduce {
        /// Artifact ID (from the ceremony definition).
        source: String,
        /// Path where the artifact was written.
        path: String,
        /// SHA-256 fingerprint of the written file.
        hash: String,
        /// File size in bytes.
        size: u64,
        /// MIME type (if known).
        #[serde(skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
    },
    /// Deviation from expected procedure
    Deviation {
        /// Human-readable reason for the deviation.
        reason: String,
        /// Step being deviated from (if applicable).
        #[serde(skip_serializing_if = "Option::is_none")]
        step_id: Option<String>,
        /// When the deviation was recorded.
        recorded_at: DateTime<Utc>,
    },
    /// Ceremony completed
    CeremonyComplete {
        /// When the ceremony finished.
        completed_at: DateTime<Utc>,
        /// Final completion status.
        status: TranscriptStatus,
    },
}

impl ChainedEvent {
    /// Compute the hash of this event using standard construction: H(H(prev) || H(data)).
    ///
    /// This follows the standard cryptographic pattern for hash chains where:
    /// - Both inputs are hashed to fixed-size 32-byte values
    /// - The hashes are concatenated (64 bytes total)
    /// - The result is hashed again
    fn compute_hash(prev: &str, data: &EventData) -> String {
        // EventData is always serializable — it's composed of primitive types,
        // strings, and Serialize-derived structs. A serialization failure here
        // indicates a programming error (e.g., adding a non-serializable field).
        #[allow(clippy::expect_used)]
        let data_json = serde_json::to_string(data).expect("Event serialization failed");
        compute_chain_hash(prev.as_bytes(), data_json.as_bytes())
    }

    /// Create a new chained event.
    pub fn new(prev: String, data: EventData) -> Self {
        let hash = Self::compute_hash(&prev, &data);
        Self { prev, data, hash }
    }

    /// Verify this event's hash is correct.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(&self.prev, &self.data);
        computed == self.hash
    }
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

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true) // Append mode for JSONL (implies write)
            .open(&path)?;

        let writer = BufWriter::new(file);

        Ok(Self {
            writer,
            path,
            last_hash: GENESIS_HASH.to_string(),
        })
    }

    /// Get the path to the transcript file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write a chained event to the file.
    fn write_event(&mut self, event: &ChainedEvent) -> io::Result<()> {
        let json = serde_json::to_string(event).map_err(io::Error::other)?;
        writeln!(self.writer, "{json}")?;
        self.writer.flush()?;
        self.last_hash.clone_from(&event.hash);
        Ok(())
    }

    /// Append an event with automatic hash chaining.
    fn append(&mut self, data: EventData) -> io::Result<()> {
        let event = ChainedEvent::new(self.last_hash.clone(), data);
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
        let data = EventData::CeremonyStart {
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
        };

        self.append(data)
    }

    fn record_event(&mut self, event: ExecutionEvent) -> io::Result<()> {
        let data = EventData::Step {
            step_id: event.step_id,
            action: event.action,
            role: event.role,
            started_at: event.started_at,
            completed_at: event.completed_at,
            outcome: event.outcome,
            evidence: event.evidence,
        };

        self.append(data)
    }

    fn finalize(&mut self, status: TranscriptStatus) -> io::Result<String> {
        let data = EventData::CeremonyComplete {
            completed_at: Utc::now(),
            status,
        };

        self.append(data)?;

        // Return the last hash as the "fingerprint" of the chain
        Ok(self.last_hash.clone())
    }

    fn mark_interrupted(&mut self) -> io::Result<()> {
        let data = EventData::CeremonyComplete {
            completed_at: Utc::now(),
            status: TranscriptStatus::Interrupted,
        };

        self.append(data)
    }

    fn record_deviation(&mut self, reason: &str, step_id: Option<&StepId>) -> io::Result<()> {
        let data = EventData::Deviation {
            reason: reason.to_string(),
            step_id: step_id.map(|id| id.as_str().to_string()),
            recorded_at: Utc::now(),
        };
        self.append(data)
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

        let data = EventData::ArtifactProduce {
            source: source.to_string(),
            path: path_str,
            hash,
            size,
            mime,
        };

        self.append(data)
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

/// Helper struct to extract raw JSON values for hash verification.
///
/// This struct uses `serde_json::RawValue` to preserve the exact JSON bytes
/// of the `data` field during deserialization. This is critical for deterministic
/// hash verification: if we deserialized to `EventData` and re-serialized,
/// field ordering or formatting differences could produce different JSON bytes,
/// causing hash verification to fail even for valid transcripts.
#[derive(Deserialize)]
struct RawChainedEvent<'a> {
    prev: String,
    #[serde(borrow)]
    data: &'a serde_json::value::RawValue,
    #[allow(dead_code)] // Read during deserialization but not used in verification
    hash: String,
}

/// Verify an event's hash using the raw JSON representation.
///
/// This preserves the exact JSON bytes to ensure deterministic hashing.
/// Uses standard construction: H(H(prev) || H(data)).
fn verify_event_hash_from_json(json_line: &str) -> Result<String, String> {
    // Parse with RawValue to preserve exact JSON representation
    let raw_event: RawChainedEvent =
        serde_json::from_str(json_line).map_err(|e| format!("JSON parse error: {e}"))?;

    // Compute hash using standard chain construction
    Ok(compute_chain_hash(
        raw_event.prev.as_bytes(),
        raw_event.data.get().as_bytes(),
    ))
}

/// Verify a JSONL transcript (hash-chained format).
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
        let line_num = line_num.saturating_add(1); // Convert to 1-based for error messages
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let event: ChainedEvent = serde_json::from_str(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;

        // Verify hash chain
        if event.prev != prev_hash {
            return Ok(VerificationResult::Invalid {
                expected: prev_hash,
                computed: event.prev.clone(),
            });
        }

        // Verify event's own hash by extracting the data field from the original JSON
        // This avoids issues with JSON serialization order
        let computed_hash = verify_event_hash_from_json(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;

        if event.hash != computed_hash {
            return Ok(VerificationResult::Invalid {
                expected: event.hash.clone(),
                computed: computed_hash,
            });
        }

        // Extract fields from CeremonyStart
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

        // Extract TPM nonce and PCRs from the first tpm_attest step
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

    // Verify artifact files against recorded hashes
    let artifacts = verify_artifacts(path, &events);

    // Check if last event is a completion event
    if let Some(last_event) = events.last() {
        match &last_event.data {
            EventData::CeremonyComplete { status, .. } => Ok(VerificationResult::Valid {
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
    } else {
        Ok(VerificationResult::Incomplete {
            status: TranscriptStatus::InProgress,
            events_count: 0,
        })
    }
}

/// Verify artifact files against the hashes recorded in the transcript.
///
/// For each `ArtifactProduce` event in the transcript:
/// 1. Resolve the artifact file path relative to the transcript's parent directory
/// 2. Check if the file exists
/// 3. Compute its SHA-256 hash
/// 4. Compare against the hash recorded in the event
///
/// Returns a vector of verification results, one per artifact.
fn verify_artifacts(transcript_path: &Path, events: &[ChainedEvent]) -> Vec<ArtifactVerification> {
    // Get the base directory (parent of the transcript file)
    let base_dir = transcript_path.parent().unwrap_or_else(|| Path::new("."));

    let mut results = Vec::new();

    for event in events {
        if let EventData::ArtifactProduce {
            source,
            path: artifact_path,
            hash: expected_hash,
            ..
        } = &event.data
        {
            // Resolve artifact path relative to transcript directory.
            let full_path = base_dir.join(artifact_path);

            let verification = match compute_file_fingerprint(&full_path) {
                Ok(computed_hash) => {
                    if &computed_hash == expected_hash {
                        ArtifactVerification {
                            source: source.clone(),
                            path: artifact_path.clone(),
                            expected_hash: expected_hash.clone(),
                            verified: true,
                            error: None,
                        }
                    } else {
                        ArtifactVerification {
                            source: source.clone(),
                            path: artifact_path.clone(),
                            expected_hash: expected_hash.clone(),
                            verified: false,
                            error: Some(format!(
                                "Hash mismatch (expected: {expected_hash}, computed: {computed_hash})"
                            )),
                        }
                    }
                }
                Err(e) => ArtifactVerification {
                    source: source.clone(),
                    path: artifact_path.clone(),
                    expected_hash: expected_hash.clone(),
                    verified: false,
                    error: Some(format!("Failed to read file: {e}")),
                },
            };

            results.push(verification);
        }
    }

    results
}

/// Result of verifying a single artifact file.
#[derive(Debug, Clone)]
pub struct ArtifactVerification {
    /// Artifact ID (from the ceremony definition).
    pub source: String,
    /// Path where the artifact was written.
    pub path: String,
    /// Expected SHA-256 fingerprint (from transcript).
    pub expected_hash: String,
    /// Whether the computed hash matched the expected hash.
    pub verified: bool,
    /// Error description if verification failed.
    pub error: Option<String>,
}

/// Result of transcript verification.
#[non_exhaustive]
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VerificationResult {
    /// Transcript is valid and fingerprint matches
    Valid {
        /// Final SHA-256 fingerprint of the transcript chain.
        fingerprint: String,
        /// Completion status recorded in the final event.
        status: TranscriptStatus,
        /// Whether this was a dry run (no actual operations performed)
        dry_run: bool,
        /// Artifact file verification results
        artifacts: Vec<ArtifactVerification>,
        /// Build-time image manifest (from `CeremonyStart`)
        image: Option<ImageManifest>,
        /// Boot-time initrd measurements (from `CeremonyStart`)
        initrd: Option<InitrdMeasurements>,
        /// Nonce from the first `tpm_attest` step evidence, if any
        tpm_nonce: Option<String>,
        /// PCR values from the first `tpm_attest` step evidence, if any
        ///
        /// Uses `BTreeMap` for deterministic display order.
        tpm_pcrs: BTreeMap<String, String>,
    },
    /// Transcript has been tampered with
    Invalid {
        /// Expected hash (from the `hash` field of the final event).
        expected: String,
        /// Computed hash (recomputed from transcript content).
        computed: String,
    },
    /// Transcript is incomplete (no final fingerprint)
    Incomplete {
        /// Last recorded status.
        status: TranscriptStatus,
        /// Number of events parsed before the transcript ends.
        events_count: usize,
    },
}

/// A fully parsed and verified transcript.
#[derive(Debug)]
pub struct ParsedTranscript {
    /// All chained events in order.
    pub events: Vec<ChainedEvent>,
    /// Final chain fingerprint (hash of the last event).
    pub fingerprint: String,
    /// Whether this was a dry run.
    pub dry_run: bool,
    /// Completion status.
    pub status: TranscriptStatus,
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

        // Verify hash chain continuity
        if event.prev != prev_hash {
            return Err(io::Error::other(format!(
                "Line {line_num}: hash chain broken (expected prev={prev_hash}, got prev={})",
                event.prev
            )));
        }

        // Verify event's own hash
        let computed_hash = verify_event_hash_from_json(&line)
            .map_err(|e| io::Error::other(format!("Line {line_num}: {e}")))?;
        if event.hash != computed_hash {
            return Err(io::Error::other(format!(
                "Line {line_num}: event hash mismatch (expected={}, computed={computed_hash})",
                event.hash
            )));
        }

        // Extract dry_run from CeremonyStart
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

    // Must end with CeremonyComplete
    let status = match events.last().map(|e| &e.data) {
        Some(EventData::CeremonyComplete { status, .. }) => status.clone(),
        _ => {
            return Err(io::Error::other(
                "Transcript is incomplete (no CeremonyComplete event)",
            ));
        }
    };

    // Verify artifact files against recorded hashes (same as verify_jsonl_transcript)
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

impl std::fmt::Display for VerificationResult {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationResult::Valid {
                fingerprint,
                status,
                dry_run,
                artifacts,
                image,
                initrd,
                tpm_nonce,
                tpm_pcrs,
            } => {
                if *dry_run {
                    writeln!(
                        f,
                        "WARNING: This is a DRY RUN transcript - no actual cryptographic operations were performed"
                    )?;
                }
                writeln!(f, "Transcript integrity verified.")?;
                writeln!(f, "  Status:      {status:?}")?;
                writeln!(f, "  Fingerprint: {fingerprint}")?;

                // Image manifest (build-time)
                if let Some(img) = image {
                    let version = &img.version;
                    let fs_hash = &img.filesystem.hash;
                    let bin_hash = &img.binary.hash;
                    writeln!(f, "\nImage (build-time):")?;
                    writeln!(f, "  Version:    {version}")?;
                    writeln!(f, "  Filesystem: {fs_hash}")?;
                    writeln!(f, "  Binary:     {bin_hash}")?;
                }

                // Initrd measurements (boot-time)
                if let Some(imd) = initrd {
                    writeln!(f, "\nInitrd measurements (boot-time, pre-mount):")?;
                    let fs_hash = imd.filesystem.hash.as_deref().unwrap_or("(none)");
                    let fs_verified = match imd.filesystem.verified {
                        Some(true) => " [verified]",
                        Some(false) => " [not verified]",
                        None => "",
                    };
                    writeln!(f, "  Filesystem: {fs_hash}{fs_verified}")?;
                    let cer_hash = imd.ceremony.hash.as_deref().unwrap_or("(none)");
                    writeln!(f, "  Ceremony:   {cer_hash}")?;
                }

                // Cross-checks (initrd vs image manifest)
                if let (Some(img), Some(imd)) = (image, initrd) {
                    writeln!(f, "\nCross-checks:")?;
                    if let Some(ref fs_hash) = imd.filesystem.hash {
                        let matches = fs_hash == &img.filesystem.hash;
                        writeln!(
                            f,
                            "  initrd.filesystem == image.filesystem: {}",
                            if matches { "match" } else { "MISMATCH" }
                        )?;
                    }
                    match imd.filesystem.verified {
                        Some(true) => {
                            writeln!(f, "  initrd verification gate:            passed")?;
                        }
                        Some(false) => {
                            writeln!(f, "  initrd verification gate:            FAILED")?;
                        }
                        None => {}
                    }
                }

                // TPM attestation
                if !tpm_pcrs.is_empty() || tpm_nonce.is_some() {
                    writeln!(f, "\nTPM attestation:")?;
                    if let Some(nonce) = tpm_nonce {
                        writeln!(f, "  Nonce: {nonce}")?;
                    }
                    if !tpm_pcrs.is_empty() {
                        // BTreeMap is already sorted — no need for additional sort
                        for (pcr, val) in tpm_pcrs {
                            writeln!(f, "  PCR {pcr}: {val}")?;
                        }
                    }
                } else {
                    writeln!(
                        f,
                        "\nNo hardware attestation recorded (no tpm_attest step in transcript)."
                    )?;
                }

                // Artifact verification results
                if !artifacts.is_empty() {
                    let verified_count = artifacts.iter().filter(|a| a.verified).count();
                    let total = artifacts.len();
                    writeln!(
                        f,
                        "\nArtifact verification: {verified_count}/{total} files verified"
                    )?;
                    for artifact in artifacts {
                        if artifact.verified {
                            writeln!(f, "  ✓ {} ({})", artifact.path, artifact.source)?;
                        } else if let Some(error) = &artifact.error {
                            writeln!(f, "  ✗ {} ({}): {}", artifact.path, artifact.source, error)?;
                        } else {
                            writeln!(
                                f,
                                "  ✗ {} ({}): Hash mismatch",
                                artifact.path, artifact.source
                            )?;
                        }
                    }
                }
                Ok(())
            }
            VerificationResult::Invalid { expected, computed } => {
                write!(
                    f,
                    "TAMPERED: Fingerprint mismatch!\n  Expected: {expected}\n  Computed: {computed}"
                )
            }
            VerificationResult::Incomplete {
                status,
                events_count,
            } => {
                write!(
                    f,
                    "Incomplete transcript (no final fingerprint). Status: {status:?}. Events recorded: {events_count}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_model::ActionType;
    use tempfile::tempdir;

    #[test]
    fn test_fingerprint_computation() {
        let data = b"hello world";
        let fingerprint = compute_fingerprint(data);
        assert!(fingerprint.starts_with("sha256:"));
        // SHA-256 of "hello world" is well-known
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
                version: "1.0".to_string(),
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

        // Verify the transcript
        let result = verify_transcript(&path)?;
        assert!(matches!(result, VerificationResult::Valid { .. }));

        // Verify it's actually JSONL format (multiple lines)
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
                version: "1.0".to_string(),
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

        // Add several events
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

        // Read and verify hash chain
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
            assert!(event.verify_hash(), "Event hash verification failed");
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
                version: "1.0".to_string(),
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

        // Tamper with the file
        let mut content = std::fs::read_to_string(&path)?;
        content = content.replace("Test", "Tampered");
        std::fs::write(&path, content)?;

        // Verification should fail
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
                version: "1.0".to_string(),
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
            true, // dry_run = true
        )?;
        writer.finalize(TranscriptStatus::Completed)?;

        // Verification should succeed but report dry_run = true
        let result = verify_transcript(&path)?;
        match result {
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
                version: "1.0".to_string(),
            },
            Some(InstanceInfo {
                fingerprint: "sha256:inst".to_string(),
                parameters: BTreeMap::from([("key".to_string(), serde_json::json!("value"))]),
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
                version: "1.0".to_string(),
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

        // Tamper
        let mut content = std::fs::read_to_string(&path)?;
        content = content.replace("Test", "Tampered");
        std::fs::write(&path, content)?;

        let result = read_transcript(&path);
        assert!(result.is_err());
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
                version: "1.0".to_string(),
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
        // Don't call finalize — transcript is incomplete

        let result = read_transcript(&path);
        assert!(result.is_err());
        Ok(())
    }

    /// Generate the deterministic test fixture at examples/test-fixtures/sample-transcript.jsonl.
    ///
    /// Run with: cargo test -p rite-runtime `generate_sample_transcript` -- --ignored
    #[test]
    #[ignore = "manual fixture regeneration — run explicitly when sample transcript format changes"]
    #[allow(clippy::too_many_lines)]
    fn generate_sample_transcript() -> io::Result<()> {
        use chrono::TimeZone;

        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/test-fixtures");
        std::fs::create_dir_all(&fixture_dir)?;
        let path = fixture_dir.join("sample-transcript.jsonl");

        let mut prev = GENESIS_HASH.to_string();
        let mut events: Vec<ChainedEvent> = Vec::new();

        let push_event = |data: EventData, events: &mut Vec<ChainedEvent>, prev: &mut String| {
            let event = ChainedEvent::new(prev.clone(), data);
            *prev = event.hash.clone();
            events.push(event);
        };

        // CeremonyStart
        push_event(
            EventData::CeremonyStart {
                schema_version: TRANSCRIPT_SCHEMA_VERSION.to_string(),
                dry_run: false,
                ceremony: CeremonyInfo {
                    fingerprint:
                        "sha256:abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                            .to_string(),
                    name: "Sub-CA Key Ceremony".to_string(),
                    version: "1.0".to_string(),
                },
                instance: Some(InstanceInfo {
                    fingerprint:
                        "sha256:inst234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
                            .to_string(),
                    parameters: BTreeMap::from([
                        ("ceremony_date".to_string(), serde_json::json!("2025-06-15")),
                        ("key_label".to_string(), serde_json::json!("SUB-CA-PROD")),
                    ]),
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
            },
            &mut events,
            &mut prev,
        );

        // Step 1: confirm
        push_event(
            EventData::Step {
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
            },
            &mut events,
            &mut prev,
        );

        // Step 2: generate_keypair
        push_event(
            EventData::Step {
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
            },
            &mut events,
            &mut prev,
        );

        // Step 3: confirm (witness)
        push_event(
            EventData::Step {
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
            },
            &mut events,
            &mut prev,
        );

        // Deviation
        push_event(
            EventData::Deviation {
                reason: "Witness requested re-verification of key fingerprint".to_string(),
                step_id: Some("step_3".to_string()),
                recorded_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 2, 30).unwrap(),
            },
            &mut events,
            &mut prev,
        );

        // Step 4: export_public
        push_event(
            EventData::Step {
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
            },
            &mut events,
            &mut prev,
        );

        // ArtifactProduce
        push_event(
            EventData::ArtifactProduce {
                source: "step_4".to_string(),
                path: "sub_ca_public_key.pem".to_string(),
                hash: "sha256:def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    .to_string(),
                size: 272,
                mime: Some("application/x-pem-file".to_string()),
            },
            &mut events,
            &mut prev,
        );

        // Step 5: attest
        push_event(
            EventData::Step {
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
            },
            &mut events,
            &mut prev,
        );

        // CeremonyComplete
        push_event(
            EventData::CeremonyComplete {
                completed_at: Utc.with_ymd_and_hms(2025, 6, 15, 10, 5, 0).unwrap(),
                status: TranscriptStatus::Completed,
            },
            &mut events,
            &mut prev,
        );

        // Write to file
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
                version: "1.0".to_string(),
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

        let event = ChainedEvent::new(GENESIS_HASH.to_string(), data);
        assert_eq!(event.prev, GENESIS_HASH);
        assert!(event.verify_hash());
    }
}
