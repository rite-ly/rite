//! Transcript data types for ceremony audit trails.
//!
//! These types model the structure of ceremony execution records. A transcript
//! is a hash-chained sequence of [`ChainedEvent`] values that captures what
//! happened during a ceremony run, who participated, and what was produced.
//!
//! The runtime-side functions (`read_transcript`, `verify_transcript`,
//! `compute_fingerprint`) live in `rite-runtime` — their signatures may still
//! evolve before the first stable release. The types here are the stable,
//! semver-committed portion of the transcript API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::ActionType;

/// Schema version for the JSONL transcript format.
///
/// Increment when the format changes in a way that breaks existing parsers or
/// verification tools.
pub const TRANSCRIPT_SCHEMA_VERSION: &str = "0.1";

/// Genesis hash for the first event in the hash chain.
///
/// Uses all-zeros — a valid SHA-256 representation that cannot collide with any
/// real event hash. The first event has `prev: GENESIS_HASH`.
pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Information about the ceremony definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyInfo {
    /// SHA-256 fingerprint of the ceremony YAML file.
    pub fingerprint: String,
    /// Ceremony name.
    pub name: String,
}

/// Information about resolved ceremony inputs (parameters, materials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// SHA-256 fingerprint of all resolved runtime inputs (parameters + material fingerprints).
    pub fingerprint: String,
    /// Resolved parameters (names, dates, labels).
    ///
    /// Uses `BTreeMap` for deterministic serialization order in JSONL transcripts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, serde_json::Value>,
    /// SHA-256 fingerprints of digital materials, keyed by material ID.
    ///
    /// Physical materials have no digital fingerprint and are omitted.
    /// Uses `BTreeMap` for deterministic serialization order in JSONL transcripts.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub materials: BTreeMap<String, String>,
}

/// A participant assigned to a role for this ceremony execution.
///
/// Recorded in `CeremonyStart` so the transcript is self-contained: a verifier
/// can identify every participant without consulting external sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRecord {
    /// Role identifier (e.g. `crypto_officer`, `witness__1`).
    pub role_id: String,
    /// Human-readable role name (e.g. "Crypto Officer").
    pub role_name: String,
    /// Named individual assigned to this role, if specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
}

/// A single component in the release manifest (filesystem or binary).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageComponent {
    /// SHA-256 hash of this component.
    pub hash: String,
}

/// Release manifest, inlined from the USB image at ceremony runtime startup.
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
    /// PCR measurements from the TPM (if available).
    // External data from the ISO; order irrelevant — keep HashMap
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr: Option<HashMap<String, String>>,
}

/// A single component measured by the initrd hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitrdComponent {
    /// SHA-256 hash of this component (if measured).
    pub hash: Option<String>,
    /// Whether the hash was verified against the manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

/// Measurements written by the initrd hook before squashfs was mounted.
///
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
    /// SHA-256 fingerprint of the binary (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Binary version.
    pub version: String,
}

/// Transcript completion status.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    /// Ceremony completed successfully.
    Completed,
    /// Ceremony was interrupted (crash, abort, error).
    Interrupted,
    /// Ceremony is still in progress.
    InProgress,
}

/// Outcome of a step execution as recorded in the transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventOutcome {
    /// Status: `completed` or `skipped`.
    pub status: String,
    /// Human-readable message or skip reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Evidence produced by a step execution.
///
/// Uses `BTreeMap` for deterministic serialization order in JSONL transcripts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepEvidence {
    /// Generic key-value evidence data.
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

/// Event data types for JSONL transcript entries.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum EventData {
    /// Ceremony started.
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
        /// OS environment variables at ceremony start (if captured).
        // environment order is irrelevant — keep HashMap
        #[serde(skip_serializing_if = "Option::is_none")]
        environment: Option<HashMap<String, String>>,
        /// Participants assigned to roles for this execution.
        ///
        /// Makes the transcript self-contained: role names and person assignments
        /// are recorded here so audit records are standalone.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        participants: Vec<ParticipantRecord>,
        /// Timestamp when the ceremony started.
        started_at: DateTime<Utc>,
    },
    /// Step execution.
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
    /// Evidence file added (photo, document, etc.).
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
    /// Artifact produced by ceremony.
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
    /// Deviation from expected procedure.
    Deviation {
        /// Human-readable reason for the deviation.
        reason: String,
        /// Step being deviated from (if applicable).
        #[serde(skip_serializing_if = "Option::is_none")]
        step_id: Option<String>,
        /// When the deviation was recorded.
        recorded_at: DateTime<Utc>,
    },
    /// Ceremony completed.
    CeremonyComplete {
        /// When the ceremony finished.
        completed_at: DateTime<Utc>,
        /// Final completion status.
        status: TranscriptStatus,
    },
}

/// A hash-chained event in the JSONL transcript.
///
/// The `hash` field is `H(H(prev) || H(data))` using SHA-256, encoded as
/// `"sha256:{lowercase_hex}"`. Use `read_transcript` in `rite-runtime` to
/// parse and verify a transcript; individual hashes are verified there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedEvent {
    /// Hash of the previous event (`GENESIS_HASH` for the first event).
    pub prev: String,
    /// Event data.
    pub data: EventData,
    /// SHA-256 hash of this event computed as H(H(prev) || H(data)).
    pub hash: String,
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
    /// Transcript is valid and fingerprint matches.
    Valid {
        /// Final SHA-256 fingerprint of the transcript chain.
        fingerprint: String,
        /// Completion status recorded in the final event.
        status: TranscriptStatus,
        /// Whether this was a dry run (no actual operations performed).
        dry_run: bool,
        /// Artifact file verification results.
        artifacts: Vec<ArtifactVerification>,
        /// Build-time image manifest (from `CeremonyStart`).
        image: Option<ImageManifest>,
        /// Boot-time initrd measurements (from `CeremonyStart`).
        initrd: Option<InitrdMeasurements>,
        /// Nonce from the first `tpm_attest` step evidence, if any.
        tpm_nonce: Option<String>,
        /// PCR values from the first `tpm_attest` step evidence, if any.
        ///
        /// Uses `BTreeMap` for deterministic display order.
        tpm_pcrs: BTreeMap<String, String>,
    },
    /// Transcript has been tampered with.
    Invalid {
        /// Expected hash (from the `hash` field of the final event).
        expected: String,
        /// Computed hash (recomputed from transcript content).
        computed: String,
    },
    /// Transcript is incomplete (no final fingerprint).
    Incomplete {
        /// Last recorded status.
        status: TranscriptStatus,
        /// Number of events parsed before the transcript ends.
        events_count: usize,
    },
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

                if let Some(img) = image {
                    writeln!(f, "\nImage (build-time):")?;
                    writeln!(f, "  Version:    {}", img.version)?;
                    writeln!(f, "  Filesystem: {}", img.filesystem.hash)?;
                    writeln!(f, "  Binary:     {}", img.binary.hash)?;
                }

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
                        Some(true) => writeln!(f, "  initrd verification gate:            passed")?,
                        Some(false) => {
                            writeln!(f, "  initrd verification gate:            FAILED")?;
                        }
                        None => {}
                    }
                }

                if !tpm_pcrs.is_empty() || tpm_nonce.is_some() {
                    writeln!(f, "\nTPM attestation:")?;
                    if let Some(nonce) = tpm_nonce {
                        writeln!(f, "  Nonce: {nonce}")?;
                    }
                    for (pcr, val) in tpm_pcrs {
                        writeln!(f, "  PCR {pcr}: {val}")?;
                    }
                } else {
                    writeln!(
                        f,
                        "\nNo hardware attestation recorded (no tpm_attest step in transcript)."
                    )?;
                }

                if !artifacts.is_empty() {
                    let verified_count = artifacts.iter().filter(|a| a.verified).count();
                    let total = artifacts.len();
                    writeln!(
                        f,
                        "\nArtifact verification: {verified_count}/{total} files verified"
                    )?;
                    for artifact in artifacts {
                        if artifact.verified {
                            writeln!(f, "  \u{2713} {} ({})", artifact.path, artifact.source)?;
                        } else if let Some(error) = &artifact.error {
                            writeln!(
                                f,
                                "  \u{2717} {} ({}): {}",
                                artifact.path, artifact.source, error
                            )?;
                        } else {
                            writeln!(
                                f,
                                "  \u{2717} {} ({}): Hash mismatch",
                                artifact.path, artifact.source
                            )?;
                        }
                    }
                }
                Ok(())
            }
            VerificationResult::Invalid { expected, computed } => write!(
                f,
                "TAMPERED: Fingerprint mismatch!\n  Expected: {expected}\n  Computed: {computed}"
            ),
            VerificationResult::Incomplete {
                status,
                events_count,
            } => write!(
                f,
                "Incomplete transcript (no final fingerprint). Status: {status:?}. Events recorded: {events_count}"
            ),
        }
    }
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
