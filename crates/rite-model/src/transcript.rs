//! Persisted transcript schema.
//!
//! These types are the **durable** audit surface: what gets written to
//! `transcript.jsonl`, what `rite verify` reads back, what report and
//! audit tooling consume. They are deliberately kept independent of the
//! executor and the channel plumbing, a third-party verifier can parse
//! a transcript with only `rite-model` on its dependency list.
//!
//! The live runtime↔frontend channel protocol (`ExecEvent`, `UiCommand`,
//! `Response`, `Icon`, …) lives in `rite-runtime` next to the executor
//! that owns the channels. The boundary is **persisted vs in-flight**.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ir::{ActId, RoleId, StepId};

/// Validator applied by the runtime to a free-form text or literal response
/// before it is accepted.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ValidatorSpec {
    /// Reject empty or whitespace-only input.
    NonEmpty,
    /// Input must match this regular expression.
    Regex(String),
    /// Named, runtime-defined predicate (e.g. `serial_number`).
    Predefined(String),
}

/// Request for user input, recorded into the transcript as part of
/// [`StepFact::PromptAnswered`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Prompt {
    /// Yes / no question with an optional default.
    Confirm {
        /// Question shown to the user.
        question: String,
        /// Default selection if the user presses Enter without choosing.
        default: Option<bool>,
    },
    /// Free-form text input, validated against a [`ValidatorSpec`].
    Text {
        /// Label shown to the user.
        label: String,
        /// Validator applied before the response is accepted.
        validator: ValidatorSpec,
    },
    /// Sensitive input (PIN, password). Echo is suppressed; plaintext is
    /// never serialized to the transcript.
    Secret {
        /// Label shown to the user.
        label: String,
    },
    /// User must type a specific literal string exactly. Validation is
    /// performed by the runtime against `expected`.
    Literal {
        /// Label shown to the user.
        label: String,
        /// Exact string the user must type.
        expected: String,
    },
    /// Wait for the user to acknowledge before proceeding. Used for pacing.
    Continue {
        /// Optional hint such as "Press Enter when ready".
        hint: Option<String>,
    },
}

/// Serializable, redacted form of a user response.
///
/// Used inside [`StepFact::PromptAnswered`] so that the transcript records
/// what was answered without ever persisting plaintext secrets. The
/// in-flight `Response` type lives next to the channel protocol in
/// `rite-runtime`; conversion happens at the moment the prompt is accepted.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseRecord {
    /// Yes / no answer.
    Bool {
        /// The answer.
        value: bool,
    },
    /// Free-form text answer.
    Text {
        /// The answer.
        value: String,
    },
    /// Secret answer, replaced by a deterministic hash of the plaintext so
    /// verifiers can confirm a specific secret was provided without seeing it.
    SecretRedacted {
        /// Lowercase hex of `sha256(plaintext)`.
        sha256_of_plaintext: String,
    },
    /// Acknowledgement of a [`Prompt::Continue`].
    Acknowledged,
}

/// Structured error record for transcript serialization.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    /// Stable kind label (e.g. `aborted`, `step_failed`, `material_load_failed`).
    pub kind: String,
    /// Human-readable message.
    pub message: String,
}

impl ErrorRecord {
    /// Construct an error record.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }
}

/// Outcome of a single step, carried by [`StepFact::StepCompleted`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StepOutcome {
    /// Step executed successfully.
    Completed {
        /// Human-readable completion message.
        message: String,
    },
}

/// Durable, transcript-worthy fact.
///
/// Every variant is recorded by the runtime's transcript sink synchronously
/// before being forwarded to the UI. Action handlers emit
/// [`BackendOperation`] and [`AttestationRecorded`]; all other variants are
/// emitted by the executor at the corresponding lifecycle boundary.
///
/// [`BackendOperation`]: StepFact::BackendOperation
/// [`AttestationRecorded`]: StepFact::AttestationRecorded
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StepFact {
    /// Ceremony has started running.
    CeremonyStarted {
        /// Ceremony name from the DSL.
        name: String,
        /// Wall-clock timestamp at start.
        started_at: DateTime<Utc>,
    },
    /// Beginning of an act (named subdivision of a ceremony).
    ActStarted {
        /// Act identifier.
        id: ActId,
        /// Act label as authored in the DSL.
        label: String,
    },
    /// Beginning of a step.
    StepStarted {
        /// Step identifier.
        id: StepId,
        /// Step label as authored in the DSL.
        label: String,
        /// Role responsible for this step (stable id).
        role: RoleId,
        /// Human-readable role name, from the ceremony's role definition.
        /// Carried alongside the id so transcripts stay self-contained for
        /// reports and verifiers without re-reading the ceremony YAML.
        role_name: String,
        /// Wall-clock timestamp at start.
        started_at: DateTime<Utc>,
    },
    /// A prompt has been answered and validated.
    PromptAnswered {
        /// Step that issued the prompt, if any. `None` for ceremony-level
        /// prompts emitted before the first step (e.g. the ceremony-start
        /// confirmation) or after the last step.
        #[serde(skip_serializing_if = "Option::is_none")]
        step: Option<StepId>,
        /// The prompt as issued.
        prompt: Prompt,
        /// Redacted response record.
        response: ResponseRecord,
        /// Wall-clock timestamp when the response was accepted.
        at: DateTime<Utc>,
    },
    /// A backend operation completed and produced structured evidence.
    BackendOperation {
        /// Step under which the operation ran.
        step: StepId,
        /// Stable operation kind (e.g. `generate_keypair`, `sign_data`).
        kind: String,
        /// Structured inputs to the operation (parameters, references).
        inputs: serde_json::Value,
        /// Structured outputs from the operation (artifact ids, hashes).
        outputs: serde_json::Value,
        /// Optional fingerprint of the produced material.
        fingerprint: Option<String>,
    },
    /// A human attestation was recorded.
    AttestationRecorded {
        /// Step under which the attestation was recorded.
        step: StepId,
        /// Role that issued the attestation.
        role: RoleId,
        /// Verbatim attestation statement.
        statement: String,
        /// Wall-clock timestamp when the attestation was recorded.
        at: DateTime<Utc>,
    },
    /// An artifact was written to disk.
    ArtifactWritten {
        /// Step that produced the artifact.
        step: StepId,
        /// Artifact name as declared in the DSL.
        name: String,
        /// Path on disk.
        path: PathBuf,
        /// Lowercase hex SHA-256 of the artifact bytes.
        sha256: String,
    },
    /// A deviation was logged by the operator.
    DeviationRecorded {
        /// Step in which the deviation was logged, if any. `None` for
        /// deviations logged outside of a step (before the first step or
        /// while a ceremony-level prompt is pending).
        #[serde(skip_serializing_if = "Option::is_none")]
        step: Option<StepId>,
        /// Verbatim deviation text.
        text: String,
        /// Wall-clock timestamp when the deviation was recorded.
        at: DateTime<Utc>,
    },
    /// Step finished executing.
    StepCompleted {
        /// Step identifier.
        id: StepId,
        /// Outcome (completed or skipped).
        outcome: StepOutcome,
        /// Wall-clock timestamp at completion.
        completed_at: DateTime<Utc>,
    },
    /// Ceremony finished successfully.
    ///
    /// The transcript's cryptographic identity is `SHA-256(line_bytes)`
    /// for this line, recoverable by any reader, so the fact itself
    /// carries no fingerprint field. The runtime forwards the value to
    /// frontends through an out-of-band channel event.
    CeremonyCompleted {
        /// Wall-clock timestamp at completion.
        completed_at: DateTime<Utc>,
    },
    /// Ceremony failed or was aborted.
    CeremonyFailed {
        /// Structured error record.
        error: ErrorRecord,
        /// Wall-clock timestamp at failure.
        failed_at: DateTime<Utc>,
    },
}

/// JSON-shape snapshot tests, the tripwire for accidental wire-format breaks.
///
/// Every variant of [`StepFact`], [`Prompt`], [`ResponseRecord`], [`StepOutcome`],
/// and [`ValidatorSpec`] is serialized once with fixed payloads and compared
/// against an inline JSON literal. The on-disk transcript schema is what
/// `rite verify`, `rite report`, and any third-party verifier consume; a
/// rename, a `serde(tag)` change, a `rename_all` flip, or a timestamp format
/// swap must surface here, not in the field.
///
/// Breaking the format is allowed in early beta, **deliberately**, update
/// the fixture in the same commit so the diff documents the wire change.
#[cfg(test)]
mod schema_snapshot_tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap()
    }

    fn assert_json(fact: &StepFact, expected: &serde_json::Value) {
        let actual = serde_json::to_value(fact).expect("serialize StepFact");
        assert_eq!(&actual, expected, "wire-format drift for {fact:?}");
    }

    #[test]
    fn ceremony_started() {
        assert_json(
            &StepFact::CeremonyStarted {
                name: "Root CA".to_string(),
                started_at: ts(),
            },
            &json!({
                "type": "ceremony_started",
                "name": "Root CA",
                "started_at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn act_started() {
        assert_json(
            &StepFact::ActStarted {
                id: ActId::new("setup"),
                label: "Setup".to_string(),
            },
            &json!({
                "type": "act_started",
                "id": "setup",
                "label": "Setup",
            }),
        );
    }

    #[test]
    fn step_started() {
        assert_json(
            &StepFact::StepStarted {
                id: StepId::new("s1"),
                label: "2.1".to_string(),
                role: RoleId::new("crypto_officer"),
                role_name: "Crypto Officer".to_string(),
                started_at: ts(),
            },
            &json!({
                "type": "step_started",
                "id": "s1",
                "label": "2.1",
                "role": "crypto_officer",
                "role_name": "Crypto Officer",
                "started_at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_confirm_bool() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Confirm {
                    question: "Proceed?".to_string(),
                    default: Some(true),
                },
                response: ResponseRecord::Bool { value: true },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "confirm", "question": "Proceed?", "default": true },
                "response": { "type": "bool", "value": true },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_text_nonempty() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "Name".to_string(),
                    validator: ValidatorSpec::NonEmpty,
                },
                response: ResponseRecord::Text {
                    value: "Alice".to_string(),
                },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "Name",
                    "validator": { "kind": "non_empty" },
                },
                "response": { "type": "text", "value": "Alice" },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_text_regex() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "SN".to_string(),
                    validator: ValidatorSpec::Regex(r"^[A-Z0-9]+$".to_string()),
                },
                response: ResponseRecord::Text {
                    value: "AB12".to_string(),
                },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "SN",
                    "validator": { "kind": "regex", "value": "^[A-Z0-9]+$" },
                },
                "response": { "type": "text", "value": "AB12" },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_text_predefined() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "SN".to_string(),
                    validator: ValidatorSpec::Predefined("serial_number".to_string()),
                },
                response: ResponseRecord::Text {
                    value: "ABCD".to_string(),
                },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "SN",
                    "validator": { "kind": "predefined", "value": "serial_number" },
                },
                "response": { "type": "text", "value": "ABCD" },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_secret_redacted() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Secret {
                    label: "PIN".to_string(),
                },
                response: ResponseRecord::SecretRedacted {
                    sha256_of_plaintext: "f".repeat(64),
                },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "secret", "label": "PIN" },
                "response": {
                    "type": "secret_redacted",
                    "sha256_of_plaintext": "f".repeat(64),
                },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_literal_text() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Literal {
                    label: "Type 'attest'".to_string(),
                    expected: "attest".to_string(),
                },
                response: ResponseRecord::Text {
                    value: "attest".to_string(),
                },
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "literal", "label": "Type 'attest'", "expected": "attest" },
                "response": { "type": "text", "value": "attest" },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn prompt_answered_continue_acknowledged() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Continue {
                    hint: Some("Press Enter".to_string()),
                },
                response: ResponseRecord::Acknowledged,
                at: ts(),
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "continue", "hint": "Press Enter" },
                "response": { "type": "acknowledged" },
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn backend_operation() {
        assert_json(
            &StepFact::BackendOperation {
                step: StepId::new("s1"),
                kind: "generate_keypair".to_string(),
                inputs: json!({ "algorithm": "rsa", "bits": 4096 }),
                outputs: json!({ "key_id": "k1" }),
                fingerprint: Some("sha256:deadbeef".to_string()),
            },
            &json!({
                "type": "backend_operation",
                "step": "s1",
                "kind": "generate_keypair",
                "inputs": { "algorithm": "rsa", "bits": 4096 },
                "outputs": { "key_id": "k1" },
                "fingerprint": "sha256:deadbeef",
            }),
        );
    }

    #[test]
    fn attestation_recorded() {
        assert_json(
            &StepFact::AttestationRecorded {
                step: StepId::new("s1"),
                role: RoleId::new("crypto_officer"),
                statement: "I confirm.".to_string(),
                at: ts(),
            },
            &json!({
                "type": "attestation_recorded",
                "step": "s1",
                "role": "crypto_officer",
                "statement": "I confirm.",
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn artifact_written() {
        assert_json(
            &StepFact::ArtifactWritten {
                step: StepId::new("s1"),
                name: "root.crt".to_string(),
                path: "/out/root.crt".into(),
                sha256: "a".repeat(64),
            },
            &json!({
                "type": "artifact_written",
                "step": "s1",
                "name": "root.crt",
                "path": "/out/root.crt",
                "sha256": "a".repeat(64),
            }),
        );
    }

    #[test]
    fn deviation_recorded() {
        assert_json(
            &StepFact::DeviationRecorded {
                step: Some(StepId::new("s1")),
                text: "phone rang".to_string(),
                at: ts(),
            },
            &json!({
                "type": "deviation_recorded",
                "step": "s1",
                "text": "phone rang",
                "at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn step_completed_completed() {
        assert_json(
            &StepFact::StepCompleted {
                id: StepId::new("s1"),
                outcome: StepOutcome::Completed {
                    message: "done".to_string(),
                },
                completed_at: ts(),
            },
            &json!({
                "type": "step_completed",
                "id": "s1",
                "outcome": { "status": "completed", "message": "done" },
                "completed_at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn ceremony_completed() {
        assert_json(
            &StepFact::CeremonyCompleted { completed_at: ts() },
            &json!({
                "type": "ceremony_completed",
                "completed_at": "2026-01-02T03:04:05Z",
            }),
        );
    }

    #[test]
    fn ceremony_failed() {
        assert_json(
            &StepFact::CeremonyFailed {
                error: ErrorRecord::new("aborted", "ceremony aborted by operator"),
                failed_at: ts(),
            },
            &json!({
                "type": "ceremony_failed",
                "error": { "kind": "aborted", "message": "ceremony aborted by operator" },
                "failed_at": "2026-01-02T03:04:05Z",
            }),
        );
    }
}
