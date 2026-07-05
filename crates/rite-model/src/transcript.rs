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
    /// Secret answer. The plaintext is never stored, and no digest of it is
    /// kept either: a hash of a low-entropy secret (such as a 6-8 digit PIV
    /// PIN) is brute-forceable from a shared transcript. The position of the
    /// enclosing `PromptAnswered` fact in the chain already records that a
    /// secret was entered at this point.
    // Note: a salted, per-run HMAC could later attest that two prompts received
    // the same secret without reintroducing the low-entropy guessing oracle.
    // Deferred until a concrete use case needs it.
    SecretRedacted {},
    /// Acknowledgement of a [`Prompt::Continue`].
    Acknowledged,
}

/// Audit classification of a bad outcome, recorded so an auditor can tell the
/// nature of a failure apart without parsing the free-form `message`.
///
/// This is the *audit* taxonomy (what an auditor sees), distinct from the
/// runtime's `Retriability` (whether a step may re-run). For a backend error
/// the two align: a retriable error is `Environmental`. They are kept separate
/// because some classes never map cleanly onto retriability (an `Abort` is a
/// decision, not an error).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// The world wasn't ready; the step's work did not happen (token absent,
    /// loose cable, PIN required).
    Environmental,
    /// The ceremony's own logic concluded badly (a verification mismatch, a
    /// refused attestation). A result, not a recoverable condition.
    Procedural,
    /// The run itself is compromised or the definition is broken (transcript
    /// write failed, channel lost, unknown action, invalid params).
    Integrity,
    /// The operator chose to stop. Not an error at all, but recorded on the
    /// terminal fact so abort is distinguishable from failure.
    Abort,
}

/// Structured error record for transcript serialization.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    /// Audit classification of this error.
    pub class: ErrorClass,
    /// Stable kind label (e.g. `aborted`, `step_failed`, `material_load_failed`).
    pub kind: String,
    /// Human-readable message.
    pub message: String,
}

impl ErrorRecord {
    /// Construct an error record.
    pub fn new(class: ErrorClass, kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            class,
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
    },
    /// A step attempt failed. Recorded per attempt, so a retried step shows
    /// `StepAttemptFailed{attempt: 1}` followed by the operator's retry
    /// decision and, on success, `StepCompleted`. The final attempt of a step
    /// that the run gives up on is followed by the terminal `CeremonyFailed`.
    StepAttemptFailed {
        /// Step whose attempt failed.
        step: StepId,
        /// 1-based attempt number within this step.
        attempt: u32,
        /// Structured error record for the failed attempt.
        error: ErrorRecord,
    },
    /// Step finished executing.
    StepCompleted {
        /// Step identifier.
        id: StepId,
        /// Outcome (completed or skipped).
        outcome: StepOutcome,
    },
    /// Ceremony finished successfully.
    ///
    /// The transcript's cryptographic identity is `SHA-256(line_bytes)`
    /// for this line, recoverable by any reader, so the fact itself
    /// carries no fingerprint field. The runtime forwards the value to
    /// frontends through an out-of-band channel event.
    CeremonyCompleted {},
    /// Ceremony failed or was aborted.
    CeremonyFailed {
        /// Structured error record.
        error: ErrorRecord,
    },
    /// The ceremony entropy source was seeded with machine randomness.
    ///
    /// Emitted once by the runner at ceremony start (run-metadata). Records
    /// the machine contribution `m` and the frozen derivation scheme so any
    /// value the ceremony later draws is re-derivable from the transcript
    /// alone. Part of the [entropy source](StepFact::EntropyDrawn) family.
    ///
    /// Like every fact, it is timed by the `at` on its chain envelope.
    EntropySeeded {
        /// Lowercase hex of the gathered machine entropy `m`.
        m: String,
        /// Provenance of `m` (e.g. `os`). A single label today; comma-separated
        /// if more than one source is ever mixed.
        source: String,
        /// Frozen derivation-scheme tag (e.g. `rite-kdf/v1`) that pins the
        /// entire construction. A verifier rejects an unrecognised value.
        derivation: String,
    },
    /// A human folded additional entropy into the seed, advancing the ratchet.
    ///
    /// Emitted by the authored `gather_entropy` step. The verbatim operator
    /// contribution is recorded so the epoch chain re-folds identically; it is
    /// public, witnessed entropy, not a secret. Timed by its enclosing step
    /// boundaries (and by the `PromptAnswered` that captured the input).
    EntropyContributed {
        /// Step under which the contribution was gathered.
        step: StepId,
        /// Epoch index produced by this fold (1 for the first contribution).
        epoch: u32,
        /// Verbatim operator contribution, fed as UTF-8 into the ratchet.
        contribution: String,
    },
    /// A value was drawn from the entropy source (a nonce, certificate serial,
    /// or challenge).
    ///
    /// Emitted whenever an action draws bytes from the entropy source. The
    /// derivation `path` plus the recorded seed let `rite verify` re-derive
    /// the value and confirm the right value reached the right consumer. Like
    /// other action-emitted evidence, it is timed by its enclosing step.
    EntropyDrawn {
        /// Step that drew the value.
        step: StepId,
        /// Derivation path `<epoch>/<step>/<purpose>`.
        path: String,
        /// Lowercase hex of the derived bytes. Its length fixes the byte count,
        /// so `rite verify` re-derives exactly this many bytes from the seed.
        value: String,
    },
}

impl StepFact {
    /// Whether this fact evidences work performed on the world: a backend
    /// operation, a written artifact, a captured attestation, or consumed
    /// entropy. Interaction records (an answered prompt, an operator
    /// deviation note) and lifecycle markers are not side effects: repeating
    /// the interaction is safe and simply produces a fresh record.
    ///
    /// The runtime's retry gate refuses to re-execute a step attempt that
    /// already emitted a side-effect fact.
    #[must_use]
    pub fn is_side_effect(&self) -> bool {
        match self {
            StepFact::BackendOperation { .. }
            | StepFact::AttestationRecorded { .. }
            | StepFact::ArtifactWritten { .. }
            | StepFact::EntropyContributed { .. }
            | StepFact::EntropyDrawn { .. } => true,
            StepFact::CeremonyStarted { .. }
            | StepFact::ActStarted { .. }
            | StepFact::StepStarted { .. }
            | StepFact::PromptAnswered { .. }
            | StepFact::DeviationRecorded { .. }
            | StepFact::StepAttemptFailed { .. }
            | StepFact::StepCompleted { .. }
            | StepFact::CeremonyCompleted {}
            | StepFact::CeremonyFailed { .. }
            | StepFact::EntropySeeded { .. } => false,
        }
    }
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
    use serde_json::json;

    fn assert_json(fact: &StepFact, expected: &serde_json::Value) {
        let actual = serde_json::to_value(fact).expect("serialize StepFact");
        assert_eq!(&actual, expected, "wire-format drift for {fact:?}");
    }

    #[test]
    fn ceremony_started() {
        assert_json(
            &StepFact::CeremonyStarted {
                name: "Root CA".to_string(),
            },
            &json!({
                "type": "ceremony_started",
                "name": "Root CA",
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
            },
            &json!({
                "type": "step_started",
                "id": "s1",
                "label": "2.1",
                "role": "crypto_officer",
                "role_name": "Crypto Officer",
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
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "confirm", "question": "Proceed?", "default": true },
                "response": { "type": "bool", "value": true },
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
                response: ResponseRecord::SecretRedacted {},
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "secret", "label": "PIN" },
                "response": { "type": "secret_redacted" },
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
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "literal", "label": "Type 'attest'", "expected": "attest" },
                "response": { "type": "text", "value": "attest" },
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
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "continue", "hint": "Press Enter" },
                "response": { "type": "acknowledged" },
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
            },
            &json!({
                "type": "attestation_recorded",
                "step": "s1",
                "role": "crypto_officer",
                "statement": "I confirm.",
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
            },
            &json!({
                "type": "deviation_recorded",
                "step": "s1",
                "text": "phone rang",
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
            },
            &json!({
                "type": "step_completed",
                "id": "s1",
                "outcome": { "status": "completed", "message": "done" },
            }),
        );
    }

    #[test]
    fn ceremony_completed() {
        assert_json(
            &StepFact::CeremonyCompleted {},
            &json!({
                "type": "ceremony_completed",
            }),
        );
    }

    #[test]
    fn ceremony_failed() {
        assert_json(
            &StepFact::CeremonyFailed {
                error: ErrorRecord::new(
                    ErrorClass::Abort,
                    "aborted",
                    "ceremony aborted by operator",
                ),
            },
            &json!({
                "type": "ceremony_failed",
                "error": {
                    "class": "abort",
                    "kind": "aborted",
                    "message": "ceremony aborted by operator",
                },
            }),
        );
    }

    #[test]
    fn step_attempt_failed() {
        assert_json(
            &StepFact::StepAttemptFailed {
                step: StepId::new("import_key"),
                attempt: 1,
                error: ErrorRecord::new(
                    ErrorClass::Environmental,
                    "backend_error",
                    "Token not present",
                ),
            },
            &json!({
                "type": "step_attempt_failed",
                "step": "import_key",
                "attempt": 1,
                "error": {
                    "class": "environmental",
                    "kind": "backend_error",
                    "message": "Token not present",
                },
            }),
        );
    }

    #[test]
    fn entropy_seeded() {
        assert_json(
            &StepFact::EntropySeeded {
                m: "00112233".to_string(),
                source: "os".to_string(),
                derivation: "rite-kdf/v1".to_string(),
            },
            &json!({
                "type": "entropy_seeded",
                "m": "00112233",
                "source": "os",
                "derivation": "rite-kdf/v1",
            }),
        );
    }

    #[test]
    fn entropy_contributed() {
        assert_json(
            &StepFact::EntropyContributed {
                step: StepId::new("roll_dice"),
                epoch: 1,
                contribution: "3 1 6 4 2 5".to_string(),
            },
            &json!({
                "type": "entropy_contributed",
                "step": "roll_dice",
                "epoch": 1,
                "contribution": "3 1 6 4 2 5",
            }),
        );
    }

    #[test]
    fn entropy_drawn() {
        assert_json(
            &StepFact::EntropyDrawn {
                step: StepId::new("issue"),
                path: "0/issue/cert-serial".to_string(),
                value: "aabbccddeeff00112233".to_string(),
            },
            &json!({
                "type": "entropy_drawn",
                "step": "issue",
                "path": "0/issue/cert-serial",
                "value": "aabbccddeeff00112233",
            }),
        );
    }
}
