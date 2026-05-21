//! Channel vocabulary between the executor and a frontend.
//!
//! The persisted transcript schema (`StepFact` + friends) lives in
//! [`rite_model::transcript`] so non-executor consumers (`rite-script`,
//! third-party verifiers) can parse a transcript without depending on
//! the runtime. This module owns only the **in-flight** vocabulary ,
//! channel events and commands, prompt response values that carry
//! plaintext, and UI-only signals.
//!
//! - [`ExecEvent`], runtime → frontend (`Fact`, `Signal`, `AwaitPrompt`)
//! - [`UiCommand`], frontend → runtime
//! - [`Response`], in-flight user response (channel-only, never serialized;
//!   converted to [`rite_model::ResponseRecord`] when persisted)
//! - [`UiSignal`], [`Icon`], UI narration, never on disk

use rite_model::{Prompt, StepFact, StepId};
use secrecy::SecretString;

/// Identifier that pairs a prompt request with its matching response.
///
/// Issued by the runtime when emitting [`ExecEvent::AwaitPrompt`]; echoed back
/// by the frontend in [`UiCommand::PromptResponse`]. Allows the runtime to
/// reject stale or out-of-order responses unambiguously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PromptId(u64);

impl PromptId {
    /// Create a new identifier. Callers (the executor) ensure uniqueness
    /// within a ceremony run.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Underlying numeric value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

/// Visual cue for UI lines. Mapped to a glyph by the frontend.
///
/// The runtime intentionally does not provide a `Display` impl: glyphs are a
/// presentation concern owned by the frontend (the TUI animates `Spinner` over
/// multiple frames, the console picks a single character per icon, a future
/// log-only frontend may use ASCII).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Operation in progress; animated in TUI.
    Spinner,
    /// Success / completion.
    Checkmark,
    /// Failure / error.
    Cross,
    /// Informational message.
    Info,
    /// Warning (non-fatal).
    Warning,
}

/// In-process user response.
///
/// Carries plaintext secrets and is intentionally **not** `Clone` or
/// `Serialize`, both would risk accidental leakage. For transcript
/// serialization use [`rite_model::ResponseRecord`], which encodes secrets
/// as a redaction marker with a hash of the plaintext.
#[derive(Debug)]
pub enum Response {
    /// Yes / no answer.
    Bool(bool),
    /// Free-form text answer (already validated by the runtime).
    Text(String),
    /// Sensitive answer. Wrapped in [`SecretString`] to zeroize on drop.
    Secret(SecretString),
    /// Acknowledgement of a [`Prompt::Continue`].
    Acknowledge,
}

/// Transient UI-only signal. Never written to the transcript.
#[derive(Debug, Clone)]
pub enum UiSignal {
    /// Human-readable narration line for the live UI.
    LogLine {
        /// Step the line belongs to (if any).
        step: Option<StepId>,
        /// Visual cue.
        icon: Icon,
        /// Line text.
        text: String,
    },
    /// Progress signal for spinners and progress bars.
    Progress {
        /// Step the progress belongs to.
        step: StepId,
        /// Short phase label (e.g. `signing`, `verifying`).
        phase: String,
        /// Optional completion fraction in `[0.0, 1.0]`.
        fraction: Option<f32>,
    },
}

/// Event emitted by the runtime to the frontend.
#[derive(Debug)]
pub enum ExecEvent {
    /// A transcript-worthy fact. Already persisted by the transcript sink
    /// by the time it reaches the frontend.
    Fact(StepFact),
    /// A UI-only signal.
    Signal(UiSignal),
    /// The runtime is waiting for a user response. The frontend must reply
    /// with [`UiCommand::PromptResponse`] carrying the matching `prompt_id`.
    AwaitPrompt {
        /// Step that issued the prompt.
        step: StepId,
        /// Identifier echoed back in the matching response.
        prompt_id: PromptId,
        /// The prompt itself.
        prompt: Prompt,
        /// If a previous attempt was rejected by the runtime's validator,
        /// the rejection reason for the frontend to surface to the user.
        previous_attempt_rejected_because: Option<String>,
    },
    /// Sent once after the terminal fact has been recorded and the chain
    /// head is final. Out-of-band so the fact itself doesn't carry the
    /// hash of the chain it belongs to. Frontends use this to display the
    /// fingerprint on the completion screen.
    Finalized {
        /// `sha256:<hex>` of the last line in the transcript.
        fingerprint: String,
    },
}

/// Command sent by the frontend to the runtime.
#[derive(Debug)]
pub enum UiCommand {
    /// Response to an [`ExecEvent::AwaitPrompt`].
    PromptResponse {
        /// Identifier of the prompt being answered.
        prompt_id: PromptId,
        /// The response.
        response: Response,
    },
    /// Record a deviation. Available at any time.
    LogDeviation {
        /// Verbatim deviation text.
        text: String,
    },
    /// Abort the ceremony at the next safe point.
    Abort,
}
