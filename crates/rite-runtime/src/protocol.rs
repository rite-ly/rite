//! Channel vocabulary between the executor and a frontend.
//!
//! The persisted transcript schema (`StepFact` + friends) lives in
//! [`rite_model::transcript`] so non-executor consumers (`rite-render`,
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

use rite_model::{Material, MaterialId, MaterialKind, Prompt, StepFact, StepId};
use secrecy::SecretString;

use crate::system_info::{Environment, SystemInfo};

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

/// Overview of a declared material, carried by
/// [`UiSignal::CeremonyOverview`] so the live UI can render the material
/// list. In-flight only: the ceremony YAML is the source of truth for
/// material metadata, so this never reaches the transcript.
#[derive(Debug, Clone)]
pub struct MaterialOverview {
    /// Material identifier.
    pub id: MaterialId,
    /// Optional title; falls back to `id` for display.
    pub title: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Kind of material (digital file or physical item).
    pub kind: MaterialOverviewKind,
}

/// Kind of material in [`MaterialOverview`]. Mirrors the structural
/// distinction of the IR's [`MaterialKind`] without the load-time
/// implementation detail (file sources).
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum MaterialOverviewKind {
    /// File-backed digital material.
    Digital,
    /// Tangible item with optional identifier and quantity.
    Physical {
        /// Human-readable identifier (e.g. serial number).
        identifier: Option<String>,
        /// Item count for checklist rendering.
        quantity: Option<u32>,
    },
}

impl MaterialOverviewKind {
    /// Construct a [`MaterialOverviewKind::Physical`] with optional
    /// identifier and quantity. Needed because the variant is reachable
    /// only via the constructor when the enum stays `#[non_exhaustive]`.
    #[must_use]
    pub fn physical(identifier: Option<String>, quantity: Option<u32>) -> Self {
        Self::Physical {
            identifier,
            quantity,
        }
    }
}

impl MaterialOverview {
    /// Display name: the optional title, falling back to the material id.
    /// Mirrors [`Material::display_name`] for the channel-side shape.
    #[must_use]
    pub fn display_title(&self) -> &str {
        self.title.as_deref().unwrap_or(self.id.as_str())
    }

    /// Project a resolved IR [`Material`] onto the overview shape sent to
    /// frontends.
    #[must_use]
    pub fn from_material(material: &Material) -> Self {
        let kind = match &material.kind {
            MaterialKind::Digital { .. } => MaterialOverviewKind::Digital,
            MaterialKind::Physical {
                identifier,
                quantity,
            } => MaterialOverviewKind::Physical {
                identifier: identifier.clone(),
                quantity: *quantity,
            },
        };
        Self {
            id: material.id.clone(),
            title: material.title.clone(),
            description: material.description.clone(),
            kind,
        }
    }
}

/// Transient UI-only signal. Never written to the transcript.
///
/// Signals are operator-assistance, not evidence. A frontend may **drop any
/// variant** without affecting correctness or the transcript (this is exactly
/// why `headless` and `console` ignore most of them). To persist information,
/// emit a [`StepFact`] from an action; nothing here is ever promoted into the
/// transcript. See `docs/development/runtime-and-frontend.md` for the full
/// fact-vs-signal model.
///
/// The enum is intentionally **not** `#[non_exhaustive]`: it is a
/// workspace-internal protocol type, and forcing every frontend to match each
/// variant exhaustively (no wildcard arms) is the wanted compile-time check
/// that a new signal is consciously handled or ignored everywhere. Public-API
/// enums still get `#[non_exhaustive]`.
///
/// Variants fall into three sub-families:
/// - **narration**: ephemeral lines and progress ([`LogLine`](Self::LogLine),
///   [`Progress`](Self::Progress)).
/// - **one-shot structured**: a single snapshot emitted at ceremony start
///   ([`CeremonyOverview`](Self::CeremonyOverview),
///   [`SystemInfo`](Self::SystemInfo)).
/// - **re-emittable structured**: state the runtime may resend during the run;
///   the frontend replaces its view on each ([`Environment`](Self::Environment)).
#[derive(Debug, Clone)]
pub enum UiSignal {
    // --- narration ---
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

    // --- one-shot structured ---
    /// Descriptive metadata for the pre-ceremony overview screen. Emitted
    /// once, right after [`StepFact::CeremonyStarted`]. Deliberately kept
    /// out of the transcript: the YAML is the source of truth for these
    /// fields, and embedding them in the persisted record would bloat
    /// every transcript with data that the verifier could pull from the
    /// ceremony source instead.
    CeremonyOverview {
        /// Optional ceremony description.
        description: Option<String>,
        /// Declared materials, in declaration order.
        materials: Vec<MaterialOverview>,
        /// Total number of steps in the execution plan.
        step_count: usize,
    },
    /// Static build and host identity for the System tab. Emitted once, right
    /// after [`CeremonyOverview`](Self::CeremonyOverview). UI-only: machine
    /// identity that belongs in the transcript is recorded by the
    /// `machine_info` action, not fed in through this channel.
    ///
    /// Boxed: [`SystemInfo`] is much larger than the other variants, and
    /// keeping the enum (and `ExecEvent`) small avoids bloating every
    /// channel message.
    SystemInfo(Box<SystemInfo>),

    // --- re-emittable structured ---
    /// Live device inventory for the System tab. Emitted once today, but
    /// shaped to be **re-emitted**: the frontend replaces its environment view
    /// on each, so a future live observer is purely additive. UI-only, never
    /// persisted.
    Environment(Environment),
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
        /// Step that issued the prompt, if any. `None` for ceremony-level
        /// prompts (e.g. the ceremony-start confirmation emitted before
        /// the first step).
        step: Option<StepId>,
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
