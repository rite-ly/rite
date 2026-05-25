//! UI state. Pure data, never reaches for I/O or terminal handles.

use std::collections::VecDeque;

use rite_model::{Prompt, StepId};
use rite_runtime::{Icon, PromptId};

/// Maximum length of a deviation note. Anything longer is rejected before
/// the command is sent, keeps the transcript line readable.
pub(crate) const DEVIATION_INPUT_MAX: usize = 280;

/// Maximum number of log lines retained for the visible feed.
pub(crate) const LOG_CAPACITY: usize = 200;

/// Top-level UI state. A single [`Screen`] discriminant captures what
/// the user is looking at, so the borrow checker enforces that we can't
/// render two contradictory views.
#[derive(Debug, Clone)]
pub struct Model {
    /// Ceremony name, as soon as `CeremonyStarted` arrives.
    pub ceremony_name: Option<String>,
    /// Current screen.
    pub screen: Screen,
    /// Screen to restore when a modal is dismissed. `None` when the
    /// current screen is itself the underlying step screen.
    pub return_to: Option<Screen>,
    /// Most-recent step being executed, if any.
    pub current_step: Option<StepView>,
    /// Bounded log feed.
    pub log: VecDeque<LogLine>,
    /// Deviations recorded so far.
    pub deviations: Vec<DeviationView>,
    /// Pending prompt the runtime is awaiting an answer to.
    pub pending_prompt: Option<PendingPrompt>,
    /// Lifecycle phase.
    pub running: RunningState,
    /// Frame counter for spinner animation. Advances on every `Tick`.
    pub tick: u64,
    /// Log-tab scroll offset, counted in lines *up from the tail*.
    /// `0` = following the tail; positive = scrolled into history.
    /// Clamped to `log.len()` whenever the feed is pushed or evicted.
    pub log_scroll: usize,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            ceremony_name: None,
            screen: Screen::Step { tab: StepTab::Step },
            return_to: None,
            current_step: None,
            log: VecDeque::with_capacity(LOG_CAPACITY),
            deviations: Vec::new(),
            pending_prompt: None,
            running: RunningState::Active,
            tick: 0,
            log_scroll: 0,
        }
    }
}

impl Model {
    /// Build a fresh model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a log line, evicting the oldest entry if the bounded feed is full.
    ///
    /// When the user is scrolled up (`log_scroll > 0`), the visible content
    /// is held in place by clamping `log_scroll` to the new length.
    ///
    /// Any incoming line implies the previously-spinning operation has
    /// finished, so a trailing `Icon::Spinner` entry is converted to
    /// `Icon::Checkmark` before the new line is pushed, the spinner
    /// stops animating in the feed.
    pub(crate) fn push_log(&mut self, line: LogLine) {
        if let Some(LogLine::Entry {
            icon: icon @ Icon::Spinner,
            ..
        }) = self.log.back_mut()
        {
            *icon = Icon::Checkmark;
        }
        if self.log.len() == LOG_CAPACITY {
            self.log.pop_front();
        }
        self.log.push_back(line);
        if self.log_scroll > self.log.len() {
            self.log_scroll = self.log.len();
        }
    }

    /// Push a modal in front of the current screen, remembering what to
    /// return to when it is dismissed. Idempotent if already inside a modal.
    pub(crate) fn open_modal(&mut self, modal: Screen) {
        if self.return_to.is_none() {
            self.return_to = Some(self.screen.clone());
        }
        self.screen = modal;
    }

    /// Restore the saved screen if any. No-op when called outside a modal.
    pub(crate) fn close_modal(&mut self) {
        if let Some(prev) = self.return_to.take() {
            self.screen = prev;
        }
    }

    /// Whether anything currently rendered changes between ticks.
    ///
    /// Used by the main loop to skip a `terminal.draw` on `Msg::Tick` when
    /// the frame would be byte-identical anyway, keeps the TUI idle at 0%
    /// CPU while waiting on a prompt.
    #[must_use]
    pub fn needs_animation(&self) -> bool {
        // Invariant: `push_log` converts any prior trailing Spinner to a
        // Checkmark, so at most the tail entry can be an active spinner.
        matches!(
            self.log.back(),
            Some(LogLine::Entry {
                icon: Icon::Spinner,
                ..
            })
        )
    }
}

/// Single source of truth for which screen is visible. Because only one
/// variant is active at a time, we can't render two contradictory views
/// or sit "in a modal over a different modal", exactly one screen,
/// always.
#[derive(Debug, Clone)]
pub enum Screen {
    /// Step execution screen. Default and most common.
    Step {
        /// Active tab within the step screen.
        tab: StepTab,
    },
    /// Operator is composing a deviation note.
    DeviationModal {
        /// Partial deviation text the operator is composing.
        input: String,
    },
    /// Confirming abort. `y` sends `UiCommand::Abort`; `n` / Esc returns.
    AbortConfirm,
    /// Terminal "ceremony completed" screen.
    Completed {
        /// Final transcript fingerprint, populated by `ExecEvent::Finalized`
        /// that arrives right after the `CeremonyCompleted` fact.
        fingerprint: Option<String>,
    },
    /// Terminal "ceremony failed" screen.
    Failed {
        /// Failure reason.
        reason: String,
    },
}

impl Screen {
    /// Whether this screen is a terminal end-state (no further interaction).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Screen::Completed { .. } | Screen::Failed { .. })
    }
}

/// Active tab on the [`Screen::Step`] screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepTab {
    /// Step narration and prompt area.
    Step,
    /// Cumulative log feed and deviations.
    Log,
}

/// Lifecycle phase of the ceremony as observed by the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunningState {
    /// Ceremony is still running.
    Active,
    /// User has requested abort; waiting for the executor to unwind.
    Aborting,
    /// Done (success or failure). Loop exits.
    Done,
}

/// Snapshot of the currently-executing step.
#[derive(Debug, Clone)]
pub struct StepView {
    /// Step identifier.
    pub id: StepId,
    /// Step label as authored in the DSL.
    pub label: String,
    /// Human-readable role name for display.
    pub role_name: String,
}

/// Bounded log feed entry.
#[derive(Debug, Clone)]
pub enum LogLine {
    /// Regular log line emitted by the runtime as a `UiSignal::LogLine`.
    Entry {
        /// Visual cue.
        icon: Icon,
        /// Line text.
        text: String,
    },
    /// Visual marker pushed at every `StepStarted`. Replaces the old
    /// role-transition modal, operators see the boundary inline.
    StepDivider {
        /// Step label as authored in the DSL (e.g. `"2.1"`).
        label: String,
        /// Human-readable role name for the new step.
        role_name: String,
    },
}

/// Deviation as recorded in the live UI.
#[derive(Debug, Clone)]
pub struct DeviationView {
    /// Step in which the deviation was recorded, if any.
    pub step: Option<StepId>,
    /// Verbatim deviation text.
    pub text: String,
}

/// In-flight prompt the UI is awaiting an answer to.
#[derive(Debug, Clone)]
pub struct PendingPrompt {
    /// Prompt identifier (echoed back in the response command).
    pub prompt_id: PromptId,
    /// The prompt itself.
    pub prompt: Prompt,
    /// Partial user input (used for text/literal/secret prompts).
    pub input: String,
    /// Most recent rejection reason from the validator, if any.
    pub rejection: Option<String>,
}
