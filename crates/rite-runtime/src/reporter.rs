//! Action-facing handle for emitting events and prompting the operator.
//!
//! The [`Reporter`] is held by the executor and threaded into every action
//! handler. It is the only way handlers interact with the outside world ,
//! they cannot write to the transcript, send to the UI channel, or read
//! commands directly. This keeps the audit surface narrow and consistent.
//!
//! # Responsibilities
//!
//! - **Facts**: [`Reporter::fact`] records a [`StepFact`] to the inline
//!   [`TranscriptSink`] and forwards it to the UI as [`ExecEvent::Fact`].
//! - **Signals**: [`Reporter::log`] and [`Reporter::progress`] emit
//!   [`UiSignal`]s that never touch the transcript.
//! - **Prompts**: [`Reporter::prompt`] emits an [`ExecEvent::AwaitPrompt`],
//!   blocks for a matching response, validates it, and automatically
//!   records [`StepFact::PromptAnswered`] on acceptance.
//! - **Cooperative cancellation**: [`Reporter::check_abort`] drains any
//!   pending [`UiCommand`]s, returning [`ReporterError::Aborted`] if the
//!   operator requested abort.
//!
//! While blocking for a prompt response, the reporter also processes any
//! [`UiCommand::LogDeviation`] and [`UiCommand::Abort`] commands that
//! arrive, so deviations are recorded with no lag and abort interrupts
//! the prompt cleanly.

use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use rite_model::{ErrorClass, ErrorRecord, Prompt, ResponseRecord, StepFact, StepId};
use thiserror::Error;

use crate::clock::Clock;
use crate::entropy::CeremonyRandom;
use crate::protocol::{ExecEvent, Icon, PromptId, Response, UiCommand, UiSignal};
use crate::transcript_sink::TranscriptSink;

/// Errors that can arise while emitting events or awaiting a response.
#[derive(Debug, Error)]
pub enum ReporterError {
    /// The operator requested an abort. Propagated up through the action
    /// handler so the executor can unwind to a clean failure.
    #[error("ceremony aborted by operator")]
    Aborted,
    /// The UI thread disconnected from one of the channels. The executor
    /// treats this as a fatal failure (the operator is no longer reachable).
    #[error("frontend channel disconnected")]
    Disconnected,
    /// Failed to persist a fact to the transcript sink.
    #[error("transcript write failed: {0}")]
    Transcript(#[from] std::io::Error),
    /// Reporter was asked to emit a step-scoped signal but no step is set.
    #[error("internal: no current step set for {0}")]
    NoCurrentStep(&'static str),
    /// An action drew the same `(step, purpose)` twice. A purpose is drawn at
    /// most once per step; a repeat would reuse the value, so it is a bug in
    /// the action and fails the ceremony.
    #[error("duplicate entropy draw for purpose '{purpose}' in step '{step}'")]
    DuplicateDraw {
        /// Step that issued the duplicate draw.
        step: StepId,
        /// Purpose drawn more than once.
        purpose: String,
    },
    /// A value was drawn before the entropy source was seeded. The runner
    /// installs the machine seed at ceremony start, before any step can run,
    /// so this is an internal ordering bug, never an operator-reachable state.
    #[error("internal: entropy source drawn before it was seeded")]
    Unseeded,
    /// An action requested more bytes than a single `HKDF-Expand` can produce
    /// ([`MAX_DRAW_LEN`](crate::entropy::MAX_DRAW_LEN) bytes). The draw side
    /// rejects it here so the derivation fails cleanly instead of panicking
    /// inside `expand`. Every value a ceremony draws (nonces, serials,
    /// challenges) is far below this, so a request beyond it is an action bug.
    #[error("entropy draw of {len} bytes exceeds the {max}-byte HKDF-Expand limit")]
    DrawTooLong {
        /// Requested draw length in bytes.
        len: usize,
        /// The `HKDF-Expand` output limit.
        max: usize,
    },
}

impl ReporterError {
    /// Convert this error into an [`ErrorRecord`] suitable for the transcript.
    #[must_use]
    pub fn to_error_record(&self) -> ErrorRecord {
        let (class, kind) = match self {
            ReporterError::Aborted => (ErrorClass::Abort, "aborted"),
            ReporterError::Disconnected => (ErrorClass::Integrity, "frontend_disconnected"),
            ReporterError::Transcript(_) => (ErrorClass::Integrity, "transcript_io"),
            ReporterError::NoCurrentStep(_) => (ErrorClass::Integrity, "internal_no_current_step"),
            ReporterError::DuplicateDraw { .. } => {
                (ErrorClass::Integrity, "duplicate_entropy_draw")
            }
            ReporterError::Unseeded => (ErrorClass::Integrity, "internal_entropy_unseeded"),
            ReporterError::DrawTooLong { .. } => (ErrorClass::Integrity, "entropy_draw_too_long"),
        };
        ErrorRecord::new(class, kind, self.to_string())
    }
}

/// Action-facing handle threaded into every action handler.
pub struct Reporter<'a> {
    event_tx: &'a Sender<ExecEvent>,
    cmd_rx: &'a Receiver<UiCommand>,
    transcript: &'a mut dyn TranscriptSink,
    next_prompt_id: u64,
    current_step: Option<StepId>,
    /// The ceremony entropy source: the single auditable origin of every
    /// random value drawn during the run. `None` until the runner seeds it at
    /// ceremony start; a draw before then is an internal ordering bug and fails
    /// loudly rather than deriving from a stand-in seed.
    random: Option<CeremonyRandom>,
    /// The run clock. Read once per fact in [`Reporter::fact`] to stamp the
    /// event time onto both the transcript line and the live UI event.
    clock: Arc<dyn Clock>,
    /// Count of side-effect facts ([`StepFact::is_side_effect`]) emitted over
    /// the whole run. The executor snapshots this before a step attempt and
    /// compares afterwards: if the attempt performed work on the world (a
    /// backend operation, an artifact, an entropy draw) it is no longer
    /// safely re-executable, so a transient error is not retried. Interaction
    /// records like an answered prompt do not count: re-running the attempt
    /// just prompts again.
    side_effects_emitted: u64,
}

impl<'a> Reporter<'a> {
    /// Build a reporter bound to the given channels, transcript sink, and clock.
    pub fn new(
        event_tx: &'a Sender<ExecEvent>,
        cmd_rx: &'a Receiver<UiCommand>,
        transcript: &'a mut dyn TranscriptSink,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            event_tx,
            cmd_rx,
            transcript,
            next_prompt_id: 0,
            current_step: None,
            random: None,
            clock,
            side_effects_emitted: 0,
        }
    }

    /// Number of side-effect facts emitted so far in this run. Used by the
    /// executor to detect whether a step attempt performed work on the world
    /// before failing, which makes it unsafe to re-execute.
    #[must_use]
    pub fn side_effects_emitted(&self) -> u64 {
        self.side_effects_emitted
    }

    /// Install the machine seed for the entropy source.
    ///
    /// Called once by the runner at ceremony start, before any step can draw.
    /// Until this runs the source is absent and any draw fails. The caller is
    /// responsible for recording the corresponding [`StepFact::EntropySeeded`]
    /// so the source stays reconstructible from the transcript.
    pub fn seed_entropy(&mut self, m: &[u8]) {
        self.random = Some(CeremonyRandom::from_machine_seed(m));
    }

    /// Set the step that subsequent log lines and progress signals are
    /// attributed to. Called by the executor at each step boundary.
    pub fn set_current_step(&mut self, step: Option<StepId>) {
        self.current_step = step;
    }

    /// The current step, if any. Mostly useful for tests.
    #[must_use]
    pub fn current_step(&self) -> Option<&StepId> {
        self.current_step.as_ref()
    }

    /// Record a transcript-worthy fact.
    ///
    /// Facts are the audit record: everything durable flows through here, and
    /// it comes from an action in the plan (plus the runner's own lifecycle
    /// facts). Writes to the transcript sink synchronously, then forwards to
    /// the UI as [`ExecEvent::Fact`]. The transcript is flushed before the UI
    /// observes the fact. To surface something to the operator *without*
    /// recording it, use [`Reporter::signal`] / [`Reporter::log`] instead.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Transcript`] if the sink fails to persist,
    /// or [`ReporterError::Disconnected`] if the frontend is gone.
    pub fn fact(&mut self, fact: StepFact) -> Result<(), ReporterError> {
        // Stamp the event time once, from the run clock, and use it for both
        // the durable record and the live UI event so they never disagree.
        let at = self.clock.now();
        self.transcript.record(at, &fact)?;
        if fact.is_side_effect() {
            self.side_effects_emitted = self.side_effects_emitted.saturating_add(1);
        }
        self.event_tx
            .send(ExecEvent::Fact { at, fact })
            .map_err(|_| ReporterError::Disconnected)?;
        Ok(())
    }

    /// Draw `len` bytes from the ceremony entropy source for `purpose`.
    ///
    /// The generic primitive behind every nonce, certificate serial, and
    /// challenge: the caller names a purpose, the source derives the value
    /// from the current epoch seed and records an [`StepFact::EntropyDrawn`]
    /// carrying the derivation path and value, so `rite verify` can re-derive
    /// it. Requires a current step (the path is step-scoped).
    ///
    /// # Errors
    ///
    /// [`ReporterError::NoCurrentStep`] if called outside a step, or
    /// [`ReporterError::Transcript`] / [`ReporterError::Disconnected`] if the
    /// fact cannot be emitted.
    pub fn draw(&mut self, purpose: &str, len: usize) -> Result<Vec<u8>, ReporterError> {
        if len > crate::entropy::MAX_DRAW_LEN {
            return Err(ReporterError::DrawTooLong {
                len,
                max: crate::entropy::MAX_DRAW_LEN,
            });
        }
        let step = self
            .current_step
            .clone()
            .ok_or(ReporterError::NoCurrentStep("draw"))?;
        let random = self.random.as_mut().ok_or(ReporterError::Unseeded)?;
        let drawn =
            random
                .draw(&step, purpose, len)
                .ok_or_else(|| ReporterError::DuplicateDraw {
                    step: step.clone(),
                    purpose: purpose.to_string(),
                })?;
        self.fact(StepFact::EntropyDrawn {
            step,
            path: drawn.path,
            value: base16ct::lower::encode_string(&drawn.value),
        })?;
        Ok(drawn.value)
    }

    /// Fold a human entropy contribution into the seed, advancing the ratchet.
    ///
    /// The contribution is public, witnessed entropy (the HMAC *message* keyed
    /// by the prior seed, never a secret), so any input is safe and only adds
    /// unpredictability. Records an [`StepFact::EntropyContributed`] carrying
    /// the verbatim contribution and the new epoch, so the chain re-folds
    /// identically on verification. Requires a current step.
    ///
    /// # Errors
    ///
    /// [`ReporterError::NoCurrentStep`] if called outside a step, or
    /// [`ReporterError::Transcript`] / [`ReporterError::Disconnected`] if the
    /// fact cannot be emitted.
    pub fn fold_entropy(&mut self, contribution: &str) -> Result<(), ReporterError> {
        let step = self
            .current_step
            .clone()
            .ok_or(ReporterError::NoCurrentStep("fold_entropy"))?;
        let random = self.random.as_mut().ok_or(ReporterError::Unseeded)?;
        random.fold(contribution.as_bytes());
        let epoch = random.epoch();
        self.fact(StepFact::EntropyContributed {
            step,
            epoch,
            contribution: contribution.to_string(),
        })
    }

    /// Emit a raw [`UiSignal`]. Never recorded to the transcript.
    ///
    /// Signals are ephemeral operator-assistance: a frontend may drop any of
    /// them without affecting correctness or the transcript. They are never
    /// promoted into the audit record; use [`Reporter::fact`] for anything
    /// that must persist. Most callers should use the specialized helpers
    /// ([`Reporter::log`] for narration, [`Reporter::progress`] for spinners).
    /// This method exists for structured signals (e.g. the pre-ceremony
    /// overview, the system snapshot) that don't fit either shape.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Disconnected`] if the frontend is gone.
    pub fn signal(&mut self, signal: UiSignal) -> Result<(), ReporterError> {
        self.event_tx
            .send(ExecEvent::Signal(signal))
            .map_err(|_| ReporterError::Disconnected)?;
        Ok(())
    }

    /// Emit a UI-only narration line. Never recorded to the transcript.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Disconnected`] if the frontend is gone.
    pub fn log(&mut self, icon: Icon, text: impl Into<String>) -> Result<(), ReporterError> {
        let signal = UiSignal::LogLine {
            step: self.current_step.clone(),
            icon,
            text: text.into(),
        };
        self.event_tx
            .send(ExecEvent::Signal(signal))
            .map_err(|_| ReporterError::Disconnected)?;
        Ok(())
    }

    /// Emit a progress signal (e.g. spinner phase, completion fraction).
    ///
    /// Never recorded to the transcript. Requires a current step.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Disconnected`] or
    /// [`ReporterError::NoCurrentStep`].
    pub fn progress(
        &mut self,
        phase: impl Into<String>,
        fraction: Option<f32>,
    ) -> Result<(), ReporterError> {
        let step = self
            .current_step
            .clone()
            .ok_or(ReporterError::NoCurrentStep("progress"))?;
        let signal = UiSignal::Progress {
            step,
            phase: phase.into(),
            fraction,
        };
        self.event_tx
            .send(ExecEvent::Signal(signal))
            .map_err(|_| ReporterError::Disconnected)?;
        Ok(())
    }

    /// Drain any pending commands. Returns [`ReporterError::Aborted`] if an
    /// abort command is in the queue.
    ///
    /// Designed to be called liberally during long-running backend
    /// operations. `try_recv` on a crossbeam channel is on the order of
    /// nanoseconds, so the cost is negligible.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Aborted`] if abort was requested, or
    /// [`ReporterError::Disconnected`] if the frontend went away.
    pub fn check_abort(&mut self) -> Result<(), ReporterError> {
        loop {
            match self.cmd_rx.try_recv() {
                Ok(cmd) => self.handle_offline_command(cmd)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Err(ReporterError::Disconnected),
            }
        }
    }

    /// Issue a prompt and block until a validated response is received.
    ///
    /// While blocking, also handles [`UiCommand::Abort`] and
    /// [`UiCommand::LogDeviation`] so the user can deviate or abort mid-prompt.
    /// On rejection by the runtime's validator, re-emits the prompt with
    /// the rejection reason attached so the frontend can surface it.
    ///
    /// Automatically emits [`StepFact::PromptAnswered`] when the response
    /// is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ReporterError::Aborted`] if abort was requested,
    /// [`ReporterError::Disconnected`] if the frontend went away, or
    /// [`ReporterError::Transcript`] if the fact cannot be recorded.
    pub fn prompt(&mut self, prompt: &Prompt) -> Result<Response, ReporterError> {
        let step = self.current_step.clone();
        let prompt_id = self.allocate_prompt_id();
        let mut previous_rejection: Option<String> = None;

        loop {
            self.event_tx
                .send(ExecEvent::AwaitPrompt {
                    step: step.clone(),
                    prompt_id,
                    prompt: prompt.clone(),
                    previous_attempt_rejected_because: previous_rejection.take(),
                })
                .map_err(|_| ReporterError::Disconnected)?;

            // Inner loop: drain commands until a matching, validated response arrives.
            loop {
                let cmd = self
                    .cmd_rx
                    .recv()
                    .map_err(|_| ReporterError::Disconnected)?;
                match cmd {
                    UiCommand::Abort => return Err(ReporterError::Aborted),
                    UiCommand::LogDeviation { text } => {
                        self.emit_deviation(step.clone(), text)?;
                    }
                    UiCommand::PromptResponse {
                        prompt_id: incoming_id,
                        response,
                    } => {
                        if incoming_id != prompt_id {
                            // Stale response from a previous prompt, drop.
                            continue;
                        }
                        match validate(prompt, &response) {
                            Ok(()) => {
                                let record = response_to_record(&response);
                                self.fact(StepFact::PromptAnswered {
                                    step: step.clone(),
                                    prompt: prompt.clone(),
                                    response: record,
                                })?;
                                return Ok(response);
                            }
                            Err(reason) => {
                                previous_rejection = Some(reason);
                                break; // re-emit AwaitPrompt with rejection
                            }
                        }
                    }
                }
            }
        }
    }

    fn allocate_prompt_id(&mut self) -> PromptId {
        let id = PromptId::new(self.next_prompt_id);
        self.next_prompt_id = self.next_prompt_id.wrapping_add(1);
        id
    }

    /// Handle a command that arrives outside of a prompt-wait context.
    fn handle_offline_command(&mut self, cmd: UiCommand) -> Result<(), ReporterError> {
        match cmd {
            UiCommand::Abort => Err(ReporterError::Aborted),
            UiCommand::LogDeviation { text } => {
                let step = self.current_step.clone();
                self.emit_deviation(step, text)
            }
            // A stray prompt response outside any prompt context is dropped.
            UiCommand::PromptResponse { .. } => Ok(()),
        }
    }

    fn emit_deviation(&mut self, step: Option<StepId>, text: String) -> Result<(), ReporterError> {
        self.fact(StepFact::DeviationRecorded { step, text })
    }
}

/// Convert an in-flight [`Response`] into its redacted, serializable form.
///
/// The boundary where a plaintext secret is dropped. Lives here (next to
/// `Response`) rather than on `ResponseRecord` so that `secrecy` stays a
/// runtime-only dependency.
fn response_to_record(response: &Response) -> ResponseRecord {
    match response {
        Response::Bool(b) => ResponseRecord::Bool { value: *b },
        Response::Text(t) => ResponseRecord::Text { value: t.clone() },
        Response::Secret(_) => ResponseRecord::SecretRedacted {},
        Response::Acknowledge => ResponseRecord::Acknowledged,
    }
}

/// Validate a response against the prompt's constraints.
///
/// Returns `Ok(())` if the response is acceptable, or `Err(reason)` if it
/// must be rejected. The reason is surfaced to the frontend through
/// [`ExecEvent::AwaitPrompt::previous_attempt_rejected_because`].
///
/// Two checks are performed:
/// 1. **Shape**: the response variant matches the prompt variant (e.g.
///    a [`Prompt::Confirm`] requires a [`Response::Bool`]). A mismatch
///    indicates a frontend bug.
/// 2. **Content**: the [`Prompt::Text`] validator is applied to the text,
///    and [`Prompt::Literal`] requires byte-for-byte equality with the
///    expected string.
fn validate(prompt: &Prompt, response: &Response) -> Result<(), String> {
    match (prompt, response) {
        (Prompt::Confirm { .. }, Response::Bool(_))
        | (Prompt::Continue { .. }, Response::Acknowledge)
        | (Prompt::Secret { .. }, Response::Secret(_)) => Ok(()),

        (Prompt::Text { validator, .. }, Response::Text(value)) => {
            apply_validator(validator, value)
        }

        (Prompt::Literal { expected, .. }, Response::Text(value)) => {
            if value == expected {
                Ok(())
            } else {
                Err(format!("expected exactly: {expected}"))
            }
        }

        _ => Err("response shape does not match prompt shape".to_string()),
    }
}

fn apply_validator(spec: &rite_model::ValidatorSpec, value: &str) -> Result<(), String> {
    use rite_model::ValidatorSpec;
    match spec {
        ValidatorSpec::NonEmpty => {
            if value.trim().is_empty() {
                Err("value must not be empty".to_string())
            } else {
                Ok(())
            }
        }
        // Regex validation requires an additional dependency; not yet wired in.
        ValidatorSpec::Regex(_) => Err("regex validation is not yet implemented".to_string()),
        // Named predicates will land alongside specific ceremony actions
        // that need them (serial numbers, hex strings, etc.).
        ValidatorSpec::Predefined(name) => Err(format!("unknown validator: {name}")),
        _ => Err("unknown validator variant".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;
    use secrecy::SecretString;

    use super::*;
    use crate::clock::SystemClock;
    use crate::transcript_sink::InMemorySink;
    use rite_model::ValidatorSpec;

    fn ids(step: &str) -> StepId {
        StepId::new(step)
    }

    fn test_clock() -> Arc<dyn Clock> {
        Arc::new(SystemClock)
    }

    #[test]
    fn fact_stamps_event_from_the_injected_clock() {
        use crate::test_support::{FixedClock, fixed_test_time};

        let (event_tx, event_rx) = unbounded();
        let (_cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let mut sink = InMemorySink::new();
        let fixed = fixed_test_time();
        let mut reporter =
            Reporter::new(&event_tx, &cmd_rx, &mut sink, Arc::new(FixedClock(fixed)));

        reporter
            .fact(StepFact::CeremonyStarted {
                name: "T".to_string(),
            })
            .expect("fact");

        match event_rx.recv().expect("event") {
            ExecEvent::Fact { at, .. } => assert_eq!(at, fixed),
            other => panic!("expected Fact, got {other:?}"),
        }
    }

    #[test]
    fn fact_writes_to_sink_and_forwards_to_ui() {
        let (event_tx, event_rx) = unbounded();
        let (_cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        reporter
            .fact(StepFact::DeviationRecorded {
                step: Some(ids("s1")),
                text: "minor".to_string(),
            })
            .expect("emit fact");

        assert_eq!(sink.len(), 1);
        match event_rx.try_recv().expect("ui event") {
            ExecEvent::Fact {
                fact: StepFact::DeviationRecorded { text, .. },
                ..
            } => {
                assert_eq!(text, "minor");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn draw_rejects_a_length_past_the_hkdf_expand_limit() {
        // A draw beyond MAX_DRAW_LEN would panic inside `expand`; the boundary
        // rejects it as a recoverable error first. The length check precedes
        // the step/seed checks, so no seeding is needed to exercise it.
        let (event_tx, _event_rx) = unbounded();
        let (_cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        let err = reporter
            .draw("oversized", crate::entropy::MAX_DRAW_LEN.saturating_add(1))
            .expect_err("oversized draw");
        assert!(matches!(err, ReporterError::DrawTooLong { len, .. }
            if len == crate::entropy::MAX_DRAW_LEN + 1));
    }

    #[test]
    fn log_does_not_touch_transcript() {
        let (event_tx, event_rx) = unbounded();
        let (_cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        reporter.log(Icon::Info, "hello").expect("log");

        assert_eq!(sink.len(), 0);
        match event_rx.try_recv().expect("ui event") {
            ExecEvent::Signal(UiSignal::LogLine { text, .. }) => assert_eq!(text, "hello"),
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn check_abort_returns_aborted_when_abort_in_queue() {
        let (event_tx, _event_rx) = unbounded::<ExecEvent>();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        cmd_tx.send(UiCommand::Abort).expect("send");
        let err = reporter.check_abort().expect_err("abort");
        assert!(matches!(err, ReporterError::Aborted));
    }

    #[test]
    fn check_abort_processes_deviation_then_returns_ok() {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        cmd_tx
            .send(UiCommand::LogDeviation {
                text: "phone rang".to_string(),
            })
            .expect("send");
        reporter.check_abort().expect("ok");

        assert_eq!(sink.len(), 1);
        match event_rx.try_recv().expect("ui event") {
            ExecEvent::Fact {
                fact: StepFact::DeviationRecorded { text, .. },
                ..
            } => {
                assert_eq!(text, "phone rang");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    struct AwaitedPrompt {
        prompt_id: PromptId,
        rejection: Option<String>,
    }

    /// Drain `ExecEvent`s until the next `AwaitPrompt`, panicking if the
    /// channel closes first. Non-prompt events are discarded.
    fn recv_await_prompt(event_rx: &Receiver<ExecEvent>) -> AwaitedPrompt {
        loop {
            if let ExecEvent::AwaitPrompt {
                prompt_id,
                previous_attempt_rejected_because,
                ..
            } = event_rx
                .recv()
                .expect("event channel closed before AwaitPrompt")
            {
                return AwaitedPrompt {
                    prompt_id,
                    rejection: previous_attempt_rejected_because,
                };
            }
        }
    }

    /// Spawn a "frontend" thread that drains all `ExecEvent`s and feeds each
    /// `AwaitPrompt` to the supplied `respond` callback. Keeps `event_rx`
    /// alive until the channel closes, so the reporter's later `Fact` sends
    /// don't trip a spurious `Disconnected` error.
    fn spawn_frontend<F>(
        event_rx: Receiver<ExecEvent>,
        cmd_tx: Sender<UiCommand>,
        mut respond: F,
    ) -> std::thread::JoinHandle<()>
    where
        F: FnMut(PromptId, &Prompt, &Sender<UiCommand>) + Send + 'static,
    {
        std::thread::spawn(move || {
            while let Ok(ev) = event_rx.recv() {
                if let ExecEvent::AwaitPrompt {
                    prompt_id, prompt, ..
                } = ev
                {
                    respond(prompt_id, &prompt, &cmd_tx);
                }
            }
        })
    }

    #[test]
    fn prompt_round_trip_emits_await_and_records_fact() {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        let frontend = spawn_frontend(event_rx, cmd_tx, |prompt_id, _, tx| {
            tx.send(UiCommand::PromptResponse {
                prompt_id,
                response: Response::Bool(true),
            })
            .expect("send response");
        });

        let response = reporter
            .prompt(&Prompt::Confirm {
                question: "proceed?".to_string(),
                default: Some(true),
            })
            .expect("prompt");
        assert!(matches!(response, Response::Bool(true)));
        assert_eq!(sink.len(), 1);
        assert!(matches!(
            sink.facts().first(),
            Some(StepFact::PromptAnswered { .. })
        ));

        drop(event_tx);
        frontend.join().expect("frontend join");
    }

    #[test]
    fn prompt_redacts_secret_in_record() {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        let frontend = spawn_frontend(event_rx, cmd_tx, |prompt_id, _, tx| {
            tx.send(UiCommand::PromptResponse {
                prompt_id,
                response: Response::Secret(SecretString::from("hunter2".to_string())),
            })
            .expect("send response");
        });

        reporter
            .prompt(&Prompt::Secret {
                label: "PIN".to_string(),
            })
            .expect("prompt");

        match sink.facts().first().expect("fact") {
            StepFact::PromptAnswered { response, .. } => match response {
                ResponseRecord::SecretRedacted {} => {}
                other => panic!("expected redacted secret, got {other:?}"),
            },
            other => panic!("unexpected fact: {other:?}"),
        }

        drop(event_tx);
        frontend.join().expect("frontend join");
    }

    #[test]
    fn prompt_loop_handles_deviation_then_response() {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        let frontend = spawn_frontend(event_rx, cmd_tx, |prompt_id, _, tx| {
            tx.send(UiCommand::LogDeviation {
                text: "noted".to_string(),
            })
            .expect("send deviation");
            tx.send(UiCommand::PromptResponse {
                prompt_id,
                response: Response::Acknowledge,
            })
            .expect("send response");
        });

        reporter
            .prompt(&Prompt::Continue { hint: None })
            .expect("prompt");

        assert_eq!(sink.len(), 2);
        assert!(matches!(
            sink.facts().first(),
            Some(StepFact::DeviationRecorded { .. })
        ));
        assert!(matches!(
            sink.facts().get(1),
            Some(StepFact::PromptAnswered { .. })
        ));

        drop(event_tx);
        frontend.join().expect("frontend join");
    }

    #[test]
    fn validator_signature_compiles_with_predefined_variant() {
        // Sanity check: Predefined variant of ValidatorSpec is referenceable.
        let _v = ValidatorSpec::Predefined("serial_number".to_string());
    }

    #[test]
    fn non_empty_validator_rejects_empty_and_accepts_text() {
        assert!(
            super::validate(
                &Prompt::Text {
                    label: "name".to_string(),
                    validator: ValidatorSpec::NonEmpty,
                },
                &Response::Text(String::new()),
            )
            .is_err()
        );

        assert!(
            super::validate(
                &Prompt::Text {
                    label: "name".to_string(),
                    validator: ValidatorSpec::NonEmpty,
                },
                &Response::Text("Alice".to_string()),
            )
            .is_ok()
        );
    }

    #[test]
    fn non_empty_validator_rejects_whitespace_only() {
        let err = super::validate(
            &Prompt::Text {
                label: "name".to_string(),
                validator: ValidatorSpec::NonEmpty,
            },
            &Response::Text("   \t".to_string()),
        )
        .expect_err("should reject whitespace");
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn literal_validator_requires_byte_for_byte_match() {
        let prompt = Prompt::Literal {
            label: "type 'attest'".to_string(),
            expected: "attest".to_string(),
        };
        assert!(super::validate(&prompt, &Response::Text("attest".to_string())).is_ok());
        let err = super::validate(&prompt, &Response::Text("ATTEST".to_string()))
            .expect_err("case-sensitive");
        assert!(err.contains("attest"));
    }

    #[test]
    fn regex_validator_not_yet_implemented_returns_rejection() {
        let err = super::validate(
            &Prompt::Text {
                label: "id".to_string(),
                validator: ValidatorSpec::Regex(r"^[a-z]+$".to_string()),
            },
            &Response::Text("abc".to_string()),
        )
        .expect_err("regex not implemented");
        assert!(err.contains("regex"));
    }

    #[test]
    fn predefined_validator_unknown_name_rejected() {
        let err = super::validate(
            &Prompt::Text {
                label: "sn".to_string(),
                validator: ValidatorSpec::Predefined("serial_number".to_string()),
            },
            &Response::Text("AB1234".to_string()),
        )
        .expect_err("predefined unknown");
        assert!(err.contains("serial_number"));
    }

    #[test]
    fn prompt_re_emits_with_rejection_reason_when_validator_fails() {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        let mut sink = InMemorySink::new();
        let mut reporter = Reporter::new(&event_tx, &cmd_rx, &mut sink, test_clock());
        reporter.set_current_step(Some(ids("s1")));

        // Frontend: first AwaitPrompt → reply empty (rejected by validator),
        // second AwaitPrompt → carries the rejection reason, reply "Alice".
        // Then keep `event_rx` alive until the reporter drops `event_tx` so
        // its post-response `PromptAnswered` send doesn't race the channel.
        let frontend = std::thread::spawn(move || {
            let first = recv_await_prompt(&event_rx);
            assert!(first.rejection.is_none(), "first prompt has no rejection");
            cmd_tx
                .send(UiCommand::PromptResponse {
                    prompt_id: first.prompt_id,
                    response: Response::Text(String::new()),
                })
                .expect("send empty");

            let second = recv_await_prompt(&event_rx);
            assert!(
                second.rejection.is_some(),
                "second prompt carries the rejection reason",
            );
            cmd_tx
                .send(UiCommand::PromptResponse {
                    prompt_id: second.prompt_id,
                    response: Response::Text("Alice".to_string()),
                })
                .expect("send Alice");

            while event_rx.recv().is_ok() {}
        });

        let response = reporter
            .prompt(&Prompt::Text {
                label: "name".to_string(),
                validator: ValidatorSpec::NonEmpty,
            })
            .expect("prompt");
        match response {
            Response::Text(t) => assert_eq!(t, "Alice"),
            _ => panic!("expected Text"),
        }
        drop(event_tx);
        frontend.join().expect("frontend join");
    }
}
