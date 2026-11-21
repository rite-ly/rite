//! Test-only helpers for action implementors.
//!
//! Provides a [`ReporterHarness`] that owns the channels and an
//! [`InMemorySink`] needed to construct a
//! [`Reporter`] in unit and integration tests, so downstream crates can
//! exercise their actions without dealing with channel plumbing.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, unbounded};
use jiff::Timestamp;
use rite_model::{ArtifactId, Step, StepId};
use rite_model::{EventTime, EventTimeRangeError};

use crate::actions::ArtifactValue;
use crate::backend::BackendRegistry;
use crate::clock::{Clock, SystemClock};
use crate::executor::ExecutionError;
use crate::protocol::{ExecEvent, PromptId, Response, UiCommand, UiSignal};
use crate::reporter::Reporter;
use crate::runner::{ActionRegistry, RunBackends, merge_step_result, run_step};
use crate::state::ExecutionState;
use crate::transcript_sink::{InMemorySink, JsonlFileSink, TranscriptSink};
use rite_model::{Sha256Digest, StepFact, TranscriptHeader};

/// Owns the channels and sink needed to build a [`Reporter`] for tests.
///
/// The matching event receiver is kept alive for the harness's lifetime,
/// so a reporter built from [`Self::reporter`] never sees a spurious
/// disconnect while emitting facts. Its commands are the ones queued when
/// it was built, and nothing more: a prompt with no answer left fails as a
/// disconnect rather than waiting for one that cannot come.
pub struct ReporterHarness {
    sink: InMemorySink,
    event_tx: Sender<ExecEvent>,
    event_rx: Receiver<ExecEvent>,
    cmd_tx: Sender<UiCommand>,
    cmd_rx: Receiver<UiCommand>,
    /// The queued commands a reporter reads, from a channel whose sender
    /// is already dropped.
    step_rx: Receiver<UiCommand>,
    next_response_id: u64,
    clock: Arc<dyn Clock>,
}

impl ReporterHarness {
    /// Build a harness with empty channels, an empty sink and the system
    /// clock.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        Self {
            sink: begun_sink(),
            event_tx,
            event_rx,
            cmd_tx,
            cmd_rx,
            step_rx: unbounded().1,
            next_response_id: 0,
            clock: Arc::new(SystemClock),
        }
    }

    /// Use `clock` as the run clock of the reporters this harness builds.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The narration lines logged since the last call, in order.
    ///
    /// Reading them drains the reporter's event channel: the facts, prompts
    /// and other signals sent since the last call are discarded.
    pub fn logged(&self) -> Vec<String> {
        self.event_rx
            .try_iter()
            .filter_map(|event| match event {
                ExecEvent::Signal(UiSignal::LogLine { text, .. }) => Some(text),
                _ => None,
            })
            .collect()
    }

    /// Pre-queue a response to the next prompt the action under test will issue.
    ///
    /// Prompt ids start at 0 and increase by one per prompt, so queued
    /// responses are matched in issue order: the first call answers the first
    /// prompt, the second answers the second, and so on. The reporter reads
    /// commands from an unbounded channel, so queuing before `execute` is
    /// enough and no second thread is needed.
    ///
    /// Assumes a single reporter built from this harness (the id sequence is
    /// not reset by [`Self::reporter`]); that matches every current test.
    pub fn enqueue_response(&mut self, response: Response) {
        let prompt_id = PromptId::new(self.next_response_id);
        self.next_response_id = self.next_response_id.wrapping_add(1);
        // The receiver is held by the harness for its lifetime, so this send
        // cannot disconnect.
        let _ = self.cmd_tx.send(UiCommand::PromptResponse {
            prompt_id,
            response,
        });
    }

    /// Pre-queue a second answer to the prompt the last queued response
    /// answered, for when that one is refused: a refused prompt is asked
    /// again under the same id.
    pub fn enqueue_retry(&mut self, response: Response) {
        let prompt_id = PromptId::new(self.next_response_id.wrapping_sub(1));
        let _ = self.cmd_tx.send(UiCommand::PromptResponse {
            prompt_id,
            response,
        });
    }

    /// Build a reporter scoped to the given step. The reporter borrows
    /// the harness for its lifetime.
    ///
    /// The entropy source is seeded with a fixed test seed, mirroring the
    /// runner, so actions that draw values (serials, nonces) work out of the
    /// box. Tests that need a specific seed can call
    /// [`Reporter::seed_entropy`] again.
    pub fn reporter(&mut self, step: StepId) -> Reporter<'_> {
        // What an earlier reporter left, then what was queued since, in a
        // channel that ends once they are read.
        let (tx, rx) = unbounded();
        for cmd in self.step_rx.try_iter().chain(self.cmd_rx.try_iter()) {
            let _ = tx.send(cmd);
        }
        self.step_rx = rx;
        let mut reporter = Reporter::new(
            &self.event_tx,
            &self.step_rx,
            &mut self.sink,
            Arc::clone(&self.clock),
        );
        reporter.set_current_step(Some(step));
        reporter.seed_entropy(b"rite-test-harness-seed");
        reporter
    }

    /// Facts recorded by the harness's transcript sink, in order.
    #[must_use]
    pub fn facts(&self) -> &[StepFact] {
        self.sink.facts()
    }
}

impl Default for ReporterHarness {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs resolved steps one at a time through the executor's own step path,
/// for a test that needs to see each step's outcome and artifacts.
///
/// There is no operator: a step is not paced, and a retry prompt has no answer
/// unless one is queued on the harness.
pub struct StepRunner {
    actions: ActionRegistry,
    backends: BackendRegistry,
    bound: HashSet<String>,
    state: ExecutionState,
    harness: ReporterHarness,
    /// The id the next prompt takes, carried from step to step.
    next_prompt_id: u64,
}

impl StepRunner {
    /// A runner with no artifacts, dispatching to `actions` and `backends`.
    #[must_use]
    pub fn new(actions: ActionRegistry, backends: BackendRegistry) -> Self {
        Self {
            actions,
            backends,
            bound: HashSet::new(),
            state: ExecutionState::new(HashMap::new(), HashMap::new(), HashMap::new(), false),
            harness: ReporterHarness::new(),
            next_prompt_id: 0,
        }
    }

    /// Make `value` available to later steps as the material `id`.
    pub fn add_material(&mut self, id: ArtifactId, value: ArtifactValue) {
        self.state.artifacts.insert(id, value);
    }

    /// Declare `key` as the material `id`, a key its backend already holds,
    /// bound by the first step that reads it.
    pub fn add_held_key(&mut self, id: ArtifactId, key: rite_model::HeldKey) {
        self.state.held_keys.insert(id, key);
    }

    /// Declare `credential`, a credential its backend has, for the steps
    /// that read it.
    pub fn add_credential(&mut self, credential: rite_model::Credential) {
        self.state
            .credentials
            .insert(credential.id.clone(), credential);
    }

    /// Run `step`, and keep what it produces for later steps.
    ///
    /// # Errors
    ///
    /// Returns what would end the run at this step.
    pub fn run(&mut self, step: &Step) -> Result<(), ExecutionError> {
        // A reporter per step, numbering prompts on from the last, so
        // answers queued for a whole run reach the steps that ask.
        let mut reporter = self.harness.reporter(step.id.clone());
        reporter.continue_prompt_ids(self.next_prompt_id);
        let mut backends = RunBackends {
            registry: &mut self.backends,
            bound: &mut self.bound,
        };
        let result = run_step(
            step,
            &self.actions,
            &mut self.state,
            &mut reporter,
            &mut backends,
            false,
        );
        self.next_prompt_id = reporter.next_prompt_id();
        merge_step_result(&mut self.state, result?);
        Ok(())
    }

    /// The artifact `id`, if a material or a step put it there.
    #[must_use]
    pub fn artifact(&self, id: &ArtifactId) -> Option<&ArtifactValue> {
        self.state.artifacts.get(id)
    }

    /// The bytes of the artifact `id`, as a step reading it would see them.
    #[must_use]
    pub fn artifact_bytes(&self, id: &ArtifactId) -> Option<&[u8]> {
        crate::resolve_artifact_bytes(&self.state.artifacts, id, None).ok()
    }

    /// Queue the answer to the next prompt a step asks: a PIN, or whether to
    /// retry a failed attempt.
    pub fn enqueue_response(&mut self, response: Response) {
        self.harness.enqueue_response(response);
    }

    /// Facts recorded so far, in order.
    #[must_use]
    pub fn facts(&self) -> &[StepFact] {
        self.harness.facts()
    }
}

/// A header for tests: a fixed run id, not a dry run.
#[must_use]
pub fn test_header() -> TranscriptHeader {
    TranscriptHeader::new("rite test", &"0".repeat(32), false)
}

/// An in-memory sink with [`test_header`] already written, ready to record
/// facts.
///
/// # Panics
///
/// Never in practice: writing the first header to a fresh in-memory sink
/// cannot fail.
#[must_use]
#[allow(clippy::expect_used)]
pub fn begun_sink() -> InMemorySink {
    let mut sink = InMemorySink::new();
    sink.begin(&test_header())
        .expect("a fresh in-memory sink takes a header");
    sink
}

/// Write `transcript.jsonl` in `dir`: [`test_header`], then each fact at its
/// default level and [`fixed_test_time`]. Returns the fingerprint.
///
/// # Errors
///
/// Returns the I/O error if the file cannot be created or written.
pub fn write_transcript(
    dir: &std::path::Path,
    facts: &[StepFact],
) -> std::io::Result<Sha256Digest> {
    let mut sink = JsonlFileSink::create(dir)?;
    sink.begin(&test_header())?;
    for fact in facts {
        sink.record(fixed_test_time(), fact.default_level(), fact)?;
    }
    sink.finalize()
}

/// A `CeremonyStarted` fact for tests, over a fixed template digest.
#[must_use]
pub fn ceremony_started(name: &str) -> StepFact {
    StepFact::CeremonyStarted {
        name: name.to_string(),
        template: Sha256Digest::of(b"test ceremony"),
    }
}

/// A fixed instant for tests that need a deterministic event time. Arbitrary
/// but stable, so recorded `at` values and snapshots stay reproducible.
#[must_use]
#[allow(clippy::expect_used)]
pub fn fixed_test_time() -> EventTime {
    EventTime::from_timestamp(Timestamp::constant(1_700_000_000, 0))
        .expect("2023 is inside the years 0000 to 9999")
}

/// Wrap a fact into an [`ExecEvent::Fact`] stamped with [`fixed_test_time`],
/// for frontend tests that feed synthetic events into a driver.
#[must_use]
pub fn fact_event(fact: StepFact) -> ExecEvent {
    ExecEvent::Fact {
        at: fixed_test_time(),
        fact,
    }
}

/// A [`Clock`] frozen at a caller-chosen instant, for asserting
/// that event times come from the injected clock rather than the wall clock.
pub struct FixedClock(pub EventTime);

impl Clock for FixedClock {
    fn now(&self) -> Result<EventTime, EventTimeRangeError> {
        Ok(self.0)
    }
}
