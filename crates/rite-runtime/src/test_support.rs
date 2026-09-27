//! Test-only helpers for action implementors.
//!
//! Provides a [`ReporterHarness`] that owns the channels and an
//! [`InMemorySink`](crate::InMemorySink) needed to construct a
//! [`Reporter`] in unit and integration tests, so downstream crates can
//! exercise their actions without dealing with channel plumbing.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use crossbeam_channel::{Receiver, Sender, unbounded};
use rite_model::StepId;

use crate::clock::{Clock, SystemClock};
use crate::protocol::{ExecEvent, PromptId, Response, UiCommand};
use crate::reporter::Reporter;
use crate::transcript_sink::{InMemorySink, JsonlFileSink, TranscriptSink};
use rite_model::{Sha256Digest, StepFact, TranscriptHeader};

/// Owns the channels and sink needed to build a [`Reporter`] for tests.
///
/// The matching event receiver and command sender are kept alive for the
/// harness's lifetime, so a reporter built from [`Self::reporter`] never
/// sees a spurious disconnect while emitting facts.
pub struct ReporterHarness {
    sink: InMemorySink,
    event_tx: Sender<ExecEvent>,
    _event_rx: Receiver<ExecEvent>,
    cmd_tx: Sender<UiCommand>,
    cmd_rx: Receiver<UiCommand>,
    next_response_id: u64,
}

impl ReporterHarness {
    /// Build a harness with empty channels and an empty sink.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        Self {
            sink: begun_sink(),
            event_tx,
            _event_rx: event_rx,
            cmd_tx,
            cmd_rx,
            next_response_id: 0,
        }
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

    /// Build a reporter scoped to the given step. The reporter borrows
    /// the harness for its lifetime.
    ///
    /// The entropy source is seeded with a fixed test seed, mirroring the
    /// runner, so actions that draw values (serials, nonces) work out of the
    /// box. Tests that need a specific seed can call
    /// [`Reporter::seed_entropy`] again.
    pub fn reporter(&mut self, step: StepId) -> Reporter<'_> {
        let mut reporter = Reporter::new(
            &self.event_tx,
            &self.cmd_rx,
            &mut self.sink,
            Arc::new(SystemClock),
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
pub fn fixed_test_time() -> DateTime<Utc> {
    // `from_timestamp_nanos` is infallible, unlike the seconds-based
    // constructor, so this needs no `expect` in non-test library code.
    DateTime::from_timestamp_nanos(1_700_000_000_000_000_000)
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

/// A [`Clock`](crate::Clock) frozen at a caller-chosen instant, for asserting
/// that event times come from the injected clock rather than the wall clock.
pub struct FixedClock(pub DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
