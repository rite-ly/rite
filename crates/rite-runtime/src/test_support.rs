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
use crate::protocol::{ExecEvent, UiCommand};
use crate::reporter::Reporter;
use crate::transcript_sink::InMemorySink;
use rite_model::StepFact;

/// Owns the channels and sink needed to build a [`Reporter`] for tests.
///
/// The matching event receiver and command sender are kept alive for the
/// harness's lifetime, so a reporter built from [`Self::reporter`] never
/// sees a spurious disconnect while emitting facts.
pub struct ReporterHarness {
    sink: InMemorySink,
    event_tx: Sender<ExecEvent>,
    _event_rx: Receiver<ExecEvent>,
    _cmd_tx: Sender<UiCommand>,
    cmd_rx: Receiver<UiCommand>,
}

impl ReporterHarness {
    /// Build a harness with empty channels and an empty sink.
    #[must_use]
    pub fn new() -> Self {
        let (event_tx, event_rx) = unbounded();
        let (cmd_tx, cmd_rx) = unbounded();
        Self {
            sink: InMemorySink::new(),
            event_tx,
            _event_rx: event_rx,
            _cmd_tx: cmd_tx,
            cmd_rx,
        }
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
