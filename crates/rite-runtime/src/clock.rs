//! The ceremony clock: the single source of wall-clock time for the run.
//!
//! Event time is part of the hashed transcript line, so it is audit evidence.
//! It is owned by the executor (the authority on what happened), not by the
//! transcript sink (a swappable persistence detail): the same `at` the sink
//! writes is the `at` the live frontend sees, and it does not change if the
//! storage backend changes. Reading the clock is the one nondeterministic input
//! in the record path, so it lives behind this trait and can be faked in tests.

use rite_model::{EventTime, EventTimeRangeError};

/// Source of wall-clock time for a ceremony run.
///
/// Implementations must be cheap to call (read once per emitted fact) and
/// thread-safe: the executor runs on its own thread and shares the clock with
/// the [`Reporter`](crate::Reporter).
pub trait Clock: Send + Sync {
    /// The current instant, in UTC, to the microsecond.
    ///
    /// # Errors
    ///
    /// Returns [`EventTimeRangeError`] if the clock reads a time with no
    /// written form, before the year 0000. The run cannot record it, so the
    /// step that asked fails.
    fn now(&self) -> Result<EventTime, EventTimeRangeError>;
}

/// The real clock: reads the host wall clock via [`EventTime::now`]. The
/// default for every production run.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<EventTime, EventTimeRangeError> {
        EventTime::now()
    }
}
