//! The time a fact was recorded, in its one written form.

use std::fmt;
use std::str::FromStr;

use jiff::{RoundMode, Timestamp, TimestampRound, Unit};
use serde::{Deserialize, Serialize};

/// When a fact was recorded: a UTC instant at microsecond precision, written
/// as RFC 3339 with exactly six fractional digits and a `Z` suffix, as in
/// `2023-11-14T22:13:20.123456Z`.
///
/// The written form is an input to the transcript's commitment chain, so it
/// is the only one: parsing rejects any other spelling of the same instant.
/// Precision beyond microseconds is cut when the value is made, so the value
/// a run holds in memory is the value its transcript records.
///
/// Only an instant in the years 0000 to 9999 has that form, so only such an
/// instant makes an `EventTime`: every value prints, serializes and parses
/// back the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventTime(Timestamp);

/// Length of the written form, `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
const WRITTEN_LEN: usize = 27;

/// `0000-01-01T00:00:00Z`, the first instant with a written form. jiff's own
/// range ends inside the year 9999, so it bounds the other side.
const FIRST: Timestamp = Timestamp::constant(-62_167_219_200, 0);

#[cfg(test)]
impl schemars::JsonSchema for EventTime {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "At".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "When the fact was recorded: an RFC 3339 time in UTC with six \
                fractional digits. The chain commits to this exact string.",
            "type": "string",
            "format": "date-time",
            "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$",
        })
    }
}

/// An instant before the year 0000, which has no written form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTimeRangeError(Timestamp);

impl fmt::Display for EventTimeRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is before the year 0000 and has no written form",
            self.0
        )
    }
}

impl std::error::Error for EventTimeRangeError {}

/// A string that is not an event time in its written form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTimeFormatError(String);

impl fmt::Display for EventTimeFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' is not an RFC 3339 time in UTC with six fractional digits",
            self.0
        )
    }
}

impl std::error::Error for EventTimeFormatError {}

impl EventTime {
    /// The Unix epoch, `1970-01-01T00:00:00.000000Z`.
    pub const UNIX_EPOCH: Self = Self(Timestamp::UNIX_EPOCH);

    /// The current wall-clock time.
    ///
    /// # Errors
    ///
    /// Returns [`EventTimeRangeError`] if the host clock reads a time before
    /// the year 0000.
    pub fn now() -> Result<Self, EventTimeRangeError> {
        Self::from_timestamp(Timestamp::now())
    }

    /// The event time of `timestamp`, cut down to the microsecond, before
    /// 1970 as after.
    ///
    /// # Errors
    ///
    /// Returns [`EventTimeRangeError`] if `timestamp` is before the year 0000.
    pub fn from_timestamp(timestamp: Timestamp) -> Result<Self, EventTimeRangeError> {
        let micros = TimestampRound::new()
            .smallest(Unit::Microsecond)
            .mode(RoundMode::Floor);
        // Rounding down fails only below jiff's first microsecond, which is
        // long before the year 0000.
        match timestamp.round(micros) {
            Ok(cut) if cut >= FIRST => Ok(Self(cut)),
            _ => Err(EventTimeRangeError(timestamp)),
        }
    }

    /// Whether `s` has the length and leading digit of the written form.
    /// jiff writes a year outside 0000-9999 with a sign and six digits.
    fn is_shaped(s: &str) -> bool {
        s.len() == WRITTEN_LEN && s.starts_with(|c: char| c.is_ascii_digit())
    }

    /// The instant, for arithmetic and for display in another form.
    #[must_use]
    pub fn timestamp(self) -> Timestamp {
        self.0
    }

    /// Parse an event time in its written form.
    ///
    /// ```
    /// use rite_model::EventTime;
    ///
    /// let at = EventTime::parse("2023-11-14T22:13:20.123456Z").unwrap();
    /// assert_eq!(at.to_string(), "2023-11-14T22:13:20.123456Z");
    /// // Any other spelling of the same instant is refused.
    /// assert!(EventTime::parse("2023-11-14T23:13:20.123456+01:00").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`EventTimeFormatError`] unless `s` is exactly the form
    /// [`Display`](fmt::Display) writes, with a four-digit year.
    pub fn parse(s: &str) -> Result<Self, EventTimeFormatError> {
        // jiff's parsers accept more than this form (offsets, basic and
        // truncated ISO 8601, any number of fractional digits, a leap second
        // read as :59). The written form is the one that prints back the same.
        let shaped = Self::is_shaped(s);
        s.parse::<Timestamp>()
            .ok()
            .map(Self)
            .filter(|at| shaped && at.to_string() == s)
            .ok_or_else(|| EventTimeFormatError(s.to_string()))
    }
}

impl fmt::Display for EventTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.0)
    }
}

impl FromStr for EventTime {
    type Err = EventTimeFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for EventTime {
    type Error = EventTimeFormatError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<EventTime> for String {
    fn from(at: EventTime) -> Self {
        at.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(second: i64, nanosecond: i32) -> EventTime {
        EventTime::from_timestamp(Timestamp::constant(second, nanosecond)).expect("in range")
    }

    #[test]
    fn written_with_six_fractional_digits_in_utc() {
        assert_eq!(
            at(1_700_000_000, 0).to_string(),
            "2023-11-14T22:13:20.000000Z"
        );
        assert_eq!(
            at(1_700_000_000, 100_000_000).to_string(),
            "2023-11-14T22:13:20.100000Z"
        );
    }

    #[test]
    fn precision_below_a_microsecond_is_cut_when_made() {
        let cut = at(1_700_000_000, 123_456_789);
        assert_eq!(cut, at(1_700_000_000, 123_456_000));
        assert_eq!(cut.to_string(), "2023-11-14T22:13:20.123456Z");
    }

    #[test]
    fn precision_is_cut_down_before_1970_too() {
        // 500 ns before the epoch belongs to the microsecond before it, not
        // to the epoch itself.
        assert_eq!(
            at(-1, 999_999_500).to_string(),
            "1969-12-31T23:59:59.999999Z"
        );
    }

    #[test]
    fn only_the_years_0000_to_9999_make_an_event_time() {
        let first = EventTime::from_timestamp(FIRST).expect("year 0");
        assert_eq!(first.to_string(), "0000-01-01T00:00:00.000000Z");
        assert_eq!(EventTime::parse(&first.to_string()), Ok(first));
        // jiff stops short of the year 10000, so its last instant is one,
        // cut down to the microsecond, and parses back.
        let last = EventTime::from_timestamp(Timestamp::MAX).expect("jiff's last instant");
        assert_eq!(last.timestamp().subsec_nanosecond() % 1000, 0);
        assert_eq!(EventTime::parse(&last.to_string()), Ok(last));

        let before = FIRST - jiff::SignedDuration::from_nanos(1);
        assert!(EventTime::from_timestamp(before).is_err());
        assert!(EventTime::from_timestamp(Timestamp::MIN).is_err());
    }

    #[test]
    fn parse_reads_back_the_written_form() {
        let original = at(1_700_000_000, 123_456_000);
        assert_eq!(EventTime::parse(&original.to_string()), Ok(original));
    }

    #[test]
    fn parse_rejects_every_other_form() {
        for bad in [
            "2023-11-14T23:13:20.123456+01:00",
            "2023-11-14T22:13:20.123456+00:00",
            "2023-11-14T22:13:20.123456-00:00",
            "2023-11-14T22:13:20.123Z",
            "2023-11-14T22:13:20.123456789Z",
            "2023-11-14T22:13:20Z",
            "2023-11-14T22:13Z",
            "2023-11-14T22Z",
            "20231114T221320.123456Z",
            "2023-11-14T22:13:20,123456Z",
            "2023-11-14t22:13:20.123456z",
            "2023-11-14 22:13:20.123456Z",
            " 2023-11-14T22:13:20.123456Z",
            "+002023-11-14T22:13:20.123456Z",
            "2023-11-14T22:13:20.123456Z[UTC]",
            "2016-12-31T23:59:60.000000Z",
            "-000001-01-01T00:00:00.000000Z",
            "+010000-01-01T00:00:00.000000Z",
            "not a time",
        ] {
            assert!(EventTime::parse(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn serde_uses_the_written_form() {
        let original = at(1_700_000_000, 123_456_000);
        let json = serde_json::to_string(&original).expect("serialize");
        assert_eq!(json, "\"2023-11-14T22:13:20.123456Z\"");
        assert_eq!(
            serde_json::from_str::<EventTime>(&json).expect("deserialize"),
            original
        );
        assert!(serde_json::from_str::<EventTime>("\"2023-11-14T22:13:20Z\"").is_err());
    }
}
