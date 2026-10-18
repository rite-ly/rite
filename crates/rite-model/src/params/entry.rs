//! Params for the `enter_value` and `enter_secret` actions.

use super::FormatSpec;
use serde::{Deserialize, Serialize};

/// Params for the `enter_value` and `enter_secret` actions.
///
/// The shape fields are turned into one rule by
/// [`EntryShape`](super::EntryShape), which is also what
/// `rite check` applies to them.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryParams {
    /// What the person is asked for, shown at the prompt.
    pub message: String,
    /// What kind of value it is: a format name, or `{ pattern: "..." }`.
    /// Text by default. An encoding makes the artifact the decoded bytes.
    #[serde(default)]
    pub format: Option<FormatSpec>,
    /// An exact length, in characters for text and bytes for an encoding.
    #[serde(default)]
    pub length: Option<usize>,
    /// The fewest units accepted.
    #[serde(default)]
    pub min_length: Option<usize>,
    /// The most units accepted.
    #[serde(default)]
    pub max_length: Option<usize>,
}
