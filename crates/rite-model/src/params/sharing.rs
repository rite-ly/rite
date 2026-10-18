//! Params for the secret sharing actions.

use serde::{Deserialize, Serialize};

/// Params for `reveal` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevealParams {
    /// What the value is and what to do with it, shown above it and
    /// printed on the sheet.
    pub message: String,
    /// The encoding: `paper32` (the default), `hex`, or `bip39` for a
    /// wallet's recovery phrase.
    #[serde(default)]
    pub format: Option<crate::RevealFormat>,
    /// Text printed on the sheet: where it goes, who keeps it.
    #[serde(default)]
    pub note: Option<String>,
    /// The value's length in the format's unit, words for `bip39` and
    /// bytes otherwise, when the author knows it, so the sheet has exactly
    /// the right number of rows; a value of another size is refused. A
    /// share counts the three header bytes in front of its secret.
    #[serde(default)]
    pub length: Option<u64>,
}

/// Params for `enter_share` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnterShareParams {
    /// What the share is, shown above the rows: the sheet's heading.
    pub message: String,
    /// The encoding the sheet was written in: `paper32` (the default) or
    /// `hex`.
    #[serde(default)]
    pub format: Option<crate::RevealFormat>,
    /// Shown with the rows: where the sheet came from, who types it.
    #[serde(default)]
    pub note: Option<String>,
    /// The share's length in bytes, its secret's plus three header bytes,
    /// when the author knows it, so the prompt asks for exactly the right
    /// rows; a share of another size is refused.
    #[serde(default)]
    pub length: Option<u64>,
}

/// Params for `split_secret` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitSecretParams {
    /// The sharing scheme, defaulting to `rite-sss/v1`, the only one this
    /// build implements. Named so the transcript says which one was used.
    #[serde(default)]
    pub scheme: Option<crate::SharingScheme>,
    /// How many shares reconstruct the secret, from 2 to the scheme's limit.
    pub threshold: u8,
    /// How many shares to make, from `threshold` to the scheme's limit, 100
    /// for `rite-sss/v1`. Every subset of `threshold` shares is checked
    /// before the step completes, so a split with more than 100,000 such
    /// subsets is refused as well.
    pub shares: u8,
}

impl Default for SplitSecretParams {
    fn default() -> Self {
        Self {
            scheme: None,
            threshold: 2,
            shares: 2,
        }
    }
}
