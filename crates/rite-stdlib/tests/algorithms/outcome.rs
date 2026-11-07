//! What every family's rows have in common: an outcome per policy level, and
//! a refusal stated by where it happens, what it says, and why.

/// A ceremony-wide cryptographic policy level.
///
/// Rite has no such setting yet, so the one level is the behaviour of a
/// ceremony that declares none. A level added here makes every [`Expected`]
/// say what happens under it, because [`Expected::under`] matches
/// exhaustively; the runner then passes the level to the ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Default,
}

impl Policy {
    pub const ALL: &'static [Policy] = &[Policy::Default];

    /// A test's name under this level: the row's name for the default, with
    /// the level appended for any other.
    pub fn name(self, row: String) -> String {
        match self {
            Policy::Default => row,
        }
    }
}

/// What a row expects, per policy level.
#[derive(Debug, Clone, Copy)]
pub struct Expected<T> {
    pub default: T,
}

impl<T> Expected<T> {
    pub fn under(&self, policy: Policy) -> &T {
        match policy {
            Policy::Default => &self.default,
        }
    }
}

/// The same outcome under every policy level. There is one level today; see
/// [`Policy`].
pub const fn always<T: Copy>(outcome: T) -> Expected<T> {
    Expected { default: outcome }
}

/// Where in a case a refusal happens.
///
/// Recorded so that a refusal moving is a failure. A key refused at import
/// that starts to import, and is then refused by the step, is a change of
/// behaviour even when the message is the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `rite check`'s validation of the case as a ceremony, before anything
    /// runs. A name Rite does not know is refused here.
    Check,
    /// `import_key` putting the case's key into the backend.
    Import,
    /// `generate_key` making the case's key in the backend.
    Generate,
    /// The step under test.
    Step,
}

/// A refusal, and the words that identify it.
///
/// `says` is a fragment of the error message, specific enough that a
/// different refusal does not contain it.
#[derive(Debug, Clone, Copy)]
pub struct Refusal {
    pub at: Stage,
    pub says: &'static str,
}

/// Why something is refused, which is what a reader of the matrix needs.
///
/// Both are tested the same way, and neither is checked against Rite: its
/// errors carry no such distinction. It records intent, so that a change can
/// be read for what it is: an `Unsupported` case that starts to work is
/// progress, a `Refused` one is a decision being reversed.
#[derive(Debug, Clone, Copy)]
pub enum Why {
    /// Rite does not do this yet, and nothing stops it doing so.
    Unsupported,
    /// Rite does not do this by design.
    Refused,
}

/// How `rite check` refuses a key algorithm Rite has no name for, on
/// `import_key` or `generate_key`.
pub const NO_SUCH_ALGORITHM: &str = "'with.algorithm' must be one of: RSA-2048";
