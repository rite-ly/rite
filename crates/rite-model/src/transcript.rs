//! Persisted transcript schema.
//!
//! These types are the **durable** audit surface: what gets written to
//! `transcript.jsonl`, what `rite verify` reads back, what report and
//! audit tooling consume. They are deliberately kept independent of the
//! executor and the channel plumbing, a third-party verifier can parse
//! a transcript with only `rite-model` on its dependency list.
//!
//! The live runtime↔frontend channel protocol (`ExecEvent`, `UiCommand`,
//! `Response`, `Icon`, …) lives in `rite-runtime` next to the executor
//! that owns the channels. The boundary is **persisted vs in-flight**.

use std::collections::BTreeMap;

use base64ct::Encoding as _;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Sha256Digest;
use crate::ir::{ActId, MaterialId, ParamId, RoleId, StepId};

/// Transcript format version this crate writes and reads: the line envelope
/// and the chain rule.
///
/// 0 while rite is before 1.0: the format changes between releases without
/// a new number, and the header's `producer` names the release that wrote a
/// transcript.
pub const TRANSCRIPT_FORMAT: u32 = 0;

/// Version of the [`StepFact`] vocabulary this crate writes and reads. 0
/// before 1.0, like [`TRANSCRIPT_FORMAT`].
pub const FACT_VOCABULARY: u32 = 0;

/// URL of the JSON Schema for the transcript lines this release writes,
/// written on the header line for editors and other tools. A reader ignores
/// it.
pub const TRANSCRIPT_SCHEMA: &str = concat!(
    "https://ritely.io/schemas/",
    env!("CARGO_PKG_VERSION"),
    "/transcript.schema.json"
);

/// First line of every transcript: what the file is, read before any fact.
///
/// Chained like every other line, so it cannot be swapped without breaking
/// the fingerprint. A reader checks [`rite_transcript`](Self::rite_transcript)
/// before parsing anything else and refuses a value it does not know.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(
        description = "What the file is. A reader checks `rite_transcript` before reading \
        anything else, and refuses a version it does not know."
    )
)]
pub struct TranscriptHeader {
    /// Format version of the envelope and chain rule ([`TRANSCRIPT_FORMAT`]).
    #[cfg_attr(
        test,
        schemars(description = "Version of the line format and the chain rule.")
    )]
    pub rite_transcript: u32,
    /// Version of the fact vocabulary ([`FACT_VOCABULARY`]).
    #[cfg_attr(
        test,
        schemars(
            description = "Version of the fact vocabulary: which fact types and fields the \
            transcript uses."
        )
    )]
    pub vocabulary: u32,
    /// Program and version that wrote the transcript, as it reports itself.
    /// Informational: a binary cannot vouch for its own identity.
    #[cfg_attr(
        test,
        schemars(
            description = "The program and version that wrote the transcript, as it reports \
            itself. Informational: a program cannot vouch for its own identity."
        )
    )]
    pub producer: String,
    /// Random identifier of this run, 32 lowercase hex digits.
    #[cfg_attr(
        test,
        schemars(
            description = "A random identifier of this run: 32 lowercase hex digits.",
            extend("pattern" = "^[0-9a-f]{32}$")
        )
    )]
    pub run_id: String,
    /// Whether the run was a dry run. A dry-run transcript is a rehearsal
    /// record, never evidence of a ceremony.
    #[cfg_attr(
        test,
        schemars(
            description = "Whether the run was a dry run. A dry-run transcript is a rehearsal \
            record, never evidence of a ceremony."
        )
    )]
    pub dry_run: bool,
    /// Every level this transcript uses, by name. Holds the built-in levels
    /// at their fixed values, and any level the ceremony declares.
    #[cfg_attr(
        test,
        schemars(
            description = "Every level the transcript uses, by name. It holds public, \
            restricted and confidential at their fixed values, and any other level the ceremony \
            declares. No two names share a value."
        )
    )]
    pub levels: BTreeMap<String, Level>,
}

impl TranscriptHeader {
    /// A header for the current format and vocabulary.
    #[must_use]
    pub fn new(producer: &str, run_id: &str, dry_run: bool) -> Self {
        Self {
            rite_transcript: TRANSCRIPT_FORMAT,
            vocabulary: FACT_VOCABULARY,
            producer: producer.to_string(),
            run_id: run_id.to_string(),
            dry_run,
            levels: Level::BUILT_IN
                .iter()
                .map(|(name, level)| ((*name).to_string(), *level))
                .collect(),
        }
    }

    /// Whether the header declares `level`.
    #[must_use]
    pub fn declares(&self, level: Level) -> bool {
        self.levels.values().any(|declared| *declared == level)
    }

    /// A declared level, by the name the header gives it or by its number.
    #[must_use]
    pub fn level(&self, name_or_value: &str) -> Option<Level> {
        if let Some(level) = self.levels.get(name_or_value) {
            return Some(*level);
        }
        let level = Level::new(name_or_value.parse().ok()?);
        self.declares(level).then_some(level)
    }
}

/// Confidentiality level of a transcript line: who may see the fact.
///
/// An integer, ordered from widest audience to narrowest, so a disclosure is
/// a threshold and checking it needs no names. The level is committed in the
/// chain with the line. Secrets are not a level: a secret value is never
/// recorded at all.
///
/// Three levels are built in, at fixed values that mean the same thing in
/// every transcript. The gaps leave room for an organisation to declare its
/// own levels between and beyond them; the header names every level a
/// transcript uses.
///
/// | Level | Value | Audience | TLP 2.0 |
/// |---|---|---|---|
/// | `public` | 10 | anyone | CLEAR |
/// | `restricted` | 20 | auditors, under agreement | AMBER |
/// | `confidential` | 30 | the ceremony's own organisation | RED |
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(
    test,
    schemars(
        description = "The confidentiality level of a line: who may see its fact. Levels are \
        integers ordered from the widest audience to the narrowest, so a disclosure up to a level \
        withholds every line above it. Three levels are built in at fixed values: public (10, \
        anyone), restricted (20, auditors under agreement) and confidential (30, the ceremony's \
        own organisation). Every level a transcript uses is declared in its header."
    )
)]
pub struct Level(u32);

impl Level {
    /// Anyone.
    pub const PUBLIC: Level = Level(10);
    /// Auditors, under agreement.
    pub const RESTRICTED: Level = Level(20);
    /// The ceremony's own organisation.
    pub const CONFIDENTIAL: Level = Level(30);

    /// The built-in levels with their names, widest audience first.
    pub const BUILT_IN: [(&'static str, Level); 3] = [
        ("public", Level::PUBLIC),
        ("restricted", Level::RESTRICTED),
        ("confidential", Level::CONFIDENTIAL),
    ];

    /// A level at `value`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The level's value, as written in the transcript and committed in the
    /// chain.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match Level::BUILT_IN.iter().find(|(_, level)| level == self) {
            Some((name, _)) => f.write_str(name),
            None => write!(f, "level {}", self.0),
        }
    }
}

/// Validator applied by the runtime to a typed response before it is
/// accepted.
///
/// The rule is part of the prompt, so it is recorded with it: a transcript
/// says a six-digit secret was entered, never which one. [`check`](Self::check)
/// is the one place a rule is applied, so `rite check` and the running
/// ceremony agree on what a pattern accepts.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "The check an answer had to pass."))]
pub enum ValidatorSpec {
    /// Reject empty or whitespace-only input.
    #[cfg_attr(test, schemars(description = "The answer is not empty or blank."))]
    NonEmpty,
    /// Input must match this regular expression in full.
    #[cfg_attr(
        test,
        schemars(description = "The answer matches a regular expression in full.")
    )]
    Regex(#[cfg_attr(test, schemars(description = "The regular expression."))] String),
    /// Named, runtime-defined predicate (e.g. `serial_number`).
    #[cfg_attr(
        test,
        schemars(description = "The answer passes a check the program defines, by name.")
    )]
    Predefined(
        #[cfg_attr(
            test,
            schemars(description = "The name of the check, such as serial_number.")
        )]
        String,
    ),
    /// A value of one [`Format`], with a length within bounds.
    ///
    /// What a PIN or a key component needs, stated without a pattern the
    /// person writing the ceremony has to get right. The length is counted
    /// in the format's own units: characters for text, bytes for an
    /// encoding.
    #[cfg_attr(
        test,
        schemars(
            description = "The answer is a value of one format, with a length within \
                                 bounds, counted in characters for text and in bytes for an \
                                 encoding."
        )
    )]
    Format {
        /// What kind of value this is.
        #[cfg_attr(test, schemars(description = "What kind of value the answer is."))]
        format: Format,
        /// Fewest units accepted, if bounded.
        #[cfg_attr(test, schemars(description = "The fewest units accepted, if bounded."))]
        min_length: Option<usize>,
        /// Most units accepted, if bounded.
        #[cfg_attr(test, schemars(description = "The most units accepted, if bounded."))]
        max_length: Option<usize>,
    },
}

/// What kind of value a person types.
///
/// Each format has one canonical representation, which is what an entry step
/// keeps: the text as typed for a text format, the decoded bytes for an
/// encoding. An encoding is forgiving of the grouping a person types it in,
/// so whitespace is dropped before decoding.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "What kind of value a person types."))]
pub enum Format {
    /// Anything the person can type.
    #[cfg_attr(test, schemars(description = "Anything the person can type."))]
    Text,
    /// `0` to `9`.
    #[cfg_attr(test, schemars(description = "Decimal digits only."))]
    Digits,
    /// ASCII letters and digits.
    #[cfg_attr(test, schemars(description = "ASCII letters and digits."))]
    Alphanumeric,
    /// Bytes as hexadecimal, in either case, two digits per byte.
    #[cfg_attr(
        test,
        schemars(description = "Bytes as hexadecimal, in either case, two digits per byte.")
    )]
    Hex,
    /// Bytes as standard base64 with padding, as `openssl base64` writes it.
    #[cfg_attr(test, schemars(description = "Bytes as standard base64 with padding."))]
    Base64,
}

impl Format {
    /// Whether the value stands for bytes, which is what the step then keeps.
    #[must_use]
    pub fn is_encoding(self) -> bool {
        match self {
            Format::Text | Format::Digits | Format::Alphanumeric => false,
            Format::Hex | Format::Base64 => true,
        }
    }

    /// Whether a text format accepts this character. An encoding accepts
    /// whatever decodes.
    fn accepts(self, c: char) -> bool {
        match self {
            Format::Text | Format::Hex | Format::Base64 => true,
            Format::Digits => c.is_ascii_digit(),
            Format::Alphanumeric => c.is_ascii_alphanumeric(),
        }
    }

    /// Decode a typed value of an encoding.
    ///
    /// # Errors
    ///
    /// Returns why the value is not this encoding, or that the format is not
    /// one, worded for the person who typed it and naming nothing of what
    /// they typed.
    pub fn decode(self, value: &str) -> Result<Vec<u8>, String> {
        // The value may be a secret, so the copy without its whitespace is
        // wiped with the call.
        let compact: Zeroizing<String> =
            Zeroizing::new(value.chars().filter(|c| !c.is_whitespace()).collect());
        match self {
            Format::Hex => base16ct::mixed::decode_vec(compact.as_bytes())
                .map_err(|_| "value must be hex, two digits per byte".to_string()),
            Format::Base64 => base64ct::Base64::decode_vec(&compact)
                .map_err(|_| "value must be standard base64, with padding".to_string()),
            Format::Text | Format::Digits | Format::Alphanumeric => {
                Err(format!("{} is text and does not decode", self.describe()))
            }
        }
    }

    /// The unit a length counts, as a person reads it in a hint.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Format::Text => "characters",
            Format::Digits => "digits",
            Format::Alphanumeric => "letters or digits",
            Format::Hex => "bytes as hex",
            Format::Base64 => "bytes as base64",
        }
    }

    /// A stand-in of `length` units that satisfies the format, for a run
    /// with no one at the keyboard. Never a real value.
    ///
    /// `None` above [`PLACEHOLDER_LIMIT`]: a length a ceremony declares is
    /// not bounded, and a stand-in that size would be allocated for nothing.
    /// The caller then declines to answer rather than answering with
    /// something the rule refuses, which would be asked again without end.
    #[must_use]
    pub fn placeholder(self, length: usize) -> Option<String> {
        if length > PLACEHOLDER_LIMIT {
            return None;
        }
        Some(match self {
            Format::Text | Format::Alphanumeric => "x".repeat(length),
            Format::Digits => "0".repeat(length),
            Format::Hex => base16ct::lower::encode_string(&vec![0u8; length]),
            Format::Base64 => base64ct::Base64::encode_string(&vec![0u8; length]),
        })
    }
}

/// The longest stand-in a [`Format::placeholder`] builds, in the format's
/// units. Large enough for any value a person would type or paste, and the
/// entry itself is not bounded by it.
pub const PLACEHOLDER_LIMIT: usize = 64 * 1024;

impl std::str::FromStr for Format {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "text" => Ok(Format::Text),
            "digits" => Ok(Format::Digits),
            "alphanumeric" => Ok(Format::Alphanumeric),
            "hex" => Ok(Format::Hex),
            "base64" => Ok(Format::Base64),
            other => Err(format!(
                "unknown format '{other}': expected text, digits, alphanumeric, hex or base64"
            )),
        }
    }
}

impl ValidatorSpec {
    /// Apply the rule to a typed value.
    ///
    /// # Errors
    ///
    /// Returns what the value fails to satisfy, worded for the person who
    /// typed it, or why the rule itself cannot be applied.
    pub fn check(&self, value: &str) -> Result<(), String> {
        match self {
            ValidatorSpec::NonEmpty => {
                if value.trim().is_empty() {
                    Err("value must not be empty".to_string())
                } else {
                    Ok(())
                }
            }
            ValidatorSpec::Regex(pattern) => {
                let regex = compile_pattern(pattern)?;
                if regex.is_match(value) {
                    Ok(())
                } else {
                    Err(format!("value must match {pattern}"))
                }
            }
            // Named predicates will land alongside the actions that need them.
            ValidatorSpec::Predefined(name) => Err(format!("unknown validator: {name}")),
            ValidatorSpec::Format {
                format,
                min_length,
                max_length,
            } => {
                let hint = self.hint().unwrap_or_default();
                if value.trim().is_empty() {
                    return Err("value must not be empty".to_string());
                }
                // An encoding is decoded and discarded, wiped on the way out:
                // the value may be a secret, and this runs before the step
                // holds it.
                let length = if format.is_encoding() {
                    Zeroizing::new(format.decode(value)?).len()
                } else {
                    if !value.chars().all(|c| format.accepts(c)) {
                        return Err(format!("value must be {hint}"));
                    }
                    value.chars().count()
                };
                if min_length.is_some_and(|min| length < min)
                    || max_length.is_some_and(|max| length > max)
                {
                    return Err(format!("value must be {hint}, this is {length}"));
                }
                Ok(())
            }
        }
    }

    /// The rule as a person reads it before typing, if there is one worth
    /// stating.
    ///
    /// `NonEmpty` says nothing: every prompt asks for something. A pattern is
    /// shown as written, since a regular expression has no better rendering.
    #[must_use]
    pub fn hint(&self) -> Option<String> {
        match self {
            ValidatorSpec::NonEmpty | ValidatorSpec::Predefined(_) => None,
            ValidatorSpec::Regex(pattern) => Some(format!("matching {pattern}")),
            ValidatorSpec::Format {
                format,
                min_length,
                max_length,
            } => {
                let what = format.describe();
                Some(match (min_length, max_length) {
                    (Some(min), Some(max)) if min == max => format!("{min} {what}"),
                    (Some(min), Some(max)) => format!("{min} to {max} {what}"),
                    (Some(min), None) => format!("at least {min} {what}"),
                    (None, Some(max)) => format!("at most {max} {what}"),
                    (None, None) if format.is_encoding() => what.to_string(),
                    (None, None) => format!("{what} only"),
                })
            }
        }
    }
}

/// Compile a pattern so that it must match the whole value.
///
/// A rule that read `[0-9]+` and accepted `abc123def` would pass what its
/// author meant to refuse, so the anchors are always supplied here rather
/// than expected of the author.
///
/// # Errors
///
/// Returns why the pattern is not a regular expression.
pub fn compile_pattern(pattern: &str) -> Result<regex_lite::Regex, String> {
    regex_lite::Regex::new(&format!("^(?:{pattern})$"))
        .map_err(|e| format!("invalid pattern '{pattern}': {e}"))
}

/// Request for user input, recorded into the transcript as part of
/// [`StepFact::PromptAnswered`].
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "A prompt as it was shown."))]
pub enum Prompt {
    /// Yes / no question with an optional default.
    #[cfg_attr(test, schemars(description = "A yes or no question."))]
    Confirm {
        /// Question shown to the user.
        #[cfg_attr(test, schemars(description = "The question."))]
        question: String,
        /// Default selection if the user presses Enter without choosing.
        #[cfg_attr(
            test,
            schemars(
                description = "The answer given when the person confirms without choosing, if \
                any."
            )
        )]
        default: Option<bool>,
    },
    /// Free-form text input, validated against a [`ValidatorSpec`].
    #[cfg_attr(
        test,
        schemars(description = "A request for free text, checked before it is accepted.")
    )]
    Text {
        /// Label shown to the user.
        #[cfg_attr(test, schemars(description = "The label shown."))]
        label: String,
        /// Validator applied before the response is accepted.
        #[cfg_attr(test, schemars(description = "The check the answer had to pass."))]
        validator: ValidatorSpec,
    },
    /// Sensitive input (PIN, password). Echo is suppressed; plaintext is
    /// never serialized to the transcript.
    #[cfg_attr(
        test,
        schemars(
            description = "A request for a secret, such as a PIN. The answer is never \
            recorded."
        )
    )]
    Secret {
        /// Label shown to the user.
        #[cfg_attr(test, schemars(description = "The label shown."))]
        label: String,
        /// Validator applied before the response is accepted.
        #[cfg_attr(test, schemars(description = "The check the answer had to pass."))]
        validator: ValidatorSpec,
    },
    /// User must type a specific literal string exactly. Validation is
    /// performed by the runtime against `expected`.
    #[cfg_attr(
        test,
        schemars(
            description = "A request to type a given text exactly, such as a confirmation \
            phrase."
        )
    )]
    Literal {
        /// Label shown to the user.
        #[cfg_attr(test, schemars(description = "The label shown."))]
        label: String,
        /// Exact string the user must type.
        #[cfg_attr(test, schemars(description = "The text that had to be typed."))]
        expected: String,
    },
    /// Wait for the user to acknowledge before proceeding. Used for pacing.
    #[cfg_attr(
        test,
        schemars(description = "A pause until the person is ready to continue.")
    )]
    Continue {
        /// Optional hint such as "Press Enter when ready".
        #[cfg_attr(test, schemars(description = "The hint shown, if any."))]
        hint: Option<String>,
    },
}

/// Serializable, redacted form of a user response.
///
/// Used inside [`StepFact::PromptAnswered`] so that the transcript records
/// what was answered without ever persisting plaintext secrets. The
/// in-flight `Response` type lives next to the channel protocol in
/// `rite-runtime`; conversion happens at the moment the prompt is accepted.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(
    test,
    schemars(
        description = "The answer to a prompt, as recorded. A secret answer is never \
        recorded, not even as a digest."
    )
)]
pub enum ResponseRecord {
    /// Yes / no answer.
    #[cfg_attr(test, schemars(description = "A yes or no answer."))]
    Bool {
        /// The answer.
        #[cfg_attr(test, schemars(description = "The answer."))]
        value: bool,
    },
    /// Free-form text answer.
    #[cfg_attr(test, schemars(description = "A free-text answer."))]
    Text {
        /// The answer.
        #[cfg_attr(test, schemars(description = "The answer, as typed."))]
        value: String,
    },
    /// Secret answer. The plaintext is never stored, and no digest of it is
    /// kept either: a hash of a low-entropy secret (such as a 6-8 digit PIV
    /// PIN) is brute-forceable from a shared transcript. The position of the
    /// enclosing `PromptAnswered` fact in the chain already records that a
    /// secret was entered at this point.
    // Note: a salted, per-run HMAC could later attest that two prompts received
    // the same secret without reintroducing the low-entropy guessing oracle.
    // Deferred until a concrete use case needs it.
    #[cfg_attr(
        test,
        schemars(
            description = "A secret was entered. Only the fact that it was entered is \
            recorded."
        )
    )]
    SecretRedacted {},
    /// Acknowledgement of a [`Prompt::Continue`].
    #[cfg_attr(test, schemars(description = "The person continued past a pause."))]
    Acknowledged,
}

/// Audit classification of a bad outcome, recorded so an auditor can tell the
/// nature of a failure apart without parsing the free-form `message`.
///
/// This is the *audit* taxonomy (what an auditor sees), distinct from the
/// runtime's `Retriability` (whether a step may re-run). For a backend error
/// the two align: a retriable error is `Environmental`. They are kept separate
/// because some classes never map cleanly onto retriability (an `Abort` is a
/// decision, not an error).
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "What kind of bad outcome this was."))]
pub enum ErrorClass {
    /// The world wasn't ready; the step's work did not happen (token absent,
    /// loose cable, PIN required).
    #[cfg_attr(
        test,
        schemars(
            description = "Something around the ceremony was not ready, such as a device not \
            connected, and the step's work did not happen."
        )
    )]
    Environmental,
    /// The ceremony's own logic concluded badly (a verification mismatch, a
    /// refused attestation). A result, not a recoverable condition.
    #[cfg_attr(
        test,
        schemars(
            description = "The ceremony's own logic concluded badly, such as a verification \
            that did not match or a refused attestation."
        )
    )]
    Procedural,
    /// The run itself is compromised or the definition is broken (transcript
    /// write failed, channel lost, unknown action, invalid params).
    #[cfg_attr(
        test,
        schemars(
            description = "The run itself cannot be trusted to continue, or the ceremony \
            definition is broken."
        )
    )]
    Integrity,
    /// The operator chose to stop. Not an error at all, but recorded on the
    /// terminal fact so abort is distinguishable from failure.
    #[cfg_attr(
        test,
        schemars(description = "An operator chose to stop the ceremony.")
    )]
    Abort,
}

/// Structured error record for transcript serialization.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(
        description = "What went wrong: a class for audit, a stable kind, and a message for \
        people."
    )
)]
pub struct ErrorRecord {
    /// Audit classification of this error.
    #[cfg_attr(test, schemars(description = "The kind of bad outcome, for audit."))]
    pub class: ErrorClass,
    /// Stable kind label (e.g. `aborted`, `step_failed`, `material_load_failed`).
    #[cfg_attr(
        test,
        schemars(description = "A stable label for the error, such as aborted or step_failed.")
    )]
    pub kind: String,
    /// Human-readable message.
    #[cfg_attr(test, schemars(description = "A description of the error for people."))]
    pub message: String,
}

impl ErrorRecord {
    /// Construct an error record.
    pub fn new(class: ErrorClass, kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            class,
            kind: kind.into(),
            message: message.into(),
        }
    }
}

/// Outcome of a single step, carried by [`StepFact::StepCompleted`].
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "How a step ended."))]
pub enum StepOutcome {
    /// Step executed successfully.
    #[cfg_attr(test, schemars(description = "The step did its work."))]
    Completed {
        /// Human-readable completion message.
        #[cfg_attr(
            test,
            schemars(description = "A short description of what the step did.")
        )]
        message: String,
    },
}

/// Durable, transcript-worthy fact.
///
/// Every variant is recorded by the runtime's transcript sink synchronously
/// before being forwarded to the UI. Action handlers emit
/// [`BackendOperation`] and [`AttestationRecorded`]; all other variants are
/// emitted by the executor at the corresponding lifecycle boundary.
///
/// [`BackendOperation`]: StepFact::BackendOperation
/// [`AttestationRecorded`]: StepFact::AttestationRecorded
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[cfg_attr(
    test,
    schemars(
        description = "One recorded fact, identified by its `type`. Each fact type has a \
        fixed set of fields in a given vocabulary."
    )
)]
pub enum StepFact {
    /// Ceremony has started running.
    #[cfg_attr(test, schemars(description = "The ceremony started."))]
    CeremonyStarted {
        /// Ceremony name from the DSL.
        #[cfg_attr(test, schemars(description = "The ceremony's name."))]
        name: String,
        /// Digest of the ceremony YAML the run was resolved from. The inputs
        /// supplied for this run are recorded as their own facts, one each,
        /// so this digest covers the template only.
        #[cfg_attr(
            test,
            schemars(
                description = "Digest of the ceremony definition file the run was resolved \
                from. The inputs of the run are recorded as their own facts, so this digest covers \
                the definition only."
            )
        )]
        template: Sha256Digest,
    },
    /// A role the ceremony defines, with its display name.
    ///
    /// Recorded once per role at ceremony start, whether or not anyone is
    /// assigned to it. Later facts name the role by id only.
    #[cfg_attr(
        test,
        schemars(
            description = "A role the ceremony defines. Recorded once per role at the start, \
            whether or not anyone is assigned to it; later facts name the role by its identifier."
        )
    )]
    RoleDeclared {
        /// Role identifier.
        #[cfg_attr(test, schemars(description = "The role."))]
        role: RoleId,
        /// Human-readable role name, from the ceremony's role definition.
        #[cfg_attr(test, schemars(description = "The role's display name."))]
        name: String,
    },
    /// A person was assigned to a role for this run.
    ///
    /// One fact per assignment, so each can be withheld on its own.
    #[cfg_attr(
        test,
        schemars(
            description = "A person was assigned to a role for this run. One fact per \
            assignment, so each can be withheld on its own."
        )
    )]
    RoleAssigned {
        /// Role identifier.
        #[cfg_attr(test, schemars(description = "The role."))]
        role: RoleId,
        /// The person, as supplied at run time. Recorded as given; nothing
        /// in the ceremony proves who the person is.
        #[cfg_attr(
            test,
            schemars(
                description = "The person, as supplied when the run started. Recorded as \
                given: nothing in the transcript proves who the person is."
            )
        )]
        person: String,
    },
    /// A parameter took its value for this run, supplied or defaulted.
    #[cfg_attr(
        test,
        schemars(description = "A parameter took its value for this run, supplied or defaulted.")
    )]
    ParameterBound {
        /// Parameter identifier.
        #[cfg_attr(test, schemars(description = "The parameter."))]
        name: ParamId,
        /// The resolved value.
        #[cfg_attr(test, schemars(description = "The value, as the ceremony used it."))]
        value: serde_json::Value,
    },
    /// A material was loaded at ceremony start.
    ///
    /// The digest of a digital material is a separate fact,
    /// [`MaterialDigest`](StepFact::MaterialDigest), so the two can be
    /// disclosed to different audiences.
    #[cfg_attr(
        test,
        schemars(
            description = "A material was loaded at the start of the run. The digest of a \
            digital material is a separate fact, material_digest, so the two can be disclosed to \
            different audiences."
        )
    )]
    MaterialLoaded {
        /// Material identifier.
        #[cfg_attr(test, schemars(description = "The material."))]
        name: MaterialId,
        /// Identifier of a physical or pre-provisioned material, such as a
        /// serial number, when the ceremony supplied one.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(
            test,
            schemars(
                description = "The identifier of a physical or pre-provisioned material, such \
                as a serial number, when one was supplied."
            )
        )]
        identifier: Option<String>,
    },
    /// The digest of a digital material's bytes.
    #[cfg_attr(
        test,
        schemars(description = "The digest of a digital material's bytes, as loaded.")
    )]
    MaterialDigest {
        /// Material identifier.
        #[cfg_attr(test, schemars(description = "The material."))]
        name: MaterialId,
        /// Digest of the file as loaded.
        #[cfg_attr(test, schemars(description = "The digest of the material's bytes."))]
        digest: Sha256Digest,
    },
    /// A backend was first acquired in this run.
    ///
    /// Recorded once per backend, before the first operation on it. Backend
    /// operations name the backend and do not repeat its identity, which can
    /// carry device serials.
    #[cfg_attr(
        test,
        schemars(
            description = "A backend was used for the first time in this run. Recorded once \
            per backend, before its first operation; operations name the backend and do not repeat \
            its identity."
        )
    )]
    BackendBound {
        /// Backend name from the ceremony.
        #[cfg_attr(test, schemars(description = "The backend's name in the ceremony."))]
        name: String,
        /// Backend provider (e.g. `openssl`, `yubikey`, `pkcs11`).
        #[cfg_attr(
            test,
            schemars(description = "The kind of backend, such as openssl, yubikey or pkcs11.")
        )]
        provider: String,
        /// Identity the backend reports for itself, such as a device serial
        /// and firmware version.
        #[cfg_attr(
            test,
            schemars(
                description = "The identity the backend reports for itself, such as a device \
                serial number and firmware version."
            )
        )]
        identity: String,
    },
    /// A snapshot of the machine the ceremony ran on.
    #[cfg_attr(
        test,
        schemars(description = "A description of the machine the ceremony ran on.")
    )]
    MachineInfoRecorded {
        /// Step that captured the snapshot.
        #[cfg_attr(test, schemars(description = "The step that recorded it."))]
        step: StepId,
        /// The parts of the host snapshot the step was asked to record.
        #[cfg_attr(
            test,
            schemars(
                description = "The parts of the machine description the step was asked to \
                record."
            )
        )]
        info: serde_json::Value,
    },
    /// Beginning of an act (named subdivision of a ceremony).
    #[cfg_attr(
        test,
        schemars(description = "An act, a named part of the ceremony, started.")
    )]
    ActStarted {
        /// Act identifier.
        #[cfg_attr(test, schemars(description = "The act."))]
        id: ActId,
        /// Act label as authored in the DSL.
        #[cfg_attr(
            test,
            schemars(description = "The act's label, as written in the ceremony.")
        )]
        label: String,
    },
    /// Beginning of a step.
    #[cfg_attr(test, schemars(description = "A step started."))]
    StepStarted {
        /// Step identifier.
        #[cfg_attr(test, schemars(description = "The step."))]
        id: StepId,
        /// Step label as authored in the DSL.
        #[cfg_attr(
            test,
            schemars(description = "The step's label, as written in the ceremony.")
        )]
        label: String,
        /// Role responsible for this step. Its name is on the role's
        /// [`RoleDeclared`](StepFact::RoleDeclared) fact.
        #[cfg_attr(
            test,
            schemars(
                description = "The role responsible for the step. Its display name is on the \
                role's role_declared fact."
            )
        )]
        role: RoleId,
    },
    /// A prompt has been answered and validated.
    #[cfg_attr(
        test,
        schemars(description = "Someone answered a prompt, and the answer was accepted.")
    )]
    PromptAnswered {
        /// Step that issued the prompt, if any. `None` for ceremony-level
        /// prompts emitted before the first step (e.g. the ceremony-start
        /// confirmation) or after the last step.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(
            test,
            schemars(
                description = "The step that asked, or absent for a prompt asked outside any \
                step."
            )
        )]
        step: Option<StepId>,
        /// The prompt as issued.
        #[cfg_attr(test, schemars(description = "The prompt, as shown."))]
        prompt: Prompt,
        /// Redacted response record.
        #[cfg_attr(test, schemars(description = "The answer, as recorded."))]
        response: ResponseRecord,
    },
    /// A backend operation completed and produced structured evidence.
    #[cfg_attr(
        test,
        schemars(
            description = "A backend performed an operation. The inputs and outputs are \
            specific to the kind of operation."
        )
    )]
    BackendOperation {
        /// Step under which the operation ran.
        #[cfg_attr(test, schemars(description = "The step the operation ran in."))]
        step: StepId,
        /// Stable operation kind (e.g. `generate_key`, `sign_data`).
        #[cfg_attr(
            test,
            schemars(description = "The kind of operation, such as generate_key or sign_data.")
        )]
        kind: String,
        /// The backend the step ran with, by the name the ceremony gives it;
        /// its identity is on that backend's [`StepFact::BackendBound`].
        /// Absent for an operation done in software.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(
            test,
            schemars(
                description = "The backend the step ran with, by the name the ceremony gives it.                 Its identity is on that backend's backend_bound fact. Absent for an operation                 done in software."
            )
        )]
        backend: Option<String>,
        /// Structured inputs to the operation (parameters, references).
        #[cfg_attr(
            test,
            schemars(
                description = "What the operation was given: parameters and references to \
                artifacts or materials."
            )
        )]
        inputs: serde_json::Value,
        /// Structured outputs from the operation (artifact ids, hashes).
        #[cfg_attr(
            test,
            schemars(description = "What the operation produced: artifact names and digests.")
        )]
        outputs: serde_json::Value,
        /// Optional fingerprint of the produced material.
        #[cfg_attr(
            test,
            schemars(
                description = "A fingerprint of the material the operation produced, when it \
                has one."
            )
        )]
        fingerprint: Option<String>,
    },
    /// A key held outside the ceremony was used as the recipient of a wrap.
    ///
    /// Its own fact rather than a field on the wrap operation: the method of a
    /// wrap is publishable and the identity of a custodian may not be, and a
    /// fact carries one confidentiality level.
    ///
    /// The fingerprint records the bytes that were present. Nothing in the
    /// ceremony corroborates that they belong to the intended recipient, and
    /// nothing shows the recipient can open the result. The fact states an
    /// assumption the ceremony rests on, not something Rite proved.
    #[cfg_attr(
        test,
        schemars(
            description = "A key held outside the ceremony received a wrapped key. A separate \
            fact from the operation, so the method of a wrap can be published while the recipient \
            stays withheld."
        )
    )]
    WrapRecipientRecorded {
        /// Step that wrapped to this recipient.
        #[cfg_attr(test, schemars(description = "The step that wrapped the key."))]
        step: StepId,
        /// The artifact or material the recipient key came from, as named in
        /// the ceremony.
        #[cfg_attr(
            test,
            schemars(
                description = "The artifact or material the recipient's key came from, by its \
                name in the ceremony."
            )
        )]
        source: String,
        /// `sha256:<hex>` over the recipient's SPKI DER.
        #[cfg_attr(
            test,
            schemars(
                description = "The digest of the recipient's public key, as DER-encoded \
                SubjectPublicKeyInfo.",
                with = "Sha256Digest"
            )
        )]
        fingerprint: String,
        /// Whether the ceremony declared this fingerprint in advance, so the
        /// runtime checked the key it received against the definition rather
        /// than recording whatever arrived.
        #[cfg_attr(
            test,
            schemars(
                description = "Whether the ceremony named this fingerprint in advance. When \
                it did, the key received was checked against it; otherwise the fingerprint records \
                whatever key arrived."
            )
        )]
        declared: bool,
    },
    /// A human attestation was recorded.
    #[cfg_attr(test, schemars(description = "A person made an attestation."))]
    AttestationRecorded {
        /// Step under which the attestation was recorded.
        #[cfg_attr(test, schemars(description = "The step the attestation was made in."))]
        step: StepId,
        /// Role that issued the attestation.
        #[cfg_attr(test, schemars(description = "The role that made the attestation."))]
        role: RoleId,
        /// Verbatim attestation statement.
        #[cfg_attr(test, schemars(description = "The statement, word for word."))]
        statement: String,
    },
    /// An artifact was written to the run's `artifacts/` directory.
    #[cfg_attr(
        test,
        schemars(description = "An artifact was written to the run's artifacts directory.")
    )]
    ArtifactWritten {
        /// Step that produced the artifact.
        #[cfg_attr(test, schemars(description = "The step that produced the artifact."))]
        step: StepId,
        /// Artifact name as declared in the DSL.
        #[cfg_attr(
            test,
            schemars(description = "The artifact's name, as declared in the ceremony.")
        )]
        name: String,
        /// File name under `artifacts/`: one path component, no directory.
        #[cfg_attr(
            test,
            schemars(
                description = "The file name in the artifacts directory: a single path \
                component."
            )
        )]
        file: String,
        /// Digest of the file's bytes. Absent when the artifact is content a
        /// step opened: a digest of a secret can be tested against guesses,
        /// so none is recorded.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(
            test,
            schemars(
                description = "The digest of the file's bytes. Absent for content a step \
                opened, since a digest of a secret can be tested against guesses."
            )
        )]
        digest: Option<Sha256Digest>,
    },
    /// A deviation was logged by the operator.
    #[cfg_attr(test, schemars(description = "An operator recorded a deviation."))]
    DeviationRecorded {
        /// Step in which the deviation was logged, if any. `None` for
        /// deviations logged outside of a step (before the first step or
        /// while a ceremony-level prompt is pending).
        #[serde(skip_serializing_if = "Option::is_none")]
        #[cfg_attr(
            test,
            schemars(
                description = "The step during which the deviation was recorded, or absent \
                outside any step."
            )
        )]
        step: Option<StepId>,
        /// Verbatim deviation text.
        #[cfg_attr(test, schemars(description = "The deviation, word for word."))]
        text: String,
    },
    /// A step attempt failed. Recorded per attempt, so a retried step shows
    /// `StepAttemptFailed{attempt: 1}` followed by the operator's retry
    /// decision and, on success, `StepCompleted`. The final attempt of a step
    /// that the run gives up on is followed by the terminal `CeremonyFailed`.
    #[cfg_attr(
        test,
        schemars(
            description = "One attempt at a step failed. Recorded per attempt: a step that is \
            retried and then succeeds has this fact for each failed attempt, then step_completed."
        )
    )]
    StepAttemptFailed {
        /// Step whose attempt failed.
        #[cfg_attr(test, schemars(description = "The step."))]
        step: StepId,
        /// 1-based attempt number within this step.
        #[cfg_attr(
            test,
            schemars(description = "The attempt's number within the step, starting at 1.")
        )]
        attempt: u32,
        /// Structured error record for the failed attempt.
        #[cfg_attr(test, schemars(description = "What went wrong in this attempt."))]
        error: ErrorRecord,
    },
    /// Step finished executing.
    #[cfg_attr(test, schemars(description = "A step finished."))]
    StepCompleted {
        /// Step identifier.
        #[cfg_attr(test, schemars(description = "The step."))]
        id: StepId,
        /// How the step ended.
        #[cfg_attr(test, schemars(description = "How the step ended."))]
        outcome: StepOutcome,
    },
    /// Ceremony finished successfully.
    ///
    /// The transcript's fingerprint is the `chain` value of this line, which
    /// any reader recomputes, so the fact itself carries no fingerprint
    /// field. The runtime forwards the value to frontends through an
    /// out-of-band channel event.
    #[cfg_attr(
        test,
        schemars(
            description = "The ceremony finished. It is the last line of a transcript whose \
            run completed."
        )
    )]
    CeremonyCompleted {},
    /// Ceremony failed or was aborted.
    #[cfg_attr(
        test,
        schemars(
            description = "The ceremony failed or was aborted. It is the last line of a \
            transcript whose run did not complete."
        )
    )]
    CeremonyFailed {
        /// Structured error record.
        #[cfg_attr(test, schemars(description = "What went wrong."))]
        error: ErrorRecord,
    },
    /// The ceremony entropy source was seeded with machine randomness.
    ///
    /// Emitted once by the runner at ceremony start (run-metadata). Records
    /// the machine contribution `m` and the frozen derivation scheme so any
    /// value the ceremony later draws is re-derivable from the transcript
    /// alone. Part of the [entropy source](StepFact::EntropyDrawn) family.
    ///
    /// Like every fact, it is timed by the `at` on its chain envelope.
    #[cfg_attr(
        test,
        schemars(
            description = "The ceremony's entropy source was seeded with machine randomness. \
            Recorded once, at the start, so every value drawn from the source can be derived again \
            from the transcript."
        )
    )]
    EntropySeeded {
        /// Lowercase hex of the gathered machine entropy `m`.
        #[cfg_attr(
            test,
            schemars(
                description = "The machine randomness, as lowercase hex.",
                extend("pattern" = "^(?:[0-9a-f]{2})+$")
            )
        )]
        m: String,
        /// Provenance of `m` (e.g. `os`). A single label today; comma-separated
        /// if more than one source is ever mixed.
        #[cfg_attr(
            test,
            schemars(description = "Where the machine randomness came from, such as os.")
        )]
        source: String,
        /// Frozen derivation-scheme tag (e.g. `rite-kdf/v1`) that pins the
        /// entire construction. A verifier rejects an unrecognised value.
        #[cfg_attr(
            test,
            schemars(
                description = "The derivation scheme, such as rite-kdf/v1. A verifier refuses \
                a scheme it does not know."
            )
        )]
        derivation: String,
    },
    /// A human folded additional entropy into the seed, advancing the ratchet.
    ///
    /// Emitted by the authored `gather_entropy` step. The verbatim operator
    /// contribution is recorded so the epoch chain re-folds identically; it is
    /// public, witnessed entropy, not a secret. Timed by its enclosing step
    /// boundaries (and by the `PromptAnswered` that captured the input).
    #[cfg_attr(
        test,
        schemars(
            description = "A person added their own randomness to the entropy source, \
            starting a new epoch."
        )
    )]
    EntropyContributed {
        /// Step under which the contribution was gathered.
        #[cfg_attr(test, schemars(description = "The step the contribution was made in."))]
        step: StepId,
        /// Epoch index produced by this fold (1 for the first contribution).
        #[cfg_attr(
            test,
            schemars(description = "The epoch this contribution starts, counting from 1.")
        )]
        epoch: u32,
        /// Verbatim operator contribution, fed as UTF-8 into the ratchet.
        #[cfg_attr(
            test,
            schemars(
                description = "The contribution, word for word, mixed into the source as \
                UTF-8."
            )
        )]
        contribution: String,
    },
    /// A value was drawn from the entropy source (a nonce, certificate serial,
    /// or challenge).
    ///
    /// Emitted whenever an action draws bytes from the entropy source. The
    /// derivation `path` plus the recorded seed let `rite verify` re-derive
    /// the value and confirm the right value reached the right consumer. Like
    /// other action-emitted evidence, it is timed by its enclosing step.
    #[cfg_attr(
        test,
        schemars(
            description = "A value was drawn from the entropy source, such as a nonce, a \
            certificate serial number or a challenge. A verifier derives it again from the seed, \
            the contributions and the path."
        )
    )]
    EntropyDrawn {
        /// Step that drew the value.
        #[cfg_attr(test, schemars(description = "The step that drew the value."))]
        step: StepId,
        /// Derivation path `<epoch>/<step>/<purpose>`.
        #[cfg_attr(
            test,
            schemars(description = "The derivation path: `<epoch>/<step>/<purpose>`.")
        )]
        path: String,
        /// Lowercase hex of the derived bytes. Its length fixes the byte count,
        /// so `rite verify` re-derives exactly this many bytes from the seed.
        #[cfg_attr(
            test,
            schemars(
                description = "The value, as lowercase hex. Its length is the number of bytes \
                drawn.",
                extend("pattern" = "^(?:[0-9a-f]{2})*$")
            )
        )]
        value: String,
    },
}

/// The `type` tag of every [`StepFact`] variant in this vocabulary.
///
/// A reader uses it to tell a fact from a newer vocabulary, which it counts and
/// skips, from a known fact that does not parse, which is an error.
pub const FACT_TYPES: &[&str] = &[
    "ceremony_started",
    "role_declared",
    "role_assigned",
    "parameter_bound",
    "material_loaded",
    "material_digest",
    "backend_bound",
    "machine_info_recorded",
    "act_started",
    "step_started",
    "prompt_answered",
    "backend_operation",
    "wrap_recipient_recorded",
    "attestation_recorded",
    "artifact_written",
    "deviation_recorded",
    "step_attempt_failed",
    "step_completed",
    "ceremony_completed",
    "ceremony_failed",
    "entropy_seeded",
    "entropy_contributed",
    "entropy_drawn",
];

impl StepFact {
    /// The level a fact of this type is recorded at.
    ///
    /// Method facts (what was done, in what order, with what result) are
    /// public, and so are attestations, whose statement is authored in the
    /// ceremony. Free text, answers typed at prompts, the error message of a
    /// failed attempt, and identities of devices and inputs are restricted.
    /// Persons, material digests and the host snapshot are confidential.
    ///
    /// A failed ceremony stays public despite its error message: a public
    /// disclosure needs its terminal fact.
    #[must_use]
    pub fn default_level(&self) -> Level {
        match self {
            StepFact::CeremonyStarted { .. }
            | StepFact::RoleDeclared { .. }
            | StepFact::ActStarted { .. }
            | StepFact::StepStarted { .. }
            | StepFact::BackendOperation { .. }
            | StepFact::ArtifactWritten { .. }
            | StepFact::AttestationRecorded { .. }
            | StepFact::StepCompleted { .. }
            | StepFact::CeremonyCompleted {}
            | StepFact::CeremonyFailed { .. }
            // Re-deriving the entropy source needs all three.
            | StepFact::EntropySeeded { .. }
            | StepFact::EntropyContributed { .. }
            | StepFact::EntropyDrawn { .. } => Level::PUBLIC,
            StepFact::ParameterBound { .. }
            | StepFact::MaterialLoaded { .. }
            | StepFact::BackendBound { .. }
            | StepFact::PromptAnswered { .. }
            | StepFact::WrapRecipientRecorded { .. }
            | StepFact::StepAttemptFailed { .. }
            | StepFact::DeviationRecorded { .. } => Level::RESTRICTED,
            StepFact::RoleAssigned { .. }
            | StepFact::MaterialDigest { .. }
            | StepFact::MachineInfoRecorded { .. } => Level::CONFIDENTIAL,
        }
    }

    /// Whether this fact evidences work performed on the world: a backend
    /// operation, a written artifact, a captured attestation, or consumed
    /// entropy. Interaction records (an answered prompt, an operator
    /// deviation note) and lifecycle markers are not side effects: repeating
    /// the interaction is safe and simply produces a fresh record.
    ///
    /// The runtime's retry gate refuses to re-execute a step attempt that
    /// already emitted a side-effect fact.
    #[must_use]
    pub fn is_side_effect(&self) -> bool {
        match self {
            StepFact::BackendOperation { .. }
            | StepFact::AttestationRecorded { .. }
            | StepFact::ArtifactWritten { .. }
            | StepFact::EntropyContributed { .. }
            | StepFact::EntropyDrawn { .. } => true,
            StepFact::CeremonyStarted { .. }
            // Run inputs and identities, recorded before any step works.
            | StepFact::RoleDeclared { .. }
            | StepFact::RoleAssigned { .. }
            | StepFact::ParameterBound { .. }
            | StepFact::MaterialLoaded { .. }
            | StepFact::MaterialDigest { .. }
            | StepFact::BackendBound { .. }
            // Records the host, not work performed on it.
            | StepFact::MachineInfoRecorded { .. }
            | StepFact::ActStarted { .. }
            | StepFact::StepStarted { .. }
            | StepFact::PromptAnswered { .. }
            // Records an input the step read, not work it performed.
            | StepFact::WrapRecipientRecorded { .. }
            | StepFact::DeviationRecorded { .. }
            | StepFact::StepAttemptFailed { .. }
            | StepFact::StepCompleted { .. }
            | StepFact::CeremonyCompleted {}
            | StepFact::CeremonyFailed { .. }
            | StepFact::EntropySeeded { .. } => false,
        }
    }
}

/// JSON-shape snapshot tests, the tripwire for accidental wire-format breaks.
///
/// Every variant of [`StepFact`], [`Prompt`], [`ResponseRecord`], [`StepOutcome`],
/// and [`ValidatorSpec`] is serialized once with fixed payloads and compared
/// against an inline JSON literal. The on-disk transcript schema is what
/// `rite verify`, `rite report`, and any third-party verifier consume; a
/// rename, a `serde(tag)` change, a `rename_all` flip, or a timestamp format
/// swap must surface here, not in the field.
///
/// Breaking the format is allowed in early beta, **deliberately**, update
/// the fixture in the same commit so the diff documents the wire change.
#[cfg(test)]
mod validator_tests {
    use super::*;

    fn shape(format: Format, min: usize, max: usize) -> ValidatorSpec {
        ValidatorSpec::Format {
            format,
            min_length: Some(min),
            max_length: Some(max),
        }
    }

    #[test]
    fn a_text_format_checks_characters_and_length() {
        let pin = shape(Format::Digits, 6, 8);
        assert!(pin.check("123456").is_ok());
        assert!(pin.check("12345678").is_ok());
        assert!(pin.check("12345").unwrap_err().contains("this is 5"));
        assert!(pin.check("123456789").unwrap_err().contains("this is 9"));
        assert!(pin.check("12345a").unwrap_err().contains("digits"));

        assert!(shape(Format::Alphanumeric, 1, 4).check("ab12").is_ok());
        assert!(shape(Format::Alphanumeric, 1, 4).check("ab-1").is_err());
        assert!(shape(Format::Text, 1, 4).check("ab-1").is_ok());
        assert!(
            ValidatorSpec::Format {
                format: Format::Text,
                min_length: None,
                max_length: None,
            }
            .check("  ")
            .is_err(),
            "a value is still something"
        );
    }

    /// The pattern covers the whole value: a rule that read `[0-9]+` and
    /// accepted `abc123` would pass what its author meant to refuse.
    #[test]
    fn a_pattern_must_match_the_whole_value() {
        let digits = ValidatorSpec::Regex("[0-9]+".to_string());
        assert!(digits.check("123").is_ok());
        assert!(digits.check("abc123").is_err());
        assert!(digits.check("123abc").is_err());
        // Alternation is grouped before anchoring.
        let either = ValidatorSpec::Regex("yes|no".to_string());
        assert!(either.check("no").is_ok());
        assert!(either.check("nope").is_err());
    }

    #[test]
    fn a_refusal_names_the_rule_and_not_the_value() {
        let err = shape(Format::Digits, 6, 6).check("hunter2").unwrap_err();
        assert!(!err.contains("hunter2"));
        let err = ValidatorSpec::Regex("[0-9]+".to_string())
            .check("hunter2")
            .unwrap_err();
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn a_hint_reads_as_a_person_would_say_it() {
        assert_eq!(shape(Format::Digits, 6, 6).hint().unwrap(), "6 digits");
        assert_eq!(
            shape(Format::Text, 6, 8).hint().unwrap(),
            "6 to 8 characters"
        );
        assert_eq!(
            ValidatorSpec::Format {
                format: Format::Hex,
                min_length: Some(32),
                max_length: None,
            }
            .hint()
            .unwrap(),
            "at least 32 bytes as hex"
        );
        assert_eq!(
            ValidatorSpec::Format {
                format: Format::Alphanumeric,
                min_length: None,
                max_length: None,
            }
            .hint()
            .unwrap(),
            "letters or digits only"
        );
        assert_eq!(
            ValidatorSpec::Format {
                format: Format::Base64,
                min_length: None,
                max_length: None,
            }
            .hint()
            .unwrap(),
            "bytes as base64"
        );
        assert!(ValidatorSpec::NonEmpty.hint().is_none());
    }

    /// The string is transport: grouping and case are dropped, and what is
    /// checked is the bytes.
    #[test]
    fn an_encoding_decodes_and_counts_bytes() {
        let key = shape(Format::Hex, 4, 4);
        assert!(key.check("deadbeef").is_ok());
        assert!(key.check("DE AD be ef").is_ok());
        assert!(key.check("deadbe").unwrap_err().contains("this is 3"));
        assert!(key.check("deadbeefx").unwrap_err().contains("hex"));
        assert_eq!(Format::Hex.decode("DE AD").unwrap(), vec![0xde, 0xad]);

        let b64 = ValidatorSpec::Format {
            format: Format::Base64,
            min_length: None,
            max_length: None,
        };
        assert!(b64.check("aGVsbG8=").is_ok());
        assert!(b64.check("aGVsbG8").is_err(), "padding is required");
        assert_eq!(Format::Base64.decode("aGVs\nbG8=").unwrap(), b"hello");
        assert!(Format::Digits.decode("12").is_err(), "text does not decode");
    }

    #[test]
    fn a_placeholder_satisfies_its_own_format() {
        for format in [
            Format::Text,
            Format::Digits,
            Format::Alphanumeric,
            Format::Hex,
            Format::Base64,
        ] {
            let stand_in = format.placeholder(32).unwrap();
            assert!(shape(format, 32, 32).check(&stand_in).is_ok());
        }
        assert!(Format::Text.placeholder(PLACEHOLDER_LIMIT + 1).is_none());
    }
}

#[cfg(test)]
mod schema_snapshot_tests {
    use super::*;
    use serde_json::json;

    fn assert_json(fact: &StepFact, expected: &serde_json::Value) {
        let actual = serde_json::to_value(fact).expect("serialize StepFact");
        assert_eq!(&actual, expected, "wire-format drift for {fact:?}");
        let tag = actual
            .get("type")
            .and_then(serde_json::Value::as_str)
            .expect("a type tag");
        assert!(FACT_TYPES.contains(&tag), "{tag} missing from FACT_TYPES");
        crate::schema::assert_fact_matches_schema(&actual);
    }

    #[test]
    fn a_level_is_named_or_numbered_and_must_be_declared() {
        let header = TranscriptHeader::new("rite test", "0", false);
        assert_eq!(header.level("public"), Some(Level::PUBLIC));
        assert_eq!(header.level("20"), Some(Level::RESTRICTED));
        assert_eq!(header.level("15"), None);
        assert_eq!(header.level("partners"), None);
    }

    #[test]
    fn levels_are_ordered_integers() {
        assert!(Level::PUBLIC < Level::RESTRICTED);
        assert!(Level::RESTRICTED < Level::CONFIDENTIAL);
        assert!(Level::new(15) > Level::PUBLIC && Level::new(15) < Level::RESTRICTED);
        assert_eq!(
            serde_json::to_value(Level::CONFIDENTIAL).expect("serialize"),
            json!(30)
        );
        assert_eq!(Level::RESTRICTED.to_string(), "restricted");
        assert_eq!(Level::new(15).to_string(), "level 15");
    }

    #[test]
    fn ceremony_started() {
        assert_json(
            &StepFact::CeremonyStarted {
                name: "Root CA".to_string(),
                template: Sha256Digest::of(b"ceremony"),
            },
            &json!({
                "type": "ceremony_started",
                "name": "Root CA",
                "template": Sha256Digest::of(b"ceremony").as_str(),
            }),
        );
    }

    #[test]
    fn header() {
        let header = TranscriptHeader::new("rite 0.6.0", &"0".repeat(32), false);
        assert_eq!(
            serde_json::to_value(&header).expect("serialize header"),
            json!({
                "rite_transcript": 0,
                "vocabulary": 0,
                "producer": "rite 0.6.0",
                "run_id": "0".repeat(32),
                "dry_run": false,
                "levels": { "public": 10, "restricted": 20, "confidential": 30 },
            }),
        );
    }

    #[test]
    fn role_assigned() {
        assert_json(
            &StepFact::RoleAssigned {
                role: RoleId::new("crypto_officer"),
                person: "Alice Rivera".to_string(),
            },
            &json!({
                "type": "role_assigned",
                "role": "crypto_officer",
                "person": "Alice Rivera",
            }),
        );
    }

    #[test]
    fn parameter_bound() {
        assert_json(
            &StepFact::ParameterBound {
                name: ParamId::new("validity_days"),
                value: json!(3650),
            },
            &json!({
                "type": "parameter_bound",
                "name": "validity_days",
                "value": 3650,
            }),
        );
    }

    #[test]
    fn material_loaded() {
        assert_json(
            &StepFact::MaterialLoaded {
                name: MaterialId::new("usb_drive"),
                identifier: Some("SN-1234".to_string()),
            },
            &json!({
                "type": "material_loaded",
                "name": "usb_drive",
                "identifier": "SN-1234",
            }),
        );
        assert_json(
            &StepFact::MaterialLoaded {
                name: MaterialId::new("csr"),
                identifier: None,
            },
            &json!({ "type": "material_loaded", "name": "csr" }),
        );
    }

    #[test]
    fn material_digest() {
        assert_json(
            &StepFact::MaterialDigest {
                name: MaterialId::new("csr"),
                digest: Sha256Digest::of(b"csr"),
            },
            &json!({
                "type": "material_digest",
                "name": "csr",
                "digest": Sha256Digest::of(b"csr").as_str(),
            }),
        );
    }

    #[test]
    fn backend_bound() {
        assert_json(
            &StepFact::BackendBound {
                name: "token".to_string(),
                provider: "yubikey".to_string(),
                identity: "yubikey-serial=12345678+firmware=5.7.1".to_string(),
            },
            &json!({
                "type": "backend_bound",
                "name": "token",
                "provider": "yubikey",
                "identity": "yubikey-serial=12345678+firmware=5.7.1",
            }),
        );
    }

    #[test]
    fn machine_info_recorded() {
        assert_json(
            &StepFact::MachineInfoRecorded {
                step: StepId::new("capture"),
                info: json!({ "arch": "x86_64", "hostname": null }),
            },
            &json!({
                "type": "machine_info_recorded",
                "step": "capture",
                "info": { "arch": "x86_64", "hostname": null },
            }),
        );
    }

    #[test]
    fn act_started() {
        assert_json(
            &StepFact::ActStarted {
                id: ActId::new("setup"),
                label: "Setup".to_string(),
            },
            &json!({
                "type": "act_started",
                "id": "setup",
                "label": "Setup",
            }),
        );
    }

    #[test]
    fn step_started() {
        assert_json(
            &StepFact::StepStarted {
                id: StepId::new("s1"),
                label: "2.1".to_string(),
                role: RoleId::new("crypto_officer"),
            },
            &json!({
                "type": "step_started",
                "id": "s1",
                "label": "2.1",
                "role": "crypto_officer",
            }),
        );
    }

    #[test]
    fn role_declared() {
        assert_json(
            &StepFact::RoleDeclared {
                role: RoleId::new("crypto_officer"),
                name: "Crypto Officer".to_string(),
            },
            &json!({
                "type": "role_declared",
                "role": "crypto_officer",
                "name": "Crypto Officer",
            }),
        );
    }

    #[test]
    fn prompt_answered_confirm_bool() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Confirm {
                    question: "Proceed?".to_string(),
                    default: Some(true),
                },
                response: ResponseRecord::Bool { value: true },
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "confirm", "question": "Proceed?", "default": true },
                "response": { "type": "bool", "value": true },
            }),
        );
    }

    #[test]
    fn prompt_answered_text_nonempty() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "Name".to_string(),
                    validator: ValidatorSpec::NonEmpty,
                },
                response: ResponseRecord::Text {
                    value: "Alice".to_string(),
                },
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "Name",
                    "validator": { "kind": "non_empty" },
                },
                "response": { "type": "text", "value": "Alice" },
            }),
        );
    }

    #[test]
    fn prompt_answered_text_regex() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "SN".to_string(),
                    validator: ValidatorSpec::Regex(r"^[A-Z0-9]+$".to_string()),
                },
                response: ResponseRecord::Text {
                    value: "AB12".to_string(),
                },
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "SN",
                    "validator": { "kind": "regex", "value": "^[A-Z0-9]+$" },
                },
                "response": { "type": "text", "value": "AB12" },
            }),
        );
    }

    #[test]
    fn prompt_answered_text_predefined() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Text {
                    label: "SN".to_string(),
                    validator: ValidatorSpec::Predefined("serial_number".to_string()),
                },
                response: ResponseRecord::Text {
                    value: "ABCD".to_string(),
                },
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "text",
                    "label": "SN",
                    "validator": { "kind": "predefined", "value": "serial_number" },
                },
                "response": { "type": "text", "value": "ABCD" },
            }),
        );
    }

    #[test]
    fn prompt_answered_secret_redacted() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Secret {
                    label: "PIN".to_string(),
                    validator: ValidatorSpec::NonEmpty,
                },
                response: ResponseRecord::SecretRedacted {},
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": {
                    "type": "secret",
                    "label": "PIN",
                    "validator": { "kind": "non_empty" },
                },
                "response": { "type": "secret_redacted" },
            }),
        );
    }

    #[test]
    fn prompt_answered_literal_text() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Literal {
                    label: "Type 'attest'".to_string(),
                    expected: "attest".to_string(),
                },
                response: ResponseRecord::Text {
                    value: "attest".to_string(),
                },
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "literal", "label": "Type 'attest'", "expected": "attest" },
                "response": { "type": "text", "value": "attest" },
            }),
        );
    }

    #[test]
    fn prompt_answered_continue_acknowledged() {
        assert_json(
            &StepFact::PromptAnswered {
                step: Some(StepId::new("s1")),
                prompt: Prompt::Continue {
                    hint: Some("Press Enter".to_string()),
                },
                response: ResponseRecord::Acknowledged,
            },
            &json!({
                "type": "prompt_answered",
                "step": "s1",
                "prompt": { "type": "continue", "hint": "Press Enter" },
                "response": { "type": "acknowledged" },
            }),
        );
    }

    #[test]
    fn backend_operation() {
        assert_json(
            &StepFact::BackendOperation {
                step: StepId::new("s1"),
                kind: "generate_key".to_string(),
                backend: Some("hsm".to_string()),
                inputs: json!({ "algorithm": "rsa", "bits": 4096 }),
                outputs: json!({ "key_id": "k1" }),
                fingerprint: Some("sha256:deadbeef".to_string()),
            },
            &json!({
                "type": "backend_operation",
                "step": "s1",
                "kind": "generate_key",
                "backend": "hsm",
                "inputs": { "algorithm": "rsa", "bits": 4096 },
                "outputs": { "key_id": "k1" },
                "fingerprint": "sha256:deadbeef",
            }),
        );
    }

    #[test]
    fn wrap_recipient_recorded() {
        let fingerprint = Sha256Digest::of(b"escrow spki").to_string();
        assert_json(
            &StepFact::WrapRecipientRecorded {
                step: StepId::new("s1"),
                source: "escrow_pubkey".to_string(),
                fingerprint: fingerprint.clone(),
                declared: true,
            },
            &json!({
                "type": "wrap_recipient_recorded",
                "step": "s1",
                "source": "escrow_pubkey",
                "fingerprint": fingerprint,
                "declared": true,
            }),
        );
    }

    #[test]
    fn attestation_recorded() {
        assert_json(
            &StepFact::AttestationRecorded {
                step: StepId::new("s1"),
                role: RoleId::new("crypto_officer"),
                statement: "I confirm.".to_string(),
            },
            &json!({
                "type": "attestation_recorded",
                "step": "s1",
                "role": "crypto_officer",
                "statement": "I confirm.",
            }),
        );
    }

    #[test]
    fn artifact_written() {
        assert_json(
            &StepFact::ArtifactWritten {
                step: StepId::new("s1"),
                name: "root_cert".to_string(),
                file: "root_cert.crt".to_string(),
                digest: Some(Sha256Digest::of(b"cert")),
            },
            &json!({
                "type": "artifact_written",
                "step": "s1",
                "name": "root_cert",
                "file": "root_cert.crt",
                "digest": Sha256Digest::of(b"cert").as_str(),
            }),
        );
    }

    #[test]
    fn artifact_written_secret_has_no_digest() {
        assert_json(
            &StepFact::ArtifactWritten {
                step: StepId::new("s1"),
                name: "opened".to_string(),
                file: "opened.bin".to_string(),
                digest: None,
            },
            &json!({
                "type": "artifact_written",
                "step": "s1",
                "name": "opened",
                "file": "opened.bin",
            }),
        );
    }

    #[test]
    fn deviation_recorded() {
        assert_json(
            &StepFact::DeviationRecorded {
                step: Some(StepId::new("s1")),
                text: "phone rang".to_string(),
            },
            &json!({
                "type": "deviation_recorded",
                "step": "s1",
                "text": "phone rang",
            }),
        );
    }

    #[test]
    fn step_completed_completed() {
        assert_json(
            &StepFact::StepCompleted {
                id: StepId::new("s1"),
                outcome: StepOutcome::Completed {
                    message: "done".to_string(),
                },
            },
            &json!({
                "type": "step_completed",
                "id": "s1",
                "outcome": { "status": "completed", "message": "done" },
            }),
        );
    }

    #[test]
    fn ceremony_completed() {
        assert_json(
            &StepFact::CeremonyCompleted {},
            &json!({
                "type": "ceremony_completed",
            }),
        );
    }

    #[test]
    fn ceremony_failed() {
        assert_json(
            &StepFact::CeremonyFailed {
                error: ErrorRecord::new(
                    ErrorClass::Abort,
                    "aborted",
                    "ceremony aborted by operator",
                ),
            },
            &json!({
                "type": "ceremony_failed",
                "error": {
                    "class": "abort",
                    "kind": "aborted",
                    "message": "ceremony aborted by operator",
                },
            }),
        );
    }

    #[test]
    fn step_attempt_failed() {
        assert_json(
            &StepFact::StepAttemptFailed {
                step: StepId::new("import_key"),
                attempt: 1,
                error: ErrorRecord::new(
                    ErrorClass::Environmental,
                    "backend_error",
                    "Token not present",
                ),
            },
            &json!({
                "type": "step_attempt_failed",
                "step": "import_key",
                "attempt": 1,
                "error": {
                    "class": "environmental",
                    "kind": "backend_error",
                    "message": "Token not present",
                },
            }),
        );
    }

    #[test]
    fn entropy_seeded() {
        assert_json(
            &StepFact::EntropySeeded {
                m: "00112233".to_string(),
                source: "os".to_string(),
                derivation: "rite-kdf/v1".to_string(),
            },
            &json!({
                "type": "entropy_seeded",
                "m": "00112233",
                "source": "os",
                "derivation": "rite-kdf/v1",
            }),
        );
    }

    #[test]
    fn entropy_contributed() {
        assert_json(
            &StepFact::EntropyContributed {
                step: StepId::new("roll_dice"),
                epoch: 1,
                contribution: "3 1 6 4 2 5".to_string(),
            },
            &json!({
                "type": "entropy_contributed",
                "step": "roll_dice",
                "epoch": 1,
                "contribution": "3 1 6 4 2 5",
            }),
        );
    }

    #[test]
    fn entropy_drawn() {
        assert_json(
            &StepFact::EntropyDrawn {
                step: StepId::new("issue"),
                path: "0/issue/cert-serial".to_string(),
                value: "aabbccddeeff00112233".to_string(),
            },
            &json!({
                "type": "entropy_drawn",
                "step": "issue",
                "path": "0/issue/cert-serial",
                "value": "aabbccddeeff00112233",
            }),
        );
    }
}
