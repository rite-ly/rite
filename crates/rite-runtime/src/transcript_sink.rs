//! Transcript sink, the durable consumer of [`StepFact`]s.
//!
//! The sink is an inline observer in the executor thread. It records each
//! [`StepFact`] synchronously before the executor proceeds to its next action,
//! and the on-disk implementation `fsync`s the line to the storage device
//! before returning. This invariant, *the transcript is durable before the
//! UI sees the fact* , is what makes the on-disk record the authoritative
//! source of evidence and the live UI a tee of the same stream.
//!
//! # On-disk format (`transcript.jsonl`)
//!
//! The first line is the header, which says what the file is before any fact
//! is read:
//!
//! ```jsonc
//! {"$schema": "https://ritely.io/schemas/…/transcript.schema.json", "header": {"dry_run": false, "levels": {"public": 10, …}, …}, "chain": "sha256:…"}
//! ```
//!
//! `$schema` names the JSON Schema of the release that wrote the file, for
//! editors and other tools. It is outside the header, so the chain does not
//! commit to it, and a reader ignores it.
//!
//! Every following line is one fact: its time, its confidentiality level and
//! two checkpoints, which every line has, then a fresh random salt and the
//! fact itself:
//!
//! ```jsonc
//! {"at": "2026-06-01T20:34:51.123456Z", "level": 10, "leaf": "sha256:…", "chain": "sha256:…", "salt": "…", "fact": { "type": "step_started", … }}
//! ```
//!
//! A line whose fact is withheld from a disclosure keeps `at`, `level`,
//! `leaf` and `chain`, and drops `salt` and `fact`.
//!
//! The chain rule is in [`rite_model::commitment`]. `leaf` and `chain` are
//! derivable, and stored so a reader can name the first line where its own
//! computation disagrees: a `leaf` mismatch means the fact or its canonical
//! form differs, a `chain` mismatch with a matching leaf means the time, the
//! level or an earlier line differs. They do not stop a forger, who rewrites
//! them; what ties a transcript to a ceremony is the fingerprint, the `chain`
//! of the last line, compared against the value written down at the end of
//! the run.
//!
//! `at` is the event's wall-clock time, supplied by the executor's clock when
//! it emits the fact (the sink records it rather than choosing it, so the time
//! is independent of the storage backend). It is committed in the chain as
//! the exact string on the line.
//!
//! # Implementations
//!
//! - [`JsonlFileSink`], writes to disk, flushes after every line.
//! - [`InMemorySink`], collects facts in a `Vec` for tests and tooling.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use rand::TryRng;
use rand::rngs::SysRng;
use serde::Deserialize;
use thiserror::Error;

use rite_model::bundle::TRANSCRIPT_FILE;
use rite_model::commitment::{SALT_LEN, chain_node, fact_leaf, header_node};
use rite_model::{
    FACT_TYPES, Level, Sha256Digest, StepFact, TRANSCRIPT_FORMAT, TRANSCRIPT_SCHEMA,
    TranscriptHeader, canonical_json,
};

/// A transcript's fingerprint: the `chain` of its last line.
pub type TranscriptFingerprint = Sha256Digest;

/// Synchronous, durable observer of [`StepFact`]s.
///
/// Implementations must record each fact, including syncing it to the
/// underlying storage where applicable, before returning. The executor
/// relies on this to maintain the invariant that the UI never sees a fact
/// that has not been durably persisted.
pub trait TranscriptSink: Send {
    /// Write the header line. Must be called once, before any fact.
    ///
    /// # Errors
    ///
    /// Returns an error if the header was already written, or the underlying
    /// I/O error if the sink cannot persist it.
    fn begin(&mut self, header: &TranscriptHeader) -> io::Result<()>;

    /// Record a single fact at `level`, stamped with the caller-supplied
    /// event time `at`. Must persist before returning, the file-backed
    /// implementation calls `sync_data` so a power loss after `record` returns
    /// cannot drop the fact.
    ///
    /// `at` and `level` are supplied by the executor, not chosen here, so the
    /// sink stays a serializer with no policy of its own.
    ///
    /// # Errors
    ///
    /// Returns an error if the header has not been written or the transcript
    /// is finalized, if the header does not declare `level`, if the fact holds
    /// a value the canonical form does not cover, or the underlying I/O error
    /// if the sink cannot persist the fact.
    fn record(&mut self, at: DateTime<Utc>, level: Level, fact: &StepFact) -> io::Result<()>;

    /// Finalize the transcript and return its fingerprint.
    ///
    /// Calling `finalize` more than once is implementation-defined; the
    /// default expectation is that the second call returns the cached
    /// fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the header was never written, or the underlying
    /// I/O error if any pending state cannot be persisted.
    fn finalize(&mut self) -> io::Result<TranscriptFingerprint>;
}

/// The chain as a sink builds it: the last node, the levels the header
/// declares, and whether the run is over.
///
/// Committing to a line does not advance the chain. The sink advances it once
/// the line is persisted, so a failed write leaves the chain where the file is.
#[derive(Debug, Default)]
struct Chain {
    node: Option<[u8; 32]>,
    levels: Vec<Level>,
    finalized: bool,
}

/// A line committed to but not yet persisted: its canonical content and the
/// values the line records beside it.
enum Committed {
    Header {
        canonical: String,
        node: [u8; 32],
        levels: Vec<Level>,
    },
    Fact {
        at: String,
        level: Level,
        salt: [u8; SALT_LEN],
        canonical: String,
        leaf: [u8; 32],
        node: [u8; 32],
    },
}

impl Committed {
    fn node(&self) -> [u8; 32] {
        match self {
            Committed::Header { node, .. } | Committed::Fact { node, .. } => *node,
        }
    }

    /// The line as written to `transcript.jsonl`.
    fn line(&self) -> String {
        match self {
            Committed::Header {
                canonical, node, ..
            } => format!(
                "{{\"$schema\":\"{TRANSCRIPT_SCHEMA}\",\"header\":{canonical},\"chain\":\"{}\"}}",
                Sha256Digest::from_bytes(node),
            ),
            Committed::Fact {
                at,
                level,
                salt,
                canonical,
                leaf,
                node,
            } => format!(
                "{{\"at\":\"{at}\",\"level\":{},\"leaf\":\"{}\",\"chain\":\"{}\",\"salt\":\"{}\",\"fact\":{canonical}}}",
                level.value(),
                Sha256Digest::from_bytes(leaf),
                Sha256Digest::from_bytes(node),
                base16ct::lower::encode_string(salt),
            ),
        }
    }
}

impl Chain {
    fn header(&self, header: &TranscriptHeader) -> io::Result<Committed> {
        if self.node.is_some() {
            return Err(io::Error::other("transcript header already written"));
        }
        let value = serde_json::to_value(header).map_err(io::Error::other)?;
        let canonical = canonical_json(&value).map_err(io::Error::other)?;
        let node = header_node(&canonical);
        Ok(Committed::Header {
            canonical,
            node,
            levels: header.levels.values().copied().collect(),
        })
    }

    fn fact(&self, at: DateTime<Utc>, level: Level, fact: &StepFact) -> io::Result<Committed> {
        let previous = self
            .node
            .ok_or_else(|| io::Error::other("transcript header not written"))?;
        if self.finalized {
            return Err(io::Error::other("transcript already finalized"));
        }
        // A reader refuses a line at a level the header does not name.
        if !self.levels.contains(&level) {
            return Err(io::Error::other(format!(
                "level {} is not declared in the transcript header",
                level.value()
            )));
        }
        let value = serde_json::to_value(fact).map_err(io::Error::other)?;
        let canonical = canonical_json(&value).map_err(io::Error::other)?;
        let mut salt = [0u8; SALT_LEN];
        SysRng.try_fill_bytes(&mut salt).map_err(io::Error::other)?;
        let leaf = fact_leaf(&salt, &canonical);
        let at = at.to_rfc3339_opts(SecondsFormat::Micros, true);
        let node = chain_node(&previous, &at, level, &leaf);
        Ok(Committed::Fact {
            at,
            level,
            salt,
            canonical,
            leaf,
            node,
        })
    }

    fn advance(&mut self, committed: &Committed) {
        self.node = Some(committed.node());
        if let Committed::Header { levels, .. } = committed {
            self.levels.clone_from(levels);
        }
    }

    fn finalize(&mut self) -> io::Result<TranscriptFingerprint> {
        let node = self
            .node
            .ok_or_else(|| io::Error::other("transcript header not written"))?;
        self.finalized = true;
        Ok(Sha256Digest::from_bytes(&node))
    }
}

/// JSONL file sink with a salted commitment chain.
///
/// Writes `transcript.jsonl` to a target directory, one line per call,
/// flushed and synced before returning. The transcript is self-identifying:
/// the `chain` of its last line is the fingerprint, and no sidecar file is
/// written.
#[derive(Debug)]
pub struct JsonlFileSink {
    jsonl_path: PathBuf,
    writer: BufWriter<File>,
    chain: Chain,
}

impl JsonlFileSink {
    /// Create a new sink in `dir`. Writes `transcript.jsonl` next to it.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the JSONL file cannot be created.
    pub fn create(dir: &Path) -> io::Result<Self> {
        let jsonl_path = dir.join(TRANSCRIPT_FILE);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&jsonl_path)?;
        Ok(Self {
            jsonl_path,
            writer: BufWriter::new(file),
            chain: Chain::default(),
        })
    }

    /// Append one line and sync it to storage.
    fn append(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        // `flush` drains the BufWriter into the File; `sync_data` then
        // forces the kernel to push the page-cache pages to the storage
        // device before we return. Without the sync, a power loss between
        // `record` and the OS's next writeback would drop already-reported
        // facts even though the executor moved on. Cost at ceremony pace
        // (one record every few seconds of human pace) is negligible.
        self.writer.flush()?;
        self.writer.get_ref().sync_data()
    }

    /// Path to the JSONL file this sink is writing to.
    #[must_use]
    pub fn jsonl_path(&self) -> &Path {
        &self.jsonl_path
    }
}

impl TranscriptSink for JsonlFileSink {
    fn begin(&mut self, header: &TranscriptHeader) -> io::Result<()> {
        let committed = self.chain.header(header)?;
        self.append(&committed.line())?;
        self.chain.advance(&committed);
        Ok(())
    }

    fn record(&mut self, at: DateTime<Utc>, level: Level, fact: &StepFact) -> io::Result<()> {
        let committed = self.chain.fact(at, level, fact)?;
        self.append(&committed.line())?;
        self.chain.advance(&committed);
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<TranscriptFingerprint> {
        self.chain.finalize()
    }
}

/// In-memory sink that collects every recorded [`StepFact`].
///
/// Useful for tests and for tooling that wants to inspect the fact stream
/// without going through disk. It builds the same chain as the file sink, so
/// its fingerprint is the one the file would have.
#[derive(Debug, Default)]
pub struct InMemorySink {
    header: Option<TranscriptHeader>,
    facts: Vec<StepFact>,
    chain: Chain,
}

impl InMemorySink {
    /// Create an empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The header, once written.
    #[must_use]
    pub fn header(&self) -> Option<&TranscriptHeader> {
        self.header.as_ref()
    }

    /// Recorded facts in the order they arrived.
    #[must_use]
    pub fn facts(&self) -> &[StepFact] {
        &self.facts
    }

    /// Number of facts recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether any fact has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

impl TranscriptSink for InMemorySink {
    fn begin(&mut self, header: &TranscriptHeader) -> io::Result<()> {
        let committed = self.chain.header(header)?;
        self.chain.advance(&committed);
        self.header = Some(header.clone());
        Ok(())
    }

    fn record(&mut self, at: DateTime<Utc>, level: Level, fact: &StepFact) -> io::Result<()> {
        let committed = self.chain.fact(at, level, fact)?;
        self.chain.advance(&committed);
        self.facts.push(fact.clone());
        Ok(())
    }

    fn finalize(&mut self) -> io::Result<TranscriptFingerprint> {
        self.chain.finalize()
    }
}

/// The header line as read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderLine {
    /// Read so a line that carries it parses; nothing depends on it.
    #[serde(rename = "$schema", default)]
    _schema: Option<String>,
    header: serde_json::Value,
    chain: Sha256Digest,
}

/// A fact line as read, complete or withheld.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactLine {
    at: String,
    level: Level,
    #[serde(default, deserialize_with = "present")]
    salt: Option<String>,
    #[serde(default, deserialize_with = "present")]
    fact: Option<serde_json::Value>,
    leaf: Sha256Digest,
    chain: Sha256Digest,
}

/// A member that is on the line is `Some`, `null` included, so only an absent
/// `salt` and `fact` make a withheld line, as the schema has it.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A recorded fact with its line's time and level.
///
/// The event time lives on the line rather than on individual facts, so
/// consumers read it uniformly.
#[derive(Debug, Clone)]
pub struct TimedFact {
    /// 1-based line number in the transcript.
    pub line: usize,
    /// Wall-clock time the fact was recorded.
    pub at: DateTime<Utc>,
    /// Confidentiality level the line was recorded at.
    pub level: Level,
    /// The recorded fact.
    pub fact: StepFact,
}

/// A line whose fact is withheld: the transcript was disclosed without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithheldLine {
    /// 1-based line number.
    pub line: usize,
    /// Level the withheld fact was recorded at.
    pub level: Level,
}

/// A line whose fact has a type this reader does not know, from a newer
/// vocabulary. Its commitment is checked; its content is not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFact {
    /// 1-based line number.
    pub line: usize,
    /// Level the line was recorded at.
    pub level: Level,
    /// The fact's `type` tag.
    pub type_name: String,
}

/// Outcome of verifying a transcript on disk.
#[derive(Debug, Clone)]
pub struct TranscriptVerified {
    /// The header line.
    pub header: TranscriptHeader,
    /// Number of facts read and verified, the header not included.
    pub fact_count: usize,
    /// Final transcript fingerprint (the `chain` of the last line).
    pub fingerprint: TranscriptFingerprint,
    /// `true` if the last fact is a terminal one (`CeremonyCompleted` or
    /// `CeremonyFailed`). `false` means the transcript was cut off
    /// before the executor reached its finalize step, a truncated run.
    pub terminated: bool,
}

/// Verification failure modes.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Underlying I/O error reading the transcript.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// A line did not parse as a transcript line.
    #[error("line {line} is not a valid transcript line: {reason}")]
    InvalidLine {
        /// 1-indexed line number.
        line: usize,
        /// Parse error.
        reason: String,
    },
    /// A fact does not match the leaf recorded beside it: the fact, its
    /// salt, or the way it was canonicalised differs from what was committed.
    #[error(
        "line {line}: the fact does not match its leaf (computed {computed}, recorded {recorded})"
    )]
    LeafMismatch {
        /// 1-indexed line number.
        line: usize,
        /// Leaf computed from the salt and fact on the line.
        computed: String,
        /// Leaf recorded on the line.
        recorded: String,
    },
    /// A line's chain value is not the one its time, level, leaf and the
    /// line before it produce.
    #[error("line {line}: the chain breaks here (computed {computed}, recorded {recorded})")]
    ChainMismatch {
        /// 1-indexed line number where the break was detected.
        line: usize,
        /// Chain value computed from the line and the one before.
        computed: String,
        /// Chain value recorded on the line.
        recorded: String,
    },
    /// The transcript file has zero lines.
    #[error("transcript is empty")]
    Empty,
    /// The first line is not a transcript header.
    #[error("line 1 is not a transcript header: {0}")]
    MissingHeader(String),
    /// The header's level table is unusable: a built-in level is missing or
    /// moved, or two names share a value.
    #[error("the header's levels are invalid: {0}")]
    InvalidLevels(String),
    /// The header declares a transcript format this verifier does not know.
    /// The format fixes how every line is read, so nothing else is attempted.
    #[error("unknown transcript format {0} (this verifier reads format {TRANSCRIPT_FORMAT})")]
    UnknownFormat(u64),
    /// A value was drawn (or a contribution folded) before any
    /// `EntropySeeded` fact established the source.
    #[error("entropy source used before it was seeded")]
    SeedMissing,
    /// A second `EntropySeeded` fact appeared. The source is seeded exactly
    /// once at ceremony start; accepting a re-seed would let a crafted
    /// transcript swap the seed mid-stream and have later draws "verify"
    /// against a seed of the forger's choosing.
    #[error("entropy source seeded more than once")]
    DuplicateSeed,
    /// The seed fact declares a derivation scheme the verifier does not
    /// recognise. Never trust an unknown scheme (the JWT-`alg` lesson).
    #[error("unknown entropy derivation scheme: {0}")]
    UnknownDerivation(String),
    /// A recorded hex value (the seed `m` or a drawn value) did not decode.
    #[error("malformed entropy value: {0}")]
    MalformedEntropy(String),
    /// A drawn value does not match what re-derivation from the recorded
    /// seed and path produces: the source was tampered with.
    #[error("entropy draw at path '{path}' does not match re-derived value")]
    DrawMismatch {
        /// Derivation path of the mismatched draw.
        path: String,
    },
    /// A recorded draw is longer than `HKDF-Expand` can produce
    /// ([`MAX_DRAW_LEN`](crate::entropy::MAX_DRAW_LEN) bytes), so it cannot
    /// have come from the real source. Rejected up front: attempting the
    /// re-derivation would abort the verifier instead of failing the check.
    #[error(
        "entropy draw at path '{path}' records {len} bytes, beyond the {max}-byte HKDF-Expand limit"
    )]
    DrawTooLong {
        /// Derivation path of the oversized draw.
        path: String,
        /// Recorded value length in bytes.
        len: usize,
        /// The `HKDF-Expand` output limit.
        max: usize,
    },
    /// A draw's recorded path does not start with the
    /// `<epoch>/<step>/` prefix the verifier rebuilds from its own fold
    /// count and the step named on the fact, so the draw is attributed to
    /// the wrong epoch or step.
    #[error("entropy draw path '{path}' does not match expected '{expected_prefix}<purpose>'")]
    PathMismatch {
        /// Recorded derivation path.
        path: String,
        /// The `<epoch>/<step>/` prefix the verifier expected.
        expected_prefix: String,
    },
    /// A contribution's recorded epoch does not match its position in the
    /// fold sequence (first contribution is epoch 1, and so on).
    #[error("entropy contribution at step '{step}' records epoch {recorded}, expected {expected}")]
    EpochMismatch {
        /// Step that recorded the contribution.
        step: String,
        /// Epoch index recorded on the fact.
        recorded: u32,
        /// Epoch index implied by the fold count.
        expected: u32,
    },
    /// The same derivation path was drawn twice. The runtime never reuses a
    /// path, so a duplicate means the record was edited or replayed.
    #[error("entropy draw path '{path}' recorded more than once")]
    DuplicateDrawPath {
        /// The repeated derivation path.
        path: String,
    },
}

/// Verify a JSONL transcript file produced by [`JsonlFileSink`].
///
/// Reads the file line by line, recomputes every leaf and chain value, and
/// checks each against the checkpoints recorded on the line.
///
/// # Errors
///
/// Returns [`VerifyError`] for any I/O failure, malformed line, or
/// commitment mismatch.
pub fn verify_transcript(jsonl_path: &Path) -> Result<TranscriptVerified, VerifyError> {
    let loaded = read_verified_transcript(jsonl_path)?;
    Ok(TranscriptVerified {
        header: loaded.header,
        fact_count: loaded.facts.len(),
        fingerprint: loaded.fingerprint,
        terminated: loaded.terminated,
    })
}

/// Verified transcript contents: the facts, what could not be read, the
/// fingerprint, and whether the run reached a terminal fact.
#[derive(Debug, Clone)]
pub struct LoadedTranscript {
    /// The header line.
    pub header: TranscriptHeader,
    /// Facts in the order they were recorded, each with its line's time and
    /// level. Withheld and unknown facts are not in this list.
    pub facts: Vec<TimedFact>,
    /// Lines whose fact is withheld.
    pub withheld: Vec<WithheldLine>,
    /// Lines whose fact has a type this reader does not know.
    pub unknown: Vec<UnknownFact>,
    /// Final transcript fingerprint (the `chain` of the last line).
    pub fingerprint: TranscriptFingerprint,
    /// `true` if the last line is a disclosed `CeremonyCompleted` or
    /// `CeremonyFailed`.
    pub terminated: bool,
}

/// Verify a JSONL transcript and return its facts.
///
/// Same check as [`verify_transcript`], plus returns the deserialized
/// [`StepFact`] stream, the withheld and unknown lines, and whether the last
/// line is a terminal fact.
///
/// # Errors
///
/// Same as [`verify_transcript`].
pub fn read_verified_transcript(jsonl_path: &Path) -> Result<LoadedTranscript, VerifyError> {
    let file = File::open(jsonl_path)?;
    verify_lines(BufReader::new(file).lines())
}

/// [`read_verified_transcript`] over a transcript already in memory.
///
/// # Errors
///
/// Same as [`verify_transcript`].
pub fn verify_jsonl(jsonl: &str) -> Result<LoadedTranscript, VerifyError> {
    verify_lines(jsonl.lines().map(|line| Ok(line.to_string())))
}

fn verify_lines(
    mut lines: impl Iterator<Item = io::Result<String>>,
) -> Result<LoadedTranscript, VerifyError> {
    let first = lines.next().ok_or(VerifyError::Empty)??;
    let (header, mut node) = read_header(&first)?;

    let mut loaded = LoadedTranscript {
        header,
        facts: Vec::new(),
        withheld: Vec::new(),
        unknown: Vec::new(),
        fingerprint: Sha256Digest::from_bytes(&node),
        terminated: false,
    };

    for (idx, line) in lines.enumerate() {
        let line = line?;
        // Line 1 is the header; facts start on line 2.
        let line_no = idx.saturating_add(2);
        node = read_fact_line(&line, line_no, &node, &mut loaded)?;
    }

    loaded.fingerprint = Sha256Digest::from_bytes(&node);
    Ok(loaded)
}

/// Withhold every fact recorded above `threshold`, keeping each line's
/// commitments, so the result folds to the same fingerprint.
///
/// The header and every line at or below the threshold are copied unchanged.
/// A withheld line keeps its `at`, `level`, `leaf` and `chain` and loses its
/// `salt` and `fact`. Lines already withheld stay withheld. The input is not
/// verified here; verify it before, and the output after.
///
/// # Errors
///
/// Returns [`VerifyError::Empty`] for an empty transcript, or
/// [`VerifyError::InvalidLine`] for a fact line that does not parse.
pub fn disclose_transcript(jsonl: &str, threshold: Level) -> Result<String, VerifyError> {
    let mut lines = jsonl.lines();
    let header = lines.next().ok_or(VerifyError::Empty)?;
    let mut out = String::with_capacity(jsonl.len());
    out.push_str(header);
    out.push('\n');
    for (idx, line) in lines.enumerate() {
        // Line 1 is the header; facts start on line 2.
        let line_no = idx.saturating_add(2);
        let parsed: FactLine = serde_json::from_str(line).map_err(|e| invalid(line_no, &e))?;
        if parsed.level > threshold && parsed.fact.is_some() {
            out.push_str(&withheld_line(&parsed)?);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Ok(out)
}

/// The withheld form of a line: its commitments without its content.
fn withheld_line(line: &FactLine) -> Result<String, VerifyError> {
    let at = serde_json::to_string(&line.at).map_err(|e| invalid(0, &e))?;
    Ok(format!(
        "{{\"at\":{at},\"level\":{},\"leaf\":\"{}\",\"chain\":\"{}\"}}",
        line.level.value(),
        line.leaf,
        line.chain,
    ))
}

/// Read and check the header line, returning the header and `node_0`.
fn read_header(line: &str) -> Result<(TranscriptHeader, [u8; 32]), VerifyError> {
    let parsed: HeaderLine =
        serde_json::from_str(line).map_err(|e| VerifyError::MissingHeader(e.to_string()))?;
    // The format decides how everything else is read, so it is checked
    // before the header's own commitment.
    let format = parsed
        .header
        .get("rite_transcript")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| VerifyError::MissingHeader("no rite_transcript version".to_string()))?;
    if format != u64::from(TRANSCRIPT_FORMAT) {
        return Err(VerifyError::UnknownFormat(format));
    }
    let canonical = canonical_json(&parsed.header).map_err(|e| invalid(1, &e))?;
    let node = header_node(&canonical);
    check_checkpoint(&parsed.chain, &node, |computed, recorded| {
        VerifyError::ChainMismatch {
            line: 1,
            computed,
            recorded,
        }
    })?;
    let header: TranscriptHeader = serde_json::from_value(parsed.header)
        .map_err(|e| VerifyError::MissingHeader(e.to_string()))?;
    check_levels(&header)?;
    Ok((header, node))
}

/// The built-in levels must appear at their fixed values, and no two names may
/// share a value, so every line's level has exactly one name.
fn check_levels(header: &TranscriptHeader) -> Result<(), VerifyError> {
    for (name, level) in Level::BUILT_IN {
        if header.levels.get(name) != Some(&level) {
            return Err(VerifyError::InvalidLevels(format!(
                "'{name}' must be {}",
                level.value()
            )));
        }
    }
    let mut seen = HashSet::new();
    for level in header.levels.values() {
        if !seen.insert(*level) {
            return Err(VerifyError::InvalidLevels(format!(
                "more than one name for {}",
                level.value()
            )));
        }
    }
    Ok(())
}

/// Read and check one fact line, adding its fact to `loaded`, and return the
/// chain value after it.
fn read_fact_line(
    line: &str,
    line_no: usize,
    previous: &[u8; 32],
    loaded: &mut LoadedTranscript,
) -> Result<[u8; 32], VerifyError> {
    let parsed: FactLine = serde_json::from_str(line).map_err(|e| invalid(line_no, &e))?;
    if !loaded.header.declares(parsed.level) {
        return Err(invalid(
            line_no,
            &format!(
                "level {} is not declared in the header",
                parsed.level.value()
            ),
        ));
    }
    let at: DateTime<Utc> = DateTime::parse_from_rfc3339(&parsed.at)
        .map_err(|e| invalid(line_no, &e))?
        .with_timezone(&Utc);

    let leaf = match (parsed.salt, parsed.fact) {
        (Some(salt), Some(fact)) => {
            let salt = decode_salt(&salt).ok_or_else(|| {
                invalid(
                    line_no,
                    &format!("salt is not {SALT_LEN} bytes of lowercase hex"),
                )
            })?;
            let canonical = canonical_json(&fact).map_err(|e| invalid(line_no, &e))?;
            let leaf = fact_leaf(&salt, &canonical);
            check_checkpoint(&parsed.leaf, &leaf, |computed, recorded| {
                VerifyError::LeafMismatch {
                    line: line_no,
                    computed,
                    recorded,
                }
            })?;
            loaded.terminated = add_fact(fact, at, parsed.level, line_no, loaded)?;
            leaf
        }
        (None, None) => {
            loaded.withheld.push(WithheldLine {
                line: line_no,
                level: parsed.level,
            });
            loaded.terminated = false;
            parsed.leaf.to_bytes()
        }
        _ => {
            return Err(invalid(
                line_no,
                &"a line carries both `salt` and `fact`, or neither",
            ));
        }
    };

    let node = chain_node(previous, &parsed.at, parsed.level, &leaf);
    check_checkpoint(&parsed.chain, &node, |computed, recorded| {
        VerifyError::ChainMismatch {
            line: line_no,
            computed,
            recorded,
        }
    })?;
    Ok(node)
}

/// Parse a disclosed fact into `loaded`, returning whether it is terminal.
///
/// A fact whose type this vocabulary does not know is counted rather than
/// read; a known type that does not parse is an error.
fn add_fact(
    fact: serde_json::Value,
    at: DateTime<Utc>,
    level: Level,
    line_no: usize,
    loaded: &mut LoadedTranscript,
) -> Result<bool, VerifyError> {
    let type_name = fact
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid(line_no, &"the fact has no `type`"))?
        .to_string();
    if !FACT_TYPES.contains(&type_name.as_str()) {
        loaded.unknown.push(UnknownFact {
            line: line_no,
            level,
            type_name,
        });
        return Ok(false);
    }
    let fact: StepFact = serde_json::from_value(fact).map_err(|e| invalid(line_no, &e))?;
    let terminal = matches!(
        fact,
        StepFact::CeremonyCompleted { .. } | StepFact::CeremonyFailed { .. }
    );
    loaded.facts.push(TimedFact {
        line: line_no,
        at,
        level,
        fact,
    });
    Ok(terminal)
}

fn decode_salt(hex: &str) -> Option<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    let decoded = base16ct::lower::decode(hex, &mut salt).ok()?;
    (decoded.len() == SALT_LEN).then_some(salt)
}

/// Compare a computed value against the checkpoint recorded on a line.
fn check_checkpoint(
    recorded: &Sha256Digest,
    computed: &[u8; 32],
    mismatch: impl FnOnce(String, String) -> VerifyError,
) -> Result<(), VerifyError> {
    if recorded.to_bytes() == *computed {
        Ok(())
    } else {
        Err(mismatch(
            Sha256Digest::from_bytes(computed).to_string(),
            recorded.to_string(),
        ))
    }
}

fn invalid(line: usize, reason: &impl std::fmt::Display) -> VerifyError {
    VerifyError::InvalidLine {
        line,
        reason: reason.to_string(),
    }
}

/// Outcome of re-deriving a transcript's entropy source.
#[derive(Debug, Clone, Default)]
pub struct EntropyVerified {
    /// Derivation-scheme tag declared by the seed fact, if the ceremony used
    /// the source at all.
    pub derivation: Option<String>,
    /// Provenance of the machine seed as recorded by the seed fact (e.g.
    /// `os`, or the `dry-run` sentinel). Consumers surface this so a
    /// dry-run transcript, which re-derives just as cleanly as a real one,
    /// is never presented as real evidence.
    pub source: Option<String>,
    /// Number of human contributions folded into the ratchet.
    pub contributions: usize,
    /// Number of drawn values that re-derived to their recorded value.
    pub values_verified: usize,
}

/// Re-derive a transcript's entropy source and confirm every drawn value.
///
/// Replays the `rite-kdf/v1` ratchet over the recorded facts: it rebuilds
/// `seed_0` from the recorded machine entropy, folds each human contribution
/// in chain order, and for every [`StepFact::EntropyDrawn`] re-derives the
/// value from the recorded path and checks it against the recorded value. A
/// tampered seed, contribution, path, or value fails the check.
///
/// Beyond the value re-derivation, the replay enforces the source's own
/// invariants, so a transcript cannot record a fact stream the runtime could
/// never have produced:
///
/// - the source is seeded exactly once;
/// - each contribution's recorded `epoch` matches its position in the fold
///   sequence;
/// - each draw's recorded path carries the `<epoch>/<step>/` prefix rebuilt
///   from the verifier's own fold count and the step named on the fact;
/// - no derivation path is drawn twice;
/// - no recorded value exceeds what `HKDF-Expand` can produce
///   ([`MAX_DRAW_LEN`](crate::entropy::MAX_DRAW_LEN) bytes), which would
///   otherwise abort the verifier instead of failing the check.
///
/// The caller is expected to have chain-verified the facts first (via
/// [`read_verified_transcript`]); this function only re-derives.
///
/// # Errors
///
/// Returns a [`VerifyError`] variant describing the first inconsistency:
/// [`VerifyError::SeedMissing`], [`VerifyError::DuplicateSeed`],
/// [`VerifyError::UnknownDerivation`], [`VerifyError::MalformedEntropy`],
/// [`VerifyError::EpochMismatch`], [`VerifyError::PathMismatch`],
/// [`VerifyError::DuplicateDrawPath`], [`VerifyError::DrawTooLong`], or
/// [`VerifyError::DrawMismatch`].
pub fn verify_entropy<'a>(
    facts: impl IntoIterator<Item = &'a StepFact>,
) -> Result<EntropyVerified, VerifyError> {
    let mut seed: Option<[u8; 32]> = None;
    let mut epoch: u32 = 0;
    let mut drawn_paths: HashSet<String> = HashSet::new();
    let mut result = EntropyVerified::default();

    for fact in facts {
        match fact {
            StepFact::EntropySeeded {
                m,
                source,
                derivation,
                ..
            } => {
                if seed.is_some() {
                    return Err(VerifyError::DuplicateSeed);
                }
                if derivation != crate::entropy::DERIVATION_V1 {
                    return Err(VerifyError::UnknownDerivation(derivation.clone()));
                }
                let m_bytes = base16ct::lower::decode_vec(m)
                    .map_err(|e| VerifyError::MalformedEntropy(format!("seed m: {e}")))?;
                seed = Some(crate::entropy::initial_seed(&m_bytes));
                result.derivation = Some(derivation.clone());
                result.source = Some(source.clone());
            }
            StepFact::EntropyContributed {
                step,
                epoch: recorded_epoch,
                contribution,
                ..
            } => {
                let current = seed.as_ref().ok_or(VerifyError::SeedMissing)?;
                let expected = epoch.saturating_add(1);
                if *recorded_epoch != expected {
                    return Err(VerifyError::EpochMismatch {
                        step: step.as_str().to_string(),
                        recorded: *recorded_epoch,
                        expected,
                    });
                }
                seed = Some(crate::entropy::fold_seed(current, contribution.as_bytes()));
                epoch = expected;
                result.contributions = result.contributions.saturating_add(1);
            }
            StepFact::EntropyDrawn {
                step, path, value, ..
            } => {
                let current = seed.as_ref().ok_or(VerifyError::SeedMissing)?;
                // Rebuild the path prefix from the verifier's own fold count
                // and the step named on the fact; only the purpose segment is
                // taken from the record. A draw attributed to the wrong epoch
                // or step fails here even if its value re-derives.
                let expected_prefix = crate::entropy::build_path(epoch, step, "");
                if !path.starts_with(&expected_prefix) || path.len() == expected_prefix.len() {
                    return Err(VerifyError::PathMismatch {
                        path: path.clone(),
                        expected_prefix,
                    });
                }
                if !drawn_paths.insert(path.clone()) {
                    return Err(VerifyError::DuplicateDrawPath { path: path.clone() });
                }
                // The recorded value's own length fixes how many bytes to
                // re-derive; decoding it also rejects a malformed hex record.
                let recorded = base16ct::lower::decode_vec(value)
                    .map_err(|e| VerifyError::MalformedEntropy(format!("draw {path}: {e}")))?;
                if recorded.len() > crate::entropy::MAX_DRAW_LEN {
                    return Err(VerifyError::DrawTooLong {
                        path: path.clone(),
                        len: recorded.len(),
                        max: crate::entropy::MAX_DRAW_LEN,
                    });
                }
                let expected = crate::entropy::derive_value(current, path, recorded.len());
                if expected != recorded {
                    return Err(VerifyError::DrawMismatch { path: path.clone() });
                }
                result.values_verified = result.values_verified.saturating_add(1);
            }
            _ => {}
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixed_test_time as test_at;

    fn sample_fact() -> StepFact {
        crate::test_support::ceremony_started("Test")
    }

    fn begun_file_sink(dir: &Path) -> JsonlFileSink {
        let mut sink = JsonlFileSink::create(dir).expect("create");
        sink.begin(&crate::test_support::test_header())
            .expect("header");
        sink
    }

    #[test]
    fn in_memory_sink_records_and_finalizes() {
        let mut sink = crate::test_support::begun_sink();
        assert!(sink.is_empty());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        assert_eq!(sink.len(), 1);
        let fp = sink.finalize().expect("finalize");
        assert!(fp.as_str().starts_with("sha256:"));
    }

    #[test]
    fn in_memory_sink_rejects_record_after_finalize() {
        let mut sink = crate::test_support::begun_sink();
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.finalize().expect("finalize");
        let err = sink
            .record(test_at(), Level::PUBLIC, &sample_fact())
            .expect_err("should fail");
        assert!(err.to_string().contains("already finalized"));
    }

    #[test]
    fn in_memory_sink_chain_advances() {
        let mut sink = crate::test_support::begun_sink();
        let initial = sink.chain.node;
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        assert_ne!(sink.chain.node, initial);
        let after_first = sink.chain.node;
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        assert_ne!(sink.chain.node, after_first);
    }

    #[test]
    fn record_persists_the_supplied_time_and_reader_recovers_it() {
        // The sink records the `at` it is given (it does not read a clock), and
        // the reader recovers exactly that instant from the envelope.
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        let at = test_at();
        sink.record(at, Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.finalize().expect("finalize");

        let loaded = read_verified_transcript(sink.jsonl_path()).expect("read");
        assert_eq!(loaded.facts.first().expect("one fact").at, at);
    }

    #[test]
    fn jsonl_file_sink_writes_checkpoints_that_fold_to_the_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.record(test_at(), Level::RESTRICTED, &sample_fact())
            .expect("record");
        let fp = sink.finalize().expect("finalize");

        let jsonl = std::fs::read_to_string(sink.jsonl_path()).expect("read jsonl");
        let lines: Vec<serde_json::Value> = jsonl
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse line"))
            .collect();
        assert_eq!(lines.len(), 3, "expected a header and two facts");
        assert!(lines.first().and_then(|l| l.get("header")).is_some());
        let second = lines.get(2).expect("second fact");
        assert_eq!(
            second.get("level").and_then(serde_json::Value::as_u64),
            Some(20)
        );
        assert_eq!(
            lines
                .last()
                .and_then(|l| l.get("chain"))
                .and_then(serde_json::Value::as_str),
            Some(fp.as_str()),
            "the last chain value is the fingerprint"
        );
    }

    #[test]
    fn two_records_of_the_same_fact_get_different_salts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        let jsonl = std::fs::read_to_string(sink.jsonl_path()).expect("read jsonl");
        let salts: Vec<String> = jsonl
            .lines()
            .skip(1)
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).expect("parse");
                v.get("salt")
                    .and_then(serde_json::Value::as_str)
                    .expect("salt")
                    .to_string()
            })
            .collect();
        assert_eq!(salts.len(), 2);
        assert_ne!(salts.first(), salts.last());
    }

    #[test]
    fn jsonl_file_sink_refuses_existing_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _first = JsonlFileSink::create(tmp.path()).expect("first");
        let err = JsonlFileSink::create(tmp.path()).expect_err("second should fail");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn verify_round_trip_succeeds_on_well_formed_transcript() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        let written = sink.finalize().expect("finalize");

        let verified = verify_transcript(sink.jsonl_path()).expect("verify");
        assert_eq!(verified.fact_count, 3);
        assert_eq!(verified.fingerprint, written);
        // Sample fact isn't a terminal one; the transcript is open-ended.
        assert!(!verified.terminated);
    }

    /// Write a transcript of a header and three facts, then return its
    /// path and lines for a test to edit.
    fn three_fact_transcript(dir: &Path) -> (PathBuf, Vec<String>) {
        let mut sink = begun_file_sink(dir);
        for _ in 0..3 {
            sink.record(test_at(), Level::PUBLIC, &sample_fact())
                .expect("record");
        }
        let path = sink.jsonl_path().to_path_buf();
        let lines = std::fs::read_to_string(&path)
            .expect("read")
            .lines()
            .map(String::from)
            .collect();
        (path, lines)
    }

    fn rewrite(path: &Path, lines: &[String]) {
        std::fs::write(path, lines.join("\n") + "\n").expect("write");
    }

    fn edit_line(lines: &mut [String], index: usize, edit: impl FnOnce(&mut serde_json::Value)) {
        let line = lines.get_mut(index).expect("line");
        let mut value: serde_json::Value = serde_json::from_str(line).expect("parse");
        edit(&mut value);
        *line = serde_json::to_string(&value).expect("serialize");
    }

    #[test]
    fn an_edited_fact_is_caught_at_its_leaf() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        edit_line(&mut lines, 2, |v| {
            if let Some(fact) = v.get_mut("fact").and_then(serde_json::Value::as_object_mut) {
                fact.insert("name".to_string(), serde_json::json!("Other"));
            }
        });
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("tampered fact");
        assert!(matches!(err, VerifyError::LeafMismatch { line: 3, .. }));
    }

    #[test]
    fn an_edited_level_is_caught_at_its_chain_value() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        edit_line(&mut lines, 2, |v| {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("level".to_string(), serde_json::json!(30));
            }
        });
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("tampered level");
        assert!(matches!(err, VerifyError::ChainMismatch { line: 3, .. }));
    }

    #[test]
    fn a_deleted_line_breaks_the_chain_at_the_next_one() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        lines.remove(2);
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("deleted line");
        assert!(matches!(err, VerifyError::ChainMismatch { line: 3, .. }));
    }

    #[test]
    fn a_withheld_line_folds_to_the_same_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        let complete = verify_transcript(&path).expect("complete").fingerprint;
        edit_line(&mut lines, 2, |v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("salt");
                obj.remove("fact");
            }
        });
        rewrite(&path, &lines);
        let loaded = read_verified_transcript(&path).expect("withheld");
        assert_eq!(loaded.fingerprint, complete);
        assert_eq!(
            loaded.withheld,
            vec![WithheldLine {
                line: 3,
                level: Level::PUBLIC
            }]
        );
        assert_eq!(loaded.facts.len(), 2);
    }

    #[test]
    fn disclosing_withholds_above_the_threshold_and_keeps_the_fingerprint() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        for level in [Level::PUBLIC, Level::CONFIDENTIAL, Level::RESTRICTED] {
            sink.record(test_at(), level, &sample_fact())
                .expect("record");
        }
        let complete = sink.finalize().expect("finalize");
        let text = std::fs::read_to_string(sink.jsonl_path()).expect("read");

        let disclosed = disclose_transcript(&text, Level::RESTRICTED).expect("disclose");
        let path = tmp.path().join("disclosed.jsonl");
        std::fs::write(&path, &disclosed).expect("write");
        let loaded = read_verified_transcript(&path).expect("verify");

        assert_eq!(loaded.fingerprint, complete);
        assert_eq!(
            loaded.withheld,
            vec![WithheldLine {
                line: 3,
                level: Level::CONFIDENTIAL
            }]
        );
        assert_eq!(loaded.facts.len(), 2);
        // Disclosing again at the same threshold changes nothing.
        assert_eq!(
            disclose_transcript(&disclosed, Level::RESTRICTED).expect("again"),
            disclosed
        );
    }

    #[test]
    fn a_line_with_a_fact_and_no_salt_is_invalid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        edit_line(&mut lines, 2, |v| {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("salt");
            }
        });
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("half-withheld line");
        assert!(matches!(err, VerifyError::InvalidLine { line: 3, .. }));
    }

    #[test]
    fn a_line_with_null_salt_and_fact_is_not_withheld() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        edit_line(&mut lines, 2, |v| {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("salt".to_string(), serde_json::Value::Null);
                obj.insert("fact".to_string(), serde_json::Value::Null);
            }
        });
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("null members");
        assert!(matches!(err, VerifyError::InvalidLine { line: 3, .. }));
    }

    #[test]
    fn an_unknown_fact_type_is_counted_not_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        let path = sink.jsonl_path().to_path_buf();
        let mut lines: Vec<String> = std::fs::read_to_string(&path)
            .expect("read")
            .lines()
            .map(String::from)
            .collect();
        // A fact from a newer vocabulary, committed correctly.
        let previous: serde_json::Value =
            serde_json::from_str(lines.last().expect("last")).expect("parse");
        let previous_node = Sha256Digest::parse(
            previous
                .get("chain")
                .and_then(serde_json::Value::as_str)
                .expect("chain"),
        )
        .expect("digest")
        .to_bytes();
        let fact = serde_json::json!({ "type": "future_fact", "detail": 1 });
        let salt = [7u8; SALT_LEN];
        let leaf = fact_leaf(&salt, &canonical_json(&fact).expect("canonical"));
        let at = "2026-09-22T10:00:00.000000Z";
        let node = chain_node(&previous_node, at, Level::PUBLIC, &leaf);
        lines.push(
            serde_json::json!({
                "at": at,
                "level": 10,
                "salt": base16ct::lower::encode_string(&salt),
                "fact": fact,
                "leaf": Sha256Digest::from_bytes(&leaf).as_str(),
                "chain": Sha256Digest::from_bytes(&node).as_str(),
            })
            .to_string(),
        );
        rewrite(&path, &lines);

        let loaded = read_verified_transcript(&path).expect("read");
        assert_eq!(
            loaded.unknown,
            vec![UnknownFact {
                line: 3,
                level: Level::PUBLIC,
                type_name: "future_fact".to_string()
            }]
        );
        assert_eq!(loaded.facts.len(), 1);
    }

    #[test]
    fn verify_empty_transcript_returns_empty_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("transcript.jsonl");
        std::fs::write(&path, "").expect("write empty");
        let err = verify_transcript(&path).expect_err("empty");
        assert!(matches!(err, VerifyError::Empty));
    }

    #[test]
    fn a_fact_before_the_header_is_refused() {
        let mut sink = InMemorySink::new();
        let err = sink
            .record(test_at(), Level::PUBLIC, &sample_fact())
            .expect_err("no header yet");
        assert!(err.to_string().contains("header not written"));
    }

    #[test]
    fn a_second_header_is_refused() {
        let mut sink = crate::test_support::begun_sink();
        let err = sink
            .begin(&crate::test_support::test_header())
            .expect_err("second header");
        assert!(err.to_string().contains("already written"));
    }

    #[test]
    fn the_reader_returns_the_header() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        let loaded = read_verified_transcript(sink.jsonl_path()).expect("read");
        assert_eq!(loaded.header, crate::test_support::test_header());
        assert_eq!(loaded.facts.len(), 1);
    }

    /// Write a transcript whose header is `header`, with a correct header
    /// commitment and no facts.
    fn transcript_with_header(dir: &Path, header: &TranscriptHeader) -> PathBuf {
        let value = serde_json::to_value(header).expect("header json");
        let node = header_node(&canonical_json(&value).expect("canonical"));
        let line = serde_json::json!({
            "header": value,
            "chain": Sha256Digest::from_bytes(&node).as_str(),
        })
        .to_string();
        let path = dir.join("transcript.jsonl");
        std::fs::write(&path, format!("{line}\n")).expect("write");
        path
    }

    #[test]
    fn an_unknown_format_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut header = crate::test_support::test_header();
        header.rite_transcript = 2;
        let path = transcript_with_header(tmp.path(), &header);
        let err = verify_transcript(&path).expect_err("unknown format");
        assert!(matches!(err, VerifyError::UnknownFormat(2)));
    }

    #[test]
    fn a_newer_vocabulary_is_read() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut header = crate::test_support::test_header();
        header.vocabulary = 9;
        let path = transcript_with_header(tmp.path(), &header);
        let loaded = read_verified_transcript(&path).expect("newer vocabulary");
        assert_eq!(loaded.header.vocabulary, 9);
    }

    #[test]
    fn a_moved_built_in_level_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut header = crate::test_support::test_header();
        header.levels.insert("public".to_string(), Level::new(5));
        let path = transcript_with_header(tmp.path(), &header);
        let err = verify_transcript(&path).expect_err("moved built-in");
        assert!(matches!(err, VerifyError::InvalidLevels(_)));
    }

    #[test]
    fn a_line_at_an_undeclared_level_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, mut lines) = three_fact_transcript(tmp.path());
        edit_line(&mut lines, 2, |v| {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("level".to_string(), 15.into());
            }
        });
        rewrite(&path, &lines);
        let err = verify_transcript(&path).expect_err("undeclared level");
        assert!(
            matches!(err, VerifyError::InvalidLine { line: 3, .. }),
            "{err}"
        );
    }

    #[test]
    fn the_sink_refuses_a_level_the_header_does_not_declare() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut sink = begun_file_sink(tmp.path());
        let err = sink
            .record(test_at(), Level::new(15), &sample_fact())
            .expect_err("undeclared level");
        assert!(err.to_string().contains("not declared"), "{err}");
        // Nothing was written, and the chain did not move.
        sink.record(test_at(), Level::PUBLIC, &sample_fact())
            .expect("record");
        let loaded = read_verified_transcript(sink.jsonl_path()).expect("verify");
        assert_eq!(loaded.facts.len(), 1);
    }

    #[test]
    fn a_declared_organisation_level_is_accepted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut header = crate::test_support::test_header();
        header.levels.insert("partners".to_string(), Level::new(15));
        let mut sink = JsonlFileSink::create(tmp.path()).expect("create");
        sink.begin(&header).expect("header");
        sink.record(test_at(), Level::new(15), &sample_fact())
            .expect("record");
        let loaded = read_verified_transcript(sink.jsonl_path()).expect("read");
        assert_eq!(loaded.facts.first().map(|t| t.level), Some(Level::new(15)));
    }

    #[test]
    fn an_edited_header_is_caught() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = transcript_with_header(tmp.path(), &crate::test_support::test_header());
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, text.replace("\"dry_run\":false", "\"dry_run\":true"))
            .expect("write");
        let err = verify_transcript(&path).expect_err("edited header");
        assert!(matches!(err, VerifyError::ChainMismatch { line: 1, .. }));
    }

    #[test]
    fn a_transcript_starting_with_a_fact_is_refused() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (path, lines) = three_fact_transcript(tmp.path());
        rewrite(&path, lines.get(1..).expect("facts"));
        let err = verify_transcript(&path).expect_err("no header");
        assert!(matches!(err, VerifyError::MissingHeader(_)));
    }

    use rite_model::StepId;

    fn seeded_fact(m: &[u8]) -> StepFact {
        StepFact::EntropySeeded {
            m: base16ct::lower::encode_string(m),
            source: "os".to_string(),
            derivation: crate::entropy::DERIVATION_V1.to_string(),
        }
    }

    fn drawn_fact(seed: &[u8; 32], step: &str, path: &str, len: usize) -> StepFact {
        StepFact::EntropyDrawn {
            step: StepId::new(step),
            path: path.to_string(),
            value: base16ct::lower::encode_string(&crate::entropy::derive_value(seed, path, len)),
        }
    }

    #[test]
    fn verify_entropy_re_derives_a_clean_draw() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = [
            seeded_fact(m),
            drawn_fact(&seed, "issue", "0/issue/cert-serial", 9),
        ];
        let v = verify_entropy(facts.iter()).expect("verify");
        assert_eq!(v.values_verified, 1);
        assert_eq!(v.contributions, 0);
        assert_eq!(v.derivation.as_deref(), Some("rite-kdf/v1"));
    }

    #[test]
    fn verify_entropy_follows_the_ratchet_through_a_contribution() {
        let m = b"machine entropy bytes";
        let seed0 = crate::entropy::initial_seed(m);
        let seed1 = crate::entropy::fold_seed(&seed0, b"3 1 6 4 2 5");
        let facts = [
            seeded_fact(m),
            StepFact::EntropyContributed {
                step: StepId::new("roll"),
                epoch: 1,
                contribution: "3 1 6 4 2 5".to_string(),
            },
            // Drawn after the fold, so it must derive from the epoch-1 seed.
            drawn_fact(&seed1, "issue", "1/issue/cert-serial", 9),
        ];
        let v = verify_entropy(facts.iter()).expect("verify");
        assert_eq!(v.contributions, 1);
        assert_eq!(v.values_verified, 1);
    }

    #[test]
    fn verify_entropy_detects_a_tampered_value() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let mut drawn = drawn_fact(&seed, "issue", "0/issue/cert-serial", 9);
        if let StepFact::EntropyDrawn { value, .. } = &mut drawn {
            *value = "deadbeefdeadbeefdead".to_string();
        }
        let facts = [seeded_fact(m), drawn];
        let err = verify_entropy(facts.iter()).expect_err("tamper");
        assert!(matches!(err, VerifyError::DrawMismatch { .. }));
    }

    #[test]
    fn verify_entropy_rejects_unknown_derivation() {
        let facts = [StepFact::EntropySeeded {
            m: "00".to_string(),
            source: "os".to_string(),
            derivation: "rite-kdf/v99".to_string(),
        }];
        let err = verify_entropy(facts.iter()).expect_err("unknown scheme");
        assert!(matches!(err, VerifyError::UnknownDerivation(_)));
    }

    #[test]
    fn verify_entropy_rejects_draw_before_seed() {
        let seed = crate::entropy::initial_seed(b"x");
        let facts = [drawn_fact(&seed, "issue", "0/issue/cert-serial", 9)];
        let err = verify_entropy(facts.iter()).expect_err("unseeded");
        assert!(matches!(err, VerifyError::SeedMissing));
    }

    #[test]
    fn verify_entropy_surfaces_the_seed_source() {
        let m = b"machine entropy bytes";
        let v = verify_entropy([seeded_fact(m)].iter()).expect("verify");
        assert_eq!(v.source.as_deref(), Some("os"));
    }

    #[test]
    fn verify_entropy_rejects_a_second_seed() {
        // A mid-stream re-seed would let a forged transcript swap the seed
        // under later draws; the replay refuses rather than resetting.
        let facts = [seeded_fact(b"first"), seeded_fact(b"second")];
        let err = verify_entropy(facts.iter()).expect_err("re-seed");
        assert!(matches!(err, VerifyError::DuplicateSeed));
    }

    #[test]
    fn verify_entropy_rejects_an_oversized_draw_without_panicking() {
        // 8161 bytes is one past the HKDF-Expand limit (255 * 32). Re-deriving
        // it would panic inside `expand`; the verifier must reject it as a
        // malformed record instead of aborting.
        let m = b"machine entropy bytes";
        let oversized = "ab".repeat(crate::entropy::MAX_DRAW_LEN.saturating_add(1));
        let facts = [
            seeded_fact(m),
            StepFact::EntropyDrawn {
                step: StepId::new("issue"),
                path: "0/issue/cert-serial".to_string(),
                value: oversized,
            },
        ];
        let err = verify_entropy(facts.iter()).expect_err("oversized draw");
        assert!(matches!(err, VerifyError::DrawTooLong { len, .. } if len == 8161));
    }

    #[test]
    fn verify_entropy_rejects_a_draw_path_with_the_wrong_epoch() {
        // No contribution was folded, so the draw must come from epoch 0; a
        // recorded epoch-1 path is a stream the runtime could not produce.
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = [
            seeded_fact(m),
            drawn_fact(&seed, "issue", "1/issue/cert-serial", 9),
        ];
        let err = verify_entropy(facts.iter()).expect_err("wrong epoch");
        assert!(matches!(err, VerifyError::PathMismatch { .. }));
    }

    #[test]
    fn verify_entropy_rejects_a_draw_path_with_the_wrong_step() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = [
            seeded_fact(m),
            // Path names step `other` but the fact was recorded under `issue`.
            drawn_fact(&seed, "issue", "0/other/cert-serial", 9),
        ];
        let err = verify_entropy(facts.iter()).expect_err("wrong step");
        assert!(matches!(err, VerifyError::PathMismatch { .. }));
    }

    #[test]
    fn verify_entropy_rejects_an_empty_purpose() {
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = [seeded_fact(m), drawn_fact(&seed, "issue", "0/issue/", 9)];
        let err = verify_entropy(facts.iter()).expect_err("empty purpose");
        assert!(matches!(err, VerifyError::PathMismatch { .. }));
    }

    #[test]
    fn verify_entropy_rejects_a_contribution_epoch_out_of_sequence() {
        let m = b"machine entropy bytes";
        let facts = [
            seeded_fact(m),
            StepFact::EntropyContributed {
                step: StepId::new("roll"),
                // First fold must record epoch 1.
                epoch: 2,
                contribution: "3 1 6 4 2 5".to_string(),
            },
        ];
        let err = verify_entropy(facts.iter()).expect_err("epoch skip");
        assert!(matches!(
            err,
            VerifyError::EpochMismatch {
                recorded: 2,
                expected: 1,
                ..
            }
        ));
    }

    #[test]
    fn verify_entropy_rejects_a_duplicate_draw_path() {
        // The runtime never reuses a path; a repeat means the record was
        // edited or replayed.
        let m = b"machine entropy bytes";
        let seed = crate::entropy::initial_seed(m);
        let facts = [
            seeded_fact(m),
            drawn_fact(&seed, "issue", "0/issue/cert-serial", 9),
            drawn_fact(&seed, "issue", "0/issue/cert-serial", 9),
        ];
        let err = verify_entropy(facts.iter()).expect_err("duplicate path");
        assert!(matches!(err, VerifyError::DuplicateDrawPath { .. }));
    }
}
