//! Execution runtime for Rite ceremonies.
//!
//! `rite-runtime` defines the protocol that frontends use to drive a
//! ceremony to completion, the executor that walks the ceremony plan,
//! and the supporting machinery for transcripts and action handlers.
//!
//! # Key types
//!
//! - [`Executor`], channel-driven engine that walks a ceremony plan.
//! - [`Action`] / [`ActionRegistry`], the handler trait and registry.
//! - [`BackendRegistry`] / [`BackendFactory`], lazy backend store.
//! - [`Reporter`], action-facing handle for facts, signals, and prompts.
//! - [`TranscriptSink`], durable JSONL audit log with hash chaining.
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod actions;
mod artifact_resolver;
mod backend;
mod display;
mod entropy;
mod executor;
mod expressions;
mod output_config;
mod protocol;
mod reporter;
mod runner;
mod state;
mod step_info;
mod system_info;
pub mod test_support;
mod transcript;
mod transcript_sink;

// Execution
pub use executor::ExecutionError;

// Actions
pub use actions::{ActionCategory, ActionMetadata, ArtifactValue, KeyFormat};

// Backend registry (traits live in `rite-sdk`, not here)
pub use backend::{BackendFactory, BackendRegistry};

// Channel vocabulary for the runtime ↔ frontend boundary.
// Persisted transcript types (`StepFact`, `Prompt`, `ResponseRecord`, …)
// live in `rite_model::transcript` and are not re-exported here.
pub use protocol::{
    ExecEvent, Icon, MaterialOverview, MaterialOverviewKind, PromptId, Response, UiCommand,
    UiSignal,
};

// Structured machine/build/environment facts carried by UI signals.
pub use system_info::{
    BackendVersion, BuildInfo, Disk, Environment, FeatureCheck, FeatureStatus, Hardening, HostInfo,
    ParseError as SystemInfoParseError, StartupSnapshot, SystemInfo,
};

// Shared formatter for live frontends.
pub use display::{fact_summary, signal_summary, truncate_for_display};

// Entropy source: the single auditable source of ceremony randomness, plus
// the pure `rite-kdf/v1` derivation used by both the draw path and `rite verify`.
pub use entropy::{CeremonyRandom, DERIVATION_V1, Draw, derive_value, fold_seed, initial_seed};

// Reporter: action-facing handle for facts, signals, and prompts.
pub use reporter::{Reporter, ReporterError};

// Executor and its action trait.
pub use runner::{Action, ActionError, ActionRegistry, ExecutionSummary, Executor, parse_params};

// Transcript sink, the durable consumer of `StepFact`s.
pub use transcript_sink::{
    EntropyVerified, InMemorySink, JsonlFileSink, LoadedTranscript, TranscriptFingerprint,
    TranscriptSink, TranscriptVerified, VerifyError, read_verified_transcript, verify_entropy,
    verify_transcript as verify_step_fact_transcript,
};

// State (needed by `Action` implementors in downstream crates).
pub use state::{ExecutionState, HandlerContext, StepResult};
pub use step_info::StepInfo;

// Output / fingerprint helpers.
pub use output_config::OutputConfig;
pub use transcript::{compute_file_fingerprint, compute_fingerprint};

// Expression evaluation (used by action implementors).
pub use expressions::{
    evaluate, evaluate_expr_value, evaluate_expr_value_to_string, value_to_json,
};

// Artifact resolution (used by action implementors).
pub use artifact_resolver::{resolve_artifact_bytes, resolve_backend_key};
