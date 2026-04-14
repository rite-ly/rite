//! Execution runtime for Rite ceremonies.
//!
//! `rite-runtime` provides the execution engine for Rite ceremony files.
//! It defines the action handler interface, the backend registry, the transcript
//! system, and the executor that drives a resolved ceremony to completion.
//!
//! # Key types
//!
//! - [`CeremonyExecutor`] — drives ceremony execution with console I/O
//! - [`ActionRegistry`] / [`ActionHandler`] — register and look up step handlers
//! - [`BackendRegistry`] / [`BackendFactory`] — lazy-initializing backend store
//! - [`StepUI`] — abstraction over user interaction (console, TUI, headless)
//! - [`TranscriptWriter`] — structured JSONL audit log with hash chaining

#![warn(missing_docs)]

mod actions;
mod artifact_resolver;
mod backend;
mod executor;
mod expressions;
mod output_config;
mod printing;
mod state;
mod step_info;
mod step_ui;
mod transcript;
mod transcript_config;

// Execution
pub use executor::{CeremonyExecutor, ExecutionError, ExecutionResult, StepOutcome};

// Actions
pub use actions::{
    ActionCategory, ActionHandler, ActionMetadata, ActionRegistry, ArtifactValue, KeyFormat,
};
// Display helpers for downstream action handler crates (rite-stdlib, etc.)
pub use actions::display;

// Backend registry (traits live in `rite-sdk`, not here)
pub use backend::{BackendFactory, BackendRegistry};

// UI
pub use step_ui::{ConsoleStepUI, Icon, MinimalStepUI, StepUI};

// State (needed by `ActionHandler` implementors in downstream crates)
pub use state::{ExecutionState, HandlerContext, StepResult};
pub use step_info::StepInfo;

// Transcript
pub use output_config::OutputConfig;
pub use transcript::{
    ArtifactVerification, BinaryInfo, CeremonyInfo, ChainedEvent, EventData, EventOutcome,
    ExecutionEvent, GENESIS_HASH, ImageManifest, InitrdMeasurements, InstanceInfo,
    JsonlTranscriptWriter, NullTranscriptWriter, ParsedTranscript, ParticipantRecord, StepEvidence,
    TRANSCRIPT_SCHEMA_VERSION, TranscriptStatus, TranscriptWriter, VerificationResult,
    compute_file_fingerprint, compute_fingerprint, read_transcript, verify_transcript,
};
pub use transcript_config::TranscriptConfig;

// Expression evaluation (used by action handler implementors)
pub use expressions::{
    evaluate, evaluate_expr_value, evaluate_expr_value_to_string, value_to_json,
};

// Artifact resolution (used by action handler implementors)
pub use artifact_resolver::{resolve_artifact_bytes, resolve_backend_key};
