//! Report data extraction from a verified [`StepFact`] stream.
//!
//! The output is a `serde::Serialize` snapshot consumed by the built-in
//! HTML renderer and, in the future, by template engines.

use chrono::{DateTime, Duration, Utc};
use rite_model::{StepFact, StepOutcome};
use serde::Serialize;
use std::collections::HashMap;

/// Top-level report shape consumed by the renderer.
///
/// Built from a verified `StepFact` stream plus the transcript's final
/// fingerprint. All fields are derived from the stream; no ceremony YAML
/// is consulted in v1.
#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    /// Display name of the ceremony, as recorded in `CeremonyStarted`.
    pub ceremony_name: String,
    /// Hash fingerprint of the full transcript (sidecar value).
    pub transcript_fingerprint: String,
    /// Final ceremony status.
    pub status: ReportStatus,
    /// UTC timestamp of ceremony start.
    pub started_at: DateTime<Utc>,
    /// UTC timestamp of ceremony completion or failure, if reached.
    pub completed_at: Option<DateTime<Utc>>,
    /// Wall-clock duration in seconds, when both ends are known.
    pub duration_seconds: Option<i64>,
    /// Failure summary, populated when `status == Failed`.
    pub failure: Option<ReportFailure>,
    /// Steps in execution order.
    pub steps: Vec<ReportStep>,
    /// Artifacts produced during the ceremony.
    pub artifacts: Vec<ReportArtifact>,
    /// Deviations recorded during the ceremony.
    pub deviations: Vec<ReportDeviation>,
}

/// Terminal status of a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// `CeremonyCompleted` was recorded.
    Completed,
    /// `CeremonyFailed` was recorded.
    Failed,
    /// Neither terminal fact was seen, the run was cut off before completion.
    InProgress,
}

/// Failure summary, extracted from `CeremonyFailed`.
#[derive(Debug, Clone, Serialize)]
pub struct ReportFailure {
    /// Stable error kind label.
    pub kind: String,
    /// Human-readable message.
    pub message: String,
}

/// Execution record for a single ceremony step.
#[derive(Debug, Clone, Serialize)]
pub struct ReportStep {
    /// Step identifier as declared in the DSL.
    pub step_id: String,
    /// Step label as authored in the DSL.
    pub label: String,
    /// Human-readable role name, as recorded in the transcript.
    pub role: String,
    /// UTC timestamp when the step started.
    pub started_at: DateTime<Utc>,
    /// UTC timestamp when the step completed, when a `StepCompleted`
    /// fact was recorded.
    pub completed_at: Option<DateTime<Utc>>,
    /// Step outcome status: `"completed"`, `"skipped"`, or `"in_progress"`.
    pub outcome_status: String,
    /// Message attached to the outcome, if any.
    pub outcome_message: Option<String>,
}

/// An artifact produced during the ceremony.
#[derive(Debug, Clone, Serialize)]
pub struct ReportArtifact {
    /// Step that produced the artifact.
    pub step_id: String,
    /// Artifact name as declared in the DSL.
    pub name: String,
    /// Path on disk.
    pub path: String,
    /// Lowercase hex SHA-256 of the artifact bytes.
    pub sha256: String,
}

/// A deviation logged by the operator during the ceremony.
#[derive(Debug, Clone, Serialize)]
pub struct ReportDeviation {
    /// Step in which the deviation was recorded.
    pub step_id: String,
    /// Verbatim deviation text.
    pub text: String,
    /// UTC timestamp when the deviation was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// Build a [`ReportData`] from a verified `StepFact` stream and the
/// transcript's final fingerprint.
///
/// `transcript_fingerprint` is expected to come from the same call to
/// the runtime's `read_verified_transcript` that produced `facts`.
#[must_use]
pub fn build_report_data(facts: &[StepFact], transcript_fingerprint: &str) -> ReportData {
    let mut builder = Builder::new(transcript_fingerprint.to_string());
    for fact in facts {
        builder.ingest(fact);
    }
    builder.finish()
}

struct Builder {
    transcript_fingerprint: String,
    ceremony_name: String,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    status: ReportStatus,
    failure: Option<ReportFailure>,
    steps: Vec<ReportStep>,
    step_index: HashMap<String, usize>,
    artifacts: Vec<ReportArtifact>,
    deviations: Vec<ReportDeviation>,
}

impl Builder {
    fn new(transcript_fingerprint: String) -> Self {
        Self {
            transcript_fingerprint,
            ceremony_name: String::new(),
            started_at: None,
            completed_at: None,
            status: ReportStatus::InProgress,
            failure: None,
            steps: Vec::new(),
            step_index: HashMap::new(),
            artifacts: Vec::new(),
            deviations: Vec::new(),
        }
    }

    fn ingest(&mut self, fact: &StepFact) {
        match fact {
            StepFact::CeremonyStarted { name, started_at } => {
                self.ceremony_name.clone_from(name);
                self.started_at = Some(*started_at);
            }
            StepFact::StepStarted {
                id,
                label,
                role_name,
                started_at,
                ..
            } => {
                let step_id = id.as_str().to_string();
                self.step_index.insert(step_id.clone(), self.steps.len());
                self.steps.push(ReportStep {
                    step_id,
                    label: label.clone(),
                    role: role_name.clone(),
                    started_at: *started_at,
                    completed_at: None,
                    outcome_status: "in_progress".to_string(),
                    outcome_message: None,
                });
            }
            StepFact::StepCompleted {
                id,
                outcome,
                completed_at,
            } => {
                if let Some(step) = self
                    .step_index
                    .get(id.as_str())
                    .and_then(|i| self.steps.get_mut(*i))
                {
                    step.completed_at = Some(*completed_at);
                    let (status, message) = describe_outcome(outcome);
                    step.outcome_status = status;
                    step.outcome_message = message;
                }
            }
            StepFact::ArtifactWritten {
                step,
                name,
                path,
                sha256,
            } => {
                self.artifacts.push(ReportArtifact {
                    step_id: step.as_str().to_string(),
                    name: name.clone(),
                    path: path.display().to_string(),
                    sha256: sha256.clone(),
                });
            }
            StepFact::DeviationRecorded { step, text, at } => {
                self.deviations.push(ReportDeviation {
                    step_id: step.as_str().to_string(),
                    text: text.clone(),
                    recorded_at: *at,
                });
            }
            StepFact::CeremonyCompleted { completed_at, .. } => {
                self.status = ReportStatus::Completed;
                self.completed_at = Some(*completed_at);
            }
            StepFact::CeremonyFailed { error, failed_at } => {
                self.status = ReportStatus::Failed;
                self.completed_at = Some(*failed_at);
                self.failure = Some(ReportFailure {
                    kind: error.kind.clone(),
                    message: error.message.clone(),
                });
            }
            // PromptAnswered / BackendOperation / AttestationRecorded /
            // ActStarted are not surfaced in v1; per-step detail is a
            // follow-up.
            _ => {}
        }
    }

    fn finish(self) -> ReportData {
        let duration_seconds = match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end.signed_duration_since(start).num_seconds()),
            _ => None,
        };
        ReportData {
            ceremony_name: self.ceremony_name,
            transcript_fingerprint: self.transcript_fingerprint,
            status: self.status,
            started_at: self.started_at.unwrap_or_else(Utc::now),
            completed_at: self.completed_at,
            duration_seconds,
            failure: self.failure,
            steps: self.steps,
            artifacts: self.artifacts,
            deviations: self.deviations,
        }
    }
}

fn describe_outcome(outcome: &StepOutcome) -> (String, Option<String>) {
    match outcome {
        StepOutcome::Completed { message } => ("completed".to_string(), Some(message.clone())),
        _ => ("unknown".to_string(), None),
    }
}

/// Format a `chrono::Duration` as a short human string (e.g. `2m 7s`).
///
/// Exposed for renderer reuse; not part of the public report data.
#[must_use]
pub(crate) fn format_duration(duration: Duration) -> String {
    let total = duration.num_seconds().max(0);
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
