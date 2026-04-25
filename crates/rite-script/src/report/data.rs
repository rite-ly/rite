//! Report data extraction from parsed transcripts.

use chrono::{DateTime, Utc};
use rite_model::transcript::{ChainedEvent, EventData, ParsedTranscript, ParticipantRecord};
use rite_model::{ActionType, Ceremony};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

/// All data needed to render a report, extracted from a transcript and an optional ceremony.
///
/// Produced by [`build_report_data`]. This is the template context for both the built-in
/// HTML renderer and any custom renderer (template engine, JSON export, etc.).
#[derive(Serialize)]
pub struct ReportData {
    /// Display name of the ceremony as recorded in the transcript.
    pub ceremony_name: String,
    /// Hash fingerprint of the ceremony definition file.
    pub ceremony_fingerprint: String,
    /// Hash fingerprint of the full transcript.
    pub transcript_fingerprint: String,
    /// Whether this was a dry-run execution.
    pub dry_run: bool,
    /// Final ceremony status in `snake_case` (e.g. `"completed"`, `"interrupted"`, `"in_progress"`).
    pub status: String,
    /// UTC timestamp of ceremony start.
    pub started_at: DateTime<Utc>,
    /// UTC timestamp of ceremony completion, if reached.
    pub completed_at: Option<DateTime<Utc>>,
    /// All ceremony parameter key-value pairs, sorted by key.
    ///
    /// When the ceremony definition is available, includes all parameters (defaults + supplied).
    /// Falls back to values recorded in the transcript's `CeremonyStart` event.
    pub parameters: Vec<(String, String)>,
    /// Version string of the `rite` binary that ran the ceremony.
    pub binary_version: String,
    /// Hash fingerprint of the `rite` binary, if recorded.
    pub binary_fingerprint: Option<String>,
    /// Participants in role order.
    pub participants: Vec<ReportParticipant>,
    /// Steps in execution order.
    pub steps: Vec<ReportStep>,
    /// Artifacts produced during the ceremony.
    pub artifacts: Vec<ReportArtifact>,
    /// Deviations recorded during the ceremony.
    pub deviations: Vec<ReportDeviation>,
}

/// A ceremony participant with their role assignment.
#[derive(Serialize)]
pub struct ReportParticipant {
    /// Role identifier as defined in the ceremony DSL.
    pub role_id: String,
    /// Human-readable role display name.
    pub display_name: String,
    /// Name of the person assigned to this role, if known.
    pub person: Option<String>,
}

/// Execution record for a single ceremony step.
#[derive(Serialize)]
pub struct ReportStep {
    /// Step identifier as defined in the ceremony DSL.
    pub step_id: String,
    /// Action type that was executed.
    pub action: ActionType,
    /// Display name of the role that performed this step, if any.
    pub role: Option<String>,
    /// UTC timestamp when step execution began.
    pub started_at: DateTime<Utc>,
    /// UTC timestamp when step execution completed.
    pub completed_at: DateTime<Utc>,
    /// Outcome status string (e.g. `"ok"`, `"failed"`).
    pub outcome_status: String,
    /// Optional message attached to the outcome.
    pub outcome_message: Option<String>,
}

/// An artifact produced during ceremony execution.
#[derive(Serialize)]
pub struct ReportArtifact {
    /// Output identifier that produced this artifact.
    pub source: String,
    /// File path where the artifact was written.
    pub path: String,
    /// Hash of the artifact contents.
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// A deviation recorded during ceremony execution.
#[derive(Serialize)]
pub struct ReportDeviation {
    /// Human-readable reason for the deviation.
    pub reason: String,
    /// Step identifier associated with the deviation, if any.
    pub step_id: Option<String>,
    /// UTC timestamp when the deviation was recorded.
    pub recorded_at: DateTime<Utc>,
}

/// Mutable accumulator for transcript event ingestion.
///
/// Fields here include both `ReportData` outputs and intermediate state
/// (`role_ids`, `transcript_participants`) used to derive the final participants
/// list and role-name enrichment.
#[derive(Default)]
struct Builder {
    ceremony_name: String,
    ceremony_fingerprint: String,
    started_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
    /// Fallback parameters from the transcript (used when no ceremony file is provided).
    transcript_parameters: Vec<(String, String)>,
    binary_version: String,
    binary_fingerprint: Option<String>,
    role_ids: BTreeSet<String>,
    transcript_participants: Vec<ParticipantRecord>,
    steps: Vec<ReportStep>,
    artifacts: Vec<ReportArtifact>,
    deviations: Vec<ReportDeviation>,
}

impl Builder {
    fn ingest(&mut self, event: &ChainedEvent) {
        match &event.data {
            EventData::CeremonyStart {
                ceremony,
                instance,
                binary,
                environment: env,
                participants,
                started_at: start,
                ..
            } => {
                self.ceremony_name.clone_from(&ceremony.name);
                self.ceremony_fingerprint.clone_from(&ceremony.fingerprint);
                self.started_at = *start;
                self.binary_version.clone_from(&binary.version);
                self.binary_fingerprint.clone_from(&binary.fingerprint);
                if let Some(inst) = instance {
                    let mut sorted: Vec<_> = inst.parameters.iter().collect();
                    sorted.sort_by_key(|(k, _)| k.as_str());
                    self.transcript_parameters = sorted
                        .into_iter()
                        .map(|(k, v)| (k.clone(), crate::html::json_value_to_string(v)))
                        .collect();
                }
                let _ = env; // TODO: capture environment when the runtime populates it
                self.transcript_participants.clone_from(participants);
            }
            EventData::Step {
                step_id,
                action,
                role,
                started_at: step_start,
                completed_at: step_end,
                outcome,
                ..
            } => {
                if let Some(r) = role {
                    self.role_ids.insert(r.clone());
                }
                self.steps.push(ReportStep {
                    step_id: step_id.clone(),
                    action: *action,
                    role: role.clone(),
                    started_at: *step_start,
                    completed_at: *step_end,
                    outcome_status: outcome.status.clone(),
                    outcome_message: outcome.message.clone(),
                });
            }
            EventData::ArtifactProduce {
                source,
                path,
                hash,
                size,
                ..
            } => {
                self.artifacts.push(ReportArtifact {
                    source: source.clone(),
                    path: path.clone(),
                    hash: hash.clone(),
                    size: *size,
                });
            }
            EventData::Deviation {
                reason,
                step_id,
                recorded_at,
            } => {
                self.deviations.push(ReportDeviation {
                    reason: reason.clone(),
                    step_id: step_id.clone(),
                    recorded_at: *recorded_at,
                });
            }
            EventData::CeremonyComplete {
                completed_at: end, ..
            } => {
                self.completed_at = Some(*end);
            }
            // TODO: capture EvidenceAdd events (photos, signed documents) in the report
            // TODO: capture image/initrd from CeremonyStart for hardware-secured ceremony reports
            _ => {}
        }
    }
}

/// Build the parameters list from the best available source.
///
/// When the ceremony definition is available, all parameters (including those with defaults)
/// are extracted directly from it. Falls back to values recorded in the transcript.
fn build_parameters(b: &Builder, ceremony: Option<&Ceremony>) -> Vec<(String, String)> {
    if let Some(cer) = ceremony {
        let mut params: Vec<_> = cer
            .parameters
            .iter()
            .map(|(id, param)| {
                (
                    id.as_str().to_string(),
                    crate::html::json_value_to_string(&param.value),
                )
            })
            .collect();
        params.sort_by(|(a, _), (b, _)| a.cmp(b));
        return params;
    }
    b.transcript_parameters.clone()
}

/// Build the participants list, in priority order: ceremony file → transcript
/// participants → step-event role IDs (last-resort for legacy transcripts).
fn build_participants(b: &Builder, ceremony: Option<&Ceremony>) -> Vec<ReportParticipant> {
    if let Some(cer) = ceremony {
        return cer
            .roles
            .iter()
            .map(|(role_id, role)| ReportParticipant {
                role_id: role_id.as_str().to_string(),
                display_name: role.name.clone(),
                person: role.person.clone(),
            })
            .collect();
    }
    if !b.transcript_participants.is_empty() {
        return b
            .transcript_participants
            .iter()
            .map(|p| ReportParticipant {
                role_id: p.role_id.clone(),
                display_name: p.role_name.clone(),
                person: p.person.clone(),
            })
            .collect();
    }
    b.role_ids
        .iter()
        .map(|role_id| ReportParticipant {
            role_id: role_id.clone(),
            display_name: role_id.clone(),
            person: None,
        })
        .collect()
}

/// Build a `role_id → display_name` lookup from the best available source.
/// Returns `None` when no enrichment source exists; callers leave step roles unchanged.
fn build_role_lookup(b: &Builder, ceremony: Option<&Ceremony>) -> Option<HashMap<String, String>> {
    if let Some(cer) = ceremony {
        return Some(
            cer.roles
                .iter()
                .map(|(id, r)| (id.as_str().to_string(), r.name.clone()))
                .collect(),
        );
    }
    if !b.transcript_participants.is_empty() {
        return Some(
            b.transcript_participants
                .iter()
                .map(|p| (p.role_id.clone(), p.role_name.clone()))
                .collect(),
        );
    }
    None
}

/// Extract structured report data from a parsed transcript.
///
/// Walks `transcript.events` once. If `ceremony` is `Some`, enriches role IDs
/// with display names from the ceremony definition.
pub fn build_report_data(transcript: &ParsedTranscript, ceremony: Option<&Ceremony>) -> ReportData {
    let mut b = Builder::default();
    for event in &transcript.events {
        b.ingest(event);
    }

    let parameters = build_parameters(&b, ceremony);
    let participants = build_participants(&b, ceremony);
    let role_lookup = build_role_lookup(&b, ceremony);

    let mut steps = b.steps;
    if let Some(lookup) = role_lookup {
        for step in &mut steps {
            if let Some(role_id) = &step.role
                && let Some(name) = lookup.get(role_id)
            {
                step.role = Some(name.clone());
            }
        }
    }

    let status = serde_json::to_value(&transcript.status)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{:?}", transcript.status));

    ReportData {
        ceremony_name: b.ceremony_name,
        ceremony_fingerprint: b.ceremony_fingerprint,
        transcript_fingerprint: transcript.fingerprint.clone(),
        dry_run: transcript.dry_run,
        status,
        started_at: b.started_at,
        completed_at: b.completed_at,
        parameters,
        binary_version: b.binary_version,
        binary_fingerprint: b.binary_fingerprint,
        participants,
        steps,
        artifacts: b.artifacts,
        deviations: b.deviations,
    }
}
