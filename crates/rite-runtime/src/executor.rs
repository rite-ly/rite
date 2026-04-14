//! Ceremony execution engine.

use crate::actions::{ActionRegistry, ArtifactValue};
use crate::backend::BackendRegistry;
use crate::expressions;
use crate::output_config::OutputConfig;
use crate::printing;
use crate::state::{ExecutionState, StepResult};
use crate::step_info::StepInfo;
use crate::step_ui::{ConsoleStepUI, Icon, StepUI};
use crate::transcript::{
    EventOutcome, ExecutionEvent, JsonlTranscriptWriter, NullTranscriptWriter, ParticipantRecord,
    StepEvidence, TranscriptStatus, TranscriptWriter, compute_file_fingerprint,
};
use crate::transcript_config::{self, TranscriptConfig};
use chrono::Utc;
use rite_model::{
    ActId, ActionType, ArtifactId, Ceremony, Material, MaterialId, MaterialKind, MaterialSource,
    OutputId, ParamId, RoleId, Step, StepId,
};
use rite_sdk::BackendError;
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use thiserror::Error;

/// Errors during ceremony execution.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExecutionError {
    /// Required parameters are missing values.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// A step was aborted by the user.
    #[error("Step '{0}' was aborted by user")]
    StepAborted(StepId),

    /// An I/O error occurred.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// A step handler returned a failure.
    #[error("Step '{step}' failed: {reason}")]
    StepFailed {
        /// Step that failed.
        step: StepId,
        /// Failure description.
        reason: String,
    },

    /// The action type is not registered.
    #[error("Unknown action: '{0}'")]
    UnknownAction(ActionType),

    /// Invalid or missing parameters for a handler.
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// A material could not be loaded.
    #[error("Failed to load material '{name}': {reason}")]
    MaterialLoadFailed {
        /// Material name.
        name: String,
        /// Failure description.
        reason: String,
    },

    /// An output artifact could not be written.
    #[error("Failed to write output '{name}': {reason}")]
    OutputWriteFailed {
        /// Output name.
        name: String,
        /// Failure description.
        reason: String,
    },

    /// Transcript writing failed.
    #[error("Transcript error: {0}")]
    TranscriptError(String),

    /// A backend returned an error.
    #[error("Backend error: {0}")]
    BackendError(#[from] BackendError),
}

/// Result of executing a single step.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StepOutcome {
    /// Step executed successfully.
    Completed {
        /// Human-readable completion message.
        message: String,
    },
    /// Step was skipped (condition not met).
    Skipped {
        /// Reason the step was skipped.
        reason: String,
    },
}

/// Result of executing the entire ceremony.
#[derive(Debug)]
#[non_exhaustive]
pub struct ExecutionResult {
    /// Ceremony name.
    pub ceremony_name: String,
    /// Number of steps that completed successfully.
    pub steps_completed: usize,
    /// Number of steps that were skipped.
    pub steps_skipped: usize,
    /// Path to the transcript file (if generated).
    pub transcript_path: Option<PathBuf>,
    /// Final fingerprint of the transcript (if generated).
    pub transcript_fingerprint: Option<String>,
}

/// Executes ceremonies interactively via console I/O.
pub struct CeremonyExecutor<R: BufRead + Send, W: Write + Send> {
    reader: R,
    writer: W,
    dry_run: bool,
    registry: ActionRegistry,
    transcript_config: TranscriptConfig,
    output_config: OutputConfig,
}

impl CeremonyExecutor<io::BufReader<io::Stdin>, io::Stdout> {
    /// Create an executor using stdin/stdout with output configuration.
    #[must_use]
    pub fn new_interactive(
        dry_run: bool,
        registry: ActionRegistry,
        output_config: OutputConfig,
    ) -> Self {
        let transcript_config = TranscriptConfig::from_output_config(&output_config);
        Self {
            reader: io::BufReader::new(io::stdin()),
            writer: io::stdout(),
            dry_run,
            registry,
            transcript_config,
            output_config,
        }
    }

    /// Create an executor using stdin/stdout with explicit transcript configuration.
    #[must_use]
    pub fn new_interactive_with_transcript(
        dry_run: bool,
        registry: ActionRegistry,
        output_config: OutputConfig,
        transcript_config: TranscriptConfig,
    ) -> Self {
        Self {
            reader: io::BufReader::new(io::stdin()),
            writer: io::stdout(),
            dry_run,
            registry,
            transcript_config,
            output_config,
        }
    }
}

impl<R: BufRead + Send, W: Write + Send> CeremonyExecutor<R, W> {
    /// Create an executor with custom I/O and output configuration.
    #[must_use]
    pub fn new(
        reader: R,
        writer: W,
        dry_run: bool,
        registry: ActionRegistry,
        output_config: OutputConfig,
    ) -> Self {
        let transcript_config = TranscriptConfig::from_output_config(&output_config);
        Self {
            reader,
            writer,
            dry_run,
            registry,
            transcript_config,
            output_config,
        }
    }

    /// Override the transcript configuration.
    #[must_use]
    pub fn with_transcript_config(mut self, config: TranscriptConfig) -> Self {
        self.transcript_config = config;
        self
    }

    /// Execute a resolved ceremony.
    pub fn execute(
        &mut self,
        ceremony: &Ceremony,
        backend_registry: BackendRegistry,
    ) -> Result<ExecutionResult, ExecutionError> {
        // Validate: all required parameters must have values
        let missing: Vec<_> = ceremony
            .parameters
            .iter()
            .filter(|(_, p)| p.value.is_null())
            .map(|(id, _)| id.as_str().to_string())
            .collect();

        if !missing.is_empty() {
            return Err(ExecutionError::ValidationFailed(format!(
                "Parameters missing values: {}",
                missing.join(", ")
            )));
        }

        // Build parameter map (type-safe IDs → JSON values)
        let resolved_params: HashMap<ParamId, serde_json::Value> = ceremony
            .parameters
            .iter()
            .map(|(id, p)| (id.clone(), p.value.clone()))
            .collect();

        // Initialize transcript writer
        let transcript_path = self.transcript_config.path.clone();
        let mut transcript_writer: Box<dyn TranscriptWriter> = match &transcript_path {
            Some(path) => Box::new(
                JsonlTranscriptWriter::new(path)
                    .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?,
            ),
            None => Box::new(NullTranscriptWriter),
        };

        // Build role map: ID → (display name, person)
        let roles: HashMap<RoleId, (String, Option<String>)> = ceremony
            .roles
            .iter()
            .map(|(id, r)| (id.clone(), (r.name.clone(), r.person.clone())))
            .collect();

        let participants: Vec<ParticipantRecord> = {
            let mut sorted: Vec<_> = roles.iter().collect();
            sorted.sort_by_key(|(id, _)| id.as_str());
            sorted
                .into_iter()
                .map(|(id, (name, person))| ParticipantRecord {
                    role_id: id.as_str().to_string(),
                    role_name: name.clone(),
                    person: person.clone(),
                })
                .collect()
        };

        let ceremony_info = self.transcript_config.build_ceremony_info(ceremony);
        let instance_info = self
            .transcript_config
            .build_instance_info(ceremony, &resolved_params);
        let binary_info = transcript_config::build_binary_info();
        let image_info = transcript_config::build_image_info();
        let initrd_info = transcript_config::build_initrd_measurements();

        transcript_writer
            .begin(
                ceremony_info,
                instance_info,
                binary_info,
                image_info,
                initrd_info,
                None,
                participants,
                self.dry_run,
            )
            .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;

        printing::print_header(&mut self.writer, ceremony, self.dry_run)?;

        // Create console UI (borrows reader + writer for its lifetime)
        let mut ui = ConsoleStepUI::new(&mut self.reader, &mut self.writer);

        let result = execute_core(
            ceremony,
            &self.registry,
            backend_registry,
            &mut *transcript_writer,
            &self.output_config,
            transcript_path.as_deref(),
            self.dry_run,
            resolved_params,
            &roles,
            &mut ui,
        );

        // End borrows on reader/writer so self.writer is usable again.
        #[allow(clippy::drop_non_drop)]
        drop(ui);

        match result {
            Ok(exec_result) => {
                printing::print_footer(&mut self.writer, ceremony, exec_result.steps_completed)?;

                if let Some(path) = &exec_result.transcript_path {
                    let display = path.display();
                    writeln!(self.writer)?;
                    writeln!(self.writer, "Transcript written to: {display}")?;
                    if let Some(ref fp) = exec_result.transcript_fingerprint {
                        writeln!(self.writer, "Fingerprint: {fp}")?;
                    }
                }

                Ok(exec_result)
            }
            Err(e) => {
                let _ = transcript_writer.mark_interrupted();
                Err(e)
            }
        }
    }
}

/// Core execution loop, parameterized by UI implementation.
///
/// This function handles material loading, step execution, and transcript
/// finalization. It is shared between the console executor and future UI
/// implementations (TUI, headless, test).
///
/// # Arguments
/// - `ceremony` — The resolved ceremony to execute.
/// - `action_registry` — Registry of available action handlers.
/// - `backend_registry` — Registry of initialized backends (lazy init on first use).
/// - `transcript_writer` — Transcript sink (JSONL or null).
/// - `output_config` — Determines output directory paths.
/// - `transcript_path` — Path where transcript will be written (for result reporting).
/// - `dry_run` — Skip side-effectful operations when true.
/// - `resolved_params` — Resolved parameter values for this execution instance.
/// - `roles` — Role ID → (display name, person) mapping.
/// - `ui` — User interaction implementation.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn execute_core(
    ceremony: &Ceremony,
    action_registry: &ActionRegistry,
    mut backend_registry: BackendRegistry,
    transcript_writer: &mut dyn TranscriptWriter,
    output_config: &OutputConfig,
    transcript_path: Option<&std::path::Path>,
    dry_run: bool,
    resolved_params: HashMap<ParamId, serde_json::Value>,
    roles: &HashMap<RoleId, (String, Option<String>)>,
    ui: &mut dyn StepUI,
) -> Result<ExecutionResult, ExecutionError> {
    // Build role name map (ID → display name only) for ExecutionState
    let role_names: HashMap<RoleId, String> = roles
        .iter()
        .map(|(id, (name, _))| (id.clone(), name.clone()))
        .collect();

    let materials_map: HashMap<MaterialId, String> = ceremony
        .materials
        .iter()
        .map(|(id, m)| (id.clone(), m.display_name().to_string()))
        .collect();

    let mut state = ExecutionState::new(resolved_params, role_names, materials_map, dry_run);

    // Load materials into state
    for (id, material) in ceremony.materials.iter() {
        let artifact = load_material_artifact(id.as_str(), material)?;
        state = state.with_material(ArtifactId::new(id.as_str()), artifact);
        let display_name = material.display_name();
        ui.log(Icon::Checkmark, &format!("Loaded material: {display_name}"));
    }

    let mut completed = 0usize;
    let mut skipped = 0usize;

    let has_acts = !ceremony.acts.is_empty();
    let mut current_act: Option<ActId> = None;

    for step in &ceremony.execution_plan {
        // Print act header on act transition
        if has_acts {
            let step_act = ceremony
                .sections
                .get(&step.section)
                .and_then(|s| s.act.clone());

            if step_act != current_act {
                if let Some(ref act_id) = step_act
                    && let Some(act) = ceremony.acts.get(act_id)
                {
                    let act_number = ceremony
                        .acts
                        .iter()
                        .position(|(id, _)| id == act_id)
                        .map_or(1, |i| i.saturating_add(1));
                    let act_name = act.name.as_deref().unwrap_or(act_id.as_str());
                    ui.log(Icon::Info, &format!("▸ Act {act_number}: {act_name}"));
                }
                current_act = step_act;
            }
        }

        // Step header
        let step_label = &step.step_label;
        let step_id = &step.id;
        ui.log(Icon::Info, &format!("⏺ Step {step_label}: {step_id}"));
        if let Some(role) = &step.role {
            let role_name = state.resolve_role(role);
            ui.log(Icon::Info, &format!("Role: {role_name}"));
        }

        let started_at = Utc::now();

        // Look up handler
        let handler = action_registry
            .get(&step.action)
            .ok_or(ExecutionError::UnknownAction(step.action))?;

        let ctx = state.handler_context();

        // Build StepInfo for this step
        let step_info = step_info_from(step);

        // Evaluate action parameters (expressions pre-parsed by resolver)
        let mut params = expressions::evaluate_expr_value(&step.with, &ctx)?;
        handler.apply_defaults(&mut params, &step_info);

        // Resolve backend lazily
        let backend = if let Some(name) = &step_info.backend {
            Some(
                backend_registry
                    .get_mut(name)
                    .map_err(|e| ExecutionError::StepFailed {
                        step: step_info.id.clone(),
                        reason: e.to_string(),
                    })?,
            )
        } else {
            None
        };

        let (result, evidence): (StepResult, StepEvidence) =
            handler.execute(&step_info, &ctx, &params, ui, backend)?;

        let completed_at = Utc::now();

        // Print step outcome
        match &result.outcome {
            StepOutcome::Completed { message } => {
                ui.log(Icon::Checkmark, message);
            }
            StepOutcome::Skipped { reason } => {
                ui.log(Icon::Info, &format!("Skipped: {reason}"));
            }
        }

        // Build and record transcript event
        let event = ExecutionEvent {
            step_id: step.id.as_str().to_string(),
            action: step.action,
            role: step.role.as_ref().map(|r| format!("${{{r}}}")),
            started_at,
            completed_at,
            outcome: EventOutcome::from(&result.outcome),
            evidence,
        };

        transcript_writer
            .record_event(event.clone())
            .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;

        // Update counters
        match &result.outcome {
            StepOutcome::Completed { .. } => completed = completed.saturating_add(1),
            StepOutcome::Skipped { .. } => skipped = skipped.saturating_add(1),
        }

        state = state.with_step_result(result, event);

        // Write output-bound artifacts to disk immediately after step completes
        if let Some(artifact_id) = &step.creates {
            let output_id = OutputId::new(artifact_id.as_str());
            if ceremony.outputs.contains(&output_id) && !dry_run {
                let artifacts_dir = output_config.artifacts_dir();
                fs::create_dir_all(&artifacts_dir).map_err(|e| {
                    ExecutionError::OutputWriteFailed {
                        name: "artifacts directory".to_string(),
                        reason: e.to_string(),
                    }
                })?;

                let artifact_value = state.artifacts.get(artifact_id).ok_or_else(|| {
                    ExecutionError::OutputWriteFailed {
                        name: artifact_id.as_str().to_string(),
                        reason: "artifact not produced".to_string(),
                    }
                })?;

                let (path, hash, size, mime_type) =
                    write_artifact_to_disk(artifact_id, artifact_value, output_config)?;

                transcript_writer
                    .record_artifact(artifact_id.as_str(), &path, hash, size, mime_type)
                    .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;

                let artifact_display = path.display();
                ui.log(
                    Icon::Checkmark,
                    &format!("Artifact written: {artifact_display}"),
                );
            }
        }

        // Step pacing: automated steps (no role) pause for acknowledgment.
        // Steps with roles already pace via human interaction in prompts.
        if step.role.is_none() && !step.silent && !dry_run {
            ui.prompt_continue("Step complete.")?;
        }
    }

    // Finalize transcript
    let fingerprint = transcript_writer
        .finalize(TranscriptStatus::Completed)
        .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;

    Ok(ExecutionResult {
        ceremony_name: ceremony.metadata.name.clone(),
        steps_completed: completed,
        steps_skipped: skipped,
        transcript_path: transcript_path.map(std::path::Path::to_path_buf),
        transcript_fingerprint: Some(fingerprint),
    })
}

/// Build a `StepInfo` from a resolved `Step`.
fn step_info_from(step: &Step) -> StepInfo {
    StepInfo::new(
        step.id.clone(),
        step.role.clone(),
        step.backend.clone(),
        step.creates.clone(),
        step.reads_resolved.clone(),
    )
}

/// Load a single material into an `ArtifactValue`.
fn load_material_artifact(
    name: &str,
    material: &Material,
) -> Result<ArtifactValue, ExecutionError> {
    match &material.kind {
        MaterialKind::Physical { identifier, .. } => {
            let text = identifier
                .as_deref()
                .or(material.title.as_deref())
                .unwrap_or(name)
                .to_string();
            Ok(ArtifactValue::Text(text))
        }
        MaterialKind::Digital { source } => {
            let source = source
                .as_ref()
                .ok_or_else(|| ExecutionError::MaterialLoadFailed {
                    name: name.to_string(),
                    reason: "no source provided for digital material".to_string(),
                })?;
            match source {
                MaterialSource::File { file } => {
                    let bytes = fs::read(file).map_err(|e| ExecutionError::MaterialLoadFailed {
                        name: name.to_string(),
                        reason: e.to_string(),
                    })?;
                    Ok(ArtifactValue::Bytes(bytes))
                }
                MaterialSource::Identifier { identifier } => {
                    // Digital material with an inline identifier — treat as text content.
                    Ok(ArtifactValue::Text(identifier.clone()))
                }
            }
        }
    }
}

/// Serialize an artifact, write it to disk, and return `(path, sha256-hex, size-bytes, mime-type)`.
fn write_artifact_to_disk(
    artifact_id: &ArtifactId,
    artifact_value: &ArtifactValue,
    output_config: &OutputConfig,
) -> Result<(PathBuf, String, u64, Option<String>), ExecutionError> {
    let serialized =
        artifact_value
            .serialize(None)
            .map_err(|e| ExecutionError::OutputWriteFailed {
                name: artifact_id.as_str().to_string(),
                reason: e,
            })?;

    let path = output_config.artifact_path(artifact_id.as_str(), serialized.extension);

    fs::write(&path, &serialized.bytes).map_err(|e| ExecutionError::OutputWriteFailed {
        name: artifact_id.as_str().to_string(),
        reason: e.to_string(),
    })?;

    let hash = compute_file_fingerprint(&path).map_err(|e| ExecutionError::OutputWriteFailed {
        name: artifact_id.as_str().to_string(),
        reason: format!("hash computation failed: {e}"),
    })?;

    let size = fs::metadata(&path)
        .map_err(|e| ExecutionError::OutputWriteFailed {
            name: artifact_id.as_str().to_string(),
            reason: format!("metadata read failed: {e}"),
        })?
        .len();

    Ok((path, hash, size, serialized.mime_type))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_accepts_backend_registry() {
        let ceremony_yaml = r#"
version: "2.0"
name: "Backend Test"
roles: {}
sections:
  main:
    steps: {}
"#;

        let resolved = rite_resolver::resolve(ceremony_yaml, None)
            .into_result()
            .unwrap();

        let backend_registry = BackendRegistry::new();
        let registry = crate::actions::ActionRegistry::new();
        let tempdir = tempfile::TempDir::new().unwrap();
        let output_config =
            OutputConfig::for_ceremony(Some(tempdir.path().to_path_buf()), &resolved.metadata.name);
        let mut executor = CeremonyExecutor::new_interactive(false, registry, output_config);

        let result = executor.execute(&resolved, backend_registry);
        assert!(result.is_ok());
    }
}
