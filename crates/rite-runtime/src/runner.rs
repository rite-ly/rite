//! Channel-driven ceremony executor built around the protocol vocabulary.
//!
//! Frontends (TUI, console, headless) interact with the executor
//! exclusively through [`UiCommand`] and [`ExecEvent`]; the transcript is
//! recorded inline as facts are emitted.
//!
//! # Architecture
//!
//! ```text
//!         ┌──────────────────────────┐
//!         │      Frontend thread     │
//!         │  (TUI / console / etc.)  │
//!         └──────────────────────────┘
//!           ▲                   │
//!  ExecEvent│                   │UiCommand
//!           │                   ▼
//!         ┌──────────────────────────┐
//!         │      Executor thread     │
//!         │  ┌────────────────────┐  │
//!         │  │      Reporter      │──┼─→ TranscriptSink (inline)
//!         │  └────────────────────┘  │
//!         │      ▲                   │
//!         │      │ reporter.fact()   │
//!         │  ┌────────────────────┐  │
//!         │  │   Action handlers  │  │
//!         │  └────────────────────┘  │
//!         └──────────────────────────┘
//! ```
//!
//! The executor owns the [`TranscriptSink`] for the duration of the run and
//! finalizes it before returning. Action handlers receive a `&mut Reporter`
//! and emit transcript-worthy facts through it.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use crossbeam_channel::{Receiver, Sender};
use rite_model::{ActId, ActionType, ArtifactId, Ceremony, MaterialId, OutputId, ParamId, RoleId};
use rite_sdk::{Backend, BackendError};
use thiserror::Error;

use crate::actions::ActionMetadata;
use crate::backend::BackendRegistry;
use crate::executor::{
    ExecutionError, load_material_artifact, step_info_from, write_artifact_to_disk,
};
use crate::expressions;
use crate::output_config::OutputConfig;
use crate::protocol::{ExecEvent, Icon, UiCommand};
use crate::reporter::{Reporter, ReporterError};
use crate::state::{ExecutionState, HandlerContext, StepResult};
use crate::step_info::StepInfo;
use crate::transcript_sink::{TranscriptFingerprint, TranscriptSink};
use rite_model::{ErrorRecord, Prompt, StepFact, StepOutcome};

/// Errors that may surface from an [`Action`] handler.
#[derive(Debug, Error)]
pub enum ActionError {
    /// Operator requested abort. Propagated from [`Reporter::check_abort`]
    /// or [`Reporter::prompt`].
    #[error("ceremony aborted by operator")]
    Aborted,
    /// Frontend channel disconnected. The executor unwinds to a failure.
    #[error("frontend channel disconnected")]
    Disconnected,
    /// Transcript sink failed to persist a fact.
    #[error("transcript write failed: {0}")]
    Transcript(std::io::Error),
    /// Underlying backend returned an error.
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    /// Catch-all for handler-specific failures.
    #[error("{0}")]
    Failed(String),
}

impl From<ReporterError> for ActionError {
    fn from(value: ReporterError) -> Self {
        match value {
            ReporterError::Aborted => ActionError::Aborted,
            ReporterError::Disconnected => ActionError::Disconnected,
            ReporterError::Transcript(e) => ActionError::Transcript(e),
            ReporterError::NoCurrentStep(_) => ActionError::Failed(value.to_string()),
        }
    }
}

/// Deserialize the per-step parameter blob into a typed handler-specific struct.
///
/// Wraps `serde_json::from_value` and converts the error into
/// [`ActionError::Failed`] with a consistent "invalid params: …" wording.
///
/// # Errors
///
/// Returns [`ActionError::Failed`] if `params` cannot be deserialized into `P`.
pub fn parse_params<P: serde::de::DeserializeOwned>(
    params: &serde_json::Value,
) -> Result<P, ActionError> {
    serde_json::from_value(params.clone())
        .map_err(|e| ActionError::Failed(format!("invalid params: {e}")))
}

impl From<ReporterError> for ExecutionError {
    fn from(value: ReporterError) -> Self {
        match value {
            ReporterError::Aborted => ExecutionError::StepAborted(rite_model::StepId::new("")),
            ReporterError::Disconnected => {
                ExecutionError::TranscriptError("frontend channel disconnected".to_string())
            }
            ReporterError::Transcript(e) => ExecutionError::TranscriptError(e.to_string()),
            ReporterError::NoCurrentStep(_) => ExecutionError::TranscriptError(value.to_string()),
        }
    }
}

/// Action trait, every ceremony step handler implements this.
///
/// Handlers emit facts and prompts through [`Reporter`] and return a
/// [`StepResult`]. Transcript evidence is whatever facts the handler
/// emits via [`Reporter::fact`] during execution; there is no separate
/// evidence struct.
pub trait Action: Send + Sync {
    /// Metadata describing this action (type, category, description).
    fn metadata(&self) -> ActionMetadata;

    /// Apply per-step parameter defaults before validation.
    fn apply_defaults(&self, _params: &mut serde_json::Value, _step: &StepInfo) {}

    /// Execute the action.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError`] when the handler cannot complete, when the
    /// operator aborts, or when the frontend disappears.
    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError>;
}

/// Registry mapping action types to their handlers.
#[derive(Default)]
pub struct ActionRegistry {
    actions: HashMap<ActionType, Arc<dyn Action>>,
}

impl ActionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an action handler.
    pub fn register(&mut self, action: Arc<dyn Action>) {
        let action_type = action.metadata().action_type;
        self.actions.insert(action_type, action);
    }

    /// Look up the handler for an action type.
    #[must_use]
    pub fn get(&self, action: &ActionType) -> Option<&Arc<dyn Action>> {
        self.actions.get(action)
    }

    /// Iterate over registered action types.
    pub fn action_types(&self) -> impl Iterator<Item = &ActionType> {
        self.actions.keys()
    }

    /// Return action types used in the execution plan that have no
    /// registered handler. Results are deduplicated and returned in
    /// first-occurrence order.
    #[must_use]
    pub fn unsupported_actions(&self, steps: &[rite_model::Step]) -> Vec<ActionType> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for step in steps {
            if !self.actions.contains_key(&step.action) && seen.insert(step.action) {
                result.push(step.action);
            }
        }
        result
    }
}

/// Summary returned by [`Executor::run`] on a successful completion.
#[derive(Debug)]
pub struct ExecutionSummary {
    /// Ceremony name from the DSL.
    pub ceremony_name: String,
    /// Number of steps that completed successfully.
    pub steps_completed: usize,
    /// Final transcript fingerprint.
    pub transcript_fingerprint: TranscriptFingerprint,
}

/// Channel-driven executor. One per ceremony run.
pub struct Executor {
    ceremony: Ceremony,
    registry: ActionRegistry,
    backend_registry: BackendRegistry,
    output_config: OutputConfig,
    dry_run: bool,
}

impl Executor {
    /// Build an executor for a single ceremony run.
    #[must_use]
    pub fn new(
        ceremony: Ceremony,
        registry: ActionRegistry,
        backend_registry: BackendRegistry,
        output_config: OutputConfig,
        dry_run: bool,
    ) -> Self {
        Self {
            ceremony,
            registry,
            backend_registry,
            output_config,
            dry_run,
        }
    }

    /// Drive the ceremony to completion.
    ///
    /// Blocking. Intended to be invoked on a dedicated executor thread
    /// spawned by the frontend. The `transcript_sink` is finalized before
    /// this function returns, and its fingerprint is included in the
    /// returned summary.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutionError`] for any condition that prevents the
    /// ceremony from completing, validation failures, missing actions,
    /// abort, backend errors, or transcript I/O failures.
    pub fn run(
        self,
        cmd_rx: &Receiver<UiCommand>,
        event_tx: &Sender<ExecEvent>,
        mut transcript_sink: Box<dyn TranscriptSink>,
    ) -> Result<ExecutionSummary, ExecutionError> {
        validate_parameters(&self.ceremony)?;

        let resolved_params: HashMap<ParamId, serde_json::Value> = self
            .ceremony
            .parameters
            .iter()
            .map(|(id, p)| (id.clone(), p.value.clone()))
            .collect();

        let roles: HashMap<RoleId, String> = self
            .ceremony
            .roles
            .iter()
            .map(|(id, r)| (id.clone(), r.name.clone()))
            .collect();

        let materials_map: HashMap<MaterialId, String> = self
            .ceremony
            .materials
            .iter()
            .map(|(id, m)| (id.clone(), m.display_name().to_string()))
            .collect();

        let ceremony_name = self.ceremony.metadata.name.clone();
        let mut reporter = Reporter::new(event_tx, cmd_rx, transcript_sink.as_mut());

        let outcome = self.execute_inner(&mut reporter, resolved_params, roles, materials_map);

        // Record the terminal fact first so it ends up on disk. Then
        // finalize the sink (which only returns the chain head, no
        // sidecar is written) and forward both the fact and the
        // fingerprint to the UI.
        match outcome {
            Ok(counts) => {
                let completed = StepFact::CeremonyCompleted {
                    completed_at: Utc::now(),
                };
                transcript_sink
                    .record(&completed)
                    .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;
                let _ = event_tx.send(ExecEvent::Fact(completed));
                let fingerprint = transcript_sink
                    .finalize()
                    .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;
                let _ = event_tx.send(ExecEvent::Finalized {
                    fingerprint: fingerprint.as_str().to_string(),
                });
                Ok(ExecutionSummary {
                    ceremony_name,
                    steps_completed: counts.completed,
                    transcript_fingerprint: fingerprint,
                })
            }
            Err(err) => {
                let record = err.to_error_record();
                let failed = StepFact::CeremonyFailed {
                    error: record,
                    failed_at: Utc::now(),
                };
                let _ = transcript_sink.record(&failed);
                let _ = event_tx.send(ExecEvent::Fact(failed));
                if let Ok(fingerprint) = transcript_sink.finalize() {
                    let _ = event_tx.send(ExecEvent::Finalized {
                        fingerprint: fingerprint.as_str().to_string(),
                    });
                }
                Err(err)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_inner(
        mut self,
        reporter: &mut Reporter<'_>,
        resolved_params: HashMap<ParamId, serde_json::Value>,
        roles: HashMap<RoleId, String>,
        materials_map: HashMap<MaterialId, String>,
    ) -> Result<StepCounts, ExecutionError> {
        let dry_run = self.dry_run;

        // CeremonyStarted
        reporter.fact(StepFact::CeremonyStarted {
            name: self.ceremony.metadata.name.clone(),
            started_at: Utc::now(),
        })?;

        let mut state = ExecutionState::new(resolved_params, roles, materials_map, dry_run);

        // Load materials. Pre-step logs are attributed to no specific step.
        for (id, material) in self.ceremony.materials.iter() {
            let artifact = load_material_artifact(id.as_str(), material)?;
            state = state.with_material(ArtifactId::new(id.as_str()), artifact);
            let display_name = material.display_name();
            reporter.log(Icon::Checkmark, format!("Loaded material: {display_name}"))?;
        }

        let has_acts = !self.ceremony.acts.is_empty();
        let mut current_act: Option<ActId> = None;
        let mut counts = StepCounts::default();

        // Move the plan out so we can iterate it while still borrowing
        // other fields of `self.ceremony` (sections, acts, outputs).
        let plan = std::mem::take(&mut self.ceremony.execution_plan);
        for step in &plan {
            // Act boundary
            if has_acts {
                let step_act = self
                    .ceremony
                    .sections
                    .get(&step.section)
                    .and_then(|s| s.act.clone());
                if step_act != current_act {
                    if let Some(act_id) = &step_act
                        && let Some(act) = self.ceremony.acts.get(act_id)
                    {
                        reporter.fact(StepFact::ActStarted {
                            id: act_id.clone(),
                            label: act
                                .name
                                .clone()
                                .unwrap_or_else(|| act_id.as_str().to_string()),
                        })?;
                    }
                    current_act = step_act;
                }
            }

            reporter.set_current_step(Some(step.id.clone()));
            let started_at = Utc::now();
            let role_id = step.role.clone().unwrap_or_else(|| RoleId::new(""));
            let role_name = self
                .ceremony
                .roles
                .get(&role_id)
                .map_or_else(|| role_id.as_str().to_string(), |r| r.name.clone());
            reporter.fact(StepFact::StepStarted {
                id: step.id.clone(),
                label: step.step_label.clone(),
                role: role_id,
                role_name,
                started_at,
            })?;

            // Look up handler
            let handler = self
                .registry
                .get(&step.action)
                .ok_or(ExecutionError::UnknownAction(step.action))?
                .clone();

            let ctx = state.handler_context();
            let step_info = step_info_from(step);
            let mut params = expressions::evaluate_expr_value(&step.with, &ctx)?;
            handler.apply_defaults(&mut params, &step_info);

            let backend = if let Some(name) = &step_info.backend {
                Some(self.backend_registry.get_mut(name).map_err(|e| {
                    ExecutionError::StepFailed {
                        step: step_info.id.clone(),
                        reason: e.to_string(),
                    }
                })?)
            } else {
                None
            };

            let result = handler
                .execute(&step_info, &ctx, &params, reporter, backend)
                .map_err(|err| match err {
                    ActionError::Aborted => ExecutionError::StepAborted(step.id.clone()),
                    ActionError::Disconnected => ExecutionError::StepFailed {
                        step: step.id.clone(),
                        reason: "frontend channel disconnected".to_string(),
                    },
                    ActionError::Transcript(e) => ExecutionError::TranscriptError(e.to_string()),
                    ActionError::Backend(e) => ExecutionError::BackendError(e),
                    ActionError::Failed(reason) => ExecutionError::StepFailed {
                        step: step.id.clone(),
                        reason,
                    },
                })?;

            let completed_at = Utc::now();

            // StepCompleted
            reporter.fact(StepFact::StepCompleted {
                id: step.id.clone(),
                outcome: result.outcome.clone(),
                completed_at,
            })?;

            if let StepOutcome::Completed { .. } = &result.outcome {
                counts.completed = counts.completed.saturating_add(1);
            }

            state = merge_step_result(state, result);

            // Write output-bound artifacts. The DSL declares which artifact
            // a step `creates`; we promote that to disk if it is also a
            // ceremony-level output.
            if let Some(artifact_id) = &step.creates
                && !dry_run
            {
                let output_id = OutputId::new(artifact_id.as_str());
                if self.ceremony.outputs.contains(&output_id) {
                    std::fs::create_dir_all(self.output_config.artifacts_dir()).map_err(|e| {
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

                    let (path, hash, _size, _mime_type) =
                        write_artifact_to_disk(artifact_id, artifact_value, &self.output_config)?;

                    reporter.fact(StepFact::ArtifactWritten {
                        step: step.id.clone(),
                        name: artifact_id.as_str().to_string(),
                        path: path.clone(),
                        sha256: hash,
                    })?;
                }
            }

            // Pacing: pause unless silent or dry run.
            if !step.silent && !dry_run {
                reporter.prompt(&Prompt::Continue { hint: None })?;
            }
        }

        reporter.set_current_step(None);
        drop(plan);

        Ok(counts)
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct StepCounts {
    completed: usize,
}

impl ExecutionError {
    /// Convert this execution error into a transcript-friendly record.
    fn to_error_record(&self) -> ErrorRecord {
        let kind = match self {
            ExecutionError::ValidationFailed(_) => "validation_failed",
            ExecutionError::StepAborted(_) => "aborted",
            ExecutionError::Io(_) => "io",
            ExecutionError::StepFailed { .. } => "step_failed",
            ExecutionError::UnknownAction(_) => "unknown_action",
            ExecutionError::InvalidParams(_) => "invalid_params",
            ExecutionError::MaterialLoadFailed { .. } => "material_load_failed",
            ExecutionError::OutputWriteFailed { .. } => "output_write_failed",
            ExecutionError::TranscriptError(_) => "transcript_error",
            ExecutionError::BackendError(_) => "backend_error",
        };
        ErrorRecord::new(kind, self.to_string())
    }
}

fn validate_parameters(ceremony: &Ceremony) -> Result<(), ExecutionError> {
    let missing: Vec<_> = ceremony
        .parameters
        .iter()
        .filter(|(_, p)| p.value.is_null())
        .map(|(id, _)| id.as_str().to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ExecutionError::ValidationFailed(format!(
            "Parameters missing values: {}",
            missing.join(", ")
        )))
    }
}

/// Fold a step's produced artifacts into the running [`ExecutionState`].
fn merge_step_result(state: ExecutionState, result: StepResult) -> ExecutionState {
    let mut artifacts = state.artifacts;
    for (id, value) in result.artifacts {
        artifacts.insert(id, value);
    }
    ExecutionState {
        params: state.params,
        roles: state.roles,
        materials: state.materials,
        dry_run: state.dry_run,
        artifacts,
    }
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;
    use rite_model::ActionType;

    use super::*;
    use crate::actions::ActionCategory;
    use crate::transcript_sink::InMemorySink;

    struct PingAction;

    impl Action for PingAction {
        fn metadata(&self) -> ActionMetadata {
            ActionMetadata {
                action_type: ActionType::Attest,
                description: "test action that always succeeds",
                category: ActionCategory::Verification,
            }
        }

        fn execute(
            &self,
            _step: &StepInfo,
            _ctx: &HandlerContext,
            _params: &serde_json::Value,
            reporter: &mut Reporter<'_>,
            _backend: Option<&mut dyn Backend>,
        ) -> Result<StepResult, ActionError> {
            reporter.log(Icon::Info, "ping")?;
            Ok(StepResult::completed("pinged".to_string()))
        }
    }

    fn minimal_ceremony() -> Ceremony {
        let yaml = r#"
version: "0.2"
name: "Test"
roles:
  participant:
    person: "Alice"
sections:
  main:
    role: ${role.participant}
    steps:
      ping:
        action: attest
        silent: true
        with:
          statement: "I confirm."
"#;
        rite_resolver::resolve(yaml, None)
            .into_result()
            .expect("resolve")
    }

    fn dry_run_output_config() -> OutputConfig {
        OutputConfig::new(std::path::PathBuf::from("/tmp/runner-test"))
    }

    #[test]
    fn runs_a_minimal_ceremony_and_emits_lifecycle_facts() {
        let ceremony = minimal_ceremony();
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(PingAction));

        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();
        let sink: Box<dyn TranscriptSink> = Box::new(InMemorySink::new());

        let executor = Executor::new(
            ceremony,
            registry,
            BackendRegistry::new(),
            dry_run_output_config(),
            true,
        );

        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        // Drain events. With silent=true and dry_run=true, no prompts fire.
        let mut facts = Vec::new();
        while let Ok(ev) = event_rx.recv() {
            if let ExecEvent::Fact(fact) = ev {
                facts.push(fact);
            }
        }

        let summary = join.join().expect("executor join").expect("run ok");
        assert_eq!(summary.steps_completed, 1);

        let kinds: Vec<&'static str> = facts.iter().map(fact_kind).collect();
        assert_eq!(
            kinds,
            vec![
                "ceremony_started",
                "step_started",
                "step_completed",
                "ceremony_completed",
            ],
        );

        drop(cmd_tx);
    }

    #[test]
    fn aborts_when_action_returns_aborted() {
        struct AbortAction;
        impl Action for AbortAction {
            fn metadata(&self) -> ActionMetadata {
                ActionMetadata {
                    action_type: ActionType::Attest,
                    description: "aborts immediately",
                    category: ActionCategory::Verification,
                }
            }
            fn execute(
                &self,
                _step: &StepInfo,
                _ctx: &HandlerContext,
                _params: &serde_json::Value,
                _reporter: &mut Reporter<'_>,
                _backend: Option<&mut dyn Backend>,
            ) -> Result<StepResult, ActionError> {
                Err(ActionError::Aborted)
            }
        }

        let ceremony = minimal_ceremony();
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(AbortAction));

        let (_cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();
        let sink: Box<dyn TranscriptSink> = Box::new(InMemorySink::new());

        let executor = Executor::new(
            ceremony,
            registry,
            BackendRegistry::new(),
            dry_run_output_config(),
            true,
        );

        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        let mut got_failed = false;
        while let Ok(ev) = event_rx.recv() {
            if let ExecEvent::Fact(StepFact::CeremonyFailed { error, .. }) = ev {
                assert_eq!(error.kind, "aborted");
                got_failed = true;
            }
        }
        assert!(got_failed, "expected CeremonyFailed event");

        let result = join.join().expect("executor join");
        assert!(matches!(result, Err(ExecutionError::StepAborted(_))));
    }

    fn fact_kind(fact: &StepFact) -> &'static str {
        match fact {
            StepFact::CeremonyStarted { .. } => "ceremony_started",
            StepFact::ActStarted { .. } => "act_started",
            StepFact::StepStarted { .. } => "step_started",
            StepFact::PromptAnswered { .. } => "prompt_answered",
            StepFact::BackendOperation { .. } => "backend_operation",
            StepFact::AttestationRecorded { .. } => "attestation_recorded",
            StepFact::ArtifactWritten { .. } => "artifact_written",
            StepFact::DeviationRecorded { .. } => "deviation_recorded",
            StepFact::StepCompleted { .. } => "step_completed",
            StepFact::CeremonyCompleted { .. } => "ceremony_completed",
            StepFact::CeremonyFailed { .. } => "ceremony_failed",
            _ => "unknown",
        }
    }
}
