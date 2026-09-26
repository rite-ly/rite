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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender};
use rand::TryRng;
use rand::rngs::SysRng;
use rite_model::{
    ActId, ActionType, ArtifactId, Ceremony, Level, MaterialId, MaterialKind, MaterialSource,
    OutputId, ParamId, RoleId, Sha256Digest, Step, TranscriptHeader,
};
use rite_sdk::{Backend, BackendError, Retriability};
use thiserror::Error;

use crate::actions::ArtifactValue;
use crate::backend::BackendRegistry;
use crate::clock::{Clock, SystemClock};
use crate::entropy::DERIVATION_V1;
use crate::executor::{
    ExecutionError, load_material_artifact, step_info_from, write_artifact_to_disk,
};
use crate::expressions;
use crate::output_config::OutputConfig;
use crate::protocol::{ExecEvent, MaterialOverview, Response, UiCommand, UiSignal};
use crate::reporter::{Reporter, ReporterError};
use crate::state::{ExecutionState, HandlerContext, StepResult};
use crate::step_info::StepInfo;
use crate::system_info::StartupSnapshot;
use crate::transcript_sink::{TranscriptFingerprint, TranscriptSink};
use rite_model::{ErrorClass, ErrorRecord, Prompt, RetryPolicy, StepFact, StepOutcome};

/// Gather the machine entropy `m` that seeds the ceremony entropy source.
///
/// Sourced directly from the host OS RNG ([`SysRng`]), independent of any
/// ceremony backend, so a device the ceremony later challenges cannot
/// influence its own challenge nonce. A dry run instead returns a fixed,
/// clearly-labelled sentinel so a re-derived value can never be mistaken for
/// one produced under real entropy.
fn gather_machine_entropy(dry_run: bool) -> Result<([u8; 32], String), ExecutionError> {
    let mut m = [0u8; 32];
    if dry_run {
        for (slot, byte) in m.iter_mut().zip(b"rite-dry-run-not-real-entropy") {
            *slot = *byte;
        }
        return Ok((m, "dry-run".to_string()));
    }
    SysRng
        .try_fill_bytes(&mut m)
        .map_err(|e| ExecutionError::EntropyError(e.to_string()))?;
    Ok((m, "os".to_string()))
}

/// Program and version recorded in the transcript header.
/// Name and version of the program writing transcripts, as the header
/// records it.
pub const PRODUCER: &str = concat!("rite ", env!("CARGO_PKG_VERSION"));

/// A fresh run identifier: 16 bytes from the OS RNG, as lowercase hex.
fn new_run_id() -> Result<String, ExecutionError> {
    let mut id = [0u8; 16];
    SysRng
        .try_fill_bytes(&mut id)
        .map_err(|e| ExecutionError::EntropyError(e.to_string()))?;
    Ok(base16ct::lower::encode_string(&id))
}

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
            ReporterError::NoCurrentStep(_)
            | ReporterError::DuplicateDraw { .. }
            | ReporterError::Unseeded
            | ReporterError::DrawTooLong { .. } => ActionError::Failed(value.to_string()),
        }
    }
}

impl ActionError {
    /// Classify whether the step that failed with this error may be retried.
    ///
    /// Delegates to [`BackendError::retriability`] for [`ActionError::Backend`];
    /// every other handler-level error is [`Retriability::Fatal`]. `Failed`
    /// covers procedural failures (a `check_value` mismatch must never be
    /// re-run, that would be tampering) as well as integrity and configuration
    /// errors, all of which are non-retriable. `Aborted` is an operator decision
    /// handled on the abort path and is never auto-retried, so it is classified
    /// fatal here as a safe default.
    #[must_use]
    pub fn retriability(&self) -> Retriability {
        match self {
            ActionError::Backend(e) => e.retriability(),
            ActionError::Aborted
            | ActionError::Disconnected
            | ActionError::Transcript(_)
            | ActionError::Failed(_) => Retriability::Fatal,
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
            ReporterError::Aborted => ExecutionError::Aborted,
            ReporterError::Disconnected => {
                ExecutionError::TranscriptError("frontend channel disconnected".to_string())
            }
            ReporterError::Transcript(e) => ExecutionError::TranscriptError(e.to_string()),
            ReporterError::NoCurrentStep(_) => ExecutionError::TranscriptError(value.to_string()),
            ReporterError::DuplicateDraw { .. }
            | ReporterError::Unseeded
            | ReporterError::DrawTooLong { .. } => ExecutionError::EntropyError(value.to_string()),
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
    /// The action this handler implements, as the DSL names it.
    fn action_type(&self) -> ActionType;

    /// Apply per-step parameter defaults before validation.
    fn apply_defaults(&self, _params: &mut serde_json::Value, _step: &StepInfo) {}

    /// Report values in a step's `with:` block that *this build* cannot carry
    /// out, without executing the step.
    ///
    /// Only build-relative findings belong here. Whether a value is one the
    /// action accepts at all is settled by
    /// [`rite_model::params::check`], which the resolver runs, so that an
    /// editor linking no backend reports it too. What is left for a handler is
    /// the question only a linked binary can answer: whether the feature,
    /// backend or library that would carry the value out is present.
    ///
    /// `params` holds the literal part of the block, as produced by
    /// [`literal_expr_value`](rite_model::expression::literal_expr_value): a
    /// field whose value is an unevaluated expression is absent, because its
    /// value belongs to run time. Never report a field as missing.
    fn unsupported_params(&self, _params: &serde_json::Value, _step: &StepInfo) -> Vec<String> {
        Vec::new()
    }

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

/// A `with:` value this build cannot carry out, and the step holding it.
///
/// The same distinction [`ActionRegistry::unsupported_actions`] rests on: a
/// definition is validated on one machine and executed on another, so a
/// finding that depends on the running binary must not condemn the document.
/// `rite check` warns; `rite run` refuses, because that process is the one
/// that would have to do the work.
#[derive(Debug, Clone)]
pub struct StepUnsupportedParam {
    /// The step whose `with:` block holds the value.
    pub step: rite_model::StepId,
    /// What this build cannot do, phrased for the ceremony author.
    pub message: String,
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
        let action_type = action.action_type();
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

    /// Ask each step's handler what this build cannot carry out.
    ///
    /// Handlers see the literal part of the block with defaults applied, the
    /// same order the executor uses. A step whose action has no handler in
    /// this build is skipped: [`unsupported_actions`](Self::unsupported_actions)
    /// already reports it, and there is nobody to ask. A step whose whole
    /// `with:` block is an expression is skipped too, since none of it is
    /// known yet.
    #[must_use]
    pub fn unsupported_step_params(&self, steps: &[rite_model::Step]) -> Vec<StepUnsupportedParam> {
        let mut found = Vec::new();
        for step in steps {
            let Some(handler) = self.actions.get(&step.action) else {
                continue;
            };
            let Some(mut params) = rite_model::expression::literal_expr_value(&step.with) else {
                continue;
            };
            let step_info = crate::executor::step_info_from(step);
            handler.apply_defaults(&mut params, &step_info);
            found.extend(
                handler
                    .unsupported_params(&params, &step_info)
                    .into_iter()
                    .map(|message| StepUnsupportedParam {
                        step: step.id.clone(),
                        message,
                    }),
            );
        }
        found
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
    startup: StartupSnapshot,
    clock: Arc<dyn Clock>,
}

impl Executor {
    /// Build an executor for a single ceremony run.
    ///
    /// `startup` carries the system identity and device environment the CLI
    /// gathered at launch; the executor echoes them to the frontend as UI
    /// signals at ceremony start and does not otherwise inspect them.
    #[must_use]
    pub fn new(
        ceremony: Ceremony,
        registry: ActionRegistry,
        backend_registry: BackendRegistry,
        output_config: OutputConfig,
        dry_run: bool,
        startup: StartupSnapshot,
    ) -> Self {
        Self {
            ceremony,
            registry,
            backend_registry,
            output_config,
            dry_run,
            startup,
            clock: Arc::new(SystemClock),
        }
    }

    /// Override the run clock. The default is [`SystemClock`]; tests inject a
    /// fixed or stepping clock to make recorded event times deterministic.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
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

        // The header goes first: it says what the file is before any fact.
        let header = TranscriptHeader::new(PRODUCER, &new_run_id()?, self.dry_run);
        transcript_sink
            .begin(&header)
            .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;

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
        // Keep a clock handle for the terminal facts below: `execute_inner`
        // consumes `self`, so the reporter and the runner share this clone.
        let clock = Arc::clone(&self.clock);
        let mut reporter = Reporter::new(
            event_tx,
            cmd_rx,
            transcript_sink.as_mut(),
            Arc::clone(&clock),
        );

        let outcome = self.execute_inner(&mut reporter, resolved_params, roles, materials_map);

        // Record the terminal fact first so it ends up on disk. Then
        // finalize the sink (which only returns the chain head, no
        // sidecar is written) and forward both the fact and the
        // fingerprint to the UI.
        match outcome {
            Ok(counts) => {
                let at = clock.now();
                let completed = StepFact::CeremonyCompleted {};
                transcript_sink
                    .record(at, completed.default_level(), &completed)
                    .map_err(|e| ExecutionError::TranscriptError(e.to_string()))?;
                let _ = event_tx.send(ExecEvent::Fact {
                    at,
                    fact: completed,
                });
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
                let at = clock.now();
                let record = err.to_error_record();
                let failed = StepFact::CeremonyFailed { error: record };
                let _ = transcript_sink.record(at, failed.default_level(), &failed);
                let _ = event_tx.send(ExecEvent::Fact { at, fact: failed });
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

        reporter.fact(StepFact::CeremonyStarted {
            name: self.ceremony.metadata.name.clone(),
            template: self.ceremony.source_digest.clone(),
        })?;

        // Establish the ceremony entropy source before any step can draw from
        // it. This machine seed is run-metadata (the runner-emitted exception
        // to "facts come from actions"); human contributions, by contrast, are
        // authored `gather_entropy` steps that fold into the ratchet later.
        let (m, source) = gather_machine_entropy(dry_run)?;
        reporter.seed_entropy(&m);
        reporter.fact(StepFact::EntropySeeded {
            m: base16ct::lower::encode_string(&m),
            source,
            derivation: DERIVATION_V1.to_string(),
        })?;

        // The inputs this run was given, one fact each so each can be
        // disclosed on its own. The template digest on `CeremonyStarted`
        // covers none of them.
        for (id, role) in self.ceremony.roles.iter() {
            reporter.fact(StepFact::RoleDeclared {
                role: id.clone(),
                name: role.name.clone(),
            })?;
        }
        for (id, role) in self.ceremony.roles.iter() {
            if let Some(person) = &role.person {
                reporter.fact(StepFact::RoleAssigned {
                    role: id.clone(),
                    person: person.clone(),
                })?;
            }
        }
        for (id, parameter) in self.ceremony.parameters.iter() {
            reporter.fact(StepFact::ParameterBound {
                name: id.clone(),
                value: parameter.value.clone(),
            })?;
        }

        // Pre-ceremony overview: descriptive metadata for the UI's
        // Overview screen. Sent as a UI-only signal, not a transcript
        // fact, because the YAML is the source of truth for these fields
        // and the run record shouldn't duplicate them.
        reporter.signal(UiSignal::CeremonyOverview {
            description: self.ceremony.metadata.description.clone(),
            materials: self
                .ceremony
                .materials
                .iter()
                .map(|(_, m)| MaterialOverview::from_material(m))
                .collect(),
            step_count: self.ceremony.execution_plan.len(),
        })?;

        // Machine identity and device environment for the System tab. Both
        // UI-only: identity that belongs in the transcript is recorded by the
        // `machine_info` action, not fed in here. `Environment` is emitted
        // once today but shaped to be re-emitted by a future live observer.
        reporter.signal(UiSignal::SystemInfo(Box::new(self.startup.system.clone())))?;
        reporter.signal(UiSignal::Environment(self.startup.environment.clone()))?;

        // Ceremony-start gate: let the operator review the overview
        // before any side effect (material loading, first step body). The
        // prompt is emitted with no current step set, so it carries
        // `step: None` through to the frontend.
        if !dry_run {
            reporter.prompt(&Prompt::Continue {
                hint: Some("Press Enter to start the ceremony".to_string()),
            })?;
        }

        let mut state = ExecutionState::new(resolved_params, roles, materials_map, dry_run);

        // Load materials. The digest of a file is its own fact, so an
        // audience can learn that an input was loaded without being able to
        // test guesses against its content.
        for (id, material) in self.ceremony.materials.iter() {
            let artifact = load_material_artifact(id.as_str(), material)?;
            let identifier = match &material.kind {
                MaterialKind::Physical { identifier, .. } => identifier.clone(),
                MaterialKind::Digital {
                    source: Some(MaterialSource::Identifier { identifier }),
                } => Some(identifier.clone()),
                MaterialKind::Digital { .. } => None,
            };
            // A file loads as bytes; an identifier or physical item as text.
            let digest = match &artifact {
                ArtifactValue::Bytes(bytes) => Some(Sha256Digest::of(bytes)),
                _ => None,
            };
            reporter.fact(StepFact::MaterialLoaded {
                name: id.clone(),
                identifier,
            })?;
            if let Some(digest) = digest {
                reporter.fact(StepFact::MaterialDigest {
                    name: id.clone(),
                    digest,
                })?;
            }
            state = state.with_material(ArtifactId::new(id.as_str()), artifact);
        }

        let mut backends = RunBackends {
            registry: &mut self.backend_registry,
            bound: HashSet::new(),
        };
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
            reporter.set_current_backend(step.backend.clone());
            reporter.fact(StepFact::StepStarted {
                id: step.id.clone(),
                label: step.step_label.clone(),
                role: step.role.clone().unwrap_or_else(|| RoleId::new("")),
            })?;

            // Pacing: gate the step body on operator acknowledgement. The
            // prompt fires with the step header already visible, so the
            // operator confirms "ready for step X" rather than "what just
            // happened was fine". `silent` skips it for auto-advancing
            // bookkeeping steps; `dry_run` skips it for non-interactive
            // verification.
            if !step.silent && !dry_run {
                reporter.prompt(&Prompt::Continue {
                    hint: Some(format!("Press Enter to start step {}", step.step_label)),
                })?;
            }

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

            let result = execute_step_with_retry(
                handler.as_ref(),
                step,
                &step_info,
                &ctx,
                &params,
                reporter,
                &mut backends,
            )?;

            // StepCompleted
            reporter.fact(StepFact::StepCompleted {
                id: step.id.clone(),
                outcome: result.outcome.clone(),
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

                    let (path, digest, _size, _mime_type) =
                        write_artifact_to_disk(artifact_id, artifact_value, &self.output_config)?;

                    // Only the file name is recorded: the file lives under
                    // the run's `artifacts/` directory, and the operator's
                    // filesystem layout stays out of the transcript.
                    let file = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(|| ExecutionError::OutputWriteFailed {
                            name: artifact_id.as_str().to_string(),
                            reason: format!("'{}' has no UTF-8 file name", path.display()),
                        })?
                        .to_string();

                    // Opened content gets no digest: a digest of a secret can
                    // be tested against guesses.
                    let digest = match artifact_value {
                        ArtifactValue::Secret(_) => None,
                        _ => Some(digest),
                    };

                    reporter.fact_at(
                        artifact_level(step.action, artifact_value),
                        StepFact::ArtifactWritten {
                            step: step.id.clone(),
                            name: artifact_id.as_str().to_string(),
                            file,
                            digest,
                        },
                    )?;
                }
            }
        }

        reporter.set_current_step(None);
        reporter.set_current_backend(None);
        drop(plan);

        Ok(counts)
    }
}

#[derive(Default, Debug, Clone, Copy)]
struct StepCounts {
    completed: usize,
}

/// The level an artifact is recorded at, which decides whether a disclosure
/// carries its file.
///
/// Certificates and public keys exist to be distributed. Bytes are public
/// only from the actions that make distributable bytes, a CSR or a signature;
/// from any other step they may be a document the ceremony handled, so they
/// stay restricted. Wrapped keys and encrypted content are ciphertext: not
/// secret, and not for everyone either. Opened content is confidential and is
/// never bundled at all.
fn artifact_level(action: ActionType, value: &ArtifactValue) -> Level {
    match value {
        ArtifactValue::Certificate(_) | ArtifactValue::PublicKey(_) => Level::PUBLIC,
        ArtifactValue::Bytes(_)
            if matches!(
                action,
                ActionType::GenerateCsr | ActionType::SignData | ActionType::PivSign
            ) =>
        {
            Level::PUBLIC
        }
        ArtifactValue::Bytes(_)
        | ArtifactValue::Text(_)
        | ArtifactValue::WrappedKey(_)
        | ArtifactValue::EncryptedData(_)
        | ArtifactValue::BackendKey { .. }
        | ArtifactValue::Shares(_) => Level::RESTRICTED,
        ArtifactValue::Secret(_) => Level::CONFIDENTIAL,
    }
}

/// The run's backends, and which of them have had their identity recorded.
struct RunBackends<'a> {
    registry: &'a mut BackendRegistry,
    bound: HashSet<String>,
}

impl RunBackends<'_> {
    /// Hand out a backend, recording its identity the first time it is
    /// acquired. Operations name the backend and do not repeat the identity,
    /// which can carry device serials.
    fn acquire(
        &mut self,
        name: &str,
        reporter: &mut Reporter<'_>,
    ) -> Result<&mut dyn Backend, ActionError> {
        let backend = self.registry.get_mut(name)?;
        if self.bound.insert(name.to_string()) {
            reporter.fact(StepFact::BackendBound {
                name: name.to_string(),
                provider: backend.provider().to_string(),
                identity: backend.fingerprint(),
            })?;
        }
        Ok(backend)
    }
}

/// Run one step, retrying transient failures under operator control.
///
/// Each attempt re-acquires the backend handle (it is moved into the handler)
/// and snapshots the side-effect count beforehand: a transient error is
/// retriable only if the attempt performed no work on the world yet (the
/// conservative re-executability gate). Interaction records such as an
/// answered prompt do not close the gate: a retried attempt simply prompts
/// again. A retriable error within the step's [`RetryPolicy`] prompts the
/// operator; any other failure terminates the run.
fn execute_step_with_retry(
    handler: &dyn Action,
    step: &Step,
    step_info: &StepInfo,
    ctx: &HandlerContext,
    params: &serde_json::Value,
    reporter: &mut Reporter<'_>,
    backends: &mut RunBackends<'_>,
) -> Result<StepResult, ExecutionError> {
    let mut attempt: u32 = 1;
    loop {
        let side_effects_before = reporter.side_effects_emitted();

        // Backend acquisition is part of the attempt: a failed lazy
        // initialization (device unplugged, daemon down) carries the same
        // retriability semantics as a backend error inside the handler.
        let attempt_result = match &step_info.backend {
            Some(name) => backends.acquire(name, reporter).and_then(|backend| {
                handler.execute(step_info, ctx, params, reporter, Some(backend))
            }),
            None => handler.execute(step_info, ctx, params, reporter, None),
        };

        let action_err = match attempt_result {
            Ok(result) => return Ok(result),
            // Abort is an operator decision, not an attempt failure: no
            // StepAttemptFailed is recorded, the run terminates here.
            Err(ActionError::Aborted) => return Err(ExecutionError::Aborted),
            Err(action_err) => action_err,
        };

        // Conservative re-executability gate: a step that already performed
        // work on the world this attempt is not safely re-runnable.
        let no_new_side_effects = reporter.side_effects_emitted() == side_effects_before;
        let retriable = action_err.retriability().is_retriable() && no_new_side_effects;
        let exec_err = action_error_to_execution(action_err, &step.id);
        reporter.fact(StepFact::StepAttemptFailed {
            step: step.id.clone(),
            attempt,
            error: exec_err.to_error_record(),
        })?;

        let policy_allows = match step.retry {
            RetryPolicy::Never => false,
            RetryPolicy::MaxAttempts(max) => attempt < max,
            RetryPolicy::Prompt => true,
        };

        if retriable && policy_allows {
            // Default `false`: the headless/dry-run driver answers the default,
            // so non-interactive runs abort rather than loop on a deterministic
            // error.
            let answer = reporter.prompt(&Prompt::Confirm {
                question: format!("Step {} failed: {exec_err}. Retry?", step.step_label),
                default: Some(false),
            })?;
            if matches!(answer, Response::Bool(true)) {
                attempt = attempt.saturating_add(1);
                continue;
            }
        }
        return Err(exec_err);
    }
}

/// Map a handler-level [`ActionError`] to the execution-level error the run
/// terminates with. `Aborted` is included for completeness; the executor
/// special-cases it before calling this so it never records a step-attempt
/// failure for an abort.
fn action_error_to_execution(err: ActionError, step_id: &rite_model::StepId) -> ExecutionError {
    match err {
        ActionError::Aborted => ExecutionError::Aborted,
        ActionError::Disconnected => ExecutionError::StepFailed {
            step: step_id.clone(),
            reason: "frontend channel disconnected".to_string(),
        },
        ActionError::Transcript(e) => ExecutionError::TranscriptError(e.to_string()),
        ActionError::Backend(e) => ExecutionError::BackendError(e),
        ActionError::Failed(reason) => ExecutionError::StepFailed {
            step: step_id.clone(),
            reason,
        },
    }
}

impl ExecutionError {
    /// Convert this execution error into a transcript-friendly record.
    ///
    /// The audit `class` derives from the error's nature; for a backend error
    /// it reuses the same retriability judgment the runtime uses for retry
    /// (a retriable backend error is environmental).
    fn to_error_record(&self) -> ErrorRecord {
        let (class, kind) = match self {
            ExecutionError::ValidationFailed(_) => (ErrorClass::Integrity, "validation_failed"),
            ExecutionError::Aborted => (ErrorClass::Abort, "aborted"),
            ExecutionError::Io(_) => (ErrorClass::Integrity, "io"),
            ExecutionError::StepFailed { .. } => (ErrorClass::Procedural, "step_failed"),
            ExecutionError::UnknownAction(_) => (ErrorClass::Integrity, "unknown_action"),
            ExecutionError::InvalidParams(_) => (ErrorClass::Integrity, "invalid_params"),
            ExecutionError::EntropyError(_) => (ErrorClass::Integrity, "entropy_error"),
            ExecutionError::MaterialLoadFailed { .. } => {
                (ErrorClass::Integrity, "material_load_failed")
            }
            ExecutionError::OutputWriteFailed { .. } => {
                (ErrorClass::Integrity, "output_write_failed")
            }
            ExecutionError::TranscriptError(_) => (ErrorClass::Integrity, "transcript_error"),
            ExecutionError::BackendError(e) => {
                let class = if e.retriability().is_retriable() {
                    ErrorClass::Environmental
                } else {
                    ErrorClass::Integrity
                };
                (class, "backend_error")
            }
        };
        ErrorRecord::new(class, kind, self.to_string())
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
    use crate::transcript_sink::InMemorySink;

    #[test]
    fn action_error_retriability_delegates_to_backend() {
        assert_eq!(
            ActionError::Backend(BackendError::TokenNotPresent).retriability(),
            Retriability::Transient,
        );
        assert_eq!(
            ActionError::Backend(BackendError::PinBlocked).retriability(),
            Retriability::Fatal,
        );
    }

    #[test]
    fn handler_level_errors_are_fatal() {
        assert_eq!(ActionError::Aborted.retriability(), Retriability::Fatal);
        assert_eq!(
            ActionError::Disconnected.retriability(),
            Retriability::Fatal
        );
        assert_eq!(
            ActionError::Failed("check_value mismatch".into()).retriability(),
            Retriability::Fatal,
        );
    }

    struct PingAction;

    impl Action for PingAction {
        fn action_type(&self) -> ActionType {
            ActionType::Attest
        }

        fn execute(
            &self,
            _step: &StepInfo,
            _ctx: &HandlerContext,
            _params: &serde_json::Value,
            reporter: &mut Reporter<'_>,
            _backend: Option<&mut dyn Backend>,
        ) -> Result<StepResult, ActionError> {
            reporter.log(crate::protocol::Icon::Info, "ping")?;
            Ok(StepResult::completed("pinged".to_string()))
        }
    }

    fn minimal_ceremony() -> Ceremony {
        let yaml = r#"
version: "0.3"
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

    /// Reports that this build has no puce, so a test can watch a
    /// build-relative finding travel through the registry.
    struct PickyAction;

    impl Action for PickyAction {
        fn action_type(&self) -> ActionType {
            ActionType::Attest
        }

        fn unsupported_params(&self, params: &serde_json::Value, _step: &StepInfo) -> Vec<String> {
            match params.get("statement").and_then(serde_json::Value::as_str) {
                Some("puce") => vec!["this build has no puce".to_string()],
                _ => Vec::new(),
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
            Ok(StepResult::completed("done".to_string()))
        }
    }

    fn ceremony_with_statement(statement: &str) -> Ceremony {
        let yaml = format!(
            r#"
version: "0.3"
name: "Test"
roles:
  participant:
    person: "Alice"
sections:
  main:
    role: ${{role.participant}}
    steps:
      ping:
        action: attest
        with:
          statement: "{statement}"
"#
        );
        rite_resolver::resolve(&yaml, None)
            .into_result()
            .expect("resolve")
    }

    #[test]
    fn reports_what_this_build_cannot_carry_out() {
        let ceremony = ceremony_with_statement("puce");
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(PickyAction));

        let found = registry.unsupported_step_params(&ceremony.execution_plan);
        let [issue] = found.as_slice() else {
            panic!("expected exactly one finding, got {found:?}");
        };
        assert_eq!(issue.step.as_str(), "ping");
        assert_eq!(issue.message, "this build has no puce");
    }

    #[test]
    fn accepts_a_block_the_handler_is_happy_with() {
        let ceremony = ceremony_with_statement("I confirm.");
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(PickyAction));

        assert!(
            registry
                .unsupported_step_params(&ceremony.execution_plan)
                .is_empty()
        );
    }

    #[test]
    fn skips_an_action_this_build_has_no_handler_for() {
        // `unsupported_actions` is what reports these; asking a handler that
        // does not exist would be a second, misleading error on one step.
        let ceremony = ceremony_with_statement("puce");
        let registry = ActionRegistry::new();

        assert!(
            registry
                .unsupported_step_params(&ceremony.execution_plan)
                .is_empty()
        );
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
            StartupSnapshot::placeholder(),
        );

        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        // Drain events. With silent=true and dry_run=true, no prompts fire.
        let mut facts = Vec::new();
        while let Ok(ev) = event_rx.recv() {
            if let ExecEvent::Fact { fact, .. } = ev {
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
                "entropy_seeded",
                "role_declared",
                "role_assigned",
                "step_started",
                "step_completed",
                "ceremony_completed",
            ],
        );

        drop(cmd_tx);
    }

    /// Produces opened content, so a test can watch it reach the run
    /// directory through the same path as any other artifact.
    struct OpensContent;

    impl Action for OpensContent {
        fn action_type(&self) -> ActionType {
            ActionType::Attest
        }

        fn execute(
            &self,
            step: &StepInfo,
            _ctx: &HandlerContext,
            _params: &serde_json::Value,
            _reporter: &mut Reporter<'_>,
            _backend: Option<&mut dyn Backend>,
        ) -> Result<StepResult, ActionError> {
            let produces = step.produces.clone().expect("step creates");
            Ok(StepResult::completed_with_artifact(
                "opened",
                produces,
                crate::actions::ArtifactValue::Secret(secrecy::SecretBox::new(Box::new(
                    b"the recovery phrase".to_vec(),
                ))),
            ))
        }
    }

    /// A ceremony whose one step creates `opened`, declared as an output.
    fn ceremony_writing_opened_content() -> Ceremony {
        let yaml = r#"
version: "0.3"
name: "Test"
roles:
  participant:
    person: "Alice"
output:
  opened:
    type: document
sections:
  main:
    role: ${role.participant}
    steps:
      open:
        action: attest
        silent: true
        with:
          statement: "I confirm."
        creates: opened
"#;
        rite_resolver::resolve(yaml, None)
            .into_result()
            .expect("resolve")
    }

    /// Run `ceremony` to completion, acknowledging every prompt, and return
    /// the run's result with the facts it emitted.
    fn run_acknowledging_prompts(
        ceremony: Ceremony,
        output_config: OutputConfig,
    ) -> (Result<ExecutionSummary, ExecutionError>, Vec<StepFact>) {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(OpensContent));

        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();
        let sink: Box<dyn TranscriptSink> = Box::new(InMemorySink::new());

        let executor = Executor::new(
            ceremony,
            registry,
            BackendRegistry::new(),
            output_config,
            false,
            StartupSnapshot::placeholder(),
        );

        let frontend = std::thread::spawn({
            let cmd_tx = cmd_tx.clone();
            move || {
                let mut facts = Vec::new();
                while let Ok(event) = event_rx.recv() {
                    match event {
                        ExecEvent::Fact { fact, .. } => facts.push(fact),
                        ExecEvent::AwaitPrompt { prompt_id, .. } => {
                            let _ = cmd_tx.send(UiCommand::PromptResponse {
                                prompt_id,
                                response: crate::protocol::Response::Acknowledge,
                            });
                        }
                        _ => {}
                    }
                }
                facts
            }
        });

        let result = executor.run(&cmd_rx, &event_tx, sink);
        drop(event_tx);
        drop(cmd_tx);
        let facts = frontend.join().expect("frontend join");
        (result, facts)
    }

    #[test]
    fn opened_content_declared_as_an_output_is_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = OutputConfig::new(dir.path().to_path_buf());
        let (result, facts) = run_acknowledging_prompts(ceremony_writing_opened_content(), config);

        let summary = result.expect("ceremony runs");
        assert_eq!(summary.steps_completed, 1);
        let written = facts.iter().find_map(|f| match f {
            StepFact::ArtifactWritten {
                name, file, digest, ..
            } => Some((name.clone(), file.clone(), digest.clone())),
            _ => None,
        });
        let (name, file, digest) = written.expect("the artifact is written");
        assert_eq!(name, "opened");
        // Opened content: no digest of a secret goes into the record.
        assert_eq!(digest, None);
        assert_eq!(
            std::fs::read(dir.path().join("artifacts").join(file)).expect("read artifact"),
            b"the recovery phrase"
        );
    }

    #[test]
    fn run_stamps_every_fact_from_the_injected_clock() {
        use crate::test_support::{FixedClock, fixed_test_time};

        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(PingAction));

        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();
        let sink: Box<dyn TranscriptSink> = Box::new(InMemorySink::new());

        let fixed = fixed_test_time();
        let executor = Executor::new(
            minimal_ceremony(),
            registry,
            BackendRegistry::new(),
            dry_run_output_config(),
            true,
            StartupSnapshot::placeholder(),
        )
        .with_clock(Arc::new(FixedClock(fixed)));

        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        let mut times = Vec::new();
        while let Ok(ev) = event_rx.recv() {
            if let ExecEvent::Fact { at, .. } = ev {
                times.push(at);
            }
        }
        join.join().expect("executor join").expect("run ok");

        // Every fact carries the injected time, including the terminal
        // `ceremony_completed`, which the runner emits outside `reporter.fact`.
        assert!(!times.is_empty());
        assert!(times.iter().all(|&t| t == fixed));

        drop(cmd_tx);
    }

    #[derive(Debug, PartialEq, Eq)]
    enum PacingTrace {
        CeremonyStarted,
        StepStarted(String),
        ContinuePrompt { step: Option<String> },
        StepCompleted,
        CeremonyCompleted,
    }

    /// Two-step ceremony with pacing enabled: each step's body must be
    /// gated on a `Continue` prompt that the executor emits **between**
    /// `StepStarted` and the handler. After the last step there must be
    /// no trailing pause, only `StepCompleted` and `CeremonyCompleted`.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn pacing_prompts_fire_at_step_start_not_step_end() {
        let yaml = r#"
version: "0.3"
name: "Pacing"
roles:
  participant:
    person: "Alice"
sections:
  main:
    role: ${role.participant}
    steps:
      first:
        action: attest
        with:
          statement: "first"
      second:
        action: attest
        with:
          statement: "second"
"#;
        let ceremony = rite_resolver::resolve(yaml, None)
            .into_result()
            .expect("resolve");
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
            false, // dry_run=false so prompts actually fire
            StartupSnapshot::placeholder(),
        );

        // Drive the frontend on a worker so the executor's prompt waits
        // don't deadlock. Acknowledge every Continue that arrives and
        // collect a trace of the events the executor emitted.
        let frontend = std::thread::spawn({
            let cmd_tx = cmd_tx.clone();
            move || {
                let mut trace = Vec::new();
                while let Ok(event) = event_rx.recv() {
                    match event {
                        ExecEvent::Fact {
                            fact: StepFact::CeremonyStarted { .. },
                            ..
                        } => {
                            trace.push(PacingTrace::CeremonyStarted);
                        }
                        ExecEvent::Fact {
                            fact: StepFact::StepStarted { label, .. },
                            ..
                        } => {
                            trace.push(PacingTrace::StepStarted(label));
                        }
                        ExecEvent::Fact {
                            fact: StepFact::StepCompleted { .. },
                            ..
                        } => {
                            trace.push(PacingTrace::StepCompleted);
                        }
                        ExecEvent::Fact {
                            fact: StepFact::CeremonyCompleted { .. },
                            ..
                        } => {
                            trace.push(PacingTrace::CeremonyCompleted);
                        }
                        ExecEvent::AwaitPrompt {
                            prompt_id,
                            prompt: Prompt::Continue { .. },
                            step,
                            ..
                        } => {
                            trace.push(PacingTrace::ContinuePrompt {
                                step: step.map(|s| s.as_str().to_string()),
                            });
                            let _ = cmd_tx.send(UiCommand::PromptResponse {
                                prompt_id,
                                response: crate::protocol::Response::Acknowledge,
                            });
                        }
                        _ => {}
                    }
                }
                trace
            }
        });

        let summary = executor
            .run(&cmd_rx, &event_tx, sink)
            .expect("ceremony runs");
        assert_eq!(summary.steps_completed, 2);
        // Drop the local senders so the frontend thread sees the
        // event channel close and returns.
        drop(event_tx);
        drop(cmd_tx);
        let trace = frontend.join().expect("frontend join");

        // Required order:
        //   CeremonyStarted, Continue{None},
        //   StepStarted(1), Continue{Some(1)}, StepCompleted,
        //   StepStarted(2), Continue{Some(2)}, StepCompleted,
        //   CeremonyCompleted
        let mut iter = trace.iter();
        assert_eq!(iter.next(), Some(&PacingTrace::CeremonyStarted));
        assert_eq!(
            iter.next(),
            Some(&PacingTrace::ContinuePrompt { step: None })
        );
        let first_step = match iter.next() {
            Some(PacingTrace::StepStarted(label)) => label.clone(),
            other => panic!("expected first StepStarted, got {other:?}"),
        };
        assert_eq!(
            iter.next(),
            Some(&PacingTrace::ContinuePrompt {
                step: Some("first".to_string()),
            }),
            "first step's Continue prompt must fire after StepStarted and before the body",
        );
        assert_eq!(iter.next(), Some(&PacingTrace::StepCompleted));
        let second_step = match iter.next() {
            Some(PacingTrace::StepStarted(label)) => label.clone(),
            other => panic!("expected second StepStarted, got {other:?}"),
        };
        assert_eq!(
            iter.next(),
            Some(&PacingTrace::ContinuePrompt {
                step: Some("second".to_string()),
            }),
        );
        assert_eq!(iter.next(), Some(&PacingTrace::StepCompleted));
        assert_eq!(iter.next(), Some(&PacingTrace::CeremonyCompleted));
        assert_eq!(iter.next(), None, "no further events expected");
        // Steps are auto-numbered when there's only one section.
        assert_eq!(first_step, "1");
        assert_eq!(second_step, "2");
    }

    #[test]
    fn aborts_when_action_returns_aborted() {
        struct AbortAction;
        impl Action for AbortAction {
            fn action_type(&self) -> ActionType {
                ActionType::Attest
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
            StartupSnapshot::placeholder(),
        );

        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        let mut got_failed = false;
        while let Ok(ev) = event_rx.recv() {
            if let ExecEvent::Fact {
                fact: StepFact::CeremonyFailed { error, .. },
                ..
            } = ev
            {
                assert_eq!(error.kind, "aborted");
                // An abort is classified distinctly from a failure, and its
                // message is ceremony-level (no empty step-id quotes).
                assert_eq!(error.class, ErrorClass::Abort);
                assert_eq!(error.message, "Ceremony aborted by the operator");
                got_failed = true;
            }
        }
        assert!(got_failed, "expected CeremonyFailed event");

        let result = join.join().expect("executor join");
        assert!(matches!(result, Err(ExecutionError::Aborted)));
    }

    // ---- Retry loop tests ----

    /// What [`FlakyAction`] does at the start of every attempt (failing or
    /// not, mirroring an action that always prompts before its backend call),
    /// to exercise the re-executability gate.
    enum BeforeFail {
        Nothing,
        /// Emit a side-effect fact (a backend operation): closes the gate.
        SideEffect,
        /// Issue a secret prompt (like a PIN entry): the answered prompt is
        /// recorded but must not close the gate.
        Prompt,
        /// Record an operator deviation note: recorded but must not close
        /// the gate.
        Deviation,
    }

    /// Test action whose first `fails_remaining` executions fail with
    /// `error()`, then it succeeds.
    struct FlakyAction {
        fails_remaining: std::sync::Mutex<u32>,
        error: fn() -> ActionError,
        before_fail: BeforeFail,
    }

    impl FlakyAction {
        fn new(fails: u32, error: fn() -> ActionError, before_fail: BeforeFail) -> Arc<Self> {
            Arc::new(Self {
                fails_remaining: std::sync::Mutex::new(fails),
                error,
                before_fail,
            })
        }
    }

    impl Action for FlakyAction {
        fn action_type(&self) -> ActionType {
            ActionType::Attest
        }

        fn execute(
            &self,
            _step: &StepInfo,
            _ctx: &HandlerContext,
            _params: &serde_json::Value,
            reporter: &mut Reporter<'_>,
            _backend: Option<&mut dyn Backend>,
        ) -> Result<StepResult, ActionError> {
            let mut remaining = self.fails_remaining.lock().expect("lock");
            match self.before_fail {
                BeforeFail::Nothing => {}
                BeforeFail::SideEffect => {
                    reporter.backend_operation(
                        "test_op",
                        serde_json::Value::Null,
                        serde_json::Value::Null,
                        None,
                    )?;
                }
                BeforeFail::Prompt => {
                    reporter.prompt(&Prompt::Secret {
                        label: "Enter PIN".to_string(),
                        validator: rite_model::ValidatorSpec::NonEmpty,
                    })?;
                }
                BeforeFail::Deviation => {
                    reporter.fact(StepFact::DeviationRecorded {
                        step: None,
                        text: "operator note".to_string(),
                    })?;
                }
            }
            if *remaining == 0 {
                return Ok(StepResult::completed("done".to_string()));
            }
            *remaining = remaining.saturating_sub(1);
            Err((self.error)())
        }
    }

    fn transient() -> ActionError {
        ActionError::Backend(BackendError::TokenNotPresent)
    }

    fn ceremony_with_retry(retry_clause: &str) -> Ceremony {
        let yaml = format!(
            r#"
version: "0.3"
name: "Retry"
roles:
  participant:
    person: "Alice"
sections:
  main:
    role: ${{role.participant}}
    steps:
      work:
        action: attest
        silent: true
        {retry_clause}
        with:
          statement: "x"
"#
        );
        rite_resolver::resolve(&yaml, None)
            .into_result()
            .expect("resolve")
    }

    /// Run `ceremony` with `action`, answering every retry `Confirm` with
    /// `confirm_answer`. Returns the run result, the emitted facts, and the
    /// number of retry prompts seen.
    fn drive(
        ceremony: Ceremony,
        action: Arc<dyn Action>,
        confirm_answer: bool,
    ) -> (
        Result<ExecutionSummary, ExecutionError>,
        Vec<StepFact>,
        usize,
    ) {
        drive_with_backends(ceremony, action, confirm_answer, BackendRegistry::new())
    }

    /// Like [`drive`], with a caller-provided backend registry for steps
    /// that name a backend.
    fn drive_with_backends(
        ceremony: Ceremony,
        action: Arc<dyn Action>,
        confirm_answer: bool,
        backend_registry: BackendRegistry,
    ) -> (
        Result<ExecutionSummary, ExecutionError>,
        Vec<StepFact>,
        usize,
    ) {
        let mut registry = ActionRegistry::new();
        registry.register(action);

        let (cmd_tx, cmd_rx) = unbounded::<UiCommand>();
        let (event_tx, event_rx) = unbounded::<ExecEvent>();
        let sink: Box<dyn TranscriptSink> = Box::new(InMemorySink::new());

        let executor = Executor::new(
            ceremony,
            registry,
            backend_registry,
            dry_run_output_config(),
            true, // dry_run: skips pacing/start prompts, leaving only the retry Confirm
            StartupSnapshot::placeholder(),
        );
        let join = std::thread::spawn(move || executor.run(&cmd_rx, &event_tx, sink));

        let mut facts = Vec::new();
        let mut confirms = 0usize;
        while let Ok(ev) = event_rx.recv() {
            match ev {
                ExecEvent::Fact { fact, .. } => facts.push(fact),
                ExecEvent::AwaitPrompt {
                    prompt_id,
                    prompt: Prompt::Confirm { .. },
                    ..
                } => {
                    confirms = confirms.saturating_add(1);
                    cmd_tx
                        .send(UiCommand::PromptResponse {
                            prompt_id,
                            response: Response::Bool(confirm_answer),
                        })
                        .expect("send confirm");
                }
                ExecEvent::AwaitPrompt {
                    prompt_id,
                    prompt: Prompt::Secret { .. },
                    ..
                } => {
                    cmd_tx
                        .send(UiCommand::PromptResponse {
                            prompt_id,
                            response: Response::Secret("123456".to_string().into()),
                        })
                        .expect("send secret");
                }
                _ => {}
            }
        }
        let result = join.join().expect("executor join");
        (result, facts, confirms)
    }

    fn attempt_numbers(facts: &[StepFact]) -> Vec<u32> {
        facts
            .iter()
            .filter_map(|f| match f {
                StepFact::StepAttemptFailed { attempt, .. } => Some(*attempt),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn transient_failure_is_retried_then_succeeds() {
        let action = FlakyAction::new(1, transient, BeforeFail::Nothing);
        let (result, facts, confirms) = drive(ceremony_with_retry(""), action, true);

        let summary = result.expect("run ok");
        assert_eq!(summary.steps_completed, 1);
        assert_eq!(confirms, 1, "one retry prompt");
        assert_eq!(attempt_numbers(&facts), vec![1]);
        // The recorded attempt is classified environmental (a transient backend error).
        let StepFact::StepAttemptFailed { error, .. } = facts
            .iter()
            .find(|f| matches!(f, StepFact::StepAttemptFailed { .. }))
            .expect("attempt fact")
        else {
            unreachable!()
        };
        assert_eq!(error.class, ErrorClass::Environmental);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, StepFact::StepCompleted { .. }))
        );
    }

    #[test]
    fn retry_is_blocked_once_a_side_effect_was_emitted() {
        // Transient error, but the attempt already performed a backend
        // operation: the conservative gate refuses to retry, so no prompt
        // fires.
        let action = FlakyAction::new(u32::MAX, transient, BeforeFail::SideEffect);
        let (result, facts, confirms) = drive(ceremony_with_retry(""), action, true);

        assert!(result.is_err(), "run fails");
        assert_eq!(confirms, 0, "gate blocks the retry prompt");
        assert_eq!(attempt_numbers(&facts), vec![1]);
        assert!(
            facts
                .iter()
                .any(|f| matches!(f, StepFact::CeremonyFailed { .. }))
        );
    }

    #[test]
    fn prompting_before_a_transient_failure_stays_retriable() {
        // A PIN-style secret prompt answered before the failure records a
        // PromptAnswered fact, but answering a prompt is not a side effect:
        // the retry must still be offered, and the second attempt re-prompts.
        let action = FlakyAction::new(1, transient, BeforeFail::Prompt);
        let (result, facts, confirms) = drive(ceremony_with_retry(""), action, true);

        let summary = result.expect("run ok");
        assert_eq!(summary.steps_completed, 1);
        assert_eq!(confirms, 1, "the retry prompt fired");
        assert_eq!(attempt_numbers(&facts), vec![1]);
        let secret_answers = facts
            .iter()
            .filter(|f| {
                matches!(
                    f,
                    StepFact::PromptAnswered {
                        prompt: Prompt::Secret { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(secret_answers, 2, "each attempt records its own answer");
    }

    #[test]
    fn a_deviation_note_does_not_block_retry() {
        let action = FlakyAction::new(1, transient, BeforeFail::Deviation);
        let (result, _facts, confirms) = drive(ceremony_with_retry(""), action, true);

        let summary = result.expect("run ok");
        assert_eq!(summary.steps_completed, 1);
        assert_eq!(confirms, 1, "the retry prompt fired");
    }

    #[test]
    fn backend_acquisition_failure_is_retriable() {
        use std::sync::atomic::{AtomicU32, Ordering};

        // Lazy backend initialization fails on the first probe (device
        // unplugged) and succeeds on the second: the operator must get the
        // same retry offer as for a transient error inside the handler.
        struct NullBackend {
            name: String,
        }
        impl Backend for NullBackend {
            fn name(&self) -> &str {
                &self.name
            }
            fn provider(&self) -> &'static str {
                "mock"
            }
            fn fingerprint(&self) -> String {
                format!("mock={}", self.name)
            }
        }

        let probes = Arc::new(AtomicU32::new(0));
        let probes_in_factory = Arc::clone(&probes);
        let mut backends =
            crate::backend::BackendRegistry::with_factory(Box::new(move |_name, _config| {
                if probes_in_factory.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(BackendError::HardwareFailure("no device".to_string()))
                } else {
                    Ok(Box::new(NullBackend {
                        name: "token".to_string(),
                    }) as Box<dyn Backend>)
                }
            }));
        backends.declare(
            "token".to_string(),
            rite_sdk::BackendConfig {
                provider: "mock".to_string(),
                extra: serde_json::json!({}),
            },
        );

        let yaml = r#"
version: "0.3"
name: "Retry"
backends:
  token:
    provider: mock
roles:
  participant:
    person: "Alice"
sections:
  main:
    role: ${role.participant}
    steps:
      work:
        action: attest
        backend: token
        silent: true
        with:
          statement: "x"
"#;
        let ceremony = rite_resolver::resolve(yaml, None)
            .into_result()
            .expect("resolve");

        let action = FlakyAction::new(0, transient, BeforeFail::Nothing);
        let (result, facts, confirms) = drive_with_backends(ceremony, action, true, backends);

        let summary = result.expect("run ok after the operator retried");
        assert_eq!(summary.steps_completed, 1);
        assert_eq!(confirms, 1, "the retry prompt fired");
        assert_eq!(attempt_numbers(&facts), vec![1]);
        let StepFact::StepAttemptFailed { error, .. } = facts
            .iter()
            .find(|f| matches!(f, StepFact::StepAttemptFailed { .. }))
            .expect("attempt fact")
        else {
            unreachable!()
        };
        assert_eq!(error.class, ErrorClass::Environmental);
        assert_eq!(probes.load(Ordering::SeqCst), 2, "hardware probed again");
    }

    #[test]
    fn retry_never_fails_immediately() {
        let action = FlakyAction::new(u32::MAX, transient, BeforeFail::Nothing);
        let (result, facts, confirms) = drive(ceremony_with_retry("retry: never"), action, true);

        assert!(result.is_err());
        assert_eq!(confirms, 0, "retry: never never prompts");
        assert_eq!(attempt_numbers(&facts), vec![1]);
    }

    #[test]
    fn retry_attempts_caps_total_tries() {
        let action = FlakyAction::new(u32::MAX, transient, BeforeFail::Nothing);
        let (result, facts, confirms) =
            drive(ceremony_with_retry("retry: {attempts: 2}"), action, true);

        assert!(result.is_err());
        // Attempt 1 fails and prompts; attempt 2 fails and the cap forbids a
        // further prompt.
        assert_eq!(confirms, 1);
        assert_eq!(attempt_numbers(&facts), vec![1, 2]);
    }

    #[test]
    fn declining_the_retry_prompt_terminates() {
        let action = FlakyAction::new(u32::MAX, transient, BeforeFail::Nothing);
        let (result, facts, confirms) = drive(ceremony_with_retry(""), action, false);

        assert!(result.is_err());
        assert_eq!(confirms, 1, "prompted once, operator declined");
        assert_eq!(attempt_numbers(&facts), vec![1]);
    }

    #[test]
    fn artifact_levels_follow_what_the_artifact_is() {
        use secrecy::SecretBox;

        let bytes = || ArtifactValue::Bytes(b"x".to_vec());
        assert_eq!(
            artifact_level(ActionType::SignData, &bytes()),
            Level::PUBLIC
        );
        assert_eq!(
            artifact_level(ActionType::GenerateCsr, &bytes()),
            Level::PUBLIC
        );
        // Bytes from any other step may be a document the ceremony handled.
        assert_eq!(
            artifact_level(ActionType::DecryptData, &bytes()),
            Level::RESTRICTED
        );
        assert_eq!(
            artifact_level(
                ActionType::DecryptData,
                &ArtifactValue::Secret(SecretBox::new(Box::new(b"x".to_vec())))
            ),
            Level::CONFIDENTIAL
        );
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
            StepFact::StepAttemptFailed { .. } => "step_attempt_failed",
            StepFact::StepCompleted { .. } => "step_completed",
            StepFact::CeremonyCompleted { .. } => "ceremony_completed",
            StepFact::CeremonyFailed { .. } => "ceremony_failed",
            StepFact::EntropySeeded { .. } => "entropy_seeded",
            StepFact::EntropyContributed { .. } => "entropy_contributed",
            StepFact::EntropyDrawn { .. } => "entropy_drawn",
            StepFact::RoleDeclared { .. } => "role_declared",
            StepFact::RoleAssigned { .. } => "role_assigned",
            StepFact::ParameterBound { .. } => "parameter_bound",
            StepFact::MaterialLoaded { .. } => "material_loaded",
            StepFact::MaterialDigest { .. } => "material_digest",
            StepFact::BackendBound { .. } => "backend_bound",
            StepFact::MachineInfoRecorded { .. } => "machine_info_recorded",
            _ => "unknown",
        }
    }
}
