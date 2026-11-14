//! One run's worth of state: a backend, the artifacts so far, and the steps
//! that act on them.
//!
//! Each case gets a fresh session, so no case can see a key another made.
//! A case's steps form a ceremony, and they meet what a ceremony's would, in
//! the same order:
//!
//! 1. `rite check`'s validation. Before a step runs, the steps so far and
//!    this one are written out as a ceremony, with every artifact the case
//!    put in place as a material, and validated as `rite check` validates a
//!    file. An error there is a refusal at [`Stage::Check`]: what an operator
//!    is told before anything runs.
//! 2. The step itself, as the resolver planned it, through the executor's own
//!    step path: the handler it looks up, its params evaluated and checked, the
//!    backend it names. What the matrix leaves out is the run around the steps:
//!    the operator, the transcript file and the outputs written to disk.

use std::collections::BTreeSet;

use rite_model::{ArtifactId, Step};
use rite_openssl::OpenSslBackend;
use rite_resolver::Severity;
use rite_runtime::{Action, ArtifactValue, BackendRegistry, test_support::StepRunner};
use rite_stdlib::{GenerateKeyAction, ImportKeyAction};
use serde_json::{Value, json};

use crate::keys::TestKey;
use crate::outcome::Stage;

/// The backend name the steps and the keys they produce carry.
pub const BACKEND: &str = "openssl";

/// A refusal: where it happened, and what it said.
pub type Refused = (Stage, String);

/// Where a case's key comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `import_key` of the committed key, whose public half is a file the
    /// checks read independently of Rite.
    Imported,
    /// `generate_key` of a key of that type, as most ceremonies make theirs.
    /// Its public half is the one Rite exports, and it never leaves the
    /// backend.
    Generated,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Source::Imported => "imported",
            Source::Generated => "generated",
        }
    }
}

/// Who runs a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The step names the backend, as every key operation must.
    Backend,
    /// The step names none, as `verify_signature` over evidence from
    /// elsewhere usually does: the check runs in software.
    Software,
}

impl Via {
    pub fn name(self) -> &'static str {
        match self {
            Via::Backend => "through the backend",
            Via::Software => "in software",
        }
    }
}

pub struct Session {
    runner: StepRunner,
    /// The artifacts the case put in place, which the ceremony declares as
    /// materials.
    materials: BTreeSet<String>,
    /// The steps so far, as the ceremony writes them.
    steps: Vec<(String, Value)>,
}

impl Session {
    pub fn new() -> Self {
        let mut backends = BackendRegistry::new();
        backends.register(Box::new(
            OpenSslBackend::try_new(BACKEND).expect("the OpenSSL backend starts"),
        ));
        Self {
            runner: StepRunner::new(rite_stdlib::default_registry(), backends),
            materials: BTreeSet::new(),
            steps: Vec::new(),
        }
    }

    /// Make `value` available to later steps as `id`, as a material: bytes
    /// the ceremony reads from a file.
    pub fn add(&mut self, id: &str, value: ArtifactValue) {
        self.materials.insert(id.to_string());
        self.runner.add_material(ArtifactId::new(id), value);
    }

    /// The facts the steps so far recorded.
    pub fn facts(&self) -> &[rite_model::StepFact] {
        self.runner.facts()
    }

    pub fn artifact(&self, id: &str) -> &ArtifactValue {
        self.runner
            .artifact(&ArtifactId::new(id))
            .unwrap_or_else(|| panic!("no artifact `{id}` in this session"))
    }

    /// Put `key` into the backend as `id`, the way a ceremony's `import_key`
    /// step does: its algorithm by name, the usages it needs for wrapping, and
    /// `extractable` when it is to be wrapped.
    pub fn import(&mut self, key: TestKey, id: &str, extractable: bool) -> Result<(), Refused> {
        self.import_for(key, id, key.usages(), extractable)
    }

    /// [`Session::import`] with the usages a step other than wrapping needs.
    /// A refusal by the step is at [`Stage::Import`].
    pub fn import_for(
        &mut self,
        key: TestKey,
        id: &str,
        usages: &[&str],
        extractable: bool,
    ) -> Result<(), Refused> {
        let material = format!("{id}_material");
        self.add(&material, ArtifactValue::Bytes(key.private()));
        let params = json!({
            "algorithm": key.algorithm_name(),
            "label": id,
            "policy": { "usages": usages, "extractable": extractable },
        });
        self.run(
            &ImportKeyAction,
            id,
            &[("key_material", &material)],
            &params,
        )
        .map_err(at(Stage::Import))
    }

    /// Hold a key of `key`'s type as `id`, from `source`, for the step under
    /// test to use rather than to wrap.
    pub fn hold(
        &mut self,
        source: Source,
        key: TestKey,
        id: &str,
        usages: &[&str],
    ) -> Result<(), Refused> {
        match source {
            Source::Imported => self.import_for(key, id, usages, false),
            Source::Generated => self.generate(key, id, usages),
        }
    }

    /// Generate a key of `key`'s type as `id`, the way a ceremony's
    /// `generate_key` step does. A refusal by the step is at
    /// [`Stage::Generate`].
    pub fn generate(&mut self, key: TestKey, id: &str, usages: &[&str]) -> Result<(), Refused> {
        let params = json!({
            "algorithm": key.algorithm_name(),
            "policy": { "usages": usages },
        });
        self.run(&GenerateKeyAction, id, &[], &params)
            .map_err(at(Stage::Generate))
    }

    /// Run the step of `action`'s type on the backend as `produces`, reading
    /// `inputs` (name, artifact) and leaving what it produces under `produces`.
    pub fn run(
        &mut self,
        action: &dyn Action,
        produces: &str,
        inputs: &[(&str, &str)],
        params: &Value,
    ) -> Result<(), Refused> {
        self.run_via(Via::Backend, action, produces, inputs, params)
    }

    /// [`Session::run`], choosing who runs the step.
    pub fn run_via(
        &mut self,
        via: Via,
        action: &dyn Action,
        produces: &str,
        inputs: &[(&str, &str)],
        params: &Value,
    ) -> Result<(), Refused> {
        let step = self.check(via, action, produces, inputs, params)?;
        self.runner
            .run(&step)
            .map_err(|e| (Stage::Step, e.to_string()))
    }

    /// Validate the ceremony the steps so far and this one make, as `rite
    /// check` does, and return this step as the resolver planned it. The step
    /// joins the ceremony either way, so a later step is checked against the
    /// ones before it.
    fn check(
        &mut self,
        via: Via,
        action: &dyn Action,
        produces: &str,
        inputs: &[(&str, &str)],
        params: &Value,
    ) -> Result<Step, Refused> {
        let mut declared = serde_json::Map::new();
        declared.insert("action".into(), json!(action.action_type()));
        // An action that makes nothing names no artifact; `produces` then
        // names only the step.
        if !action.action_type().spec().creates.is_empty() {
            declared.insert("creates".into(), json!(produces));
        }
        declared.insert("with".into(), params.clone());
        if via == Via::Backend {
            declared.insert("backend".into(), json!(BACKEND));
        }
        if !inputs.is_empty() {
            let reads: serde_json::Map<_, _> = inputs
                .iter()
                .map(|(name, id)| ((*name).to_string(), json!(format!("${{artifact.{id}}}"))))
                .collect();
            declared.insert("reads".into(), reads.into());
        }
        let declared = Value::Object(declared);
        // Numbered, because the map the ceremony is written from sorts its
        // keys, and the steps must stay in the order they run.
        let number = self.steps.len().checked_add(1).expect("a few steps");
        let id = format!("step_{number:02}_{produces}");
        self.steps.push((id.clone(), declared));

        let ceremony = self.ceremony();
        let (resolved, _, diagnostics) = rite_resolver::analyze_str(None, &ceremony.to_string());
        let errors: Vec<String> = diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.message)
            .collect();
        if !errors.is_empty() {
            return Err((Stage::Check, errors.join("\n  ")));
        }
        let plan = resolved
            .expect("a ceremony with no errors resolves")
            .execution_plan;
        Ok(plan
            .into_iter()
            .find(|step| step.id.as_str() == id)
            .expect("the plan holds the step just added"))
    }

    /// The ceremony so far. JSON is YAML, so it goes to the resolver as is.
    fn ceremony(&self) -> Value {
        let materials: serde_json::Map<String, Value> = self
            .materials
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    json!({ "type": "bytes", "path": format!("{id}.bin") }),
                )
            })
            .collect();
        let steps: serde_json::Map<String, Value> = self.steps.iter().cloned().collect();
        json!({
            "version": "0.3",
            "name": "An algorithm matrix case",
            "backends": { BACKEND: { "provider": "openssl" } },
            "materials": materials,
            "roles": { "operator": { "name": "Operator" } },
            "sections": {
                "case": {
                    "name": "The case",
                    "role": "${role.operator}",
                    "steps": steps,
                },
            },
        })
    }
}

/// A refusal by a step that is part of setting up a case, not the step under
/// test, moved to `stage`. A refusal by `rite check` stays one.
fn at(stage: Stage) -> impl Fn(Refused) -> Refused {
    move |(found, error)| match found {
        Stage::Step => (stage, error),
        other => (other, error),
    }
}
