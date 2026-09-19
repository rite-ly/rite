//! `import_key` action, lift bytes the ceremony holds into a backend key.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params, resolve_artifact_bytes,
};
use rite_sdk::{Backend, KeyAlgorithm, KeySpec};
use serde_json::json;

use crate::params::{ImportKeyParams, installed_key_default_policy};

/// Install key material the ceremony already holds as a key of a named
/// algorithm.
///
/// The bytes can come from anywhere a `Bytes` artifact can: a material file
/// carried into the room, or a step earlier in the same run. Rite can say
/// nothing about where material it did not produce came from, so the record
/// names the artifact the bytes were read from and claims no more than that.
pub struct ImportKeyAction;

impl Action for ImportKeyAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::ImportKey,
            description: "Import a key from material the ceremony holds",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: ImportKeyParams = parse_params(params)?;

        let algorithm: KeyAlgorithm = typed.algorithm.parse().map_err(|_| {
            ActionError::Failed(format!("Unsupported algorithm: '{}'", typed.algorithm))
        })?;

        let material_ref = step.required_named_input("key_material", "import_key")?;
        let material_id = material_ref.artifact_id();
        let key_bytes =
            resolve_artifact_bytes(ctx.artifacts, &material_id, material_ref.property()).map_err(
                |e| {
                    ActionError::Failed(format!(
                        "Cannot read key material from '{}': {e}",
                        material_ref.display_name()
                    ))
                },
            )?;

        let label = typed
            .label
            .clone()
            .unwrap_or_else(|| "imported-key".to_string());

        let kind = if algorithm.is_symmetric() {
            "key"
        } else {
            "keypair"
        };
        reporter.log(
            Icon::Spinner,
            format!("Importing {} {kind} as '{label}'...", typed.algorithm),
        )?;

        let backend = backend
            .ok_or_else(|| ActionError::Failed("Backend required to import a key".to_string()))?;
        let backend_name = backend.name().to_string();
        let backend_fingerprint = backend.fingerprint();

        let keystore = backend.as_keystore_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not hold keys, so it cannot import one"
            ))
        })?;

        // What an imported key may do is the ceremony's claim, exactly as at
        // unwrap: nothing travels with raw material saying what it is for.
        let defaults = installed_key_default_policy(Some(algorithm));
        let policy = match &typed.policy {
            None => defaults,
            Some(declared) => declared
                .resolve_from(&defaults)
                .map_err(ActionError::Failed)?,
        };

        let spec = KeySpec {
            algorithm,
            label: label.clone(),
            policy: policy.clone(),
            location_hint: None,
        };
        let metadata = keystore.import_key(spec, &key_bytes)?;

        let imported_fingerprint = metadata
            .public_key
            .as_ref()
            .map(|key| compute_fingerprint(key.as_bytes()));

        // A keypair answers to its public half and a symmetric key to its
        // check value. One `expect_key` covers both, discriminated by the
        // prefix, as at unwrap.
        let imported_identity = imported_fingerprint
            .clone()
            .or_else(|| metadata.check_value.as_ref().map(ToString::to_string));

        check_declared_identity(
            typed.expect_key.as_deref(),
            imported_identity.as_deref(),
            &backend_name,
        )?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "import_key".to_string(),
            inputs: requested(&typed, &material_ref.display_name(), &label, &policy),
            outputs: produced(
                &backend_name,
                &backend_fingerprint,
                &metadata,
                imported_fingerprint.as_deref(),
            ),
            fingerprint: imported_identity,
        })?;

        let key = ArtifactValue::BackendKey {
            backend_name,
            key_id: metadata.key_id.clone(),
            algorithm: metadata.algorithm,
            public_key: metadata.public_key.clone(),
            check_value: metadata.check_value.clone(),
        };

        let message = format!("{} {kind} imported", typed.algorithm);
        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Checkmark,
                format!("Key stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                key,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}

/// What the ceremony asked this step to lift, and what it committed to first.
///
/// `key_material` names the artifact the bytes were read from, which is the
/// whole of what Rite knows about their origin: where that artifact was
/// produced in this run a verifier can trace it, and where it was a material
/// carried into the room there is nothing to trace.
///
/// Deliberately no digest of the material. That would be a hash of a secret,
/// which is the shape rite#126 removed; what the key is answers under
/// `imported_key_*` instead.
fn requested(
    typed: &ImportKeyParams,
    key_material: &str,
    label: &str,
    policy: &rite_sdk::KeyPolicy,
) -> serde_json::Value {
    json!({
        "key_material": key_material,
        "algorithm": typed.algorithm,
        "label": label,
        "expect_key": typed.expect_key,
        "policy": crate::params::policy_json(policy),
    })
}

/// What came back, and what names it.
///
/// A keypair is named by the fingerprint of its public half and a symmetric key
/// by its check value, so exactly one of the two is present.
fn produced(
    backend_name: &str,
    backend_fingerprint: &str,
    metadata: &rite_sdk::KeyMetadata,
    imported_fingerprint: Option<&str>,
) -> serde_json::Value {
    json!({
        "backend": backend_name,
        "backend_fingerprint": backend_fingerprint,
        "imported_key_id": metadata.key_id.as_str(),
        "imported_key_algorithm": metadata.algorithm.to_string(),
        "imported_key_fingerprint": imported_fingerprint,
        "imported_key_check_value": metadata.check_value.as_ref().map(ToString::to_string),
    })
}

/// Hold the imported key against what the ceremony said it would be.
///
/// Declaring nothing is allowed, since a ceremony may be lifting material whose
/// identity it learns only afterwards. Declaring something the backend cannot
/// answer is not: that would report a check as passed when none ran.
fn check_declared_identity(
    declared: Option<&str>,
    imported: Option<&str>,
    backend_name: &str,
) -> Result<(), ActionError> {
    let Some(declared) = declared else {
        return Ok(());
    };
    match imported {
        Some(imported) if imported == declared => Ok(()),
        Some(imported) => Err(ActionError::Failed(format!(
            "Imported key is {imported}, but the ceremony declares {declared}. \
             The wrong material was lifted, so this step will not complete."
        ))),
        None => Err(ActionError::Failed(format!(
            "Backend '{backend_name}' names the imported key neither by a public key nor by a \
             check value, so the declared {declared} cannot be checked."
        ))),
    }
}
