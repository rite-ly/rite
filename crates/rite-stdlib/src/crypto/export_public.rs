//! `export_public` action, export a public key from a backend keypair.

use rite_model::{ActionType, StepFact, StepInputs};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    KeyFormat, Reporter, StepInfo, StepResult, compute_fingerprint, resolve_backend_key,
};
use rite_sdk::Backend;
use serde_json::json;

/// Export the public component of a backend-resident keypair into a
/// portable PEM artifact.
pub struct ExportPublicAction;

impl Action for ExportPublicAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::ExportPublic,
            description: "Export the public key from a keypair",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        _params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        reporter.log(Icon::Spinner, "Exporting public key...")?;

        let source_ref = step.typed_inputs.as_ref().and_then(StepInputs::as_single);
        if let Some(r) = source_ref {
            reporter.log(Icon::Info, format!("Source keypair: {}", r.display_name()))?;
        }
        let source_ref = source_ref.ok_or_else(|| {
            ActionError::Failed("export_public requires input reference".to_string())
        })?;
        let artifact_id = source_ref.artifact_id();

        let (backend_name, key_id, _algorithm, cached_pub_key) =
            resolve_backend_key(ctx.artifacts, &artifact_id).map_err(|_| {
                ActionError::Failed("export_public requires BackendKey artifact".to_string())
            })?;

        let public_key_bytes = if let Some(pub_key) = cached_pub_key {
            pub_key.clone()
        } else {
            let backend_mut = backend.ok_or_else(|| {
                ActionError::Failed("Backend required to export public key".to_string())
            })?;
            if backend_mut.name() != backend_name {
                return Err(ActionError::Failed(format!(
                    "Key owned by backend '{backend_name}', but current backend is '{}'",
                    backend_mut.name()
                )));
            }
            let keystore = backend_mut.as_keystore_mut().ok_or_else(|| {
                ActionError::Failed(format!(
                    "Backend '{backend_name}' does not support key export"
                ))
            })?;
            keystore.export_public_key(key_id)?
        };

        let fingerprint = compute_fingerprint(&public_key_bytes);
        let public_key = ArtifactValue::PublicKey {
            key_data: public_key_bytes,
            format: KeyFormat::Pem,
        };

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "export_public".to_string(),
            inputs: json!({ "source_artifact": source_ref.display_name() }),
            outputs: json!({ "exported_key_fingerprint": fingerprint }),
            fingerprint: Some(fingerprint),
        })?;

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Checkmark,
                format!("Public key stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                "Public key exported",
                produces.clone(),
                public_key,
            ))
        } else {
            Ok(StepResult::completed("Public key exported"))
        }
    }
}
