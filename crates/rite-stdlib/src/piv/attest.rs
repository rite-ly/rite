//! `yubikey_attest_slot` action: generate a `YubiKey` attestation certificate.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
};
use rite_sdk::Backend;
use serde_json::json;

use super::params::AttestSlotParams;

/// Generate a `YubiKey` attestation certificate for a PIV slot.
///
/// Uses `YubiKey` slot F9 (the attestation key factory-provisioned by `Yubico`)
/// to sign the certificate of the key in the target slot, proving that key was
/// generated on-device and was never exported.
pub struct YubikeyAttestSlotAction;

impl Action for YubikeyAttestSlotAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::YubikeyAttestSlot,
            description: "Generate YubiKey attestation certificate for a PIV slot",
            category: ActionCategory::Crypto,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: AttestSlotParams = parse_params(params)?;

        if let Some(msg) = &typed.message {
            reporter.log(Icon::Info, msg.clone())?;
        }
        reporter.log(
            Icon::Spinner,
            format!("Generating YubiKey attestation for slot {}...", typed.slot),
        )?;

        // Validate the slot hint early so bad params fail before hardware access.
        let piv_slot = rite_piv::ops::slot_from_hint(&typed.slot)
            .map_err(|e| ActionError::Failed(format!("Invalid PIV slot: {e}")))?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed("Backend required for yubikey_attest_slot action".into())
        })?;
        let backend_name = backend.name().to_string();

        let yubikey = backend.as_yubikey_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support YubiKey operations"
            ))
        })?;

        let cert_der = yubikey.attest_slot(piv_slot)?;
        let cert_fingerprint = compute_fingerprint(&cert_der);

        reporter.log(
            Icon::Checkmark,
            format!(
                "Attestation certificate generated ({} bytes)",
                cert_der.len()
            ),
        )?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "yubikey_attest_slot".to_string(),
            inputs: json!({ "slot": typed.slot }),
            outputs: json!({
                "cert_fingerprint": cert_fingerprint,
                "cert_size": cert_der.len(),
            }),
            fingerprint: Some(cert_fingerprint),
        })?;

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Attestation certificate stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                "YubiKey attestation certificate generated",
                produces.clone(),
                ArtifactValue::Bytes(cert_der),
            ))
        } else {
            Ok(StepResult::completed(
                "YubiKey attestation certificate generated",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockBackend;
    use rite_model::{ArtifactId, StepFact, StepId};
    use rite_runtime::test_support::ReporterHarness;
    use std::collections::HashMap;

    #[test]
    fn attests_slot_and_emits_fact() {
        let mut harness = ReporterHarness::new();
        let step = StepInfo::new(
            StepId::new("attest"),
            None,
            Some("mock".to_string()),
            Some(ArtifactId::new("attestation")),
            None,
        );
        let params = serde_json::json!({ "slot": "9c" });
        let artifacts = HashMap::new();
        let pmap = HashMap::new();
        let roles = HashMap::new();
        let materials = HashMap::new();
        let ctx = HandlerContext {
            params: &pmap,
            artifacts: &artifacts,
            roles: &roles,
            materials: &materials,
        };
        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());

        let result = {
            let mut reporter = harness.reporter(StepId::new("attest"));
            YubikeyAttestSlotAction
                .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
                .expect("attest succeeds against the mock")
        };

        assert_eq!(result.artifacts.len(), 1);
        let (id, value) = result.artifacts.first().expect("one produced artifact");
        assert_eq!(id.as_str(), "attestation");
        assert!(matches!(value, ArtifactValue::Bytes(b) if b == b"MOCK_ATTESTATION_CERT_DER"));

        assert!(harness.facts().iter().any(|f| matches!(
            f,
            StepFact::BackendOperation { kind, .. } if kind == "yubikey_attest_slot"
        )));
    }
}
