//! `piv_read_certificate` action: read an X.509 certificate from a PIV slot.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, compute_fingerprint, parse_params,
};
use rite_sdk::{Backend, CertRef, CertificateDer};
use serde_json::json;

use super::params::PivReadCertificateParams;

/// Read an X.509 certificate from a PIV smart card slot.
//
// This is PIV-specific only in that it addresses the certificate by slot. If a
// generic "read certificate from a backend" action is later introduced (any
// `CertStoreBackend`, addressed by `CertRef`), this could collapse into a thin
// wrapper that maps a slot hint to `CertRef::PivSlot`. Worth reconciling at that
// point rather than growing two parallel cert-read paths.
pub struct PivReadCertificateAction;

impl Action for PivReadCertificateAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::PivReadCertificate,
            description: "Read X.509 certificate from PIV smart card slot",
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
        let typed: PivReadCertificateParams = parse_params(params)?;

        if let Some(msg) = &typed.message {
            reporter.log(Icon::Info, msg.clone())?;
        }
        reporter.log(
            Icon::Spinner,
            format!("Reading certificate from PIV slot {}...", typed.slot),
        )?;

        // Validate the slot early so bad params fail before hardware access.
        let piv_slot = rite_piv::ops::slot_from_hint(&typed.slot)
            .map_err(|e| ActionError::Failed(format!("Invalid PIV slot: {e}")))?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed("Backend required to read PIV certificate".into())
        })?;
        let backend_name = backend.name().to_string();

        let certstore = backend.as_certstore_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' does not support certificate operations"
            ))
        })?;

        let cert_der = certstore.read_cert(&CertRef::PivSlot(piv_slot))?;
        let cert_fingerprint = compute_fingerprint(&cert_der);

        reporter.log(
            Icon::Checkmark,
            format!(
                "Certificate read ({} bytes, fingerprint: {cert_fingerprint})",
                cert_der.len()
            ),
        )?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "piv_read_certificate".to_string(),
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
                format!("Certificate stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                "Certificate read from PIV slot",
                produces.clone(),
                ArtifactValue::Certificate(CertificateDer::new(cert_der).map_err(|e| {
                    ActionError::Failed(format!("PIV slot holds an unreadable certificate: {e}"))
                })?),
            ))
        } else {
            Ok(StepResult::completed("Certificate read from PIV slot"))
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
    fn reads_certificate_and_emits_fact() {
        let mut harness = ReporterHarness::new();
        let step = StepInfo::new(
            StepId::new("read"),
            None,
            Some("mock".to_string()),
            Some(ArtifactId::new("cert")),
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
        let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());

        let result = {
            let mut reporter = harness.reporter(StepId::new("read"));
            PivReadCertificateAction
                .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
                .expect("read succeeds against the mock")
        };

        assert_eq!(result.artifacts.len(), 1);
        let (id, value) = result.artifacts.first().expect("one produced artifact");
        assert_eq!(id.as_str(), "cert");
        // A certificate, not loose bytes: every consumer downstream reads a key
        // or a subject out of it, and typing it here is what makes that work.
        let ArtifactValue::Certificate(certificate) = value else {
            panic!("expected a certificate artifact, got {value:?}");
        };
        assert!(certificate.public_key().is_ok());

        assert!(harness.facts().iter().any(|f| matches!(
            f,
            StepFact::BackendOperation { kind, .. } if kind == "piv_read_certificate"
        )));
    }

    #[test]
    fn rejects_an_unknown_slot() {
        let mut harness = ReporterHarness::new();
        let step = StepInfo::new(
            StepId::new("read"),
            None,
            Some("mock".to_string()),
            None,
            None,
        );
        let params = serde_json::json!({ "slot": "zz" });
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
        let mut backend = MockBackend::new("mock".to_string(), "seed".to_string());

        let mut reporter = harness.reporter(StepId::new("read"));
        let err = PivReadCertificateAction
            .execute(&step, &ctx, &params, &mut reporter, Some(&mut backend))
            .expect_err("an unknown slot must fail");
        assert!(err.to_string().contains("Invalid PIV slot"));
    }
}
