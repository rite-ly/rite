//! Generate a PKCS#10 CSR from a backend-managed key.
//!
//! Assembles a `CertReqInfo` from subject parameters, signs it via the
//! backend's `SignBackend`, and produces a DER-encoded CSR. For
//! backend-managed keys (HSM, software store) the private key never
//! leaves the backend, so the CSR must be generated in-ceremony with
//! the same backend before [`crate::pki::issue_certificate`] can consume it.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, parse_params, resolve_backend_key,
};
use rite_sdk::Backend;
use serde_json::json;
use x509_cert::attr::Attribute;
use x509_cert::der::{
    Decode, Encode,
    asn1::{BitString, Ia5String, OctetString, SetOfVec},
    oid::AssociatedOid,
};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::{
    ext::pkix::SubjectAltName,
    name::Name,
    request::{CertReq, CertReqInfo, ExtensionReq, Version},
    spki::SubjectPublicKeyInfoOwned,
};

use crate::params::GenerateCsrParams;

use super::oids::sig_profile_for_algorithm;

/// Generate a PKCS#10 CSR using a backend-managed signing key.
pub struct GenerateCsrAction;

impl Action for GenerateCsrAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::GenerateCsr,
            description: "Generate PKCS#10 CSR from backend-managed key",
            category: ActionCategory::Crypto,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: GenerateCsrParams = parse_params(params)?;

        let signing_key_ref = step.required_named_input("signing_key", "generate_csr")?;

        let signing_key_id = signing_key_ref.artifact_id();
        let (key_backend_name, key_id, key_algorithm, public_key_bytes) =
            resolve_backend_key(ctx.artifacts, &signing_key_id).map_err(|e| {
                ActionError::Failed(format!(
                    "signing_key '{}' must be a BackendKey: {e}",
                    signing_key_ref.display_name()
                ))
            })?;

        let public_key_bytes = public_key_bytes.ok_or_else(|| {
            ActionError::Failed(
                "generate_csr: signing key has no exported public key \
                 (non-exportable HSM keys are not supported)"
                    .to_string(),
            )
        })?;

        let key_id = key_id.clone();
        let key_backend_name = key_backend_name.to_string();
        let (sign_algorithm, sig_alg, evidence_algorithm) =
            sig_profile_for_algorithm(key_algorithm)
                .map_err(|e| ActionError::Failed(format!("generate_csr: {e}")))?;

        let subject: Name = typed.subject.parse().map_err(|_| {
            ActionError::Failed(format!(
                "Invalid subject DN '{}': expected RFC 4514 string (e.g. \"CN=foo,O=bar,C=US\")",
                typed.subject
            ))
        })?;

        reporter.log(Icon::Info, format!("Subject: {subject}"))?;

        let spki = SubjectPublicKeyInfoOwned::from_der(public_key_bytes).map_err(|e| {
            ActionError::Failed(format!("Failed to parse signing key's public key: {e}"))
        })?;

        let attributes: SetOfVec<Attribute> = if let Some(san) =
            typed.san.as_ref().filter(|v| !v.is_empty())
        {
            let san_attr = build_san_attribute(san)?;
            let mut set = SetOfVec::new();
            set.insert(san_attr)
                .map_err(|e| ActionError::Failed(format!("Failed to build CSR attributes: {e}")))?;
            set
        } else {
            SetOfVec::default()
        };

        let info = CertReqInfo {
            version: Version::V1,
            subject,
            public_key: spki,
            attributes,
        };

        let info_der = info
            .to_der()
            .map_err(|e| ActionError::Failed(format!("CertReqInfo DER encoding failed: {e}")))?;

        reporter.log(Icon::Spinner, "Signing CertReqInfo...")?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed(
                "Backend required for CSR signing (use MockBackend for dry-run)".to_string(),
            )
        })?;

        let backend_fingerprint = backend.fingerprint();
        let backend_name = backend.name().to_string();

        if backend_name != key_backend_name {
            return Err(ActionError::Failed(format!(
                "Signing key is on backend '{key_backend_name}', but step backend is '{backend_name}'"
            )));
        }

        let sign_backend = backend.as_sign_mut().ok_or_else(|| {
            ActionError::Failed(format!("Backend '{backend_name}' does not support signing"))
        })?;

        let signature_bytes = sign_backend.sign(&key_id, &info_der, sign_algorithm)?;

        let csr = CertReq {
            info,
            algorithm: sig_alg,
            signature: BitString::from_bytes(&signature_bytes).map_err(|e| {
                ActionError::Failed(format!("Failed to encode signature as BitString: {e}"))
            })?,
        };

        let csr_der = csr
            .to_der()
            .map_err(|e| ActionError::Failed(format!("CSR DER encoding failed: {e}")))?;

        reporter.log(Icon::Checkmark, "CSR signed")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "generate_csr".to_string(),
            inputs: json!({
                "algorithm": evidence_algorithm,
                "signing_key": signing_key_ref.display_name(),
                "subject": typed.subject,
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
            }),
            fingerprint: None,
        })?;

        let artifact = ArtifactValue::Bytes(csr_der);
        let message = "PKCS#10 CSR generated".to_string();

        if let Some(produces) = &step.produces {
            reporter.log(Icon::Info, format!("CSR stored as artifact '{produces}'"))?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                artifact,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}

/// Build a PKCS#9 extensionRequest attribute containing a `SubjectAltName` extension.
fn build_san_attribute(san_strings: &[String]) -> Result<Attribute, ActionError> {
    let mut names: Vec<GeneralName> = Vec::new();
    for s in san_strings {
        if let Some(value) = s.strip_prefix("DNS:") {
            let ia5 = Ia5String::new(value)
                .map_err(|e| ActionError::Failed(format!("Invalid DNS SAN '{value}': {e}")))?;
            names.push(GeneralName::DnsName(ia5));
        } else if let Some(value) = s.strip_prefix("IP:") {
            let ip: std::net::IpAddr = value.parse().map_err(|_| {
                ActionError::Failed(format!(
                    "Invalid IP SAN '{value}': must be a valid IPv4 or IPv6 address"
                ))
            })?;
            names.push(GeneralName::from(ip));
        } else if let Some(value) = s.strip_prefix("email:") {
            let ia5 = Ia5String::new(value)
                .map_err(|e| ActionError::Failed(format!("Invalid email SAN '{value}': {e}")))?;
            names.push(GeneralName::Rfc822Name(ia5));
        } else {
            return Err(ActionError::Failed(format!(
                "Unknown SAN prefix in '{s}': supported prefixes are DNS:, IP:, email:"
            )));
        }
    }

    let san = SubjectAltName(names);
    let san_der = san
        .to_der()
        .map_err(|e| ActionError::Failed(format!("Failed to encode SubjectAltName: {e}")))?;

    let ext = x509_cert::ext::Extension {
        extn_id: SubjectAltName::OID,
        critical: false,
        extn_value: OctetString::new(san_der).map_err(|e| {
            ActionError::Failed(format!("Failed to build SAN extension value: {e}"))
        })?,
    };

    Attribute::try_from(ExtensionReq(vec![ext])).map_err(|e| {
        ActionError::Failed(format!("Failed to build extensionRequest attribute: {e}"))
    })
}
