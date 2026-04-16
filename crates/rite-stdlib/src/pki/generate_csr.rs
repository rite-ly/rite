//! Generate PKCS#10 CSR from a backend-managed key.
//!
//! This action takes a backend-managed signing key and subject parameters, assembles a
//! `CertReqInfo`, signs it via the backend's `SignBackend`, and produces a DER-encoded CSR.
//!
//! ## Why this action exists
//!
//! `issue_certificate` requires a CSR as input. For backend-managed keys (HSM, software store),
//! the private key never leaves the backend — so a CSR must be generated in-ceremony using
//! the same backend. This action bridges that gap: it builds the CSR structure from subject
//! params, uses the backend to sign it with the private key, and yields a raw CSR artifact
//! that `issue_certificate` can consume.

use der::{
    Decode, Encode,
    asn1::{BitString, Ia5String, Null, OctetString, SetOfVec},
};
use rite_model::{ActionType, StepInputs};
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ArtifactValue, ExecutionError, HandlerContext,
    StepEvidence, StepInfo, StepResult, StepUI, display, resolve_backend_key,
};
use rite_sdk::{Backend, SignAlgorithm};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::{
    ext::pkix::SubjectAltName,
    name::Name,
    request::{CertReq, CertReqInfo, Version},
    spki::SubjectPublicKeyInfoOwned,
};

use crate::params::GenerateCsrParams;

use super::oids::{EXTENSION_REQUEST_OID, ID_CE_SUBJECT_ALT_NAME, SHA256_WITH_RSA_ENCRYPTION};

/// Generate PKCS#10 CSR from backend key action.
pub struct GenerateCsrAction;

impl ActionHandler for GenerateCsrAction {
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
        ui: &mut dyn StepUI,
        backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        let typed: GenerateCsrParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let signing_key_ref = step
            .typed_inputs
            .as_ref()
            .and_then(StepInputs::as_named)
            .and_then(|m| m.get("signing_key"));

        let signing_key_ref = signing_key_ref.ok_or_else(|| {
            ExecutionError::InvalidParams(
                "generate_csr: 'signing_key' named input is required".to_string(),
            )
        })?;

        let signing_key_id = signing_key_ref.artifact_id();
        let (key_backend_name, key_id, _, public_key_bytes) =
            resolve_backend_key(ctx.artifacts, &signing_key_id).map_err(|e| {
                ExecutionError::InvalidParams(format!(
                    "signing_key '{}' must be a BackendKey: {e}",
                    signing_key_ref.display_name()
                ))
            })?;

        let public_key_bytes = public_key_bytes.ok_or_else(|| {
            ExecutionError::InvalidParams(
                "generate_csr: signing key has no exported public key \
                 (non-exportable HSM keys are not supported)"
                    .to_string(),
            )
        })?;

        let key_id = key_id.clone();
        let key_backend_name = key_backend_name.to_string();

        let subject: Name = typed.subject.parse().map_err(|_| {
            ExecutionError::InvalidParams(format!(
                "Invalid subject DN '{}': expected RFC 4514 string (e.g. \"CN=foo,O=bar,C=US\")",
                typed.subject
            ))
        })?;

        display::write_line(ui, &format!("Subject: {subject}"))?;

        let spki = SubjectPublicKeyInfoOwned::from_der(public_key_bytes).map_err(|e| {
            ExecutionError::InvalidParams(format!("Failed to parse signing key's public key: {e}"))
        })?;

        let attributes: SetOfVec<Attribute> =
            if let Some(san) = typed.san.as_ref().filter(|v| !v.is_empty()) {
                let san_attr = build_san_attribute(san, step)?;
                let mut set = SetOfVec::new();
                set.insert(san_attr)
                    .map_err(|e| ExecutionError::StepFailed {
                        step: step.id.clone(),
                        reason: format!("Failed to build CSR attributes: {e}"),
                    })?;
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

        let info_der = info.to_der().map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("CertReqInfo DER encoding failed: {e}"),
        })?;

        display::write_line(ui, "Signing CertReqInfo...")?;

        let backend = backend.ok_or_else(|| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: "Backend required for CSR signing (use MockBackend for dry-run)".to_string(),
        })?;

        let backend_fingerprint = backend.fingerprint();
        let backend_name = backend.name().to_string();

        if backend_name != key_backend_name {
            return Err(ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!(
                    "Signing key is on backend '{key_backend_name}', but step backend is '{backend_name}'"
                ),
            });
        }

        let sign_backend = backend
            .as_sign_mut()
            .ok_or_else(|| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("Backend '{backend_name}' does not support signing"),
            })?;

        let signature_bytes = sign_backend
            .sign(&key_id, &info_der, SignAlgorithm::RsaPkcs1Sha256)
            .map_err(|e| ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("Signing failed: {e}"),
            })?;

        let null_der = Null.to_der().map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Failed to encode NULL: {e}"),
        })?;
        let null_any = der::Any::from_der(&null_der).map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Failed to build algorithm params: {e}"),
        })?;
        let sig_alg = x509_cert::spki::AlgorithmIdentifier {
            oid: SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(null_any),
        };

        let csr = CertReq {
            info,
            algorithm: sig_alg,
            signature: BitString::from_bytes(&signature_bytes).map_err(|e| {
                ExecutionError::StepFailed {
                    step: step.id.clone(),
                    reason: format!("Failed to encode signature as BitString: {e}"),
                }
            })?,
        };

        let csr_der = csr.to_der().map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("CSR DER encoding failed: {e}"),
        })?;

        display::write_success(ui, &format!("CSR generated ({} bytes DER)", csr_der.len()))?;

        let mut evidence = StepEvidence::new();
        evidence.insert("algorithm", "sha256WithRSAEncryption");
        evidence.insert("signing_key", signing_key_ref.display_name().as_str());
        evidence.insert("backend", backend_name.as_str());
        evidence.insert("backend_fingerprint", backend_fingerprint.as_str());

        let artifact = ArtifactValue::Bytes(csr_der);
        let message = "PKCS#10 CSR generated".to_string();

        if let Some(produces) = &step.produces {
            display::write_line(ui, &format!("CSR stored as artifact '{produces}'"))?;
            let result = StepResult::completed_with_artifact(message, produces.clone(), artifact);
            Ok((result, evidence))
        } else {
            let result = StepResult::completed(message);
            Ok((result, evidence))
        }
    }
}

/// Build a PKCS#9 extensionRequest attribute containing a `SubjectAltName` extension.
fn build_san_attribute(
    san_strings: &[String],
    step: &StepInfo,
) -> Result<Attribute, ExecutionError> {
    let mut names: Vec<GeneralName> = Vec::new();
    for s in san_strings {
        if let Some(value) = s.strip_prefix("DNS:") {
            let ia5 = Ia5String::new(value).map_err(|e| {
                ExecutionError::InvalidParams(format!("Invalid DNS SAN '{value}': {e}"))
            })?;
            names.push(GeneralName::DnsName(ia5));
        } else if let Some(value) = s.strip_prefix("IP:") {
            let ip_bytes = parse_ip_address(value).ok_or_else(|| {
                ExecutionError::InvalidParams(format!(
                    "Invalid IP SAN '{value}': must be a valid IPv4 or IPv6 address"
                ))
            })?;
            let octet = OctetString::new(ip_bytes).map_err(|e| {
                ExecutionError::InvalidParams(format!("Failed to encode IP SAN: {e}"))
            })?;
            names.push(GeneralName::IpAddress(octet));
        } else if let Some(value) = s.strip_prefix("email:") {
            let ia5 = Ia5String::new(value).map_err(|e| {
                ExecutionError::InvalidParams(format!("Invalid email SAN '{value}': {e}"))
            })?;
            names.push(GeneralName::Rfc822Name(ia5));
        } else {
            return Err(ExecutionError::InvalidParams(format!(
                "Unknown SAN prefix in '{s}': supported prefixes are DNS:, IP:, email:"
            )));
        }
    }

    let san = SubjectAltName(names);

    let san_der = san.to_der().map_err(|e| ExecutionError::StepFailed {
        step: step.id.clone(),
        reason: format!("Failed to encode SubjectAltName: {e}"),
    })?;

    let ext = x509_cert::ext::Extension {
        extn_id: ID_CE_SUBJECT_ALT_NAME,
        critical: false,
        extn_value: OctetString::new(san_der).map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Failed to build SAN extension value: {e}"),
        })?,
    };

    let extensions: x509_cert::ext::Extensions = vec![ext];
    let extensions_der = extensions
        .to_der()
        .map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Failed to encode Extensions: {e}"),
        })?;

    let exts_any = der::Any::from_der(&extensions_der).map_err(|e| ExecutionError::StepFailed {
        step: step.id.clone(),
        reason: format!("Failed to wrap extensions as Any: {e}"),
    })?;

    let mut attr_values: SetOfVec<der::Any> = SetOfVec::new();
    attr_values
        .insert(exts_any)
        .map_err(|e| ExecutionError::StepFailed {
            step: step.id.clone(),
            reason: format!("Failed to build attribute values: {e}"),
        })?;

    Ok(Attribute {
        oid: EXTENSION_REQUEST_OID,
        values: attr_values,
    })
}

/// Parse an IP address string into raw bytes (4 bytes for IPv4, 16 for IPv6).
fn parse_ip_address(s: &str) -> Option<Vec<u8>> {
    if let Ok(addr) = s.parse::<std::net::Ipv4Addr>() {
        Some(addr.octets().to_vec())
    } else if let Ok(addr) = s.parse::<std::net::Ipv6Addr>() {
        Some(addr.octets().to_vec())
    } else {
        None
    }
}
