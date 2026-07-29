//! Issue an X.509 certificate from a PKCS#10 CSR.
//!
//! Assembles a `TbsCertificate` from the CSR plus a chosen profile,
//! signs it via the backend's `SignBackend`, and produces a DER-encoded
//! X.509 certificate.
//!
//! # Design
//!
//! Certificate construction goes through `x509_cert`'s `CertificateBuilder`,
//! using its external-signature path (`finalize` to obtain the TBS bytes,
//! `assemble` to attach the signature). The backend only provides raw
//! signature bytes via `SignBackend::sign`; no private key material enters
//! this process. This means the action works with any backend implementing
//! `SignBackend` (software, PKCS#11, `YubiKey`) without per-backend
//! cert-building code.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, ArtifactValue, HandlerContext, Icon,
    Reporter, StepInfo, StepResult, parse_params, resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::Backend;
use serde_json::json;
use signature::Keypair;
use x509_cert::der::{
    self, Decode, DecodePem, Document, Encode,
    asn1::{BitString, ObjectIdentifier, OctetString},
    oid::AssociatedOid,
};
use x509_cert::{
    Certificate, TbsCertificate,
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
        SubjectAltName, SubjectKeyIdentifier,
    },
    name::Name,
    request::{CertReq, ExtensionReq},
    serial_number::SerialNumber,
    spki::{
        AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
        SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef,
    },
    time::Validity,
};

use crate::params::IssueCertificateParams;

use super::oids::{
    ECDSA_WITH_SHA256, ML_DSA_44, ML_DSA_65, ML_DSA_87, SHA256_WITH_RSA_ENCRYPTION,
    sig_profile_for_algorithm,
};

/// id-kp-serverAuth OID (1.3.6.1.5.5.7.3.1)
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

/// id-kp-codeSigning OID (1.3.6.1.5.5.7.3.3)
const ID_KP_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");

/// Certificate profile, parsed from the `profile` param string.
enum CertProfile {
    RootCa,
    SubCa { path_len: u8 },
    TlsServer,
    CodeSigning,
    EndEntity,
}

impl CertProfile {
    fn canonical_name(&self) -> &'static str {
        match self {
            CertProfile::RootCa => "root_ca",
            CertProfile::SubCa { .. } => "sub_ca",
            CertProfile::TlsServer => "tls_server",
            CertProfile::CodeSigning => "code_signing",
            CertProfile::EndEntity => "end_entity",
        }
    }
}

/// Public half of the backend-held issuing key.
#[derive(Clone)]
struct IssuingPublicKey(SubjectPublicKeyInfoOwned);

impl EncodePublicKey for IssuingPublicKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<Document> {
        Document::try_from(&self.0)
    }
}

/// Presents the ceremony backend's issuing key to the `x509_cert` builder.
///
/// The builder needs the issuing key's public half and its signature
/// algorithm identifier; the signature itself is produced by the backend
/// between `Builder::finalize` and `Builder::assemble`, so this type holds
/// no private key material.
struct BackendIssuingKey {
    public_key: IssuingPublicKey,
    signature_algorithm: AlgorithmIdentifierOwned,
}

impl Keypair for BackendIssuingKey {
    type VerifyingKey = IssuingPublicKey;

    fn verifying_key(&self) -> IssuingPublicKey {
        self.public_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for BackendIssuingKey {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.signature_algorithm.clone())
    }
}

/// Adapts a [`CertProfile`] to the `x509_cert` builder's profile interface,
/// carrying the run-specific values the extensions are derived from.
struct ProfileAdapter {
    profile: CertProfile,
    subject: Name,
    issuer: Name,
    /// Whether an issuer certificate was supplied; gates the
    /// `AuthorityKeyIdentifier` extension (self-signed roots carry none).
    has_issuer_cert: bool,
    /// `SubjectAltName` carried over from the CSR's extensionRequest
    /// attribute, for profiles that honor it.
    san: Option<x509_cert::ext::Extension>,
}

impl BuilderProfile for ProfileAdapter {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<x509_cert::ext::Extension>> {
        // `issuer_spk` is derived by the builder from the issuing key
        // adapter, so the AKI matches the signer by construction.
        let issuer_spk = self.has_issuer_cert.then_some(issuer_spk);
        build_extensions(&self.profile, spk, issuer_spk, self.san.as_ref())
            .map_err(x509_cert::builder::Error::from)
    }
}

/// Issue an X.509 certificate from a PKCS#10 CSR.
pub struct IssueCertificateAction;

impl Action for IssueCertificateAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::IssueCertificate,
            description: "Issue X.509 certificate from PKCS#10 CSR",
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
        let typed: IssueCertificateParams = parse_params(params)?;

        let validity_days = typed.validity_days.unwrap_or(3650);
        let profile = parse_profile(typed.profile.as_deref(), typed.path_len)?;

        let signing_key_ref = step.required_named_input("signing_key", "issue_certificate")?;
        let csr_ref = step.required_named_input("csr", "issue_certificate")?;
        let issuer_cert_ref = step.named_input("issuer_cert");

        let signing_key_id = signing_key_ref.artifact_id();
        let (key_backend_name, key_id, key_algorithm, _) =
            resolve_backend_key(ctx.artifacts, &signing_key_id).map_err(|e| {
                ActionError::Failed(format!(
                    "signing_key '{}' must be a BackendKey: {e}",
                    signing_key_ref.display_name()
                ))
            })?;
        let key_id = key_id.clone();
        let key_backend_name = key_backend_name.to_string();

        let csr_id = csr_ref.artifact_id();
        let csr_bytes = resolve_artifact_bytes(ctx.artifacts, &csr_id, csr_ref.property())
            .map_err(|e| {
                ActionError::Failed(format!(
                    "csr '{}' could not be resolved: {e}",
                    csr_ref.display_name()
                ))
            })?;

        let csr = parse_csr(&csr_bytes)
            .map_err(|e| ActionError::Failed(format!("Failed to parse CSR: {e}")))?;

        reporter.log(Icon::Info, "Parsed CSR successfully")?;
        reporter.log(Icon::Info, format!("Subject: {}", csr.info.subject))?;

        verify_csr_signature(&csr).map_err(ActionError::Failed)?;
        reporter.log(Icon::Checkmark, "CSR signature verified")?;

        let issuer_cert_opt = if let Some(issuer_ref) = issuer_cert_ref {
            let issuer_id = issuer_ref.artifact_id();
            let issuer_bytes =
                resolve_artifact_bytes(ctx.artifacts, &issuer_id, issuer_ref.property()).map_err(
                    |e| {
                        ActionError::Failed(format!(
                            "issuer_cert '{}' could not be resolved: {e}",
                            issuer_ref.display_name()
                        ))
                    },
                )?;
            let issuer_cert = parse_certificate(&issuer_bytes)
                .map_err(|e| ActionError::Failed(format!("Failed to parse issuer cert: {e}")))?;
            Some(issuer_cert)
        } else {
            None
        };

        let issuer_name: Name = if let Some(ref ic) = issuer_cert_opt {
            ic.tbs_certificate().subject().clone()
        } else if let Some(cn) = typed.issuer_cn.as_deref() {
            format!("CN={cn}")
                .parse()
                .map_err(|e| ActionError::Failed(format!("Invalid issuer CN: {e}")))?
        } else {
            // Self-signed issuance: the issuer is the CSR subject, so the
            // certificate chains to itself (RFC 5280 self-issued).
            csr.info.subject.clone()
        };

        // Draw the serial from the ceremony entropy source rather than an
        // unrecorded RNG, so it is auditable and re-derivable by `rite verify`.
        // `SerialNumber` wraps an unsigned ASN.1 INTEGER, so the raw bytes need
        // no sign fixup (no bit is spent on representation). Sixteen bytes give
        // 128 bits, the conventional CA serial size and well above the 64-bit
        // CA/Browser Forum floor. An all-zero draw (p = 2^-128) would yield
        // serial 0; negligible, so it is not guarded.
        let serial_bytes = reporter.draw("cert-serial", 16)?;
        let serial = SerialNumber::new(&serial_bytes)
            .map_err(|e| ActionError::Failed(format!("Failed to build serial number: {e}")))?;

        let validity = build_validity(validity_days)
            .map_err(|e| ActionError::Failed(format!("Failed to build validity period: {e}")))?;

        let (sign_algorithm, sig_alg, evidence_algorithm) =
            sig_profile_for_algorithm(key_algorithm).map_err(|e| {
                ActionError::Failed(format!("Failed to build signature algorithm: {e}"))
            })?;

        // The issuing key's public half: the issuer certificate's SPKI, or
        // the CSR's own key when issuing self-signed (root) certificates.
        let issuer_spki = issuer_cert_opt
            .as_ref()
            .map(|ic| ic.tbs_certificate().subject_public_key_info().clone());
        let has_issuer_cert = issuer_spki.is_some();

        let issuing_key = BackendIssuingKey {
            public_key: IssuingPublicKey(
                issuer_spki.unwrap_or_else(|| csr.info.public_key.clone()),
            ),
            signature_algorithm: sig_alg,
        };

        let profile_name = profile.canonical_name();
        let adapter = ProfileAdapter {
            profile,
            subject: csr.info.subject.clone(),
            issuer: issuer_name,
            has_issuer_cert,
            san: extract_san_from_csr(&csr),
        };

        let mut builder = CertificateBuilder::new(adapter, serial, validity, csr.info.public_key)
            .map_err(|e| {
            ActionError::Failed(format!("Failed to set up certificate builder: {e}"))
        })?;

        let tbs_der = builder
            .finalize(&issuing_key)
            .map_err(|e| ActionError::Failed(format!("TBSCertificate DER encoding failed: {e}")))?;

        reporter.log(Icon::Spinner, "Signing TBSCertificate...")?;

        let backend = backend.ok_or_else(|| {
            ActionError::Failed(
                "Backend required for certificate signing (use MockBackend for dry-run)"
                    .to_string(),
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

        let signature_bytes = sign_backend.sign(&key_id, &tbs_der, sign_algorithm)?;

        let signature = BitString::from_bytes(&signature_bytes).map_err(|e| {
            ActionError::Failed(format!("Failed to encode signature as BitString: {e}"))
        })?;

        let cert = builder
            .assemble(signature, &issuing_key)
            .map_err(|e| ActionError::Failed(format!("Certificate assembly failed: {e}")))?;

        let cert_der = cert
            .to_der()
            .map_err(|e| ActionError::Failed(format!("Certificate DER encoding failed: {e}")))?;

        reporter.log(Icon::Checkmark, "Certificate signed")?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "issue_certificate".to_string(),
            inputs: json!({
                "algorithm": evidence_algorithm,
                "profile": profile_name,
                "validity_days": validity_days,
                "signing_key": signing_key_ref.display_name(),
                "csr": csr_ref.display_name(),
            }),
            outputs: json!({
                "backend": backend_name,
                "backend_fingerprint": backend_fingerprint,
            }),
            fingerprint: None,
        })?;

        let artifact = ArtifactValue::Certificate { der: cert_der };
        let message = "X.509 certificate issued from CSR".to_string();

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Certificate stored as artifact '{produces}'"),
            )?;
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

fn parse_profile(profile: Option<&str>, path_len: Option<u8>) -> Result<CertProfile, ActionError> {
    match profile {
        None | Some("end_entity") => Ok(CertProfile::EndEntity),
        Some("root_ca") => Ok(CertProfile::RootCa),
        Some("sub_ca" | "intermediate_ca") => Ok(CertProfile::SubCa {
            path_len: path_len.unwrap_or(0),
        }),
        Some("tls_server") => Ok(CertProfile::TlsServer),
        Some("code_signing") => Ok(CertProfile::CodeSigning),
        Some(other) => Err(ActionError::Failed(format!(
            "Unknown certificate profile '{other}'. Supported: root_ca, sub_ca, tls_server, \
             code_signing, end_entity"
        ))),
    }
}

fn build_extensions(
    profile: &CertProfile,
    subject_spki: SubjectPublicKeyInfoRef<'_>,
    issuer_spki: Option<SubjectPublicKeyInfoRef<'_>>,
    san_ext: Option<&x509_cert::ext::Extension>,
) -> Result<x509_cert::ext::Extensions, der::Error> {
    let mut exts: x509_cert::ext::Extensions = Vec::new();

    match profile {
        CertProfile::RootCa => {
            exts.push(build_basic_constraints(true, None)?);
            exts.push(build_key_usage(
                KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature,
            )?);
            exts.push(build_ski(subject_spki)?);
        }
        CertProfile::SubCa { path_len } => {
            exts.push(build_basic_constraints(true, Some(*path_len))?);
            exts.push(build_key_usage(
                KeyUsages::KeyCertSign | KeyUsages::CRLSign | KeyUsages::DigitalSignature,
            )?);
            exts.push(build_ski(subject_spki)?);
            if let Some(spki) = issuer_spki {
                exts.push(build_aki(spki)?);
            }
        }
        CertProfile::TlsServer => {
            exts.push(build_basic_constraints(false, None)?);
            exts.push(build_key_usage(
                KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment,
            )?);
            exts.push(build_eku(&[ID_KP_SERVER_AUTH])?);
            exts.push(build_ski(subject_spki)?);
            if let Some(spki) = issuer_spki {
                exts.push(build_aki(spki)?);
            }
            if let Some(ext) = san_ext {
                exts.push(ext.clone());
            }
        }
        CertProfile::CodeSigning => {
            exts.push(build_basic_constraints(false, None)?);
            exts.push(build_key_usage(KeyUsages::DigitalSignature.into())?);
            exts.push(build_eku(&[ID_KP_CODE_SIGNING])?);
            if let Some(spki) = issuer_spki {
                exts.push(build_aki(spki)?);
            }
        }
        CertProfile::EndEntity => {
            exts.push(build_basic_constraints(false, None)?);
            if let Some(spki) = issuer_spki {
                exts.push(build_aki(spki)?);
            }
        }
    }

    Ok(exts)
}

fn build_basic_constraints(
    ca: bool,
    path_len: Option<u8>,
) -> Result<x509_cert::ext::Extension, der::Error> {
    let bc = BasicConstraints {
        ca,
        path_len_constraint: path_len,
    };
    Ok(x509_cert::ext::Extension {
        extn_id: BasicConstraints::OID,
        critical: true,
        extn_value: OctetString::new(bc.to_der()?)?,
    })
}

fn build_key_usage(
    bits: der::flagset::FlagSet<KeyUsages>,
) -> Result<x509_cert::ext::Extension, der::Error> {
    let ku = KeyUsage(bits);
    Ok(x509_cert::ext::Extension {
        extn_id: KeyUsage::OID,
        critical: true,
        extn_value: OctetString::new(ku.to_der()?)?,
    })
}

fn build_eku(oids: &[ObjectIdentifier]) -> Result<x509_cert::ext::Extension, der::Error> {
    let eku = ExtendedKeyUsage(oids.to_vec());
    Ok(x509_cert::ext::Extension {
        extn_id: ExtendedKeyUsage::OID,
        critical: false,
        extn_value: OctetString::new(eku.to_der()?)?,
    })
}

fn build_ski(spki: SubjectPublicKeyInfoRef<'_>) -> Result<x509_cert::ext::Extension, der::Error> {
    // RFC 5280 Section 4.2.1.2 method-1 derivation, provided by `x509_cert`.
    let subject_key_id = SubjectKeyIdentifier::try_from(spki)?;
    Ok(x509_cert::ext::Extension {
        extn_id: SubjectKeyIdentifier::OID,
        critical: false,
        extn_value: OctetString::new(subject_key_id.to_der()?)?,
    })
}

fn build_aki(
    issuer_spki: SubjectPublicKeyInfoRef<'_>,
) -> Result<x509_cert::ext::Extension, der::Error> {
    // Key-identifier-only AKI, derived like the issuer's SKI (RFC 5280
    // Section 4.2.1.1), provided by `x509_cert`.
    let authority_key_id = AuthorityKeyIdentifier::try_from(issuer_spki)?;
    Ok(x509_cert::ext::Extension {
        extn_id: AuthorityKeyIdentifier::OID,
        critical: false,
        extn_value: OctetString::new(authority_key_id.to_der()?)?,
    })
}

/// Extract the `SubjectAltName` extension from a CSR's extensionRequest attribute (if present).
fn extract_san_from_csr(csr: &CertReq) -> Option<x509_cert::ext::Extension> {
    for attr in csr.info.attributes.iter() {
        if attr.oid != ExtensionReq::OID {
            continue;
        }
        for val in attr.values.iter() {
            if let Ok(exts) = val.decode_as::<x509_cert::ext::Extensions>() {
                for ext in exts {
                    if ext.extn_id == SubjectAltName::OID {
                        return Some(ext);
                    }
                }
            }
        }
    }
    None
}

/// SHA-256 `DigestInfo` DER prefix for PKCS#1 v1.5 (RFC 3447 §9.2, note 1).
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Verify the CSR's self-signature.
fn verify_csr_signature(csr: &CertReq) -> Result<(), String> {
    let oid = csr.algorithm.oid;

    let spki_der = csr
        .info
        .public_key
        .to_der()
        .map_err(|e| format!("Failed to encode public key: {e}"))?;
    let info_der = csr
        .info
        .to_der()
        .map_err(|e| format!("Failed to encode CertReqInfo: {e}"))?;

    if oid == SHA256_WITH_RSA_ENCRYPTION {
        use rsa::pkcs8::DecodePublicKey;
        use sha2::Digest;

        let rsa_key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("Failed to parse RSA public key from CSR: {e}"))?;

        let hash = sha2::Sha256::digest(&info_der);
        let mut digest_info = SHA256_DIGEST_INFO_PREFIX.to_vec();
        digest_info.extend_from_slice(&hash);

        rsa_key
            .verify(
                rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                &digest_info,
                csr.signature.raw_bytes(),
            )
            .map_err(|_| {
                "CSR self-signature verification failed: signature does not match".to_string()
            })
    } else if oid == ECDSA_WITH_SHA256 {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use p256::pkcs8::DecodePublicKey;

        let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("Failed to parse ECDSA P-256 public key from CSR: {e}"))?;
        let signature = Signature::from_der(csr.signature.raw_bytes())
            .map_err(|e| format!("Failed to parse ECDSA signature from CSR: {e}"))?;

        verifying_key.verify(&info_der, &signature).map_err(|_| {
            "CSR self-signature verification failed: ECDSA signature does not match".to_string()
        })
    } else if oid == ML_DSA_44 || oid == ML_DSA_65 || oid == ML_DSA_87 {
        verify_ml_dsa_csr(&spki_der, &info_der, csr.signature.raw_bytes())
    } else {
        Err(format!(
            "CSR signature algorithm {oid} is not supported for verification. \
             Supported algorithms are sha256WithRSAEncryption, ecdsa-with-SHA256, \
             and ML-DSA-44/65/87."
        ))
    }
}

/// Verify an ML-DSA CSR self-signature.
///
/// The RSA and ECDSA branches above verify with `RustCrypto`, but no equivalent
/// in-tree verifier covers ML-DSA, so this delegates to the same OpenSSL
/// provider that produced the signature. Unifying all three onto one
/// implementation is tracked as the open question in the meta-repo's
/// `sign-verify-actions` investigation.
#[cfg(feature = "openssl")]
fn verify_ml_dsa_csr(spki_der: &[u8], info_der: &[u8], signature: &[u8]) -> Result<(), String> {
    match rite_openssl::verify_ml_dsa_signature(spki_der, info_der, signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(
            "CSR self-signature verification failed: ML-DSA signature does not match".to_string(),
        ),
        Err(e) => Err(format!("Failed to verify ML-DSA CSR self-signature: {e}")),
    }
}

#[cfg(not(feature = "openssl"))]
fn verify_ml_dsa_csr(_spki_der: &[u8], _info_der: &[u8], _signature: &[u8]) -> Result<(), String> {
    Err("ML-DSA CSR verification requires the 'openssl' feature".to_string())
}

fn parse_csr(bytes: &[u8]) -> Result<CertReq, der::Error> {
    if bytes.starts_with(b"-----") {
        let pem_str =
            std::str::from_utf8(bytes).map_err(|_| der::Error::from(der::ErrorKind::Failed))?;
        CertReq::from_pem(pem_str)
    } else {
        CertReq::from_der(bytes)
    }
}

fn parse_certificate(bytes: &[u8]) -> Result<Certificate, der::Error> {
    if bytes.starts_with(b"-----") {
        let pem_str =
            std::str::from_utf8(bytes).map_err(|_| der::Error::from(der::ErrorKind::Failed))?;
        Certificate::from_pem(pem_str)
    } else {
        Certificate::from_der(bytes)
    }
}

fn build_validity(validity_days: u32) -> Result<Validity, der::Error> {
    let duration = std::time::Duration::from_secs(u64::from(validity_days).saturating_mul(86_400));
    Validity::from_now(duration)
}
