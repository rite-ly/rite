//! Key material resolution and the signature checks that run without a backend.
//!
//! Two jobs, both on the way into a cryptographic step:
//!
//! - [`resolve_public_key`] and [`resolve_certificate`] turn an artifact
//!   reference into key material. Actions call them rather than reading
//!   artifact bytes themselves, so every step that names a key or a certificate
//!   accepts the same shapes and reports the same error.
//! - [`verify`] is the single seam between the action library and the software
//!   crypto provider. Anything that checks a signature without a device goes
//!   through here rather than calling `rite_openssl`, so swapping the provider
//!   is a change to this file and nothing else. It forwards to the provider, or
//!   fails if none was compiled in.
//!
//! Only verification has a seam here, because it needs only a public key. That
//! makes it the one cryptographic operation a ceremony can perform on evidence
//! it did not produce: a CSR that arrived from elsewhere, or a signature made
//! on a card that will never expose its key.

use std::collections::HashMap;
use std::hash::BuildHasher;

use rite_model::ArtifactId;
use rite_runtime::ArtifactValue;
use rite_sdk::{BackendError, CertificateDer, PublicKeyDer, SignAlgorithm};

/// Verify `signature` over `message` with a public key.
///
/// The key must match `algorithm`. Callers routinely take the algorithm from
/// the document under inspection, so a mismatch is refused rather than
/// reinterpreted.
///
/// Takes the same [`PublicKeyDer`] as
/// [`VerifyBackend::verify_public_key`](rite_sdk::VerifyBackend::verify_public_key),
/// so naming a backend on a verify step changes who runs the check and never
/// what is accepted.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] when the key and algorithm
/// disagree, or when the algorithm is missing from this build, and
/// [`BackendError::Other`] when the signature cannot be parsed.
///
/// A well-formed signature that simply does not match is `Ok(false)`, not an
/// error.
pub fn verify(
    key: &PublicKeyDer,
    message: &[u8],
    signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    #[cfg(feature = "openssl")]
    {
        rite_openssl::verify_signature(key.as_bytes(), message, signature, algorithm)
    }
    #[cfg(not(feature = "openssl"))]
    {
        let _ = (key, message, signature);
        Err(no_provider(&format!("verifying {algorithm}")))
    }
}

/// Resolve an artifact to the public key it carries.
///
/// The one way an action gets from an artifact reference to a key. Every step
/// that verifies a signature or wraps to a recipient names a key the same way,
/// so they resolve it the same way and report the same error when it is not
/// one.
///
/// Accepts a keypair the backend exports, an exported public key, a
/// certificate, and bytes loaded from a file. Bytes are interpreted by
/// [`PublicKeyDer::from_key_material`], which covers DER and PEM for both a
/// bare key and a certificate.
///
/// This needs no crypto provider, only ASN.1 structure, so it works in a build
/// with no `openssl` feature.
///
/// An artifact that already holds a key has one key to give, so `${signer}` and
/// `${signer.public}` mean the same thing here. Any other property is refused:
/// `${signer.private}` asks for something this function never returns, and
/// answering it with the public key would hide the mistake.
///
/// # Errors
///
/// Returns [`BackendError::InvalidKeyFormat`] when the artifact holds no key,
/// or holds bytes that are not one, [`BackendError::InvalidData`] when the
/// reference names a property other than `public`, and
/// [`BackendError::NotFound`] when the artifact does not exist.
pub fn resolve_public_key<S: BuildHasher>(
    artifacts: &HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
    property: Option<&str>,
) -> Result<PublicKeyDer, BackendError> {
    // Not `KeyNotFound`, which is classified retriable: a ceremony naming an
    // artifact that does not exist is a definition error, and no amount of
    // reinserting a token will produce it.
    let artifact = artifacts.get(artifact_id).ok_or_else(|| {
        BackendError::NotFound(format!("artifact '{artifact_id}' does not exist"))
    })?;

    if let Some(property) = property.filter(|p| *p != "public") {
        return Err(BackendError::InvalidData(format!(
            "'{artifact_id}.{property}' is not a public key"
        )));
    }

    match artifact {
        // Already a key, whether exported on its own or carried by a keypair.
        ArtifactValue::PublicKey(key)
        | ArtifactValue::BackendKey {
            public_key: Some(key),
            ..
        } => Ok(key.clone()),
        ArtifactValue::Certificate(certificate) => certificate.public_key(),
        ArtifactValue::BackendKey {
            public_key: None, ..
        } => Err(BackendError::InvalidKeyFormat(format!(
            "key '{artifact_id}' is held by a backend that does not export it, \
             so there is no public key to work from"
        ))),
        // Only the content says what these are. `Certificate` above is the
        // artifact shape; this covers a certificate that arrived as plain bytes.
        ArtifactValue::Bytes(bytes) => PublicKeyDer::from_key_material(bytes),
        ArtifactValue::Text(text) => PublicKeyDer::from_key_material(text.as_bytes()),
        ArtifactValue::WrappedKey { .. } => Err(BackendError::InvalidKeyFormat(format!(
            "artifact '{artifact_id}' is a wrapped key, not a public key"
        ))),
    }
}

/// Resolve an artifact to the certificate it carries.
///
/// The counterpart to [`resolve_public_key`], for steps that need the whole
/// certificate rather than the key inside it: an issuer's name and extensions
/// live in the certificate, not in its subject public key.
///
/// Accepts a certificate artifact and bytes loaded from a file, the latter
/// interpreted by [`CertificateDer::from_key_material`], which covers DER and
/// PEM. Deciding what an encoding is happens there and nowhere else.
///
/// # Errors
///
/// Returns [`BackendError::InvalidKeyFormat`] when the artifact is not a
/// certificate, [`BackendError::InvalidData`] when the reference names a
/// property, and [`BackendError::NotFound`] when the artifact does not exist.
pub fn resolve_certificate<S: BuildHasher>(
    artifacts: &HashMap<ArtifactId, ArtifactValue, S>,
    artifact_id: &ArtifactId,
    property: Option<&str>,
) -> Result<CertificateDer, BackendError> {
    let artifact = artifacts.get(artifact_id).ok_or_else(|| {
        BackendError::NotFound(format!("artifact '{artifact_id}' does not exist"))
    })?;

    // A certificate is whole; no property selects a part of one.
    if let Some(property) = property {
        return Err(BackendError::InvalidData(format!(
            "'{artifact_id}.{property}' is not a certificate"
        )));
    }

    match artifact {
        ArtifactValue::Certificate(certificate) => Ok(certificate.clone()),
        ArtifactValue::Bytes(bytes) => CertificateDer::from_key_material(bytes),
        ArtifactValue::Text(text) => CertificateDer::from_key_material(text.as_bytes()),
        ArtifactValue::BackendKey { .. }
        | ArtifactValue::PublicKey(_)
        | ArtifactValue::WrappedKey { .. } => Err(BackendError::InvalidKeyFormat(format!(
            "artifact '{artifact_id}' holds a key, not a certificate"
        ))),
    }
}

/// Error for a build with no software crypto provider compiled in.
#[cfg(not(feature = "openssl"))]
fn no_provider(operation: &str) -> BackendError {
    BackendError::UnsupportedAlgorithm(format!("{operation} requires the 'openssl' feature"))
}
