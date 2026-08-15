//! Signature verification that needs no backend.
//!
//! The single seam between the action library and the software crypto
//! provider. Everything here could be satisfied by a different provider, so
//! everything that verifies a signature without a device goes through this
//! module rather than calling `rite_openssl` directly. A provider swap should
//! be a change to this file and nothing else.
//!
//! Verification is separated from signing because it needs only a public key.
//! That makes it the one cryptographic operation a ceremony can perform on
//! evidence it did not produce: a CSR that arrived from elsewhere, or a
//! signature made on a smart card that will never expose its key.

use rite_sdk::{BackendError, KeyAlgorithm, SignAlgorithm};

/// Verify `signature` over `message` with an SPKI DER public key.
///
/// The key must match `algorithm`. Callers routinely take the algorithm from
/// the document under inspection, so this is refused rather than reinterpreted.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] when the key and algorithm
/// disagree, or when this build has no implementation of the algorithm, and
/// [`BackendError::Other`] when the key or signature cannot be parsed.
///
/// A well-formed signature that simply does not match is `Ok(false)`, not an
/// error.
#[cfg(feature = "openssl")]
pub fn verify(
    public_der: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    rite_openssl::verify_signature(public_der, message, signature, algorithm)
}

/// Verify `signature` over `message` with an SPKI DER public key.
///
/// # Errors
///
/// Always fails: this build has no crypto provider compiled in.
#[cfg(not(feature = "openssl"))]
pub fn verify(
    _public_der: &[u8],
    _message: &[u8],
    _signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    Err(BackendError::UnsupportedAlgorithm(format!(
        "verifying {algorithm} requires the 'openssl' feature"
    )))
}

/// Read the key algorithm out of an SPKI DER public key.
///
/// A public key that arrives as bytes carries no ceremony metadata, so the
/// algorithm has to be recovered from the structure itself before anything can
/// be verified under it.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] for a key of a type Rite does
/// not handle, and [`BackendError::Other`] when the key cannot be parsed.
#[cfg(feature = "openssl")]
pub fn public_key_algorithm(public_der: &[u8]) -> Result<KeyAlgorithm, BackendError> {
    rite_openssl::public_key_algorithm(public_der)
}

/// Read the key algorithm out of an SPKI DER public key.
///
/// # Errors
///
/// Always fails: this build has no crypto provider compiled in.
#[cfg(not(feature = "openssl"))]
pub fn public_key_algorithm(_public_der: &[u8]) -> Result<KeyAlgorithm, BackendError> {
    Err(BackendError::UnsupportedAlgorithm(
        "reading a public key requires the 'openssl' feature".to_string(),
    ))
}

/// Read the subject public key out of a DER certificate, as SPKI DER.
///
/// A signer's public key usually reaches a ceremony wrapped in a certificate
/// rather than on its own, which is what `piv_read_certificate` produces and
/// what a counterparty sends.
///
/// # Errors
///
/// Returns [`BackendError::Other`] when the certificate cannot be parsed.
#[cfg(feature = "openssl")]
pub fn certificate_public_key(certificate_der: &[u8]) -> Result<Vec<u8>, BackendError> {
    rite_openssl::certificate_public_key(certificate_der)
}

/// Read the subject public key out of a DER certificate, as SPKI DER.
///
/// # Errors
///
/// Always fails: this build has no crypto provider compiled in.
#[cfg(not(feature = "openssl"))]
pub fn certificate_public_key(_certificate_der: &[u8]) -> Result<Vec<u8>, BackendError> {
    Err(BackendError::UnsupportedAlgorithm(
        "reading a certificate's public key requires the 'openssl' feature".to_string(),
    ))
}
