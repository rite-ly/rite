//! Signature verification that needs no backend.
//!
//! The single seam between the action library and the software crypto
//! provider. Anything that verifies a signature without a device goes through
//! here rather than calling `rite_openssl` directly, so swapping the provider
//! is a change to this file and nothing else.
//!
//! Only verification lives here, because it needs only a public key. That makes
//! it the one cryptographic operation a ceremony can perform on evidence it did
//! not produce: a CSR that arrived from elsewhere, or a signature made on a card
//! that will never expose its key.
//!
//! Each function forwards to the provider, or fails if none was compiled in.

use rite_sdk::{BackendError, KeyAlgorithm, SignAlgorithm};

/// Verify `signature` over `message` with an SPKI DER public key.
///
/// The key must match `algorithm`. Callers routinely take the algorithm from
/// the document under inspection, so a mismatch is refused rather than
/// reinterpreted.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] when the key and algorithm
/// disagree, or when the algorithm is missing from this build, and
/// [`BackendError::Other`] when the key or signature cannot be parsed.
///
/// A well-formed signature that simply does not match is `Ok(false)`, not an
/// error.
pub fn verify(
    public_der: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    #[cfg(feature = "openssl")]
    {
        rite_openssl::verify_signature(public_der, message, signature, algorithm)
    }
    #[cfg(not(feature = "openssl"))]
    {
        let _ = (public_der, message, signature);
        Err(no_provider(&format!("verifying {algorithm}")))
    }
}

/// Read the key algorithm out of an SPKI DER public key.
///
/// Key bytes carry no ceremony metadata, so the algorithm has to come from the
/// key structure itself.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] for a key type Rite does not
/// handle, and [`BackendError::Other`] when the key cannot be parsed.
pub fn public_key_algorithm(public_der: &[u8]) -> Result<KeyAlgorithm, BackendError> {
    #[cfg(feature = "openssl")]
    {
        rite_openssl::public_key_algorithm(public_der)
    }
    #[cfg(not(feature = "openssl"))]
    {
        let _ = public_der;
        Err(no_provider("reading a public key"))
    }
}

/// Read the subject public key out of a DER certificate, as SPKI DER.
///
/// See [`rite_openssl::certificate_public_key`] for why a certificate is
/// accepted wherever a public key is.
///
/// # Errors
///
/// Returns [`BackendError::Other`] when the certificate cannot be parsed.
pub fn certificate_public_key(certificate_der: &[u8]) -> Result<Vec<u8>, BackendError> {
    #[cfg(feature = "openssl")]
    {
        rite_openssl::certificate_public_key(certificate_der)
    }
    #[cfg(not(feature = "openssl"))]
    {
        let _ = certificate_der;
        Err(no_provider("reading a certificate's public key"))
    }
}

/// Error for a build with no software crypto provider compiled in.
#[cfg(not(feature = "openssl"))]
fn no_provider(operation: &str) -> BackendError {
    BackendError::UnsupportedAlgorithm(format!("{operation} requires the 'openssl' feature"))
}
