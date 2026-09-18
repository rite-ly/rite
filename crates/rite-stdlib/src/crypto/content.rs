//! The seam between the action library and the software content cipher.
//!
//! Encrypting content is the one cryptographic operation in this file's
//! neighbourhood that no backend performs. A cloud KMS caps a direct encrypt at
//! a few kilobytes by design, a TPM takes a kilobyte per call, and a smart card
//! is slower still, so every one of them protects a content-encryption key and
//! leaves the content to the host. Rite does the same, and this is where.
//!
//! Actions call [`seal`] and [`open`] rather than `rite_openssl`, so swapping
//! the provider is a change to this file and nothing else.

use rite_sdk::BackendError;
use zeroize::Zeroizing;

/// Content and the values a container carries beside it.
///
/// Re-exported rather than named from the provider at each call site, so the
/// claim above holds: an action names this module and never `rite_openssl`.
pub use rite_openssl::SealedContent;

/// Encrypt `payload` under a content-encryption key, with a fresh nonce.
///
/// # Errors
///
/// Returns [`BackendError`] if the key is not one the cipher accepts.
pub fn seal(cek: &[u8], payload: &[u8]) -> Result<SealedContent, BackendError> {
    rite_openssl::seal_content(cek, payload)
}

/// Undo [`seal`].
///
/// # Errors
///
/// Returns [`BackendError`] if the tag does not authenticate the ciphertext,
/// which is also the answer a wrong key gets.
pub fn open(cek: &[u8], sealed: &SealedContent) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    rite_openssl::open_content(cek, sealed)
}
