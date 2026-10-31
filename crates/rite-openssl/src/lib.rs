//! OpenSSL backend for Rite ceremonies.
//!
//! Provides [`OpenSslBackend`], a software cryptographic backend backed by OpenSSL.
//! Keys are held in memory for the lifetime of the backend instance.
//!
//! # Capabilities
//!
//! [`OpenSslBackend`] implements the following [`rite_sdk`] traits:
//!
//! - [`KeyStoreBackend`](rite_sdk::KeyStoreBackend): key generation and import
//! - [`SignBackend`](rite_sdk::SignBackend): signing
//! - [`VerifyBackend`](rite_sdk::VerifyBackend): signature verification
//! - [`KeyTransportBackend`](rite_sdk::KeyTransportBackend): key wrapping and unwrapping
//! - [`RandomBackend`](rite_sdk::RandomBackend): random byte generation
//!
//! [`verify_signature`] works without a backend instance, so it applies to keys
//! this crate never held (a PIV card's, say). [`seal_content`] and
//! [`open_content`] are free of a backend for a different reason: content
//! encryption is not an operation any key-protection device performs, so it
//! belongs beside the backends rather than inside one.
//!
//! # Feature flags
//!
//! - `vendored`: bundle OpenSSL at build time (no system library needed). Required for
//!   air-gapped USB image builds.
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod backend;
mod content;

pub use backend::{OpenSslBackend, data_key_for_recipient, verify_signature};
pub use content::{SealedContent, open_content, seal_content};

/// Whether this build can generate ML-KEM keys and wrap to them.
///
/// OpenSSL 3.5 has ML-KEM keys, but a KEM key exists to be wrapped to, and CMS
/// carries an ML-KEM recipient in a `KEMRecipientInfo` (RFC 9629), which
/// OpenSSL implements from 3.6. A build linked against 3.5 refuses both by
/// name, and still imports an ML-KEM key.
///
/// The bindings are selected when `rite-openssl` is compiled, not when it
/// runs, so this is a property of the build and cannot be recovered by
/// inspecting the runtime library version. Callers that can offer a useful
/// alternative (skipping a test, warning before a ceremony starts) should
/// branch on this rather than waiting for
/// [`BackendError::UnsupportedAlgorithm`](rite_sdk::BackendError) mid-run.
pub const ML_KEM_AVAILABLE: bool = cfg!(ossl360);

/// What about *this build* prevents generating keys of this algorithm.
///
/// The question belongs here rather than in a caller: which algorithms depend
/// on [`ML_KEM_AVAILABLE`] is a property of the bindings this crate compiles.
///
/// `None` covers both an algorithm this build can generate and one no build
/// can. Only a limitation of the binary doing the asking belongs here: a
/// caller reports it as a warning rather than a defect in the ceremony,
/// because another machine's build may run the same document.
#[must_use]
pub fn build_limitation(algorithm: rite_sdk::KeyAlgorithm) -> Option<&'static str> {
    use rite_sdk::KeyAlgorithm;
    if matches!(
        algorithm,
        KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024
    ) && !ML_KEM_AVAILABLE
    {
        return Some("needs a build linked against OpenSSL 3.6 or later, and this one is not");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::KeyAlgorithm;

    /// `rite check` reports this before a ceremony starts, so it has to name
    /// the OpenSSL version ML-KEM actually needs.
    #[test]
    fn names_the_openssl_version_ml_kem_needs() {
        let limitation = build_limitation(KeyAlgorithm::MlKem768);
        assert_eq!(limitation.is_none(), ML_KEM_AVAILABLE, "{limitation:?}");
        if let Some(reason) = limitation {
            assert!(reason.contains("OpenSSL 3.6"), "{reason}");
        }
        assert_eq!(build_limitation(KeyAlgorithm::MlDsa65), None);
        assert_eq!(build_limitation(KeyAlgorithm::Rsa2048), None);
    }
}
