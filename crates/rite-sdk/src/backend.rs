//! Backend trait hierarchy for cryptographic hardware abstraction.
//!
//! ## Design philosophy
//!
//! Backends are **orthogonal to roles and participants**. They represent the
//! execution mechanism (how an action is implemented), not the human assignment
//! (who performs the action).
//!
//! The four layers of abstraction:
//! - **Step**: Unit of execution in the workflow
//! - **Role**: WHO performs the step (human/participant)
//! - **Action**: WHAT semantic operation happens
//! - **Backend**: HOW the action is implemented (software/hardware)
//!
//! ## Trait composition
//!
//! Backends implement only the traits they're capable of. There are no universal
//! requirements: traits are composable based on backend capabilities.
//!
//! Example trait support matrix:
//! - Software: `KeyStore + Sign + KeyTransport`
//! - `YubiKey` PIV: `KeyStore + Sign + Piv + Yubikey`
//! - PKCS#11 HSM: `KeyStore + Sign + KeyTransport + Pkcs11`
//! - Mock: All traits (for testing)

use std::collections::BTreeMap;

use crate::types::{
    Attestation, CertRef, KeyId, KeyMetadata, KeySecurityAttributes, KeySpec, PcrValue,
    PivDeviceInfo, PivSlot, PivSlotInfo, Pkcs11Mechanism, Pkcs11TokenInfo, SignAlgorithm, TpmInfo,
    WrapAlgorithm, WrappedKey, YubikeySlotMetadata,
};

/// Implement the `as_*_mut` upcasting helpers on a backend struct.
///
/// Each `Backend` implementor must return `Some(self)` for every trait it
/// supports and `None` for those it does not. Without this macro that is four
/// lines of boilerplate per capability. The macro expands to those lines
/// automatically and allows attaching per-capability doc comments.
///
/// # Usage
///
/// ```ignore
/// use rite_sdk::{Backend, KeyStoreBackend, SignBackend};
///
/// impl Backend for MyBackend {
///     fn name(&self) -> &str { &self.name }
///     fn provider(&self) -> &str { "software" }
///     fn fingerprint(&self) -> String { "...".to_string() }
///
///     backend_capabilities!(
///         /// Supports RSA-2048 through RSA-8192 key generation and storage.
///         as_keystore_mut: KeyStoreBackend,
///         as_sign_mut: SignBackend,
///     );
/// }
/// ```
///
/// Capabilities not listed here are not overridden, so they inherit the trait's
/// default doc ("Not supported by this backend.") and return `None`.
///
/// The trait names passed to the macro must be in scope at the call site.
///
/// Note: `#[macro_export]` places this macro at the crate root
/// (`rite_sdk::backend_capabilities!`), not in the `backend` module.
/// This is standard Rust macro scoping.
#[macro_export]
macro_rules! backend_capabilities {
    ($($(#[$attr:meta])* $method:ident : $trait:ident),* $(,)?) => {
        $(
            $(#[$attr])*
            fn $method(&mut self) -> Option<&mut dyn $trait> {
                Some(self)
            }
        )*
    };
}

/// Core trait that all backends must implement.
///
/// Provides identity and fingerprinting for audit trails.
///
/// # Capability downcasting
///
/// Rust does not allow downcasting from `dyn Backend` to `dyn KeyStoreBackend`
/// (or any other subtrait) without explicit support. The `as_*_mut` methods
/// implement this pattern manually: a backend returns `Some(self)` for each
/// capability it supports, and `None` for those it does not.
///
/// Use the [`backend_capabilities!`] macro to generate these methods without
/// boilerplate.
pub trait Backend: Send + Sync {
    /// Backend name (unique identifier within a ceremony).
    fn name(&self) -> &str;

    /// Backend provider name (e.g., "software", "yubikey", "pkcs11").
    fn provider(&self) -> &str;

    /// Fingerprint for audit evidence.
    ///
    /// Format examples:
    /// - Software: `"software-backend=mybackend"`
    /// - `YubiKey`: `"yubikey-serial=12345678+firmware=5.7.1"`
    /// - PKCS#11: `"pkcs11-module=/usr/lib/softhsm2.so+slot=0"`
    fn fingerprint(&self) -> String;

    /// Not supported by this backend, always returns `None`.
    fn as_keystore_mut(&mut self) -> Option<&mut dyn KeyStoreBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_sign_mut(&mut self) -> Option<&mut dyn SignBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_attest_mut(&mut self) -> Option<&mut dyn AttestationBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_piv_mut(&mut self) -> Option<&mut dyn PivBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_yubikey_mut(&mut self) -> Option<&mut dyn YubikeyBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_transport_mut(&mut self) -> Option<&mut dyn KeyTransportBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_certstore_mut(&mut self) -> Option<&mut dyn CertStoreBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_random_mut(&mut self) -> Option<&mut dyn RandomBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_pkcs11_mut(&mut self) -> Option<&mut dyn Pkcs11Backend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_pkcs11_admin_mut(&mut self) -> Option<&mut dyn Pkcs11AdminBackend> {
        None
    }

    /// Not supported by this backend, always returns `None`.
    fn as_tpm_mut(&mut self) -> Option<&mut dyn TpmBackend> {
        None
    }
}

/// Key generation and storage operations.
///
/// Backends implementing this trait can generate, import, and manage
/// cryptographic keys.
pub trait KeyStoreBackend: Backend {
    /// Generate a new key.
    ///
    /// The backend owns the key and returns metadata including an opaque
    /// `KeyId` reference. For hardware backends, the private key never leaves
    /// the device.
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError>;

    /// Import an existing private key.
    ///
    /// Only supported by backends that allow key import (software, some HSMs).
    /// Hardware security modules may reject key import for security reasons.
    ///
    /// `key_bytes` must be in PKCS#8 DER format.
    fn import_private_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError>;

    /// Export the public key for `key_id` in `SubjectPublicKeyInfo` (SPKI) DER format.
    fn export_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, BackendError>;

    /// List all keys managed by this backend.
    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError>;

    /// Delete a key permanently.
    fn delete_key(&mut self, key_id: &KeyId) -> Result<(), BackendError>;
}

/// Signing and verification operations.
pub trait SignBackend: Backend {
    /// Sign `message` with `key_id` using `algorithm`.
    ///
    /// Returns raw signature bytes (format depends on algorithm).
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError>;

    /// Verify `signature` over `message` with `key_id` and `algorithm`.
    fn verify(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError>;
}

/// Hardware attestation operations.
///
/// Backends that support attestation can cryptographically prove that a key
/// was generated on a specific hardware device.
pub trait AttestationBackend: Backend {
    /// Return a cryptographic proof that `key_id` was generated on this
    /// backend's hardware and has specific properties.
    fn attest_key(&self, key_id: &KeyId) -> Result<Attestation, BackendError>;
}

/// Certificate storage operations.
///
/// Backends implementing this trait can store, read, and delete X.509
/// certificates by reference. This is a unified interface for certificate
/// management across PIV (slot-based), PKCS#11 (label/ID-based), and
/// software backends.
pub trait CertStoreBackend: Backend {
    /// Store a DER-encoded X.509 certificate.
    fn store_cert(&mut self, cert_ref: &CertRef, cert_der: &[u8]) -> Result<(), BackendError>;

    /// Read a DER-encoded X.509 certificate.
    fn read_cert(&self, cert_ref: &CertRef) -> Result<Vec<u8>, BackendError>;

    /// Delete a certificate.
    fn delete_cert(&mut self, cert_ref: &CertRef) -> Result<(), BackendError>;
}

/// Hardware or software random number generation.
///
/// Backends implementing this trait can generate random bytes. For HSM
/// backends, this uses the device's internal RNG (e.g., PKCS#11 `C_GenerateRandom`).
pub trait RandomBackend: Backend {
    /// Generate `len` random bytes.
    fn generate_random(&mut self, len: usize) -> Result<Vec<u8>, BackendError>;
}

/// Key transport (wrapping) operations.
pub trait KeyTransportBackend: Backend {
    /// Wrap `key_id` using `wrapping_key_id` with `algorithm`.
    fn wrap(
        &mut self,
        key_id: &KeyId,
        wrapping_key_id: &KeyId,
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError>;

    /// Unwrap `wrapped` using `unwrapping_key_id`, importing the result with `label`.
    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
    ) -> Result<KeyMetadata, BackendError>;

    /// Wrap `key_id` to an external recipient's raw public key.
    ///
    /// Default implementation returns `UnsupportedOperation`.
    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient_pub_key: &[u8],
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        let _ = (key_id, recipient_pub_key, algorithm);
        Err(BackendError::UnsupportedOperation(
            "wrap_to_public not supported".to_string(),
        ))
    }
}

/// PKCS#11 token operations.
///
/// Provides access to PKCS#11-specific functionality: token info, key
/// security attributes, mechanism enumeration, and session login/logout.
pub trait Pkcs11Backend: Backend {
    /// Get token information (label, manufacturer, serial, flags).
    fn token_info(&self) -> Result<Pkcs11TokenInfo, BackendError>;

    /// Read security attributes for `key_id` (`CKA_ALWAYS_SENSITIVE`, etc.).
    fn key_security_attributes(
        &self,
        key_id: &KeyId,
    ) -> Result<KeySecurityAttributes, BackendError>;

    /// List mechanisms supported by this token.
    fn supported_mechanisms(&self) -> Result<Vec<Pkcs11Mechanism>, BackendError>;

    /// Log in to the token with a PIN.
    fn login(&mut self, pin: &[u8]) -> Result<(), BackendError>;

    /// Log out of the token.
    fn logout(&mut self) -> Result<(), BackendError>;
}

/// PKCS#11 Security Officer (SO) role operations.
///
/// These operations require SO authentication and are typically performed
/// only during initial token setup.
pub trait Pkcs11AdminBackend: Backend {
    /// Initialize a token (`C_InitToken`).
    fn init_token(&mut self, so_pin: &[u8], label: &str) -> Result<(), BackendError>;

    /// Initialize the user PIN (`C_InitPIN`). Requires SO session.
    fn init_user_pin(&mut self, so_pin: &[u8], user_pin: &[u8]) -> Result<(), BackendError>;
}

/// TPM 2.0 operations.
///
/// Provides TPM-specific functionality: device info, PCR operations, and
/// quote generation.
pub trait TpmBackend: Backend {
    /// Get TPM information (version, manufacturer, firmware).
    fn tpm_info(&mut self) -> Result<TpmInfo, BackendError>;

    /// Read PCR (Platform Configuration Register) values for the given PCR indices.
    ///
    /// Returns a `BTreeMap` keyed by PCR index for deterministic ordering in transcripts.
    fn read_pcrs(&mut self, pcrs: &[u8]) -> Result<BTreeMap<u8, PcrValue>, BackendError>;

    /// Extend a PCR register with new data.
    fn extend_pcr(&mut self, pcr: u8, data: &[u8]) -> Result<(), BackendError>;

    /// Generate a TPM quote (signed attestation over PCR values).
    fn generate_quote(&mut self, pcrs: &[u8], nonce: &[u8]) -> Result<Attestation, BackendError>;
}

/// Personal Identity Verification (PIV) smart card operations.
///
/// Models the PIV card application interface defined by FIPS 201-3 and
/// NIST SP 800-73-5. Methods in this trait correspond to PIV card commands
/// and data model operations; their semantics are defined by the standard
/// and should not diverge.
///
/// Backends implementing `PivBackend` should also implement the generic traits
/// (`KeyStoreBackend`, `SignBackend`) for interoperability with non-PIV-aware actions.
///
/// # Standard references
/// - FIPS 201-3: Personal Identity Verification of Federal Employees and Contractors
/// - NIST SP 800-73-5 Part 1: PIV Card Application Data Model
/// - NIST SP 800-73-5 Part 2: PIV Card Application Card Command Interface
/// - NIST SP 800-78-5: Cryptographic Algorithms and Key Sizes for PIV
pub trait PivBackend: Backend {
    /// List populated PIV slots with metadata.
    ///
    /// Enumerates key references defined in SP 800-73-5 Part 1, Table 4b.
    fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError>;

    /// Verify the PIV Card Application PIN.
    ///
    /// Required before private key operations on slots with PIN access rules.
    /// The PIN is typically 6–8 digits (ASCII-encoded).
    /// [SP 800-73-5 Part 2, §3.3: VERIFY command]
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), BackendError>;

    /// Change the PIV Card Application PIN.
    ///
    /// [SP 800-73-5 Part 2, §3.4: CHANGE REFERENCE DATA command]
    fn change_pin(&mut self, current: &[u8], new: &[u8]) -> Result<(), BackendError>;

    /// Get remaining PIN retry count before lockout.
    fn pin_retries(&mut self) -> Result<u32, BackendError>;

    /// Reset a blocked PIN using the PUK (PIN Unblocking Key).
    ///
    /// [SP 800-73-5 Part 2, §3.4: RESET RETRY COUNTER command]
    fn unblock_pin(&mut self, puk: &[u8], new_pin: &[u8]) -> Result<(), BackendError>;

    /// Return device identity (serial, firmware version, form factor).
    ///
    /// Not all fields are available on every PIV card. Serial number
    /// retrieval is vendor-specific (not standardized by NIST SP 800-73).
    fn device_info(&self) -> Result<PivDeviceInfo, BackendError>;
}

/// `YubiKey`-specific extensions to the PIV interface.
///
/// Operations in this trait are Yubico vendor extensions that go beyond
/// the NIST SP 800-73 standard. They are specific to `YubiKey` hardware
/// and will not work with generic PIV smart cards.
///
/// # Vendor references
/// - Yubico PIV documentation: <https://developers.yubico.com/PIV/>
/// - `YubiKey` attestation: key reference F9 (Yubico-proprietary)
/// - Touch/PIN policy configuration: Yubico-proprietary extensions
///   to the GENERATE ASYMMETRIC KEY PAIR command
pub trait YubikeyBackend: PivBackend {
    /// Generate an attestation certificate for a key in `slot`.
    ///
    /// Proves the key was generated on-device (not imported).
    /// Uses `YubiKey`'s attestation key (slot F9) to sign a certificate
    /// over the public key in the target slot.
    /// This is a Yubico extension, not available on generic PIV cards.
    fn attest_slot(&self, slot: PivSlot) -> Result<Vec<u8>, BackendError>;

    /// Authenticate with the management key (3DES or AES).
    ///
    /// Required before administrative operations: key generation,
    /// certificate import, PIN/PUK retry configuration.
    fn authenticate_management(&mut self, mgm_key: &[u8]) -> Result<(), BackendError>;

    /// Change the management key.
    fn change_management_key(&mut self, current: &[u8], new: &[u8]) -> Result<(), BackendError>;

    /// Get `YubiKey`-specific metadata for `slot`.
    ///
    /// Returns touch policy, PIN policy, and key origin: information
    /// not available through standard PIV commands.
    fn slot_metadata(&self, slot: PivSlot) -> Result<YubikeySlotMetadata, BackendError>;

    /// Block PUK permanently (prevents PIN unblock forever).
    ///
    /// High-security operation: once blocked, a forgotten PIN requires
    /// full device reset (destroying all keys). Irreversible.
    fn block_puk(&mut self) -> Result<(), BackendError>;
}

/// Backend-specific errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BackendError {
    /// Authentication required (not logged in).
    #[error("Authentication required")]
    AuthRequired,

    /// PIN required to access backend.
    #[error("PIN required")]
    PinRequired,

    /// PIN verification failed (wrong PIN). Contains remaining retries if known.
    #[error("PIN verification failed ({0} retries remaining)")]
    PinFailed(u32),

    /// PIN is blocked (too many failed attempts).
    #[error("PIN blocked")]
    PinBlocked,

    /// User PIN not initialized (PKCS#11: `C_InitPIN` not yet called).
    #[error("User PIN not initialized")]
    UserPinNotInitialized,

    /// Management key authentication required.
    #[error("Management key authentication required")]
    ManagementKeyRequired,

    /// Key not found in backend storage.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Object not found (PKCS#11: `find_objects` returned empty).
    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    /// PIV slot is empty (no key or certificate).
    #[error("Slot empty: {0}")]
    SlotEmpty(String),

    /// Backend storage capacity exceeded.
    #[error("Capacity exceeded")]
    CapacityExceeded,

    /// Operation not permitted (key usage flags don't allow this).
    #[error("Operation not permitted: {0}")]
    OperationNotPermitted(String),

    /// Attribute is read-only (e.g., tried to set `CKA_ALWAYS_SENSITIVE`).
    #[error("Attribute is read-only: {0}")]
    AttributeReadOnly(String),

    /// Algorithm not supported by this backend.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Operation not supported by this backend.
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    /// Token not present in slot.
    #[error("Token not present")]
    TokenNotPresent,

    /// Hardware failure (device disconnected, I/O error, etc.).
    #[error("Hardware failure: {0}")]
    HardwareFailure(String),

    /// Invalid key format or data.
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Invalid data (malformed input, unexpected encoding, etc.).
    #[error("Invalid data: {0}")]
    InvalidData(String),

    /// Backend not found in registry.
    #[error("Backend not found: {0}")]
    NotFound(String),

    /// Configuration error (missing or invalid settings).
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Generic backend error.
    #[error("Backend error: {0}")]
    Other(String),
}
