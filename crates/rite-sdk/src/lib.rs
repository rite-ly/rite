//! Rite SDK: backend abstractions for cryptographic ceremony execution.
//!
//! `rite-sdk` is the stable interface layer between the ceremony runtime and
//! backend implementations. It defines the trait hierarchy, data types, and
//! error taxonomy that all backends must implement.
//!
//! # Implementing a backend
//!
//! Implement [`Backend`] and any combination of capability traits matching
//! your hardware or software capabilities. Use the [`backend_capabilities!`]
//! macro to reduce boilerplate for the upcasting methods.
//!
//! # Trait composition
//!
//! Backends implement only the traits matching their capabilities:
//!
//! | Backend type      | Typical capabilities                          |
//! |-------------------|-----------------------------------------------|
//! | Software          | `KeyStore + Sign + KeyTransport`              |
//! | YubiKey PIV       | `KeyStore + Sign + Piv + Yubikey`             |
//! | PKCS#11 HSM       | `KeyStore + Sign + KeyTransport + Pkcs11`     |
//! | TPM 2.0           | `KeyStore + Sign + Tpm`                       |
//! | Mock (testing)    | All traits                                    |

#![warn(missing_docs)]

mod backend;
mod types;

pub use backend::{
    AttestationBackend, Backend, BackendError, CertStoreBackend, KeyStoreBackend,
    KeyTransportBackend, PivBackend, Pkcs11AdminBackend, Pkcs11Backend, RandomBackend, SignBackend,
    TpmBackend, YubikeyBackend,
};

pub use types::{
    Attestation, AttestationKind, BackendConfig, CertRef, DeviceInfo, KeyAlgorithm, KeyId,
    KeyMetadata, KeyPolicy, KeySecurityAttributes, KeySpec, KeyUsages, ParseError, PcrValue,
    PivDeviceInfo, PivKeyOrigin, PivPinPolicy, PivSlot, PivSlotInfo, PivTouchPolicy,
    Pkcs11Mechanism, Pkcs11TokenFlags, Pkcs11TokenInfo, SignAlgorithm, TpmInfo, WrapAlgorithm,
    WrappedKey, WrappedKeyFormat, YubikeySlotMetadata,
};
