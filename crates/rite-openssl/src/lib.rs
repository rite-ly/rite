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
//! - [`SignBackend`](rite_sdk::SignBackend): signing and verification
//! - [`KeyTransportBackend`](rite_sdk::KeyTransportBackend): key wrapping and unwrapping
//! - [`RandomBackend`](rite_sdk::RandomBackend): random byte generation
//!
//! # Feature flags
//!
//! - `vendored`: bundle OpenSSL at build time (no system library needed). Required for
//!   air-gapped USB image builds.

#![warn(missing_docs)]

mod backend;

pub use backend::OpenSslBackend;
