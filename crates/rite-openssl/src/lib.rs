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
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod backend;

pub use backend::{OpenSslBackend, verify_ml_dsa_signature};

/// Whether this build can perform ML-DSA operations.
///
/// ML-DSA arrived in OpenSSL 3.5, and the bindings for it are selected when
/// `rite-openssl` is compiled, not when it runs. A binary linked against an
/// older OpenSSL contains no ML-DSA code at all, so this is a property of the
/// build and cannot be recovered by inspecting the runtime library version.
///
/// Callers that can offer a useful alternative (skipping a test, warning before
/// a ceremony starts) should branch on this rather than waiting for
/// [`BackendError::UnsupportedAlgorithm`](rite_sdk::BackendError) mid-run.
pub const ML_DSA_AVAILABLE: bool = cfg!(ossl350);
