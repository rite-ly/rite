//! `YubiKey` backend for Rite ceremonies.
//!
//! Extends the standard PIV backend (`rite-piv`) with `Yubico`-specific
//! features: on-device attestation (slot F9), touch/PIN policy metadata, and
//! management key authentication.
//!
//! ## Capabilities
//!
//! - [`KeyStoreBackend`](rite_sdk::KeyStoreBackend): slot-based key generation
//! - [`SignBackend`](rite_sdk::SignBackend): on-card signing
//! - [`CertStoreBackend`](rite_sdk::CertStoreBackend): slot certificate storage
//! - [`PivBackend`](rite_sdk::PivBackend): slot management, PIN lifecycle
//! - [`YubikeyBackend`](rite_sdk::YubikeyBackend): attestation, touch policy, management key
//! - [`AttestationBackend`](rite_sdk::AttestationBackend): via `attest_slot`
//!
//! This crate is a pure backend: it depends only on `rite-sdk` and `rite-piv`.
//! The `yubikey_attest_slot` ceremony action that drives it lives in
//! `rite-stdlib`.
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod backend;

pub use backend::YubikeyDevice;
