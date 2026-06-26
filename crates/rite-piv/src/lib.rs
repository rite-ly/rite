//! PIV smart card backend for Rite ceremonies.
//!
//! Provides a backend implementation for generic PIV (Personal Identity
//! Verification) smart cards per FIPS 201-3 and NIST SP 800-73-5.
//!
//! Communication uses the `yubikey` Rust crate over PC/SC. Despite its name,
//! the crate implements the standard PIV command set, so [`PivCardBackend`]
//! works with any compliant PIV card. Yubico vendor extensions (attestation,
//! touch policy, management key) live in the separate `rite-yubikey` crate.
//!
//! ## Capabilities
//!
//! - [`KeyStoreBackend`](rite_sdk::KeyStoreBackend): slot-based key generation
//! - [`SignBackend`](rite_sdk::SignBackend): on-card signing
//! - [`CertStoreBackend`](rite_sdk::CertStoreBackend): slot certificate storage
//! - [`PivBackend`](rite_sdk::PivBackend): slot management, PIN lifecycle
//!
//! Standard PIV has no attestation, so `AttestationBackend` is not implemented
//! here (see `rite-yubikey`).
//!
//! This crate is a pure backend: it depends only on `rite-sdk` and the vendor
//! `yubikey` crate. The ceremony actions that drive it (`piv_read_certificate`,
//! `piv_sign`) live in `rite-stdlib`, which calls [`ops::slot_from_hint`] to
//! parse slot identifiers from ceremony YAML.
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod backend;
pub mod convert;
pub mod ops;

pub use backend::PivCardBackend;
