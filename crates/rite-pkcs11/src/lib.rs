//! PKCS#11 backend for Rite ceremonies.
//!
//! # Scope
//!
//! Read-only. This milestone opens a session against a vendor module and
//! reports what the token is, what mechanisms it offers, and what a key it
//! holds is permitted to do. It generates nothing and signs nothing yet.
//!
//! The reason to build it in this order is that the wrapping model rests on
//! claims about PKCS#11 that nothing in this workspace could test: that
//! `C_WrapKey` refuses a non-extractable key, that its output is raw mechanism
//! bytes rather than a CMS structure, and that `CKA_WRAP` gates wrapping. The
//! tests under `tests/` answer those against a real token, so the claims
//! become measurements before the transcript format freezes around them.
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod backend;

pub use backend::{Pkcs11Config, Pkcs11TokenBackend};
