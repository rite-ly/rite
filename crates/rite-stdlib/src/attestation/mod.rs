//! Attestation action handlers: a person's statement, and a device's
//! statement about one of its keys.

mod attest;
mod attest_key;

pub use attest::AttestAction;
pub use attest_key::AttestKeyAction;
