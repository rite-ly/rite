//! Attestation action handlers: a person's statement, a device's statement
//! about one of its keys, and the check of a device's statement.

mod attest;
mod attest_key;
#[cfg(feature = "openssl")]
mod verify_attestation;

pub use attest::AttestAction;
pub use attest_key::AttestKeyAction;
#[cfg(feature = "openssl")]
pub use verify_attestation::VerifyAttestationAction;
