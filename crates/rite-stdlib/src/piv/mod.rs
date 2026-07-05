//! PIV smart-card and `YubiKey` ceremony actions.
//!
//! These actions are backend-agnostic: they drive any backend that implements
//! the relevant `rite-sdk` capability traits (`CertStoreBackend`, `SignBackend`,
//! `PivBackend`, `YubikeyBackend`). Slot-hint parsing is shared from `rite-piv`.

mod params;
mod read_certificate;
mod sign;

pub use read_certificate::PivReadCertificateAction;
pub use sign::PivSignAction;

#[cfg(feature = "yubikey")]
mod attest;
#[cfg(feature = "yubikey")]
pub use attest::YubikeyAttestSlotAction;
