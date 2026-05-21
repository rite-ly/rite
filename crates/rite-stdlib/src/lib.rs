//! Standard action library for Rite ceremonies.
//!
//! This crate provides the built-in action implementations:
//!
//! - **Verification**: `clock_check`, `confirm`, `check_value`, `oral_readback`, `machine_info`
//! - **Attestation**: `attest`
//! - **Crypto**: `generate_keypair`, `export_public`, `wrap_key`, `unwrap_key`
//! - **PKI**: `generate_csr`, `issue_certificate`
//!
//! # Backend integration
//!
//! All crypto and PKI actions require a backend; there are no software
//! fallbacks. For dry-run mode, configure a `MockBackend` in your
//! ceremony YAML.
//!
//! # Features
//!
//! - `verification`: verification actions (requires `subtle`, `sysinfo`)
//! - `attestation`: attestation recording
//! - `crypto`: crypto actions (`generate_keypair`, `export_public`, `wrap_key`, `unwrap_key`)
//! - `pki`: PKI actions (`generate_csr`, `issue_certificate`; requires `x509-cert`, `der`, `sha1`, `rsa`, `p256`, `rand`)
//! - `default`: all features enabled
//!
//! # Usage
//!
//! ```ignore
//! use rite_stdlib::default_registry;
//!
//! let registry = default_registry();
//! ```

#![warn(missing_docs)]

pub mod backend;
mod params;

#[cfg(feature = "attestation")]
pub mod attestation;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "pki")]
pub mod pki;
#[cfg(feature = "verification")]
pub mod verification;

use std::sync::Arc;

use rite_runtime::{ActionRegistry, BackendFactory};

pub use backend::{MockBackend, create_backend, default_backend_factory};

#[cfg(feature = "attestation")]
pub use attestation::AttestAction;
#[cfg(feature = "crypto")]
pub use crypto::{ExportPublicAction, GenerateKeypairAction, UnwrapKeyAction, WrapKeyAction};
#[cfg(feature = "pki")]
pub use pki::{GenerateCsrAction, IssueCertificateAction};
#[cfg(feature = "verification")]
pub use verification::{
    CheckValueAction, ClockCheckAction, ConfirmAction, MachineInfoAction, OralReadbackAction,
};

/// Create a new action registry with all standard-library actions registered.
#[must_use]
pub fn default_registry() -> ActionRegistry {
    let mut registry = ActionRegistry::new();
    register_stdlib(&mut registry);
    registry
}

/// Register all standard-library actions into an existing registry.
#[allow(unused_variables)]
pub fn register_stdlib(registry: &mut ActionRegistry) {
    #[cfg(feature = "verification")]
    {
        registry.register(Arc::new(ClockCheckAction));
        registry.register(Arc::new(ConfirmAction));
        registry.register(Arc::new(CheckValueAction));
        registry.register(Arc::new(OralReadbackAction));
        registry.register(Arc::new(MachineInfoAction));
    }

    #[cfg(feature = "attestation")]
    {
        registry.register(Arc::new(AttestAction));
    }

    #[cfg(feature = "crypto")]
    {
        registry.register(Arc::new(GenerateKeypairAction));
        registry.register(Arc::new(ExportPublicAction));
        registry.register(Arc::new(WrapKeyAction));
        registry.register(Arc::new(UnwrapKeyAction));
    }

    #[cfg(feature = "pki")]
    {
        registry.register(Arc::new(GenerateCsrAction));
        registry.register(Arc::new(IssueCertificateAction));
    }
}

/// Build the default [`BackendFactory`] closure.
///
/// Wraps [`default_backend_factory`] for convenience.
#[must_use]
pub fn stdlib_backend_factory() -> BackendFactory {
    default_backend_factory()
}
