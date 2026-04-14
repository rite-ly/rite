//! Backend implementations for `rite-stdlib`.
//!
//! This module provides the `MockBackend` for testing and dry-run, and a
//! string-based `create_backend` factory that the executor calls to lazily
//! initialize backends.

mod mock;

pub use mock::MockBackend;

use rite_runtime::BackendFactory;
use rite_sdk::{BackendConfig, BackendError};

/// Create a backend by provider name and config.
///
/// Currently supports: `"mock"`.
/// Hardware-specific backends (`openssl`, `tpm`, `piv`) are provided by
/// separate crates.
pub fn create_backend(
    name: String,
    config: &BackendConfig,
) -> Result<Box<dyn rite_sdk::Backend>, BackendError> {
    match config.provider.as_str() {
        "mock" => {
            let seed = config
                .extra
                .get("seed")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Box::new(MockBackend::new(name, seed)))
        }
        other => Err(BackendError::Configuration(format!(
            "Unknown backend provider '{other}' (rite-stdlib supports: mock)"
        ))),
    }
}

/// Build the default `BackendFactory` for use with `BackendRegistry::with_factory`.
pub fn default_backend_factory() -> BackendFactory {
    Box::new(create_backend)
}
