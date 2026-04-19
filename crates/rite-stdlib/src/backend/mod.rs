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
/// Supports: `"mock"`, `"openssl"` (requires the `openssl` feature).
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
        "openssl" => {
            #[cfg(feature = "openssl")]
            {
                rite_openssl::OpenSslBackend::try_new(&name)
                    .map(|b| Box::new(b) as Box<dyn rite_sdk::Backend>)
            }
            #[cfg(not(feature = "openssl"))]
            {
                Err(BackendError::Configuration(
                    "Backend 'openssl' requires the 'openssl' feature".to_string(),
                ))
            }
        }
        other => Err(BackendError::Configuration(format!(
            "Unknown backend provider '{other}'"
        ))),
    }
}

/// Build the default `BackendFactory` for use with `BackendRegistry::with_factory`.
pub fn default_backend_factory() -> BackendFactory {
    Box::new(create_backend)
}
