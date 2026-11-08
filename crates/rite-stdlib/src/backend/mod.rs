//! Backend implementations for `rite-stdlib`.
//!
//! This module provides the `MockBackend` for testing and dry-run, and the
//! `create_backend` factory that the executor calls to lazily initialize
//! backends.

mod mock;

pub use mock::MockBackend;

use rite_runtime::BackendFactory;
use rite_sdk::{BackendConfig, BackendError, Provider};

/// Whether this build carries `provider`.
///
/// A provider the language knows may still be compiled out, as `piv` is
/// without its feature. A run asks before its first step, since creating
/// the backend happens only when a step first uses it.
#[must_use]
pub fn is_built(provider: Provider) -> bool {
    match provider {
        Provider::Mock => true,
        Provider::Openssl => cfg!(feature = "openssl"),
        Provider::Piv => cfg!(feature = "piv"),
        Provider::Yubikey => cfg!(feature = "yubikey"),
    }
}

/// Create a backend by provider and config.
///
/// A provider this build lacks is a configuration error naming the feature
/// to enable. [`is_built`] decides it, so the check before a run and this
/// refusal cannot disagree; the `cfg` on each arm only keeps a compiled-out
/// constructor out of the build.
pub fn create_backend(
    name: String,
    config: &BackendConfig,
) -> Result<Box<dyn rite_sdk::Backend>, BackendError> {
    if !is_built(config.provider) {
        return Err(not_built(config.provider));
    }
    match config.provider {
        Provider::Mock => {
            let seed = config
                .extra
                .get("seed")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(Box::new(MockBackend::new(name, seed)))
        }
        Provider::Openssl => {
            #[cfg(feature = "openssl")]
            {
                rite_openssl::OpenSslBackend::try_new(&name)
                    .map(|b| Box::new(b) as Box<dyn rite_sdk::Backend>)
            }
            #[cfg(not(feature = "openssl"))]
            {
                Err(not_built(Provider::Openssl))
            }
        }
        Provider::Piv => {
            #[cfg(feature = "piv")]
            {
                rite_piv::PivCardBackend::try_new(name, config)
                    .map(|b| Box::new(b) as Box<dyn rite_sdk::Backend>)
            }
            #[cfg(not(feature = "piv"))]
            {
                Err(not_built(Provider::Piv))
            }
        }
        Provider::Yubikey => {
            #[cfg(feature = "yubikey")]
            {
                rite_yubikey::YubikeyDevice::try_new(name, config)
                    .map(|b| Box::new(b) as Box<dyn rite_sdk::Backend>)
            }
            #[cfg(not(feature = "yubikey"))]
            {
                Err(not_built(Provider::Yubikey))
            }
        }
    }
}

/// The error for a provider this build was compiled without.
fn not_built(provider: Provider) -> BackendError {
    BackendError::Configuration(format!(
        "Backend '{provider}' requires the '{provider}' feature"
    ))
}

/// Build the default `BackendFactory` for use with `BackendRegistry::with_factory`.
pub fn default_backend_factory() -> BackendFactory {
    Box::new(create_backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever this build carries, `is_built` and the factory agree: a
    /// provider it says is missing is refused as missing, and one it says is
    /// built is never refused for its feature.
    #[test]
    fn is_built_and_the_factory_agree() {
        for &provider in Provider::ALL {
            let config = BackendConfig {
                provider,
                extra: serde_json::json!({}),
            };
            let missing = not_built(provider).to_string();
            let refused = create_backend("b".to_string(), &config)
                .err()
                .is_some_and(|e| e.to_string() == missing);
            assert_eq!(refused, !is_built(provider), "{provider}");
        }
    }
}
