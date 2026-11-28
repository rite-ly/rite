//! Backend implementations for `rite-stdlib`.
//!
//! This module provides the `MockBackend` for testing and dry-run, and the
//! `create_backend` factory that the executor calls to lazily initialize
//! backends.

mod mock;
#[cfg(feature = "pki")]
mod mock_attestation;

pub use mock::MockBackend;
#[cfg(feature = "pki")]
pub use mock_attestation::MOCK_ATTESTATION_ROOT;

use std::collections::BTreeMap;

use rite_runtime::{ActionError, BackendFactory};
use rite_sdk::{
    Backend, BackendConfig, BackendError, CertificateDer, KeyAlgorithm, KeyId, KeyTransportBackend,
    Provider,
};
#[cfg(feature = "crypto")]
use rite_sdk::{KeyAgreementBackend, KeyDecryptBackend};

/// The roots the mock attests under. A dry run, which puts the mock in place
/// of every backend, hands them to its steps as rehearsal anchors. Their
/// private keys are in this repository, so anyone can chain to them.
#[must_use]
pub fn rehearsal_anchors() -> Vec<CertificateDer> {
    #[cfg(feature = "pki")]
    {
        // A committed fixture; a test pins that it parses.
        CertificateDer::new(MOCK_ATTESTATION_ROOT.to_vec())
            .into_iter()
            .collect()
    }
    // Without `pki` the mock attests nothing.
    #[cfg(not(feature = "pki"))]
    {
        Vec::new()
    }
}

/// Refuse a step that runs on `backend` with a key `key_owner` holds.
///
/// Shared by every action that hands a key to its backend, so an operator who
/// points a step at the wrong backend gets the same message from each.
#[cfg_attr(
    not(any(feature = "crypto", feature = "attestation", feature = "pki")),
    allow(dead_code)
)]
pub(crate) fn require_key_owner(
    backend: &dyn rite_sdk::Backend,
    key_owner: &str,
    key_name: &str,
) -> Result<(), rite_runtime::ActionError> {
    let backend_name = backend.name();
    if key_owner == backend_name {
        Ok(())
    } else {
        Err(rite_runtime::ActionError::Failed(format!(
            "Key '{key_name}' is owned by backend '{key_owner}', but this step runs on \
             '{backend_name}'"
        )))
    }
}

/// The backend a step names, as the capability the step needs, once it is known
/// to be the backend that holds the key.
///
/// Every key operation asks the same two questions first: is there a backend at
/// all, and is it the one holding the key this step was given. The second is a
/// trust boundary, not a convenience, since a step that ran a key operation on
/// a device that does not hold the key would record a device that did no work.
///
/// `operation` completes the sentence "Backend 'x' <operation>", so a refusal
/// names what this step wanted rather than the trait it failed to reach.
///
/// # Errors
///
/// Returns [`ActionError::Failed`] if no backend was named, if the one named is
/// not the one holding the key, or if it does not transport keys.
pub(crate) fn transport_backend<'a>(
    backend: Option<&'a mut dyn Backend>,
    key_backend: &str,
    operation: &str,
) -> Result<(&'a mut dyn KeyTransportBackend, String), ActionError> {
    let (backend, name) = holding_backend(backend, key_backend, operation)?;
    let transport = backend
        .as_transport_mut()
        .ok_or_else(|| ActionError::Failed(format!("Backend '{name}' cannot {operation}")))?;
    Ok((transport, name))
}

/// [`transport_backend`] for a step that needs the backend to agree a key.
///
/// # Errors
///
/// As [`transport_backend`], and the same "Backend '<name>' cannot <operation>"
/// when the backend does not agree keys. Announces a key that asks for a
/// touch, as [`announce_presence`] says.
#[cfg(feature = "crypto")]
pub(crate) fn agreement_backend<'a>(
    backend: Option<&'a mut dyn Backend>,
    key_backend: &str,
    key_id: &KeyId,
    operation: &str,
    reporter: &mut rite_runtime::Reporter<'_>,
) -> Result<&'a mut dyn KeyAgreementBackend, ActionError> {
    let (backend, name) = holding_backend(backend, key_backend, operation)?;
    let agreement = backend
        .as_agreement_mut()
        .ok_or_else(|| ActionError::Failed(format!("Backend '{name}' cannot {operation}")))?;
    announce_presence(agreement, key_id, reporter)?;
    Ok(agreement)
}

/// [`transport_backend`] for a step that needs the backend to decrypt a key
/// encrypted to a public key it holds.
///
/// # Errors
///
/// As [`transport_backend`], and the same "Backend '<name>' cannot <operation>"
/// when the backend does not decrypt keys. Announces a key that asks for a
/// touch, as [`announce_presence`] says.
#[cfg(feature = "crypto")]
pub(crate) fn key_decrypt_backend<'a>(
    backend: Option<&'a mut dyn Backend>,
    key_backend: &str,
    key_id: &KeyId,
    operation: &str,
    reporter: &mut rite_runtime::Reporter<'_>,
) -> Result<&'a mut dyn KeyDecryptBackend, ActionError> {
    let (backend, name) = holding_backend(backend, key_backend, operation)?;
    let decrypt = backend
        .as_key_decrypt_mut()
        .ok_or_else(|| ActionError::Failed(format!("Backend '{name}' cannot {operation}")))?;
    announce_presence(decrypt, key_id, reporter)?;
    Ok(decrypt)
}

/// The two questions every key operation asks first, and the backend's name.
fn holding_backend<'a>(
    backend: Option<&'a mut dyn Backend>,
    key_backend: &str,
    operation: &str,
) -> Result<(&'a mut dyn Backend, String), ActionError> {
    let backend =
        backend.ok_or_else(|| ActionError::Failed(format!("Backend required to {operation}")))?;
    let name = backend.name().to_string();
    if name != key_backend {
        return Err(ActionError::Failed(format!(
            "Key owned by backend '{key_backend}', but current backend is '{name}'"
        )));
    }
    Ok((backend, name))
}

/// Tell the operator to touch the device if the key `key_id` names asks
/// for a person at it.
///
/// Called right before the operation: once the device waits for a touch,
/// the step blocks until one comes or the device gives up, and nothing else
/// tells the operator why. A backend that reports no policy, or fails to
/// read it, gets no notice; the operation reports what the device does.
///
/// Called by the accessors that hand an action a private-key operation
/// ([`sign_backend`], `agreement_backend`, `key_decrypt_backend`), once the
/// backend is known to offer it, so an action cannot forget it. Not by
/// [`transport_backend`]: a symmetric key on a device has no touch policy.
#[cfg_attr(not(any(feature = "crypto", feature = "pki")), allow(dead_code))]
pub(crate) fn announce_presence(
    backend: &mut dyn rite_sdk::Backend,
    key_id: &KeyId,
    reporter: &mut rite_runtime::Reporter<'_>,
) -> Result<(), rite_runtime::ActionError> {
    let presence = backend
        .as_keystore_mut()
        .and_then(|keystore| keystore.access_policy(key_id).ok().flatten())
        .filter(rite_sdk::AccessPolicy::asks_for_presence)
        .and_then(|policy| policy.presence);
    if let Some(when) = presence {
        reporter.log(
            rite_runtime::Icon::Warning,
            format!(
                "Touch the device of backend '{}' if it blinks (presence: {when})",
                backend.name()
            ),
        )?;
    }
    Ok(())
}

/// The signing capability of `backend` for `key`, which `key_name` names
/// in messages, once the backend is shown to own it. Announces a key that
/// asks for a touch, as [`announce_presence`] says.
///
/// Shared by every signing action, so each gives the same messages.
#[cfg_attr(not(any(feature = "crypto", feature = "pki")), allow(dead_code))]
pub(crate) fn sign_backend<'a>(
    backend: &'a mut dyn rite_sdk::Backend,
    key: &rite_runtime::BackendKeyMeta<'_>,
    key_name: &str,
    reporter: &mut rite_runtime::Reporter<'_>,
) -> Result<&'a mut dyn rite_sdk::SignBackend, rite_runtime::ActionError> {
    require_key_owner(backend, key.backend_name, key_name)?;
    let backend_name = backend.name().to_string();
    let signer = backend.as_sign_mut().ok_or_else(|| {
        rite_runtime::ActionError::Failed(format!(
            "Backend '{backend_name}' does not support signing"
        ))
    })?;
    announce_presence(signer, key.key_id, reporter)?;
    Ok(signer)
}

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

/// The keys a mock backend's config says it holds: `held_keys`, a map from
/// the id each answers to to its algorithm, `{"piv:9d": "ECDSA-P384"}`.
///
/// `rite run` writes it for every mock backend from the ceremony's
/// `backend_key` materials, so a rehearsal holds the keys a device would.
fn mock_held_keys(config: &BackendConfig) -> Result<Vec<(KeyId, KeyAlgorithm)>, BackendError> {
    let Some(held) = config.extra.get("held_keys") else {
        return Ok(Vec::new());
    };
    let held: BTreeMap<String, KeyAlgorithm> =
        serde_json::from_value(held.clone()).map_err(|e| {
            BackendError::Configuration(format!(
                "a mock's 'held_keys' is a map from id to algorithm: {e}"
            ))
        })?;
    Ok(held
        .into_iter()
        .map(|(key_id, algorithm)| (KeyId::new(key_id), algorithm))
        .collect())
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
            let held = mock_held_keys(config)?;
            Ok(Box::new(
                MockBackend::new(name, seed).with_held_keys(&held)?,
            ))
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

    /// What [`announce_presence`] logs for a mock key generated with
    /// `presence`.
    fn presence_notice(presence: Option<rite_sdk::AccessWhen>) -> Vec<String> {
        let mut mock = MockBackend::new("token".to_string(), "seed".to_string());
        let spec = rite_sdk::KeySpec {
            algorithm: KeyAlgorithm::EcdsaP256,
            label: "signer".to_string(),
            policy: rite_sdk::KeyPolicy {
                access: rite_sdk::AccessPolicy {
                    authentication: None,
                    presence,
                },
                ..rite_sdk::KeyPolicy::default_for(KeyAlgorithm::EcdsaP256)
            },
            location_hint: Some("9c".to_string()),
        };
        let keystore = rite_sdk::Backend::as_keystore_mut(&mut mock).unwrap();
        let key_id = keystore.generate_key(spec).unwrap().key_id;
        let mut harness = rite_runtime::test_support::ReporterHarness::new();
        let mut reporter = harness.reporter(rite_model::StepId::new("sign"));
        announce_presence(&mut mock, &key_id, &mut reporter).unwrap();
        drop(reporter);
        harness.logged()
    }

    /// A key that asks for a touch tells the operator before the device
    /// waits; one that does not says nothing.
    #[test]
    fn a_key_that_asks_for_a_touch_is_announced() {
        let notice = presence_notice(Some(rite_sdk::AccessWhen::Cached));
        assert_eq!(
            notice,
            ["Touch the device of backend 'token' if it blinks (presence: cached)"]
        );
        assert_eq!(
            presence_notice(Some(rite_sdk::AccessWhen::PerUse)),
            ["Touch the device of backend 'token' if it blinks (presence: per_use)"]
        );
        assert!(presence_notice(Some(rite_sdk::AccessWhen::Never)).is_empty());
        assert!(presence_notice(None).is_empty());
    }

    /// The committed root parses, so a dry run never loses its anchor.
    #[cfg(feature = "pki")]
    #[test]
    fn the_mock_root_is_a_rehearsal_anchor() {
        assert_eq!(
            rehearsal_anchors()
                .iter()
                .map(CertificateDer::as_bytes)
                .collect::<Vec<_>>(),
            [MOCK_ATTESTATION_ROOT]
        );
    }
}
