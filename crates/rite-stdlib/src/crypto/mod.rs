//! Cryptographic action handlers.

mod content;
mod decrypt_data;
mod encrypt_data;
mod export_public;
mod generate_key;
mod import_key;
mod sign_data;
mod unwrap_key;
mod verify_signature;
mod wrap_key;

pub use decrypt_data::DecryptDataAction;
pub use encrypt_data::EncryptDataAction;
pub use export_public::ExportPublicAction;
pub use generate_key::GenerateKeyAction;
pub use import_key::ImportKeyAction;
pub use sign_data::SignDataAction;
pub use unwrap_key::UnwrapKeyAction;
pub use verify_signature::VerifySignatureAction;
pub use wrap_key::WrapKeyAction;

use rite_runtime::ActionError;
use rite_sdk::{Backend, KeyTransportBackend};

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
    let backend =
        backend.ok_or_else(|| ActionError::Failed(format!("Backend required to {operation}")))?;
    let name = backend.name().to_string();
    if name != key_backend {
        return Err(ActionError::Failed(format!(
            "Key owned by backend '{key_backend}', but current backend is '{name}'"
        )));
    }
    let transport = backend
        .as_transport_mut()
        .ok_or_else(|| ActionError::Failed(format!("Backend '{name}' cannot {operation}")))?;
    Ok((transport, name))
}
