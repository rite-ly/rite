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

use rite_model::{ArtifactRef, StepFact};
use rite_runtime::{ActionError, HandlerContext, Reporter, StepInfo};
use rite_sdk::{Backend, KeyFingerprint, KeyTransportBackend, PublicKeyDer};

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

/// The fingerprint an `expect_recipient` parameter declares.
///
/// The parameter stays text in the step's parameters, where the ceremony
/// schema checks its form and says what is wrong with it. This is where it
/// becomes a fingerprint, so a malformed value that reached the handler some
/// other way is refused rather than compared as text.
pub(crate) fn declared_fingerprint(
    value: Option<&str>,
) -> Result<Option<KeyFingerprint>, ActionError> {
    value
        .map(|text| {
            text.parse().map_err(|_| {
                ActionError::Failed(format!(
                    "expect_recipient '{text}' is not a fingerprint of the form \
                     'sha256:<64 lowercase hex digits>'"
                ))
            })
        })
        .transpose()
}

/// A public key held outside the ceremony that a step addresses its output to.
pub(crate) struct ExternalRecipient<'a> {
    /// The input naming the key.
    pub key_ref: &'a ArtifactRef,
    /// The fingerprint the ceremony declared for it, if any.
    pub expected: Option<KeyFingerprint>,
    /// What addressing the wrong key would do, completing the sentence "...,
    /// but the ceremony declares X." in the refusal.
    pub consequence: &'a str,
}

impl ExternalRecipient<'_> {
    /// Resolve the key, check it against the declared fingerprint, and record
    /// it.
    ///
    /// `admits` is the step's own check that it can address this key at all,
    /// run before the fact. A recipient the step was going to refuse is never
    /// recorded as having received anything. The fact is recorded before the
    /// operation itself, so an aborted run still says which key was presented.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Failed`] if the input is not a public key, if it
    /// is not the declared one, or if `admits` refuses it.
    pub fn resolve(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        reporter: &mut Reporter<'_>,
        admits: impl FnOnce(&PublicKeyDer) -> Result<(), ActionError>,
    ) -> Result<PublicKeyDer, ActionError> {
        let name = self.key_ref.display_name();
        let recipient = crate::signatures::resolve_public_key(
            ctx.artifacts,
            &self.key_ref.artifact_id(),
            self.key_ref.property(),
        )
        .map_err(|e| {
            ActionError::Failed(format!(
                "Cannot resolve recipient '{name}' as a public key: {e}"
            ))
        })?;

        let fingerprint = recipient.fingerprint();
        if let Some(declared) = self.expected
            && declared != fingerprint
        {
            return Err(ActionError::Failed(format!(
                "Recipient '{name}' is {fingerprint}, but the ceremony declares {declared}. {}",
                self.consequence
            )));
        }
        admits(&recipient)?;

        reporter.fact(StepFact::WrapRecipientRecorded {
            step: step.id.clone(),
            source: name,
            fingerprint,
            declared: self.expected.is_some(),
        })?;
        Ok(recipient)
    }
}
