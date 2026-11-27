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
use rite_sdk::cms::Recipient;
use rite_sdk::{KeyFingerprint, PublicKeyDer};

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
    /// Whether the output names its recipient, as a CMS container does and a
    /// raw scheme does not. Only then does the record hold the name.
    pub named: bool,
}

impl ExternalRecipient<'_> {
    /// Resolve the key, check it against the declared fingerprint, and record
    /// it.
    ///
    /// A certificate names the recipient as it names itself, by its subject
    /// key identifier, so the holder's tools find it. A key given alone, or as
    /// `${cert.public}`, is named as OpenSSL would name it in a certificate,
    /// by its RFC 5280 identifier. The record holds the name, and where it
    /// came from, beside the fingerprint.
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
    ) -> Result<Recipient, ActionError> {
        let name = self.key_ref.display_name();
        let cannot = |e: rite_sdk::BackendError| {
            ActionError::Failed(format!(
                "Cannot resolve recipient '{name}' as a public key: {e}"
            ))
        };
        // A certificate first, since it names the key as its holder's tools
        // look for it; `resolve_certificate` refuses a property, so
        // `${cert.public}` reads the key alone.
        let id = self.key_ref.artifact_id();
        let recipient = match crate::signatures::resolve_certificate(
            ctx.artifacts,
            &id,
            self.key_ref.property(),
        ) {
            Ok(certificate) => Recipient::certified(&certificate),
            Err(_) => {
                crate::signatures::resolve_public_key(ctx.artifacts, &id, self.key_ref.property())
                    .and_then(Recipient::key)
            }
        }
        .map_err(cannot)?;

        let fingerprint = recipient.public_key().fingerprint();
        if let Some(declared) = self.expected
            && declared != fingerprint
        {
            return Err(ActionError::Failed(format!(
                "Recipient '{name}' is {fingerprint}, but the ceremony declares {declared}. {}",
                self.consequence
            )));
        }
        admits(recipient.public_key())?;

        reporter.fact(StepFact::WrapRecipientRecorded {
            step: step.id.clone(),
            source: name,
            fingerprint,
            declared: self.expected.is_some(),
            named_by: self.named.then(|| recipient.name().clone()),
        })?;
        Ok(recipient)
    }
}
