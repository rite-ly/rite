//! `combine_shares` action, the secret back from shares `split_secret` made.

use rite_model::{ActionType, SharingScheme};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, StepInfo, StepResult,
};
use rite_sdk::Backend;
use secrecy::SecretBox;
use serde_json::json;

use super::gf256::{self, Share};
use super::{ShareOrBytes, wire};

/// Reconstruct a secret from at least a threshold of its shares.
///
/// The shares arrive as `reads: { shares: [...] }`, in whatever order the
/// ceremony lists them. Each is a share of a set an earlier step made, a
/// share a custodian typed back, or bytes in the share layout: what
/// `decrypt_data` returns from a share sealed to a holder, or a share file
/// opened outside Rite. The index that matters is the one inside
/// the share, which is what the sheet in the bag carries. Each share
/// records how many are needed, so too few is an error before anything is
/// computed, and shares that disagree on the threshold or the secret's
/// length are rejected. Shares from a different split of the same shape
/// cannot be told apart: the arithmetic succeeds and produces a different
/// secret, which is why a recovery ends by checking what came back against
/// something observable.
///
/// Takes no `with:`, and no `scheme:` in particular: the shares carry it,
/// and a step that could restate it could restate it wrongly. Shares made
/// under different schemes are refused.
///
/// The result stays in memory and is erased when the run ends.
pub struct CombineSharesAction;

impl Action for CombineSharesAction {
    fn action_type(&self) -> ActionType {
        ActionType::CombineShares
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        _params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let inputs = step.required_named_inputs("shares", "combine_shares")?;

        // In the order written, so a refusal names the entry the author
        // sees.
        let mut shares = Vec::with_capacity(inputs.len());
        let mut given = Vec::with_capacity(inputs.len());
        let mut scheme: Option<SharingScheme> = None;
        for (position, input) in inputs.iter().enumerate() {
            let wire::Decoded {
                scheme: this,
                share,
            } = ShareOrBytes::read(ctx, input)
                .and_then(ShareOrBytes::into_share)
                .map_err(|e| {
                    ActionError::Failed(format!(
                        "shares[{position}] '{}': {e}",
                        input.display_name()
                    ))
                })?;
            let first = *scheme.get_or_insert(this);
            if first != this {
                return Err(ActionError::Failed(format!(
                    "shares[{position}] '{}' is a {this} share, and the shares before it are \
                     {first}; shares of one split share a scheme",
                    input.display_name()
                )));
            }
            given.push(json!({
                "source": input.display_name(),
                "index": share.index(),
            }));
            shares.push(share);
        }
        let scheme = scheme
            .ok_or_else(|| ActionError::Failed("combine_shares was given no shares".to_string()))?;

        let threshold = shares.first().map(Share::threshold).unwrap_or_default();

        reporter.log(
            Icon::Spinner,
            format!(
                "Combining {} shares of a {threshold}-of-n split...",
                shares.len()
            ),
        )?;

        // `SharingScheme` is `#[non_exhaustive]` in `rite-model`, so a scheme
        // this build does not implement fails with its name in the message.
        let secret = match scheme {
            SharingScheme::RiteSssV1 => {
                gf256::combine(&shares).map_err(|e| ActionError::Failed(e.to_string()))?
            }
            other => {
                return Err(ActionError::Failed(format!(
                    "This build does not implement the {other} sharing scheme"
                )));
            }
        };
        drop(shares);

        reporter.log(Icon::Checkmark, "Secret reconstructed".to_string())?;

        // Which shares, by the index inside each. Nothing about what came
        // out, not even its length: a length is the shape of a secret, and
        // for a passphrase it is the one thing to keep out of a transcript.
        // The evidence that it is the right secret is whatever the ceremony
        // checks it against next, not a hash an auditor cannot read the
        // input space of.
        reporter.backend_operation(
            "combine_shares",
            json!({
                "scheme": scheme.to_string(),
                "threshold": threshold,
                "shares": given,
            }),
            json!({}),
            None,
        )?;

        let message = format!("Secret reconstructed from {} shares", given.len());
        // Moved out of the arithmetic's wiping buffer, not copied; the empty
        // vector left behind is what that buffer wipes.
        let mut secret = secret;
        let value = ArtifactValue::Secret(SecretBox::new(Box::new(std::mem::take(&mut *secret))));

        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!("Secret stored as artifact '{produces}'"),
            )?;
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                value,
            ))
        } else {
            Ok(StepResult::completed(message))
        }
    }
}
