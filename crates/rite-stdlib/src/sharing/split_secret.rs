//! `split_secret` action, Shamir shares of a secret the ceremony holds.

use rite_model::{ActionType, SharingScheme};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, Share, ShareSet, StepInfo,
    StepResult, parse_params, resolve_artifact_bytes,
};
use rite_sdk::Backend;
use serde_json::json;
use zeroize::Zeroizing;

use super::gf256;
use crate::params::SplitSecretParams;

/// Split a secret into shares of which a threshold reconstruct it.
///
/// The secret arrives through `reads:` and is borrowed from the store, so the
/// step makes no copy of it beyond the one the arithmetic needs, and that one
/// is wiped. The polynomial coefficients come from the step's backend: a
/// biased coefficient leaks the secret, and the backend is what answers for
/// the quality of its random bytes.
///
/// Before the step completes, every subset of `threshold` shares is combined
/// and compared to the secret. A share that leaves the room in a tamper bag
/// has been shown to work with every other bag. The check is always run,
/// which bounds how large a split can be: one with more than
/// [`gf256::MAX_VERIFIED_SUBSETS`] subsets is refused before it is made.
pub struct SplitSecretAction;

impl Action for SplitSecretAction {
    fn action_type(&self) -> ActionType {
        ActionType::SplitSecret
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: SplitSecretParams = parse_params(params)?;
        let scheme = typed.scheme.unwrap_or(SharingScheme::RiteSssV1);
        check_size(scheme, typed.threshold, typed.shares)?;

        let secret_ref = step.required_named_input("secret", "split_secret")?;
        let secret_id = secret_ref.artifact_id();
        let secret = resolve_artifact_bytes(ctx.artifacts, &secret_id, secret_ref.property())
            .map_err(|e| {
                ActionError::Failed(format!("secret '{}': {e}", secret_ref.display_name()))
            })?;

        let backend = backend
            .ok_or_else(|| ActionError::Failed("Backend required to split a secret".into()))?;
        let backend_name = backend.name().to_string();
        let random = backend.as_random_mut().ok_or_else(|| {
            ActionError::Failed(format!(
                "Backend '{backend_name}' cannot generate random bytes, which the polynomial \
                 coefficients need"
            ))
        })?;

        reporter.log(
            Icon::Spinner,
            format!(
                "Splitting '{}' {}-of-{} under {scheme}...",
                secret_ref.display_name(),
                typed.threshold,
                typed.shares
            ),
        )?;

        // Wiped on drop: the coefficients and one share are the secret.
        let coefficients = Zeroizing::new(
            random.generate_random(gf256::random_len(secret.len(), typed.threshold))?,
        );
        // `SharingScheme` is `#[non_exhaustive]` in `rite-model`, so a scheme
        // this build does not implement fails with its name in the message
        // rather than falling into a wildcard arm.
        let set = match scheme {
            SharingScheme::RiteSssV1 => {
                gf256::split(secret, typed.threshold, typed.shares, &coefficients)
                    .map_err(|e| ActionError::Failed(e.to_string()))?
            }
            other => {
                return Err(ActionError::Failed(format!(
                    "This build does not implement the {other} sharing scheme"
                )));
            }
        };

        let subsets_checked = check_subsets(&set, secret, reporter)?;

        let threshold = set.threshold();
        reporter.log(Icon::Checkmark, format!("{} shares made", typed.shares))?;

        // Neither a digest nor the length of the secret. A digest of a secret
        // is a digest of a secret, and a length is its shape: for a wallet
        // seed the definition gives it away anyway, for a passphrase it is
        // the character count.
        reporter.backend_operation(
            "split_secret",
            json!({
                "scheme": scheme.to_string(),
                "threshold": typed.threshold,
                "shares": typed.shares,
                "secret": secret_ref.display_name(),
            }),
            json!({
                "subsets_verified": subsets_checked,
            }),
            None,
        )?;

        let message = format!("{}-of-{} shares made", typed.threshold, typed.shares);
        if let Some(produces) = &step.produces {
            reporter.log(
                Icon::Info,
                format!(
                    "Shares stored as artifact '{produces}', reached as '{produces}.share_1' \
                     through '{produces}.share_{}'",
                    typed.shares
                ),
            )?;
            // Each share's `y` moves out of the arithmetic's wiping buffer into
            // the artifact's, without a copy.
            let shares = set.into_shares().into_iter().map(|share| {
                let (threshold, index, y) = share.into_parts();
                Share::new(threshold, index, y)
            });
            Ok(StepResult::completed_with_artifact(
                message,
                produces.clone(),
                ArtifactValue::Shares(ShareSet::new(threshold, shares)),
            ))
        } else {
            Err(ActionError::Failed(
                "split_secret must create an artifact; shares that no step can name are lost \
                 the moment this step ends"
                    .into(),
            ))
        }
    }
}

/// Refuse a split larger than the scheme makes or than the step can check.
///
/// Before the backend is asked for anything: the definition, not the room,
/// is where a split this size is wrong. `rite check` applies the share limit
/// to literal values, so what reaches here is a `${param}`; it does not
/// count subsets at all, so a dry run is what surfaces that one early.
fn check_size(scheme: SharingScheme, threshold: u8, shares: u8) -> Result<(), ActionError> {
    if shares > scheme.max_shares() {
        return Err(ActionError::Failed(format!(
            "{shares} shares asked for, and {scheme} makes at most {}",
            scheme.max_shares()
        )));
    }
    let subsets = gf256::subset_count(usize::from(shares), usize::from(threshold));
    if subsets.is_none_or(|count| count > gf256::MAX_VERIFIED_SUBSETS) {
        return Err(ActionError::Failed(format!(
            "A {threshold}-of-{shares} split has {} subsets of shares to verify, and this step \
             verifies at most {}; use a smaller threshold or fewer shares",
            subsets.map_or_else(|| "too many".to_string(), |n| n.to_string()),
            gf256::MAX_VERIFIED_SUBSETS
        )));
    }
    Ok(())
}

/// Combine every `threshold`-subset and compare. Returns how many were
/// checked, for the transcript.
fn check_subsets(
    set: &gf256::ShareSet,
    secret: &[u8],
    reporter: &mut Reporter<'_>,
) -> Result<u64, ActionError> {
    let checked = set.verify_all_subsets(secret).map_err(|indexes| {
        let named: Vec<String> = indexes.iter().map(|i| format!("share_{i}")).collect();
        ActionError::Failed(format!(
            "Shares {} do not reconstruct the secret; nothing was sealed",
            named.join(", ")
        ))
    })?;
    reporter.log(
        Icon::Checkmark,
        format!(
            "Every {}-of-{} subset reconstructs the secret ({checked} checked)",
            set.threshold(),
            set.count()
        ),
    )?;
    Ok(checked)
}
