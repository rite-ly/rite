//! `split_secret` action, Shamir shares of a secret the ceremony holds.

use rite_model::{ActionType, ArtifactRef, SharingScheme};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, Share, ShareSet, StepInfo,
    StepResult, parse_params, resolve_artifact_bytes, resolve_backend_key,
};
use rite_sdk::{Backend, KeyCheckValue, SecretKeyValue};
use serde_json::json;
use zeroize::Zeroizing;

use super::gf256;
use crate::backend::transport_backend;
use rite_model::params::SplitSecretParams;

/// Split a secret into shares of which a threshold reconstruct it.
///
/// The secret arrives through `reads:` and is borrowed from the store, so the
/// step makes no copy of it beyond the one the arithmetic needs, and that one
/// is wiped. The polynomial coefficients come from the step's backend: a
/// biased coefficient leaks the secret, and the backend is what answers for
/// the quality of its random bytes.
///
/// The step reads exactly one input. `secret:` is bytes the ceremony holds.
/// `key:` is a symmetric key held by a backend. Using `key:` shows that the
/// key leaves its backend in this step. The key's value is read out of the
/// backend for the split, and no later step can name it, only the shares. The
/// backend lets the value out only if the key's policy says `sensitive: false`
/// and `extractable: true`.
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

        let input = split_input(step)?;
        // Everything that can refuse the step is checked before the secret is
        // read, so a key never leaves its backend for a split that cannot
        // finish.
        let produces = step.produces.as_ref().ok_or_else(|| {
            ActionError::Failed(
                "split_secret must create an artifact; shares that no step can name are lost \
                 the moment this step ends"
                    .into(),
            )
        })?;

        let backend = backend
            .ok_or_else(|| ActionError::Failed("Backend required to split a secret".into()))?;
        let backend_name = backend.name().to_string();
        if backend.as_random_mut().is_none() {
            return Err(no_random(&backend_name));
        }

        let read = match input {
            Input::Secret(reference) => read_held(ctx, reference)?,
            Input::Key(reference) => read_key(ctx, reference, &mut *backend, reporter)?,
        };
        let secret = read.bytes();

        // Checked above; looked up again because the read borrowed the backend.
        let random = backend
            .as_random_mut()
            .ok_or_else(|| no_random(&backend_name))?;

        reporter.log(
            Icon::Spinner,
            format!(
                "Splitting '{}' {}-of-{} under {scheme}...",
                input.reference().display_name(),
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
        // the character count. A key is different: its check value is how it
        // is named elsewhere, and is truncated by design. Record it so the
        // shares can be associated with the key.
        let mut inputs = serde_json::Map::new();
        inputs.insert("scheme".into(), json!(scheme.to_string()));
        inputs.insert("threshold".into(), json!(typed.threshold));
        inputs.insert("shares".into(), json!(typed.shares));
        inputs.insert(input.name().into(), json!(input.reference().display_name()));
        if let Some(check_value) = read.check_value() {
            inputs.insert("key_check_value".into(), json!(check_value.to_string()));
        }
        reporter.backend_operation(
            "split_secret",
            serde_json::Value::Object(inputs),
            json!({
                "subsets_verified": subsets_checked,
            }),
            None,
        )?;

        let message = format!("{}-of-{} shares made", typed.threshold, typed.shares);
        // Each share's `y` moves out of the arithmetic's wiping buffer into
        // the artifact's, without a copy.
        let shares = set.into_shares().into_iter().map(|share| {
            let (threshold, index, y) = share.into_parts();
            Share::new(threshold, index, y)
        });
        Ok(StepResult::completed_with_artifact(
            message,
            produces.clone(),
            ArtifactValue::Shares(ShareSet::new(scheme, threshold, shares)),
        ))
    }
}

fn no_random(backend_name: &str) -> ActionError {
    ActionError::Failed(format!(
        "Backend '{backend_name}' cannot generate random bytes, which the polynomial \
         coefficients need"
    ))
}

/// What a split reads.
enum Secret<'a> {
    /// Bytes held by the artifact store.
    Held(&'a [u8]),
    /// A key's value, returned by the backend for this split and wiped when
    /// dropped.
    Key(SecretKeyValue),
}

impl Secret<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Held(bytes) => bytes,
            Self::Key(key) => key.value(),
        }
    }

    fn check_value(&self) -> Option<&KeyCheckValue> {
        match self {
            Self::Held(_) => None,
            Self::Key(key) => Some(key.check_value()),
        }
    }
}

/// The input read by the split.
#[derive(Clone, Copy)]
enum Input<'s> {
    /// `secret:`, bytes the ceremony holds.
    Secret(&'s ArtifactRef),
    /// `key:`, a symmetric key held by a backend.
    Key(&'s ArtifactRef),
}

impl<'s> Input<'s> {
    /// The input name used in the transcript.
    fn name(self) -> &'static str {
        match self {
            Self::Secret(_) => "secret",
            Self::Key(_) => "key",
        }
    }

    fn reference(self) -> &'s ArtifactRef {
        match self {
            Self::Secret(reference) | Self::Key(reference) => reference,
        }
    }
}

/// Select the input named by the step.
///
/// The resolver rejects a step that names neither input or both inputs. This
/// error is reachable only if the step was built without going through
/// resolution.
fn split_input(step: &StepInfo) -> Result<Input<'_>, ActionError> {
    match (step.named_input("secret"), step.named_input("key")) {
        (Some(secret), None) => Ok(Input::Secret(secret)),
        (None, Some(key)) => Ok(Input::Key(key)),
        (Some(_), Some(_)) => Err(ActionError::Failed(
            "split_secret reads both 'secret' and 'key'; name one".to_string(),
        )),
        (None, None) => Err(ActionError::Failed(
            "split_secret: missing required input 'secret' or 'key'".to_string(),
        )),
    }
}

/// The bytes `secret:` names, borrowed from the store.
fn read_held<'a>(
    ctx: &HandlerContext<'a>,
    reference: &ArtifactRef,
) -> Result<Secret<'a>, ActionError> {
    resolve_artifact_bytes(
        ctx.artifacts,
        &reference.artifact_id(),
        reference.property(),
    )
    .map(Secret::Held)
    .map_err(|e| ActionError::Failed(format!("secret '{}': {e}", reference.display_name())))
}

/// The value of the key `key:` names, read out of its backend.
///
/// The export is recorded as soon as the key's value leaves the backend, so it
/// remains in the transcript if the split later fails.
fn read_key<'a>(
    ctx: &HandlerContext<'a>,
    reference: &ArtifactRef,
    backend: &mut dyn Backend,
    reporter: &mut Reporter<'_>,
) -> Result<Secret<'a>, ActionError> {
    let named = resolve_backend_key(ctx.artifacts, &reference.artifact_id()).map_err(|e| {
        ActionError::Failed(format!(
            "key '{}': {e}. Use 'secret:' to read bytes.",
            reference.display_name()
        ))
    })?;
    let (transport, _) = transport_backend(
        Some(backend),
        named.backend_name,
        "hand over a key's value to split it",
    )?;
    let key = transport.export_secret_key(named.key_id)?;
    reporter.backend_operation(
        "export_secret_key",
        json!({
            "key": reference.display_name(),
            "key_check_value": key.check_value().to_string(),
        }),
        json!({}),
        None,
    )?;
    // The backend computed this over the bytes it returned; the artifact
    // carries the one the key was named by when it was made or imported.
    if let Some(expected) = named.check_value
        && expected != key.check_value()
    {
        return Err(ActionError::Failed(format!(
            "Backend '{}' returned a value with check value {}, but key '{}' has \
             recorded check value {expected}. Nothing was split.",
            named.backend_name,
            key.check_value(),
            reference.display_name()
        )));
    }
    Ok(Secret::Key(key))
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
