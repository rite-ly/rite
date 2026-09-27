//! `enter_share` action: a share typed back from its sheet.
//!
//! The rows go through an [`Prompt::EnterRows`], which the frontend takes
//! one row at a time and checks as they come, so a miscopied character is
//! caught at the row it is in. The runtime receives the rows as a secret
//! and reads them again here, as a whole, into a share; rows that are not
//! one are asked for again. The transcript records the share's index and
//! which rows were repaired, never the rows.

use rite_model::{ActionType, Prompt, RevealFormat, SharingScheme};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, Response, Share, ShareSet,
    StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;
use secrecy::ExposeSecret;
use serde_json::json;

use super::gf256;
use super::wire;
use crate::params::EnterShareParams;

/// Ask for a share row by row, and hold it as a share a later step
/// combines.
pub struct EnterShareAction;

impl Action for EnterShareAction {
    fn action_type(&self) -> ActionType {
        ActionType::EnterShare
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: EnterShareParams = parse_params(params)?;
        let Some(produces) = step.produces.clone() else {
            return Err(ActionError::Failed(
                "enter_share must create an artifact; a share no step can name is lost the \
                 moment this step ends"
                    .into(),
            ));
        };
        let format = typed.format.unwrap_or(RevealFormat::Paper32);
        let length = typed
            .length
            .map(|n| usize::try_from(n).unwrap_or(usize::MAX));

        // The share is read inside the check, so a refusal goes back to the
        // person with the reason, and the share that passes is kept rather
        // than read twice.
        let mut read: Option<(gf256::Share, Vec<String>)> = None;
        let prompt = Prompt::EnterRows {
            label: typed.message.clone(),
            note: typed.note.clone(),
            format,
            rows: length.map(|n| format.rows(SharingScheme::RiteSssV1.share_len(n))),
            validator: None,
        };
        let response = reporter.prompt_checked(&prompt, |response| {
            let Response::Secret(text) = response else {
                return Err("expected the rows of a share".to_string());
            };
            let value = format.decode(text.expose_secret())?;
            let share = wire::decode(&value.bytes)
                .map_err(|e| format!("these rows are not a share: {e}"))?;
            if let Some(length) = length
                && share.secret_len() != length
            {
                return Err(format!(
                    "this share is of a {}-byte secret, and the step says length: {length}; \
                     check it is the right sheet",
                    share.secret_len()
                ));
            }
            read = Some((share, value.repaired));
            Ok(())
        })?;
        drop(response);
        let (share, repaired) = read.ok_or_else(|| {
            ActionError::Failed("the rows were accepted and no share was read".into())
        })?;

        for repair in &repaired {
            reporter.log(Icon::Warning, format!("Repaired {repair}"))?;
        }
        let (threshold, index) = (share.threshold(), share.index());
        reporter.log(
            Icon::Checkmark,
            format!("Share {index} of a {threshold}-of-n split read"),
        )?;

        // Which share, and where the sheet needed help: the rows the person
        // should look at again. Nothing of the share itself.
        reporter.backend_operation(
            "enter_share",
            json!({ "format": format.as_str() }),
            json!({
                "scheme": gf256::FORMAT,
                "threshold": threshold,
                "index": index,
                "repaired": repaired,
            }),
            None,
        )?;

        let (threshold, index, y) = share.into_parts();
        let set = ShareSet::new(threshold, [Share::new(threshold, index, y)]);
        reporter.log(Icon::Info, format!("Share stored as artifact '{produces}'"))?;
        Ok(StepResult::completed_with_artifact(
            format!("Share {index} typed back"),
            produces,
            ArtifactValue::Shares(set),
        ))
    }
}
