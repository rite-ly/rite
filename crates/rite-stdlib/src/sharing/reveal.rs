//! `reveal` action: a value on screen for a person to write down, then
//! gone.
//!
//! The value reaches the step through `reads:`, borrowed, and leaves it
//! through a [`Prompt::Reveal`], which the frontend shows while the prompt
//! is up and withdraws on acknowledgement. Nothing of the value goes to a
//! log line, since a log line stays on screen for the next person, and
//! nothing goes to the transcript: the prompt fact carries the message and
//! the acknowledgement. What was shown is the definition's business, and
//! `rite script` prints the sheet for it.

use rite_model::display::hex_upper;
use rite_model::paper32;
use rite_model::{ActionType, Prompt, RevealFormat, Shown};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, Response, StepInfo,
    StepResult, parse_params, resolve_artifact_bytes, resolve_share,
};
use rite_sdk::Backend;
use zeroize::Zeroizing;

use super::gf256;
use super::paper;
use crate::params::RevealParams;

/// Show a value in a chosen encoding, and take it off the screen once the
/// person has written it down.
///
/// A share is shown as the rows of its wire layout, any other byte
/// artifact as the rows of its bytes; `format: hex` shows either as hex.
pub struct RevealAction;

impl Action for RevealAction {
    fn action_type(&self) -> ActionType {
        ActionType::Reveal
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: RevealParams = parse_params(params)?;
        let input = step.required_named_input("value", "reveal")?;
        let id = input.artifact_id();
        let name = input.display_name();

        let layout = RevealFormat::layout_for(typed.format);
        let is_share = matches!(ctx.artifacts.get(&id), Some(ArtifactValue::Shares(_)));
        let text = if is_share {
            let held = resolve_share(ctx.artifacts, &id, input.property())
                .map_err(|e| ActionError::Failed(format!("value '{name}': {e}")))?;
            check_length(typed.length, held.y().len(), &name)?;
            let share = gf256::Share::new(held.threshold(), held.index(), held.y().to_vec())
                .map_err(|e| ActionError::Failed(format!("value '{name}' is not a share: {e}")))?;
            match layout.format {
                RevealFormat::Paper32 => paper::encode(&share),
                RevealFormat::Hex => {
                    let bytes = Zeroizing::new(super::wire::encode(&share));
                    hex_upper(&bytes)
                }
                other => return Err(unsupported(other)),
            }
        } else {
            let bytes = resolve_artifact_bytes(ctx.artifacts, &id, input.property())
                .map_err(|e| ActionError::Failed(format!("value '{name}': {e}")))?;
            check_length(typed.length, bytes.len(), &name)?;
            match layout.format {
                RevealFormat::Paper32 => paper32::encode(bytes),
                RevealFormat::Hex => hex_upper(bytes),
                other => return Err(unsupported(other)),
            }
        };

        let format = layout.format;
        reporter.log(
            Icon::Info,
            format!("Showing '{name}' as {format}, for writing down"),
        )?;

        let shown = Shown::new(text, layout);
        match reporter.prompt(&Prompt::Reveal {
            label: typed.message.clone(),
            note: typed.note.clone(),
            shown,
        })? {
            Response::Acknowledge => {}
            _ => return Err(ActionError::Aborted),
        }

        reporter.log(Icon::Checkmark, "Written down; no longer on screen")?;
        Ok(StepResult::completed(format!(
            "'{name}' shown as {format} and written down"
        )))
    }
}

/// The sheet was printed for `length:` bytes; a value of another size does
/// not fit it, and the person finds out at the last row. Refuse before
/// anything is shown. For a share, the length is the secret's, as the
/// sheet counts it.
fn check_length(declared: Option<u64>, actual: usize, name: &str) -> Result<(), ActionError> {
    match declared {
        Some(declared) if u64::try_from(actual).ok() != Some(declared) => {
            Err(ActionError::Failed(format!(
                "value '{name}' is {actual} bytes; the step says length: {declared}, and the \
                 sheet was printed for that"
            )))
        }
        _ => Ok(()),
    }
}

fn unsupported(format: RevealFormat) -> ActionError {
    ActionError::Failed(format!("This build does not show a value as {format}"))
}
