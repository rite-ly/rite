//! Confirm action - simple confirmation.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, StepEvidence,
    StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;

use crate::params::ConfirmParams;

/// Confirm action - simple confirmation.
pub struct ConfirmAction;

impl ActionHandler for ConfirmAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::Confirm,
            description: "Request user confirmation",
            category: ActionCategory::Verification,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        ui: &mut dyn StepUI,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        let typed: ConfirmParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let message = typed
            .message
            .as_deref()
            .unwrap_or("Please confirm to proceed");

        display::write_line(ui, message)?;
        display::write_blank(ui)?;

        if ctx.dry_run {
            display::write_dry_run(ui, "auto-confirming")?;
            let result = StepResult::completed("Verification confirmed (dry run)");
            let evidence = StepEvidence::new();
            return Ok((result, evidence));
        }

        if display::prompt_yes_no(ui, "Confirm?")? {
            let result = StepResult::completed("Verification confirmed");

            let mut evidence = StepEvidence::new();
            if let Some(msg) = typed.message {
                evidence.insert("prompt", msg);
            }
            evidence.insert("confirmed", true);

            Ok((result, evidence))
        } else {
            Err(ExecutionError::StepAborted(step.id.clone()))
        }
    }
}
