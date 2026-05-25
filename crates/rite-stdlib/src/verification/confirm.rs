//! `confirm` action, record an operator confirmation.

use rite_model::{ActionType, Prompt};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, Response,
    StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::ConfirmParams;

/// Confirm action, pause the ceremony and require a yes/no acknowledgement.
pub struct ConfirmAction;

impl Action for ConfirmAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::Confirm,
            description: "Request user confirmation",
            category: ActionCategory::Verification,
        }
    }

    fn execute(
        &self,
        _step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: ConfirmParams = parse_params(params)?;

        let message = typed
            .message
            .as_deref()
            .unwrap_or("Please confirm to proceed");

        reporter.log(Icon::Info, message)?;

        if ctx.dry_run {
            reporter.log(Icon::Info, "[dry run, auto-confirming]")?;
            return Ok(StepResult::completed("Verification confirmed (dry run)"));
        }

        let response = reporter.prompt(&Prompt::Confirm {
            question: "Confirm?".to_string(),
            default: None,
        })?;
        match response {
            Response::Bool(true) => Ok(StepResult::completed("Verification confirmed")),
            _ => Err(ActionError::Aborted),
        }
    }
}
