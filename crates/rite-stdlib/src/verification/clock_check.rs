//! `clock_check` action, record the system clock at ceremony start.

use chrono::{Local, Utc};
use rite_model::{ActionType, Prompt};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, Response,
    StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::ClockCheckParams;

/// Clock check action, display the current system time (UTC + local) and
/// require operator confirmation that it is correct.
///
/// Typically the first step in a ceremony so that every subsequent
/// timestamp can be referenced to a known-correct wall clock.
pub struct ClockCheckAction;

impl Action for ClockCheckAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::ClockCheck,
            description: "Verify system clock is correct",
            category: ActionCategory::Verification,
        }
    }

    fn execute(
        &self,
        _step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: ClockCheckParams = parse_params(params)?;

        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.as_str())?;
        }

        let utc_time = Utc::now();
        let local_time = utc_time.with_timezone(&Local);

        let utc_formatted = utc_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let local_formatted = local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string();

        reporter.log(Icon::Info, format!("UTC time:    {utc_formatted}"))?;
        reporter.log(Icon::Info, format!("Local time:  {local_formatted}"))?;
        reporter.log(
            Icon::Info,
            "All ceremony timestamps will be recorded in UTC.",
        )?;

        match reporter.prompt(&Prompt::Confirm {
            question: "Is the system clock correct?".to_string(),
            default: None,
        })? {
            Response::Bool(true) => Ok(StepResult::completed("Clock verified")),
            _ => Err(ActionError::Aborted),
        }
    }
}
