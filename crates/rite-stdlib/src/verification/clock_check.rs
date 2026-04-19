//! Clock check action - verify system clock is correct.

use chrono::{Local, Utc};
use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, StepEvidence,
    StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;

use crate::params::ClockCheckParams;

/// Clock check action - verify system clock is correct.
///
/// Displays the current system time (both local and UTC) and requires
/// operator confirmation that the time is correct. This should typically
/// be the first step in a ceremony to establish machine context.
pub struct ClockCheckAction;

impl ActionHandler for ClockCheckAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::ClockCheck,
            description: "Verify system clock is correct",
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
        let typed: ClockCheckParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        if let Some(message) = &typed.message {
            display::write_line(ui, message)?;
            display::write_blank(ui)?;
        }

        let utc_time = Utc::now();
        let local_time = utc_time.with_timezone(&Local);

        let utc_formatted = utc_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let local_formatted = local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string();

        display::write_line(ui, &format!("UTC time:    {utc_formatted}"))?;
        display::write_line(ui, &format!("Local time:  {local_formatted}"))?;
        display::write_blank(ui)?;
        display::write_line(ui, "All ceremony timestamps will be recorded in UTC.")?;
        display::write_blank(ui)?;

        if ctx.dry_run {
            display::write_dry_run(ui, "auto-confirming clock")?;
            let mut evidence = StepEvidence::new();
            if let Some(message) = typed.message {
                evidence.insert("prompt", message);
            }
            evidence.insert("utc_time", utc_time.to_rfc3339());
            evidence.insert("local_time", local_time.to_rfc3339());
            evidence.insert("timezone", local_time.format("%Z").to_string());
            evidence.insert("confirmed", true);
            return Ok((StepResult::completed("Clock verified (dry run)"), evidence));
        }

        if display::prompt_yes_no(ui, "Is the system clock correct?")? {
            let result = StepResult::completed("Clock verified");

            let mut evidence = StepEvidence::new();
            if let Some(message) = typed.message {
                evidence.insert("prompt", message);
            }
            evidence.insert("utc_time", utc_time.to_rfc3339());
            evidence.insert("local_time", local_time.to_rfc3339());
            evidence.insert("timezone", local_time.format("%Z").to_string());
            evidence.insert("confirmed", true);

            Ok((result, evidence))
        } else {
            Err(ExecutionError::StepAborted(step.id.clone()))
        }
    }
}
