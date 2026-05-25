//! `check_value` action, machine-verified comparison of two values.
//!
//! Compares two values known to the system and records pass/fail in the
//! transcript. The comparison is deterministic and automatic; the step
//! fails (and the ceremony unwinds) when the values do not match.
//!
//! # When to use `check_value` vs other verification actions
//!
//! - **`check_value`**: Both values are known to the system. Comparison is deterministic.
//!   Example: verify SHA-256 hash of a downloaded binary matches the expected value.
//!
//! - **`confirm`**: Human must attest to something based on external observation.
//!   Example: "Verify all network cables are disconnected".
//!
//! - **`oral_readback`**: Human verifies a computed value against external state.
//!   Example: read the public-key fingerprint aloud, compare against a printed certificate.

use rite_model::ActionType;
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, StepInfo,
    StepResult, parse_params, truncate_for_display,
};
use rite_sdk::Backend;
use subtle::ConstantTimeEq;

use crate::params::CheckValueParams;

/// Automatic value comparison action.
pub struct CheckValueAction;

impl Action for CheckValueAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::CheckValue,
            description: "Machine-verified value comparison",
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
        let typed: CheckValueParams = parse_params(params)?;

        let actual = &typed.actual;
        let expected = &typed.expected;
        let message = typed.message.as_deref().unwrap_or("Value verification");

        // Constant-time comparison to avoid timing attacks on secret values.
        let values_match: bool = actual.as_bytes().ct_eq(expected.as_bytes()).into();

        if values_match {
            reporter.log(Icon::Checkmark, message)?;
            if ctx.dry_run {
                reporter.log(Icon::Info, "[dry run, verified]")?;
            }
            Ok(StepResult::completed(format!("{message}: PASS")))
        } else {
            reporter.log(Icon::Cross, format!("FAIL: {message}"))?;
            if typed.sensitive {
                reporter.log(Icon::Info, "Values do not match (sensitive values hidden)")?;
            } else {
                reporter.log(Icon::Info, "Values do not match:")?;
                reporter.log(
                    Icon::Info,
                    format!("    Actual:   {}", truncate_for_display(actual, 64)),
                )?;
                reporter.log(
                    Icon::Info,
                    format!("    Expected: {}", truncate_for_display(expected, 64)),
                )?;
            }
            Err(ActionError::Failed(format!(
                "{message}: values do not match"
            )))
        }
    }
}
