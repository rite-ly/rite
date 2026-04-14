//! Check value action - machine-verified comparison of two values.
//!
//! This action compares two values known to the system and records pass/fail in the transcript.
//! It is automatic (no human decision required) and aborts the ceremony on mismatch.
//!
//! # When to use `check_value` vs other verification actions
//!
//! - **`check_value`**: Both values are known to the system. Comparison is deterministic.
//!   Example: Verify SHA-256 hash of downloaded binary matches expected value.
//!
//! - **`confirm`**: Human must attest to something based on external observation.
//!   Example: "Verify all network cables are disconnected" (system can't check this).
//!
//! - **`oral_readback`**: Human must verify a computed value against external state.
//!   Example: Read public key fingerprint aloud, compare against printed certificate.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, Icon,
    StepEvidence, StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;
use subtle::ConstantTimeEq;

use crate::params::CheckValueParams;

/// Check value action for automatic comparison of two values.
pub struct CheckValueAction;

impl ActionHandler for CheckValueAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::CheckValue,
            description: "Machine-verified value comparison",
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
        let typed: CheckValueParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let actual = &typed.actual;
        let expected = &typed.expected;
        let message = typed.message.as_deref().unwrap_or("Value verification");

        // Constant-time comparison to avoid timing attacks on secret values.
        let values_match: bool = actual.as_bytes().ct_eq(expected.as_bytes()).into();

        if values_match {
            display::write_pass(ui, message)?;

            if ctx.dry_run {
                display::write_dry_run(ui, "verified")?;
            }

            let result = StepResult::completed(format!("{message}: PASS"));

            let mut evidence = StepEvidence::new();
            if let Some(msg) = typed.message {
                evidence.insert("verification", msg);
            }
            evidence.insert("result", "pass");

            if !typed.sensitive {
                evidence.insert("actual_value", actual.clone());
                evidence.insert("expected_value", expected.clone());
            }

            Ok((result, evidence))
        } else {
            display::write_fail(ui, message)?;
            display::write_blank(ui)?;

            if typed.sensitive {
                display::write_line(ui, "Values do not match (sensitive values hidden)")?;
            } else {
                display::write_line(ui, "Values do not match:")?;
                ui.log(
                    Icon::Info,
                    &format!("    Actual:   {}", truncate_for_display(actual, 64)),
                );
                ui.log(
                    Icon::Info,
                    &format!("    Expected: {}", truncate_for_display(expected, 64)),
                );
            }
            display::write_blank(ui)?;

            Err(ExecutionError::StepFailed {
                step: step.id.clone(),
                reason: format!("{message}: values do not match"),
            })
        }
    }
}

/// Truncate a string for display, showing ellipsis if too long.
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_for_display() {
        assert_eq!(truncate_for_display("short", 10), "short");
        assert_eq!(
            truncate_for_display("this is a long string", 10),
            "this is a ..."
        );
    }
}
