//! Attest action - formal attestation recording.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, StepEvidence,
    StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;

use crate::params::AttestParams;

/// Attestation action.
pub struct AttestAction;

impl ActionHandler for AttestAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::Attest,
            description: "Record a formal attestation",
            category: ActionCategory::Attestation,
        }
    }

    fn apply_defaults(&self, params: &mut serde_json::Value, _step: &StepInfo) {
        if !params.is_object() {
            *params = serde_json::json!({});
        }
        if let Some(obj) = params.as_object_mut() {
            obj.entry("statement".to_string())
                .or_insert_with(|| serde_json::json!("I attest to the accuracy of the above"));
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
        let typed: AttestParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let statement = typed
            .statement
            .as_deref()
            .unwrap_or("I attest to the accuracy of the above");

        let role_ref = step.role_str().unwrap_or("Participant");
        let role_display = ctx.resolve_role_name(role_ref);

        display::write_line(ui, &format!("Role: {role_display}"))?;
        display::write_line(ui, &format!("Statement: \"{statement}\""))?;
        display::write_blank(ui)?;

        if ctx.dry_run {
            display::write_dry_run(ui, "auto-attesting")?;
            let result = StepResult::completed(format!("Attestation recorded for {role_display}"));
            let evidence = StepEvidence::new();
            return Ok((result, evidence));
        }

        display::write_line(ui, "By typing 'attest', you confirm the above statement.")?;

        if display::prompt_exact(ui, "Type 'attest' to confirm", "attest")? {
            let result = StepResult::completed(format!("Attestation recorded for {role_display}"));

            let mut evidence = StepEvidence::new();
            if let Some(s) = typed.statement {
                evidence.insert("statement", s);
            } else {
                evidence.insert("statement", "I attest to the accuracy of the above");
            }
            if let Some(role) = step.role_str() {
                evidence.insert("attester_role", role.to_string());
            }

            Ok((result, evidence))
        } else {
            Err(ExecutionError::StepAborted(step.id.clone()))
        }
    }
}
