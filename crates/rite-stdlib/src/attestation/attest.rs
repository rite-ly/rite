//! `attest` action, record a formal attestation by a named role.

use rite_model::{ActionType, Prompt, RoleId, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, StepInfo,
    StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::AttestParams;

const DEFAULT_STATEMENT: &str = "I attest to the accuracy of the above";

/// Record a formal attestation. The operator must type the literal
/// `attest` to confirm; on success a [`StepFact::AttestationRecorded`]
/// fact is added to the transcript.
pub struct AttestAction;

impl Action for AttestAction {
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
                .or_insert_with(|| serde_json::json!(DEFAULT_STATEMENT));
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: AttestParams = parse_params(params)?;

        let statement = typed
            .statement
            .clone()
            .unwrap_or_else(|| DEFAULT_STATEMENT.to_string());
        let role_ref = step.role_str().unwrap_or("Participant");
        let role_display = ctx.resolve_role_name(role_ref);

        reporter.log(Icon::Info, format!("Statement: \"{statement}\""))?;

        reporter.log(
            Icon::Info,
            "By typing 'attest', you confirm the above statement.",
        )?;
        reporter.prompt(&Prompt::Literal {
            label: "Type 'attest' to confirm".to_string(),
            expected: "attest".to_string(),
        })?;

        let role = step
            .role_str()
            .map_or_else(|| RoleId::new("participant"), RoleId::new);
        reporter.fact(StepFact::AttestationRecorded {
            step: step.id.clone(),
            role,
            statement: statement.clone(),
        })?;

        Ok(StepResult::completed(format!(
            "Attestation recorded for {role_display}"
        )))
    }
}
