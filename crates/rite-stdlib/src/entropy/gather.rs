//! `gather_entropy` action, fold human-supplied entropy into the ceremony seed.

use rite_model::{ActionType, Prompt, ValidatorSpec};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, Response,
    StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::GatherEntropyParams;

/// Default instruction. Dice is only a suggestion: the operator may type any
/// random value, and the method can be made mandatory by overriding
/// `instruction` in the ceremony.
const DEFAULT_INSTRUCTION: &str =
    "Generate a random value, for example roll a die 10 times and type the result.";

/// Fold a human entropy contribution into the ceremony entropy source.
///
/// Prompts the assigned participant for a free-form random value and mixes it
/// into the seed ratchet via [`Reporter::fold_entropy`], advancing the epoch.
/// The contribution is public, witnessed entropy: any input is safe and only
/// adds unpredictability, so it is validated non-empty but never rejected.
pub struct GatherEntropyAction;

impl Action for GatherEntropyAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::GatherEntropy,
            description: "Gather human entropy into the ceremony seed",
            category: ActionCategory::Verification,
        }
    }

    fn apply_defaults(&self, params: &mut serde_json::Value, _step: &StepInfo) {
        if !params.is_object() {
            *params = serde_json::json!({});
        }
        if let Some(obj) = params.as_object_mut() {
            obj.entry("instruction".to_string())
                .or_insert_with(|| serde_json::json!(DEFAULT_INSTRUCTION));
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
        let typed: GatherEntropyParams = parse_params(params)?;
        let instruction = typed
            .instruction
            .unwrap_or_else(|| DEFAULT_INSTRUCTION.to_string());

        let role_display = ctx.resolve_role_name(step.role_str().unwrap_or("Participant"));

        reporter.log(Icon::Info, instruction.clone())?;

        let response = reporter.prompt(&Prompt::Text {
            label: instruction,
            validator: ValidatorSpec::NonEmpty,
        })?;
        let Response::Text(contribution) = response else {
            return Err(ActionError::Failed(
                "expected a text response for the entropy contribution".to_string(),
            ));
        };
        reporter.fold_entropy(&contribution)?;

        Ok(StepResult::completed(format!(
            "Entropy contribution recorded for {role_display}"
        )))
    }
}
