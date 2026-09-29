//! `enter_value` and `enter_secret` actions, take a typed value into the
//! ceremony.
//!
//! One implementation under two names. The name is the claim: `enter_value`
//! makes a text artifact the transcript carries, and `enter_secret` makes a
//! secret artifact it never does. Nothing in the block decides which, so a
//! passphrase step reads as one in the YAML and in the printed script, and a
//! flag that could be left off is not what stands between a secret and the
//! transcript.

use rite_model::params::EntryShape;
use rite_model::{ActionType, Format, Prompt, RevealFormat, ValidatorSpec};
use rite_runtime::{
    Action, ActionError, ArtifactValue, HandlerContext, Icon, Reporter, Response, StepInfo,
    StepResult, parse_params,
};
use rite_sdk::Backend;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::params::EntryParams;

/// Take a value a person types, as a text artifact and a transcript fact.
pub struct EnterValueAction;

/// Take a secret a person types, as a secret artifact and nothing else.
pub struct EnterSecretAction;

impl Action for EnterValueAction {
    fn action_type(&self) -> ActionType {
        ActionType::EnterValue
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let (label, validator) = entry(params)?;
        if rows_of(&validator).is_some() {
            return Err(ActionError::Failed(
                "'paper32' is for a value from a sheet, which is a secret: use enter_secret, \
                 or enter_share for a share"
                    .to_string(),
            ));
        }
        let response = reporter.prompt(&Prompt::Text {
            label,
            validator: validator.clone(),
        })?;
        let Response::Text(value) = response else {
            return Err(ActionError::Failed(
                "expected a text response for the entered value".to_string(),
            ));
        };
        // A step with nothing to create still records what was typed: the
        // answer is on the prompt fact, which is evidence on its own.
        let Some(produces) = step.produces.clone() else {
            return Ok(StepResult::completed(format!("Recorded '{value}'")));
        };
        reporter.log(
            Icon::Checkmark,
            format!("Recorded as artifact '{produces}'"),
        )?;
        // What was typed is on the prompt fact; the artifact is the value in
        // its canonical form, which for an encoding is what it decodes to.
        let artifact = match canonical(&validator, &value)? {
            Some(bytes) => ArtifactValue::Bytes(bytes),
            None => ArtifactValue::Text(value.clone()),
        };
        Ok(StepResult::completed_with_artifact(
            format!("Recorded '{value}'"),
            produces,
            artifact,
        ))
    }
}

impl Action for EnterSecretAction {
    fn action_type(&self) -> ActionType {
        ActionType::EnterSecret
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        // Checked before the prompt: a secret typed into a step that holds
        // it nowhere would be asked for and thrown away.
        let produces = step.produces.clone().ok_or_else(|| {
            ActionError::Failed(
                "enter_secret holds the secret as an artifact, so the step needs 'creates:'"
                    .to_string(),
            )
        })?;
        let (label, validator) = entry(params)?;
        // A value from a sheet is typed a row at a time, each row checked
        // as it comes; anything else on one line with echo off.
        let prompt = match rows_of(&validator) {
            Some((format, rows)) => Prompt::EnterRows {
                label,
                note: None,
                format,
                rows,
                validator: Some(validator.clone()),
            },
            None => Prompt::Secret {
                label,
                validator: validator.clone(),
            },
        };
        let response = reporter.prompt(&prompt)?;
        let Response::Secret(secret) = response else {
            return Err(ActionError::Failed(
                "expected a secret response for the entered secret".to_string(),
            ));
        };
        reporter.log(
            Icon::Checkmark,
            format!("Secret held as artifact '{produces}'"),
        )?;
        Ok(StepResult::completed_with_artifact(
            "Secret entered",
            produces,
            hold(&validator, &secret)?,
        ))
    }
}

/// The prompt an entry step puts to the person: its label, with the rule
/// stated after it, and the rule itself.
///
/// The rule is stated up front so the person knows what is wanted before
/// typing, not only after a refusal.
fn entry(params: &serde_json::Value) -> Result<(String, ValidatorSpec), ActionError> {
    let typed: EntryParams = parse_params(params)?;
    let validator = EntryShape {
        format: typed.format,
        length: typed.length,
        min_length: typed.min_length,
        max_length: typed.max_length,
    }
    .validator()
    .map_err(ActionError::Failed)?;
    let label = match validator.hint() {
        Some(hint) => format!("{} ({hint})", typed.message),
        None => typed.message,
    };
    Ok((label, validator))
}

/// The sheet encoding a rule reads rows of, and how many rows when the
/// length is exact; `None` for a value typed on one line.
fn rows_of(validator: &ValidatorSpec) -> Option<(RevealFormat, Option<usize>)> {
    match validator {
        ValidatorSpec::Format {
            format: Format::Paper32,
            min_length,
            max_length,
        } => {
            let exact = min_length.filter(|&min| Some(min) == *max_length);
            Some((
                RevealFormat::Paper32,
                exact.map(|n| RevealFormat::Paper32.rows(n)),
            ))
        }
        _ => None,
    }
}

/// The bytes a typed value stands for under its rule, when the rule is an
/// encoding; `None` when the value is its own canonical form.
///
/// The prompt loop already refused a value that does not decode, so a
/// failure here is the rule and the check disagreeing, which is a bug. The
/// buffer is returned to be moved into an artifact, never copied.
fn canonical(validator: &ValidatorSpec, value: &str) -> Result<Option<Vec<u8>>, ActionError> {
    match validator {
        ValidatorSpec::Format { format, .. } if format.is_encoding() => {
            format.decode(value).map(Some).map_err(ActionError::Failed)
        }
        _ => Ok(None),
    }
}

/// The typed secret as an artifact, in a box that wipes on drop.
fn hold(validator: &ValidatorSpec, secret: &SecretString) -> Result<ArtifactValue, ActionError> {
    let bytes = match canonical(validator, secret.expose_secret())? {
        Some(decoded) => decoded,
        None => secret.expose_secret().as_bytes().to_vec(),
    };
    Ok(ArtifactValue::Secret(SecretBox::new(Box::new(bytes))))
}
