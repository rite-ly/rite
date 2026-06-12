//! `oral_readback` action, verbal verification using NATO phonetic or other formats.

use rite_model::{ActionType, Prompt};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, Response,
    StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::{OralReadbackParams, ReadbackFormat};

/// NATO phonetic alphabet mapping.
const NATO_ALPHABET: &[(&str, &str)] = &[
    ("A", "Alpha"),
    ("B", "Bravo"),
    ("C", "Charlie"),
    ("D", "Delta"),
    ("E", "Echo"),
    ("F", "Foxtrot"),
    ("G", "Golf"),
    ("H", "Hotel"),
    ("I", "India"),
    ("J", "Juliet"),
    ("K", "Kilo"),
    ("L", "Lima"),
    ("M", "Mike"),
    ("N", "November"),
    ("O", "Oscar"),
    ("P", "Papa"),
    ("Q", "Quebec"),
    ("R", "Romeo"),
    ("S", "Sierra"),
    ("T", "Tango"),
    ("U", "Uniform"),
    ("V", "Victor"),
    ("W", "Whiskey"),
    ("X", "X-ray"),
    ("Y", "Yankee"),
    ("Z", "Zulu"),
    ("0", "Zero"),
    ("1", "One"),
    ("2", "Two"),
    ("3", "Three"),
    ("4", "Four"),
    ("5", "Five"),
    ("6", "Six"),
    ("7", "Seven"),
    ("8", "Eight"),
    ("9", "Nine"),
];

/// Convert a string to NATO phonetic representation.
fn to_nato_phonetic(input: &str) -> String {
    let nato_map: std::collections::HashMap<char, &str> = NATO_ALPHABET
        .iter()
        .map(|(c, word)| (c.chars().next().unwrap_or_default(), *word))
        .collect();

    input
        .chars()
        .filter_map(|c| {
            let upper = c.to_ascii_uppercase();
            nato_map.get(&upper).map(|word| format!("{word} ({upper})"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Convert a string to hex representation with spacing.
fn to_hex_format(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.join(" "))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Oral readback action for verbal verification.
pub struct OralReadbackAction;

impl Action for OralReadbackAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::OralReadback,
            description: "Oral readback verification",
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
        let typed: OralReadbackParams = parse_params(params)?;

        let value = typed
            .value
            .as_deref()
            .ok_or_else(|| ActionError::Failed("'value' is required".to_string()))?;

        let display_value: String = match typed.characters {
            Some(limit) => value.chars().take(limit as usize).collect(),
            None => value.to_string(),
        };

        let format = typed.format.unwrap_or_default();
        let formatted = match format {
            ReadbackFormat::NatoPhonetic => to_nato_phonetic(&display_value),
            ReadbackFormat::Hex => to_hex_format(&display_value),
            ReadbackFormat::Raw => display_value.clone(),
        };

        reporter.log(Icon::Info, "READER: Please read aloud the following value:")?;
        reporter.log(Icon::Info, format!("    Raw value: {display_value}"))?;
        reporter.log(Icon::Info, format!("    {}: {formatted}", format.label()))?;

        reporter.log(
            Icon::Info,
            "CONFIRMER: Verify the reader spoke the correct value.",
        )?;

        match reporter.prompt(&Prompt::Confirm {
            question: "Confirmer verifies readback is correct?".to_string(),
            default: None,
        })? {
            Response::Bool(true) => Ok(StepResult::completed("Oral readback verified")),
            _ => Err(ActionError::Aborted),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nato_phonetic() {
        assert_eq!(to_nato_phonetic("ABC"), "Alpha (A), Bravo (B), Charlie (C)");
        assert_eq!(to_nato_phonetic("123"), "One (1), Two (2), Three (3)");
        assert_eq!(to_nato_phonetic("A1B"), "Alpha (A), One (1), Bravo (B)");
    }

    #[test]
    fn test_nato_phonetic_lowercase() {
        assert_eq!(to_nato_phonetic("abc"), "Alpha (A), Bravo (B), Charlie (C)");
    }

    #[test]
    fn test_hex_format() {
        assert_eq!(to_hex_format("AB"), "41 42");
        assert_eq!(to_hex_format("ABCDEF"), "41 42 43 44  45 46");
    }
}
