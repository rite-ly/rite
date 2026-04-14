//! Oral readback action - verbal verification using NATO phonetic or other formats.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, Icon,
    StepEvidence, StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;

use crate::params::OralReadbackParams;

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
            nato_map
                .get(&upper)
                .map(|word| format!("{word} ({upper})"))
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

impl ActionHandler for OralReadbackAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::OralReadback,
            description: "Oral readback verification",
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
        let typed: OralReadbackParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        let value = typed
            .value
            .as_deref()
            .ok_or_else(|| ExecutionError::InvalidParams("'value' is required".to_string()))?;

        let display_value = if let Some(limit) = typed.characters {
            &value[..value.len().min(limit as usize)]
        } else {
            value
        };

        let format = typed.format.as_deref().unwrap_or("nato_phonetic");
        let formatted = match format {
            "nato_phonetic" | "nato" => to_nato_phonetic(display_value),
            "hex" => to_hex_format(display_value),
            "raw" => display_value.to_string(),
            other => {
                return Err(ExecutionError::InvalidParams(format!(
                    "Unknown format: '{other}'. Valid formats: nato_phonetic, hex, raw"
                )));
            }
        };

        display::write_line(ui, "READER: Please read aloud the following value:")?;
        display::write_blank(ui)?;
        ui.log(Icon::Info, &format!("    Raw value: {display_value}"));
        display::write_blank(ui)?;
        ui.log(Icon::Info, &format!("    {format}: {formatted}"));
        display::write_blank(ui)?;

        if ctx.dry_run {
            display::write_dry_run(ui, "auto-confirming")?;
            let result = StepResult::completed("Oral readback completed (dry run)");
            let evidence = StepEvidence::new();
            return Ok((result, evidence));
        }

        display::write_line(ui, "CONFIRMER: Verify the reader spoke the correct value.")?;
        display::write_blank(ui)?;

        if !display::prompt_yes_no(ui, "Confirmer verifies readback is correct?")? {
            return Err(ExecutionError::StepAborted(step.id.clone()));
        }

        let result = StepResult::completed("Oral readback verified");

        let mut evidence = StepEvidence::new();

        if !typed.sensitive {
            evidence.insert("value", value.to_string());
        }

        if let Some(format) = typed.format {
            evidence.insert("format", format);
        }
        if let Some(chars) = typed.characters {
            evidence.insert("characters_read", chars);
        }
        evidence.insert("verified", true);

        Ok((result, evidence))
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
