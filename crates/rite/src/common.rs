//! Shared helpers for input assembly and pre-flight checks.

use clap::Args;
use rite_model::{Ceremony, MaterialKind, MaterialSource};
use rite_resolver::CeremonyInputs;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::Path;

/// Input flags shared by `check` and `run`.
#[derive(Args, Debug)]
pub struct InputArgs {
    /// Set a parameter value (`NAME=VALUE`)
    #[arg(long = "param", value_name = "NAME=VALUE")]
    pub params: Vec<String>,
    /// Assign a person to a role (`ROLE_ID=PERSON`)
    #[arg(long = "role", value_name = "ROLE_ID=PERSON")]
    pub roles: Vec<String>,
    /// Provide a material source (`NAME=@PATH` or `NAME=IDENTIFIER`)
    #[arg(long = "material", value_name = "NAME=PATH_OR_ID")]
    pub materials: Vec<String>,
}

/// Split a KEY=VALUE string on the first `=`.
pub fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=VALUE, got '{s}'"))?;
    if key.is_empty() {
        return Err(format!("empty name in '{s}'"));
    }
    Ok((key.to_string(), value.to_string()))
}

/// Parse a material value: `@path` → File, anything else → Identifier.
pub fn parse_material_value(value: &str) -> MaterialSource {
    if let Some(path) = value.strip_prefix('@') {
        MaterialSource::File {
            file: std::env::current_dir().unwrap_or_default().join(path),
        }
    } else {
        MaterialSource::Identifier {
            identifier: value.to_string(),
        }
    }
}

/// Collect `RITE_PARAM_*`, `RITE_ROLE_*`, and `RITE_MATERIAL_*` env vars in a single pass.
fn collect_env_vars() -> (
    HashMap<String, serde_json::Value>,
    HashMap<String, String>,
    HashMap<String, MaterialSource>,
) {
    let mut params = HashMap::new();
    let mut roles = HashMap::new();
    let mut materials = HashMap::new();
    for (key, value) in std::env::vars() {
        if let Some(name) = key.strip_prefix("RITE_PARAM_") {
            params.insert(name.to_lowercase(), serde_json::Value::String(value));
        } else if let Some(name) = key.strip_prefix("RITE_ROLE_") {
            roles.insert(name.to_lowercase(), value);
        } else if let Some(name) = key.strip_prefix("RITE_MATERIAL_") {
            materials.insert(name.to_lowercase(), parse_material_value(&value));
        }
    }
    (params, roles, materials)
}

/// Build `CeremonyInputs` from CLI flags and env vars.
///
/// Priority: env vars < CLI flags (CLI wins).
pub fn build_inputs(
    params: &[String],
    roles: &[String],
    materials: &[String],
) -> Result<CeremonyInputs, String> {
    let (mut input_params, mut input_roles, mut input_materials) = collect_env_vars();

    for s in params {
        let (key, value) = parse_key_value(s)?;
        input_params.insert(key.to_lowercase(), serde_json::Value::String(value));
    }
    for s in roles {
        let (key, value) = parse_key_value(s)?;
        input_roles.insert(key.to_lowercase(), value);
    }
    for s in materials {
        let (key, value) = parse_key_value(s)?;
        input_materials.insert(key.to_lowercase(), parse_material_value(&value));
    }

    Ok(CeremonyInputs {
        parameters: input_params,
        roles: input_roles,
        materials: input_materials,
    })
}

/// Build inputs from CLI args and env, printing error and exiting on failure.
pub fn build_inputs_or_exit(input_args: &InputArgs) -> CeremonyInputs {
    match build_inputs(&input_args.params, &input_args.roles, &input_args.materials) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Invalid argument: {e}");
            std::process::exit(1);
        }
    }
}

/// Resolve a ceremony file, printing diagnostics and exiting on failure.
///
/// Used by `check`, `script`, and `report` — any non-interactive entry point
/// that needs a `Ceremony` from a YAML path.
pub fn resolve_or_exit(path: &Path, inputs: Option<&CeremonyInputs>) -> Ceremony {
    let (resolved_opt, diags) = rite_resolver::analyze(path, inputs);

    for d in &diags {
        eprintln!("{d}");
    }

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    if has_errors {
        std::process::exit(1);
    }

    resolved_opt.unwrap_or_else(|| {
        eprintln!("Internal error: ceremony resolved to None with no errors");
        std::process::exit(1);
    })
}

/// Check that all digital materials with file sources exist on disk.
///
/// Called after resolution succeeds but before execution, so errors are reported
/// cleanly before any I/O is attempted.
pub fn preflight_check_materials(resolved: &rite_model::Ceremony) -> Result<(), String> {
    for (id, material) in resolved.materials.iter() {
        if let MaterialKind::Digital {
            source: Some(MaterialSource::File { file }),
        } = &material.kind
            && !file.exists()
        {
            return Err(format!(
                "Material '{}': file not found: {}",
                id.as_str(),
                file.display()
            ));
        }
    }
    Ok(())
}

/// Prompt the user for any required parameters that have no value yet.
///
/// Skips parameters whose value is already set (either from CLI/env or by a default
/// applied during resolution). Called before full resolution so that the ceremony can
/// be resolved with a complete set of inputs.
pub fn prompt_missing_params(inputs: &mut CeremonyInputs, ceremony: &rite_model::Ceremony) {
    let stdin = std::io::stdin();

    for (id, param) in ceremony.parameters.iter() {
        let name = id.as_str();

        // Skip if already provided via CLI/env, or if the resolver set a default (value not null).
        if inputs.parameters.contains_key(name) || !param.value.is_null() {
            continue;
        }

        eprintln!();
        eprintln!("Parameter required: {name}");
        let type_label = match param.declared_type {
            rite_model::ParameterType::String => "string",
            rite_model::ParameterType::Date => "date",
            rite_model::ParameterType::Integer => "integer",
            rite_model::ParameterType::Boolean => "boolean",
            _ => "unknown",
        };
        eprintln!("  Type: {type_label}");
        if let Some(desc) = &param.description {
            eprintln!("  Description: {desc}");
        }
        eprint!("Enter value: ");

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_ok() {
            let value = line.trim_end().to_string();
            if !value.is_empty() {
                inputs
                    .parameters
                    .insert(name.to_string(), serde_json::Value::String(value));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_key_value_splits_on_first_equals() {
        assert_eq!(
            parse_key_value("key=value").unwrap(),
            ("key".to_string(), "value".to_string())
        );
    }

    #[test]
    fn parse_key_value_value_may_contain_equals() {
        assert_eq!(
            parse_key_value("key=val=ue").unwrap(),
            ("key".to_string(), "val=ue".to_string())
        );
    }

    #[test]
    fn parse_key_value_empty_key_is_error() {
        assert!(parse_key_value("=value").is_err());
    }

    #[test]
    fn parse_key_value_no_equals_is_error() {
        assert!(parse_key_value("noequals").is_err());
    }

    #[test]
    fn parse_material_value_at_prefix_is_file() {
        let source = parse_material_value("@/some/path.pem");
        assert!(matches!(source, MaterialSource::File { file } if file.ends_with("some/path.pem")));
    }

    #[test]
    fn parse_material_value_no_at_is_identifier() {
        let source = parse_material_value("my-identifier");
        assert!(
            matches!(source, MaterialSource::Identifier { identifier } if identifier == "my-identifier")
        );
    }

    #[test]
    fn build_inputs_normalizes_cli_keys_to_lowercase() {
        let inputs = build_inputs(
            &["Param_Name=value".to_string()],
            &["Role_ID=Alice".to_string()],
            &["Material_ID=@file.pem".to_string()],
        )
        .expect("inputs build");

        assert!(inputs.parameters.contains_key("param_name"));
        assert!(inputs.roles.contains_key("role_id"));
        assert!(inputs.materials.contains_key("material_id"));
    }
}
