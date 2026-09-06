//! Shared helpers for input assembly and pre-flight checks.

use clap::{Args, ValueEnum};
use rite_model::{Ceremony, MaterialKind, MaterialSource};
use rite_render::{Branding, Theme};
use rite_resolver::CeremonyInputs;
use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Input flags shared by `check`, `run`, and `script`.
#[derive(Args, Debug)]
pub struct InputArgs {
    /// Set a ceremony parameter
    #[arg(long = "param", value_name = "NAME=VALUE")]
    pub params: Vec<String>,
    /// Assign a person to a role
    #[arg(long = "role", value_name = "ROLE_ID=PERSON")]
    pub roles: Vec<String>,
    /// Provide a material source
    ///
    /// Use `NAME=@PATH` for a file on disk, or `NAME=IDENTIFIER` for a
    /// pre-provisioned material.
    #[arg(long = "material", value_name = "NAME=PATH_OR_ID")]
    pub materials: Vec<String>,
}

/// Long-help footer listing the input environment variables. Shown on the
/// `--help` of every command that loads a ceremony (`check`, `run`, `script`).
pub const INPUT_ENV_HELP: &str = "\
Environment variables:
  RITE_PARAM_<NAME>     Set a ceremony parameter (like --param)
  RITE_ROLE_<ROLE_ID>   Assign a person to a role (like --role)
  RITE_MATERIAL_<NAME>  Provide a material source (like --material)

The name after the prefix is case-insensitive (RITE_ROLE_CRYPTO_OFFICER and
RITE_ROLE_crypto_officer are equivalent).
A command-line flag takes precedence over the matching variable.";

/// Built-in document theme, shared by `script` and `report`.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub enum ThemeArg {
    /// Formal serif "ceremony protocol" look.
    #[default]
    Formal,
}

impl From<ThemeArg> for Theme {
    fn from(arg: ThemeArg) -> Self {
        match arg {
            ThemeArg::Formal => Theme::Formal,
        }
    }
}

/// Branding overrides applied on top of a built-in theme.
#[derive(Args, Debug)]
pub struct BrandingArgs {
    /// Organization name in the header
    #[arg(long, value_name = "NAME")]
    pub brand_name: Option<String>,
    /// Logo image for the header
    #[arg(long, value_name = "PATH")]
    pub logo: Option<PathBuf>,
    /// Accent color (hex, e.g. `#1f3a5f`)
    #[arg(long, value_name = "COLOR")]
    pub accent: Option<String>,
}

/// Assemble [`Branding`] from CLI flags, printing an error and exiting on failure.
pub fn build_branding_or_exit(args: &BrandingArgs) -> Branding {
    let logo = args.logo.as_ref().map(|path| {
        let bytes = std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("Failed to read logo {}: {e}", path.display());
            std::process::exit(1);
        });
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("logo")
            .to_string();
        (bytes, name)
    });

    Branding::from_inputs(
        args.brand_name.clone(),
        logo.as_ref()
            .map(|(bytes, name)| (bytes.as_slice(), name.as_str())),
        args.accent.as_deref(),
    )
    .unwrap_or_else(|e| {
        eprintln!("Invalid argument: {e}");
        std::process::exit(1);
    })
}

/// Default output path for a generated document: the source file's stem with a
/// new extension, written next to the source.
///
/// Strips the compound `.rite.yaml` / `.rite.yml` suffix (and a plain `.yaml` /
/// `.yml`) so `pki/root_ca.rite.yaml` becomes `pki/root_ca.<extension>`.
pub fn default_output_path(source: &Path, extension: &str) -> PathBuf {
    let name = source
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ceremony");
    let name = name
        .strip_suffix(".yaml")
        .or_else(|| name.strip_suffix(".yml"))
        .unwrap_or(name);
    let stem = name.strip_suffix(".rite").unwrap_or(name);
    source.with_file_name(format!("{stem}.{extension}"))
}

/// Write a rendered document to its destination, printing an error and exiting
/// on failure.
///
/// `output` carries the `--output` flag: `None` writes to `default`, `Some("-")`
/// writes to stdout, and any other path is written verbatim. File writes print a
/// confirmation to stderr; stdout output is left clean so it can be piped.
pub fn write_document(content: &str, output: Option<&Path>, default: &Path) {
    let target = match output {
        Some(p) if p.as_os_str() == "-" => {
            print!("{content}");
            return;
        }
        Some(p) => p,
        None => default,
    };

    if let Err(e) = std::fs::write(target, content) {
        eprintln!("Failed to write output to {}: {e}", target.display());
        std::process::exit(1);
    }
    eprintln!("Wrote {}", target.display());
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
    resolve_with_spans_or_exit(path, inputs).0
}

/// Resolve a ceremony file and keep the span map, printing diagnostics and
/// exiting on failure.
///
/// Used by `check`, which reports handler-level findings of its own and needs
/// somewhere in the source to point them at.
pub fn resolve_with_spans_or_exit(
    path: &Path,
    inputs: Option<&CeremonyInputs>,
) -> (Ceremony, rite_resolver::SpanMap) {
    let (resolved_opt, spans, diags) = rite_resolver::analyze_with_spans(path, inputs);

    for d in &diags {
        eprintln!("{d}");
    }

    let has_errors = diags
        .iter()
        .any(|d| d.severity == rite_resolver::Severity::Error);

    if has_errors {
        std::process::exit(1);
    }

    let resolved = resolved_opt.unwrap_or_else(|| {
        eprintln!("Internal error: ceremony resolved to None with no errors");
        std::process::exit(1);
    });
    (resolved, spans)
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

/// Names of actions in the execution plan that *this* build has no handler for.
///
/// "Unsupported" is relative to the running binary: an action is missing only
/// because the crate was compiled without the feature that registers it (e.g.
/// `piv`). It is not a defect in the ceremony definition.
///
/// This is why `check` and `run` treat the result differently. `check`
/// validates the definition and only *warns*, because the binary that
/// eventually executes may be a fuller build than the one running `check`
/// (a laptop or CI runner validating a ceremony that an air-gapped machine will
/// run). `run` *is* the executor, so a missing feature is fatal and should
/// abort before any hardware is touched or transcript written.
///
/// Returns the action names in first-occurrence order, deduplicated. Empty when
/// the build supports every action the plan uses.
#[must_use]
pub fn unsupported_action_names(resolved: &Ceremony) -> Vec<String> {
    registry()
        .unsupported_actions(&resolved.execution_plan)
        .iter()
        .map(ToString::to_string)
        .collect()
}

/// The stdlib action registry for this build.
///
/// Which handlers it holds is fixed at compile time, so one instance serves
/// every pre-flight in a run of the CLI.
fn registry() -> &'static rite_runtime::ActionRegistry {
    static REGISTRY: std::sync::OnceLock<rite_runtime::ActionRegistry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(rite_stdlib::default_registry)
}

/// Ask each step's handler what is wrong with its `with:` block.
///
/// Each finding carries a [`rite_runtime::ParamIssueKind`] saying whether it
/// condemns the document or only this build, which is the same split
/// [`unsupported_action_names`] rests on.
#[must_use]
pub fn step_param_issues(resolved: &Ceremony) -> Vec<rite_runtime::StepParamIssue> {
    registry().validate_steps(&resolved.execution_plan)
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
    fn default_output_path_strips_compound_rite_yaml() {
        assert_eq!(
            default_output_path(Path::new("pki/root_ca.rite.yaml"), "html"),
            PathBuf::from("pki/root_ca.html")
        );
    }

    #[test]
    fn default_output_path_handles_plain_yaml_and_yml() {
        assert_eq!(
            default_output_path(Path::new("foo.yaml"), "html"),
            PathBuf::from("foo.html")
        );
        assert_eq!(
            default_output_path(Path::new("foo.rite.yml"), "typ"),
            PathBuf::from("foo.typ")
        );
    }

    #[test]
    fn default_output_path_keeps_intermediate_dots() {
        assert_eq!(
            default_output_path(Path::new("my.config.rite.yaml"), "html"),
            PathBuf::from("my.config.html")
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
