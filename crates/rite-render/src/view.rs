//! Template view models for Rite document generation.
//!
//! These are the flat, `serde::Serialize` shapes that the built-in theme
//! templates consume. They deliberately sit between the resolved
//! [`rite_model::Ceremony`] IR (for scripts) / [`crate::report::ReportData`]
//! (for reports) and the templates, so the IR can evolve without rewriting
//! every theme.
//!
//! # Stability
//!
//! This shape is **not** a stable contract. Only the built-in themes consume
//! it, and it may change between releases. A documented, versioned context is
//! future work, to be settled if and when user-supplied templates are exposed.

use crate::html::{capitalize_words, json_value_to_string};
use crate::structure::build_script_structure;
use base64ct::{Base64, Encoding};
use chrono::{DateTime, Duration, Utc};
use minijinja::HtmlEscape;
use rite_model::expression::ExprValue;
use rite_model::{Ceremony, MaterialKind, ParamId, RoleId, Step};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Optional run-time branding applied on top of any built-in theme.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Branding {
    /// Organization conducting the ceremony, shown in the header.
    pub brand_name: Option<String>,
    /// Logo as a self-contained `data:` URI (embedded, not linked).
    pub logo_data_uri: Option<String>,
    /// Validated CSS accent color (hex), injected as the `--accent` variable.
    pub accent: Option<String>,
}

impl Branding {
    /// Assemble branding from raw CLI inputs.
    ///
    /// `logo` is the raw file bytes paired with the original file name (used to
    /// infer the MIME type). `accent` is validated as a hex CSS color.
    ///
    /// # Errors
    ///
    /// Returns an error string when `accent` is not a valid hex color.
    pub fn from_inputs(
        brand_name: Option<String>,
        logo: Option<(&[u8], &str)>,
        accent: Option<&str>,
    ) -> Result<Self, String> {
        let accent = match accent {
            Some(raw) => Some(validate_accent(raw)?),
            None => None,
        };
        let logo_data_uri = logo.map(|(bytes, name)| encode_logo(bytes, name));
        Ok(Self {
            brand_name,
            logo_data_uri,
            accent,
        })
    }
}

/// Validate and normalize a CSS hex color (`#rgb`, `#rgba`, `#rrggbb`, `#rrggbbaa`).
///
/// Branding accent values land directly in a stylesheet, so only a strict hex
/// form is accepted; anything else is rejected to avoid injecting arbitrary CSS.
///
/// # Errors
///
/// Returns an error string when the input is not one of the accepted hex forms.
pub fn validate_accent(raw: &str) -> Result<String, String> {
    let invalid = || format!("invalid accent color '{raw}': expected a hex color like #1f3a5f");
    let hex = raw.trim().strip_prefix('#').ok_or_else(invalid)?;
    if matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(format!("#{}", hex.to_ascii_lowercase()))
    } else {
        Err(invalid())
    }
}

/// Encode logo bytes as a `data:` URI, inferring the MIME type from the file name.
fn encode_logo(bytes: &[u8], file_name: &str) -> String {
    let mime = match file_name
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        _ => "application/octet-stream",
    };
    let encoded = Base64::encode_string(bytes);
    format!("data:{mime};base64,{encoded}")
}

/// Top-level context for the ceremony script templates.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptView {
    /// Ceremony name (document title).
    pub title: String,
    /// Overview prose, if present.
    pub description: Option<String>,
    /// The `ceremony_date` parameter value, if declared.
    pub ceremony_date: Option<String>,
    /// Remaining parameters (excluding `ceremony_date`), sorted by name.
    pub parameters: Vec<ParamView>,
    /// Roles in declaration order, with abbreviations.
    pub roles: Vec<RoleView>,
    /// Physical materials for the preparation checklist.
    pub physical_materials: Vec<MaterialView>,
    /// Digital materials for the preparation checklist.
    pub digital_materials: Vec<MaterialView>,
    /// Prose prerequisites for the preparation checklist.
    pub prerequisites: Vec<String>,
    /// Whether any preparation content exists (materials or prerequisites).
    pub has_preparation: bool,
    /// Whether the ceremony declares named acts (drives act headers).
    pub has_named_acts: bool,
    /// Acts in execution order.
    pub acts: Vec<ActView>,
    /// Declared outputs, sorted by id.
    pub outputs: Vec<OutputView>,
    /// Post-ceremony duties in declaration order.
    pub post_ceremony: Vec<DutyView>,
}

/// A role as displayed in the script.
#[derive(Debug, Clone, Serialize)]
pub struct RoleView {
    /// Human-readable role name.
    pub name: String,
    /// Short abbreviation (unique within the ceremony).
    pub abbrev: String,
    /// Assigned person, if any.
    pub person: Option<String>,
}

/// A displayed parameter row.
#[derive(Debug, Clone, Serialize)]
pub struct ParamView {
    /// Title-cased label.
    pub label: String,
    /// Stringified value.
    pub value: String,
}

/// A material checklist entry.
#[derive(Debug, Clone, Serialize)]
pub struct MaterialView {
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Human-readable identifier for a physical item (serial, label, batch code).
    pub identifier: Option<String>,
    /// Quantity to bring, for physical items appearing more than once.
    pub quantity: Option<u32>,
}

/// An act grouping sections.
#[derive(Debug, Clone, Serialize)]
pub struct ActView {
    /// 1-based act number.
    pub number: usize,
    /// Act name, if any.
    pub name: Option<String>,
    /// Act preamble, if any.
    pub description: Option<String>,
    /// Sections in this act.
    pub sections: Vec<SectionView>,
}

/// A section grouping steps.
#[derive(Debug, Clone, Serialize)]
pub struct SectionView {
    /// Section name (falls back to its id).
    pub name: String,
    /// Section description, if any.
    pub description: Option<String>,
    /// Steps in execution order.
    pub steps: Vec<StepView>,
}

/// A single step row.
#[derive(Debug, Clone, Serialize)]
pub struct StepView {
    /// Display label (e.g. `1.2`).
    pub label: String,
    /// Resolved human-readable instruction.
    pub prose: String,
    /// Role name, or an em-dash when unassigned.
    pub role_name: String,
    /// Role abbreviation, when a role is assigned.
    pub role_abbrev: Option<String>,
    /// Preconditions to confirm before this step.
    pub preconditions: Vec<String>,
    /// Pre-built "Before step …" label for the preconditions box.
    pub precondition_label: Option<String>,
}

/// A declared output.
#[derive(Debug, Clone, Serialize)]
pub struct OutputView {
    /// Output id.
    pub id: String,
    /// Output type.
    pub kind: String,
    /// Optional description.
    pub description: Option<String>,
}

/// A post-ceremony duty.
#[derive(Debug, Clone, Serialize)]
pub struct DutyView {
    /// Duty name (e.g. "Archive Materials").
    pub heading: String,
    /// Responsible role name, if the duty assigns one.
    pub role: Option<String>,
    /// Prose description (explicit or built-in).
    pub prose: Option<String>,
    /// Checklist sub-items.
    pub items: Vec<String>,
    /// Recipient, for distribute-style duties.
    pub recipient: Option<String>,
    /// Location, for storage-style duties.
    pub location: Option<String>,
}

impl ScriptView {
    /// Build a script view from a fully resolved ceremony.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn from_ceremony(resolved: &Ceremony) -> Self {
        let structure = build_script_structure(resolved);

        let ceremony_date = resolved
            .parameters
            .get(&ParamId::new("ceremony_date"))
            .map(|p| json_value_to_string(&p.value));

        let mut params: Vec<_> = resolved
            .parameters
            .iter()
            .filter(|(id, _)| id.as_str() != "ceremony_date")
            .collect();
        params.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let parameters = params
            .into_iter()
            .map(|(id, param)| ParamView {
                label: capitalize_words(&id.as_str().replace('_', " ")),
                value: json_value_to_string(&param.value),
            })
            .collect();

        let abbrevs = build_abbrevs(resolved);
        let roles = resolved
            .roles
            .iter()
            .map(|(id, role)| RoleView {
                name: role.name.clone(),
                abbrev: abbrevs
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| role.name.clone()),
                person: role.person.clone(),
            })
            .collect();

        let physical_materials = resolved
            .materials
            .iter()
            .filter(|(_, m)| m.is_physical())
            .map(|(_, m)| {
                let (identifier, quantity) = match &m.kind {
                    MaterialKind::Physical {
                        identifier,
                        quantity,
                    } => (identifier.clone(), *quantity),
                    MaterialKind::Digital { .. } => (None, None),
                };
                MaterialView {
                    name: m.display_name().to_string(),
                    description: m.description.clone(),
                    identifier,
                    quantity,
                }
            })
            .collect::<Vec<_>>();
        let digital_materials = resolved
            .materials
            .iter()
            .filter(|(_, m)| m.is_digital())
            .map(|(_, m)| MaterialView {
                name: m.display_name().to_string(),
                description: m.description.clone(),
                identifier: None,
                quantity: None,
            })
            .collect::<Vec<_>>();
        let prerequisites = resolved.prerequisites.clone();
        let has_preparation = !physical_materials.is_empty()
            || !digital_materials.is_empty()
            || !prerequisites.is_empty();

        let has_named_acts = !resolved.acts.is_empty();
        let acts = structure
            .acts
            .iter()
            .map(|act| ActView {
                number: act.act_number,
                name: act.act_name.clone(),
                description: act.act_description.clone(),
                sections: act
                    .sections
                    .iter()
                    .map(|sg| SectionView {
                        name: sg
                            .section
                            .name
                            .clone()
                            .unwrap_or_else(|| sg.section.id.as_str().to_string()),
                        description: sg.section.description.clone(),
                        steps: sg
                            .steps
                            .iter()
                            .map(|step| step_view(step, resolved, &abbrevs))
                            .collect(),
                    })
                    .collect(),
            })
            .collect();

        let mut outputs: Vec<_> = resolved.outputs.iter().collect();
        outputs.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        let outputs = outputs
            .into_iter()
            .map(|(id, output)| OutputView {
                id: id.as_str().to_string(),
                kind: output.kind.to_string(),
                description: output.description.clone(),
            })
            .collect();

        let post_ceremony = structure
            .post_ceremony
            .iter()
            .map(|duty| {
                let role = duty.role.as_ref().map(|role_id| {
                    resolved
                        .roles
                        .get(role_id)
                        .map_or_else(|| role_id.as_str().to_string(), |r| r.name.clone())
                });
                DutyView {
                    heading: duty.kind.display_name().to_string(),
                    role,
                    prose: duty
                        .description
                        .clone()
                        .or_else(|| duty.kind.built_in_prose().map(ToString::to_string)),
                    items: duty.items.clone(),
                    recipient: duty.recipient.clone(),
                    location: duty.location.clone(),
                }
            })
            .collect();

        Self {
            title: resolved.metadata.name.clone(),
            description: resolved.metadata.description.clone(),
            ceremony_date,
            parameters,
            roles,
            physical_materials,
            digital_materials,
            prerequisites,
            has_preparation,
            has_named_acts,
            acts,
            outputs,
            post_ceremony,
        }
    }
}

fn step_view(step: &Step, resolved: &Ceremony, abbrevs: &HashMap<RoleId, String>) -> StepView {
    let (role_name, role_abbrev) = match &step.role {
        Some(role_id) => {
            let name = resolved
                .roles
                .get(role_id)
                .map_or_else(|| role_id.as_str().to_string(), |r| r.name.clone());
            (name, abbrevs.get(role_id).cloned())
        }
        None => ("\u{2013}".to_string(), None),
    };

    let precondition_label = (!step.preconditions.is_empty())
        .then(|| format!("Before step {} ({}):", step.step_label, step.id.as_str()));

    StepView {
        label: step.step_label.clone(),
        prose: step_prose(step),
        role_name,
        role_abbrev,
        preconditions: step.preconditions.clone(),
        precondition_label,
    }
}

/// Resolve the human-readable instruction for a step.
///
/// Precedence: explicit description, then a `message`/`statement` parameter,
/// then the action's built-in description.
fn step_prose(step: &Step) -> String {
    if let Some(desc) = &step.description {
        return desc.to_display_string();
    }
    if let Some(msg) = step
        .with
        .get("message")
        .and_then(ExprValue::as_literal_string)
    {
        return msg.to_string();
    }
    if let Some(stmt) = step
        .with
        .get("statement")
        .and_then(ExprValue::as_literal_string)
    {
        return format!("Attest: \"{stmt}\"");
    }
    step.action.describe().to_string()
}

/// Render a multi-line instruction string as safe HTML.
///
/// Blank lines separate paragraphs; runs of lines beginning with `- ` or `* `
/// become an unordered list. All text is HTML-escaped. This lets ceremony
/// authors write full paragraphs and bullet lists in a step description and
/// have them render structurally rather than as one run-on line.
#[must_use]
pub(crate) fn render_prose_html(text: &str) -> String {
    let mut out = String::new();
    let mut paragraph: Vec<&str> = Vec::new();
    let mut bullets: Vec<&str> = Vec::new();

    let flush_paragraph = |out: &mut String, paragraph: &mut Vec<&str>| {
        if !paragraph.is_empty() {
            out.push_str("<p>");
            out.push_str(&HtmlEscape(&paragraph.join(" ")).to_string());
            out.push_str("</p>");
            paragraph.clear();
        }
    };
    let flush_bullets = |out: &mut String, bullets: &mut Vec<&str>| {
        if !bullets.is_empty() {
            out.push_str("<ul class=\"prose-list\">");
            for item in bullets.iter() {
                out.push_str("<li>");
                out.push_str(&HtmlEscape(item).to_string());
                out.push_str("</li>");
            }
            out.push_str("</ul>");
            bullets.clear();
        }
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush_bullets(&mut out, &mut bullets);
            flush_paragraph(&mut out, &mut paragraph);
        } else if let Some(item) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            flush_paragraph(&mut out, &mut paragraph);
            bullets.push(item.trim());
        } else {
            flush_bullets(&mut out, &mut bullets);
            paragraph.push(trimmed);
        }
    }
    flush_bullets(&mut out, &mut bullets);
    flush_paragraph(&mut out, &mut paragraph);
    out
}

/// Build a deterministic, unique abbreviation for every role, keyed by id.
fn build_abbrevs(resolved: &Ceremony) -> HashMap<RoleId, String> {
    let mut used: HashSet<String> = HashSet::new();
    resolved
        .roles
        .iter()
        .map(|(id, role)| (id.clone(), unique_abbrev(&abbrev_of(&role.name), &mut used)))
        .collect()
}

/// Reserve a unique abbreviation derived from `base`, suffixing `2`, `3`, ...
/// on collision. Records the chosen value in `used` so later calls stay unique.
#[allow(clippy::arithmetic_side_effects)]
fn unique_abbrev(base: &str, used: &mut HashSet<String>) -> String {
    let mut candidate = base.to_string();
    let mut n = 2u32;
    while used.contains(&candidate) {
        candidate = format!("{base}{n}");
        n += 1;
    }
    used.insert(candidate.clone());
    candidate
}

/// Derive a short abbreviation from a role name.
///
/// Multi-word names use word initials (`Crypto Officer` → `CO`); single words
/// use their first two alphanumerics (`Witness` → `Wi`).
fn abbrev_of(name: &str) -> String {
    let initials: String = name
        .split_whitespace()
        .filter_map(|w| w.chars().next())
        .flat_map(char::to_uppercase)
        .collect();
    if initials.chars().count() >= 2 {
        return initials;
    }
    let mut chars = name.chars().filter(|c| c.is_alphanumeric());
    let mut out = String::new();
    if let Some(first) = chars.next() {
        out.extend(first.to_uppercase());
    }
    if let Some(second) = chars.next() {
        out.push(second);
    }
    if out.is_empty() { "?".to_string() } else { out }
}

/// Top-level context for the post-ceremony report templates.
#[derive(Debug, Clone, Serialize)]
pub struct ReportView {
    /// Ceremony name.
    pub ceremony_name: String,
    /// Lowercase status slug (drives the status CSS class).
    pub status_slug: String,
    /// Title-cased status label.
    pub status_display: String,
    /// Formatted start timestamp.
    pub started: String,
    /// Formatted completion timestamp, if reached.
    pub completed: Option<String>,
    /// Human-readable duration, when known.
    pub duration: Option<String>,
    /// Transcript fingerprint.
    pub transcript_fingerprint: String,
    /// Failure summary, when the ceremony failed.
    pub failure: Option<FailureView>,
    /// Failed step attempts (retries), across all steps.
    pub attempts: Vec<AttemptView>,
    /// Recorded deviations.
    pub deviations: Vec<DeviationView>,
    /// Produced artifacts.
    pub artifacts: Vec<ArtifactView>,
    /// Distinct roles seen in the log, with abbreviations (legend).
    pub roles: Vec<ReportRoleView>,
    /// Per-step execution log.
    pub steps: Vec<ExecStepView>,
    /// The `rite` version that produced the report.
    pub rite_version: String,
}

/// A failure summary in a report.
#[derive(Debug, Clone, Serialize)]
pub struct FailureView {
    /// Audit classification (environmental / procedural / integrity / abort).
    pub class: String,
    /// Stable error kind label.
    pub kind: String,
    /// Human-readable message.
    pub message: String,
}

/// A failed step attempt (a retry) in a report.
#[derive(Debug, Clone, Serialize)]
pub struct AttemptView {
    /// Step that failed.
    pub step_id: String,
    /// 1-based attempt number within the step.
    pub attempt: u32,
    /// Audit classification of the attempt's error.
    pub class: String,
    /// Stable error kind label.
    pub kind: String,
    /// Human-readable message.
    pub message: String,
    /// Formatted timestamp.
    pub recorded: String,
}

/// A recorded deviation in a report.
#[derive(Debug, Clone, Serialize)]
pub struct DeviationView {
    /// Formatted timestamp.
    pub recorded: String,
    /// Step id (may be empty).
    pub step_id: String,
    /// Verbatim deviation text.
    pub text: String,
}

/// A produced artifact in a report.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactView {
    /// Artifact name.
    pub name: String,
    /// Producing step id.
    pub step_id: String,
    /// Path on disk.
    pub path: String,
    /// Lowercase hex SHA-256.
    pub sha256: String,
}

/// A role in the report's roles legend.
#[derive(Debug, Clone, Serialize)]
pub struct ReportRoleView {
    /// Human-readable role name.
    pub name: String,
    /// Short abbreviation, unique within the report.
    pub abbrev: String,
}

/// A per-step row in the report execution log.
#[derive(Debug, Clone, Serialize)]
pub struct ExecStepView {
    /// Step id.
    pub step_id: String,
    /// Step label.
    pub label: String,
    /// Role name.
    pub role: String,
    /// Role abbreviation, matching the roles legend.
    pub role_abbrev: String,
    /// Formatted start timestamp.
    pub started: String,
    /// Formatted completion timestamp, if any.
    pub completed: Option<String>,
    /// Outcome summary.
    pub outcome: String,
}

impl ReportView {
    /// Build a report view from extracted report data.
    #[must_use]
    pub fn from_data(data: &crate::report::ReportData) -> Self {
        let status_slug = status_slug(data.status).to_string();
        let status_display = capitalize_words(&status_slug.replace('_', " "));
        let deviations = data
            .deviations
            .iter()
            .map(|d| DeviationView {
                recorded: format_datetime(&d.recorded_at),
                step_id: d.step_id.clone(),
                text: d.text.clone(),
            })
            .collect();
        let artifacts = data
            .artifacts
            .iter()
            .map(|a| ArtifactView {
                name: a.name.clone(),
                step_id: a.step_id.clone(),
                path: a.path.clone(),
                sha256: a.sha256.clone(),
            })
            .collect();
        let attempts = data
            .steps
            .iter()
            .flat_map(|s| {
                s.attempts.iter().map(move |a| AttemptView {
                    step_id: s.step_id.clone(),
                    attempt: a.attempt,
                    class: error_class_label(a.class).to_string(),
                    kind: a.kind.clone(),
                    message: a.message.clone(),
                    recorded: format_datetime(&a.failed_at),
                })
            })
            .collect();
        // The report is transcript-only, so roles come from the names recorded
        // in the log. Abbreviate them with the same helpers the script uses, so
        // a run's report and its script agree on `CO`, `Wi`, and so on.
        let mut used = HashSet::new();
        let mut roles: Vec<ReportRoleView> = Vec::new();
        for name in data.steps.iter().map(|s| &s.role) {
            if roles.iter().any(|r| &r.name == name) {
                continue;
            }
            roles.push(ReportRoleView {
                name: name.clone(),
                abbrev: unique_abbrev(&abbrev_of(name), &mut used),
            });
        }
        let abbrev_by_name: HashMap<&str, &str> = roles
            .iter()
            .map(|r| (r.name.as_str(), r.abbrev.as_str()))
            .collect();

        let steps = data
            .steps
            .iter()
            .map(|s| {
                let outcome = match &s.outcome_message {
                    Some(msg) => format!("{}, {msg}", s.outcome_status),
                    None => s.outcome_status.clone(),
                };
                ExecStepView {
                    step_id: s.step_id.clone(),
                    label: s.label.clone(),
                    role_abbrev: abbrev_by_name
                        .get(s.role.as_str())
                        .copied()
                        .unwrap_or_default()
                        .to_string(),
                    role: s.role.clone(),
                    started: format_datetime(&s.started_at),
                    completed: s.completed_at.as_ref().map(format_datetime),
                    outcome,
                }
            })
            .collect();

        Self {
            ceremony_name: data.ceremony_name.clone(),
            status_slug,
            status_display,
            started: format_datetime(&data.started_at),
            completed: data.completed_at.as_ref().map(format_datetime),
            duration: data
                .duration_seconds
                .map(|secs| crate::report::data::format_duration(Duration::seconds(secs))),
            transcript_fingerprint: data.transcript_fingerprint.clone(),
            failure: data.failure.as_ref().map(|f| FailureView {
                class: error_class_label(f.class).to_string(),
                kind: f.kind.clone(),
                message: f.message.clone(),
            }),
            attempts,
            deviations,
            artifacts,
            roles,
            steps,
            rite_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

fn status_slug(status: crate::report::ReportStatus) -> &'static str {
    use crate::report::ReportStatus;
    match status {
        ReportStatus::Completed => "completed",
        ReportStatus::Failed => "failed",
        ReportStatus::InProgress => "in_progress",
    }
}

fn error_class_label(class: rite_model::ErrorClass) -> &'static str {
    use rite_model::ErrorClass;
    match class {
        ErrorClass::Environmental => "environmental",
        ErrorClass::Procedural => "procedural",
        ErrorClass::Integrity => "integrity",
        ErrorClass::Abort => "abort",
        // `ErrorClass` is `#[non_exhaustive]`; a new variant renders generically
        // until it is given a label here.
        _ => "unknown",
    }
}

fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

#[cfg(test)]
mod tests {
    use super::{abbrev_of, render_prose_html};

    #[test]
    fn prose_single_line_is_one_paragraph() {
        assert_eq!(
            render_prose_html("Confirm readiness."),
            "<p>Confirm readiness.</p>"
        );
    }

    #[test]
    fn prose_blank_line_separates_paragraphs() {
        assert_eq!(
            render_prose_html("First.\n\nSecond."),
            "<p>First.</p><p>Second.</p>"
        );
    }

    #[test]
    fn prose_wrapped_lines_join_into_one_paragraph() {
        assert_eq!(
            render_prose_html("a line\nwrapped here"),
            "<p>a line wrapped here</p>"
        );
    }

    #[test]
    fn prose_bullets_become_a_list() {
        let html = render_prose_html("Check:\n- one\n- two");
        assert_eq!(
            html,
            "<p>Check:</p><ul class=\"prose-list\"><li>one</li><li>two</li></ul>"
        );
    }

    #[test]
    fn prose_escapes_html() {
        assert_eq!(render_prose_html("a < b & c"), "<p>a &lt; b &amp; c</p>");
    }

    #[test]
    fn abbrev_multi_word_uses_initials() {
        assert_eq!(abbrev_of("Crypto Officer"), "CO");
        assert_eq!(abbrev_of("Witness"), "Wi");
    }
}
