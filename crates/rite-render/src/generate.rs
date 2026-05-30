//! HTML generation for ceremony scripts.

#![allow(clippy::format_push_string)]

use crate::html::{capitalize_words, escape_html, json_value_to_string, render_duty};
use crate::structure::build_script_structure;
use crate::theme::THEME_CSS;
use rite_model::expression::ExprValue;
use rite_model::{Ceremony, ParamId, Step};

/// Generate an HTML ceremony script.
///
/// The generated HTML is suitable for printing (File → Print → Save as PDF).
/// Uses IANA-style step numbering (act.step format: 1.1, 1.2, 2.1, 2.2...).
///
/// TODO: replace with a template engine so organisations can provide custom themes and layouts.
#[allow(clippy::too_many_lines)]
pub fn generate_html(resolved: &Ceremony) -> String {
    let structure = build_script_structure(resolved);
    let css = THEME_CSS;
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str(&format!(
        "  <title>{}</title>\n",
        escape_html(&resolved.metadata.name)
    ));
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <style>\n");
    html.push_str(css);
    html.push_str("  </style>\n");
    html.push_str("</head>\n<body>\n");

    html.push_str(&format!(
        "  <h1>{}</h1>\n",
        escape_html(&resolved.metadata.name)
    ));

    html.push_str("  <div class=\"metadata\">\n");

    if let Some(date_param) = resolved.parameters.get(&ParamId::new("ceremony_date")) {
        let date_str = json_value_to_string(&date_param.value);
        html.push_str(&format!(
            "    <p><strong>Ceremony Date:</strong> {}</p>\n",
            escape_html(&date_str)
        ));
    }

    let mut params: Vec<_> = resolved
        .parameters
        .iter()
        .filter(|(id, _)| id.as_str() != "ceremony_date")
        .collect();
    params.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    for (param_id, param) in params {
        let display_key = capitalize_words(&param_id.as_str().replace('_', " "));
        let value_str = json_value_to_string(&param.value);
        html.push_str(&format!(
            "    <p><strong>{}:</strong> {}</p>\n",
            escape_html(&display_key),
            escape_html(&value_str)
        ));
    }
    html.push_str("  </div>\n\n");

    if let Some(desc) = &resolved.metadata.description {
        html.push_str("  <h2>Overview</h2>\n");
        html.push_str(&format!(
            "  <p class=\"overview\">{}</p>\n\n",
            escape_html(desc)
        ));
    }

    html.push_str("  <h2>Roles</h2>\n");
    html.push_str("  <ul class=\"roles\">\n");
    for (_, role) in resolved.roles.iter() {
        let role_desc = match &role.person {
            Some(person) => format!(
                "<strong>{}</strong> \u{2014} {}",
                escape_html(&role.name),
                escape_html(person)
            ),
            None => format!("<strong>{}</strong>", escape_html(&role.name)),
        };
        html.push_str(&format!("    <li>{role_desc}</li>\n"));
    }
    html.push_str("  </ul>\n\n");

    let has_physical = resolved.materials.iter().any(|(_, m)| m.is_physical());
    let has_digital = resolved.materials.iter().any(|(_, m)| m.is_digital());
    let has_prerequisites = !resolved.prerequisites.is_empty();

    if has_physical || has_digital || has_prerequisites {
        html.push_str("  <h2>Preparation Checklist</h2>\n");

        if has_physical {
            html.push_str("  <h3>Physical Materials</h3>\n");
            html.push_str("  <ul class=\"checklist\">\n");
            for (_id, material) in resolved.materials.iter().filter(|(_, m)| m.is_physical()) {
                let mut item = format!("<strong>{}</strong>", material.display_name());
                if let Some(desc) = &material.description {
                    item.push_str(&format!(" \u{2014} {}", escape_html(desc)));
                }
                html.push_str(&format!("    <li>{item}</li>\n"));
            }
            html.push_str("  </ul>\n");
        }

        if has_prerequisites {
            html.push_str("  <h3>Prerequisites</h3>\n");
            html.push_str("  <ul class=\"checklist\">\n");
            for prereq in &resolved.prerequisites {
                html.push_str(&format!("    <li>{}</li>\n", escape_html(prereq)));
            }
            html.push_str("  </ul>\n");
        }

        if has_digital {
            html.push_str("  <h3>Digital Materials</h3>\n");
            html.push_str("  <p><em>Verify digital material sources before ceremony</em></p>\n");
            html.push_str("  <ul class=\"checklist\">\n");
            for (id, material) in resolved.materials.iter().filter(|(_, m)| m.is_digital()) {
                let mut item = format!("<strong>{}</strong>", id.as_str());
                if let Some(desc) = &material.description {
                    item.push_str(&format!(" \u{2014} {}", escape_html(desc)));
                }
                html.push_str(&format!("    <li>{item}</li>\n"));
            }
            html.push_str("  </ul>\n");
        }

        html.push('\n');
    }

    let has_named_acts = !resolved.acts.is_empty();

    for act_group in &structure.acts {
        if has_named_acts {
            let act_name = act_group
                .act_name
                .as_deref()
                .or_else(|| act_group.act_id.as_ref().map(rite_model::ActId::as_str))
                .unwrap_or("Main Ceremony");
            html.push_str(&format!(
                "  <div class=\"act-header\">Act {}: {}</div>\n",
                act_group.act_number,
                escape_html(act_name)
            ));

            if let Some(desc) = &act_group.act_description {
                html.push_str(&format!(
                    "  <p class=\"act-preamble\">{}</p>\n",
                    escape_html(desc)
                ));
            }
        }

        for section_group in &act_group.sections {
            let section_name = section_group
                .section
                .name
                .as_deref()
                .unwrap_or(section_group.section.id.as_str());
            html.push_str(&format!(
                "  <h3 class=\"section-header\">{}</h3>\n",
                escape_html(section_name)
            ));

            if let Some(desc) = &section_group.section.description {
                html.push_str(&format!(
                    "  <p class=\"section-description\">{}</p>\n",
                    escape_html(desc)
                ));
            }

            for step in &section_group.steps {
                if !step.preconditions.is_empty() {
                    html.push_str("    <div class=\"preconditions\">\n");
                    html.push_str(&format!(
                        "      <p><em>Before step {} ({}):</em></p>\n",
                        &step.step_label,
                        escape_html(step.id.as_str())
                    ));
                    html.push_str("      <ul class=\"checklist\">\n");
                    for precondition in &step.preconditions {
                        html.push_str(&format!("        <li>{}</li>\n", escape_html(precondition)));
                    }
                    html.push_str("      </ul>\n");
                    html.push_str("    </div>\n");
                }
            }

            if !section_group.steps.is_empty() {
                html.push_str("  <table>\n");
                html.push_str("    <thead>\n");
                html.push_str("      <tr>\n");
                html.push_str("        <th class=\"step-num\">Step</th>\n");
                html.push_str("        <th>Activity</th>\n");
                html.push_str("        <th class=\"role\">Role</th>\n");
                html.push_str("      </tr>\n");
                html.push_str("    </thead>\n");
                html.push_str("    <tbody>\n");

                for step in &section_group.steps {
                    let activity = get_step_prose(step);
                    let role_name = step
                        .role
                        .as_ref()
                        .and_then(|role_id| resolved.roles.get(role_id))
                        .map_or("\u{2014}", |r| r.name.as_str());

                    html.push_str("      <tr>\n");
                    html.push_str(&format!(
                        "        <td class=\"step-num\">{}</td>\n",
                        step.step_label
                    ));
                    html.push_str(&format!("        <td>{}</td>\n", escape_html(&activity)));
                    html.push_str(&format!(
                        "        <td class=\"role\">{}</td>\n",
                        escape_html(role_name)
                    ));
                    html.push_str("      </tr>\n");
                }

                html.push_str("    </tbody>\n");
                html.push_str("  </table>\n\n");
            }
        }
    }

    if !resolved.outputs.is_empty() {
        html.push_str("  <h2>Expected Outputs</h2>\n");
        html.push_str("  <ul class=\"outputs\">\n");
        let mut outputs: Vec<_> = resolved.outputs.iter().collect();
        outputs.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        for (id, output) in outputs {
            let mut out_desc = format!("<strong>{}</strong>: {}", id.as_str(), output.kind);
            if let Some(desc) = &output.description {
                out_desc.push_str(&format!(" \u{2014} {}", escape_html(desc)));
            }
            html.push_str(&format!("    <li>{out_desc}</li>\n"));
        }
        html.push_str("  </ul>\n\n");
    }

    html.push_str("  <h2>Transcript Fingerprint</h2>\n");
    html.push_str("  <p>At the end of the ceremony, the transcript fingerprint is displayed. Copy at least the first line (32 characters, shown in bold) into the field below before closing the terminal, while all participants are still present.</p>\n");
    html.push_str("  <div class=\"fingerprint-record\">\n");
    html.push_str("    <p><strong>sha256:</strong></p>\n");
    html.push_str(
        "    <p class=\"fingerprint-prefix\">__ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __</p>\n",
    );
    html.push_str(
        "    <p class=\"fingerprint-remainder\">__ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __</p>\n",
    );
    html.push_str("  </div>\n\n");

    if !structure.post_ceremony.is_empty() {
        html.push_str("  <h2>Post-Ceremony Duties</h2>\n");
        html.push_str("  <p class=\"duties-intro\">The following duties must be completed after the ceremony concludes.</p>\n");
        for duty in &structure.post_ceremony {
            html.push_str(&render_duty(duty, resolved));
        }
        html.push('\n');
    }

    html.push_str("  <h2>Signatures</h2>\n");
    html.push_str("  <p>By signing below, each participant attests to the accuracy and completeness of this ceremony.</p>\n");
    html.push_str("  <div class=\"signatures\">\n");
    for (_, role) in resolved.roles.iter() {
        let name_line = match &role.person {
            Some(person) => format!("Name: {}", escape_html(person)),
            None => "Name: ___________________".to_string(),
        };
        html.push_str(&format!(
            "    <div class=\"signature-block\">\n      <p><strong>{}</strong></p>\n      <p>{name_line}</p>\n      <p>Signature: _________________________ Date: ___________</p>\n    </div>\n",
            escape_html(&role.name),
        ));
    }
    html.push_str("  </div>\n");

    html.push_str("</body>\n</html>\n");

    html
}

fn get_step_prose(step: &Step) -> String {
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
