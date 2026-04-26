//! Script structure types for organizing ceremony data.
//!
//! These types group steps by section and act for display in generated scripts.

use rite_model::{ActId, Ceremony, PostCeremonyDuty, Section, SectionId, Step};
use std::collections::HashMap;

/// Organized ceremony structure for script generation.
pub struct ScriptStructure<'a> {
    /// Acts in order, each containing their sections and steps.
    pub acts: Vec<ActGroup<'a>>,
    /// Post-ceremony duties in declaration order.
    pub post_ceremony: Vec<&'a PostCeremonyDuty>,
}

/// A group of sections belonging to one act.
pub struct ActGroup<'a> {
    /// Act identifier (None for the implicit single-act case).
    pub act_id: Option<ActId>,
    /// Human-readable act name.
    pub act_name: Option<String>,
    /// Act preamble/description.
    pub act_description: Option<String>,
    /// 1-based act number for display.
    pub act_number: usize,
    /// Sections belonging to this act, in order.
    pub sections: Vec<SectionGroup<'a>>,
}

/// A group of steps belonging to one section.
pub struct SectionGroup<'a> {
    /// The section.
    pub section: &'a Section,
    /// Steps in this section, in execution order.
    pub steps: Vec<&'a Step>,
}

/// Build the hierarchical structure for script generation.
///
/// Groups steps by section and sections by act, using the execution plan order.
pub fn build_script_structure(resolved: &Ceremony) -> ScriptStructure<'_> {
    let mut section_steps: HashMap<&SectionId, Vec<&Step>> = HashMap::new();
    for step in &resolved.execution_plan {
        section_steps.entry(&step.section).or_default().push(step);
    }

    let mut act_sections: HashMap<Option<&ActId>, Vec<&Section>> = HashMap::new();
    for (_, section) in resolved.sections.iter() {
        act_sections
            .entry(section.act.as_ref())
            .or_default()
            .push(section);
    }

    let mut acts = Vec::new();

    if resolved.acts.is_empty() {
        let sections = build_section_groups(
            &section_steps,
            act_sections.get(&None).map_or(&[], Vec::as_slice),
        );
        acts.push(ActGroup {
            act_id: None,
            act_name: None,
            act_description: None,
            act_number: 1,
            sections,
        });
    } else {
        #[allow(clippy::arithmetic_side_effects)]
        for (i, (act_id, act)) in resolved.acts.iter().enumerate() {
            let sections = build_section_groups(
                &section_steps,
                act_sections.get(&Some(act_id)).map_or(&[], Vec::as_slice),
            );
            acts.push(ActGroup {
                act_id: Some(act_id.clone()),
                act_name: act.name.clone(),
                act_description: act.description.clone(),
                act_number: i + 1,
                sections,
            });
        }

        #[allow(clippy::arithmetic_side_effects)]
        if let Some(orphan_sections) = act_sections.get(&None)
            && !orphan_sections.is_empty()
        {
            let sections = build_section_groups(&section_steps, orphan_sections);
            acts.push(ActGroup {
                act_id: None,
                act_name: None,
                act_description: None,
                act_number: acts.len() + 1,
                sections,
            });
        }
    }

    let post_ceremony = resolved.after.iter().collect();

    ScriptStructure {
        acts,
        post_ceremony,
    }
}

fn build_section_groups<'a>(
    section_steps: &HashMap<&SectionId, Vec<&'a Step>>,
    sections: &[&'a Section],
) -> Vec<SectionGroup<'a>> {
    sections
        .iter()
        .map(|section| {
            let steps = section_steps.get(&section.id).cloned().unwrap_or_default();
            SectionGroup { section, steps }
        })
        .collect()
}
