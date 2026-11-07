//! What keeps the wrapping table complete.
//!
//! The table is written by hand, so these checks are what make a missing row
//! a failure: a key without a case for some step, a scheme `wrap_key` is
//! never asked for, a form Rite writes that nothing from elsewhere opens.

use libtest_mimic::Trial;
use rite_sdk::{WrapDescription, WrapScheme, cms};

use super::cases::{FIXTURES, NOT_OPENED_FROM_ELSEWHERE, RECIPIENT_SHAPES, WRITES};
use super::fixture_path;
use super::model::{Form, Path, Read, Write, WriteStep};
use crate::harness::{coverage_trials, report};
use crate::keys::{TestKey, read};
use crate::session::Source;
use crate::shape::Shape;

pub fn trials() -> Vec<Trial> {
    coverage_trials!(
        "coverage::wrapping",
        every_shape_is_a_recipient_of_every_write_step,
        every_key_is_a_case_of_every_write_step,
        every_wrap_scheme_is_a_wrap_key_case,
        every_form_rite_writes_is_opened_from_elsewhere,
    )
}

/// Every key, under every write step and every path it can take, has a case
/// with the step's default scheme, so a step's answer for each key is
/// written down, whether that answer is a form or a refusal.
///
/// A symmetric key has no public half to be a recipient. Only a type Rite
/// names is generated: for any other, `rite check` refuses the name the same
/// way it refuses it on `import_key`, which the held row already says, and a
/// compressed key is an encoding of an imported one.
fn every_key_is_a_case_of_every_write_step() -> Result<(), String> {
    let mut missing = Vec::new();
    // The payloads are what a case wraps, never what it wraps to.
    for key in TestKey::ALL.iter().copied().filter(|key| !key.is_payload()) {
        for step in WriteStep::ALL.iter().copied() {
            for path in Path::ALL.iter().copied() {
                let takes_path = match path {
                    Path::Held(Source::Imported) => true,
                    Path::Held(Source::Generated) => key.rite().is_some() && !key.is_compressed(),
                    Path::Recipient(_) => !key.is_symmetric(),
                };
                if !takes_path {
                    continue;
                }
                let covered = WRITES.iter().any(|c| {
                    c.step == step && c.path == path && c.key == key && c.scheme.is_none()
                });
                if !covered {
                    missing.push(format!("{}::{}::{}", step.name(), path.name(), key.stem()));
                }
            }
        }
    }
    report("cases missing", &missing)
}

fn every_wrap_scheme_is_a_wrap_key_case() -> Result<(), String> {
    let missing: Vec<String> = WrapScheme::ALL
        .iter()
        .filter(|scheme| {
            !WRITES.iter().any(|c| {
                c.step == WriteStep::WrapKey
                    && match c.scheme {
                        Some(name) => name == scheme.as_str(),
                        None => **scheme == WrapScheme::CmsAes256Gcm,
                    }
            })
        })
        .map(ToString::to_string)
        .collect();
    report("wrap_key is never asked for", &missing)
}

/// Every CMS form Rite writes is opened by some read step from a container
/// another implementation wrote, or is in `NOT_OPENED_FROM_ELSEWHERE` with its
/// reason. A listed form that opens fails too, so the list stays true.
///
/// The fixture's expected outcome stands for whether it opens: its own row
/// fails if that expectation is wrong.
fn every_form_rite_writes_is_opened_from_elsewhere() -> Result<(), String> {
    let mut written: Vec<WrapDescription> = Vec::new();
    for case in WRITES {
        if let Write::Writes(form @ Form::Cms { .. }) = case.expect.default {
            let description = form.description();
            if !written.contains(&description) {
                written.push(description);
            }
        }
    }
    let opened: Vec<WrapDescription> = FIXTURES
        .iter()
        .filter(|f| {
            matches!(f.unwrap_key.default, Read::Opens)
                || matches!(f.decrypt_data.default, Read::Opens)
        })
        .filter_map(|f| cms::describe(&read(&fixture_path(f))).ok())
        .map(|facts| facts.description)
        .collect();
    let gaps: Vec<WrapDescription> = NOT_OPENED_FROM_ELSEWHERE
        .iter()
        .map(|(form, _)| form.description())
        .collect();

    let mut problems = Vec::new();
    for description in &written {
        if !opened.contains(description) && !gaps.contains(description) {
            problems.push(format!(
                "written, never opened from elsewhere, and not a listed gap: {description:?}"
            ));
        }
    }
    for ((form, reason), description) in NOT_OPENED_FROM_ELSEWHERE.iter().zip(&gaps) {
        if opened.contains(description) {
            problems.push(format!(
                "a listed gap that now opens; remove it: {form:?} ({reason})"
            ));
        }
        if !written.contains(description) {
            problems.push(format!("a listed gap Rite does not write: {form:?}"));
        }
    }
    report("forms out of step", &problems)
}

/// Every form a recipient's key arrives in is a row of each write step, the
/// SPKI DER file in the algorithm rows and the others in the shape table.
fn every_shape_is_a_recipient_of_every_write_step() -> Result<(), String> {
    let mut missing = Vec::new();
    for step in WriteStep::ALL.iter().copied() {
        for shape in Shape::ALL.iter().copied() {
            let covered = WRITES
                .iter()
                .chain(RECIPIENT_SHAPES)
                .any(|c| c.step == step && c.path == Path::Recipient(shape));
            if !covered {
                missing.push(format!("{}::recipient::as::{}", step.name(), shape.name()));
            }
        }
    }
    report("recipient shapes missing", &missing)
}
