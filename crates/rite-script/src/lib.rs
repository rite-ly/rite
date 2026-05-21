//! HTML ceremony script and report generation for Rite.
//!
//! - `script`: printable HTML briefing produced from a resolved
//!   [`rite_model::Ceremony`] (consumed by `rite script`).
//! - `report`: post-ceremony HTML report produced from a verified
//!   `StepFact` transcript (consumed by `rite report`).

#![warn(missing_docs)]

mod generate;
mod html;
pub mod report;
mod structure;
mod theme;

pub use generate::generate_html;
pub use structure::{ActGroup, ScriptStructure, SectionGroup, build_script_structure};
