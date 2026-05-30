//! Document generation for Rite ceremonies.
//!
//! - `script`: printable HTML briefing produced from a resolved
//!   [`rite_model::Ceremony`] (consumed by `rite script`).
//! - `report`: post-ceremony HTML report produced from a verified
//!   `StepFact` transcript (consumed by `rite report`).
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.

#![warn(missing_docs)]

mod generate;
mod html;
pub mod report;
mod structure;
mod theme;

pub use generate::generate_html;
pub use structure::{ActGroup, ScriptStructure, SectionGroup, build_script_structure};
