//! Document generation for Rite ceremonies.
//!
//! - `script`: printable HTML briefing produced from a resolved
//!   [`rite_model::Ceremony`] (consumed by `rite script`).
//! - `report`: post-ceremony HTML report produced from a verified
//!   `StepFact` transcript (consumed by `rite report`).
//!
//! Rendering uses embedded [minijinja] templates with a built-in theme
//! selected via [`Theme`], and optional run-time [`Branding`].
//!
//! # Stability
//!
//! Internal crate. This is an implementation detail of the `rite` CLI, with no
//! stable API and no semver guarantees across releases. Build against the
//! public `rite-sdk`, `rite-model`, or `rite-resolver` crates instead.
//!
//! [minijinja]: https://docs.rs/minijinja

#![warn(missing_docs)]

mod engine;
mod html;
pub mod report;
mod structure;
mod view;

pub use engine::{Theme, render_report, render_script};
pub use structure::{ActGroup, ScriptStructure, SectionGroup, build_script_structure};
pub use view::{Branding, ReportView, ScriptView, validate_accent};
