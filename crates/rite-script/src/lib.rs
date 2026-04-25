//! HTML ceremony script and report generation for Rite.
//!
//! This crate produces two outputs from ceremony data:
//! - [`generate_html`]: printable HTML briefing (`rite script`)
//! - [`generate_report_html`]: post-ceremony audit report (`rite report`)

#![warn(missing_docs)]

mod generate;
mod html;
mod report;
mod structure;
mod theme;

pub use generate::generate_html;
pub use report::{
    ReportArtifact, ReportConfig, ReportData, ReportDeviation, ReportInput, ReportParticipant,
    ReportStep, build_report_data, generate_report_html,
};
pub use structure::{ActGroup, ScriptStructure, SectionGroup, build_script_structure};
