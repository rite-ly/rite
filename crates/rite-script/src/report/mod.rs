//! Post-ceremony HTML report from a verified [`StepFact`] transcript.
//!
//! Two layers:
//!
//! - [`data`], pure data extraction (`StepFact` stream + transcript
//!   fingerprint → [`ReportData`]). Output is `serde::Serialize`, so a
//!   future template engine can consume the same shape the built-in
//!   renderer does.
//! - [`generate`], built-in HTML renderer that turns a [`ReportData`]
//!   into a self-contained HTML document.
//!
//! [`StepFact`]: rite_model::transcript::StepFact

pub mod data;
mod generate;

pub use data::{
    ReportArtifact, ReportData, ReportDeviation, ReportStatus, ReportStep, build_report_data,
};
pub use generate::generate_report_html;
