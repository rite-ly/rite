//! Post-ceremony report data from a verified [`StepFact`] transcript.
//!
//! [`data`] performs pure data extraction (`StepFact` stream + transcript
//! fingerprint → [`ReportData`]). The HTML rendering lives in the crate's
//! shared template engine; see [`crate::render_report`].
//!
//! [`StepFact`]: rite_model::transcript::StepFact

pub mod data;

pub use data::{
    ReportArtifact, ReportData, ReportDeviation, ReportStatus, ReportStep, build_report_data,
};
