//! Post-ceremony report generation from transcripts.

pub(crate) mod config;
pub mod data;
mod generate;

pub use config::ReportConfig;
pub use data::{
    ReportArtifact, ReportData, ReportDeviation, ReportParticipant, ReportStep, build_report_data,
};
pub use generate::{ReportInput, generate_report_html};
