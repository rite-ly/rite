//! Report configuration for controlling which sections appear in the output.

#[allow(clippy::struct_excessive_bools)]
/// Configuration controlling which sections appear in the generated report.
///
/// All sections are shown by default. Set fields to `false` to hide them.
/// This allows organizations to customize reports for different audiences
/// (e.g., executive summary vs full audit log).
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Show the summary box (date, duration, status, fingerprints).
    pub show_summary: bool,

    /// Show resolved ceremony parameters.
    pub show_parameters: bool,

    /// Show the participants/roles section.
    pub show_participants: bool,

    /// Show the step-by-step execution log.
    pub show_execution_log: bool,

    /// Show artifacts produced (files, hashes, sizes).
    pub show_artifacts: bool,

    /// Show recorded deviations from expected procedure.
    pub show_deviations: bool,

    /// Show post-ceremony duties (requires ceremony YAML).
    pub show_duties: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            show_summary: true,
            show_parameters: true,
            show_participants: true,
            show_execution_log: true,
            show_artifacts: true,
            show_deviations: true,
            show_duties: true,
        }
    }
}
