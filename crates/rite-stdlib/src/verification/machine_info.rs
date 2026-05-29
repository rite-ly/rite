//! `machine_info` action, capture device information as evidence.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, FeatureCheck, HandlerContext, HostInfo,
    Icon, Reporter, StepInfo, StepResult, parse_params,
};
use rite_sdk::Backend;

use crate::params::MachineInfoParams;
use crate::verification::host::{HostInfoScope, gather_host_info};

/// Capture hostname, machine ID, CPU model, OS information, and a
/// snapshot of platform security features as transcript evidence.
///
/// The machine ID (when available) is hashed with SHA-256 for privacy.
///
/// The gathering is shared with the System tab via
/// [`gather_host_info`](crate::verification::gather_host_info); this action
/// records a point-in-time snapshot as evidence, while the tab shows a live
/// view. The action's parameters select which parts of the gathered
/// [`HostInfo`] are logged and persisted.
pub struct MachineInfoAction;

/// Format a feature check as `status` or `status (detail)`.
fn format_feature(check: &FeatureCheck) -> String {
    match &check.detail {
        Some(detail) => format!("{} ({detail})", check.status),
        None => check.status.to_string(),
    }
}

impl Action for MachineInfoAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::MachineInfo,
            description: "Capture machine information",
            category: ActionCategory::Verification,
        }
    }

    fn execute(
        &self,
        step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        reporter: &mut Reporter<'_>,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<StepResult, ActionError> {
        let typed: MachineInfoParams = parse_params(params)?;

        if let Some(message) = &typed.message {
            reporter.log(Icon::Info, message.as_str())?;
        }

        reporter.log(Icon::Info, "Capturing machine information...")?;

        // Gather the full host snapshot, then project it down to the parts the
        // ceremony asked to record.
        let mut info = gather_host_info(HostInfoScope::Full);
        if !typed.include_machine_id {
            info.machine_id = None;
        }
        if !typed.include_cpu {
            info.cpu_model = None;
        }
        if !typed.include_os {
            info.os = None;
            info.os_version = None;
            info.kernel_version = None;
        }
        if !typed.include_security_features {
            info.hardening = None;
        }

        log_host_info(&info, reporter)?;

        // Serialize the typed, projected snapshot. Optional fields that were
        // cleared above serialize as JSON null. `arch` is always present.
        let outputs = serde_json::to_value(&info)
            .map_err(|e| ActionError::Failed(format!("failed to serialize machine info: {e}")))?;

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "machine_info".to_string(),
            inputs: serde_json::Value::Null,
            outputs,
            fingerprint: None,
        })?;

        Ok(StepResult::completed("Machine info captured"))
    }
}

/// Emit the human-readable log lines for a projected host snapshot.
fn log_host_info(info: &HostInfo, reporter: &mut Reporter<'_>) -> Result<(), ActionError> {
    if let Some(hostname) = &info.hostname {
        reporter.log(Icon::Info, format!("Hostname:        {hostname}"))?;
    }
    if let Some(mid) = &info.machine_id {
        reporter.log(Icon::Info, format!("Machine ID:      {mid}"))?;
    }
    if let Some(cpu) = &info.cpu_model {
        reporter.log(Icon::Info, format!("CPU:             {cpu}"))?;
    }
    if let Some(os) = &info.os {
        reporter.log(Icon::Info, format!("OS:              {os}"))?;
    }
    if let Some(osv) = &info.os_version {
        reporter.log(Icon::Info, format!("OS Version:      {osv}"))?;
    }
    if let Some(kv) = &info.kernel_version {
        reporter.log(Icon::Info, format!("Kernel Version:  {kv}"))?;
    }
    if let Some(h) = &info.hardening {
        reporter.log(
            Icon::Info,
            format!("RAM Encryption:  {}", format_feature(&h.ram_encryption)),
        )?;
        reporter.log(
            Icon::Info,
            format!("DMA Protection:  {}", format_feature(&h.dma_protection)),
        )?;
        reporter.log(
            Icon::Info,
            format!("Page Zeroing:    {}", format_feature(&h.freed_page_zeroing)),
        )?;
    }
    Ok(())
}
