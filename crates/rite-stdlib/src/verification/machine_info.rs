//! Machine info action - capture device information as evidence.

use rite_model::ActionType;
use rite_runtime::{
    ActionCategory, ActionHandler, ActionMetadata, ExecutionError, HandlerContext, StepEvidence,
    StepInfo, StepResult, StepUI, display,
};
use rite_sdk::Backend;
use sysinfo::System;

use crate::params::MachineInfoParams;

/// Machine info action - capture device information as evidence.
///
/// Captures hostname, machine ID, CPU model, and OS information to prove which
/// physical device ran the ceremony. The machine ID is hashed with SHA-256 for privacy.
pub struct MachineInfoAction;

fn get_hostname() -> String {
    System::host_name()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(target_os = "linux")]
fn get_machine_id() -> Option<String> {
    let raw_id = std::fs::read_to_string("/etc/machine-id").ok()?;
    let trimmed = raw_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(rite_runtime::compute_fingerprint(trimmed.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn get_machine_id() -> Option<String> {
    None
}

/// Security feature status, each field is a human-readable status string.
struct SecurityFeatures {
    hardware_ram_encryption: String,
    iommu_dma_protection: String,
    freed_page_zeroing: String,
}

#[cfg(target_os = "linux")]
fn collect_security_features() -> SecurityFeatures {
    let dmesg_out = std::process::Command::new("dmesg")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    // AMD SME: kernel logs "AMD Memory Encryption Features active: SME"
    // Intel TME: kernel logs "x86/tme: enabled by BIOS" or "x86/mktme: enabled by BIOS"
    let hardware_ram_encryption =
        if dmesg_out.contains("AMD Memory Encryption Features active: SME") {
            "AMD SME active".to_string()
        } else if dmesg_out.contains("x86/tme: enabled by BIOS")
            || dmesg_out.contains("x86/mktme: enabled by BIOS")
        {
            "Intel TME active".to_string()
        } else {
            let vendor = std::fs::read_to_string("/proc/cpuinfo")
                .unwrap_or_default()
                .lines()
                .find(|l| l.starts_with("vendor_id"))
                .and_then(|l| l.split(':').nth(1))
                .map_or_else(|| "unknown".to_string(), |v| v.trim().to_string());
            match vendor.as_str() {
                "AuthenticAMD" => {
                    "not active (AMD CPU — SME not supported or disabled in BIOS)".to_string()
                }
                "GenuineIntel" => {
                    "not active (Intel CPU — enable TME in BIOS/UEFI Security settings)".to_string()
                }
                _ => format!("not active ({vendor})"),
            }
        };

    // IOMMU: /sys/class/iommu/ entries are created when the kernel assigns IOMMU groups.
    let iommu_count = std::fs::read_dir("/sys/class/iommu").map_or(0, std::iter::Iterator::count);
    let iommu_dma_protection = if iommu_count > 0 {
        format!("active ({iommu_count} groups)")
    } else {
        "not active".to_string()
    };

    let freed_page_zeroing =
        if std::fs::read_to_string("/proc/cmdline").is_ok_and(|c| c.contains("init_on_free=1")) {
            "active".to_string()
        } else {
            "not active".to_string()
        };

    SecurityFeatures {
        hardware_ram_encryption,
        iommu_dma_protection,
        freed_page_zeroing,
    }
}

// Apple Silicon has always-on hardware memory encryption via the Secure Enclave.
// DART (per-device IOMMU) is also always active on Apple Silicon.
// Intel Macs have neither — the T2 chip encrypts the SSD only, not RAM.
#[cfg(target_os = "macos")]
fn collect_security_features() -> SecurityFeatures {
    let apple_silicon = std::env::consts::ARCH == "aarch64";
    SecurityFeatures {
        hardware_ram_encryption: if apple_silicon {
            "active (Apple Silicon — always-on hardware encryption via Secure Enclave)".to_string()
        } else {
            "not active (Intel Mac — T2 chip encrypts SSD only, not RAM)".to_string()
        },
        iommu_dma_protection: if apple_silicon {
            "active (Apple Silicon — DART per-device IOMMU always on)".to_string()
        } else {
            "not available (Intel Mac)".to_string()
        },
        freed_page_zeroing: "not applicable (macOS)".to_string(),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_security_features() -> SecurityFeatures {
    SecurityFeatures {
        hardware_ram_encryption: "not available".to_string(),
        iommu_dma_protection: "not available".to_string(),
        freed_page_zeroing: "not available".to_string(),
    }
}

fn collect_system_info() -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let mut sys = System::new_all();
    sys.refresh_all();
    (
        sys.cpus()
            .first()
            .map(|c| c.brand().to_string())
            .filter(|s| !s.is_empty()),
        System::name(),
        System::long_os_version(),
        System::kernel_version(),
    )
}

impl ActionHandler for MachineInfoAction {
    fn metadata(&self) -> ActionMetadata {
        ActionMetadata {
            action_type: ActionType::MachineInfo,
            description: "Capture machine information",
            category: ActionCategory::Verification,
        }
    }

    fn execute(
        &self,
        _step: &StepInfo,
        _ctx: &HandlerContext,
        params: &serde_json::Value,
        ui: &mut dyn StepUI,
        _backend: Option<&mut dyn Backend>,
    ) -> Result<(StepResult, StepEvidence), ExecutionError> {
        let typed: MachineInfoParams = serde_json::from_value(params.clone())
            .map_err(|e| ExecutionError::InvalidParams(e.to_string()))?;

        if let Some(message) = &typed.message {
            display::write_line(ui, message)?;
            display::write_blank(ui)?;
        }

        display::write_line(ui, "Capturing machine information...")?;
        display::write_blank(ui)?;

        let hostname = get_hostname();
        let machine_id = get_machine_id();
        let (cpu_model, os_name, os_version, kernel_version) = collect_system_info();

        display::write_line(ui, &format!("Hostname:        {hostname}"))?;

        if typed.include_machine_id
            && let Some(ref mid) = machine_id
        {
            display::write_line(ui, &format!("Machine ID:      {mid}"))?;
        }

        if typed.include_cpu
            && let Some(ref cpu) = cpu_model
        {
            display::write_line(ui, &format!("CPU:             {cpu}"))?;
        }

        if typed.include_os {
            if let Some(ref os) = os_name {
                display::write_line(ui, &format!("OS:              {os}"))?;
            }
            if let Some(ref osv) = os_version {
                display::write_line(ui, &format!("OS Version:      {osv}"))?;
            }
            if let Some(ref kv) = kernel_version {
                display::write_line(ui, &format!("Kernel Version:  {kv}"))?;
            }
        }

        let security_features = if typed.include_security_features {
            let f = collect_security_features();
            display::write_line(
                ui,
                &format!("RAM Encryption:  {}", f.hardware_ram_encryption),
            )?;
            display::write_line(ui, &format!("DMA Protection:  {}", f.iommu_dma_protection))?;
            display::write_line(ui, &format!("Page Zeroing:    {}", f.freed_page_zeroing))?;
            Some(f)
        } else {
            None
        };

        display::write_blank(ui)?;

        let result = StepResult::completed("Machine info captured");

        let mut evidence = StepEvidence::new();
        evidence.insert("hostname", hostname);

        if typed.include_machine_id
            && let Some(mid) = machine_id
        {
            evidence.insert("machine_id", mid);
        }

        if typed.include_cpu
            && let Some(cpu) = cpu_model
        {
            evidence.insert("cpu_model", cpu);
        }

        if typed.include_os {
            if let Some(os) = os_name {
                evidence.insert("os_name", os);
            }
            if let Some(osv) = os_version {
                evidence.insert("os_version", osv);
            }
            if let Some(kv) = kernel_version {
                evidence.insert("kernel_version", kv);
            }
        }

        if let Some(f) = security_features {
            evidence.insert("hardware_ram_encryption", f.hardware_ram_encryption);
            evidence.insert("iommu_dma_protection", f.iommu_dma_protection);
            evidence.insert("freed_page_zeroing", f.freed_page_zeroing);
        }

        Ok((result, evidence))
    }
}
