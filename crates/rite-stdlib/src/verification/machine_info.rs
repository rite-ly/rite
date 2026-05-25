//! `machine_info` action, capture device information as evidence.

use rite_model::{ActionType, StepFact};
use rite_runtime::{
    Action, ActionCategory, ActionError, ActionMetadata, HandlerContext, Icon, Reporter, StepInfo,
    StepResult, parse_params,
};
use rite_sdk::Backend;
use sysinfo::System;

use crate::params::MachineInfoParams;

/// Capture hostname, machine ID, CPU model, OS information, and a
/// snapshot of platform security features as transcript evidence.
///
/// The machine ID (when available) is hashed with SHA-256 for privacy.
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

/// Security feature status. Each field is a human-readable status string.
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
                    "not active (AMD CPU; SME not supported or disabled in BIOS)".to_string()
                }
                "GenuineIntel" => {
                    "not active (Intel CPU; enable TME in BIOS/UEFI Security settings)".to_string()
                }
                _ => format!("not active ({vendor})"),
            }
        };

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
// Intel Macs have neither; the T2 chip encrypts the SSD only, not RAM.
#[cfg(target_os = "macos")]
fn collect_security_features() -> SecurityFeatures {
    let apple_silicon = std::env::consts::ARCH == "aarch64";
    SecurityFeatures {
        hardware_ram_encryption: if apple_silicon {
            "active (Apple Silicon: always-on hardware encryption via Secure Enclave)".to_string()
        } else {
            "not active (Intel Mac: T2 chip encrypts SSD only, not RAM)".to_string()
        },
        iommu_dma_protection: if apple_silicon {
            "active (Apple Silicon: DART per-device IOMMU always on)".to_string()
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

        let hostname = get_hostname();
        let machine_id = get_machine_id();
        let (cpu_model, os_name, os_version, kernel_version) = collect_system_info();

        reporter.log(Icon::Info, format!("Hostname:        {hostname}"))?;

        if typed.include_machine_id
            && let Some(ref mid) = machine_id
        {
            reporter.log(Icon::Info, format!("Machine ID:      {mid}"))?;
        }

        if typed.include_cpu
            && let Some(ref cpu) = cpu_model
        {
            reporter.log(Icon::Info, format!("CPU:             {cpu}"))?;
        }

        if typed.include_os {
            if let Some(ref os) = os_name {
                reporter.log(Icon::Info, format!("OS:              {os}"))?;
            }
            if let Some(ref osv) = os_version {
                reporter.log(Icon::Info, format!("OS Version:      {osv}"))?;
            }
            if let Some(ref kv) = kernel_version {
                reporter.log(Icon::Info, format!("Kernel Version:  {kv}"))?;
            }
        }

        let security_features = if typed.include_security_features {
            let f = collect_security_features();
            reporter.log(
                Icon::Info,
                format!("RAM Encryption:  {}", f.hardware_ram_encryption),
            )?;
            reporter.log(
                Icon::Info,
                format!("DMA Protection:  {}", f.iommu_dma_protection),
            )?;
            reporter.log(
                Icon::Info,
                format!("Page Zeroing:    {}", f.freed_page_zeroing),
            )?;
            Some(f)
        } else {
            None
        };

        let mut outputs = serde_json::Map::new();
        outputs.insert("hostname".to_string(), hostname.into());
        if typed.include_machine_id
            && let Some(mid) = machine_id
        {
            outputs.insert("machine_id".to_string(), mid.into());
        }
        if typed.include_cpu
            && let Some(cpu) = cpu_model
        {
            outputs.insert("cpu_model".to_string(), cpu.into());
        }
        if typed.include_os {
            if let Some(os) = os_name {
                outputs.insert("os_name".to_string(), os.into());
            }
            if let Some(osv) = os_version {
                outputs.insert("os_version".to_string(), osv.into());
            }
            if let Some(kv) = kernel_version {
                outputs.insert("kernel_version".to_string(), kv.into());
            }
        }
        if let Some(f) = security_features {
            outputs.insert(
                "hardware_ram_encryption".to_string(),
                f.hardware_ram_encryption.into(),
            );
            outputs.insert(
                "iommu_dma_protection".to_string(),
                f.iommu_dma_protection.into(),
            );
            outputs.insert(
                "freed_page_zeroing".to_string(),
                f.freed_page_zeroing.into(),
            );
        }

        reporter.fact(StepFact::BackendOperation {
            step: step.id.clone(),
            kind: "machine_info".to_string(),
            inputs: serde_json::Value::Null,
            outputs: serde_json::Value::Object(outputs),
            fingerprint: None,
        })?;

        Ok(StepResult::completed("Machine info captured"))
    }
}
