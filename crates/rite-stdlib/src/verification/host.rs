//! Host and device gathering shared by the `machine_info` action and the
//! System tab.
//!
//! The probes live here, behind the `verification` feature (which pulls
//! `sysinfo`), and return the typed shapes defined in `rite-runtime`. Keeping
//! a single source means the recorded evidence (`machine_info`) and the live
//! UI dashboard cannot drift.

use rite_runtime::{Disk, Environment, FeatureCheck, FeatureStatus, Hardening, HostInfo};
use sysinfo::{CpuRefreshKind, RefreshKind, System};

/// How much host detail to gather.
///
/// `Basic` is cheap enough to run at every startup for the System tab header:
/// it touches no subprocess and does not refresh the full CPU list. `Full`
/// adds the heavier probes (CPU, hashed machine id, and the security-feature
/// inspection, which spawns `dmesg` on Linux) and is used by the
/// `machine_info` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostInfoScope {
    /// Architecture, OS name/version, hostname.
    Basic,
    /// Everything in `Basic` plus kernel, CPU, machine id, and hardening.
    Full,
}

/// Gather host identity at the requested scope.
#[must_use]
pub fn gather_host_info(scope: HostInfoScope) -> HostInfo {
    // These are associated functions in `sysinfo`; no `System` instance or
    // refresh is needed, so the `Basic` scope stays cheap.
    let os = System::name();
    let os_version = System::long_os_version();
    let hostname = get_hostname();

    let mut info = HostInfo {
        arch: std::env::consts::ARCH.to_string(),
        os,
        os_version,
        kernel_version: None,
        hostname: Some(hostname),
        machine_id: None,
        cpu_model: None,
        hardening: None,
    };

    if scope == HostInfoScope::Full {
        info.kernel_version = System::kernel_version();
        info.cpu_model = cpu_model();
        info.machine_id = get_machine_id();
        info.hardening = Some(collect_security_features());
    }

    info
}

/// Gather the live device environment. MVP: block devices.
#[must_use]
pub fn gather_environment() -> Environment {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disks = disks
        .list()
        .iter()
        .map(|d| {
            let file_system = osstr_opt(d.file_system());
            let kind = match d.kind() {
                sysinfo::DiskKind::Unknown(_) => None,
                other => Some(other.to_string()),
            };
            Disk {
                name: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                file_system,
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                removable: d.is_removable(),
                kind,
            }
        })
        .collect();
    Environment { disks }
}

fn osstr_opt(value: &std::ffi::OsStr) -> Option<String> {
    let s = value.to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.into_owned())
    }
}

fn get_hostname() -> String {
    System::host_name()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn cpu_model() -> Option<String> {
    // Refresh CPUs only: the brand is all we need, so skip the
    // process/memory scan a full `System::new_all()` would run.
    let sys =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));
    sys.cpus()
        .first()
        .map(|c| c.brand().to_string())
        .filter(|s| !s.is_empty())
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

#[cfg(target_os = "linux")]
fn collect_security_features() -> Hardening {
    let dmesg_out = std::process::Command::new("dmesg")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let ram_encryption = if dmesg_out.contains("AMD Memory Encryption Features active: SME") {
        FeatureCheck::with_detail(FeatureStatus::Active, "AMD SME")
    } else if dmesg_out.contains("x86/tme: enabled by BIOS")
        || dmesg_out.contains("x86/mktme: enabled by BIOS")
    {
        FeatureCheck::with_detail(FeatureStatus::Active, "Intel TME")
    } else {
        let vendor = std::fs::read_to_string("/proc/cpuinfo")
            .unwrap_or_default()
            .lines()
            .find(|l| l.starts_with("vendor_id"))
            .and_then(|l| l.split(':').nth(1))
            .map_or_else(|| "unknown".to_string(), |v| v.trim().to_string());
        match vendor.as_str() {
            "AuthenticAMD" => FeatureCheck::with_detail(
                FeatureStatus::Inactive,
                "AMD CPU; SME not supported or disabled in BIOS",
            ),
            "GenuineIntel" => FeatureCheck::with_detail(
                FeatureStatus::Inactive,
                "Intel CPU; enable TME in BIOS/UEFI Security settings",
            ),
            other => FeatureCheck::with_detail(FeatureStatus::Inactive, other.to_string()),
        }
    };

    let iommu_count = std::fs::read_dir("/sys/class/iommu").map_or(0, std::iter::Iterator::count);
    let dma_protection = if iommu_count > 0 {
        FeatureCheck::with_detail(FeatureStatus::Active, format!("{iommu_count} groups"))
    } else {
        FeatureCheck::new(FeatureStatus::Inactive)
    };

    let freed_page_zeroing =
        if std::fs::read_to_string("/proc/cmdline").is_ok_and(|c| c.contains("init_on_free=1")) {
            FeatureCheck::new(FeatureStatus::Active)
        } else {
            FeatureCheck::new(FeatureStatus::Inactive)
        };

    Hardening {
        ram_encryption,
        dma_protection,
        freed_page_zeroing,
    }
}

// Apple Silicon has always-on hardware memory encryption via the Secure
// Enclave. DART (per-device IOMMU) is also always active on Apple Silicon.
// Intel Macs have neither; the T2 chip encrypts the SSD only, not RAM.
#[cfg(target_os = "macos")]
fn collect_security_features() -> Hardening {
    let apple_silicon = std::env::consts::ARCH == "aarch64";
    let (ram_encryption, dma_protection) = if apple_silicon {
        (
            FeatureCheck::with_detail(
                FeatureStatus::Active,
                "Apple Silicon: always-on hardware encryption via Secure Enclave",
            ),
            FeatureCheck::with_detail(
                FeatureStatus::Active,
                "Apple Silicon: DART per-device IOMMU always on",
            ),
        )
    } else {
        (
            FeatureCheck::with_detail(
                FeatureStatus::Inactive,
                "Intel Mac: T2 chip encrypts SSD only, not RAM",
            ),
            FeatureCheck::with_detail(FeatureStatus::Unavailable, "Intel Mac"),
        )
    };
    Hardening {
        ram_encryption,
        dma_protection,
        freed_page_zeroing: FeatureCheck::with_detail(FeatureStatus::NotApplicable, "macOS"),
    }
}

// Windows and other platforms report everything as unavailable for now.
// TODO(windows): probe real posture (BitLocker, VBS/HVCI, Kernel DMA
// Protection). Low priority: the Windows binary is meant for authoring
// ceremonies, not running them, where this posture matters.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_security_features() -> Hardening {
    Hardening {
        ram_encryption: FeatureCheck::new(FeatureStatus::Unavailable),
        dma_protection: FeatureCheck::new(FeatureStatus::Unavailable),
        freed_page_zeroing: FeatureCheck::new(FeatureStatus::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_scope_leaves_full_only_fields_unset() {
        let info = gather_host_info(HostInfoScope::Basic);
        assert!(!info.arch.is_empty());
        assert!(info.kernel_version.is_none());
        assert!(info.cpu_model.is_none());
        assert!(info.hardening.is_none());
    }

    #[test]
    fn full_scope_populates_hardening() {
        let info = gather_host_info(HostInfoScope::Full);
        assert!(info.hardening.is_some());
    }

    #[test]
    fn environment_lists_disks() {
        // The list may be empty in constrained CI sandboxes; just exercise
        // the gather path and the field mapping.
        let env = gather_environment();
        for disk in &env.disks {
            assert!(!disk.name.is_empty() || !disk.mount_point.is_empty());
        }
    }
}
