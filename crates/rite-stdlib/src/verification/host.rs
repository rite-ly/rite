//! Host and device gathering shared by the `machine_info` action and the
//! System tab.
//!
//! The probes live here, behind the `verification` feature (which pulls
//! `sysinfo`), and return the typed shapes defined in `rite-runtime`. Keeping
//! a single source means the recorded evidence (`machine_info`) and the live
//! UI dashboard cannot drift.
//!
//! The Linux security-feature checks that read files take the root of the
//! file system as a parameter, so the fixture tests in `probe_fixtures` run
//! them on files captured from real systems.

#[cfg(any(target_os = "linux", test))]
use std::path::Path;

use rite_runtime::{Disk, Environment, FeatureCheck, FeatureStatus, Hardening, HostInfo};
use sysinfo::{CpuRefreshKind, RefreshKind, System};

#[cfg(target_os = "linux")]
use super::probe_files::read_trimmed;
#[cfg(any(target_os = "linux", test))]
use super::probe_files::{cpuinfo_field, has_cpu_flag, has_entry, kernel_at_least};

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
    let os = System::name().ok();
    let os_version = System::long_os_version().ok();
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
        info.kernel_version = System::kernel_version().ok();
        info.cpu_model = cpu_model();
        info.machine_id = get_machine_id();
        info.hardening = Some(collect_security_features());
    }

    info
}

/// Gather the live device environment. MVP: block devices.
#[must_use]
pub fn gather_environment() -> Environment {
    // Failure handled as in `network_snapshot`.
    let disks = sysinfo::Disks::new_with_refreshed_list().ok();
    let disks = disks
        .iter()
        .flatten()
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
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "unknown".to_string())
}

fn cpu_model() -> Option<String> {
    // Refresh CPUs only: the brand is all we need, so skip the
    // process/memory scan a full `System::new_all()` would run.
    let sys =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()))
            .ok()?;
    sys.cpus()
        .first()
        // AMD brand strings end in padding spaces.
        .map(|c| c.brand().trim().to_string())
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

/// Run `dmesg` from a fixed absolute path and return its output.
///
/// The binary is resolved at `/usr/bin/dmesg` (falling back to `/bin/dmesg`),
/// never through the inherited `PATH`: the output feeds recorded
/// security-posture evidence, and a `PATH` shim must not be able to forge it.
/// Returns `None` when the binary is missing or the probe fails (spawn error
/// or non-zero exit, e.g. an unprivileged read of a restricted kernel
/// buffer), so callers can record "probe failed" distinctly from "feature
/// inactive".
#[cfg(target_os = "linux")]
fn read_dmesg() -> Option<String> {
    let path = ["/usr/bin/dmesg", "/bin/dmesg"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())?;
    let output = std::process::Command::new(path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn collect_security_features() -> Hardening {
    let root = Path::new("/");
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let kernel_release = read_trimmed(&root.join("proc/sys/kernel/osrelease")).unwrap_or_default();
    let ram_encryption = ram_encryption(&cpuinfo, &kernel_release, read_dmesg);

    let dma_protection = dma_protection(root);

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
        secure_boot: secure_boot(root),
    }
}

/// Whether the CPU encrypts RAM, from the CPU flags Linux reports.
///
/// - AMD: Linux clears the `sme` flag unless Secure Memory Encryption is
///   active.
/// - Intel: since Linux 6.10 (commit cd2236c2f49e), Linux clears the `tme`
///   flag unless the firmware enabled Total Memory Encryption. Before 6.10
///   the flag only says that the CPU supports it, and only the kernel log
///   says whether it is on; `kernel.dmesg_restrict` may keep the log from an
///   unprivileged user. The TME encryption bypass setting is not read, so
///   active means enabled by the firmware.
#[cfg(any(target_os = "linux", test))]
pub(super) fn ram_encryption(
    cpuinfo: &str,
    kernel_release: &str,
    read_dmesg: impl FnOnce() -> Option<String>,
) -> FeatureCheck {
    match cpuinfo_field(cpuinfo, "vendor_id").unwrap_or_default() {
        "AuthenticAMD" if has_cpu_flag(cpuinfo, "sme") => {
            FeatureCheck::with_detail(FeatureStatus::Active, "AMD SME")
        }
        "AuthenticAMD" => FeatureCheck::with_detail(
            FeatureStatus::Inactive,
            "AMD CPU; SME not supported, disabled in firmware or off (mem_encrypt)",
        ),
        "GenuineIntel" if !has_cpu_flag(cpuinfo, "tme") => FeatureCheck::with_detail(
            FeatureStatus::Inactive,
            "Intel CPU; TME not supported or not enabled in firmware",
        ),
        "GenuineIntel" if kernel_at_least(kernel_release, 6, 10) => {
            FeatureCheck::with_detail(FeatureStatus::Active, "Intel TME")
        }
        "GenuineIntel" => match read_dmesg() {
            None => FeatureCheck::with_detail(
                FeatureStatus::Unknown,
                "Intel TME supported; Linux before 6.10 and the kernel log is not readable",
            ),
            Some(log)
                if log.contains("x86/tme: enabled by BIOS")
                    || log.contains("x86/mktme: enabled by BIOS") =>
            {
                FeatureCheck::with_detail(FeatureStatus::Active, "Intel TME")
            }
            Some(_) => FeatureCheck::with_detail(
                FeatureStatus::Inactive,
                "Intel CPU; enable TME in BIOS/UEFI Security settings",
            ),
        },
        "" => FeatureCheck::with_detail(
            FeatureStatus::Unknown,
            "no CPU vendor in /proc/cpuinfo (not x86)",
        ),
        // Another vendor, or an emulator such as Rosetta (`VirtualApple`):
        // its flags are not known to answer.
        other => FeatureCheck::with_detail(
            FeatureStatus::Unknown,
            format!("CPU vendor {other} not checked"),
        ),
    }
}

/// DMA protection, from the IOMMUs the kernel registered under `root`.
///
/// The kernel creates `/sys/class/iommu` when it has IOMMU support, so a
/// missing directory is a negative only when `/sys/class` itself is visible.
/// In a virtual machine this describes the IOMMU the guest is given.
#[cfg(any(target_os = "linux", test))]
pub(super) fn dma_protection(root: &Path) -> FeatureCheck {
    let class = root.join("sys/class");
    match std::fs::read_dir(class.join("iommu")) {
        Ok(entries) => match entries.count() {
            0 => FeatureCheck::with_detail(FeatureStatus::Inactive, "no IOMMU registered"),
            count => FeatureCheck::with_detail(FeatureStatus::Active, format!("{count} IOMMUs")),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && has_entry(&class, |_| true) => {
            FeatureCheck::with_detail(FeatureStatus::Inactive, "no IOMMU support in the kernel")
        }
        Err(e) => FeatureCheck::with_detail(
            FeatureStatus::Unknown,
            format!("/sys/class/iommu not readable: {e}"),
        ),
    }
}

/// The firmware's `SecureBoot` variable, under efivarfs: four bytes of
/// attributes, then one byte, 1 when Secure Boot is enforced.
#[cfg(any(target_os = "linux", test))]
const SECURE_BOOT_VAR: &str = "SecureBoot-8be4df61-93ca-11d2-aa0d-e39edca8b4ae";

/// The Secure Boot state, from the firmware variables under `root`.
///
/// Each layer that can hide the answer is told apart from a negative one:
/// a container hides `/sys/firmware` (Docker and Podman mount it empty), and
/// the kernel creates `efivars` as an empty mount point when efivarfs is not
/// mounted. Firmware variable names end in a GUID, so a mounted efivarfs has
/// entries with a `-`.
#[cfg(any(target_os = "linux", test))]
pub(super) fn secure_boot(root: &Path) -> FeatureCheck {
    let firmware = root.join("sys/firmware");
    if !has_entry(&firmware, |_| true) {
        return FeatureCheck::with_detail(
            FeatureStatus::Unknown,
            "/sys/firmware is not visible (a container hides it)",
        );
    }
    let efi = firmware.join("efi");
    if !efi.is_dir() {
        return FeatureCheck::with_detail(FeatureStatus::NotApplicable, "not booted through UEFI");
    }
    let efivars = efi.join("efivars");
    if !has_entry(&efivars, |name| name.contains('-')) {
        return FeatureCheck::with_detail(FeatureStatus::Unknown, "efivarfs is not mounted");
    }
    match std::fs::read(efivars.join(SECURE_BOOT_VAR)).map(|var| var.get(4).copied()) {
        Ok(Some(1)) => FeatureCheck::new(FeatureStatus::Active),
        Ok(Some(_)) => FeatureCheck::new(FeatureStatus::Inactive),
        Ok(None) => {
            FeatureCheck::with_detail(FeatureStatus::Unknown, "SecureBoot variable too short")
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            FeatureCheck::with_detail(FeatureStatus::Unavailable, "no SecureBoot variable")
        }
        Err(e) => FeatureCheck::with_detail(FeatureStatus::Unknown, e.to_string()),
    }
}

// Apple Silicon has always-on hardware memory encryption via the Secure
// Enclave. DART (per-device IOMMU) is also always active on Apple Silicon.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn collect_security_features() -> Hardening {
    Hardening {
        ram_encryption: FeatureCheck::with_detail(
            FeatureStatus::Active,
            "Apple Silicon: always-on hardware encryption via Secure Enclave",
        ),
        dma_protection: FeatureCheck::with_detail(
            FeatureStatus::Active,
            "Apple Silicon: DART per-device IOMMU always on",
        ),
        freed_page_zeroing: FeatureCheck::with_detail(FeatureStatus::NotApplicable, "macOS"),
        secure_boot: FeatureCheck::with_detail(
            FeatureStatus::Unknown,
            "Apple Silicon: the boot security policy is not read",
        ),
    }
}

// Windows, Intel Macs and other platforms report everything as unavailable.
// TODO(windows): probe real posture (BitLocker, VBS/HVCI, Kernel DMA
// Protection). Low priority: the Windows binary is meant for authoring
// ceremonies, not running them, where this posture matters.
#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
fn collect_security_features() -> Hardening {
    Hardening {
        ram_encryption: FeatureCheck::new(FeatureStatus::Unavailable),
        dma_protection: FeatureCheck::new(FeatureStatus::Unavailable),
        freed_page_zeroing: FeatureCheck::new(FeatureStatus::Unavailable),
        secure_boot: FeatureCheck::new(FeatureStatus::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AMD_CPUINFO: &str = "vendor_id\t: AuthenticAMD\n\
        flags\t\t: fpu vme smep smap sev\n";

    #[test]
    fn amd_ram_encryption_follows_the_sme_flag_without_dmesg() {
        let unused = || -> Option<String> { panic!("dmesg is not needed on AMD") };
        assert_eq!(
            ram_encryption(AMD_CPUINFO, "6.12.48", unused).status,
            FeatureStatus::Inactive
        );
        let active = AMD_CPUINFO.replace("sev", "sme sev");
        assert_eq!(
            ram_encryption(&active, "6.1.0", unused).status,
            FeatureStatus::Active
        );
    }

    const INTEL_TME_CPUINFO: &str = "vendor_id\t: GenuineIntel\nflags\t\t: fpu tme\n";

    #[test]
    fn intel_ram_encryption_follows_the_tme_flag_from_linux_6_10() {
        let unused = || -> Option<String> { panic!("dmesg is not needed from Linux 6.10") };
        assert_eq!(
            ram_encryption(INTEL_TME_CPUINFO, "6.12.48+deb13-amd64", unused).status,
            FeatureStatus::Active
        );
        let no_flag = "vendor_id\t: GenuineIntel\nflags\t\t: fpu\n";
        assert_eq!(
            ram_encryption(no_flag, "5.10.0", unused).status,
            FeatureStatus::Inactive
        );
    }

    #[test]
    fn ram_encryption_of_another_cpu_vendor_is_unknown() {
        let unused = || -> Option<String> { panic!("dmesg is not read") };
        let rosetta = "vendor_id\t: VirtualApple\nflags\t\t: fpu sse2\n";
        assert_eq!(
            ram_encryption(rosetta, "7.0.14-linuxkit", unused).status,
            FeatureStatus::Unknown
        );
        assert_eq!(
            ram_encryption("Features\t: fp asimd\n", "6.12.48", unused).status,
            FeatureStatus::Unknown
        );
    }

    #[test]
    fn intel_ram_encryption_reads_dmesg_before_linux_6_10() {
        let release = "6.1.0-28-amd64";
        assert_eq!(
            ram_encryption(INTEL_TME_CPUINFO, release, || None).status,
            FeatureStatus::Unknown
        );
        assert_eq!(
            ram_encryption(INTEL_TME_CPUINFO, release, || Some(
                "x86/tme: enabled by BIOS".to_string()
            ))
            .status,
            FeatureStatus::Active
        );
        assert_eq!(
            ram_encryption(INTEL_TME_CPUINFO, release, || Some(String::new())).status,
            FeatureStatus::Inactive
        );
    }

    #[test]
    fn dma_protection_tells_a_hidden_answer_from_a_negative_one() {
        let status = |files: &[(&str, &str)]| {
            let root = super::super::probe_files::fake_tree(files);
            dma_protection(root.path()).status
        };
        assert_eq!(
            status(&[("sys/class/iommu/dmar0/", "")]),
            FeatureStatus::Active
        );
        assert_eq!(status(&[("sys/class/iommu/", "")]), FeatureStatus::Inactive);
        assert_eq!(status(&[("sys/class/net/", "")]), FeatureStatus::Inactive);
        // /sys not mounted, or hidden.
        assert_eq!(status(&[("sys/", "")]), FeatureStatus::Unknown);
    }

    #[test]
    fn secure_boot_tells_a_hidden_answer_from_a_negative_one() {
        let status = |files: &[(&str, &str)]| {
            let root = super::super::probe_files::fake_tree(files);
            secure_boot(root.path()).status
        };
        let var = format!("sys/firmware/efi/efivars/{SECURE_BOOT_VAR}");
        // A container: /sys/firmware is an empty directory.
        assert_eq!(status(&[("sys/firmware/", "")]), FeatureStatus::Unknown);
        // Booted through BIOS.
        assert_eq!(
            status(&[("sys/firmware/acpi/", "")]),
            FeatureStatus::NotApplicable
        );
        // UEFI, efivarfs not mounted: the mount point is empty.
        assert_eq!(
            status(&[("sys/firmware/efi/efivars/", "")]),
            FeatureStatus::Unknown
        );
        // UEFI, efivarfs mounted, no SecureBoot variable.
        assert_eq!(
            status(&[(
                "sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-e39edca8b4ae",
                ""
            )]),
            FeatureStatus::Unavailable
        );
        assert_eq!(status(&[(&var, "\x06\0\0\0\x01")]), FeatureStatus::Active);
        assert_eq!(status(&[(&var, "\x06\0\0\0\0")]), FeatureStatus::Inactive);
    }

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
