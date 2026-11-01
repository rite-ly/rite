//! Where Rite runs: the operating system, a Rite Live system, a container, a
//! virtual machine.
//!
//! On Linux every value comes from a file any user can read, checked in the
//! order `systemd-detect-virt` uses. The tool itself is not called: it is
//! absent on macOS and in slim containers. The Linux probes read under a root
//! given as a parameter (see `probe_fixtures`).

#[cfg(any(target_os = "linux", test))]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use rite_runtime::{Container, RiteLive};
use rite_runtime::{OsIdentity, Platform, Virtualization};

#[cfg(any(target_os = "linux", test))]
use super::probe_files::{has_cpu_flag, key_value, read_trimmed};

/// Where a Rite Live system records the SHA-256 of the ceremony layer it
/// copied at boot, and where it puts the layer once the layer passed its
/// check (`img/mkosi/mkosi.extra/usr/lib/rite/load-ceremony`). The digest is
/// written before the check, so only the merged layer makes it count.
#[cfg(any(target_os = "linux", test))]
const CEREMONY_LAYER_DIGEST: &str = "run/rite/ceremony.sha256";
#[cfg(any(target_os = "linux", test))]
const CEREMONY_LAYER_MERGED: &str = "run/extensions/ceremony.raw";

/// Hypervisors recognised from the firmware vendor or product name alone:
/// no physical machine reports them.
#[cfg(any(target_os = "linux", test))]
const VIRTUAL_VENDORS: &[(&str, &str)] = &[
    ("QEMU", "qemu"),
    ("KVM", "kvm"),
    ("VMware", "vmware"),
    ("VMW", "vmware"),
    ("innotek GmbH", "oracle"),
    ("VirtualBox", "oracle"),
    ("Xen", "xen"),
    ("Bochs", "bochs"),
    ("Parallels", "parallels"),
    ("BHYVE", "bhyve"),
    ("Apple Virtualization", "apple"),
];

/// Detect the platform Rite runs on.
#[cfg(target_os = "linux")]
#[must_use]
pub fn detect_platform() -> Platform {
    detect_linux(Path::new("/"))
}

/// Detect the platform Rite runs on.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn detect_platform() -> Platform {
    Platform {
        os: OsIdentity {
            id: Some(sysinfo::System::distribution_id()),
            version: sysinfo::System::os_version().ok(),
            name: sysinfo::System::long_os_version().ok(),
        },
        virtualization: guest_virtualization(),
        ..Platform::default()
    }
}

/// Whether macOS runs as a guest, from `kern.hv_vmm_present`. The sysctl
/// does not name the hypervisor.
#[cfg(target_os = "macos")]
fn guest_virtualization() -> Option<Virtualization> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.hv_vmm_present"])
        .output()
        .ok()?;
    (output.status.success() && output.stdout.trim_ascii() == b"1").then(|| Virtualization {
        kind: "vm-other".to_string(),
        vendor: None,
        product: None,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn guest_virtualization() -> Option<Virtualization> {
    None
}

/// Detect a Linux platform from the file system under `root`.
#[cfg(any(target_os = "linux", test))]
pub(super) fn detect_linux(root: &Path) -> Platform {
    let read = |path: &str| read_trimmed(&root.join(path));
    let os_release = read("etc/os-release")
        .or_else(|| read("usr/lib/os-release"))
        .unwrap_or_default();
    let layer_digest =
        read(CEREMONY_LAYER_DIGEST).filter(|_| root.join(CEREMONY_LAYER_MERGED).exists());
    Platform {
        os: OsIdentity {
            id: key_value(&os_release, "ID"),
            version: key_value(&os_release, "VERSION_ID"),
            name: key_value(&os_release, "PRETTY_NAME"),
        },
        rite_live: rite_live(
            &os_release,
            &read("proc/cmdline").unwrap_or_default(),
            layer_digest.as_deref(),
        ),
        container: container(root),
        virtualization: virtualization(root),
    }
}

/// The Rite Live system the machine booted: an os-release with
/// `IMAGE_ID=rite` and a dm-verity root hash on the kernel command line.
/// `None` otherwise. `layer_digest` is the digest of the merged ceremony
/// layer, if one was merged.
#[cfg(any(target_os = "linux", test))]
fn rite_live(
    os_release: &str,
    kernel_cmdline: &str,
    layer_digest: Option<&str>,
) -> Option<RiteLive> {
    if key_value(os_release, "IMAGE_ID")? != "rite" {
        return None;
    }
    // systemd reads the kernel command line in order, so the last
    // `roothash=` is the one dm-verity enforces.
    let root_hash = kernel_cmdline
        .split_whitespace()
        .rev()
        .find_map(|option| option.strip_prefix("roothash="))?;
    Some(RiteLive {
        version: key_value(os_release, "IMAGE_VERSION"),
        root_hash: root_hash.to_string(),
        ceremony_layer: layer_digest
            .filter(|digest| !digest.is_empty())
            .map(|digest| format!("sha256:{digest}")),
    })
}

/// The container Rite runs in, if any.
#[cfg(any(target_os = "linux", test))]
fn container(root: &Path) -> Option<Container> {
    let read = |path: &str| read_trimmed(&root.join(path));
    // Podman writes this file in every container, and names the image in it
    // when the container is privileged.
    let containerenv = read("run/.containerenv");
    let image = containerenv
        .as_deref()
        .and_then(|env| key_value(env, "image"))
        .filter(|image| !image.is_empty());
    // systemd-nspawn, LXC and Podman name themselves here.
    let declared = read("run/systemd/container").filter(|kind| !kind.is_empty());
    let kind = if let Some(kind) = declared {
        kind
    } else if containerenv.is_some() {
        "podman".to_string()
    } else if root.join(".dockerenv").exists() {
        "docker".to_string()
    } else if read("proc/sys/kernel/osrelease")
        .is_some_and(|release| release.to_ascii_lowercase().contains("microsoft"))
    {
        "wsl".to_string()
    } else {
        return None;
    };
    Some(Container { kind, image })
}

/// The virtual machine Rite runs in, if any.
///
/// From the firmware's DMI strings, the `hypervisor` CPU flag (x86 only) and
/// the device tree's `hypervisor` node (Arm guests without DMI). The cloud
/// vendors also sell physical machines, so each has its own rule.
#[cfg(any(target_os = "linux", test))]
fn virtualization(root: &Path) -> Option<Virtualization> {
    let read = |path: &str| read_trimmed(&root.join(path)).filter(|value| !value.is_empty());
    let vendor = read("sys/class/dmi/id/sys_vendor");
    let product = read("sys/class/dmi/id/product_name");
    let hypervisor = has_cpu_flag(&read("proc/cpuinfo").unwrap_or_default(), "hypervisor");

    let named = [vendor.as_deref(), product.as_deref()]
        .into_iter()
        .flatten()
        .find_map(|value| {
            VIRTUAL_VENDORS
                .iter()
                .find(|(prefix, _)| value.starts_with(prefix))
                .map(|(_, kind)| *kind)
        });
    let product_name = product.as_deref().unwrap_or_default();
    let cloud = match vendor.as_deref() {
        // Hyper-V and Azure name every guest "Virtual Machine"; Surface
        // devices name the model.
        Some("Microsoft Corporation") if hypervisor || product_name == "Virtual Machine" => {
            Some("microsoft")
        }
        // EC2 bare-metal instance types end in `.metal` (`c6g.metal`).
        Some("Amazon EC2") if hypervisor || product_name.rsplit('.').next() != Some("metal") => {
            Some("amazon")
        }
        Some("Google") if hypervisor || product_name == "Google Compute Engine" => Some("google"),
        _ => None,
    };
    // The device tree names the hypervisor in a compatible string such as
    // `linux,kvm` or `xen,xen`, nul-separated.
    let from_device_tree = read("proc/device-tree/hypervisor/compatible").map(|compatible| {
        if compatible.contains("kvm") {
            "kvm"
        } else if compatible.contains("xen") {
            "xen"
        } else {
            "vm-other"
        }
    });
    let kind = named
        .or(cloud)
        .or(from_device_tree)
        .or_else(|| hypervisor.then_some("vm-other"))?;
    Some(Virtualization {
        kind: kind.to_string(),
        vendor,
        product,
    })
}

#[cfg(test)]
mod tests {
    use super::super::probe_files::fake_tree;
    use super::*;

    const LIVE_OS_RELEASE: &str = "PRETTY_NAME=\"Rite Live\"\nNAME=\"Debian GNU/Linux\"\n\
        ID=debian\nVERSION_ID=\"13\"\nIMAGE_ID=rite\nIMAGE_VERSION=0.8.0\n";
    const ROOT_HASH: &str = "9cd88c8f7d9bbc9585b0aeb6b72f452858baa6228b23fce73e18f32373beae5c";

    #[test]
    fn rite_live_reads_version_root_hash_and_layer() {
        let cmdline = format!("quiet roothash={ROOT_HASH} systemd.volatile=overlay");
        let live = rite_live(LIVE_OS_RELEASE, &cmdline, Some("40d44793")).expect("Rite Live");
        assert_eq!(live.version.as_deref(), Some("0.8.0"));
        assert_eq!(live.root_hash, ROOT_HASH);
        assert_eq!(live.ceremony_layer.as_deref(), Some("sha256:40d44793"));
    }

    #[test]
    fn rite_live_needs_the_rite_image_id_and_a_root_hash() {
        let cmdline = format!("roothash={ROOT_HASH}");
        assert!(rite_live("ID=debian\n", &cmdline, None).is_none());
        assert!(rite_live("ID=debian\nIMAGE_ID=other\n", &cmdline, None).is_none());
        assert!(rite_live(LIVE_OS_RELEASE, "quiet", None).is_none());
    }

    #[test]
    fn the_last_root_hash_on_the_command_line_counts() {
        let cmdline = format!("roothash=0000 quiet roothash={ROOT_HASH}");
        let live = rite_live(LIVE_OS_RELEASE, &cmdline, None).expect("Rite Live");
        assert_eq!(live.root_hash, ROOT_HASH);
    }

    #[test]
    fn a_ceremony_layer_counts_only_once_merged() {
        let cmdline = format!("roothash={ROOT_HASH}\n");
        let layer = |last: (&str, &str)| {
            let root = fake_tree(&[
                ("etc/os-release", LIVE_OS_RELEASE),
                ("proc/cmdline", &cmdline),
                ("run/rite/ceremony.sha256", "40d44793\n"),
                last,
            ]);
            detect_linux(root.path())
                .rite_live
                .expect("Rite Live")
                .ceremony_layer
        };
        assert_eq!(
            layer(("run/extensions/ceremony.raw", "")).as_deref(),
            Some("sha256:40d44793")
        );
        assert_eq!(
            layer(("run/rite/ceremony-error", "files outside /usr/share/rite\n")),
            None
        );
    }

    #[test]
    fn os_release_falls_back_to_usr_lib() {
        let root = fake_tree(&[("usr/lib/os-release", "ID=fedora\nVERSION_ID=41\n")]);
        let platform = detect_linux(root.path());
        assert_eq!(platform.os.id.as_deref(), Some("fedora"));
        assert!(platform.rite_live.is_none());
    }

    #[test]
    fn container_kinds() {
        let kind = |files: &[(&str, &str)]| container(fake_tree(files).path()).map(|c| c.kind);
        assert_eq!(kind(&[(".dockerenv", "")]).as_deref(), Some("docker"));
        assert_eq!(
            kind(&[
                ("run/systemd/container", "systemd-nspawn\n"),
                (".dockerenv", "")
            ])
            .as_deref(),
            Some("systemd-nspawn")
        );
        assert_eq!(
            kind(&[(
                "proc/sys/kernel/osrelease",
                "5.15.167.4-microsoft-standard-WSL2\n"
            )])
            .as_deref(),
            Some("wsl")
        );
        assert_eq!(
            kind(&[("proc/sys/kernel/osrelease", "6.12.48-amd64\n")]),
            None
        );

        let podman = fake_tree(&[(
            "run/.containerenv",
            "engine=\"podman-5.2.0\"\nimage=\"ghcr.io/rite-ly/rite:0.8.0\"\n",
        )]);
        let found = container(podman.path()).expect("a container");
        assert_eq!(found.kind, "podman");
        assert_eq!(found.image.as_deref(), Some("ghcr.io/rite-ly/rite:0.8.0"));
        let unprivileged = fake_tree(&[("run/.containerenv", "")]);
        assert!(
            container(unprivileged.path())
                .expect("a container")
                .image
                .is_none()
        );
    }

    /// The kind of virtual machine a fake root reports; empty when none.
    fn virtualization_kind(vendor: &str, product: &str, cpuinfo: &str) -> String {
        let mut files = vec![("proc/cpuinfo", cpuinfo)];
        if !vendor.is_empty() {
            files.push(("sys/class/dmi/id/sys_vendor", vendor));
        }
        if !product.is_empty() {
            files.push(("sys/class/dmi/id/product_name", product));
        }
        virtualization(fake_tree(&files).path())
            .map(|v| v.kind)
            .unwrap_or_default()
    }

    #[test]
    fn virtualization_kinds() {
        const GUEST: &str = "flags\t\t: fpu hypervisor\n";
        const HOST: &str = "flags\t\t: fpu vmx\n";
        let kind = virtualization_kind;
        assert_eq!(kind("QEMU", "Standard PC (Q35 + ICH9, 2009)", HOST), "qemu");
        assert_eq!(kind("innotek GmbH", "VirtualBox", GUEST), "oracle");
        assert_eq!(
            kind("Apple Inc.", "Apple Virtualization Generic Platform", ""),
            "apple"
        );
        assert_eq!(kind("Dell Inc.", "XPS 13 9340", GUEST), "vm-other");
        assert_eq!(kind("Dell Inc.", "XPS 13 9340", HOST), "");
        assert_eq!(kind("", "", ""), "");
    }

    #[test]
    fn cloud_vendors_that_sell_hardware_have_their_own_rules() {
        // Arm guests have no `hypervisor` flag: the rules stand without it.
        let kind = virtualization_kind;
        assert_eq!(
            kind("Microsoft Corporation", "Virtual Machine", ""),
            "microsoft"
        );
        assert_eq!(kind("Microsoft Corporation", "Surface Pro X", ""), "");
        assert_eq!(kind("Amazon EC2", "c7g.large", ""), "amazon");
        assert_eq!(kind("Amazon EC2", "c7g.metal", ""), "");
        assert_eq!(
            kind("Amazon EC2", "m5.metal", "flags\t\t: fpu hypervisor\n"),
            "amazon"
        );
    }

    #[test]
    fn device_tree_names_an_arm_hypervisor() {
        let root = fake_tree(&[(
            "proc/device-tree/hypervisor/compatible",
            "xen,xen-4.17\0xen,xen\0",
        )]);
        assert_eq!(
            virtualization(root.path()).map(|v| v.kind).as_deref(),
            Some("xen")
        );
    }

    #[test]
    fn detects_the_running_platform() {
        let platform = detect_platform();
        assert!(platform.os.id.is_some() || platform.os.name.is_some());
    }
}
