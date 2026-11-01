//! Where a run happens, as the running system reports it, and the
//! security-feature checks that describe the machine.
//!
//! The runner records a [`Platform`] once per run, as
//! [`StepFact::PlatformRecorded`](crate::StepFact::PlatformRecorded). Every
//! value is read by software on the machine, so it is an observation, not
//! proof: a custom build can copy any of them.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Where Rite runs, as the running system reports it.
///
/// A Rite Live system is one setup among others, noted when it is detected.
/// Whether its root hash is a published one is judged after the run.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(
        description = "Where the run happened, as the running system reports it. Every value \
        is read by software on the machine: an observation, not proof."
    )
)]
pub struct Platform {
    /// The architecture `rite` runs as (`x86_64`, `aarch64`).
    #[cfg_attr(test, schemars(description = "The architecture rite runs as."))]
    pub arch: String,
    /// The operating system.
    #[cfg_attr(test, schemars(description = "The operating system."))]
    pub os: OsIdentity,
    /// The Rite Live system the machine booted; `None` when no Rite Live
    /// marker was found.
    #[cfg_attr(
        test,
        schemars(
            description = "The Rite Live system the machine booted; null when no Rite Live \
            marker was found."
        )
    )]
    pub rite_live: Option<RiteLive>,
    /// The container Rite runs in. `None` when no container marker was
    /// found, which does not prove there is no container.
    #[cfg_attr(
        test,
        schemars(
            description = "The container rite runs in; null when no container marker was found, \
            which does not prove there is none."
        )
    )]
    pub container: Option<Container>,
    /// The virtual machine Rite runs in. `None` when no hypervisor marker
    /// was found, which does not prove there is no virtual machine: Docker
    /// Desktop's VM, for one, is not visible from its containers.
    #[cfg_attr(
        test,
        schemars(
            description = "The virtual machine rite runs in; null when no hypervisor marker was \
            found, which does not prove there is none (Docker Desktop's VM is not visible from \
            its containers)."
        )
    )]
    pub virtualization: Option<Virtualization>,
    /// UEFI Secure Boot.
    #[cfg_attr(test, schemars(description = "UEFI Secure Boot."))]
    pub secure_boot: FeatureCheck,
}

impl fmt::Display for Platform {
    /// One line: the OS and architecture, then what was detected around it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let os = self
            .os
            .display_name()
            .unwrap_or_else(|| "unknown OS".to_string());
        write!(f, "{os} on {}", self.arch)?;
        if let Some(live) = &self.rite_live {
            write!(
                f,
                ", Rite Live {} (root hash {})",
                live.version.as_deref().unwrap_or("of unknown version"),
                live.root_hash
            )?;
        }
        // A missing marker says so: it does not prove bare metal.
        match (&self.container, &self.virtualization) {
            (None, None) => f.write_str(", no container or VM marker found")?,
            (container, vm) => {
                match container {
                    Some(container) => write!(f, ", in a {} container", container.kind)?,
                    None => f.write_str(", no container marker found")?,
                }
                match vm {
                    Some(vm) => write!(f, ", in a {} virtual machine", vm.kind)?,
                    None => f.write_str(", no VM marker found")?,
                }
            }
        }
        write!(f, ", Secure Boot {}", self.secure_boot.status)
    }
}

/// The operating system, from os-release on Linux and from the system's own
/// version query elsewhere.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "The operating system."))]
pub struct OsIdentity {
    /// Short identifier (os-release `ID`, e.g. `"debian"`, `"macos"`).
    #[cfg_attr(
        test,
        schemars(description = "A short identifier, such as debian or macos (os-release ID).")
    )]
    pub id: Option<String>,
    /// Version (os-release `VERSION_ID`, e.g. `"13"`).
    #[cfg_attr(test, schemars(description = "The version (os-release VERSION_ID)."))]
    pub version: Option<String>,
    /// Name for display (os-release `PRETTY_NAME`).
    #[cfg_attr(
        test,
        schemars(description = "The name for display (os-release PRETTY_NAME).")
    )]
    pub name: Option<String>,
}

impl OsIdentity {
    /// The name to show: the display name, else the identifier and version.
    /// `None` when the OS reported neither.
    #[must_use]
    pub fn display_name(&self) -> Option<String> {
        self.name
            .clone()
            .or_else(|| match (&self.id, &self.version) {
                (Some(id), Some(version)) => Some(format!("{id} {version}")),
                (Some(id), None) => Some(id.clone()),
                (None, _) => None,
            })
    }
}

/// What identifies a Rite Live system, as the booted system reports it.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "What identifies a Rite Live system."))]
pub struct RiteLive {
    /// The `rite` version the system was built with (`IMAGE_VERSION` in
    /// os-release).
    #[cfg_attr(
        test,
        schemars(description = "The rite version the system was built with (IMAGE_VERSION).")
    )]
    pub version: Option<String>,
    /// dm-verity root hash of the root file system, from the kernel command
    /// line. The kernel checks every block it reads from the root against it.
    #[cfg_attr(
        test,
        schemars(
            description = "The dm-verity root hash of the root file system, from the kernel \
            command line."
        )
    )]
    pub root_hash: String,
    /// SHA-256 of the ceremony layer, as recorded when the layer was loaded
    /// at boot, as `sha256:<hex>`. Absent when no ceremony layer was loaded.
    #[cfg_attr(
        test,
        schemars(
            description = "The SHA-256 of the ceremony layer loaded at boot; null when none was \
            loaded."
        )
    )]
    pub ceremony_layer: Option<String>,
}

/// A container Rite runs in.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "A container rite runs in."))]
pub struct Container {
    /// The container manager, with the identifiers `systemd-detect-virt`
    /// prints (e.g. `"docker"`, `"podman"`, `"lxc"`, `"wsl"`).
    #[cfg_attr(
        test,
        schemars(
            description = "The container manager, as systemd-detect-virt names it (docker, \
            podman, lxc, wsl)."
        )
    )]
    pub kind: String,
    /// The image the container runs, when the manager names it (Podman
    /// does).
    #[cfg_attr(
        test,
        schemars(description = "The image the container runs, when the manager names it.")
    )]
    pub image: Option<String>,
}

/// A virtual machine Rite runs in.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "A virtual machine rite runs in."))]
pub struct Virtualization {
    /// The hypervisor, with the identifiers `systemd-detect-virt` prints
    /// (e.g. `"kvm"`, `"vmware"`, `"oracle"`, `"microsoft"`, `"apple"`), or
    /// `"vm-other"` when the hypervisor is not recognised.
    #[cfg_attr(
        test,
        schemars(
            description = "The hypervisor, as systemd-detect-virt names it (kvm, vmware, oracle, \
            microsoft, apple), or vm-other."
        )
    )]
    pub kind: String,
    /// Firmware vendor (DMI `sys_vendor`), when readable.
    #[cfg_attr(test, schemars(description = "The firmware vendor (DMI sys_vendor)."))]
    pub vendor: Option<String>,
    /// Firmware product name (DMI `product_name`), when readable.
    #[cfg_attr(
        test,
        schemars(description = "The firmware product name (DMI product_name).")
    )]
    pub product: Option<String>,
}

/// A single security-feature determination: a machine-comparable status plus
/// optional human context.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(description = "A security feature and whether it is active.")
)]
pub struct FeatureCheck {
    /// Whether the feature is active.
    #[cfg_attr(test, schemars(description = "Whether the feature is active."))]
    pub status: FeatureStatus,
    /// Human-readable context (e.g. `"AMD SME"`, `"enable TME in BIOS"`).
    #[cfg_attr(
        test,
        schemars(description = "Context for people, such as why it is unknown.")
    )]
    pub detail: Option<String>,
}

impl FeatureCheck {
    /// Construct a check with no detail.
    #[must_use]
    pub fn new(status: FeatureStatus) -> Self {
        Self {
            status,
            detail: None,
        }
    }

    /// Construct a check carrying human context.
    #[must_use]
    pub fn with_detail(status: FeatureStatus, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: Some(detail.into()),
        }
    }
}

/// Status of a platform security feature.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "Whether a security feature is active."))]
pub enum FeatureStatus {
    /// Present and active.
    #[cfg_attr(test, schemars(description = "Present and active."))]
    Active,
    /// Supported by the platform but currently off.
    #[cfg_attr(test, schemars(description = "Supported, but off."))]
    Inactive,
    /// Not available on this hardware or platform.
    #[cfg_attr(
        test,
        schemars(description = "Not available on this hardware or platform.")
    )]
    Unavailable,
    /// Not a meaningful concept on this platform.
    #[cfg_attr(
        test,
        schemars(description = "Not a meaningful concept on this platform.")
    )]
    NotApplicable,
    /// Could not be determined.
    #[cfg_attr(test, schemars(description = "Could not be determined."))]
    Unknown,
}

crate::types::vocabulary!(FeatureStatus {
    Active => "active",
    Inactive => "inactive",
    Unavailable => "unavailable",
    NotApplicable => "not_applicable",
    Unknown => "unknown",
});

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_status_serializes_as_its_name() {
        for &status in FeatureStatus::ALL {
            let json = serde_json::to_value(status).expect("serializes");
            assert_eq!(json, serde_json::json!(status.as_str()));
            let back: FeatureStatus = serde_json::from_value(json).expect("parses");
            assert_eq!(back, status);
        }
        assert!(serde_json::from_str::<FeatureStatus>("\"bogus\"").is_err());
    }

    #[test]
    fn the_summary_says_when_no_container_or_vm_marker_was_found() {
        let mut platform = Platform {
            arch: "x86_64".to_string(),
            os: OsIdentity {
                id: Some("debian".to_string()),
                version: Some("13".to_string()),
                name: None,
            },
            rite_live: None,
            container: None,
            virtualization: None,
            secure_boot: FeatureCheck::new(FeatureStatus::Active),
        };
        assert_eq!(
            platform.to_string(),
            "debian 13 on x86_64, no container or VM marker found, Secure Boot active"
        );
        platform.container = Some(Container {
            kind: "docker".to_string(),
            image: None,
        });
        assert_eq!(
            platform.to_string(),
            "debian 13 on x86_64, in a docker container, no VM marker found, Secure Boot active"
        );
    }
}
