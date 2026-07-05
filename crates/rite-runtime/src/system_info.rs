//! Structured machine, build, and environment facts surfaced to frontends.
//!
//! Two distinct shapes live here, on opposite sides of the data-flow boundary
//! described in `docs/development/runtime-and-frontend.md`:
//!
//! - [`SystemInfo`] is **static identity**: the build that is running and the
//!   host it runs on. Gathered once at startup. The same typed host shape
//!   ([`HostInfo`]) is what the `machine_info` action records to the
//!   transcript, so the model is defined once and shared.
//! - [`Environment`] is the **live device inventory** (disks today;
//!   peripherals and network later). It is deliberately shaped to be
//!   re-emitted: a future observer can resend it and a frontend replaces its
//!   view wholesale. Items carry a stable key for later diffing.
//!
//! Both travel as UI-only signals ([`crate::UiSignal`]); neither is ever
//! written to the transcript. Recording machine identity as evidence is the
//! `machine_info` action's job, not the frontend's.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Failure to parse one of this module's string-backed enums.
///
/// Shared across the enums defined here, mirroring the pattern in
/// `rite-sdk` (`rite_sdk::ParseError`), which is not constructible outside
/// its own crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown value: {0:?}")]
pub struct ParseError(String);

/// Static build and host identity for the System tab and
/// `rite version --verbose`.
///
/// Assembled by the CLI, the only crate that holds the build-time constants,
/// and echoed to the frontend once via [`crate::UiSignal::SystemInfo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Identity of the running binary.
    pub build: BuildInfo,
    /// Identity of the host it runs on.
    pub host: HostInfo,
    /// Linked cryptographic backend libraries.
    pub backends: Vec<BackendVersion>,
}

/// Identity of the running `rite` binary. A property of the artifact, set at
/// compile time; the strongly verifiable end of the trust boundary (checkable
/// against a release tag and build provenance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Crate version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Git commit the binary was built from, or `"unknown"`.
    pub commit: String,
    /// Commit date, or `"unknown"`.
    pub commit_date: String,
    /// Date the binary was built.
    pub build_date: String,
    /// Target triple.
    pub target: String,
    /// Build profile (`debug` / `release`).
    pub profile: String,
    /// Enabled cargo features, comma-separated.
    pub features: String,
    /// Compiler version string.
    pub rustc: String,
}

/// A linked cryptographic backend library and its runtime version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendVersion {
    /// Provider key (e.g. `"openssl"`).
    pub provider: String,
    /// Runtime-linked library version.
    pub version: String,
    /// How the library was linked (e.g. `"vendored"` / `"system"`).
    pub source: Option<String>,
}

/// Identity of the host machine. A property of the environment, the weakly
/// verifiable end of the trust boundary (an operator assertion that software
/// can only partly corroborate).
///
/// Optional fields are populated depending on the gathering scope: a cheap
/// startup snapshot fills only the always-present basics, while the
/// `machine_info` action fills the full set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// CPU architecture (`std::env::consts::ARCH`). Always present.
    pub arch: String,
    /// OS name (e.g. `"Linux"`, `"Darwin"`).
    pub os: Option<String>,
    /// Long OS version string.
    pub os_version: Option<String>,
    /// Kernel version.
    pub kernel_version: Option<String>,
    /// Hostname.
    pub hostname: Option<String>,
    /// Hashed machine identifier (SHA-256), when available.
    pub machine_id: Option<String>,
    /// CPU brand string.
    pub cpu_model: Option<String>,
    /// Platform security posture, when gathered at full scope.
    pub hardening: Option<Hardening>,
}

/// Snapshot of platform memory- and DMA-protection features.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardening {
    /// Hardware RAM encryption (AMD SME, Intel TME, Apple Secure Enclave).
    pub ram_encryption: FeatureCheck,
    /// IOMMU-based DMA protection.
    pub dma_protection: FeatureCheck,
    /// Zeroing of freed pages.
    pub freed_page_zeroing: FeatureCheck,
}

/// A single security-feature determination: a machine-comparable status plus
/// optional human context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureCheck {
    /// Whether the feature is active.
    pub status: FeatureStatus,
    /// Human-readable context (e.g. `"AMD SME"`, `"enable TME in BIOS"`).
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
///
/// Serialized via its [`Display`](fmt::Display) form so the transcript carries
/// a stable, comparable token rather than a sentence. Follows the
/// Display/serde alignment convention used by `rite-sdk` enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum FeatureStatus {
    /// Present and active.
    Active,
    /// Supported by the platform but currently off.
    Inactive,
    /// Not available on this hardware or platform.
    Unavailable,
    /// Not a meaningful concept on this platform.
    NotApplicable,
    /// Could not be determined.
    Unknown,
}

impl fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FeatureStatus::Active => "active",
            FeatureStatus::Inactive => "inactive",
            FeatureStatus::Unavailable => "unavailable",
            FeatureStatus::NotApplicable => "not_applicable",
            FeatureStatus::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for FeatureStatus {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "inactive" => Ok(Self::Inactive),
            "unavailable" => Ok(Self::Unavailable),
            "not_applicable" => Ok(Self::NotApplicable),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

impl From<FeatureStatus> for String {
    fn from(s: FeatureStatus) -> String {
        s.to_string()
    }
}

impl TryFrom<String> for FeatureStatus {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// Live inventory of the machine's attached devices.
///
/// UI-only and never serialized. Shaped to be **re-emitted**: a frontend
/// replaces its whole view on each [`crate::UiSignal::Environment`], so a
/// future live observer is purely additive. Each item carries a stable key
/// (e.g. [`Disk::name`]) for later diffing.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// Block devices and their mounts.
    pub disks: Vec<Disk>,
    // Future: peripherals (USB / smartcard / TPM), network interfaces.
}

/// The one-shot UI snapshots emitted at ceremony start: static system
/// identity and the initial device environment.
///
/// Assembled by the CLI (the only crate holding the build-time constants) and
/// handed to the executor, which echoes the two pieces as
/// [`crate::UiSignal::SystemInfo`] and [`crate::UiSignal::Environment`]. The
/// runtime treats this purely as a pass-through; it never inspects the
/// contents.
#[derive(Debug, Clone)]
pub struct StartupSnapshot {
    /// Static build and host identity.
    pub system: SystemInfo,
    /// Initial device environment.
    pub environment: Environment,
}

impl StartupSnapshot {
    /// A placeholder snapshot with no resolved build or host data. Used by
    /// runtime tests, which do not exercise the System tab.
    #[cfg(test)]
    pub(crate) fn placeholder() -> Self {
        let unknown = || "unknown".to_string();
        Self {
            system: SystemInfo {
                build: BuildInfo {
                    version: unknown(),
                    commit: unknown(),
                    commit_date: unknown(),
                    build_date: unknown(),
                    target: unknown(),
                    profile: unknown(),
                    features: String::new(),
                    rustc: unknown(),
                },
                host: HostInfo {
                    arch: std::env::consts::ARCH.to_string(),
                    os: None,
                    os_version: None,
                    kernel_version: None,
                    hostname: None,
                    machine_id: None,
                    cpu_model: None,
                    hardening: None,
                },
                backends: Vec::new(),
            },
            environment: Environment::default(),
        }
    }
}

/// A block device and its mount, as shown in the System tab.
#[derive(Debug, Clone)]
pub struct Disk {
    /// Device name; the stable key for diffing across re-emissions.
    pub name: String,
    /// Mount point path.
    pub mount_point: String,
    /// Filesystem type, when known.
    pub file_system: Option<String>,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Free space in bytes.
    pub available_bytes: u64,
    /// Whether the device is removable.
    pub removable: bool,
    /// Device kind (e.g. `"SSD"`, `"HDD"`), when known.
    pub kind: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_status_round_trips_through_display_and_serde() {
        for status in [
            FeatureStatus::Active,
            FeatureStatus::Inactive,
            FeatureStatus::Unavailable,
            FeatureStatus::NotApplicable,
            FeatureStatus::Unknown,
        ] {
            let text = status.to_string();
            assert_eq!(text.parse::<FeatureStatus>().expect("parses"), status);
            let json = serde_json::to_string(&status).expect("serializes");
            assert_eq!(json, format!("\"{text}\""));
            let back: FeatureStatus = serde_json::from_str(&json).expect("deserializes");
            assert_eq!(back, status);
        }
    }

    #[test]
    fn unknown_feature_status_string_is_rejected() {
        assert!("bogus".parse::<FeatureStatus>().is_err());
    }
}
