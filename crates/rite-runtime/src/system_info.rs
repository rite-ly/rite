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
//!
//! [`RunHost`] is what the runner records in every run: the [`Platform`]
//! once, and a [`NetworkSnapshot`]'s [`NetworkState`] at the opening and the
//! closing.

use std::net::IpAddr;
use std::sync::Arc;

pub use rite_model::network::{
    Counters, DefaultRoute, InterfaceKind, InterfaceState, NetworkState, Radio,
};
pub use rite_model::platform::{
    Container, FeatureCheck, FeatureStatus, OsIdentity, Platform, RiteLive, Virtualization,
};
use serde::{Deserialize, Serialize};

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
    /// UEFI Secure Boot.
    pub secure_boot: FeatureCheck,
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

/// The network state of the machine at one point in time, as the probe reads
/// it.
///
/// Gathered on demand, as often as needed: the counters of two snapshots
/// bracket what crossed each interface between them. The transcript records
/// its [`NetworkState`], which leaves out hardware and network addresses.
#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    /// Every network interface except loopback, sorted by name. `None` when
    /// the interfaces could not be listed.
    pub interfaces: Option<Vec<NetworkInterface>>,
    /// Whether the system has a route to an address outside its local
    /// networks, per address family.
    pub default_route: DefaultRoute,
    /// Radios registered with rfkill (Wi-Fi, Bluetooth, cellular). `None`
    /// when unknown: outside Linux, when rfkill cannot be read, or when
    /// rfkill is absent and `/sys/class` or the interface list is
    /// unavailable or a radio interface is present.
    pub radios: Option<Vec<Radio>>,
}

impl NetworkSnapshot {
    /// What the transcript records of this snapshot: each interface's state,
    /// whether it has an address instead of the addresses, and no hardware
    /// address.
    #[must_use]
    pub fn recorded(&self) -> NetworkState {
        NetworkState {
            interfaces: self.interfaces.as_ref().map(|interfaces| {
                interfaces
                    .iter()
                    .map(|interface| InterfaceState {
                        name: interface.name.clone(),
                        kind: interface.kind,
                        state: interface.state.clone(),
                        carrier: interface.carrier,
                        address: interface.addresses.iter().any(|a| is_routable(a)),
                        counters: interface.counters,
                    })
                    .collect()
            }),
            default_route: self.default_route,
            radios: self.radios.clone(),
        }
    }
}

/// Whether an address (`"192.168.1.20/24"`) is neither loopback nor
/// link-local. Every IPv6 interface that is up has a link-local address, so
/// one says nothing about a network. An address that does not parse counts.
fn is_routable(address: &str) -> bool {
    let ip = address.split('/').next().unwrap_or(address);
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !ip.is_loopback() && !ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => !ip.is_loopback() && !ip.is_unicast_link_local(),
        Err(_) => true,
    }
}

/// Reads the network state on demand. The runner takes a measurement at the
/// opening and the closing of a run; the CLI provides the probe, and tests a
/// scripted one.
pub trait NetworkProbe: Send + Sync {
    /// Measure the network now.
    fn snapshot(&self) -> NetworkSnapshot;
}

impl<F: Fn() -> NetworkSnapshot + Send + Sync> NetworkProbe for F {
    fn snapshot(&self) -> NetworkSnapshot {
        self()
    }
}

/// What the runner records about the machine a run happens on: the
/// platform, once, and the network, at the opening and the closing.
///
/// Assembled by the CLI, which holds the probes; `rite-runtime` reads no
/// system state itself.
#[derive(Clone)]
pub struct RunHost {
    /// The platform, detected before the run.
    pub platform: Platform,
    /// The network probe, called at each measurement.
    pub network: Arc<dyn NetworkProbe>,
}

impl RunHost {
    /// A test host with only the architecture known and a network probe that
    /// returns a default snapshot, every value of which is unknown. Used by
    /// runtime tests.
    #[cfg(test)]
    pub(crate) fn placeholder() -> Self {
        Self {
            platform: Platform {
                arch: std::env::consts::ARCH.to_string(),
                os: OsIdentity::default(),
                rite_live: None,
                container: None,
                virtualization: None,
                secure_boot: FeatureCheck::new(FeatureStatus::Unknown),
            },
            network: Arc::new(NetworkSnapshot::default),
        }
    }
}

/// A network interface and its state.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name (e.g. `"eth0"`, `"en0"`); the stable key across
    /// snapshots.
    pub name: String,
    /// What kind of link the interface is.
    pub kind: InterfaceKind,
    /// Operational state as the system reports it (e.g. `"up"`, `"down"`).
    pub state: String,
    /// Whether a link is detected (a cable plugged in, an associated access
    /// point), when the system reports it.
    pub carrier: Option<bool>,
    /// Hardware address, when the interface has one.
    pub mac: Option<String>,
    /// Addresses with their prefix length (e.g. `"192.168.1.20/24"`).
    pub addresses: Vec<String>,
    /// Traffic since the interface appeared.
    pub counters: Counters,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_interface_says_whether_it_has_an_address_not_which() {
        let interface = |addresses: &[&str]| NetworkInterface {
            name: "en0".to_string(),
            kind: InterfaceKind::Ethernet,
            state: "up".to_string(),
            carrier: Some(true),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            addresses: addresses.iter().map(ToString::to_string).collect(),
            counters: Counters::default(),
        };
        let snapshot = NetworkSnapshot {
            interfaces: Some(vec![
                interface(&["fe80::1/64", "169.254.3.4/16"]),
                interface(&["fe80::1/64", "192.168.1.20/24"]),
                interface(&["2001:db8::5/64"]),
                interface(&[]),
            ]),
            ..NetworkSnapshot::default()
        };
        let recorded = snapshot.recorded();
        let flags: Vec<bool> = recorded
            .interfaces
            .iter()
            .flatten()
            .map(|i| i.address)
            .collect();
        assert_eq!(flags, [false, true, true, false]);
        let json = serde_json::to_string(&recorded).expect("serializes");
        assert!(
            !json.contains("aa:bb") && !json.contains("192.168"),
            "{json}"
        );
        assert!(NetworkSnapshot::default().recorded().interfaces.is_none());
    }
}
