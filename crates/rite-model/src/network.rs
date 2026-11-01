//! The network state of the machine, as the runner records it.
//!
//! The runner records a [`NetworkState`] at the opening and the closing of
//! every run, as
//! [`StepFact::NetworkStateRecorded`](crate::StepFact::NetworkStateRecorded).
//! Interface counters usually increase while an interface exists. A reset
//! can make them decrease, so two measurements bracket what crossed each
//! interface between them, whichever process sent it, only if the counters
//! do not reset between them. Hardware and network addresses are not part
//! of the record.

use std::fmt;

use serde::{Deserialize, Serialize};

/// When a network measurement was taken.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "When the measurement was taken."))]
pub enum NetworkMoment {
    /// Once the operator started the ceremony, before any material is
    /// loaded.
    #[cfg_attr(
        test,
        schemars(description = "Once the ceremony started, before any material was loaded.")
    )]
    Opening,
    /// Before the ceremony's terminal fact, whether it completed or failed.
    #[cfg_attr(
        test,
        schemars(
            description = "Before the terminal fact, whether the ceremony completed or failed."
        )
    )]
    Closing,
}

crate::types::vocabulary!(NetworkMoment {
    Opening => "opening",
    Closing => "closing",
});

impl fmt::Display for NetworkMoment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The network state at one point in time.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(description = "The network state at one point in time.")
)]
pub struct NetworkState {
    /// Every network interface except loopback, sorted by name. `None` when
    /// the interfaces could not be listed.
    #[cfg_attr(
        test,
        schemars(
            description = "Every network interface except loopback, sorted by name; null when \
            the interfaces could not be listed."
        )
    )]
    pub interfaces: Option<Vec<InterfaceState>>,
    /// Whether a default route exists, per address family.
    #[cfg_attr(test, schemars(description = "Whether a default route exists."))]
    pub default_route: DefaultRoute,
    /// Radios registered with rfkill (Wi-Fi, Bluetooth, cellular). `None`
    /// when unknown: outside Linux, when rfkill cannot be read, or when
    /// rfkill is absent and `/sys/class` or the interface list is
    /// unavailable or a radio interface is present.
    #[cfg_attr(
        test,
        schemars(
            description = "Radios registered with rfkill (Wi-Fi, Bluetooth, cellular); null when \
            unknown: outside Linux, when rfkill cannot be read, or when rfkill is absent and \
            /sys/class or the interface list is unavailable or a radio interface is present."
        )
    )]
    pub radios: Option<Vec<Radio>>,
}

impl fmt::Display for NetworkState {
    /// One line: how many interfaces, how many are up and have an address,
    /// the default routes and the radios. Unknown values say so.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.interfaces {
            Some(interfaces) => {
                let up = interfaces.iter().filter(|i| i.state == "up").count();
                let addressed = interfaces.iter().filter(|i| i.address).count();
                write!(
                    f,
                    "{} interfaces ({up} up, {addressed} with an address)",
                    interfaces.len()
                )?;
            }
            None => f.write_str("interfaces unknown")?,
        }
        let route = |route: Option<bool>| match route {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        write!(
            f,
            ", default route IPv4 {}, IPv6 {}",
            route(self.default_route.v4),
            route(self.default_route.v6)
        )?;
        match &self.radios {
            None => f.write_str(", radios unknown"),
            Some(radios) if radios.is_empty() => f.write_str(", no radios"),
            Some(radios) => {
                let unblocked = radios
                    .iter()
                    .filter(|r| !r.soft_blocked && !r.hard_blocked)
                    .count();
                write!(f, ", {} radios ({unblocked} unblocked)", radios.len())
            }
        }
    }
}

/// One network interface and its state.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "A network interface and its state."))]
pub struct InterfaceState {
    /// Interface name as the system gives it (e.g. `"eth0"`, `"en0"`); the
    /// key across measurements.
    #[cfg_attr(
        test,
        schemars(
            description = "The interface name as the system gives it; the key across measurements."
        )
    )]
    pub name: String,
    /// What kind of link the interface is.
    #[cfg_attr(test, schemars(description = "What kind of link the interface is."))]
    pub kind: InterfaceKind,
    /// Operational state as the system reports it (e.g. `"up"`, `"down"`).
    #[cfg_attr(
        test,
        schemars(
            description = "The operational state as the system reports it, such as up or down."
        )
    )]
    pub state: String,
    /// Whether a link is detected (a cable plugged in, an associated access
    /// point), when the system reports it.
    #[cfg_attr(
        test,
        schemars(description = "Whether a link is detected; null when the system does not say.")
    )]
    pub carrier: Option<bool>,
    /// Whether the interface has an address that is neither loopback nor
    /// link-local.
    #[cfg_attr(
        test,
        schemars(
            description = "Whether the interface has an address that is neither loopback nor link-local."
        )
    )]
    pub address: bool,
    /// Traffic since the interface appeared.
    #[cfg_attr(test, schemars(description = "Traffic since the interface appeared."))]
    pub counters: Counters,
}

/// What kind of link a network interface is.
#[non_exhaustive]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, schemars(description = "What kind of link an interface is."))]
pub enum InterfaceKind {
    /// Wired Ethernet, including USB Ethernet adapters.
    #[cfg_attr(
        test,
        schemars(description = "Wired Ethernet, including USB adapters.")
    )]
    Ethernet,
    /// Wi-Fi.
    #[cfg_attr(test, schemars(description = "Wi-Fi."))]
    Wireless,
    /// A cellular modem.
    #[cfg_attr(test, schemars(description = "A cellular modem."))]
    Cellular,
    /// A Bluetooth network link (PAN, `bnep*`).
    #[cfg_attr(test, schemars(description = "A Bluetooth network link."))]
    Bluetooth,
    /// An interface with no device behind it: a bridge, a tunnel, a VPN, a
    /// container's virtual link.
    #[cfg_attr(
        test,
        schemars(
            description = "No device behind it: a bridge, a tunnel, a VPN, a container's link."
        )
    )]
    Virtual,
    /// Not determined (every platform but Linux).
    #[cfg_attr(test, schemars(description = "Not determined."))]
    Unknown,
}

crate::types::vocabulary!(InterfaceKind {
    Ethernet => "ethernet",
    Wireless => "wireless",
    Cellular => "cellular",
    Bluetooth => "bluetooth",
    Virtual => "virtual",
    Unknown => "unknown",
});

impl InterfaceKind {
    /// Whether the link is a radio: Wi-Fi, cellular or Bluetooth.
    #[must_use]
    pub fn is_radio(self) -> bool {
        match self {
            InterfaceKind::Wireless | InterfaceKind::Cellular | InterfaceKind::Bluetooth => true,
            InterfaceKind::Ethernet | InterfaceKind::Virtual | InterfaceKind::Unknown => false,
        }
    }
}

impl fmt::Display for InterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Traffic counters of an interface. They usually increase while the
/// interface exists; a reset can make them decrease.
///
/// Recorded as decimal strings: a kernel counter is 64 bits, and a fact
/// holds no integer above `2^53 - 1` (see [`crate::canonical_json`]).
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(description = "Traffic since the interface appeared, each count a decimal string.")
)]
pub struct Counters {
    /// Bytes received.
    #[serde(with = "decimal")]
    #[cfg_attr(test, schemars(with = "String", description = "Bytes received.", extend("pattern" = "^(0|[1-9][0-9]*)$")))]
    pub rx_bytes: u64,
    /// Bytes sent.
    #[serde(with = "decimal")]
    #[cfg_attr(test, schemars(with = "String", description = "Bytes sent.", extend("pattern" = "^(0|[1-9][0-9]*)$")))]
    pub tx_bytes: u64,
    /// Packets received.
    #[serde(with = "decimal")]
    #[cfg_attr(test, schemars(with = "String", description = "Packets received.", extend("pattern" = "^(0|[1-9][0-9]*)$")))]
    pub rx_packets: u64,
    /// Packets sent.
    #[serde(with = "decimal")]
    #[cfg_attr(test, schemars(with = "String", description = "Packets sent.", extend("pattern" = "^(0|[1-9][0-9]*)$")))]
    pub tx_packets: u64,
}

/// Whether a default route exists, per address family. `None` when the check
/// failed for another reason than a missing route (a sandbox that forbids
/// sockets, for one).
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(
    test,
    schemars(
        description = "Whether a default route exists, per address family; null when unknown."
    )
)]
pub struct DefaultRoute {
    /// IPv4.
    #[cfg_attr(test, schemars(description = "IPv4."))]
    pub v4: Option<bool>,
    /// IPv6.
    #[cfg_attr(test, schemars(description = "IPv6."))]
    pub v6: Option<bool>,
}

/// A radio and whether it is blocked.
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, schemars(description = "A radio and whether it is blocked."))]
pub struct Radio {
    /// The radio type as the kernel names it (`"wlan"`, `"bluetooth"`,
    /// `"wwan"`, `"gps"`, `"nfc"`, ...).
    #[cfg_attr(
        test,
        schemars(
            description = "The radio type as the kernel names it, such as wlan or bluetooth."
        )
    )]
    pub kind: String,
    /// The name the driver gives the radio (e.g. `"phy0"`, `"hci0"`).
    #[cfg_attr(test, schemars(description = "The name the driver gives the radio."))]
    pub name: String,
    /// Blocked in software (`rfkill block`, a desktop toggle).
    #[cfg_attr(test, schemars(description = "Blocked in software."))]
    pub soft_blocked: bool,
    /// Blocked by a hardware switch.
    #[cfg_attr(test, schemars(description = "Blocked by a hardware switch."))]
    pub hard_blocked: bool,
}

/// A `u64` as a decimal string, so it stays exact past `2^53 - 1`.
mod decimal {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    // `serde(with)` passes the field by reference.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        // `str::parse` also takes a leading `+`.
        let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        if !digits || (text.len() > 1 && text.starts_with('0')) {
            return Err(D::Error::custom(
                "a count is a decimal string with no leading zero",
            ));
        }
        text.parse()
            .map_err(|_| D::Error::custom("a count does not fit in 64 bits"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_exact_decimal_strings() {
        let counters = Counters {
            rx_bytes: u64::MAX,
            tx_bytes: 0,
            rx_packets: 1 << 53,
            tx_packets: 7,
        };
        let json = serde_json::to_value(counters).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({
                "rx_bytes": "18446744073709551615",
                "tx_bytes": "0",
                "rx_packets": "9007199254740992",
                "tx_packets": "7",
            })
        );
        let back: Counters = serde_json::from_value(json).expect("parses");
        assert_eq!(back, counters);
        for bad in ["\"01\"", "\"-1\"", "\"+1\"", "\"1.0\"", "\"\"", "1"] {
            let line =
                format!(r#"{{"rx_bytes":{bad},"tx_bytes":"0","rx_packets":"0","tx_packets":"0"}}"#);
            assert!(serde_json::from_str::<Counters>(&line).is_err(), "{bad}");
        }
    }
}
