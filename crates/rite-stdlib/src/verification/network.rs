//! The network state of the machine: interfaces, default routes, radios.
//!
//! Nothing here sends traffic. Interfaces, addresses and counters come from
//! `sysinfo` on every platform; on Linux, sysfs adds the kind of each
//! interface, its carrier and the radios. The route check opens a UDP socket
//! and connects it, which only queries the routing table. The sysfs probes
//! read under a root given as a parameter (see `probe_fixtures`).

use std::io::ErrorKind;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use rite_runtime::Radio;
use rite_runtime::{Counters, InterfaceKind, NetworkInterface, NetworkSnapshot};

#[cfg(any(target_os = "linux", test))]
use super::probe_files::{has_entry, read_trimmed};

/// An IPv4 address no network uses (RFC 5737, documentation range): only a
/// default route reaches it.
const IPV4_OUTSIDE: &str = "192.0.2.1:9";

/// An IPv6 address no network uses (RFC 3849, documentation range): only a
/// default route reaches it.
const IPV6_OUTSIDE: &str = "[2001:db8::1]:9";

/// `ARPHRD_ETHER` in `/sys/class/net/<name>/type`.
#[cfg(any(target_os = "linux", test))]
const ARPHRD_ETHER: u16 = 1;

/// `ARPHRD_RAWIP` in `/sys/class/net/<name>/type`: the raw IP link of a
/// cellular modem (`qmi_wwan`, `mhi_net`).
#[cfg(any(target_os = "linux", test))]
const ARPHRD_RAWIP: u16 = 519;

/// Take a snapshot of the network state.
#[must_use]
pub fn network_snapshot() -> NetworkSnapshot {
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let mut interfaces: Vec<NetworkInterface> = networks
        .list()
        .iter()
        .filter(|(name, data)| is_interface(name) && !is_loopback(name, data.ip_networks()))
        .map(|(name, data)| {
            let (kind, carrier) = link(name);
            let mac = data.mac_address();
            NetworkInterface {
                name: name.clone(),
                kind,
                state: data.operational_state().to_string(),
                carrier,
                mac: (!mac.is_unspecified()).then(|| mac.to_string()),
                addresses: data.ip_networks().iter().map(ToString::to_string).collect(),
                counters: Counters {
                    rx_bytes: data.total_received(),
                    tx_bytes: data.total_transmitted(),
                    rx_packets: data.total_packets_received(),
                    tx_packets: data.total_packets_transmitted(),
                },
            }
        })
        .collect();
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    #[cfg(target_os = "linux")]
    let radios = radios(
        Path::new("/sys/class/rfkill"),
        interfaces.iter().map(|interface| interface.kind),
    );
    #[cfg(not(target_os = "linux"))]
    let radios = None;
    NetworkSnapshot {
        interfaces,
        default_route_v4: has_route("0.0.0.0:0", IPV4_OUTSIDE),
        default_route_v6: has_route("[::]:0", IPV6_OUTSIDE),
        radios,
    }
}

/// Whether an interface is loopback: named so, or with only loopback
/// addresses.
fn is_loopback(name: &str, addresses: &[sysinfo::IpNetwork]) -> bool {
    matches!(name, "lo" | "lo0")
        || (!addresses.is_empty() && addresses.iter().all(|net| net.addr.is_loopback()))
}

/// Whether the system has a route to `target`. Connecting a UDP socket picks
/// the route and the source address; no packet leaves. Only "network
/// unreachable" and "host unreachable" mean no route; any other failure
/// leaves the answer unknown.
fn has_route(bind: &str, target: &str) -> Option<bool> {
    let connected = std::net::UdpSocket::bind(bind).and_then(|socket| {
        socket.connect(target)?;
        socket.local_addr()
    });
    match connected {
        Ok(_) => Some(true),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
            ) =>
        {
            Some(false)
        }
        Err(_) => None,
    }
}

/// Whether `name` is an interface. `sysinfo` lists every entry of
/// `/sys/class/net`, and the bonding driver keeps a file there
/// (`bonding_masters`); interfaces are directories.
#[cfg(target_os = "linux")]
fn is_interface(name: &str) -> bool {
    Path::new("/sys/class/net").join(name).is_dir()
}

#[cfg(not(target_os = "linux"))]
fn is_interface(_name: &str) -> bool {
    true
}

#[cfg(target_os = "linux")]
fn link(name: &str) -> (InterfaceKind, Option<bool>) {
    sysfs_link(&Path::new("/sys/class/net").join(name))
}

#[cfg(not(target_os = "linux"))]
fn link(_name: &str) -> (InterfaceKind, Option<bool>) {
    (InterfaceKind::Unknown, None)
}

/// The kind and carrier of the interface whose sysfs directory is `dir`
/// (`/sys/class/net/<name>`).
#[cfg(any(target_os = "linux", test))]
pub(super) fn sysfs_link(dir: &Path) -> (InterfaceKind, Option<bool>) {
    if !dir.is_dir() {
        return (InterfaceKind::Unknown, None);
    }
    let read = |file: &str| read_trimmed(&dir.join(file));
    let devtype = read("uevent").and_then(|uevent| {
        uevent
            .lines()
            .find_map(|line| line.strip_prefix("DEVTYPE="))
            .map(str::to_string)
    });
    let kind = interface_kind(
        read("type").and_then(|value| value.parse().ok()),
        devtype.as_deref(),
        dir.join("wireless").exists() || dir.join("phy80211").exists(),
        dir.join("device").exists(),
    );
    // The kernel refuses to report carrier on an interface that is
    // administratively down.
    let carrier = read("carrier").map(|carrier| carrier == "1");
    (kind, carrier)
}

/// The kind of an interface from what sysfs says about it: the ARP hardware
/// type, the `DEVTYPE` of its `uevent`, whether it has a `wireless` directory,
/// and whether a device backs it. Radio links come first: a Wi-Fi card, a
/// Bluetooth PAN and some modems all report the Ethernet type.
#[cfg(any(target_os = "linux", test))]
fn interface_kind(
    arp_type: Option<u16>,
    devtype: Option<&str>,
    wireless: bool,
    has_device: bool,
) -> InterfaceKind {
    if wireless || devtype == Some("wlan") {
        InterfaceKind::Wireless
    } else if devtype == Some("wwan") || arp_type == Some(ARPHRD_RAWIP) {
        InterfaceKind::Cellular
    } else if devtype == Some("bluetooth") {
        InterfaceKind::Bluetooth
    } else if !has_device {
        InterfaceKind::Virtual
    } else if arp_type == Some(ARPHRD_ETHER) {
        InterfaceKind::Ethernet
    } else {
        InterfaceKind::Unknown
    }
}

/// The radios under `rfkill` (`/sys/class/rfkill`), sorted by name.
///
/// The directory exists only once a driver registered a radio. Without it,
/// "no radios" holds only when no interface is a radio link either;
/// otherwise rfkill is hidden or absent from the kernel, and the radios are
/// unknown.
#[cfg(any(target_os = "linux", test))]
pub(super) fn radios(
    rfkill: &Path,
    interface_kinds: impl IntoIterator<Item = InterfaceKind>,
) -> Option<Vec<Radio>> {
    if !has_entry(rfkill, |_| true) {
        let radio_link = interface_kinds.into_iter().any(InterfaceKind::is_radio);
        return (!radio_link).then(Vec::new);
    }
    let entries = std::fs::read_dir(rfkill).ok()?;
    let mut radios: Vec<Radio> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let dir = entry.path();
            let read = |file: &str| read_trimmed(&dir.join(file));
            Some(Radio {
                kind: read("type")?,
                name: read("name").unwrap_or_default(),
                soft_blocked: read("soft").as_deref() == Some("1"),
                hard_blocked: read("hard").as_deref() == Some("1"),
            })
        })
        .collect();
    radios.sort_by(|a, b| a.name.cmp(&b.name));
    Some(radios)
}

#[cfg(test)]
mod tests {
    use super::super::probe_files::fake_tree;
    use super::*;

    #[test]
    fn interface_kinds_from_sysfs() {
        let net = fake_tree(&[
            ("enp3s0/type", "1\n"),
            ("enp3s0/device/", ""),
            ("enp3s0/carrier", "1\n"),
            ("wlan0/type", "1\n"),
            ("wlan0/device/", ""),
            ("wlan0/uevent", "DEVTYPE=wlan\nINTERFACE=wlan0\n"),
            ("wlp2s0/type", "1\n"),
            ("wlp2s0/device/", ""),
            ("wlp2s0/phy80211/", ""),
            ("wwan0/type", "519\n"),
            ("wwan0/device/", ""),
            ("bnep0/type", "1\n"),
            ("bnep0/device/", ""),
            ("bnep0/uevent", "DEVTYPE=bluetooth\nINTERFACE=bnep0\n"),
            ("docker0/type", "1\n"),
            ("docker0/uevent", "DEVTYPE=bridge\n"),
            ("docker0/carrier", "0\n"),
            ("tun0/type", "65534\n"),
        ]);
        let link = |name| sysfs_link(&net.path().join(name));
        assert_eq!(link("enp3s0"), (InterfaceKind::Ethernet, Some(true)));
        assert_eq!(link("wlan0").0, InterfaceKind::Wireless);
        assert_eq!(link("wlp2s0").0, InterfaceKind::Wireless);
        assert_eq!(link("wwan0").0, InterfaceKind::Cellular);
        assert_eq!(link("bnep0").0, InterfaceKind::Bluetooth);
        assert_eq!(link("docker0"), (InterfaceKind::Virtual, Some(false)));
        assert_eq!(link("tun0"), (InterfaceKind::Virtual, None));
        assert_eq!(link("gone0"), (InterfaceKind::Unknown, None));
    }

    #[test]
    fn interface_kind_of_a_device_with_another_link_type_is_unknown() {
        assert_eq!(
            interface_kind(Some(32), None, false, true),
            InterfaceKind::Unknown
        );
    }

    #[test]
    fn radios_from_rfkill() {
        let rfkill = fake_tree(&[
            ("rfkill1/type", "bluetooth\n"),
            ("rfkill1/name", "hci0\n"),
            ("rfkill1/soft", "1\n"),
            ("rfkill1/hard", "0\n"),
            ("rfkill0/type", "wlan\n"),
            ("rfkill0/name", "phy0\n"),
            ("rfkill0/soft", "0\n"),
            ("rfkill0/hard", "1\n"),
            ("rfkill2/name", "no type\n"),
        ]);
        let radios = radios(rfkill.path(), []).expect("radios");
        let summary: Vec<_> = radios
            .iter()
            .map(|r| {
                (
                    r.kind.as_str(),
                    r.name.as_str(),
                    r.soft_blocked,
                    r.hard_blocked,
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("bluetooth", "hci0", true, false),
                ("wlan", "phy0", false, true),
            ]
        );
    }

    #[test]
    fn without_rfkill_radios_are_none_only_when_no_link_is_a_radio() {
        let root = tempfile::tempdir().expect("temp dir");
        let rfkill = root.path().join("rfkill");
        let wired = [InterfaceKind::Ethernet, InterfaceKind::Virtual];
        assert_eq!(radios(&rfkill, wired).map(|r| r.len()), Some(0));
        let with_wifi = [InterfaceKind::Ethernet, InterfaceKind::Wireless];
        assert!(radios(&rfkill, with_wifi).is_none());
    }

    #[test]
    fn loopback_by_name_or_addresses() {
        let net = |addr: &str| sysinfo::IpNetwork {
            addr: addr.parse().expect("an address"),
            prefix: 8,
        };
        assert!(is_loopback("lo", &[]));
        assert!(is_loopback("lo0", &[net("127.0.0.1")]));
        assert!(is_loopback("other", &[net("127.0.0.1"), net("::1")]));
        assert!(!is_loopback("en0", &[]));
        assert!(!is_loopback("en0", &[net("127.0.0.1"), net("192.168.1.2")]));
    }

    #[test]
    fn snapshot_of_the_running_machine() {
        // The network of a CI runner is whatever it is: check the shape only.
        let snapshot = network_snapshot();
        assert!(snapshot.interfaces.is_sorted_by(|a, b| a.name < b.name));
        assert!(
            snapshot
                .interfaces
                .iter()
                .all(|i| !matches!(i.name.as_str(), "lo" | "lo0"))
        );
        if !cfg!(target_os = "linux") {
            assert!(snapshot.radios.is_none());
        }
    }
}
