//! What macOS says about its interfaces beyond `sysinfo`: the kind of each
//! link, whether it is active, and the Wi-Fi and Bluetooth radios.
//!
//! `ifconfig -a -v` prints the link status (`status: active`) and the
//! functional type (`type: Wi-Fi`) of every interface in one call.
//! `networksetup` reads the power of each Wi-Fi radio and `system_profiler`
//! the Bluetooth controller: the `ControllerPowerState` preference is not
//! kept up to date, and the I/O Registry has no such flag.
//!
//! A report leaves out what reads virtual, so a mistake here must leave an
//! interface visible: only what is known to be virtual reads so.
//!
//! The parsers take the text the tools print, so they compile and are tested
//! on any platform; only what runs the tools is macOS only.

use std::collections::HashMap;
use std::ffi::OsStr;

use rite_runtime::{InterfaceKind, Radio};

#[cfg(target_os = "macos")]
use super::super::probe_command::run_probe;

/// The links `ifconfig` lists, by interface name.
pub(super) type Links = HashMap<String, Link>;

/// The link status and the functional type of one interface.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Link {
    /// `status: active` or `status: inactive`; `None` when not printed
    /// (tunnels, some Wi-Fi interfaces).
    active: Option<bool>,
    /// `type: ...` (`"Wi-Fi"`, `"Ethernet"`, ...); `None` when not printed
    /// (tunnels, bridges).
    functional_type: Option<String>,
}

/// The links of every interface; `None` when `ifconfig` failed.
#[cfg(target_os = "macos")]
pub(super) fn read_links() -> Option<Links> {
    run_probe("/sbin/ifconfig", &["-a", "-v"]).map(|text| parse_ifconfig(&text))
}

/// The Wi-Fi and Bluetooth radios, sorted by name. `None` when one of them
/// could not be read: the list is either complete or unknown.
#[cfg(target_os = "macos")]
pub(super) fn read_radios(links: &Links) -> Option<Vec<Radio>> {
    let mut radios = wifi_devices(links)
        .into_iter()
        .map(|device| {
            let output = run_probe("/usr/sbin/networksetup", &["-getairportpower", device])?;
            Some(radio("wlan", device, parse_airport_power(&output)?))
        })
        .collect::<Option<Vec<_>>>()?;
    let bluetooth = run_probe(
        "/usr/sbin/system_profiler",
        &["-json", "-detailLevel", "mini", "SPBluetoothDataType"],
    )?;
    radios.extend(parse_bluetooth(&bluetooth)?);
    radios.sort_by(|a, b| a.name.cmp(&b.name));
    Some(radios)
}

/// The kind and carrier of the interface `name`.
pub(super) fn link(links: Option<&Links>, name: &OsStr) -> (InterfaceKind, Option<bool>) {
    let name = name.to_string_lossy();
    match links.and_then(|links| links.get(name.as_ref())) {
        Some(link) => (
            interface_kind(&name, link.functional_type.as_deref()),
            link.active,
        ),
        None => (InterfaceKind::Unknown, None),
    }
}

/// The kind of an interface from its name and functional type.
///
/// The peer-to-peer and auxiliary Wi-Fi interfaces (`awdl0`, `llw0`, `ap1`)
/// report `Wi-Fi`: they use the radio. A VM's `vmenet0` reports `Ethernet`;
/// only its name tells it apart. Tunnels and bridges report no type, and an
/// `en` interface without one is not recognized rather than virtual.
fn interface_kind(name: &str, functional_type: Option<&str>) -> InterfaceKind {
    match functional_type {
        Some("Wi-Fi") => InterfaceKind::Wireless,
        Some("Cellular") => InterfaceKind::Cellular,
        Some(kind) if kind.contains("Bluetooth") => InterfaceKind::Bluetooth,
        Some("Ethernet" | "USB Ethernet" | "IP over Thunderbolt") => {
            if name.starts_with("vmenet") {
                InterfaceKind::Virtual
            } else {
                InterfaceKind::Ethernet
            }
        }
        Some(_) => InterfaceKind::Unknown,
        None if name.starts_with("en") => InterfaceKind::Unknown,
        None => InterfaceKind::Virtual,
    }
}

/// The devices that hold a Wi-Fi radio. The other interfaces of type `Wi-Fi`
/// use the same radio and have no power of their own.
fn wifi_devices(links: &Links) -> Vec<&str> {
    links
        .iter()
        .filter(|(name, link)| {
            name.starts_with("en") && link.functional_type.as_deref() == Some("Wi-Fi")
        })
        .map(|(name, _)| name.as_str())
        .collect()
}

/// A radio, on or off. A Mac has no hardware radio switch.
fn radio(kind: &str, name: &str, on: bool) -> Radio {
    Radio {
        kind: kind.to_string(),
        name: name.to_string(),
        soft_blocked: !on,
        hard_blocked: false,
    }
}

/// The link of every interface `ifconfig -a -v` prints. An interface starts
/// on a line of its own (`en0: flags=...`); its details follow, indented.
fn parse_ifconfig(text: &str) -> Links {
    let mut links = Links::new();
    let mut current = None;
    for line in text.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line
                .split_once(": ")
                .map(|(name, _)| links.entry(name.to_string()).or_default());
        } else if let Some(link) = &mut current {
            let detail = line.trim();
            if let Some(status) = detail.strip_prefix("status: ") {
                link.active = match status {
                    "active" => Some(true),
                    "inactive" => Some(false),
                    _ => None,
                };
            } else if let Some(kind) = detail.strip_prefix("type: ") {
                link.functional_type = Some(kind.to_string());
            }
        }
    }
    links
}

/// Whether `networksetup -getairportpower` says the Wi-Fi is on:
/// `Wi-Fi Power (en0): On`.
fn parse_airport_power(text: &str) -> Option<bool> {
    match text.trim().rsplit_once(": ")?.1 {
        "On" => Some(true),
        "Off" => Some(false),
        _ => None,
    }
}

/// The Bluetooth controllers `system_profiler -json SPBluetoothDataType`
/// lists and whether each is on. Only the controller state is read; the
/// paired devices the output also names are ignored. Anything but a list of
/// controllers, an empty one included, leaves the radios unknown: an output
/// this parser does not recognize must not read as "no Bluetooth".
fn parse_bluetooth(json: &str) -> Option<Vec<Radio>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let entries = value.get("SPBluetoothDataType")?.as_array()?;
    if entries.is_empty() {
        return None;
    }
    entries
        .iter()
        .map(|entry| {
            let controller = entry.get("controller_properties")?;
            let on = match controller.get("controller_state")?.as_str()? {
                "attrib_on" => true,
                "attrib_off" => false,
                _ => return None,
            };
            let chipset = controller
                .get("controller_chipset")
                .and_then(serde_json::Value::as_str);
            Some(radio("bluetooth", chipset.unwrap_or("bluetooth"), on))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ifconfig -a -v` on a Mac with Wi-Fi up, a USB Ethernet adapter
    /// without a cable and a VM running; trimmed.
    const IFCONFIG: &str = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384 index 1
\tinet 127.0.0.1 netmask 0xff000000
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280 index 2
en1: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500 index 8
\tstatus: inactive
\ttype: IP over Thunderbolt
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 12
\tmember: en1 flags=3<LEARNING,DISCOVER>
\tstatus: inactive
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 11
\tether 02:00:00:00:00:00
\tstatus: active
\ttype: Wi-Fi
\tagent domain:Skywalk type:NetIf flags:0xa443 desc:\"Userspace Networking\"
awdl0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 13
\tstatus: active
\ttype: Wi-Fi
llw0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 14
\ttype: Wi-Fi
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500 index 15
\tagent domain:com.apple.rapport type:RapportNetworkAgent flags:0x7c3
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500 index 27
\tmedia: autoselect (none)
\tstatus: inactive
\ttype: Ethernet
vmenet0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500 index 24
\tstatus: active
\ttype: Ethernet
\tlink rate: 100.00 Mbps
";

    #[test]
    fn kinds_and_carrier_from_ifconfig() {
        let links = parse_ifconfig(IFCONFIG);
        let link = |name: &str| link(Some(&links), OsStr::new(name));
        assert_eq!(link("en0"), (InterfaceKind::Wireless, Some(true)));
        assert_eq!(link("awdl0"), (InterfaceKind::Wireless, Some(true)));
        assert_eq!(link("llw0"), (InterfaceKind::Wireless, None));
        assert_eq!(link("en5"), (InterfaceKind::Ethernet, Some(false)));
        assert_eq!(link("en1"), (InterfaceKind::Ethernet, Some(false)));
        assert_eq!(link("vmenet0"), (InterfaceKind::Virtual, Some(true)));
        assert_eq!(link("bridge0"), (InterfaceKind::Virtual, Some(false)));
        assert_eq!(link("utun0"), (InterfaceKind::Virtual, None));
        assert_eq!(link("gone0"), (InterfaceKind::Unknown, None));
    }

    #[test]
    fn what_is_not_recognized_stays_visible() {
        let unknown = InterfaceKind::Unknown;
        assert_eq!(interface_kind("en7", None), unknown);
        assert_eq!(interface_kind("en7", Some("Something new")), unknown);
        assert_eq!(
            interface_kind("en6", Some("Bluetooth PAN")),
            InterfaceKind::Bluetooth
        );
        assert_eq!(
            link(None, OsStr::new("en0")),
            (InterfaceKind::Unknown, None)
        );
    }

    #[test]
    fn only_the_en_interfaces_hold_a_wifi_radio() {
        assert_eq!(wifi_devices(&parse_ifconfig(IFCONFIG)), ["en0"]);
    }

    #[test]
    fn airport_power() {
        assert_eq!(parse_airport_power("Wi-Fi Power (en0): On\n"), Some(true));
        assert_eq!(parse_airport_power("Wi-Fi Power (en0): Off\n"), Some(false));
        assert_eq!(parse_airport_power("en7 is not a Wi-Fi interface.\n"), None);
    }

    #[test]
    fn bluetooth_controller_state() {
        let json = r#"{"SPBluetoothDataType": [{
            "controller_properties": {
                "controller_chipset": "BCM_4378",
                "controller_state": "attrib_off"
            },
            "device_not_connected": [{"Headphones": {}}]
        }]}"#;
        assert_eq!(
            parse_bluetooth(json),
            Some(vec![Radio {
                kind: "bluetooth".to_string(),
                name: "BCM_4378".to_string(),
                soft_blocked: true,
                hard_blocked: false,
            }])
        );
    }

    #[test]
    fn a_bluetooth_output_not_recognized_leaves_the_radios_unknown() {
        for output in [
            "not json",
            r#"{"SPBluetoothDataType": []}"#,
            r#"{"SPBluetoothDataType": [{"controller_properties":
                {"controller_state": "attrib_unknown"}}]}"#,
            r#"{"SPBluetoothDataType": [{"local_device_title":
                {"general_power": "attrib_on"}}]}"#,
        ] {
            assert_eq!(parse_bluetooth(output), None, "{output}");
        }
    }
}
