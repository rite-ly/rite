//! A text report of what the platform, network and security-feature probes
//! report on the running system, for checking them on systems a fixture
//! cannot hold: interfaces, counters and routes, and every OS but Linux.
//!
//! Addresses and MAC addresses are counted, not printed. Interface names and
//! a container's image name are printed: read the report before publishing it.

use rite_runtime::FeatureCheck;

use super::host::{HostInfoScope, gather_host_info};
use super::network::network_snapshot;
use super::platform::detect_platform;

/// Run every probe and describe the result, one line per value.
#[must_use]
pub fn probe_report() -> String {
    let mut lines: Vec<String> = Vec::new();
    let or_dash = |value: Option<&str>| value.unwrap_or("-").to_string();

    let platform = detect_platform();
    lines.push(format!(
        "os: {} {} ({})",
        or_dash(platform.os.id.as_deref()),
        or_dash(platform.os.version.as_deref()),
        or_dash(platform.os.name.as_deref())
    ));
    lines.push(match &platform.rite_live {
        Some(system) => format!(
            "rite live: {} dm-verity root hash {} ceremony layer {}",
            or_dash(system.version.as_deref()),
            system.root_hash,
            or_dash(system.ceremony_layer.as_deref())
        ),
        None => "rite live: no".to_string(),
    });
    lines.push(match &platform.container {
        Some(container) => format!(
            "container: {} image {}",
            container.kind,
            or_dash(container.image.as_deref())
        ),
        None => "container: not detected".to_string(),
    });
    lines.push(match &platform.virtualization {
        Some(vm) => format!(
            "virtualization: {} ({} / {})",
            vm.kind,
            or_dash(vm.vendor.as_deref()),
            or_dash(vm.product.as_deref())
        ),
        None => "virtualization: not detected".to_string(),
    });

    let host = gather_host_info(HostInfoScope::Full);
    lines.push(format!("cpu: {}", or_dash(host.cpu_model.as_deref())));
    if let Some(hardening) = &host.hardening {
        let feature = |check: &FeatureCheck| match &check.detail {
            Some(detail) => format!("{} ({detail})", check.status),
            None => check.status.to_string(),
        };
        lines.push(format!(
            "ram encryption: {}",
            feature(&hardening.ram_encryption)
        ));
        lines.push(format!(
            "dma protection: {}",
            feature(&hardening.dma_protection)
        ));
        lines.push(format!("secure boot: {}", feature(&hardening.secure_boot)));
    }

    let network = network_snapshot();
    if network.interfaces.is_none() {
        lines.push("interfaces: unknown".to_string());
    }
    for interface in network.interfaces.iter().flatten() {
        let carrier = match interface.carrier {
            Some(true) => "carrier",
            Some(false) => "no carrier",
            None => "carrier unknown",
        };
        lines.push(format!(
            "interface {}: {:?}, {}, {carrier}, {} address(es), {} B in, {} B out",
            interface.name,
            interface.kind,
            interface.state,
            interface.addresses.len(),
            interface.counters.rx_bytes,
            interface.counters.tx_bytes,
        ));
    }
    let route = |route: Option<bool>| match route {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    lines.push(format!(
        "default route: IPv4 {}, IPv6 {}",
        route(network.default_route.v4),
        route(network.default_route.v6)
    ));
    let blocked = |blocked: bool| if blocked { "blocked" } else { "unblocked" };
    match &network.radios {
        None => lines.push("radios: unknown".to_string()),
        Some(radios) if radios.is_empty() => lines.push("radios: none".to_string()),
        Some(radios) => lines.extend(radios.iter().map(|radio| {
            format!(
                "radio {} {}: soft {}, hard {}",
                radio.name,
                radio.kind,
                blocked(radio.soft_blocked),
                blocked(radio.hard_blocked),
            )
        })),
    }

    let mut report = lines.join("\n");
    report.push('\n');
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_covers_every_probe_without_addresses() {
        let report = probe_report();
        for heading in [
            "os:",
            "rite live:",
            "container:",
            "virtualization:",
            "default route:",
            "radios",
        ] {
            assert!(report.contains(heading), "no {heading} line in:\n{report}");
        }
        // Counted, never printed.
        for interface in network_snapshot().interfaces.into_iter().flatten() {
            for address in &interface.addresses {
                let ip = address.split('/').next().unwrap_or_default();
                assert!(!report.contains(ip), "{ip} printed in:\n{report}");
            }
            if let Some(mac) = &interface.mac {
                assert!(!report.contains(mac.as_str()), "{mac} printed");
            }
        }
    }
}
