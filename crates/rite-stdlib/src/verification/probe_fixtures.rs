//! The Linux probes, run over the files captured on real systems.
//!
//! Each directory under `tests/fixtures/probes/` is one system, named after
//! where the probes ran, then the system and the architecture, with the
//! hardware or a variant last (`qemu-hvf-debian-13-arm64`). `root/` holds the
//! files the probes read there and `expected.txt` what the probes report from
//! them.
//!
//! To add a system:
//!
//! 1. Run `scripts/capture-probe-fixture.sh <new directory>` on it as an
//!    ordinary user, the way `rite` runs on Rite Live.
//! 2. Copy the directory here and read every file: the script copies no MAC
//!    address, IP address or serial number, and only `roothash=` from the
//!    kernel command line, but the files are published.
//! 3. Run `RITE_UPDATE_PROBE_FIXTURES=1 cargo test -p rite-stdlib --lib
//!    probe_fixtures` and check each line of the new `expected.txt` against
//!    the machine itself: its firmware settings, its radios, the container or
//!    virtual machine it runs in.
//!
//! When a probe changes, this test shows which systems' results change;
//! accept them the same way, after reading the diff. What a fixture cannot
//! hold (interfaces, counters, routes, other OSes) is checked by running
//! `rite system` on the machine.

#![cfg(test)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rite_runtime::FeatureCheck;

use super::host::{ram_encryption, secure_boot};
use super::network::{radios, sysfs_link};
use super::platform::detect_linux;
use super::probe_files::read_trimmed;

/// The fixtures, sorted by name.
fn fixtures() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probes");
    let mut fixtures: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("tests/fixtures/probes")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    fixtures.sort();
    fixtures
}

fn name(fixture: &Path) -> String {
    fixture
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// What the probes report from the files under `root`, one line per value.
fn describe(root: &Path) -> String {
    let platform = detect_linux(root);
    let or_dash = |value: Option<&str>| value.unwrap_or("-").to_string();
    let feature = |check: &FeatureCheck| match &check.detail {
        Some(detail) => format!("{} ({detail})", check.status),
        None => check.status.to_string(),
    };

    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    line(format!(
        "os: {} {} ({})",
        or_dash(platform.os.id.as_deref()),
        or_dash(platform.os.version.as_deref()),
        or_dash(platform.os.name.as_deref())
    ));
    line(match &platform.rite_live {
        Some(system) => format!(
            "rite live: {} root hash {} ceremony layer {}",
            or_dash(system.version.as_deref()),
            system.root_hash,
            or_dash(system.ceremony_layer.as_deref())
        ),
        None => "rite live: no".to_string(),
    });
    line(match &platform.container {
        Some(container) => format!(
            "container: {} image {}",
            container.kind,
            or_dash(container.image.as_deref())
        ),
        None => "container: not detected".to_string(),
    });
    line(match &platform.virtualization {
        Some(vm) => format!(
            "virtualization: {} ({} / {})",
            vm.kind,
            or_dash(vm.vendor.as_deref()),
            or_dash(vm.product.as_deref())
        ),
        None => "virtualization: not detected".to_string(),
    });

    let cpuinfo = std::fs::read_to_string(root.join("proc/cpuinfo")).unwrap_or_default();
    let release = read_trimmed(&root.join("proc/sys/kernel/osrelease")).unwrap_or_default();
    // A fixture holds no kernel log: what dmesg would say is not captured.
    line(format!(
        "ram encryption: {}",
        feature(&ram_encryption(&cpuinfo, &release, || None))
    ));
    line(format!("secure boot: {}", feature(&secure_boot(root))));

    let mut kinds = Vec::new();
    let mut interfaces: Vec<PathBuf> = std::fs::read_dir(root.join("sys/class/net"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default();
    interfaces.sort();
    for dir in interfaces
        .iter()
        .filter(|dir| dir.is_dir() && name(dir) != "lo")
    {
        let (kind, carrier) = sysfs_link(dir);
        kinds.push(kind);
        let carrier = match carrier {
            Some(true) => "carrier",
            Some(false) => "no carrier",
            None => "carrier unknown",
        };
        line(format!("interface {}: {kind:?}, {carrier}", name(dir)));
    }
    line(match radios(&root.join("sys/class/rfkill"), kinds) {
        None => "radios: unknown".to_string(),
        Some(radios) if radios.is_empty() => "radios: none".to_string(),
        Some(radios) => {
            let mut text = "radios:".to_string();
            for radio in radios {
                let _ = write!(
                    text,
                    " {} {}{}{};",
                    radio.name,
                    radio.kind,
                    if radio.soft_blocked {
                        " soft-blocked"
                    } else {
                        ""
                    },
                    if radio.hard_blocked {
                        " hard-blocked"
                    } else {
                        ""
                    },
                );
            }
            text
        }
    });
    out
}

#[test]
fn every_fixture_gives_its_expected_result() {
    let update = std::env::var_os("RITE_UPDATE_PROBE_FIXTURES").is_some();
    let fixtures = fixtures();
    assert!(
        !fixtures.is_empty(),
        "no fixture under tests/fixtures/probes"
    );
    let mut mismatches = Vec::new();
    for fixture in &fixtures {
        let found = describe(&fixture.join("root"));
        let expected_path = fixture.join("expected.txt");
        if update {
            std::fs::write(&expected_path, &found).expect("write expected.txt");
            continue;
        }
        let expected = std::fs::read_to_string(&expected_path).unwrap_or_default();
        if found != expected {
            mismatches.push(format!(
                "{}\n--- expected\n{expected}--- found\n{found}",
                name(fixture)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "probe fixtures differ (accept with RITE_UPDATE_PROBE_FIXTURES=1):\n{}",
        mismatches.join("\n")
    );
}
