//! Reading the files the Linux probes look at: os-release, `/proc`, `/sys`.
//!
//! Every probe takes the root of the file system as a parameter and reads
//! paths relative to it, so the same code runs on a live system (root `/`) and
//! on a fixture captured from one (see `probe_fixtures`).

#![cfg(any(target_os = "linux", test))]

use std::path::Path;

/// The content of `path` without surrounding whitespace, or `None` when it
/// cannot be read.
pub(super) fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

/// Whether `dir` holds an entry whose name passes `wanted`. Names starting
/// with a dot never count: sysfs and procfs have none, and a fixture keeps an
/// empty directory in git with a `.keep` file.
pub(super) fn has_entry(dir: &Path, wanted: impl Fn(&str) -> bool) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !name.starts_with('.') && wanted(&name)
        })
    })
}

/// The value of `field` in the first block of `/proc/cpuinfo`.
pub(super) fn cpuinfo_field<'a>(cpuinfo: &'a str, field: &str) -> Option<&'a str> {
    cpuinfo.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == field).then(|| value.trim())
    })
}

/// Whether the CPU reports `flag` in `/proc/cpuinfo`. Only x86 has a
/// `flags` field; Arm lists `Features`, which has no flag asked for here.
pub(super) fn has_cpu_flag(cpuinfo: &str, flag: &str) -> bool {
    cpuinfo_field(cpuinfo, "flags").is_some_and(|flags| flags.split_whitespace().any(|f| f == flag))
}

/// Whether the kernel release (`6.12.48+deb13-amd64`) is at least
/// `major.minor`. `false` when the release does not start with a version.
pub(super) fn kernel_at_least(release: &str, major: u32, minor: u32) -> bool {
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(str::parse::<u32>);
    match (parts.next(), parts.next()) {
        (Some(Ok(found_major)), Some(Ok(found_minor))) => {
            (found_major, found_minor) >= (major, minor)
        }
        _ => false,
    }
}

/// The value of `key` in a file of `KEY=value` lines (os-release,
/// `.containerenv`), without its quotes.
pub(super) fn key_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let value = line.strip_prefix(key)?.strip_prefix('=')?;
        Some(value.trim().trim_matches(['"', '\'']).to_string())
    })
}

/// A directory tree with the given files, relative to its root. A path
/// ending in `/` is created as an empty directory.
#[cfg(test)]
pub(super) fn fake_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temp dir");
    for (path, content) in files {
        let path = root.path().join(path);
        if path.to_string_lossy().ends_with('/') {
            std::fs::create_dir_all(&path).expect("dirs");
        } else {
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
            std::fs::write(path, content).expect("write");
        }
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release_comparison() {
        assert!(kernel_at_least("6.12.48+deb13-amd64", 6, 10));
        assert!(kernel_at_least("6.10.0", 6, 10));
        assert!(!kernel_at_least("6.9.12-arch1", 6, 10));
        assert!(!kernel_at_least(
            "5.15.167.4-microsoft-standard-WSL2",
            6,
            10
        ));
        assert!(!kernel_at_least("", 6, 10));
    }

    #[test]
    fn cpu_flags_come_from_the_flags_field_only() {
        let cpuinfo = "vendor_id\t: GenuineIntel\nflags\t\t: fpu tme hypervisor\n";
        assert!(has_cpu_flag(cpuinfo, "tme"));
        assert!(!has_cpu_flag(cpuinfo, "sme"));
        assert!(!has_cpu_flag("Features\t: fp asimd\n", "fp"));
    }

    #[test]
    fn key_value_strips_quotes_and_ignores_longer_keys() {
        let os_release = "IMAGE_ID_LIKE=x\nIMAGE_ID='rite'\n";
        assert_eq!(key_value(os_release, "IMAGE_ID").as_deref(), Some("rite"));
    }

    #[test]
    fn dot_entries_do_not_count() {
        let tree = fake_tree(&[("empty/.keep", ""), ("full/SecureBoot-8be4", "")]);
        assert!(!has_entry(&tree.path().join("empty"), |_| true));
        assert!(has_entry(&tree.path().join("full"), |name| name.contains('-')));
        assert!(!has_entry(&tree.path().join("missing"), |_| true));
    }
}
