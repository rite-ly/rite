//! Assembly of the [`SystemInfo`] and [`Environment`] snapshots.
//!
//! This is the single source for build identity: the `RITE_BUILD_*` constants
//! are produced by this crate's `build.rs`, so they are only reachable here.
//! Both the System tab (via UI signals) and `rite version --verbose` consume
//! what this module gathers.

use rite_runtime::{BuildInfo, Environment, HostInfo, SystemInfo};

/// Assemble static build and host identity.
#[must_use]
pub fn gather_system() -> SystemInfo {
    SystemInfo {
        build: build_info(),
        host: host_info(),
        backends: backends(),
    }
}

/// Gather the live device environment (disks today).
#[must_use]
pub fn gather_environment() -> Environment {
    #[cfg(feature = "verification")]
    {
        rite_stdlib::gather_environment()
    }
    #[cfg(not(feature = "verification"))]
    {
        Environment::default()
    }
}

fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("RITE_BUILD_COMMIT").to_string(),
        commit_date: env!("RITE_BUILD_COMMIT_DATE").to_string(),
        build_date: env!("RITE_BUILD_DATE").to_string(),
        target: env!("RITE_BUILD_TARGET").to_string(),
        profile: env!("RITE_BUILD_PROFILE").to_string(),
        features: env!("RITE_BUILD_FEATURES").to_string(),
        rustc: env!("RITE_BUILD_RUSTC").to_string(),
    }
}

fn host_info() -> HostInfo {
    // The System tab header uses the cheap `Basic` scope: no subprocess, no
    // full CPU refresh. Richer host facts (CPU, machine id, hardening) are the
    // `machine_info` action's job and land in the transcript, not the header.
    #[cfg(feature = "verification")]
    {
        rite_stdlib::gather_host_info(rite_stdlib::HostInfoScope::Basic)
    }
    #[cfg(not(feature = "verification"))]
    {
        HostInfo {
            arch: std::env::consts::ARCH.to_string(),
            os: Some(std::env::consts::OS.to_string()),
            os_version: None,
            kernel_version: None,
            hostname: None,
            machine_id: None,
            cpu_model: None,
            hardening: None,
        }
    }
}

fn backends() -> Vec<rite_runtime::BackendVersion> {
    let mut backends = Vec::new();
    #[cfg(feature = "openssl")]
    {
        backends.push(rite_runtime::BackendVersion {
            provider: "openssl".to_string(),
            version: openssl::version::version().to_string(),
            source: Some(openssl_source().to_string()),
        });
    }
    backends
}

#[cfg(feature = "openssl")]
fn openssl_source() -> &'static str {
    if cfg!(feature = "openssl-vendored") {
        "vendored"
    } else {
        "system"
    }
}
