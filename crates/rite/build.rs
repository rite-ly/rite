use chrono::Utc;
use std::process::Command;

const UNKNOWN: &str = "unknown";

fn main() {
    // RITE_BUILD_COMMIT and RITE_BUILD_COMMIT_DATE are computed once by the
    // release pipeline (.github/workflows/release.yml) and exported as job-level
    // env vars to every builder (native + docker). Local builds without them
    // get "unknown".
    println!("cargo:rerun-if-env-changed=RITE_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=RITE_BUILD_COMMIT_DATE");

    let target = var("TARGET");
    let profile = var("PROFILE");

    println!("cargo:rustc-env=RITE_BUILD_TARGET={target}");
    println!("cargo:rustc-env=RITE_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=RITE_BUILD_FEATURES={}", features());
    println!(
        "cargo:rustc-env=RITE_BUILD_COMMIT={}",
        var("RITE_BUILD_COMMIT")
    );
    println!(
        "cargo:rustc-env=RITE_BUILD_COMMIT_DATE={}",
        var("RITE_BUILD_COMMIT_DATE")
    );
    println!(
        "cargo:rustc-env=RITE_BUILD_DATE={}",
        Utc::now().format("%Y-%m-%d")
    );
    println!("cargo:rustc-env=RITE_BUILD_RUSTC={}", rustc_version());
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| UNKNOWN.to_string())
}

fn features() -> String {
    let known = [
        ("CARGO_FEATURE_ATTESTATION", "attestation"),
        ("CARGO_FEATURE_CRYPTO", "crypto"),
        ("CARGO_FEATURE_OPENSSL", "openssl"),
        ("CARGO_FEATURE_OPENSSL_VENDORED", "openssl-vendored"),
        ("CARGO_FEATURE_PKI", "pki"),
        ("CARGO_FEATURE_RENDER", "render"),
        ("CARGO_FEATURE_VERIFICATION", "verification"),
    ];
    let mut enabled: Vec<&str> = known
        .iter()
        .filter(|(env_var, _)| std::env::var(env_var).is_ok())
        .map(|(_, name)| *name)
        .collect();
    enabled.sort_unstable();
    enabled.join(",")
}

fn cmd_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
}

fn rustc_version() -> String {
    cmd_output("rustc", &["--version"])
        .as_deref()
        .and_then(|s| s.trim().strip_prefix("rustc "))
        .unwrap_or(UNKNOWN)
        .to_string()
}
