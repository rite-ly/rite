use chrono::Utc;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let target = var("TARGET");
    let profile = var("PROFILE");

    println!("cargo:rustc-env=RITE_BUILD_TARGET={target}");
    println!("cargo:rustc-env=RITE_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=RITE_BUILD_FEATURES={}", features());
    let (commit, commit_date) = git_info();
    println!("cargo:rustc-env=RITE_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=RITE_BUILD_COMMIT_DATE={commit_date}");
    println!(
        "cargo:rustc-env=RITE_BUILD_DATE={}",
        Utc::now().format("%Y-%m-%d")
    );
    println!("cargo:rustc-env=RITE_BUILD_RUSTC={}", rustc_version());
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| "unknown".to_string())
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

fn trimmed(s: Option<&str>) -> String {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn git_info() -> (String, String) {
    let Some(out) = cmd_output("git", &["log", "-1", "--format=%h%n%cd", "--date=short"]) else {
        return ("unknown".to_string(), "unknown".to_string());
    };
    let mut lines = out.lines();
    (trimmed(lines.next()), trimmed(lines.next()))
}

fn rustc_version() -> String {
    cmd_output("rustc", &["--version"])
        .as_deref()
        .and_then(|s| s.trim().strip_prefix("rustc "))
        .unwrap_or("unknown")
        .to_string()
}
