//! Detects the linked OpenSSL version so ML-DSA support is compiled in only
//! where the provider exists.
//!
//! ML-DSA landed in OpenSSL 3.5, and the `openssl` crate gates the
//! corresponding bindings behind its own `ossl350` cfg. That cfg is private to
//! that crate, so this build script re-derives it from the version number
//! `openssl-sys` publishes through its `links` metadata.

/// `1` or `0` in place of the detected answer, to compile the other side of
/// the 3.5 line locally. It overrides this cfg and nothing else, so the linked
/// library is unchanged.
const OVERRIDE_VAR: &str = "RITE_OSSL350";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ossl350)");
    println!("cargo::rerun-if-env-changed={OVERRIDE_VAR}");

    if let Some(forced) = override_from_env() {
        println!(
            "cargo::warning={OVERRIDE_VAR}={} overrides detection",
            u8::from(forced)
        );
        if forced {
            println!("cargo::rustc-cfg=ossl350");
        }
        return;
    }

    // LibreSSL and BoringSSL report an OpenSSL version number for source
    // compatibility but do not ship the ML-DSA provider. Each signals itself
    // through a separate variable, so bail out rather than trusting the
    // version number alone.
    if std::env::var_os("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_some()
        || std::env::var_os("DEP_OPENSSL_BORINGSSL").is_some()
    {
        return;
    }

    let Ok(raw) = std::env::var("DEP_OPENSSL_VERSION_NUMBER") else {
        return;
    };
    let Ok(version) = u64::from_str_radix(&raw, 16) else {
        return;
    };

    // OPENSSL_VERSION_NUMBER is 0xMNN00PPSL, so 3.5.0 is 0x30500000.
    if version >= 0x3050_0000 {
        println!("cargo::rustc-cfg=ossl350");
    }
}

/// Empty reads as unset. Anything but `1`, `0` or empty fails the build rather
/// than being ignored, since a typo here changes what compiles.
fn override_from_env() -> Option<bool> {
    match std::env::var(OVERRIDE_VAR).ok()?.as_str() {
        "1" => Some(true),
        "0" => Some(false),
        "" => None,
        other => panic!("{OVERRIDE_VAR} takes 1 or 0, got {other:?}"),
    }
}
