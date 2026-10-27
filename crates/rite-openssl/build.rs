//! Detects the linked OpenSSL version so post-quantum support is compiled in
//! only where the provider exists.
//!
//! ML-DSA and ML-KEM keys landed in OpenSSL 3.5, and the `openssl` crate gates
//! the corresponding bindings behind its own `ossl350` cfg. That cfg is private
//! to that crate, so this build script re-derives it from the version number
//! `openssl-sys` publishes through its `links` metadata.
//!
//! CMS carries an ML-KEM recipient in a `KEMRecipientInfo` (RFC 9629), which
//! OpenSSL implements only from 3.6, so `rite-openssl` supports ML-KEM from
//! there. The `ossl360` cfg marks that, and implies `ossl350`.

/// `1` or `0` in place of the detected answer, to compile the other side of
/// the 3.5 line locally. It overrides this cfg and nothing else, so the linked
/// library is unchanged. `0` also turns `ossl360` off.
const OSSL350_VAR: &str = "RITE_OSSL350";

/// The same for the 3.6 line, to compile the 3.5-only side on a machine with
/// 3.6. `1` needs `ossl350` as well.
const OSSL360_VAR: &str = "RITE_OSSL360";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ossl350)");
    println!("cargo::rustc-check-cfg=cfg(ossl360)");
    println!("cargo::rerun-if-env-changed={OSSL350_VAR}");
    println!("cargo::rerun-if-env-changed={OSSL360_VAR}");

    let version = linked_version();

    let ossl350 = forced(OSSL350_VAR).unwrap_or_else(|| version.is_some_and(|v| v >= 0x3050_0000));
    let ossl360 = match forced(OSSL360_VAR) {
        Some(true) if !ossl350 => panic!("{OSSL360_VAR}=1 needs ossl350, which is off"),
        Some(forced) => forced,
        None => ossl350 && version.is_some_and(|v| v >= 0x3060_0000),
    };

    if ossl350 {
        println!("cargo::rustc-cfg=ossl350");
    }
    if ossl360 {
        println!("cargo::rustc-cfg=ossl360");
    }
}

/// The linked OpenSSL's `OPENSSL_VERSION_NUMBER`, or `None` where it says
/// nothing about the post-quantum providers.
fn linked_version() -> Option<u64> {
    // LibreSSL and BoringSSL report an OpenSSL version number for source
    // compatibility but do not ship the providers. Each signals itself through
    // a separate variable, so they read as `None` rather than as the number.
    if std::env::var_os("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_some()
        || std::env::var_os("DEP_OPENSSL_BORINGSSL").is_some()
    {
        return None;
    }
    // OPENSSL_VERSION_NUMBER is 0xMNN00PPSL, so 3.5.0 is 0x30500000.
    let raw = std::env::var("DEP_OPENSSL_VERSION_NUMBER").ok()?;
    u64::from_str_radix(&raw, 16).ok()
}

/// The value of an override variable, with a warning when it is set.
///
/// Empty reads as unset. Anything but `1`, `0` or empty fails the build rather
/// than being ignored, since a typo here changes what compiles.
fn forced(var: &str) -> Option<bool> {
    let forced = match std::env::var(var).ok()?.as_str() {
        "1" => true,
        "0" => false,
        "" => return None,
        other => panic!("{var} takes 1 or 0, got {other:?}"),
    };
    println!(
        "cargo::warning={var}={} overrides detection",
        u8::from(forced)
    );
    Some(forced)
}
