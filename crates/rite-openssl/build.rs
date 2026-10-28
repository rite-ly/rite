//! Detects whether the linked OpenSSL can wrap to an ML-KEM key.
//!
//! CMS carries an ML-KEM recipient in a `KEMRecipientInfo` (RFC 9629), which
//! OpenSSL implements only from 3.6, so `rite-openssl` supports ML-KEM from
//! there. The `ossl360` cfg marks that. The `openssl` crate gates its own
//! bindings behind a private cfg, so this build script re-derives the line from
//! the version number `openssl-sys` publishes through its `links` metadata.

/// `1` or `0` in place of the detected answer, to compile the 3.5-only side on
/// a machine with 3.6. It overrides this cfg and nothing else, so the linked
/// library is unchanged.
const OSSL360_VAR: &str = "RITE_OSSL360";

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ossl360)");
    println!("cargo::rerun-if-env-changed={OSSL360_VAR}");

    let ossl360 = forced(OSSL360_VAR).unwrap_or_else(|| linked_version() >= Some(0x3060_0000));
    if ossl360 {
        println!("cargo::rustc-cfg=ossl360");
    }
}

/// The linked OpenSSL's `OPENSSL_VERSION_NUMBER`, `0xMNN00PPSL`, so 3.6.0 is
/// `0x30600000`.
fn linked_version() -> Option<u64> {
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
