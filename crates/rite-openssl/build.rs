//! Detects the linked OpenSSL version so ML-DSA support is compiled in only
//! where the provider exists.
//!
//! ML-DSA landed in OpenSSL 3.5, and the `openssl` crate gates the
//! corresponding bindings behind its own `ossl350` cfg. That cfg is private to
//! that crate, so this build script re-derives it from the version number
//! `openssl-sys` publishes through its `links` metadata.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(ossl350)");

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
