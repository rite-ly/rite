//! CLI interop tests — verify that CMS blobs produced by `OpenSslBackend` can be
//! decrypted by the `openssl cms` command-line tool.
//!
//! Tests are skipped (not failed) when the `openssl` binary is not on `$PATH`.

// Helper functions here are not annotated with #[test] so clippy's
// allow-unwrap-in-tests / allow-expect-in-tests config does not cover them.
// Panicking in test helpers is the expected behaviour on test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use rite_openssl::OpenSslBackend;
use rite_sdk::{
    KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, WrapAlgorithm,
};
use std::io::Write as _;
use std::process::Command;

/// Returns `true` if the `openssl` binary is available on `$PATH`.
fn openssl_binary_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build a self-signed X.509 cert that mirrors what `cert_for_public_key()` inside
/// the backend produces: issuer/subject = CN=rite-keywrap, serial = 1.
///
/// OpenSSL CMS uses issuerAndSerialNumber from the recipient cert to locate the
/// matching `RecipientInfo` in the CMS blob. Because `cert_for_public_key` always
/// uses those same values, this cert will match and allow CLI decryption.
fn build_recipient_cert(pkey: &PKeyRef<Private>) -> openssl::x509::X509 {
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_pubkey(pkey).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "rite-keywrap")
        .unwrap();
    let name = name_builder.build();

    builder.set_issuer_name(&name).unwrap();
    builder.set_subject_name(&name).unwrap();

    let serial = BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .unwrap();
    builder.set_serial_number(&serial).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(pkey, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn run_interop_test(algorithm: WrapAlgorithm) {
    if !openssl_binary_available() {
        eprintln!("SKIP: openssl binary not found in $PATH");
        return;
    }

    // ── Recipient keypair + cert (created outside the backend) ──────────────
    let rsa = Rsa::generate(2048).unwrap();
    let recipient_pkey = PKey::from_rsa(rsa).unwrap();
    let recipient_pub_der = recipient_pkey.public_key_to_der().unwrap();

    // Self-signed cert with same issuer/serial that cert_for_public_key uses.
    let cert = build_recipient_cert(&recipient_pkey);
    let pkey_pem = recipient_pkey.private_key_to_pem_pkcs8().unwrap();
    let cert_pem = cert.to_pem().unwrap();

    // ── Backend: generate payload key and wrap it to the recipient ───────────
    let mut backend = OpenSslBackend::try_new("interop-test").unwrap();
    let payload = backend
        .generate_key(KeySpec {
            algorithm: KeyAlgorithm::Rsa2048,
            label: "payload".to_string(),
            policy: KeyPolicy::default(),
            location_hint: None,
        })
        .unwrap();
    let payload_pub = backend.export_public_key(&payload.key_id).unwrap();

    let wrapped = backend
        .wrap_to_public(&payload.key_id, &recipient_pub_der, algorithm)
        .unwrap();
    let cms_der = wrapped.data;

    // ── Write artefacts to temp files ────────────────────────────────────────
    let mut cms_file = tempfile::NamedTempFile::new().unwrap();
    cms_file.write_all(&cms_der).unwrap();
    cms_file.flush().unwrap();

    let mut key_file = tempfile::NamedTempFile::new().unwrap();
    key_file.write_all(&pkey_pem).unwrap();
    key_file.flush().unwrap();

    let mut cert_file = tempfile::NamedTempFile::new().unwrap();
    cert_file.write_all(&cert_pem).unwrap();
    cert_file.flush().unwrap();

    let out_file = tempfile::NamedTempFile::new().unwrap();

    // ── Decrypt with openssl cms CLI ─────────────────────────────────────────
    let output = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-in",
            cms_file.path().to_str().unwrap(),
            "-inform",
            "DER",
            "-inkey",
            key_file.path().to_str().unwrap(),
            "-recip",
            cert_file.path().to_str().unwrap(),
            "-out",
            out_file.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to spawn openssl process");

    assert!(
        output.status.success(),
        "openssl cms -decrypt failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    // ── Compare decrypted bytes to the original payload key ──────────────────
    // The backend serialises the private key via PKey::private_key_to_der()
    // (traditional RSA DER / PKCS#1). Parse that back and compare public keys.
    let decrypted = std::fs::read(out_file.path()).unwrap();
    let rsa = Rsa::private_key_from_der(&decrypted)
        .or_else(|_| {
            // Fallback: some OpenSSL versions may wrap in PKCS#8.
            openssl::pkey::PKey::private_key_from_der(&decrypted).and_then(|p| p.rsa())
        })
        .expect("Decrypted bytes are not a recognisable RSA private key");
    let decrypted_pub = PKey::from_rsa(rsa).unwrap().public_key_to_der().unwrap();

    assert_eq!(
        payload_pub, decrypted_pub,
        "Decrypted key public component does not match the original payload key"
    );
}

#[test]
fn test_interop_cms_rsa_cbc() {
    run_interop_test(WrapAlgorithm::CmsRsaCbc);
}

#[test]
fn test_interop_cms_rsa_gcm() {
    run_interop_test(WrapAlgorithm::CmsRsaGcm);
}
