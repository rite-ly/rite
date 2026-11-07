//! CLI interop tests for what the algorithm matrix in `rite-stdlib` cannot
//! reach through a step: the layout of a raw RSA-AES key wrap, a container
//! the command line wrote opened by the backend's own unwrap, and the
//! identifier a standard certificate names its key by.
//!
//! The forms the steps write and read, against the command line in both
//! directions, are rows of that matrix (`crates/rite-stdlib/tests/algorithms/`).
//!
//! Tests are skipped (not failed) when the `openssl` binary is not on `$PATH`.

// Helper functions here are not annotated with #[test] so clippy's
// allow-unwrap-in-tests / allow-expect-in-tests config does not cover them.
// Panicking in test helpers is the expected behaviour on test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use rite_openssl::OpenSslBackend;
use rite_sdk::{
    KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, PublicKeyDer,
    WrapScheme,
};
use std::process::Command;

/// A fresh extractable payload key, wrapped to `recipient_pkey` under
/// `scheme`, and the payload's public key.
///
/// The recipient is built outside the backend on purpose: every test here is
/// about what a third party holding only the private key can do with the blob.
fn wrap_to(
    recipient_pkey: &PKeyRef<Private>,
    scheme: WrapScheme,
) -> (PublicKeyDer, rite_sdk::WrappedKey) {
    let recipient_pub_der = PublicKeyDer::new(recipient_pkey.public_key_to_der().unwrap()).unwrap();

    let mut backend = OpenSslBackend::try_new("interop-test").unwrap();
    let payload = backend
        .generate_key(KeySpec {
            algorithm: KeyAlgorithm::Rsa2048,
            label: "payload".to_string(),
            // The point of this key is to leave, so the policy has to say so.
            policy: KeyPolicy {
                extractable: true,
                ..KeyPolicy::default()
            },
            location_hint: None,
        })
        .unwrap();
    let payload_pub = backend.export_public_key(&payload.key_id).unwrap();
    let wrapped = backend
        .wrap_to_public(&payload.key_id, &recipient_pub_der, scheme)
        .unwrap();

    (payload_pub, wrapped)
}

/// Returns `true` if the `openssl` binary is available on `$PATH`.
fn openssl_binary_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The raw-mechanism counterpart: `RSA-AES-KEY-WRAP-SHA256` reassembled by the
/// `openssl` command line rather than by Rite.
///
/// This is the check that matters for the scheme's whole purpose. A raw wrap
/// describes nothing about itself, so nothing in the blob would catch Rite
/// laying the two parts out in the wrong order, choosing a different OAEP
/// digest, or framing them. Only an independent implementation splitting it by
/// the modulus size and unwrapping each half proves the layout is the one
/// PKCS#11 specifies and cloud KMS import expects.
#[test]
fn openssl_cli_reassembles_an_rsa_aes_key_wrap() {
    if !openssl_binary_available() {
        eprintln!("skipping: openssl binary not found on PATH");
        return;
    }

    let recipient_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let (payload_pub, wrapped) = wrap_to(&recipient_pkey, WrapScheme::RsaAesKeyWrapSha256);

    // Split by the modulus size, which is the only rule the format gives a
    // recipient. No length prefix, no header.
    let (encapsulated, wrapped_payload) = wrapped.data().split_at(256);

    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let key_path = write(
        "recipient.pem",
        &recipient_pkey.private_key_to_pem_pkcs8().unwrap(),
    );
    let enc_path = write("ephemeral.bin", encapsulated);
    let payload_path = write("payload.bin", wrapped_payload);
    let aes_path = dir.path().join("ephemeral.key");
    let out_path = dir.path().join("payload.pkcs8");

    // Step 1: recover the ephemeral AES key with RSA-OAEP-SHA256.
    let unwrap_aes = Command::new("openssl")
        .args([
            "pkeyutl",
            "-decrypt",
            "-inkey",
            key_path.to_str().unwrap(),
            "-in",
            enc_path.to_str().unwrap(),
            "-out",
            aes_path.to_str().unwrap(),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha256",
            "-pkeyopt",
            "rsa_mgf1_md:sha256",
        ])
        .output()
        .expect("Failed to spawn openssl pkeyutl");
    assert!(
        unwrap_aes.status.success(),
        "openssl pkeyutl -decrypt failed:\nstderr: {}",
        String::from_utf8_lossy(&unwrap_aes.stderr),
    );

    let aes_key = std::fs::read(&aes_path).unwrap();
    assert_eq!(aes_key.len(), 32, "the ephemeral key is AES-256");

    // Step 2: unwrap the payload under it with AES-KWP (RFC 5649).
    let unwrap_payload = Command::new("openssl")
        .args([
            "enc",
            "-d",
            "-id-aes256-wrap-pad",
            "-K",
            &base16ct::lower::encode_string(&aes_key),
            "-iv",
            "A65959A6",
            "-in",
            payload_path.to_str().unwrap(),
            "-out",
            out_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to spawn openssl enc");
    assert!(
        unwrap_payload.status.success(),
        "openssl enc -id-aes256-wrap-pad failed:\nstderr: {}",
        String::from_utf8_lossy(&unwrap_payload.stderr),
    );

    let recovered = PKey::private_key_from_pkcs8(&std::fs::read(&out_path).unwrap())
        .expect("the unwrapped payload is PKCS#8, as PKCS#11 specifies");
    assert_eq!(
        payload_pub.as_bytes(),
        recovered.public_key_to_der().unwrap(),
        "the key the command line recovered is not the key that went in"
    );
}

/// And the other direction: a blob OpenSSL wrote, unwrapped by Rite.
///
/// One direction alone would pass with a structure both sides got wrong in the
/// same way. This is the half that a hand-written encoder most needs.
#[test]
fn rite_unwraps_what_the_openssl_cli_wrote() {
    if !openssl_binary_available() {
        eprintln!("skipping: openssl binary not available");
        return;
    }

    let mut backend = OpenSslBackend::try_new("interop-test").unwrap();
    let mut secret = vec![0u8; 32];
    openssl::rand::rand_bytes(&mut secret).unwrap();
    let kek = backend
        .import_key(
            KeySpec {
                algorithm: KeyAlgorithm::Aes256,
                label: "kek".to_string(),
                policy: KeyPolicy::default_for(KeyAlgorithm::Aes256),
                location_hint: None,
            },
            &secret,
            None,
        )
        .unwrap();

    // A real private key as the payload, so the unwrap path imports it the way
    // it would any recovered key.
    let payload = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let pkcs8 = payload.private_key_to_pkcs8().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("payload.der");
    let blob = dir.path().join("theirs.der");
    std::fs::write(&plain, &pkcs8).unwrap();

    let kcv = kek.check_value.as_ref().expect("a symmetric key has one");
    let encrypt = Command::new("openssl")
        .args([
            "cms",
            "-encrypt",
            "-binary",
            "-aes-256-gcm",
            "-in",
            plain.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            blob.to_str().unwrap(),
            "-secretkey",
            &base16ct::lower::encode_string(&secret),
            "-secretkeyid",
            &base16ct::lower::encode_string(kcv.as_bytes()),
        ])
        .output()
        .expect("Failed to spawn openssl cms");
    assert!(
        encrypt.status.success(),
        "openssl cms -encrypt -secretkey failed:\nstderr: {}",
        String::from_utf8_lossy(&encrypt.stderr),
    );

    let their_der = std::fs::read(&blob).unwrap();
    let facts = rite_sdk::cms::describe(&their_der).expect("Rite describes their blob");
    assert_eq!(
        facts.description.recipient_info,
        Some(rite_sdk::RecipientInfoKind::Kekri)
    );

    let wrapped = rite_sdk::WrappedKey::new(WrapScheme::CmsAes256Gcm, facts.description, their_der)
        .expect("the scheme admits what their blob says it did");
    let restored = backend
        .unwrap(
            &wrapped,
            &kek.key_id,
            "restored",
            KeyPolicy {
                extractable: true,
                ..KeyPolicy::default()
            },
            None,
        )
        .expect("Rite unwraps a blob the CLI wrote");

    assert_eq!(
        restored.public_key.as_ref().map(PublicKeyDer::as_bytes),
        Some(payload.public_key_to_der().unwrap().as_slice()),
        "the key Rite recovered is not the key the CLI wrapped"
    );

    secret.fill(0);
}

/// Write `bytes` to `name` in `dir` and return the path as a string.
fn write_file(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_string()
}

/// A recipient certificate made by the command line with its defaults carries
/// the SHA-1 subject key identifier of RFC 5280 method 1, and a container sealed
/// to it with `-keyid` names the recipient by that.
///
/// Both the certificate and the container come from the CLI, so this checks
/// Rite's derivation of that identifier against OpenSSL's rather than against
/// itself.
#[test]
fn a_standard_certificate_names_its_key_by_the_rfc_5280_identifier() {
    if !openssl_binary_available() {
        eprintln!("skipping: openssl binary not available");
        return;
    }

    let recipient = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key = write_file(
        &dir,
        "recipient.pem",
        &recipient.private_key_to_pem_pkcs8().unwrap(),
    );
    let cert = dir.path().join("recipient.crt");
    let plain = write_file(&dir, "content.bin", b"a document");
    let blob = dir.path().join("sealed.der");

    let run = |args: &[&str]| {
        let output = Command::new("openssl")
            .args(args)
            .output()
            .expect("Failed to spawn openssl");
        assert!(
            output.status.success(),
            "openssl {args:?} failed:\nstderr: {}",
            String::from_utf8_lossy(&output.stderr),
        );
    };
    run(&[
        "req",
        "-new",
        "-x509",
        "-key",
        &key,
        "-subj",
        "/CN=custodian",
        "-days",
        "1",
        "-out",
        cert.to_str().unwrap(),
    ]);
    run(&[
        "cms",
        "-encrypt",
        "-binary",
        "-aes-256-gcm",
        "-keyid",
        "-outform",
        "DER",
        "-in",
        &plain,
        "-out",
        blob.to_str().unwrap(),
        "-recip",
        cert.to_str().unwrap(),
        "-keyopt",
        "rsa_padding_mode:oaep",
        "-keyopt",
        "rsa_oaep_md:sha256",
        "-keyopt",
        "rsa_mgf1_md:sha256",
    ]);

    let envelope = rite_sdk::cms::read_auth_enveloped(&std::fs::read(&blob).unwrap()).unwrap();
    let public = PublicKeyDer::new(recipient.public_key_to_der().unwrap()).unwrap();
    assert_eq!(
        envelope.recipient.key_identifier().as_bytes(),
        public.rfc5280_key_identifier().unwrap().as_bytes(),
        "the rid is the identifier the CLI wrote into the certificate"
    );
    assert!(
        envelope.recipient.key_identifier().names_key(&public),
        "and Rite recognises the key by it"
    );
}
