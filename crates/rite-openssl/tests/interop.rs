//! CLI interop tests: verify that CMS blobs produced by `OpenSslBackend` can be
//! decrypted by the `openssl cms` command-line tool.
//!
//! Tests are skipped (not failed) when the `openssl` binary is not on `$PATH`.

// Helper functions here are not annotated with #[test] so clippy's
// allow-unwrap-in-tests / allow-expect-in-tests config does not cover them.
// Panicking in test helpers is the expected behaviour on test failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use rite_openssl::OpenSslBackend;
use rite_sdk::{
    KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, PublicKeyDer,
    WrapScheme,
};
use std::io::Write as _;
use std::process::Command;

/// A fresh RSA-2048 recipient, a fresh extractable payload key, and that
/// payload wrapped to that recipient under `scheme`.
///
/// The recipient is built outside the backend on purpose: every test here is
/// about what a third party holding only the private key can do with the blob.
fn wrap_to_fresh_recipient(
    scheme: WrapScheme,
) -> (PKey<Private>, PublicKeyDer, rite_sdk::WrappedKey) {
    let recipient_pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
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

    (recipient_pkey, payload_pub, wrapped)
}

/// Returns `true` if the `openssl` binary is available on `$PATH`.
fn openssl_binary_available() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Build a self-signed X.509 cert that mirrors what `cert_for_public_key()`
/// inside the backend produces.
///
/// The blob names its recipient by subject key identifier, so what has to
/// match is that identifier: the SHA-256 of the subject public key's SPKI DER.
/// Reconstructing it here from the public key alone, without reading any Rite
/// code, is what makes this an interop check rather than a self-consistency
/// one: a third party holding the recipient key can build the cert that opens
/// the blob.
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

    let spki = pkey.public_key_to_der().unwrap();
    let key_identifier = openssl::hash::hash(MessageDigest::sha256(), &spki).unwrap();
    let mut extn_value = vec![0x04, u8::try_from(key_identifier.len()).unwrap()];
    extn_value.extend_from_slice(&key_identifier);
    let extn_value = Asn1OctetString::new_from_bytes(&extn_value).unwrap();
    let ski_oid = Asn1Object::from_str("2.5.29.14").unwrap();
    builder
        .append_extension(X509Extension::new_from_der(&ski_oid, false, &extn_value).unwrap())
        .unwrap();

    builder.sign(pkey, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn run_interop_test(scheme: WrapScheme) {
    if !openssl_binary_available() {
        eprintln!("SKIP: openssl binary not found in $PATH");
        return;
    }

    // ── Recipient keypair, payload key, and the wrap ────────────────────────
    let (recipient_pkey, payload_pub, wrapped) = wrap_to_fresh_recipient(scheme);

    // Self-signed cert with same issuer/serial that cert_for_public_key uses.
    let cert = build_recipient_cert(&recipient_pkey);
    let pkey_pem = recipient_pkey.private_key_to_pem_pkcs8().unwrap();
    let cert_pem = cert.to_pem().unwrap();
    let cms_der = wrapped.data().to_vec();

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
    // The payload is PKCS#8 PrivateKeyInfo, which is what PKCS#11 specifies
    // for a wrapped private key and what a recipient will try first.
    let decrypted = std::fs::read(out_file.path()).unwrap();
    let recovered = PKey::private_key_from_pkcs8(&decrypted)
        .expect("Decrypted bytes are not a PKCS#8 private key");

    assert_eq!(
        payload_pub.as_bytes(),
        recovered.public_key_to_der().unwrap(),
        "Decrypted key public component does not match the original payload key"
    );
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

    let (recipient_pkey, payload_pub, wrapped) =
        wrap_to_fresh_recipient(WrapScheme::RsaAesKeyWrapSha256);

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

#[test]
fn openssl_cli_decrypts_a_wrap_to_an_external_recipient() {
    run_interop_test(WrapScheme::CmsAes256Gcm);
}

/// The blob Rite writes for a symmetric KEK is one the `openssl` CLI opens.
///
/// This is the direction that matters for archival: a custodian holding the
/// key and a copy of the blob, years later, with no Rite binary.
#[test]
fn openssl_cli_decrypts_a_wrap_under_a_symmetric_key() {
    if !openssl_binary_available() {
        eprintln!("skipping: openssl binary not available");
        return;
    }

    // The KEK is imported rather than generated, so this test knows its bytes
    // and can hand them to the CLI.
    let mut secret = vec![0u8; 32];
    openssl::rand::rand_bytes(&mut secret).unwrap();

    let mut backend = OpenSslBackend::try_new("interop-test").unwrap();
    let kek = backend
        .import_key(
            KeySpec {
                algorithm: KeyAlgorithm::Aes256,
                label: "kek".to_string(),
                policy: KeyPolicy::default_for(KeyAlgorithm::Aes256),
                location_hint: None,
            },
            &secret,
        )
        .unwrap();
    let payload = backend
        .generate_key(KeySpec {
            algorithm: KeyAlgorithm::EcdsaP256,
            label: "payload".to_string(),
            policy: KeyPolicy {
                extractable: true,
                ..KeyPolicy::default()
            },
            location_hint: None,
        })
        .unwrap();
    let payload_pub = backend.export_public_key(&payload.key_id).unwrap();
    let wrapped = backend
        .wrap(&payload.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
        .expect("a symmetric KEK takes the CMS container");

    let dir = tempfile::tempdir().unwrap();
    let blob = dir.path().join("wrapped.der");
    let out = dir.path().join("recovered.der");
    std::fs::write(&blob, wrapped.data()).unwrap();

    let kcv = kek.check_value.as_ref().expect("a symmetric key has one");
    let kcv_hex = base16ct::lower::encode_string(kcv.as_bytes());
    let decrypt = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            blob.to_str().unwrap(),
            "-secretkey",
            &base16ct::lower::encode_string(&secret),
            "-secretkeyid",
            &kcv_hex,
            "-out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to spawn openssl cms");
    assert!(
        decrypt.status.success(),
        "openssl cms -decrypt -secretkey failed:\nstderr: {}",
        String::from_utf8_lossy(&decrypt.stderr),
    );

    let recovered = PKey::private_key_from_pkcs8(&std::fs::read(&out).unwrap())
        .expect("the content is the PKCS#8 payload");
    assert_eq!(
        payload_pub.as_bytes(),
        recovered.public_key_to_der().unwrap(),
        "the key the command line recovered is not the key that went in"
    );

    secret.fill(0);
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

/// The container `encrypt_data` assembles, opened by the command line.
///
/// Built the way the action builds it, from a data key the backend produced and
/// a content pipeline that never sees the key-encryption key, rather than
/// through `wrap`. That path writes the same structure, and this is what says
/// so against an implementation neither half of Rite wrote.
#[test]
fn the_openssl_cli_opens_content_sealed_to_a_data_key() {
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
        )
        .unwrap();

    let content = b"the custodian's copy of the recovery phrase";
    let data_key = backend
        .generate_data_key(&kek.key_id, KeyAlgorithm::Aes256)
        .expect("the backend protects a data key under the KEK it holds");
    let sealed = rite_openssl::seal_content(data_key.plaintext(), content)
        .expect("the content pipeline encrypts under the data key");

    let kcv = kek.check_value.as_ref().expect("a symmetric key has one");
    let der = rite_sdk::cms::write_kek_enveloped(&rite_sdk::cms::KekEnvelope {
        key_identifier: kcv.as_bytes().to_vec(),
        wrapped_cek: data_key.wrapped().to_vec(),
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        tag: sealed.tag,
    })
    .expect("the container assembles");

    let dir = tempfile::tempdir().unwrap();
    let blob = dir.path().join("sealed.der");
    std::fs::write(&blob, &der).unwrap();

    let decrypt = Command::new("openssl")
        .args([
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            blob.to_str().unwrap(),
            "-secretkey",
            &base16ct::lower::encode_string(&secret),
            "-secretkeyid",
            &base16ct::lower::encode_string(kcv.as_bytes()),
        ])
        .output()
        .expect("Failed to spawn openssl cms");
    assert!(
        decrypt.status.success(),
        "openssl cms -decrypt -secretkey failed:\nstderr: {}",
        String::from_utf8_lossy(&decrypt.stderr),
    );
    assert_eq!(
        decrypt.stdout, content,
        "the command line recovered something other than the content that went in"
    );

    // And the backend opens the data key again from the same bytes, which is
    // the half `decrypt_data` uses.
    let reopened = backend
        .open_data_key(
            &kek.key_id,
            data_key.wrapped(),
            rite_sdk::KeyProtection::AesKeyWrap,
        )
        .expect("the KEK opens the data key it protected");
    assert_eq!(reopened.as_slice(), data_key.plaintext());
    assert_eq!(data_key.protection(), rite_sdk::KeyProtection::AesKeyWrap);

    // A protection this backend does not implement is refused rather than
    // attempted, since one protection's bytes look like another's.
    let refused = backend.open_data_key(
        &kek.key_id,
        data_key.wrapped(),
        rite_sdk::KeyProtection::RsaOaepSha256,
    );
    assert!(
        refused.is_err(),
        "a data key protected another way must not be opened as AES-KW"
    );

    secret.fill(0);
}
