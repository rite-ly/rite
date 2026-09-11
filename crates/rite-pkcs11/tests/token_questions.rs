//! Six questions about PKCS#11, asked of a real token.
//!
//! The wrapping model rests on claims about what a token does. Nothing in this
//! workspace could test them, so they were specification reading, and the
//! transcript format is about to freeze around them. These tests replace the
//! reading with measurement.
//!
//! They are `#[ignore]`d and read `SOFTHSM2_MODULE`, so a normal `cargo test`
//! skips them and a machine with `SoftHSM` installed runs them:
//!
//! ```sh
//! softhsm2-util --init-token --slot 0 --label rite-test \
//!     --so-pin 1234 --pin 1234
//! SOFTHSM2_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
//!     cargo test -p rite-pkcs11 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Set `SOFTHSM2_CONF` as well to keep the token store out of the default
//! location; CI does, and `.github/workflows/ci.yml` is the worked example.
//!
//! `SoftHSM` is a software token that follows the specification, so an answer
//! here is what the standard prescribes. A vendor device may differ, and this
//! is the baseline it differs from.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing
)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

/// Mechanisms with no constant in cryptoki 0.12, compared by raw value.
const CKM_AES_KEY_WRAP_KWP: u64 = 0x210B;
const CKM_RSA_AES_KEY_WRAP: u64 = 0x0011;

/// The module under test, or `None` when this machine has no token.
fn module() -> Option<String> {
    std::env::var("SOFTHSM2_MODULE").ok()
}

/// Load the module and find the first token present.
fn token() -> Option<(Pkcs11, Slot)> {
    let module = module()?;
    let context = Pkcs11::new(module).expect("load module");
    context
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .expect("initialize");
    let slot = *context
        .get_slots_with_token()
        .expect("list slots")
        .first()
        .expect("a token is present");
    Some((context, slot))
}

/// Open a logged-in session against that token.
fn session() -> Option<(Pkcs11, Session)> {
    let (context, slot) = token()?;
    let session = context.open_rw_session(slot).expect("open session");
    session
        .login(UserType::User, Some(&AuthPin::from("1234".to_string())))
        .expect("log in with the fixture PIN");
    Some((context, session))
}

/// Generate an RSA keypair, with the private half's extractability chosen.
fn rsa_keypair(
    session: &Session,
    label: &str,
    extractable: bool,
) -> (
    cryptoki::object::ObjectHandle,
    cryptoki::object::ObjectHandle,
) {
    let public_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::Label(format!("{label}-pub").into_bytes()),
        Attribute::Wrap(true),
        Attribute::Verify(true),
    ];
    let private_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(extractable),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Sign(true),
        Attribute::Unwrap(true),
    ];
    session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &public_template,
            &private_template,
        )
        .expect("generate RSA keypair")
}

/// Generate an AES-256 key that may wrap and unwrap.
fn aes_kek(session: &Session, label: &str) -> cryptoki::object::ObjectHandle {
    session
        .generate_key(
            &Mechanism::AesKeyGen,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::KeyType(KeyType::AES),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::ValueLen(32.into()),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
            ],
        )
        .expect("generate an AES-256 key")
}

/// Q1. Does `C_WrapKey` refuse a key whose `CKA_EXTRACTABLE` is false?
///
/// The whole wrapping model depends on the answer. If the token were to wrap
/// a non-extractable key, "non-extractable" would mean nothing.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q1_wrapping_a_non_extractable_key_is_refused() {
    let Some((_context, session)) = session() else {
        return;
    };
    let (kek_public, _kek_private) = rsa_keypair(&session, "q1-kek", true);
    let (_target_public, target_private) = rsa_keypair(&session, "q1-target", false);

    let error = session
        .wrap_key(&Mechanism::RsaPkcs, kek_public, target_private)
        .expect_err("a non-extractable key must not be wrappable");

    println!("Q1 answer: {error:?}");
    // Measured: CKR_KEY_UNEXTRACTABLE, exactly as assumed. Non-extractable
    // means the token will not hand the key out, so a policy that says so is
    // enforced by the device rather than by the software above it.
    assert!(
        format!("{error:?}").contains("KeyUnextractable"),
        "expected CKR_KEY_UNEXTRACTABLE, got: {error:?}"
    );
}

/// Q2. Which wrapping mechanisms does the token advertise?
///
/// P7 and P8 can only use mechanisms the token advertises here.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q2_which_wrapping_mechanisms_are_advertised() {
    let Some((context, slot)) = token() else {
        return;
    };

    let mechanisms = context.get_mechanism_list(slot).expect("list mechanisms");
    let has = |wanted: MechanismType| mechanisms.contains(&wanted);

    println!("Q2 answer, {} mechanisms advertised:", mechanisms.len());
    for (name, mechanism) in [
        ("CKM_AES_KEY_WRAP", MechanismType::AES_KEY_WRAP),
        ("CKM_AES_KEY_WRAP_PAD", MechanismType::AES_KEY_WRAP_PAD),
        ("CKM_RSA_PKCS_OAEP", MechanismType::RSA_PKCS_OAEP),
    ] {
        println!("  {name}: {}", if has(mechanism) { "yes" } else { "no" });
    }

    // The three P7 and P8 depend on are all present, so neither phase is
    // planning against a mechanism this token does not have.
    assert!(has(MechanismType::AES_KEY_WRAP));
    assert!(has(MechanismType::AES_KEY_WRAP_PAD));
    assert!(has(MechanismType::RSA_PKCS_OAEP));

    // CKM_AES_KEY_WRAP_KWP and CKM_RSA_AES_KEY_WRAP have no constant in
    // cryptoki 0.12 and are absent from this token by raw value too. The
    // second is the mechanism D6 called the top priority, so on SoftHSM it
    // has to be assembled from OAEP plus AES-KW rather than asked for.
    let raw: Vec<u64> = mechanisms.iter().map(|m| u64::from(*m)).collect();
    println!(
        "  CKM_AES_KEY_WRAP_KWP: {}",
        raw.contains(&CKM_AES_KEY_WRAP_KWP)
    );
    println!(
        "  CKM_RSA_AES_KEY_WRAP: {}",
        raw.contains(&CKM_RSA_AES_KEY_WRAP)
    );
}

/// Q3. Is `C_WrapKey` output raw mechanism bytes rather than a structure?
///
/// F8 says a PKCS#11 token has no CMS path, so a wrap produced here cannot be
/// handed to a CMS reader. If the output were a `ContentInfo`, the wrapping
/// model could be shared between backends; if it is raw bytes, it cannot.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q3_wrap_output_is_raw_mechanism_bytes() {
    let Some((_context, session)) = session() else {
        return;
    };
    let (kek_public, _kek_private) = rsa_keypair(&session, "q3-kek", true);
    let (_target_public, target_private) = rsa_keypair(&session, "q3-target", true);

    // Measured, and worth its own line: RSA key transport cannot wrap an
    // asymmetric private key at all. An RSA-2048 private key is around 1.2 kB
    // and a key-transport block holds one modulus, 256 bytes. This is the
    // reason CKM_RSA_AES_KEY_WRAP exists, and the reason P7 needs it rather
    // than plain OAEP.
    let refused = session
        .wrap_key(&Mechanism::RsaPkcs, kek_public, target_private)
        .expect_err("an RSA private key does not fit in a key-transport block");
    println!("Q3 answer, RSA key transport over a private key: {refused:?}");
    assert!(
        format!("{refused:?}").contains("KeyNotWrappable"),
        "expected CKR_KEY_NOT_WRAPPABLE, distinct from the unextractable case: {refused:?}"
    );

    // The AES path does carry it, and what comes back is mechanism output.
    let aes_kek = aes_kek(&session, "q3-aes-kek");
    let wrapped = session
        .wrap_key(&Mechanism::AesKeyWrapPad, aes_kek, target_private)
        .expect("AES-KWP wraps a private key");

    println!(
        "Q3 answer, AES-KWP output: {} bytes, first byte 0x{:02x}",
        wrapped.len(),
        wrapped[0]
    );
    assert_eq!(
        wrapped.len() % 8,
        0,
        "RFC 5649 output is a whole number of 8-byte blocks"
    );
    // No ContentInfo, no AlgorithmIdentifier, nothing self-describing. A
    // reader is told the mechanism out of band or not at all, which is what
    // F8 claimed and this confirms.
    assert_ne!(
        wrapped[0], 0x30,
        "a leading SEQUENCE tag would mean the token had produced a DER structure"
    );
}

/// Q4. Does `CKA_WRAP` gate wrapping, and is `CKA_WRAP_WITH_TRUSTED`
/// enforced at use time or only at provisioning?
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q4_cka_wrap_gates_wrapping() {
    let Some((_context, session)) = session() else {
        return;
    };
    // A public key explicitly not allowed to wrap.
    let public_template = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::ModulusBits(2048.into()),
        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
        Attribute::Label(b"q4-no-wrap-pub".to_vec()),
        Attribute::Wrap(false),
        Attribute::Verify(true),
    ];
    let private_template = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(b"q4-no-wrap".to_vec()),
        Attribute::Sign(true),
    ];
    let (no_wrap_public, _) = session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &public_template,
            &private_template,
        )
        .expect("generate the non-wrapping keypair");
    let (_target_public, target_private) = rsa_keypair(&session, "q4-target", true);

    let error = session
        .wrap_key(&Mechanism::RsaPkcs, no_wrap_public, target_private)
        .expect_err("a key without CKA_WRAP must not wrap");
    println!("Q4 answer, CKA_WRAP=false: {error}");
}

/// Q5. Can an AES key be generated and used as a KEK?
///
/// P8 assumes so. Without it, `AES-KW` has no key to wrap with.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q5_an_aes_key_can_be_generated_and_wrap() {
    let Some((_context, session)) = session() else {
        return;
    };
    let aes_kek = aes_kek(&session, "q5-aes-kek");

    let (_target_public, target_private) = rsa_keypair(&session, "q5-target", true);
    let wrapped = session
        .wrap_key(&Mechanism::AesKeyWrapPad, aes_kek, target_private)
        .expect("wrap under the AES KEK");

    println!("Q5 answer: AES-KWP wrap produced {} bytes", wrapped.len());
    assert!(!wrapped.is_empty());
}

/// Q6. What payload encoding does `C_UnwrapKey` produce a key from?
///
/// F14 says a third-party recipient has to guess whether Rite's wrapped
/// payload is PKCS#8 or PKCS#1/SEC1. This asks the token which it accepts.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn q6_unwrap_expects_pkcs8() {
    let Some((_context, session)) = session() else {
        return;
    };
    let aes_kek = aes_kek(&session, "q6-aes-kek");
    let (_target_public, target_private) = rsa_keypair(&session, "q6-target", true);

    let wrapped = session
        .wrap_key(&Mechanism::AesKeyWrapPad, aes_kek, target_private)
        .expect("wrap the RSA private key");

    // Unwrapping it back tells us the token round-trips its own encoding.
    let restored = session
        .unwrap_key(
            &Mechanism::AesKeyWrapPad,
            aes_kek,
            &wrapped,
            &[
                Attribute::Token(false),
                Attribute::Private(true),
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::RSA),
                Attribute::Label(b"q6-restored".to_vec()),
                Attribute::Sign(true),
                Attribute::Extractable(true),
            ],
        )
        .expect("unwrap the key the token itself wrapped");

    let attributes = session
        .get_attributes(restored, &[AttributeType::KeyType])
        .expect("read the restored key type");
    println!("Q6 answer: the token round-trips its own encoding, {attributes:?}");

    // Which encoding that is, by arithmetic. RFC 5649 adds an 8-byte header
    // and pads to a multiple of 8, so the payload is within 8 bytes below the
    // ciphertext length. A PKCS#8 PrivateKeyInfo for RSA-2048 runs about
    // 1218 bytes; the bare PKCS#1 RSAPrivateKey inside it about 1190. The gap
    // is far wider than the padding, so the two are distinguishable.
    let payload = wrapped.len() - 8;
    println!(
        "  ciphertext {} bytes, payload at most {payload}",
        wrapped.len()
    );
    assert!(
        (1200..=1240).contains(&payload),
        "payload {payload} matches neither PKCS#8 nor PKCS#1 for RSA-2048"
    );
    assert!(
        payload > 1200,
        "a payload this size is PKCS#8, not the bare PKCS#1 key it wraps"
    );
}
