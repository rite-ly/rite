//! The backend against a real token, one test per trait method.
//!
//! `token_questions.rs` talks to `cryptoki` directly, to measure what PKCS#11
//! does. These tests go through [`Pkcs11TokenBackend`], so the crate's own
//! surface is exercised rather than only the binding underneath it.
//!
//! Setup is the same, and the tests are `#[ignore]`d the same way:
//!
//! ```sh
//! softhsm2-util --init-token --slot 0 --label rite-test \
//!     --so-pin 1234 --pin 1234
//! SOFTHSM2_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
//!     cargo test -p rite-pkcs11 -- --ignored --test-threads=1
//! ```
#![allow(clippy::expect_used)]

use cryptoki::object::{Attribute, KeyType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use rite_pkcs11::{Pkcs11Config, Pkcs11TokenBackend};
use rite_sdk::{Backend, KeyId, KeyUsages, Pkcs11Backend};

/// The fixture PIN, matching the setup command above.
const PIN: &str = "1234";

fn backend() -> Option<Pkcs11TokenBackend> {
    let module = std::env::var("SOFTHSM2_MODULE").ok()?;
    Some(
        Pkcs11TokenBackend::try_new(
            "softhsm",
            &Pkcs11Config {
                module,
                token_label: None,
            },
        )
        .expect("open a session against the fixture token"),
    )
}

/// Log in, tolerating a session that the application already logged in.
///
/// PKCS#11 login state belongs to the application rather than the session, so
/// a second login is an error rather than a no-op, and test order decides
/// which call gets there first.
fn login(backend: &mut Pkcs11TokenBackend) {
    match backend.login(PIN.as_bytes()) {
        Ok(()) => {}
        Err(e) if e.to_string().contains("UserAlreadyLoggedIn") => {}
        Err(e) => panic!("log in: {e}"),
    }
}

/// Put a key on the token with attributes the backend should read back.
///
/// Generated through `cryptoki` rather than through the backend, which
/// generates nothing in this milestone.
fn put_key(label: &str) {
    let module = std::env::var("SOFTHSM2_MODULE").expect("checked by the caller");
    let context = cryptoki::context::Pkcs11::new(module).expect("load module");
    context
        .initialize(cryptoki::context::CInitializeArgs::new(
            cryptoki::context::CInitializeFlags::OS_LOCKING_OK,
        ))
        .ok();
    let slot = *context
        .get_slots_with_token()
        .expect("list slots")
        .first()
        .expect("a token is present");
    let session = context.open_rw_session(slot).expect("open session");
    // Login state is per application, not per session, so the backend's own
    // login may already cover this one. PKCS#11 reports that as an error.
    if let Err(e) = session.login(UserType::User, Some(&AuthPin::from(PIN.to_string()))) {
        assert!(
            matches!(
                e,
                cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::UserAlreadyLoggedIn, _)
            ),
            "log in: {e}"
        );
    }
    session
        .generate_key(
            &cryptoki::mechanism::Mechanism::AesKeyGen,
            &[
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::KeyType(KeyType::AES),
                Attribute::ValueLen(32.into()),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
            ],
        )
        .expect("generate the fixture key");
}

#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn identifies_itself_and_the_token_it_opened() {
    let Some(backend) = backend() else {
        return;
    };
    assert_eq!(backend.name(), "softhsm");
    assert_eq!(backend.provider(), "pkcs11");

    let info = backend.token_info().expect("read token info");
    assert!(!info.label.is_empty(), "the token names itself: {info:?}");
    assert!(
        info.flags
            .contains(rite_sdk::Pkcs11TokenFlags::TOKEN_INITIALIZED),
        "the fixture token is initialised: {info:?}"
    );

    // The fingerprint identifies the device, so it has to carry what
    // distinguishes one token from another rather than the name Rite gave it.
    let fingerprint = backend.fingerprint();
    assert!(fingerprint.contains(&info.label), "{fingerprint}");
    assert!(fingerprint.contains(&info.serial), "{fingerprint}");
}

#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn lists_the_mechanisms_the_token_offers() {
    let Some(backend) = backend() else {
        return;
    };
    let mechanisms = backend.supported_mechanisms().expect("list mechanisms");
    assert!(!mechanisms.is_empty(), "the token advertised no mechanisms");
}

#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn reads_the_attributes_a_key_was_created_with() {
    let Some(mut backend) = backend() else {
        return;
    };
    login(&mut backend);
    put_key("rite-backend-test-key");

    let attributes = backend
        .key_security_attributes(&KeyId::new("rite-backend-test-key"))
        .expect("read attributes");
    assert!(attributes.sensitive, "{attributes:?}");
    assert!(!attributes.extractable, "{attributes:?}");
    assert!(attributes.never_extractable, "{attributes:?}");
    assert!(
        attributes
            .usages
            .contains(KeyUsages::WRAP | KeyUsages::UNWRAP),
        "the attributes the key was created with reach the SDK vocabulary: {attributes:?}"
    );
}

/// A label the token does not hold is reported as `KeyNotFound`, not as a
/// hardware error.
#[test]
#[ignore = "needs SOFTHSM2_MODULE"]
fn a_key_the_token_does_not_hold_is_reported_as_missing() {
    let Some(mut backend) = backend() else {
        return;
    };
    login(&mut backend);

    let error = backend
        .key_security_attributes(&KeyId::new("no-such-key"))
        .expect_err("a label nothing carries");
    assert!(
        matches!(error, rite_sdk::BackendError::KeyNotFound(_)),
        "{error:?}"
    );
}

/// A module path that names nothing is reported as a configuration problem,
/// not as a PKCS#11 error.
#[test]
fn a_module_that_is_not_there_is_a_configuration_error() {
    let error = Pkcs11TokenBackend::try_new(
        "missing",
        &Pkcs11Config {
            module: "/nonexistent/libsofthsm2.so".to_string(),
            token_label: None,
        },
    )
    .expect_err("no module at that path");
    assert!(
        matches!(error, rite_sdk::BackendError::Configuration(_)),
        "{error:?}"
    );
}
