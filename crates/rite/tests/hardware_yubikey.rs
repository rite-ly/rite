//! Ceremonies against a real YubiKey, run by hand before a release that
//! touches the PIV code. CI has no device, so every test is `#[ignore]`.
//!
//! The suite resets the YubiKey's PIV application and provisions its own
//! keys, so it runs only on a YubiKey kept for testing, named by serial:
//!
//! ```sh
//! RITE_HW_YUBIKEY_SERIAL=12345678 cargo test -p rite --features piv,yubikey \
//!     --test hardware_yubikey -- --ignored --test-threads=1
//! ```
//!
//! It needs firmware 5.7 or later, for the RSA-4096 key in slot 83, and
//! `ykman` on the `PATH`. Without the variable, or with another
//! YubiKey inserted, each test returns without touching anything. The tests
//! take turns on the one device; the PIV application is reset once, at the
//! first test, and left provisioned (`ykman piv reset` clears it).
//!
//! Steps run in-process through the runtime's step path, which the CLI uses
//! too, so each test can answer the PIN prompt itself.
#![cfg(all(feature = "piv", feature = "yubikey"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use rite_model::{ArtifactId, MaterialKind};
use rite_runtime::test_support::StepRunner;
use rite_runtime::{ArtifactValue, BackendRegistry, ExecutionError, Response};
use rite_sdk::BackendError;
use secrecy::SecretString;

/// The factory PIN, which a reset restores.
const PIN: &str = "123456";
/// The factory management key, which a reset restores.
const MANAGEMENT_KEY: &str = "010203040506070801020304050607080102030405060708";
const MANIFEST: &[u8] = b"release 1.0\n";

/// The provisioned card: its serial and where `ykman` left each slot's
/// public key.
struct Card {
    serial: String,
    keys: PathBuf,
}

/// One test at a time on the card, and the card provisioned once.
fn card() -> Option<(MutexGuard<'static, ()>, &'static Card)> {
    static TURN: Mutex<()> = Mutex::new(());
    static CARD: OnceLock<Option<Card>> = OnceLock::new();
    // A test that failed holding the turn poisons it; the card is still
    // usable by the next.
    let turn = TURN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    CARD.get_or_init(provision)
        .as_ref()
        .map(|card| (turn, card))
}

/// Reset the PIV application of the named YubiKey and generate the keys the
/// tests use, or `None` when no YubiKey is named. Panics unless exactly the
/// named one is inserted.
fn provision() -> Option<Card> {
    let Ok(serial) = std::env::var("RITE_HW_YUBIKEY_SERIAL") else {
        eprintln!("RITE_HW_YUBIKEY_SERIAL is not set: skipping the YubiKey tests");
        return None;
    };
    let inserted = ykman(&["list", "--serials"], None);
    let inserted: Vec<&str> = inserted.lines().map(str::trim).collect();
    assert_eq!(
        inserted,
        [serial.as_str()],
        "exactly the YubiKey RITE_HW_YUBIKEY_SERIAL names must be inserted"
    );

    ykman(&["piv", "reset", "--force"], Some(&serial));
    let keys = std::env::temp_dir().join(format!("rite-hw-yubikey-{serial}"));
    std::fs::create_dir_all(&keys).unwrap();
    for (slot, algorithm, pin_policy) in [
        ("9a", "RSA2048", "DEFAULT"),
        ("9c", "ECCP256", "DEFAULT"),
        ("9d", "ECCP384", "DEFAULT"),
        ("82", "RSA2048", "DEFAULT"),
        ("83", "RSA4096", "DEFAULT"),
        ("84", "RSA2048", "ALWAYS"),
    ] {
        let public = keys.join(format!("{slot}.pem"));
        ykman(
            &[
                "piv",
                "keys",
                "generate",
                "--management-key",
                MANAGEMENT_KEY,
                "--algorithm",
                algorithm,
                "--pin-policy",
                pin_policy,
                slot,
                public.to_str().unwrap(),
            ],
            Some(&serial),
        );
    }
    Some(Card { serial, keys })
}

/// Run `ykman` on `device`, and return its standard output.
fn ykman(args: &[&str], device: Option<&str>) -> String {
    let mut command = Command::new("ykman");
    if let Some(serial) = device {
        command.args(["--device", serial]);
    }
    let output = command.args(args).output().expect("ykman on the PATH");
    assert!(
        output.status.success(),
        "ykman {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The PIN tries the card has left, as `ykman` reads them.
fn pin_tries(card: &Card) -> u32 {
    let info = ykman(&["piv", "info"], Some(&card.serial));
    let line = info
        .lines()
        .find_map(|line| line.trim().strip_prefix("PIN tries remaining:"))
        .unwrap_or_else(|| panic!("no PIN tries in `ykman piv info`:\n{info}"));
    let tries = line.trim().split('/').next().unwrap();
    tries.parse().unwrap()
}

/// A ceremony on the card with `steps`. It declares the six provisioned
/// keys, with `pin` as the 9D key's optional `fingerprint:` line.
fn ceremony(card: &Card, pin: &str, steps: &str) -> String {
    format!(
        r#"version: "0.3"
name: "YubiKey hardware check"
roles:
  operator:
    name: "Operator"
backends:
  token:
    provider: yubikey
    serial: "{serial}"
  software:
    provider: openssl
credentials:
  card_pin:
    backend: token
    grants: user
    source: entered
materials:
  rsa_key:
    type: backend_key
    backend: token
    id: "piv:9a"
    algorithm: RSA-2048
  signing_key:
    type: backend_key
    backend: token
    id: "piv:9c"
    algorithm: ECDSA-P256
  decryption_key:
    type: backend_key
    backend: token
    id: "piv:9d"
    algorithm: ECDSA-P384
{pin}
  rsa_decryption_key:
    type: backend_key
    backend: token
    id: "piv:82"
    algorithm: RSA-2048
  rsa_4096_key:
    type: backend_key
    backend: token
    id: "piv:83"
    algorithm: RSA-4096
  rsa_pin_always_key:
    type: backend_key
    backend: token
    id: "piv:84"
    algorithm: RSA-2048
  manifest:
    type: bytes
    path: "manifest.txt"
sections:
  main:
    role: ${{role.operator}}
    steps:
{steps}"#,
        serial = card.serial,
    )
}

/// An `authenticate` step on the card with its PIN, named `id`.
fn unlock(id: &str) -> String {
    authenticate(id, "card_pin")
}

/// An `authenticate` step on the card with `credential`, named `id`.
fn authenticate(id: &str, credential: &str) -> String {
    format!(
        "      {id}:\n        action: authenticate\n        backend: token\n        reads:\n          \
         credential: ${{credential.{credential}}}\n"
    )
}

/// A `sign_data` step on the card, named `id`, signing the manifest with
/// `key` into `creates`.
fn sign(id: &str, key: &str, algorithm: &str, creates: &str) -> String {
    format!(
        r"      {id}:
        action: sign_data
        backend: token
        with:
          algorithm: {algorithm}
        reads:
          key: ${{artifact.{key}}}
          data: ${{artifact.manifest}}
        creates: {creates}
"
    )
}

/// A `verify_signature` step in software, named `id`, under the scheme the
/// key implies.
fn verify(id: &str, key: &str, signature: &str) -> String {
    format!(
        r"      {id}:
        action: verify_signature
        backend: software
        reads:
          key: ${{artifact.{key}}}
          data: ${{artifact.manifest}}
          signature: ${{artifact.{signature}}}
"
    )
}

/// A `verify_signature` step in software, named `id`, under `algorithm`,
/// for a scheme the key does not imply, such as RSA-PSS.
fn verify_as(id: &str, key: &str, signature: &str, algorithm: &str) -> String {
    format!(
        r"      {id}:
        action: verify_signature
        backend: software
        with:
          algorithm: {algorithm}
        reads:
          key: ${{artifact.{key}}}
          data: ${{artifact.manifest}}
          signature: ${{artifact.{signature}}}
"
    )
}

/// What a run left: the runner, holding its facts and artifacts, and the
/// step that ended the run early with its error.
struct Run {
    runner: StepRunner,
    stopped: Option<(String, ExecutionError)>,
}

impl Run {
    fn completed(&self) {
        if let Some((step, error)) = &self.stopped {
            panic!("step '{step}' failed: {error}\n{:#?}", self.runner.facts());
        }
    }

    fn facts_of(&self, kind: &str) -> Vec<serde_json::Value> {
        self.runner
            .facts()
            .iter()
            .map(|fact| serde_json::to_value(fact).unwrap())
            .filter(|fact| fact["type"] == kind)
            .collect()
    }

    fn bytes(&self, artifact: &str) -> &[u8] {
        self.runner
            .artifact_bytes(&ArtifactId::new(artifact))
            .unwrap_or_else(|| panic!("no artifact '{artifact}'"))
    }
}

/// Run `yaml` step by step on the card, answering prompts from `responses`
/// in order, and stop at the first step that fails.
fn run(yaml: &str, responses: Vec<Response>) -> Run {
    let ceremony = rite_resolver::resolve(yaml, None)
        .into_result()
        .expect("the ceremony resolves");
    let mut backends = BackendRegistry::with_factory(rite_stdlib::stdlib_backend_factory());
    for (name, config) in &ceremony.backends {
        backends.declare(name.clone(), config.clone());
    }
    let mut runner = StepRunner::new(rite_stdlib::default_registry(), backends);
    for (id, material) in ceremony.materials.iter() {
        let artifact = ArtifactId::new(id.as_str());
        match &material.kind {
            MaterialKind::BackendKey(key) => runner.add_held_key(artifact, key.clone()),
            _ => runner.add_material(artifact, ArtifactValue::Bytes(MANIFEST.to_vec())),
        }
    }
    for (_, credential) in ceremony.credentials.iter() {
        runner.add_credential(credential.clone());
    }
    for response in responses {
        runner.enqueue_response(response);
    }
    let mut stopped = None;
    for step in &ceremony.execution_plan {
        if let Err(error) = runner.run(step) {
            stopped = Some((step.id.to_string(), error));
            break;
        }
    }
    Run { runner, stopped }
}

fn pin() -> Response {
    Response::Secret(SecretString::from(PIN))
}

/// Check `signature` over the manifest with the public key `ykman` exported
/// for `slot`, through OpenSSL and nothing of Rite's.
fn verify_off_card(card: &Card, slot: &str, digest: MessageDigest, signature: &[u8]) {
    let pem = std::fs::read(card.keys.join(format!("{slot}.pem"))).unwrap();
    let key = PKey::public_key_from_pem(&pem).unwrap();
    let mut verifier = Verifier::new(digest, &key).unwrap();
    verifier.update(MANIFEST).unwrap();
    assert!(
        verifier.verify(signature).unwrap(),
        "OpenSSL rejects the {slot} signature"
    );
}

/// [`verify_off_card`] for an RSA-PSS signature with SHA-256, MGF1 over
/// SHA-256 and the salt length fixed at 32 bytes, the parameters
/// `rite-openssl` signs with.
fn verify_pss_off_card(card: &Card, slot: &str, signature: &[u8]) {
    let pem = std::fs::read(card.keys.join(format!("{slot}.pem"))).unwrap();
    let key = PKey::public_key_from_pem(&pem).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
    verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
    verifier.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    verifier
        .set_rsa_pss_saltlen(RsaPssSaltlen::custom(32))
        .unwrap();
    verifier.update(MANIFEST).unwrap();
    assert!(
        verifier.verify(signature).unwrap(),
        "OpenSSL rejects the {slot} PSS signature"
    );
}

/// One PIN step unlocks the card for signing with a key it already held, in
/// a slot whose default PIN policy is `once`, for RSA-2048, RSA-4096 and
/// P-384. Each signature verifies in software and against what `ykman`
/// exported.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn one_pin_step_signs_with_keys_the_card_held() {
    let Some((_turn, card)) = card() else { return };
    let steps = [
        unlock("unlock"),
        sign("sign_rsa", "rsa_key", "RSA-PKCS1-SHA256", "rsa_signature"),
        sign(
            "sign_rsa_4096",
            "rsa_4096_key",
            "RSA-PKCS1-SHA256",
            "rsa_4096_signature",
        ),
        sign(
            "sign_p384",
            "decryption_key",
            "ECDSA-SHA384",
            "p384_signature",
        ),
        verify("check_rsa", "rsa_key", "rsa_signature"),
        verify("check_rsa_4096", "rsa_4096_key", "rsa_4096_signature"),
        verify("check_p384", "decryption_key", "p384_signature"),
    ]
    .concat();
    let run = run(&ceremony(card, "", &steps), vec![pin()]);
    run.completed();

    let entered = run.facts_of("backend_operation");
    let entered: Vec<_> = entered
        .iter()
        .filter(|fact| fact["kind"] == "authenticate")
        .collect();
    assert_eq!(entered.len(), 1, "{entered:#?}");
    assert_eq!(entered[0]["inputs"]["retries_before"], 3);
    let bound = run.facts_of("key_bound");
    assert_eq!(bound.len(), 3, "{bound:#?}");

    verify_off_card(
        card,
        "9a",
        MessageDigest::sha256(),
        run.bytes("rsa_signature"),
    );
    verify_off_card(
        card,
        "83",
        MessageDigest::sha256(),
        run.bytes("rsa_4096_signature"),
    );
    verify_off_card(
        card,
        "9d",
        MessageDigest::sha384(),
        run.bytes("p384_signature"),
    );
}

/// Sealed in software to a key-management key on the card, opened by the
/// card: the P-384 key in 9D through key agreement (rite#315), and the
/// RSA-2048 key in retired slot 82 and the RSA-4096 key in 83 through key
/// decryption, the raw RSA operation on the card and the OAEP decoding on
/// the host.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn the_card_opens_what_was_sealed_to_its_key() {
    let Some((_turn, card)) = card() else { return };
    for key in ["decryption_key", "rsa_decryption_key", "rsa_4096_key"] {
        let steps = [
            format!(
                r"      seal:
        action: encrypt_data
        backend: software
        reads:
          recipient: ${{artifact.{key}}}
          data: ${{artifact.manifest}}
        creates: sealed
"
            ),
            unlock("unlock"),
            format!(
                r"      open:
        action: decrypt_data
        backend: token
        reads:
          encrypted_data: ${{artifact.sealed}}
          decryption_key: ${{artifact.{key}}}
        creates: opened
"
            ),
        ]
        .concat();
        let run = run(&ceremony(card, "", &steps), vec![pin()]);
        run.completed();
        assert_eq!(run.bytes("opened"), MANIFEST, "{key}");
    }
}

/// RSA-PSS signatures from RSA-2048 and RSA-4096 keys the card held: the
/// host builds the PSS block, the card applies the raw RSA operation, and
/// both Rite's software verifier and OpenSSL with a fixed 32-byte salt
/// accept the result.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn rsa_pss_signatures_from_the_card_verify_off_card() {
    let Some((_turn, card)) = card() else { return };
    let steps = [
        unlock("unlock"),
        sign("sign_rsa", "rsa_key", "RSA-PSS-SHA256", "rsa_signature"),
        sign(
            "sign_rsa_4096",
            "rsa_4096_key",
            "RSA-PSS-SHA256",
            "rsa_4096_signature",
        ),
        verify_as("check_rsa", "rsa_key", "rsa_signature", "RSA-PSS-SHA256"),
        verify_as(
            "check_rsa_4096",
            "rsa_4096_key",
            "rsa_4096_signature",
            "RSA-PSS-SHA256",
        ),
    ]
    .concat();
    let run = run(&ceremony(card, "", &steps), vec![pin()]);
    run.completed();
    verify_pss_off_card(card, "9a", run.bytes("rsa_signature"));
    verify_pss_off_card(card, "83", run.bytes("rsa_4096_signature"));
}

/// An RSA signature reads the slot's key size through GET METADATA between
/// the PIN step and the signature. Under PIN policy `always`, that command
/// must not use up the verification the signature needs.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn an_rsa_key_with_pin_policy_always_signs_after_one_pin_step() {
    let Some((_turn, card)) = card() else { return };
    let steps = [
        unlock("unlock"),
        sign(
            "sign",
            "rsa_pin_always_key",
            "RSA-PKCS1-SHA256",
            "signature",
        ),
    ]
    .concat();
    let run = run(&ceremony(card, "", &steps), vec![pin()]);
    run.completed();
    verify_off_card(card, "84", MessageDigest::sha256(), run.bytes("signature"));
}

/// Slot 9C defaults to PIN policy `always`: the card clears the PIN after
/// each signature, so a second signature after one PIN step fails with
/// `PinRequired`, and a PIN step before each succeeds. The design of
/// `authenticate` rests on this.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn slot_9c_takes_the_pin_before_each_signature() {
    let Some((_turn, card)) = card() else { return };
    let once = [
        unlock("unlock"),
        sign("first", "signing_key", "ECDSA-SHA256", "first_signature"),
        sign("second", "signing_key", "ECDSA-SHA256", "second_signature"),
    ]
    .concat();
    // The PIN, then "no" to retrying the second signature.
    let run_once = run(
        &ceremony(card, "", &once),
        vec![pin(), Response::Bool(false)],
    );
    let Some((step, error)) = &run_once.stopped else {
        panic!(
            "a second 9C signature after one PIN step succeeded: the slot's policy is not `always`"
        );
    };
    assert_eq!(step, "second");
    assert!(
        matches!(
            error,
            ExecutionError::BackendError(BackendError::PinRequired)
        ),
        "{error:?}"
    );
    verify_off_card(
        card,
        "9c",
        MessageDigest::sha256(),
        run_once.bytes("first_signature"),
    );

    let each = [
        unlock("unlock"),
        sign("first", "signing_key", "ECDSA-SHA256", "first_signature"),
        unlock("unlock_again"),
        sign("second", "signing_key", "ECDSA-SHA256", "second_signature"),
    ]
    .concat();
    let run_each = run(&ceremony(card, "", &each), vec![pin(), pin()]);
    run_each.completed();
    // The PIN is still verified at the second PIN step; the count it reads
    // must be the card's, not the 0 the empty-VERIFY query reports then.
    let tries: Vec<_> = run_each
        .facts_of("backend_operation")
        .into_iter()
        .filter(|fact| fact["kind"] == "authenticate")
        .map(|fact| fact["inputs"]["retries_before"].clone())
        .collect();
    assert_eq!(tries, [3, 3]);
    verify_off_card(
        card,
        "9c",
        MessageDigest::sha256(),
        run_each.bytes("second_signature"),
    );
}

/// A wrong PIN fails the attempt with the tries left; the right one on the
/// retry unlocks the card and restores the count.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_wrong_pin_is_retried_and_the_count_restored() {
    let Some((_turn, card)) = card() else { return };
    // Never spend a card's last tries on a test.
    assert_eq!(pin_tries(card), 3, "the card must start with every PIN try");
    let steps = [
        unlock("unlock"),
        sign("sign", "rsa_key", "RSA-PKCS1-SHA256", "signature"),
    ]
    .concat();
    let wrong = Response::Secret(SecretString::from("654321"));
    let run = run(
        &ceremony(card, "", &steps),
        vec![wrong, Response::Bool(true), pin()],
    );
    run.completed();
    let failed = run.facts_of("step_attempt_failed");
    assert_eq!(failed.len(), 1, "{failed:#?}");
    assert_eq!(failed[0]["step"], "unlock");
    let error = serde_json::to_string(&failed[0]["error"]).unwrap();
    assert!(error.contains("2 retries remaining"), "{error}");
    assert_eq!(pin_tries(card), 3);
}

/// A pinned fingerprint that matches the card binds the key; one that does
/// not fails the step with `KeyNotFound`, before the card is asked to use it.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_pinned_fingerprint_is_checked_against_the_card() {
    let Some((_turn, card)) = card() else { return };
    let steps = [
        unlock("unlock"),
        sign("sign", "decryption_key", "ECDSA-SHA384", "signature"),
    ]
    .concat();
    let first = run(&ceremony(card, "", &steps), vec![pin()]);
    first.completed();
    let found = first.facts_of("key_bound")[0]["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();

    let pinned = run(
        &ceremony(card, &format!("    fingerprint: \"{found}\""), &steps),
        vec![pin()],
    );
    pinned.completed();
    assert_eq!(pinned.facts_of("key_bound")[0]["pinned"], true);

    let other = format!("    fingerprint: \"sha256:{}\"", "00".repeat(32));
    let mismatch = run(
        &ceremony(card, &other, &steps),
        vec![pin(), Response::Bool(false)],
    );
    let Some((step, error)) = &mismatch.stopped else {
        panic!("a key that is not the pinned one was used");
    };
    assert_eq!(step, "sign");
    assert!(
        matches!(
            error,
            ExecutionError::BackendError(BackendError::KeyNotFound(_))
        ),
        "{error:?}"
    );
    assert!(mismatch.facts_of("key_bound").is_empty());
}

/// A management key the card refuses is reported as such, not as a PIN.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_refused_management_key_is_not_a_pin_failure() {
    let Some((_turn, card)) = card() else { return };
    let mut backends = BackendRegistry::with_factory(rite_stdlib::stdlib_backend_factory());
    let config: rite_sdk::BackendConfig = serde_json::from_value(serde_json::json!({
        "provider": "yubikey",
        "serial": card.serial,
    }))
    .unwrap();
    backends.declare("token".to_string(), config);
    let device = backends.get_yubikey("token").unwrap();
    // Not the factory key, and not a weak 3DES key, which the `yubikey`
    // crate refuses before the card sees it.
    let wrong = b"rite-wrong-management-k!";
    let error = device
        .authenticate_management(rite_sdk::ManagementKey::Value(wrong))
        .unwrap_err();
    assert!(
        matches!(error, BackendError::ManagementKeyRequired),
        "{error:?}"
    );
}

/// [`ceremony`] with the card's management key declared as `card_admin`,
/// from `source`, as YAML.
fn admin_ceremony(card: &Card, source: &str, steps: &str) -> String {
    ceremony(card, "", steps).replace(
        "credentials:\n",
        &format!(
            "credentials:\n  card_admin:\n    backend: token\n    grants: admin\n    {source}\n"
        ),
    )
}

/// An `authenticate` step with the management key, then a P-256 key
/// generated in `slot` as `new_key`.
fn admin_then_generate(slot: &str, value: &str) -> String {
    let admin = authenticate("admin", "card_admin");
    format!(
        r#"{admin}{value}      generate:
        action: generate_key
        backend: token
        with:
          algorithm: ECDSA-P256
          slot: "{slot}"
        creates: new_key
"#
    )
}

/// The management key's record: what the card reported of it.
fn admin_outputs(run: &Run) -> serde_json::Value {
    run.facts_of("backend_operation")
        .into_iter()
        .find(|fact| fact["kind"] == "authenticate" && fact["inputs"]["grants"] == "admin")
        .expect("an admin authentication")["outputs"]
        .clone()
}

/// The key a step generated in `slot` is the one the card reports there.
fn generated_in(card: &Card, run: &Run, slot: &str) {
    let pem = ykman(&["piv", "keys", "export", slot, "-"], Some(&card.serial));
    let reported = PKey::public_key_from_pem(pem.as_bytes()).unwrap();
    let Some(ArtifactValue::BackendKey {
        public_key: Some(public),
        ..
    }) = run.runner.artifact(&ArtifactId::new("new_key"))
    else {
        panic!("no generated key with its public half");
    };
    let generated = PKey::public_key_from_der(public.as_bytes()).unwrap();
    assert!(
        generated.public_eq(&reported),
        "the key in {slot} is not the one generated"
    );
}

/// The factory management key opens an admin session, and a key is
/// generated in a slot. The card reports its key as AES-192 (firmware 5.7)
/// and still the default.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn the_factory_management_key_generates_a_key_on_the_card() {
    let Some((_turn, card)) = card() else { return };
    let yaml = admin_ceremony(
        card,
        "source: factory_default",
        &admin_then_generate("85", ""),
    );
    let run = run(&yaml, vec![]);
    run.completed();
    assert_eq!(
        admin_outputs(&run),
        serde_json::json!({"algorithm": "aes192", "is_default": true})
    );
    generated_in(card, &run, "85");
}

/// A held management key comes from the artifact a step reads as `value`:
/// here typed in hex.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_held_management_key_generates_a_key_on_the_card() {
    let Some((_turn, card)) = card() else { return };
    let typed = r#"      type_key:
        action: enter_secret
        with:
          message: "Management key"
          format: hex
        creates: admin_key
"#;
    let steps = admin_then_generate("86", "          value: ${artifact.admin_key}\n");
    let yaml = admin_ceremony(card, "source: held", &format!("{typed}{steps}"));
    let run = run(
        &yaml,
        vec![Response::Secret(SecretString::from(MANAGEMENT_KEY))],
    );
    run.completed();
    let recorded = serde_json::to_string(run.runner.facts()).unwrap();
    assert!(!recorded.contains(MANAGEMENT_KEY), "{recorded}");
    generated_in(card, &run, "86");
}

/// Puts the factory management key back, unprotected, when a test that
/// protected it ends, passed or not.
struct Unprotect<'a>(&'a Card);

impl Drop for Unprotect<'_> {
    fn drop(&mut self) {
        // A failure here while the test is already failing would abort the
        // run and hide why it failed: it is reported instead.
        if std::thread::panicking() {
            let restored = Command::new("ykman")
                .args([
                    "--device",
                    &self.0.serial,
                    "piv",
                    "access",
                    "change-management-key",
                ])
                .args(["--pin", PIN, "--algorithm", "AES192"])
                .args(["--new-management-key", MANAGEMENT_KEY])
                .status();
            if !restored.is_ok_and(|status| status.success()) {
                eprintln!("could not restore the factory management key: `ykman piv reset` does");
            }
            return;
        }
        ykman(
            &[
                "piv",
                "access",
                "change-management-key",
                "--pin",
                PIN,
                "--algorithm",
                "AES192",
                "--new-management-key",
                MANAGEMENT_KEY,
            ],
            Some(&self.0.serial),
        );
    }
}

/// A management key `ykman --protect` stored is released by the PIN, which
/// the step asks for first and records as its own authentication.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_protected_management_key_is_released_by_the_pin() {
    let Some((_turn, card)) = card() else { return };
    ykman(
        &[
            "piv",
            "access",
            "change-management-key",
            "--management-key",
            MANAGEMENT_KEY,
            "--pin",
            PIN,
            "--protect",
        ],
        Some(&card.serial),
    );
    let _restore = Unprotect(card);
    let yaml = admin_ceremony(
        card,
        "source:\n      protected_by: ${credential.card_pin}",
        &admin_then_generate("87", ""),
    );
    let run = run(&yaml, vec![pin()]);
    run.completed();
    let credentials: Vec<_> = run
        .facts_of("backend_operation")
        .into_iter()
        .filter(|fact| fact["kind"] == "authenticate")
        .map(|fact| fact["inputs"]["credential"].clone())
        .collect();
    assert_eq!(credentials, ["card_pin", "card_admin"]);
    assert_eq!(admin_outputs(&run)["is_default"], false);
    generated_in(card, &run, "87");
}

/// A key generated with a declared access policy has it on the card: the
/// record shows what the card reports, and `ykman` agrees. The PIN step
/// before it records that the PIN is still the factory one.
#[test]
#[ignore = "needs a YubiKey kept for testing; see the module documentation"]
fn a_declared_access_policy_is_set_and_read_back() {
    let Some((_turn, card)) = card() else { return };
    let steps = [
        unlock("unlock"),
        admin_then_generate("88", "").replace(
            "          slot: \"88\"\n",
            "          slot: \"88\"\n          policy:\n            authentication: per_use\n            \
             presence: never\n",
        ),
    ]
    .concat();
    let yaml = admin_ceremony(card, "source: factory_default", &steps);
    let run = run(&yaml, vec![pin()]);
    run.completed();
    let generated = run
        .facts_of("backend_operation")
        .into_iter()
        .find(|fact| fact["kind"] == "generate_key")
        .expect("a generate_key record");
    assert_eq!(generated["inputs"]["policy"]["authentication"], "per_use");
    assert_eq!(
        generated["outputs"]["access"],
        serde_json::json!({"authentication": "per_use", "presence": "never"})
    );
    let info = ykman(&["piv", "keys", "info", "88"], Some(&card.serial));
    let collapsed = info.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains("PIN required for use: ALWAYS")
            && collapsed.contains("Touch required for use: NEVER"),
        "ykman reports other policies for slot 88:\n{info}"
    );

    let unlocked = run
        .facts_of("backend_operation")
        .into_iter()
        .find(|fact| fact["kind"] == "authenticate" && fact["inputs"]["grants"] == "user")
        .expect("a PIN authentication");
    assert_eq!(unlocked["outputs"]["pin_is_default"], true);
}
