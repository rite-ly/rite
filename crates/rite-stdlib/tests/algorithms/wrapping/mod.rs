//! The wrapping family: `wrap_key` and `encrypt_data` writing, `unwrap_key`
//! and `decrypt_data` reading.
//!
//! A write case becomes up to three tests: the write itself, Rite opening
//! what it wrote (`::read_back`), and the `openssl` command line opening it
//! (`::openssl_opens`). A fixture becomes one per read step. Under a policy
//! level other than the default, the level is appended to the name.

mod cases;
mod coverage;
mod model;
mod regenerate;

use std::collections::BTreeSet;

use libtest_mimic::Trial;
use rite_model::StepFact;
use rite_runtime::{Action, ArtifactValue, compute_fingerprint};
use rite_sdk::{WrapDescription, WrapScheme, cms};
use rite_stdlib::{DecryptDataAction, EncryptDataAction, UnwrapKeyAction, WrapKeyAction};
use secrecy::ExposeSecret;
use serde_json::json;
use x509_cert::der::{Encode, asn1::ObjectIdentifier};

use crate::cli::{Cli, arg};
use crate::family::{Family, file_name};
use crate::harness::{
    build_lacks, check_fields, check_fingerprint, check_refused, check_source, check_value_of,
    cli_lacks, held_spki, is_committed, judge, operation, ran_via, reference_check_value, trial,
};
use crate::keys::read;
use crate::outcome::Policy;
use crate::session::{Refused, Session, Source, Via};
use cases::{FIXTURES, RECIPIENT_SHAPES, WRITES};
use model::{Fixture, Form, Path, Payload, Read, ReadStep, Write, WriteCase, WriteStep};

pub const FAMILY: Family = Family {
    fixtures: "cms",
    trials,
    fixture_files,
    regenerate: regenerate::containers,
};

fn trials() -> Vec<Trial> {
    let mut trials = Vec::new();
    for policy in Policy::ALL.iter().copied() {
        for case in WRITES.iter().chain(RECIPIENT_SHAPES) {
            trials.extend(write_trials(case, policy));
        }
        for fixture in FIXTURES {
            for step in ReadStep::ALL.iter().copied() {
                trials.push(fixture_trial(fixture, step, policy));
            }
        }
    }
    trials.extend(coverage::trials());
    trials
}

fn fixture_files() -> BTreeSet<String> {
    FIXTURES
        .iter()
        .map(|f| file_name(&fixture_path(f)))
        .collect()
}

// ── Writes ───────────────────────────────────────────────────────────────────

fn write_trials(case: &'static WriteCase, policy: Policy) -> Vec<Trial> {
    let name = policy.name(case.name());
    let skip = build_lacks(case.key).or_else(|| build_lacks(case.payload.key()));
    let expected = *case.expect.under(policy);
    let mut trials = vec![trial(name.clone(), skip.clone(), move || {
        let mut session = Session::new();
        let attempt = attempt_write(case, &mut session);
        match (expected, attempt) {
            (Write::Writes(form), Ok(())) => check_written(case, &form, &session),
            (Write::Writes(_), Err(refused)) => judge(None, Err(refused)),
            (Write::Fails(why, refusal), attempt) => {
                check_refused(case.step.name(), &session, (why, refusal), attempt)
            }
        }
    })];

    let Write::Writes(form) = expected else {
        return trials;
    };
    trials.push(trial(
        format!("{name}::read_back"),
        skip.clone(),
        move || read_back(case),
    ));
    if let Some(reader) =
        independent_reader(&form).filter(|_| case.path != Path::Held(Source::Generated))
    {
        let skip = skip.or_else(|| cli_lacks(case.key));
        trials.push(trial(format!("{name}::openssl_opens"), skip, move || {
            openssl_opens(case, reader)
        }));
    }
    trials
}

/// Run a write case in `session`, up to and including its step.
fn attempt_write(case: &WriteCase, session: &mut Session) -> Result<(), Refused> {
    match case.step {
        WriteStep::WrapKey => session
            .import(case.payload.key(), "payload", true)
            .unwrap_or_else(|e| panic!("the payload {} imports: {e:?}", case.payload.key().stem())),
        WriteStep::EncryptData => {
            session.add(
                "payload",
                ArtifactValue::Bytes(case.payload.key().private()),
            );
        }
    }
    match case.path {
        Path::Held(source) => session.hold(source, case.key, "key", case.key.usages())?,
        Path::Recipient(shape) => session.present(shape, case.key, "key", case.key.usages())?,
    }
    let (action, payload_input): (&dyn Action, &str) = match case.step {
        WriteStep::WrapKey => (&WrapKeyAction, "key_to_wrap"),
        WriteStep::EncryptData => (&EncryptDataAction, "data"),
    };
    let params = case
        .scheme
        .map_or_else(|| json!({}), |scheme| json!({ "scheme": scheme }));
    session.run(
        action,
        "written",
        &[
            (payload_input, "payload"),
            (case.path.input(case.step), "key"),
        ],
        &params,
    )
}

/// A write case's session after a write that must have succeeded.
fn written_session(case: &WriteCase) -> Result<Session, String> {
    let mut session = Session::new();
    attempt_write(case, &mut session)
        .map_err(|(at, e)| format!("the write failed at {at:?}: {e}"))?;
    Ok(session)
}

/// The written artifact's bytes and the description the step recorded.
fn written(session: &Session) -> (Vec<u8>, WrapDescription, WrapScheme) {
    match session.artifact("written") {
        ArtifactValue::WrappedKey(wrapped) => (
            wrapped.data().to_vec(),
            wrapped.description().clone(),
            wrapped.scheme(),
        ),
        ArtifactValue::EncryptedData(encrypted) => (
            encrypted.data().to_vec(),
            encrypted.description().clone(),
            encrypted.scheme(),
        ),
        other => panic!("a write step produced {other:?}"),
    }
}

/// Compare what was written with the form the case states: the scheme, the
/// description read back out of the bytes (for CMS), and what the step
/// recorded in the transcript.
fn check_written(case: &WriteCase, form: &Form, session: &Session) -> Result<(), String> {
    let (bytes, recorded, scheme) = written(session);
    let expected = form.description();
    if scheme != form.scheme() {
        return Err(format!(
            "the step wrote {scheme}, and the case expects {}",
            form.scheme()
        ));
    }
    match form {
        Form::Cms { .. } => {
            let facts = cms::describe(&bytes)
                .map_err(|e| format!("the written container does not describe: {e}"))?;
            let described = facts.description;
            if described != expected {
                return Err(format!(
                    "the bytes hold\n  {described:?}\nand the case expects\n  {expected:?}"
                ));
            }
            check_recipient_identifier(case, session, facts.recipient_key_identifier.as_ref())?;
        }
        // Nothing in a raw blob to read back: what the step recorded is all
        // there is, and it has to be the scheme's.
        Form::Raw(_) => {}
    }
    if recorded != expected {
        return Err(format!(
            "the artifact carries\n  {recorded:?}\nand the case expects\n  {expected:?}"
        ));
    }
    ran_via(session, case.step.name(), Via::Backend)?;
    if let Path::Held(source) = case.path {
        check_source(session, "key", source, case.key)?;
    }
    check_fact(
        case.step,
        session,
        scheme,
        &expected,
        &compute_fingerprint(&bytes),
    )?;
    check_identities(case, session)
}

/// The container names its recipient the way a third party computes it: a
/// public key by the SHA-256 of its SPKI file (RFC 7093, method 1), a
/// symmetric key by its check value. The command line opening the container
/// tries every recipient with the key it holds, so without this a wrong
/// identifier would pass, and a holder of many keys could not find theirs.
fn check_recipient_identifier(
    case: &WriteCase,
    session: &Session,
    identifier: Option<&cms::RecipientIdentifier>,
) -> Result<(), String> {
    let expected = if let Some(spki) = opener_public(case, session) {
        base16ct::lower::encode_string(&openssl::sha::sha256(&spki))
    } else {
        base16ct::lower::encode_string(check_value_of(session, "key").as_bytes())
    };
    let found = identifier.map(|id| base16ct::lower::encode_string(id.as_bytes()));
    if found.as_deref() == Some(expected.as_str()) {
        Ok(())
    } else {
        Err(format!(
            "the container names its recipient by {found:?}, and a third party computes {expected}"
        ))
    }
}

/// The record names the keys a write involved: the key that was wrapped, or
/// how much content was encrypted; the symmetric key it was encrypted under;
/// and, for a public key, the recipient in a fact of its own. The expected
/// fingerprints come from the SPKI files, not from Rite.
fn check_identities(case: &WriteCase, session: &Session) -> Result<(), String> {
    let inputs = operation(session, case.step.name())?.0;
    let mut expected: Vec<(&str, serde_json::Value)> = Vec::new();
    match case.step {
        WriteStep::WrapKey => {
            let payload = case.payload.key();
            if payload.is_symmetric() {
                expected.push((
                    "key_to_wrap_check_value",
                    json!(check_value_of(session, "payload").to_string()),
                ));
            } else {
                let public = payload
                    .public()
                    .expect("an asymmetric payload has a public half");
                expected.push((
                    "key_to_wrap_fingerprint",
                    json!(compute_fingerprint(&public)),
                ));
            }
        }
        WriteStep::EncryptData => {
            expected.push(("content_bytes", json!(case.payload.key().private().len())));
            if let Path::Held(_) = case.path {
                expected.push((
                    "encryption_key_check_value",
                    json!(check_value_of(session, "key").to_string()),
                ));
            }
        }
    }
    check_fields("inputs", inputs, &expected)?;

    let recipients: Vec<(String, String, bool)> = session
        .facts()
        .iter()
        .filter_map(|fact| match fact {
            StepFact::WrapRecipientRecorded {
                source,
                fingerprint,
                declared,
                ..
            } => Some((source.clone(), fingerprint.to_string(), *declared)),
            _ => None,
        })
        .collect();
    let expected = match case.path {
        Path::Held(_) => Vec::new(),
        Path::Recipient(_) => {
            let public = case.key.public().expect("a recipient has a public half");
            vec![("key".to_string(), compute_fingerprint(&public), false)]
        }
    };
    if recipients == expected {
        Ok(())
    } else {
        Err(format!(
            "the recipient facts (source, fingerprint, declared) should be {expected:?}, and the \
             record holds {recipients:?}"
        ))
    }
}

/// The step's operation fact, which is what the transcript keeps: the scheme
/// it names, the description it records, and the fingerprint of the artifact.
fn check_fact(
    step: WriteStep,
    session: &Session,
    scheme: WrapScheme,
    expected: &WrapDescription,
    fingerprint: &str,
) -> Result<(), String> {
    let (field, fingerprint_field) = match step {
        WriteStep::WrapKey => ("wrap", "wrapped_key_fingerprint"),
        WriteStep::EncryptData => ("encryption", "encrypted_data_fingerprint"),
    };
    let (inputs, outputs, recorded) = operation(session, step.name())?;
    check_fields("inputs", inputs, &[("scheme", json!(scheme.to_string()))])?;
    check_fields(
        "outputs",
        outputs,
        &[
            (
                field,
                serde_json::to_value(expected).expect("a description serializes"),
            ),
            (fingerprint_field, json!(fingerprint)),
        ],
    )?;
    check_fingerprint(recorded.as_deref(), Some(fingerprint))
}

/// Rite opens what it wrote, with the step that reads it.
fn read_back(case: &WriteCase) -> Result<(), String> {
    let mut session = written_session(case)?;
    let opener = match case.path {
        Path::Held(_) => "key",
        Path::Recipient(_) => {
            session
                .import(case.key, "opener", false)
                .map_err(|(at, e)| format!("the recipient's private key fails at {at:?}: {e}"))?;
            "opener"
        }
    };
    let step = case.step.reader();
    run_open(&mut session, step, "written", opener, case.payload)
        .map_err(|(at, e)| format!("Rite does not open what it wrote, refused at {at:?}: {e}"))?;
    let public = opener_public(case, &session);
    check_opened(&session, step, "written", (opener, public), case.payload)
}

/// The SPKI the opener of a write case is named by: the committed file, or
/// for a generated keypair what the backend made.
fn opener_public(case: &WriteCase, session: &Session) -> Option<Vec<u8>> {
    match case.path {
        Path::Held(source) => held_spki(session, "key", source, case.key),
        Path::Recipient(_) => case.key.public(),
    }
}

/// Run `step` over `input` under the key held as `key`, leaving what it
/// recovers as `opened`.
fn run_open(
    session: &mut Session,
    step: ReadStep,
    input: &str,
    key: &str,
    payload: Payload,
) -> Result<(), Refused> {
    match step {
        ReadStep::UnwrapKey => {
            // A symmetric key travels with nothing saying what it is, so the
            // receiving step declares it.
            let params = if payload.key().is_symmetric() {
                json!({ "algorithm": payload.key().algorithm_name() })
            } else {
                json!({})
            };
            session.run(
                &UnwrapKeyAction,
                "opened",
                &[("unwrapping_key", key), ("wrapped_data", input)],
                &params,
            )
        }
        ReadStep::DecryptData => session.run(
            &DecryptDataAction,
            "opened",
            &[("encrypted_data", input), ("decryption_key", key)],
            &json!({}),
        ),
    }
}

/// A read step that opened `input` recovered the payload and recorded what
/// it did. `key` is the artifact that opened it, with the SPKI of the
/// keypair it holds, `None` for a symmetric key.
fn check_opened(
    session: &Session,
    step: ReadStep,
    input: &str,
    (key, opener): (&str, Option<Vec<u8>>),
    payload: Payload,
) -> Result<(), String> {
    let (bytes, scheme) = opened_input(session, input);
    match step {
        ReadStep::UnwrapKey => same_key(session.artifact("opened"), payload)
            .and_then(|()| check_unwrapped(session, &bytes, scheme, payload)),
        ReadStep::DecryptData => {
            let ArtifactValue::Secret(content) = session.artifact("opened") else {
                return Err("decrypt_data produced something other than a secret".to_string());
            };
            if content.expose_secret().as_slice() != payload.key().private().as_slice() {
                return Err("decrypt_data recovered other bytes than were sealed".to_string());
            }
            check_decrypted(session, &bytes, scheme, (key, opener), payload)
        }
    }
}

/// The bytes a read step opens, and the scheme it must record: the artifact's
/// own for one a step of the run wrote, CMS for a container from a file.
fn opened_input(session: &Session, input: &str) -> (Vec<u8>, WrapScheme) {
    match session.artifact(input) {
        ArtifactValue::WrappedKey(wrapped) => (wrapped.data().to_vec(), wrapped.scheme()),
        ArtifactValue::EncryptedData(encrypted) => (encrypted.data().to_vec(), encrypted.scheme()),
        ArtifactValue::Bytes(bytes) => (bytes.clone(), WrapScheme::CmsAes256Gcm),
        other => panic!("a read step opens {other:?}"),
    }
}

/// `unwrap_key` recorded the container it opened by its fingerprint, and the
/// key it recovered by its type and its public half or check value. The
/// expected values come from the payload's files, not from Rite.
///
/// The record names the unwrapping key by its artifact only, so there is no
/// identity of it to check; `decrypt_data` records one.
fn check_unwrapped(
    session: &Session,
    bytes: &[u8],
    scheme: WrapScheme,
    payload: Payload,
) -> Result<(), String> {
    ran_via(session, "unwrap_key", Via::Backend)?;
    let (inputs, outputs, fingerprint) = operation(session, "unwrap_key")?;
    check_fields(
        "inputs",
        inputs,
        &[
            ("scheme", json!(scheme.to_string())),
            (
                "wrapped_data_fingerprint",
                json!(compute_fingerprint(bytes)),
            ),
        ],
    )?;
    let key = payload.key();
    let (public, check_value) = match key.public() {
        Some(spki) => (Some(compute_fingerprint(&spki)), None),
        None => (None, Some(reference_check_value(key).to_string())),
    };
    check_fields(
        "outputs",
        outputs,
        &[
            ("unwrapped_key_algorithm", json!(key.algorithm_name())),
            ("unwrapped_key_fingerprint", json!(public)),
            ("unwrapped_key_check_value", json!(check_value)),
        ],
    )?;
    check_fingerprint(fingerprint.as_deref(), public.as_deref())
}

/// `decrypt_data` recorded the container by its fingerprint, the key that
/// opened it by its public half or check value, and how much it recovered.
fn check_decrypted(
    session: &Session,
    bytes: &[u8],
    scheme: WrapScheme,
    (key, opener): (&str, Option<Vec<u8>>),
    payload: Payload,
) -> Result<(), String> {
    ran_via(session, "decrypt_data", Via::Backend)?;
    let (inputs, outputs, fingerprint) = operation(session, "decrypt_data")?;
    let container = compute_fingerprint(bytes);
    let named_by = match opener {
        Some(spki) => (
            "decryption_key_fingerprint",
            json!(compute_fingerprint(&spki)),
        ),
        None => (
            "decryption_key_check_value",
            json!(check_value_of(session, key).to_string()),
        ),
    };
    check_fields(
        "inputs",
        inputs,
        &[
            ("scheme", json!(scheme.to_string())),
            ("encrypted_data_fingerprint", json!(container)),
            named_by,
        ],
    )?;
    check_fields(
        "outputs",
        outputs,
        &[("content_bytes", json!(payload.key().private().len()))],
    )?;
    check_fingerprint(fingerprint.as_deref(), Some(&container))
}

/// Whether an unwrapped key is the payload.
fn same_key(opened: &ArtifactValue, payload: Payload) -> Result<(), String> {
    is_committed(opened, payload.key())?
        .then_some(())
        .ok_or_else(|| "unwrap_key recovered a different key than was wrapped".to_string())
}

// ── The independent reader ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Reader {
    /// `openssl cms -decrypt`.
    Cms,
    /// `openssl pkeyutl -decrypt` under OAEP with SHA-256.
    RsaOaep,
}

/// Who besides Rite reads a form.
///
/// The raw schemes without one here are checked elsewhere: RSA-AES-KEY-WRAP
/// is reassembled from the command line in `rite-openssl`'s interop tests,
/// and AES-KW and AES-KWP run the RFC 3394 and RFC 5649 vectors in its unit
/// tests. `openssl enc` runs no key-wrap mode.
fn independent_reader(form: &Form) -> Option<Reader> {
    match form {
        Form::Cms { .. } => Some(Reader::Cms),
        Form::Raw(WrapScheme::RsaOaepSha256) => Some(Reader::RsaOaep),
        Form::Raw(_) => None,
    }
}

fn openssl_opens(case: &WriteCase, reader: Reader) -> Result<(), String> {
    let cli = Cli::get().expect("skipped unless the command line is present");
    let session = written_session(case)?;
    let (bytes, _) = opened_input(&session, "written");

    let dir = tempfile::tempdir().expect("a temporary directory");
    let blob = dir.path().join("written.der");
    std::fs::write(&blob, &bytes).expect("the blob is written");
    let key = case.key.private_path();

    let opened = match (reader, case.key.is_symmetric()) {
        (Reader::Cms, true) => {
            let secret = base16ct::lower::encode_string(&case.key.private());
            cli.run(&[
                "cms",
                "-decrypt",
                "-binary",
                "-inform",
                "DER",
                "-in",
                arg(&blob),
                "-secretkey",
                &secret,
            ])?
        }
        (Reader::Cms, false) => cli.run(&[
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-in",
            arg(&blob),
            "-inkey",
            arg(&key),
            "-keyform",
            "DER",
        ])?,
        (Reader::RsaOaep, _) => cli.run(&[
            "pkeyutl",
            "-decrypt",
            "-in",
            arg(&blob),
            "-inkey",
            arg(&key),
            "-keyform",
            "DER",
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha256",
            "-pkeyopt",
            "rsa_mgf1_md:sha256",
        ])?,
    };
    if opened == case.payload.key().private() {
        Ok(())
    } else {
        Err("the command line recovered other bytes than were sealed".to_string())
    }
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

pub fn fixture_path(fixture: &Fixture) -> std::path::PathBuf {
    FAMILY.dir().join(format!("{}.der", fixture.name))
}

fn fixture_trial(fixture: &'static Fixture, step: ReadStep, policy: Policy) -> Trial {
    let name = policy.name(format!("{}::{}", step.name(), fixture.name));
    let expected = *fixture.expect(step).under(policy);
    trial(name, build_lacks(fixture.opened_with), move || {
        check_holds(fixture)?;
        let mut session = Session::new();
        let attempt = session
            .import(fixture.opened_with, "key", false)
            .and_then(|()| {
                session.add(
                    "container",
                    ArtifactValue::Bytes(read(&fixture_path(fixture))),
                );
                run_open(&mut session, step, "container", "key", Payload::P256)
            });
        match expected {
            Read::Opens => judge(None, attempt).and_then(|()| {
                let opener = ("key", fixture.opened_with.public());
                check_opened(&session, step, "container", opener, Payload::P256)
            }),
            Read::Fails(why, refusal) => {
                check_refused(step.name(), &session, (why, refusal), attempt)
            }
        }
    })
}

/// The fixture's bytes carry the identifiers its row says and none it rules
/// out, found by searching for each one's DER encoding.
fn check_holds(fixture: &Fixture) -> Result<(), String> {
    let bytes = read(&fixture_path(fixture));
    let contains = |oid: &str| {
        let encoded = ObjectIdentifier::new(oid)
            .expect("the cases name valid OIDs")
            .to_der()
            .expect("an OID encodes");
        bytes
            .windows(encoded.len())
            .any(|w| w == encoded.as_slice())
    };
    let missing: Vec<&str> = fixture
        .holds
        .iter()
        .copied()
        .filter(|oid| !contains(oid))
        .collect();
    let present: Vec<&str> = fixture
        .lacks
        .iter()
        .copied()
        .filter(|oid| contains(oid))
        .collect();
    if missing.is_empty() && present.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{} does not hold the form its row claims: missing {missing:?}, present though ruled out \
         {present:?}. Regenerate it, or correct the row.",
        fixture.name
    ))
}
