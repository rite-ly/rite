//! The signature family: `sign_data` writing, `verify_signature` reading.
//!
//! A sign case becomes up to three tests: the signature itself, Rite
//! verifying it (`::verify_back`), and the `openssl` command line verifying
//! it (`::openssl_verifies`). A sign case's key is imported or generated, as
//! its row says. A fixture, a signature the command line made, becomes one
//! `verify_signature` test, which verifies it both in software and through
//! the backend: naming a backend changes who checks, never what is accepted.

mod cases;
mod coverage;
mod model;
mod regenerate;

use std::collections::BTreeSet;

use libtest_mimic::Trial;
use rite_runtime::{ArtifactValue, compute_fingerprint};
use rite_stdlib::{SignDataAction, VerifySignatureAction};
use serde_json::json;

use crate::cli::{Cli, arg};
use crate::family::{Family, file_name};
use crate::harness::{
    build_lacks, check_fields, check_fingerprint, check_refused, check_source, cli_lacks,
    held_spki, judge, operation, ran_via, trial,
};
use crate::keys::read;
use crate::outcome::Policy;
use crate::session::{Refused, Session, Source, Via};
use crate::shape::Shape;
use cases::{FIXTURES, KEY_SHAPES, SIGNS};
use model::{Encoding, Scheme, Sign, SignCase, SignatureFixture, Verify};

/// What every signature in the family is over.
pub const MESSAGE: &[u8] = b"The Rite algorithm matrix signs this message.\n";

pub const FAMILY: Family = Family {
    fixtures: "signatures",
    trials,
    fixture_files,
    regenerate: regenerate::signatures,
};

fn trials() -> Vec<Trial> {
    let mut trials = Vec::new();
    for policy in Policy::ALL.iter().copied() {
        for case in SIGNS {
            trials.extend(sign_trials(case, policy));
        }
        for fixture in FIXTURES {
            trials.push(fixture_trial(
                fixture,
                Shape::SpkiDer,
                *fixture.expect.under(policy),
                policy,
            ));
        }
        for case in KEY_SHAPES {
            let fixture = FIXTURES
                .iter()
                .find(|f| f.name == case.fixture)
                .unwrap_or_else(|| panic!("no fixture {}", case.fixture));
            trials.push(fixture_trial(
                fixture,
                case.shape,
                *case.expect.under(policy),
                policy,
            ));
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

pub fn fixture_path(fixture: &SignatureFixture) -> std::path::PathBuf {
    FAMILY.dir().join(format!("{}.sig", fixture.name))
}

// ── sign_data ────────────────────────────────────────────────────────────────

fn sign_trials(case: &'static SignCase, policy: Policy) -> Vec<Trial> {
    let name = policy.name(case.name());
    let skip = build_lacks(case.key);
    let expected = *case.expect.under(policy);
    let mut trials = vec![trial(name.clone(), skip.clone(), move || {
        let mut session = Session::new();
        let attempt = attempt_sign(case, &mut session);
        match (expected, attempt) {
            (Sign::Signs(algorithm, scheme), Ok(())) => {
                check_signed(case, algorithm, &scheme, &session)
            }
            (Sign::Signs(..), Err(refused)) => judge(None, Err(refused)),
            (Sign::Fails(why, refusal), attempt) => {
                check_refused("sign_data", &session, (why, refusal), attempt)
            }
        }
    })];

    let Sign::Signs(algorithm, scheme) = expected else {
        return trials;
    };
    trials.push(trial(
        format!("{name}::verify_back"),
        skip.clone(),
        move || verify_back(case, algorithm),
    ));
    let skip = skip.or_else(|| cli_lacks(case.key));
    trials.push(trial(
        format!("{name}::openssl_verifies"),
        skip,
        move || openssl_verifies(case, &scheme),
    ));
    trials
}

/// Hold the case's key, imported or generated, as a key of its type is held
/// to sign, and run `sign_data` over [`MESSAGE`].
fn attempt_sign(case: &SignCase, session: &mut Session) -> Result<(), Refused> {
    // A key that cannot sign is held for what it can do, so its refusal is
    // the signing step's, not a policy that forbids it to sign.
    let usages: &[&str] = if case.key.is_signing() {
        &["sign", "verify"]
    } else {
        case.key.usages()
    };
    session.hold(case.source, case.key, "key", usages)?;
    session.add("message", ArtifactValue::Bytes(MESSAGE.to_vec()));
    session.run(
        &SignDataAction,
        "signature",
        &[("key", "key"), ("data", "message")],
        &algorithm_param(case.algorithm),
    )
}

/// The SPKI of the key that signed.
fn public_key(case: &SignCase, session: &Session) -> Vec<u8> {
    held_spki(session, "key", case.source, case.key).expect("a signing key has a public half")
}

fn algorithm_param(algorithm: Option<&str>) -> serde_json::Value {
    algorithm.map_or_else(|| json!({}), |algorithm| json!({ "algorithm": algorithm }))
}

fn signed_session(case: &SignCase) -> Result<Session, String> {
    let mut session = Session::new();
    attempt_sign(case, &mut session)
        .map_err(|(at, e)| format!("the signature failed at {at:?}: {e}"))?;
    Ok(session)
}

fn signature(session: &Session) -> Vec<u8> {
    match session.artifact("signature") {
        ArtifactValue::Signature(bytes) => bytes.clone(),
        other => panic!("sign_data produced {other:?}"),
    }
}

/// The signature has the scheme's shape, and the record names the algorithm,
/// the key's type, the length and the signature's fingerprint.
fn check_signed(
    case: &SignCase,
    algorithm: &str,
    scheme: &Scheme,
    session: &Session,
) -> Result<(), String> {
    let bytes = signature(session);
    check_encoding(&bytes, scheme.encoding)?;
    check_source(session, "key", case.source, case.key)?;
    let kind = match case.source {
        Source::Imported => "import_key",
        Source::Generated => "generate_key",
    };
    operation(session, kind)?;
    ran_via(session, "sign_data", Via::Backend)?;
    let (inputs, outputs, fingerprint) = operation(session, "sign_data")?;
    check_fields(
        "inputs",
        inputs,
        &[
            ("algorithm", json!(algorithm)),
            ("key_algorithm", json!(case.key.algorithm_name())),
        ],
    )?;
    check_fields("outputs", outputs, &[("signature_len", json!(bytes.len()))])?;
    check_fingerprint(fingerprint.as_deref(), Some(&compute_fingerprint(&bytes)))
}

/// Rite verifies what it signed, under the same `algorithm:`, with the key
/// it holds, in software as the showcase ceremony does.
fn verify_back(case: &SignCase, algorithm: &str) -> Result<(), String> {
    let mut session = signed_session(case)?;
    run_verify(&mut session, Via::Software, case.algorithm).map_err(|(at, e)| {
        format!("Rite does not verify what it signed, refused at {at:?}: {e}")
    })?;
    check_verified(
        &session,
        Via::Software,
        algorithm,
        &public_key(case, &session),
        &signature(&session),
    )
}

/// Run `verify_signature` over `message` and `signature` under `key`.
fn run_verify(session: &mut Session, via: Via, algorithm: Option<&str>) -> Result<(), Refused> {
    session.run_via(
        via,
        &VerifySignatureAction,
        "verified",
        &[
            ("key", "key"),
            ("data", "message"),
            ("signature", "signature"),
        ],
        &algorithm_param(algorithm),
    )
}

/// The record names the algorithm, the key by the fingerprint of its SPKI
/// file, and the signature by its own.
fn check_verified(
    session: &Session,
    via: Via,
    algorithm: &str,
    public: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    ran_via(session, "verify_signature", via)?;
    let (inputs, outputs, _) = operation(session, "verify_signature")?;
    check_fields("inputs", inputs, &[("algorithm", json!(algorithm))])?;
    check_fields(
        "outputs",
        outputs,
        &[
            ("verified", json!(true)),
            ("public_key_fingerprint", json!(compute_fingerprint(public))),
            (
                "signature_fingerprint",
                json!(compute_fingerprint(signature)),
            ),
        ],
    )
}

fn openssl_verifies(case: &SignCase, scheme: &Scheme) -> Result<(), String> {
    let cli = Cli::get().expect("skipped unless the command line is present");
    let session = signed_session(case)?;
    let dir = tempfile::tempdir().expect("a temporary directory");
    let message = dir.path().join("message");
    let signature_file = dir.path().join("signature");
    std::fs::write(&message, MESSAGE).expect("the message is written");
    std::fs::write(&signature_file, signature(&session)).expect("the signature is written");
    let public = dir.path().join("public.der");
    std::fs::write(&public, public_key(case, &session)).expect("the public key is written");
    let mut command = vec![
        "pkeyutl",
        "-verify",
        "-pubin",
        "-inkey",
        arg(&public),
        "-keyform",
        "DER",
        "-rawin",
        "-in",
        arg(&message),
        "-sigfile",
        arg(&signature_file),
    ];
    command.extend(pkeyutl_options(scheme));
    cli.run(&command)
        .map(|_| ())
        .map_err(|e| format!("the command line does not verify what Rite signed: {e}"))
}

/// The `-digest` and `-pkeyopt` arguments a scheme states.
pub fn pkeyutl_options(scheme: &Scheme) -> Vec<&'static str> {
    let mut options = Vec::new();
    if let Some(digest) = scheme.digest {
        options.extend(["-digest", digest]);
    }
    for option in scheme.pkeyopts {
        options.extend(["-pkeyopt", option]);
    }
    options
}

// ── verify_signature over fixtures ───────────────────────────────────────────

/// `verify_signature` over a fixture, with the signer's key in `shape`.
fn fixture_trial(
    fixture: &'static SignatureFixture,
    shape: Shape,
    expected: Verify,
    policy: Policy,
) -> Trial {
    let mut name = format!("verify_signature::{}", fixture.name);
    if shape != Shape::SpkiDer {
        name = format!("{name}::as::{}", shape.name());
    }
    let name = policy.name(name);
    trial(name, build_lacks(fixture.key), move || {
        let bytes = read(&fixture_path(fixture));
        check_encoding(&bytes, fixture.scheme.encoding).map_err(|e| {
            format!(
                "{} is not the signature its row claims: {e}. Regenerate it, or correct the row.",
                fixture.name
            )
        })?;
        let public = fixture
            .key
            .public()
            .expect("a signature fixture is made with a keypair");
        for via in [Via::Software, Via::Backend] {
            let mut session = Session::new();
            // As a signature from elsewhere arrives: the signer's public key,
            // beside the message and the signature.
            session
                .present(shape, fixture.key, "key", &["sign", "verify"])
                .map_err(|(at, e)| format!("the key in {} fails at {at:?}: {e}", shape.name()))?;
            session.add("message", ArtifactValue::Bytes(MESSAGE.to_vec()));
            session.add("signature", ArtifactValue::Bytes(bytes.clone()));
            let attempt = run_verify(&mut session, via, fixture.algorithm);
            match expected {
                Verify::Verifies(algorithm) => judge(None, attempt)
                    .and_then(|()| check_verified(&session, via, algorithm, &public, &bytes)),
                Verify::Fails(why, refusal) => {
                    check_refused("verify_signature", &session, (why, refusal), attempt)
                }
            }
            .map_err(|e| format!("verified {}: {e}", via.name()))?;
        }
        Ok(())
    })
}

// ── Encodings ────────────────────────────────────────────────────────────────

/// The signature has the shape its scheme states: a length, or a DER
/// `SEQUENCE` of two integers no longer than the curve's scalar.
fn check_encoding(bytes: &[u8], encoding: Encoding) -> Result<(), String> {
    match encoding {
        Encoding::Bytes(length) if bytes.len() == length => Ok(()),
        Encoding::Bytes(length) => Err(format!(
            "{} bytes, and the scheme makes {length}",
            bytes.len()
        )),
        Encoding::P1363 { scalar } => {
            let expected = scalar.checked_mul(2).expect("a small scalar");
            if bytes.len() == expected {
                Ok(())
            } else {
                Err(format!(
                    "{} bytes, and r || s on this curve is {expected}",
                    bytes.len()
                ))
            }
        }
        Encoding::Der { scalar } => ecdsa_der(bytes, scalar),
    }
}

/// An `Ecdsa-Sig-Value`: a `SEQUENCE` holding exactly two positive
/// `INTEGER`s in minimal form, each at most `scalar` bytes of value.
fn ecdsa_der(bytes: &[u8], scalar: usize) -> Result<(), String> {
    let (body, rest) = der_element(bytes, 0x30)?;
    if !rest.is_empty() {
        return Err(format!("{} bytes after the SEQUENCE", rest.len()));
    }
    let (r, body) = der_element(body, 0x02)?;
    let (s, body) = der_element(body, 0x02)?;
    if !body.is_empty() {
        return Err("more than two INTEGERs in the SEQUENCE".to_string());
    }
    for (name, value) in [("r", r), ("s", s)] {
        let magnitude = match value {
            [] => return Err(format!("{name} is empty")),
            [first, ..] if first & 0x80 != 0 => return Err(format!("{name} is negative")),
            [0, next, ..] if next & 0x80 == 0 => {
                return Err(format!("{name} is not in minimal form"));
            }
            // A leading zero only keeps a high bit from reading as a sign.
            [0, magnitude @ ..] | magnitude => magnitude,
        };
        if magnitude.len() > scalar {
            return Err(format!(
                "{name} is {} bytes, longer than the {scalar}-byte scalar",
                magnitude.len()
            ));
        }
    }
    Ok(())
}

/// One DER element with `tag`: its contents, and what follows it.
fn der_element(bytes: &[u8], tag: u8) -> Result<(&[u8], &[u8]), String> {
    let [found, first, rest @ ..] = bytes else {
        return Err("truncated DER".to_string());
    };
    if *found != tag {
        return Err(format!("tag {found:#04x}, expected {tag:#04x}"));
    }
    let (length, rest) = match *first {
        short @ 0..=0x7f => (usize::from(short), rest),
        0x81 => match rest {
            [length @ 0x80..=0xff, rest @ ..] => (usize::from(*length), rest),
            _ => return Err("a long-form length that fits the short form".to_string()),
        },
        other => {
            return Err(format!(
                "length form {other:#04x}, too long for a signature"
            ));
        }
    };
    if rest.len() < length {
        return Err("truncated DER".to_string());
    }
    Ok(rest.split_at(length))
}
