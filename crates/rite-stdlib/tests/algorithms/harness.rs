//! What turns a row into a test, for every family: skips, judging an attempt
//! against its row, and reading the operation a step recorded.

use libtest_mimic::{Failed, Trial};
use rite_model::StepFact;
use rite_runtime::ArtifactValue;
use rite_sdk::KeyCheckValue;

use crate::cli::Cli;
use crate::keys::TestKey;
use crate::outcome::{Refusal, Why};
use crate::session::{BACKEND, Refused, Session, Source, Via};

/// Why a test does not run here.
#[derive(Debug, Clone)]
pub enum Skip {
    /// The build cannot do what the case needs: the linked OpenSSL lacks the
    /// algorithm.
    Build(String),
    /// The `openssl` command line is missing or too old to check the output.
    Cli(String),
}

/// Set in a CI job whose build is meant to run every case, so a build skip
/// there fails instead of passing quietly as ignored.
const REQUIRE_BUILD: &str = "RITE_MATRIX_REQUIRE_BUILD";

/// A test, skipped with the reason as its label. Asked for with `--ignored`,
/// a skipped test fails with that reason: it cannot run, so it cannot pass.
pub fn trial(
    name: String,
    skip: Option<Skip>,
    test: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Trial {
    match skip {
        None => Trial::test(name, move || test().map_err(Failed::from)),
        Some(Skip::Build(reason)) if std::env::var_os(REQUIRE_BUILD).is_some() => {
            Trial::test(name, move || {
                Err(Failed::from(format!(
                    "{reason}, and {REQUIRE_BUILD} is set"
                )))
            })
        }
        Some(Skip::Build(reason) | Skip::Cli(reason)) => {
            let label = reason.clone();
            Trial::test(name, move || Err(Failed::from(reason)))
                .with_ignored_flag(true)
                .with_kind(label)
        }
    }
}

/// Why a case cannot run against this build, if it cannot.
///
/// Only for a key Rite supports. For one it does not, Rite refuses it by name
/// before the linked library is asked anything, and that refusal is the case.
pub fn build_lacks(key: TestKey) -> Option<Skip> {
    let algorithm = key.rite()?;
    rite_openssl::build_limitation(algorithm)
        .map(|limitation| Skip::Build(format!("{algorithm} {limitation}")))
}

/// Why the command line cannot check a case under `key`, if it cannot: it
/// is missing, or older than the first release that can.
pub fn cli_lacks(key: TestKey) -> Option<Skip> {
    let Some(cli) = Cli::get() else {
        return Some(Skip::Cli("no openssl command line".to_string()));
    };
    let (major, minor) = match key {
        // CMS carries an ML-KEM recipient in a `KEMRecipientInfo`, from 3.6.
        TestKey::MlKem512 | TestKey::MlKem768 | TestKey::MlKem1024 => (3, 6),
        TestKey::MlDsa44 | TestKey::MlDsa65 | TestKey::MlDsa87 => (3, 5),
        _ => return None,
    };
    (!cli.at_least(major, minor)).then(|| {
        Skip::Cli(format!(
            "{} needs openssl {major}.{minor}, this is {}",
            key.algorithm_name(),
            cli.version()
        ))
    })
}

/// Compare an attempt with what the case expects of it: `None` for success,
/// or the refusal the row states.
pub fn judge(expected: Option<(Why, Refusal)>, attempt: Result<(), Refused>) -> Result<(), String> {
    match (expected, attempt) {
        (None, Ok(())) => Ok(()),
        (None, Err((at, error))) => Err(format!(
            "expected this to work; refused at {at:?}:\n  {error}"
        )),
        (Some((why, refusal)), Ok(())) => Err(format!(
            "expected {why:?} at {:?} (\"{}\"), and it worked. If Rite now does this, change the \
             case to say so.",
            refusal.at, refusal.says
        )),
        (Some((why, refusal)), Err((at, error))) => {
            if at != refusal.at {
                return Err(format!(
                    "expected {why:?} at {:?}, and it was refused at {at:?}:\n  {error}",
                    refusal.at
                ));
            }
            if !error.contains(refusal.says) {
                return Err(format!(
                    "expected {why:?} at {at:?} saying \"{}\", and the refusal says:\n  {error}",
                    refusal.says
                ));
            }
            Ok(())
        }
    }
}

/// The operation facts the session recorded under `kind`.
fn operations<'s>(session: &'s Session, kind: &str) -> impl Iterator<Item = &'s StepFact> {
    session.facts().iter().filter(move |fact| {
        matches!(fact, StepFact::BackendOperation { kind: recorded, .. } if recorded == kind)
    })
}

/// The one operation fact a step recorded under `kind`: its inputs, its
/// outputs and its fingerprint.
pub fn operation<'s>(
    session: &'s Session,
    kind: &str,
) -> Result<
    (
        &'s serde_json::Value,
        &'s serde_json::Value,
        &'s Option<String>,
    ),
    String,
> {
    let facts: Vec<_> = operations(session, kind)
        .filter_map(|fact| match fact {
            StepFact::BackendOperation {
                inputs,
                outputs,
                fingerprint,
                ..
            } => Some((inputs, outputs, fingerprint)),
            _ => None,
        })
        .collect();
    match facts.as_slice() {
        [one] => Ok(*one),
        _ => Err(format!(
            "{kind} recorded {} operation facts, not one",
            facts.len()
        )),
    }
}

/// The operation of `kind` ran where `via` says: on the backend the step
/// names, or in software, which the record says by naming none.
pub fn ran_via(session: &Session, kind: &str, via: Via) -> Result<(), String> {
    let recorded: Vec<Option<&str>> = operations(session, kind)
        .filter_map(|fact| match fact {
            StepFact::BackendOperation { backend, .. } => Some(backend.as_deref()),
            _ => None,
        })
        .collect();
    let expected = match via {
        Via::Backend => Some(BACKEND),
        Via::Software => None,
    };
    if recorded == [expected] {
        Ok(())
    } else {
        Err(format!(
            "{kind} should have run {}, and the record names {recorded:?}",
            via.name()
        ))
    }
}

/// The key held as `id` came from where the row says: an imported key is
/// the committed one, and a generated key is not.
pub fn check_source(
    session: &Session,
    id: &str,
    source: Source,
    key: TestKey,
) -> Result<(), String> {
    match (source, is_committed(session.artifact(id), key)?) {
        (Source::Imported, true) | (Source::Generated, false) => Ok(()),
        (Source::Imported, false) => Err(format!("the imported `{id}` is not the committed key")),
        (Source::Generated, true) => Err(format!("the generated `{id}` is the committed key")),
    }
}

/// Whether `held` is `key`'s committed key: the same public half or, for a
/// symmetric key, the same check value.
pub fn is_committed(held: &ArtifactValue, key: TestKey) -> Result<bool, String> {
    let ArtifactValue::BackendKey {
        public_key,
        check_value,
        ..
    } = held
    else {
        return Err(format!("{held:?} is not a key the backend holds"));
    };
    Ok(match key.public() {
        Some(spki) => {
            public_key.as_ref().map(rite_sdk::PublicKeyDer::as_bytes) == Some(spki.as_slice())
        }
        None => check_value.as_ref() == Some(&reference_check_value(key)),
    })
}

/// The SPKI of the key held as `id`, `None` for a symmetric key: the committed
/// file for an imported key, which no part of Rite produced, or what Rite
/// exported for a generated one.
pub fn held_spki(session: &Session, id: &str, source: Source, key: TestKey) -> Option<Vec<u8>> {
    match (source, session.artifact(id)) {
        (Source::Imported, _) => key.public(),
        (Source::Generated, ArtifactValue::BackendKey { public_key, .. }) => {
            public_key.as_ref().map(|public| public.as_bytes().to_vec())
        }
        (Source::Generated, other) => panic!("generate_key produced {other:?}"),
    }
}

/// The check value of a symmetric key in the session. The record writes it
/// as its string.
pub fn check_value_of(session: &Session, id: &str) -> KeyCheckValue {
    let ArtifactValue::BackendKey {
        check_value: Some(check_value),
        ..
    } = session.artifact(id)
    else {
        panic!("`{id}` is a symmetric key with a check value")
    };
    check_value.clone()
}

/// The check value Rite gives the committed `key`, from a session of its own.
pub fn reference_check_value(key: TestKey) -> KeyCheckValue {
    let mut reference = Session::new();
    reference
        .import(key, "reference", false)
        .expect("the committed key imports");
    check_value_of(&reference, "reference")
}

/// A row's refusal: the attempt was refused where and as the row states, and
/// the step recorded no operation of its `kind`.
pub fn check_refused(
    kind: &str,
    session: &Session,
    stated: (Why, Refusal),
    attempt: Result<(), Refused>,
) -> Result<(), String> {
    judge(Some(stated), attempt)?;
    if operations(session, kind).next().is_some() {
        Err(format!(
            "the step was refused, and the record holds a {kind} operation"
        ))
    } else {
        Ok(())
    }
}

/// The fingerprint an operation fact carries.
pub fn check_fingerprint(recorded: Option<&str>, expected: Option<&str>) -> Result<(), String> {
    if recorded == expected {
        Ok(())
    } else {
        Err(format!(
            "the transcript records the fingerprint {recorded:?}, not {expected:?}"
        ))
    }
}

/// Compare recorded fields with the values a row expects, naming the first
/// that differs.
pub fn check_fields(
    what: &str,
    recorded: &serde_json::Value,
    expected: &[(&str, serde_json::Value)],
) -> Result<(), String> {
    for (field, value) in expected {
        if recorded.get(field) != Some(value) {
            return Err(format!(
                "the transcript records {what}.{field} as {:?}, not {value}",
                recorded.get(field)
            ));
        }
    }
    Ok(())
}

/// The tests for a list of coverage checks: each function in the list, named
/// after it under `prefix`, reporting what it found.
macro_rules! coverage_trials {
    ($prefix:literal, $($check:ident),+ $(,)?) => {
        vec![$(
            libtest_mimic::Trial::test(concat!($prefix, "::", stringify!($check)), || {
                $check().map_err(libtest_mimic::Failed::from)
            })
        ),+]
    };
}
pub(crate) use coverage_trials;

/// A check's findings: nothing, or what it found, one per line.
pub fn report(what: &str, items: &[String]) -> Result<(), String> {
    if items.is_empty() {
        Ok(())
    } else {
        Err(format!("{what}:\n  {}", items.join("\n  ")))
    }
}
