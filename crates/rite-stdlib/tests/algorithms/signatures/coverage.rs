//! What keeps the signature table complete: every key has a `sign_data` row
//! and a signature from elsewhere, every algorithm Rite names is signed, and
//! every signature Rite makes is also verified from one it did not make.

use libtest_mimic::Trial;
use rite_sdk::SignAlgorithm;

use super::cases::{FIXTURES, KEY_SHAPES, SIGNS};
use super::model::{Sign, Verify};
use crate::harness::{coverage_trials, report};
use crate::keys::TestKey;
use crate::session::Source;
use crate::shape::Shape;

pub fn trials() -> Vec<Trial> {
    coverage_trials!(
        "coverage::signatures",
        every_shape_is_a_verification_key,
        every_key_is_a_sign_data_case,
        every_signing_key_is_verified_from_elsewhere,
        every_rite_algorithm_is_signed,
        every_signature_rite_makes_is_verified_from_elsewhere,
    )
}

fn keys() -> impl Iterator<Item = TestKey> {
    TestKey::ALL.iter().copied().filter(|key| !key.is_payload())
}

/// Every key has a row under its default algorithm, whether it signs or is
/// refused, so `sign_data`'s answer for each key is written down: imported,
/// for every key, and generated, for every signing type. A compressed key is
/// an encoding of an imported one, which nothing generates.
fn every_key_is_a_sign_data_case() -> Result<(), String> {
    let mut missing = Vec::new();
    for key in keys() {
        let mut sources = vec![Source::Imported];
        if key.is_signing() && !key.is_compressed() {
            sources.push(Source::Generated);
        }
        for source in sources {
            let covered = SIGNS
                .iter()
                .any(|c| c.source == source && c.key == key && c.algorithm.is_none());
            if !covered {
                missing.push(format!("sign_data::{}::{}", source.name(), key.stem()));
            }
        }
    }
    report("cases missing", &missing)
}

/// Every key of a signing type has a signature made elsewhere, so what
/// `verify_signature` does with it is written down, supported or not.
fn every_signing_key_is_verified_from_elsewhere() -> Result<(), String> {
    let missing: Vec<String> = keys()
        .filter(|key| key.is_signing() && !FIXTURES.iter().any(|f| f.key == *key))
        .map(|key| key.stem().to_string())
        .collect();
    report("no signature fixture for", &missing)
}

/// Every algorithm Rite names signs in some row.
fn every_rite_algorithm_is_signed() -> Result<(), String> {
    let missing: Vec<String> = SignAlgorithm::ALL
        .iter()
        .filter(|algorithm| {
            !SIGNS.iter().any(
                |c| matches!(c.expect.default, Sign::Signs(name, _) if name == algorithm.as_str()),
            )
        })
        .map(ToString::to_string)
        .collect();
    report("no row signs with", &missing)
}

/// Every key and algorithm Rite signs with is also verified from a signature
/// the command line made with that key. A round trip alone would pass a
/// scheme that Rite signs and verifies the same wrong way.
fn every_signature_rite_makes_is_verified_from_elsewhere() -> Result<(), String> {
    let missing: Vec<String> = SIGNS
        .iter()
        .filter_map(|c| match c.expect.default {
            Sign::Signs(algorithm, _) => Some((c.key, algorithm)),
            Sign::Fails(..) => None,
        })
        .filter(|(key, algorithm)| {
            !FIXTURES.iter().any(|f| {
                f.key == *key && matches!(f.expect.default, Verify::Verifies(a) if a == *algorithm)
            })
        })
        .map(|(key, algorithm)| format!("{} under {algorithm}", key.stem()))
        .collect();
    report("signed, and never verified from elsewhere", &missing)
}

/// Every form a signer's key arrives in is a row of `verify_signature`, the
/// SPKI DER file in the fixture rows and the others in the shape table.
fn every_shape_is_a_verification_key() -> Result<(), String> {
    let missing: Vec<String> = Shape::ALL
        .iter()
        .copied()
        .filter(|shape| *shape != Shape::SpkiDer && !KEY_SHAPES.iter().any(|c| c.shape == *shape))
        .map(|shape| shape.name().to_string())
        .collect();
    report("verification key shapes missing", &missing)
}
