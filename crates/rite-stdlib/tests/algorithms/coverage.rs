//! What keeps the matrix as a whole complete: the keys against Rite's
//! algorithms, the files on disk against the tables, and the test names.
//! Each family checks its own table in its own `coverage.rs`.

use std::collections::BTreeSet;

use libtest_mimic::{Failed, Trial};
use rite_sdk::KeyAlgorithm;

use crate::FAMILIES;
use crate::harness::{coverage_trials, report};
use crate::keys::{TestKey, keys_dir};
use crate::shape::{CERTIFIED, certificate_path, certificates_dir};

/// The shared checks, and one that every test in `all` has its own name.
pub fn trials(all: &[Trial]) -> Vec<Trial> {
    let mut trials = coverage_trials!(
        "coverage",
        every_rite_algorithm_has_a_test_key,
        test_keys_name_their_algorithm_as_rite_does,
        fixture_files_are_the_ones_the_tables_name,
    );

    // Two rows that make the same name would run as two tests a filter
    // cannot tell apart, and one could hide the other in a report.
    let mut seen = BTreeSet::new();
    let repeated: Vec<String> = all
        .iter()
        .map(|t| t.name().to_string())
        .filter(|name| !seen.insert(name.clone()))
        .collect();
    trials.push(Trial::test("coverage::test_names_are_unique", move || {
        report("repeated", &repeated).map_err(Failed::from)
    }));
    trials
}

/// An algorithm Rite gains needs a key here before anything can test it.
fn every_rite_algorithm_has_a_test_key() -> Result<(), String> {
    let missing: Vec<String> = KeyAlgorithm::ALL
        .iter()
        .filter(|algorithm| {
            !TestKey::ALL
                .iter()
                .any(|key| key.rite() == Some(**algorithm))
        })
        .map(ToString::to_string)
        .collect();
    report("no TestKey for", &missing)
}

/// A supported key is named as Rite names it, and an unsupported one by a
/// name Rite does not know. The second half is what tells you Rite started
/// to support an algorithm: give the key its `KeyAlgorithm`, and its cases
/// fail until they say what now happens.
fn test_keys_name_their_algorithm_as_rite_does() -> Result<(), String> {
    let mut wrong = Vec::new();
    for key in TestKey::ALL.iter().copied() {
        let parsed = key.algorithm_name().parse::<KeyAlgorithm>().ok();
        if parsed != key.rite() {
            wrong.push(format!(
                "{}: named {:?}, which Rite reads as {parsed:?}, and TestKey::rite says {:?}",
                key.stem(),
                key.algorithm_name(),
                key.rite()
            ));
        }
    }
    report("keys out of step with Rite", &wrong)
}

/// The files on disk and the tables agree, both ways: the keys, and each
/// family's fixtures.
fn fixture_files_are_the_ones_the_tables_name() -> Result<(), String> {
    let mut problems = Vec::new();

    let mut keys = BTreeSet::new();
    for key in TestKey::ALL.iter().copied() {
        keys.insert(file_name(&key.private_path()));
        if !key.is_symmetric() {
            keys.insert(file_name(&key.public_path()));
        }
    }
    compare(&keys_dir(), &keys, &mut problems);

    let certificates: BTreeSet<String> = CERTIFIED
        .iter()
        .map(|key| file_name(&certificate_path(*key)))
        .collect();
    compare(&certificates_dir(), &certificates, &mut problems);

    for family in FAMILIES {
        compare(&family.dir(), &(family.fixture_files)(), &mut problems);
    }
    report("fixtures out of step", &problems)
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .expect("fixture paths have a UTF-8 file name")
        .to_string()
}

/// The files in `dir`, other than `MADE_WITH`, against `expected`.
fn compare(dir: &std::path::Path, expected: &BTreeSet<String>, problems: &mut Vec<String>) {
    let present: BTreeSet<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{} cannot be listed: {e}", dir.display()))
        .map(|entry| file_name(&entry.expect("a directory entry").path()))
        .filter(|name| name != "MADE_WITH")
        .collect();
    for name in expected.difference(&present) {
        problems.push(format!("{} is missing from {}", name, dir.display()));
    }
    for name in present.difference(expected) {
        problems.push(format!(
            "{} in {} is named by no table",
            name,
            dir.display()
        ));
    }
}
