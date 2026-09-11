//! Offline checks over the wrap steps a transcript records.
//!
//! Two things are checkable from a run directory alone, with no key, no
//! network, and no second transcript:
//!
//! - the wrapped artifact on disk against the algorithms the transcript says
//!   were used, including the recipient the blob names;
//! - the key a wrap consumed against the key this same ceremony generated.
//!
//! Everything else a wrap depends on is outside the reach of the bundle: that
//! the recipient can open the result, and that the recipient is who the
//! ceremony thought. A wrap that cannot be checked is reported as unchecked
//! rather than counted as evidence.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rite_model::StepFact;
use rite_sdk::{WrapDescription, WrapScheme};

use crate::verify::{artifact_location, digest_hex};

/// What was concluded about one wrap step.
#[derive(Debug)]
pub struct WrapCheck {
    /// Step that performed the wrap.
    pub step: String,
    /// Outcome of the checks that could run.
    pub status: WrapStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WrapStatus {
    /// The checks that could run, ran.
    Checked {
        /// Whether the recorded algorithms were re-derived or only asserted.
        algorithms: AlgorithmEvidence,
        /// What, if anything, corroborates the recipient the blob names.
        recipient: RecipientEvidence,
        /// The key wrapped is one this ceremony generated.
        origin_confirmed: bool,
    },
    /// The artifact contradicts the record.
    Mismatch {
        /// What disagrees.
        detail: String,
    },
    /// Nothing was checked, and why.
    Unchecked {
        /// What was missing.
        reason: String,
    },
}

/// Where the algorithms in the record came from.
///
/// A separate axis from [`RecipientEvidence`], which grades who vouched for
/// the recipient. This one grades whether anything outside the transcript can
/// confirm the algorithms at all.
#[derive(Debug, PartialEq, Eq)]
pub enum AlgorithmEvidence {
    /// Re-derived from the artifact and equal to what the transcript records.
    Derived,
    /// The scheme's output describes nothing about itself, so the recorded
    /// algorithms are what the backend reports having invoked.
    ///
    /// Not the same claim as [`WrapStatus::Unchecked`]: there is nothing of
    /// this kind to check, by construction, rather than a check that could not
    /// run, and the two must not print alike.
    AsInvoked(WrapScheme),
}

/// What the bundle can say about the key a wrap was addressed to.
///
/// The blob names its recipient by a digest of that recipient's public key, so
/// the question is what else in the transcript carries the same value.
#[derive(Debug, PartialEq, Eq)]
pub enum RecipientEvidence {
    /// The ceremony declared this recipient in advance and the run checked
    /// the key it was given against that. The strongest of the four: someone
    /// committed to the value before the ceremony.
    Declared,
    /// The run recorded the recipient it was given, and the blob names the
    /// same key. Says the record is faithful, not that anyone vouched for the
    /// key: nothing was committed to in advance.
    Recorded,
    /// The recipient is a key this ceremony generated, so the wrap can be
    /// undone here. Says nothing about anyone's intent, only about custody.
    GeneratedHere,
    /// Nothing in the transcript corroborates the recipient.
    None,
}

impl WrapCheck {
    /// One line for the verifier's output.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.status {
            WrapStatus::Checked {
                algorithms,
                recipient,
                origin_confirmed,
            } => {
                let (verdict, first) = match algorithms {
                    AlgorithmEvidence::Derived => {
                        ("ok", "artifact matches the recorded algorithms".to_string())
                    }
                    AlgorithmEvidence::AsInvoked(scheme) => (
                        "recorded",
                        format!(
                            "{scheme} output carries no algorithm identifiers, so the \
                             recorded algorithms are as invoked, not re-derived"
                        ),
                    ),
                };
                let mut notes = vec![first];
                match recipient {
                    RecipientEvidence::Declared => {
                        notes.push("names the declared recipient".to_string());
                    }
                    RecipientEvidence::Recorded => {
                        notes.push("names the recorded recipient".to_string());
                    }
                    RecipientEvidence::GeneratedHere => {
                        notes.push("addressed to a key generated in this ceremony".to_string());
                    }
                    RecipientEvidence::None => {}
                }
                if *origin_confirmed {
                    notes.push("wrapped a key generated in this ceremony".to_string());
                }
                format!("{}: {verdict} ({})", self.step, notes.join(", "))
            }
            WrapStatus::Mismatch { detail } => format!("{}: MISMATCH: {detail}", self.step),
            WrapStatus::Unchecked { reason } => format!("{}: unchecked ({reason})", self.step),
        }
    }

    /// Whether this check failed verification.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self.status, WrapStatus::Mismatch { .. })
    }
}

/// Check every wrap the transcript records.
///
/// Without a run directory there is no artifact to read, so every wrap is
/// reported unchecked.
#[must_use]
pub fn check_wraps(dir: Option<&Path>, facts: &[&StepFact]) -> Vec<WrapCheck> {
    let index = Index::of(facts);
    facts
        .iter()
        .filter_map(|fact| match fact {
            StepFact::BackendOperation {
                step,
                kind,
                inputs,
                outputs,
                ..
            } if kind == "wrap_key" => Some(WrapCheck {
                step: step.as_str().to_string(),
                status: check_one(dir, &index, inputs, outputs),
            }),
            _ => None,
        })
        .collect()
}

/// What a wrap check needs to look up, gathered in one pass over the facts.
///
/// Each wrap otherwise re-walks the whole transcript several times, once per
/// question it asks of it.
struct Index<'a> {
    /// Public keys this ceremony generated, by fingerprint.
    generated: HashSet<&'a str>,
    /// Recipient a wrap was given, by the input name that named it, with
    /// whether the ceremony declared it in advance.
    recipients: HashMap<&'a str, (&'a str, bool)>,
    /// Artifact file names by the digest recorded for their contents.
    artifacts: HashMap<&'a str, &'a std::ffi::OsStr>,
}

impl<'a> Index<'a> {
    fn of(facts: &[&'a StepFact]) -> Self {
        let mut index = Index {
            generated: HashSet::new(),
            recipients: HashMap::new(),
            artifacts: HashMap::new(),
        };
        for fact in facts {
            match fact {
                StepFact::BackendOperation { kind, outputs, .. } if kind == "generate_keypair" => {
                    if let Some(fingerprint) = string_field(outputs, "public_key_fingerprint") {
                        index.generated.insert(fingerprint);
                    }
                }
                StepFact::WrapRecipientRecorded {
                    source,
                    fingerprint,
                    declared,
                    ..
                } => {
                    index
                        .recipients
                        .entry(source.as_str())
                        .or_insert((fingerprint.as_str(), *declared));
                }
                StepFact::ArtifactWritten { path, sha256, .. } => {
                    if let Some(file_name) = path.file_name() {
                        index
                            .artifacts
                            .entry(digest_hex(sha256))
                            .or_insert(file_name);
                    }
                }
                _ => {}
            }
        }
        index
    }

    /// The bytes of the artifact whose recorded digest is `fingerprint`.
    ///
    /// The transcript is untrusted input, so the recorded path is never
    /// followed: [`artifact_location`] confines it to the run directory.
    fn artifact_bytes(&self, dir: &Path, fingerprint: &str) -> Option<Vec<u8>> {
        let file_name = self.artifacts.get(digest_hex(fingerprint))?;
        std::fs::read(dir.join(artifact_location(file_name))).ok()
    }
}

fn check_one(
    dir: Option<&Path>,
    index: &Index<'_>,
    inputs: &serde_json::Value,
    outputs: &serde_json::Value,
) -> WrapStatus {
    let Some(blob_fingerprint) = string_field(outputs, "wrapped_key_fingerprint") else {
        return unchecked("the wrap fact records no artifact fingerprint");
    };
    let Some(scheme) = recorded_scheme(inputs) else {
        return unchecked("the wrap fact records no scheme");
    };

    let origin_confirmed = string_field(inputs, "key_to_wrap_fingerprint")
        .is_some_and(|target| index.generated.contains(target));

    // A raw mechanism is not a failed CMS parse, and must not report as one.
    // The scheme in the record is what says which this is, so a verifier needs
    // no marker beyond the name it already has. Checked before the description
    // is parsed, which on this path would be parsed only to be discarded.
    if !scheme.is_self_describing() {
        return WrapStatus::Checked {
            algorithms: AlgorithmEvidence::AsInvoked(scheme),
            // The recipient facts are transcript against transcript and never
            // touch the blob, so they hold here exactly as they do for CMS.
            // Only `GeneratedHere`, which reads the blob's own identifier, is
            // out of reach.
            recipient: declared_recipient(index, inputs),
            origin_confirmed,
        };
    }

    let Some(recorded) = outputs.get("wrap") else {
        return unchecked("the wrap fact records no description of the wrap");
    };
    let recorded: WrapDescription = match serde_json::from_value(recorded.clone()) {
        Ok(description) => description,
        Err(e) => return unchecked(format!("the recorded wrap description is unreadable: {e}")),
    };

    let Some(dir) = dir else {
        return unchecked("no run directory, so the artifact could not be read");
    };
    let Some(bytes) = index.artifact_bytes(dir, blob_fingerprint) else {
        return unchecked("the wrapped artifact is not in this run directory");
    };

    let from_blob = match rite_sdk::cms::describe(&bytes) {
        Ok(facts) => facts,
        Err(e) => return unchecked(format!("the artifact could not be read as CMS: {e}")),
    };

    // One comparison of the whole description, so a field added to it is
    // checked here without this function learning its name.
    if from_blob.description != recorded {
        return WrapStatus::Mismatch {
            detail: format!(
                "the transcript records {}, the artifact says {}",
                algorithms(&recorded),
                algorithms(&from_blob.description)
            ),
        };
    }

    // The recipient identifier in the blob is a digest of the recipient's
    // public key, which is the form both the recipient fact and a
    // generate_keypair fact record, so they compare without holding any key.
    let recipient = match from_blob.recipient_key_identifier.as_deref() {
        None => RecipientEvidence::None,
        Some(identifier) => {
            let named = format!("sha256:{}", base16ct::lower::encode_string(identifier));
            let source = string_field(inputs, "wrapping_key");
            match source.and_then(|source| index.recipients.get(source)) {
                Some(&(recorded, declared)) if recorded == named => {
                    if declared {
                        RecipientEvidence::Declared
                    } else {
                        RecipientEvidence::Recorded
                    }
                }
                Some(&(recorded, _)) => {
                    return WrapStatus::Mismatch {
                        detail: format!(
                            "the transcript records recipient {recorded}, \
                             the artifact names {named}"
                        ),
                    };
                }
                // No recipient fact: the wrap went to a key the backend holds,
                // and the transcript names that key only where it was
                // generated.
                None if index.generated.contains(named.as_str()) => {
                    RecipientEvidence::GeneratedHere
                }
                None => RecipientEvidence::None,
            }
        }
    };

    WrapStatus::Checked {
        algorithms: AlgorithmEvidence::Derived,
        recipient,
        origin_confirmed,
    }
}

/// What the transcript alone says about the recipient of a wrap.
///
/// Used where the blob names no recipient, either because the scheme carries
/// no identifier or because it was not read. `Declared` and `Recorded` come
/// from comparing two facts, so they need no artifact; `GeneratedHere` does,
/// and is absent here for that reason.
fn declared_recipient(index: &Index<'_>, inputs: &serde_json::Value) -> RecipientEvidence {
    match string_field(inputs, "wrapping_key").and_then(|source| index.recipients.get(source)) {
        Some(&(_, true)) => RecipientEvidence::Declared,
        Some(&(_, false)) => RecipientEvidence::Recorded,
        None => RecipientEvidence::None,
    }
}

/// The scheme the wrap fact names.
///
/// An unreadable or unknown name is not a scheme this build can reason about,
/// so it is reported as unchecked rather than assumed to be self-describing.
fn recorded_scheme(inputs: &serde_json::Value) -> Option<WrapScheme> {
    string_field(inputs, "scheme")?.parse().ok()
}

/// A description as one line, for a mismatch a reader has to act on.
///
/// Serialized rather than listed field by field, so a field added to the
/// description appears here without this module learning its name.
fn algorithms(description: &WrapDescription) -> String {
    serde_json::to_string(description).unwrap_or_else(|_| "an unreadable description".to_string())
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn unchecked(reason: impl Into<String>) -> WrapStatus {
    WrapStatus::Unchecked {
        reason: reason.into(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use rite_model::StepId;
    use rite_sdk::{
        KeyAlgorithm, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, WrapScheme,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::LazyLock;

    /// A real CMS wrap, plus the facts a run would have recorded for it.
    struct Wrap {
        blob: Vec<u8>,
        target_fingerprint: String,
        recipient_fingerprint: String,
        outputs: serde_json::Value,
    }

    /// Built once: every test reads the same wrap and varies only the facts
    /// derived from it, and three RSA keygens per test is the slowest thing
    /// in this file by two orders of magnitude.
    static WRAP: LazyLock<Wrap> = LazyLock::new(make_wrap);

    fn make_wrap() -> Wrap {
        let mut backend = rite_openssl::OpenSslBackend::try_new("test").unwrap();
        let spec = |label: &str, policy: KeyPolicy| KeySpec {
            algorithm: KeyAlgorithm::Rsa2048,
            label: label.to_string(),
            policy,
            location_hint: None,
        };
        let kek = backend
            .generate_key(spec(
                "kek",
                KeyPolicy {
                    usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
                    ..KeyPolicy::default()
                },
            ))
            .unwrap();
        let target = backend
            .generate_key(spec(
                "target",
                KeyPolicy {
                    extractable: true,
                    ..KeyPolicy::default()
                },
            ))
            .unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let description = wrapped.description();

        let fingerprint =
            |key: &rite_sdk::PublicKeyDer| rite_runtime::compute_fingerprint(key.as_bytes());
        Wrap {
            target_fingerprint: fingerprint(&backend.export_public_key(&target.key_id).unwrap()),
            recipient_fingerprint: fingerprint(&backend.export_public_key(&kek.key_id).unwrap()),
            outputs: json!({
                "wrapped_key_fingerprint": rite_runtime::compute_fingerprint(wrapped.data()),
                "wrap": description,
            }),
            blob: wrapped.data().to_vec(),
        }
    }

    fn borrow(facts: &[StepFact]) -> Vec<&StepFact> {
        facts.iter().collect()
    }

    /// Write the blob into a run directory and build the transcript around it.
    fn transcript(dir: &Path, wrap: &Wrap, outputs: serde_json::Value) -> Vec<StepFact> {
        std::fs::create_dir_all(dir.join("artifacts")).unwrap();
        std::fs::write(dir.join("artifacts/wrapped.p7c"), &wrap.blob).unwrap();
        vec![
            StepFact::BackendOperation {
                step: StepId::new("gen"),
                kind: "generate_keypair".to_string(),
                inputs: json!({}),
                outputs: json!({ "public_key_fingerprint": wrap.target_fingerprint }),
                fingerprint: None,
            },
            StepFact::WrapRecipientRecorded {
                step: StepId::new("wrap"),
                source: "kek".to_string(),
                fingerprint: wrap.recipient_fingerprint.clone(),
                declared: true,
            },
            StepFact::BackendOperation {
                step: StepId::new("wrap"),
                kind: "wrap_key".to_string(),
                inputs: json!({
                    "scheme": "CMS-AES-256-GCM",
                    "key_to_wrap_fingerprint": wrap.target_fingerprint,
                    "wrapping_key": "kek",
                }),
                outputs,
                fingerprint: None,
            },
            StepFact::ArtifactWritten {
                step: StepId::new("wrap"),
                name: "wrapped".to_string(),
                path: PathBuf::from("/somewhere/else/artifacts/wrapped.p7c"),
                sha256: rite_runtime::compute_fingerprint(&wrap.blob),
            },
        ]
    }

    #[test]
    fn a_wrap_whose_artifact_agrees_with_the_record_is_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let facts = transcript(tmp.path(), wrap, wrap.outputs.clone());

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            WrapStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::Declared,
                origin_confirmed: true,
            },
            "{}",
            check.describe()
        );
    }

    /// A wrap under a key the backend holds emits no recipient fact, since no
    /// party outside the ceremony is involved. The blob still names the key it
    /// went to, and the ceremony generated that key, so the two meet.
    /// A recipient the run merely recorded is weaker evidence than one the
    /// ceremony committed to in advance, and the output says which it was.
    #[test]
    fn an_undeclared_recipient_is_reported_as_recorded_only() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        for fact in &mut facts {
            if let StepFact::WrapRecipientRecorded { declared, .. } = fact {
                *declared = false;
            }
        }

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            WrapStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::Recorded,
                origin_confirmed: true,
            },
            "{}",
            check.describe()
        );
    }

    #[test]
    fn a_wrap_to_a_ceremony_key_is_traced_through_the_generate_step() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        facts.retain(|fact| !matches!(fact, StepFact::WrapRecipientRecorded { .. }));
        facts.push(StepFact::BackendOperation {
            step: StepId::new("gen_kek"),
            kind: "generate_keypair".to_string(),
            inputs: json!({}),
            outputs: json!({ "public_key_fingerprint": wrap.recipient_fingerprint }),
            fingerprint: None,
        });

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            WrapStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::GeneratedHere,
                origin_confirmed: true,
            },
            "{}",
            check.describe()
        );
    }

    /// With neither a recipient fact nor a matching generate step, the
    /// recipient is simply unaccounted for. That is reported as nothing, not
    /// as a failure: a wrap to a key from outside is a normal ceremony.
    #[test]
    fn a_recipient_nothing_corroborates_is_left_unclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        facts.retain(|fact| !matches!(fact, StepFact::WrapRecipientRecorded { .. }));

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            WrapStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::None,
                origin_confirmed: true,
            },
            "{}",
            check.describe()
        );
        assert!(!check.failed());
    }

    /// A raw mechanism must not report as a failed CMS parse: that is the same
    /// status a corrupted CMS blob gets, and it would train a reader to skim
    /// past the word that matters.
    #[test]
    fn a_raw_mechanism_is_reported_as_recorded_not_as_unchecked() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        for fact in &mut facts {
            if let StepFact::BackendOperation { kind, inputs, .. } = fact
                && kind == "wrap_key"
            {
                inputs
                    .as_object_mut()
                    .expect("inputs is a JSON object")
                    .insert("scheme".to_string(), json!("RSA-AES-KEY-WRAP-SHA256"));
            }
        }

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            WrapStatus::Checked {
                algorithms: AlgorithmEvidence::AsInvoked(WrapScheme::RsaAesKeyWrapSha256),
                // The recipient was declared in advance, and that evidence
                // comes from two transcript facts rather than from the blob,
                // so a raw mechanism does not cost it.
                recipient: RecipientEvidence::Declared,
                origin_confirmed: true,
            },
            "{}",
            check.describe()
        );
        assert!(!check.failed());

        let line = check.describe();
        assert!(line.contains("as invoked, not re-derived"), "{line}");
        assert!(line.contains("names the declared recipient"), "{line}");
        assert!(
            !line.contains("could not be read as CMS"),
            "a raw wrap is not a broken CMS blob: {line}"
        );
    }

    #[test]
    fn a_record_that_overstates_the_algorithms_is_a_mismatch() {
        // The transcript claims RSA-OAEP key transport, the blob says
        // PKCS#1 v1.5. A verifier reading only the transcript would take the
        // stronger claim at face value.
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut outputs = wrap.outputs.clone();
        outputs
            .get_mut("wrap")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the wrap description is a JSON object")
            .insert(
                "key_encryption_oid".to_string(),
                json!(rite_sdk::oid::RSAES_OAEP),
            );
        let facts = transcript(tmp.path(), wrap, outputs);

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        assert!(
            checks.first().expect("one check").failed(),
            "{:?}",
            checks.first().map(WrapCheck::describe)
        );
    }

    #[test]
    fn a_record_naming_the_wrong_recipient_is_a_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let mut facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        for fact in &mut facts {
            if let StepFact::WrapRecipientRecorded { fingerprint, .. } = fact {
                *fingerprint = "sha256:00".to_string();
            }
        }

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        assert!(checks.first().expect("one check").failed());
    }

    #[test]
    fn a_wrap_without_its_artifact_is_unchecked_not_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        std::fs::remove_file(tmp.path().join("artifacts/wrapped.p7c")).unwrap();

        let checks = check_wraps(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert!(matches!(check.status, WrapStatus::Unchecked { .. }));
        assert!(
            !check.failed(),
            "an absent artifact proves nothing either way"
        );
    }

    #[test]
    fn a_transcript_alone_checks_no_wrap() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let facts = transcript(tmp.path(), wrap, wrap.outputs.clone());

        let checks = check_wraps(None, &borrow(&facts));
        assert!(matches!(
            checks.first().expect("one check").status,
            WrapStatus::Unchecked { .. }
        ));
    }
}
