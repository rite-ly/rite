//! Offline checks over the containers a transcript records.
//!
//! `wrap_key` and `encrypt_data` produce the same container around different
//! content, so they are checked the same way and reported together.
//!
//! Two things are checkable from a run directory alone, with no key, no
//! network, and no second transcript:
//!
//! - the artifact on disk against the algorithms the transcript says were used,
//!   including the recipient the blob names;
//! - the key a wrap consumed against the key this same ceremony generated.
//!
//! Everything else a container depends on is outside the reach of the bundle:
//! that the recipient can open it, and that the recipient is who the ceremony
//! thought. A container that cannot be checked is reported as unchecked rather
//! than counted as evidence.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use rite_model::StepFact;
use rite_sdk::{KeyCheckValue, RecipientInfoKind, WrapDescription, WrapScheme};

use crate::verify::digest_hex;
use rite_model::bundle::artifact_path;

/// What was concluded about one wrap step.
#[derive(Debug)]
pub struct ContainerCheck {
    /// Step that performed the wrap.
    pub step: String,
    /// Outcome of the checks that could run.
    pub status: ContainerStatus,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ContainerStatus {
    /// The checks that could run, ran.
    Checked {
        /// Whether the recorded algorithms were re-derived or only asserted.
        algorithms: AlgorithmEvidence,
        /// What, if anything, corroborates the recipient the blob names.
        recipient: RecipientEvidence,
        /// Where the key that was wrapped came from, where the transcript
        /// says so at all.
        origin: OriginEvidence,
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
    /// Not the same claim as [`ContainerStatus::Unchecked`]: there is nothing of
    /// this kind to check, by construction, rather than a check that could not
    /// run, and the two must not print alike.
    AsInvoked(WrapScheme),
}

/// What the bundle can say about the key a wrap was addressed to.
///
/// The blob names its recipient by whatever identifies that key, so
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
    /// The recipient is a key this ceremony imported, so the wrap can be
    /// undone here too, but the ceremony received that key rather than making
    /// it. Weaker than [`Self::GeneratedHere`] by exactly that much: where the
    /// material came from is outside the bundle.
    ImportedHere,
    /// Nothing in the transcript corroborates the recipient.
    None,
}

/// What the bundle can say about the key a wrap consumed.
///
/// The same distinction [`RecipientEvidence`] draws between a key the ceremony
/// made and one it was handed, on the payload side rather than the recipient
/// side.
#[derive(Debug, PartialEq, Eq)]
pub enum OriginEvidence {
    /// The wrapped key was generated in this ceremony.
    GeneratedHere,
    /// The wrapped key was imported into this ceremony from material it held.
    ImportedHere,
    /// Nothing in the transcript names where the wrapped key came from.
    None,
}

impl ContainerCheck {
    /// One line for the verifier's output.
    #[must_use]
    pub fn describe(&self) -> String {
        match &self.status {
            ContainerStatus::Checked {
                algorithms,
                recipient,
                origin,
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
                    RecipientEvidence::ImportedHere => {
                        notes.push("addressed to a key imported into this ceremony".to_string());
                    }
                    RecipientEvidence::None => {}
                }
                match origin {
                    OriginEvidence::GeneratedHere => {
                        notes.push("wrapped a key generated in this ceremony".to_string());
                    }
                    OriginEvidence::ImportedHere => {
                        notes.push("wrapped a key imported into this ceremony".to_string());
                    }
                    OriginEvidence::None => {}
                }
                format!("{}: {verdict} ({})", self.step, notes.join(", "))
            }
            ContainerStatus::Mismatch { detail } => format!("{}: MISMATCH: {detail}", self.step),
            ContainerStatus::Unchecked { reason } => format!("{}: unchecked ({reason})", self.step),
        }
    }

    /// Whether this check failed verification.
    #[must_use]
    pub fn failed(&self) -> bool {
        matches!(self.status, ContainerStatus::Mismatch { .. })
    }
}

/// The two output fields this check reads, for a fact that produced a
/// container, and `None` for a fact that produced none.
///
/// The check is the same for both operations. What differs is only the names
/// the producing action wrote, and one table is what keeps the two from
/// drifting apart.
fn container_fields(kind: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        // A key left a backend under protection.
        "wrap_key" => Some(("wrapped_key_fingerprint", "wrap")),
        // Content was encrypted for a recipient, with no custody claim.
        "encrypt_data" => Some(("encrypted_data_fingerprint", "encryption")),
        _ => None,
    }
}

/// Check every container the transcript records.
///
/// Without a run directory there is no artifact to read, so every container is
/// reported unchecked.
#[must_use]
pub fn check_containers(dir: Option<&Path>, facts: &[&StepFact]) -> Vec<ContainerCheck> {
    let index = Index::of(facts);
    facts
        .iter()
        .filter_map(|fact| {
            let StepFact::BackendOperation {
                step,
                kind,
                inputs,
                outputs,
                ..
            } = fact
            else {
                return None;
            };
            let fields = container_fields(kind)?;
            Some(ContainerCheck {
                step: step.as_str().to_string(),
                status: check_one(dir, &index, fields, step.as_str(), inputs, outputs),
            })
        })
        .collect()
}

/// What a wrap check needs to look up, gathered in one pass over the facts.
///
/// Each wrap otherwise re-walks the whole transcript several times, once per
/// question it asks of it.
struct Index<'a> {
    /// Keys this ceremony generated, by whatever names them: a fingerprint
    /// for a keypair, a check value for a symmetric key.
    generated: HashSet<&'a str>,
    /// Keys this ceremony imported, named the same way. Kept apart from
    /// `generated` because the two support different claims: one says the
    /// ceremony made the key, the other only that it received it.
    imported: HashSet<&'a str>,
    /// Recipient a wrap was given, by the step that wrapped to it, with
    /// whether the ceremony declared it in advance.
    ///
    /// Keyed by step because both facts come from one step. Keying by the
    /// input name instead would let two steps reading the same input share an
    /// entry, and the first `declared` would then stand for both.
    recipients: HashMap<&'a str, (&'a str, bool)>,
    /// Artifact file names by the digest recorded for their contents.
    artifacts: HashMap<&'a str, &'a str>,
}

impl<'a> Index<'a> {
    fn of(facts: &[&'a StepFact]) -> Self {
        let mut index = Index {
            generated: HashSet::new(),
            imported: HashSet::new(),
            recipients: HashMap::new(),
            artifacts: HashMap::new(),
        };
        for fact in facts {
            match fact {
                StepFact::BackendOperation { kind, outputs, .. } if kind == "generate_key" => {
                    // A keypair is named by its public half and a symmetric
                    // key by its check value. Both go in one set, because both
                    // are what a blob's recipient identifier renders to.
                    if let Some(fingerprint) = string_field(outputs, "public_key_fingerprint") {
                        index.generated.insert(fingerprint);
                    }
                    if let Some(check_value) = string_field(outputs, "key_check_value") {
                        index.generated.insert(check_value);
                    }
                }
                StepFact::BackendOperation { kind, outputs, .. } if kind == "import_key" => {
                    if let Some(fingerprint) = string_field(outputs, "imported_key_fingerprint") {
                        index.imported.insert(fingerprint);
                    }
                    if let Some(check_value) = string_field(outputs, "imported_key_check_value") {
                        index.imported.insert(check_value);
                    }
                }
                StepFact::WrapRecipientRecorded {
                    step,
                    fingerprint,
                    declared,
                    ..
                } => {
                    index
                        .recipients
                        .entry(step.as_str())
                        .or_insert((fingerprint.as_str(), *declared));
                }
                StepFact::ArtifactWritten {
                    file,
                    digest: Some(digest),
                    ..
                } => {
                    index
                        .artifacts
                        .entry(digest_hex(digest.as_str()))
                        .or_insert(file.as_str());
                }
                _ => {}
            }
        }
        index
    }

    /// The bytes of the artifact whose recorded digest is `fingerprint`.
    ///
    /// The transcript is untrusted input, so the recorded path is never
    /// followed: [`artifact_path`] confines it to the run directory.
    fn artifact_bytes(&self, dir: &Path, fingerprint: &str) -> Option<Vec<u8>> {
        let file = self.artifacts.get(digest_hex(fingerprint))?;
        std::fs::read(dir.join(artifact_path(file)?)).ok()
    }
}

fn check_one(
    dir: Option<&Path>,
    index: &Index<'_>,
    (artifact_field, description_field): (&str, &str),
    step: &str,
    inputs: &serde_json::Value,
    outputs: &serde_json::Value,
) -> ContainerStatus {
    let Some(blob_fingerprint) = string_field(outputs, artifact_field) else {
        return unchecked("the fact records no artifact fingerprint");
    };
    let Some(scheme) = recorded_scheme(inputs) else {
        return unchecked("the fact records no scheme");
    };

    // Whichever form names the wrapped key. Both land in one set, so a
    // symmetric payload traces to its generate step the way a keypair does.
    let wrapped_key_names: Vec<&str> = ["key_to_wrap_fingerprint", "key_to_wrap_check_value"]
        .iter()
        .filter_map(|field| string_field(inputs, field))
        .collect();
    let origin = if wrapped_key_names
        .iter()
        .any(|target| index.generated.contains(target))
    {
        OriginEvidence::GeneratedHere
    } else if wrapped_key_names
        .iter()
        .any(|target| index.imported.contains(target))
    {
        OriginEvidence::ImportedHere
    } else {
        OriginEvidence::None
    };

    // A raw mechanism is not a failed CMS parse, and must not report as one.
    // The scheme in the record is what says which this is, so a verifier needs
    // no marker beyond the name it already has. Checked before the description
    // is parsed, which on this path would be parsed only to be discarded.
    if !scheme.is_self_describing() {
        return ContainerStatus::Checked {
            algorithms: AlgorithmEvidence::AsInvoked(scheme),
            // The recipient facts are transcript against transcript and never
            // touch the blob, so they hold here exactly as they do for CMS.
            // Only `GeneratedHere`, which reads the blob's own identifier, is
            // out of reach.
            recipient: declared_recipient(index, step),
            origin,
        };
    }

    let Some(recorded) = outputs.get(description_field) else {
        return unchecked("the fact records no description of what was done");
    };
    let recorded: WrapDescription = match serde_json::from_value(recorded.clone()) {
        Ok(description) => description,
        Err(e) => return unchecked(format!("the recorded description is unreadable: {e}")),
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
        return ContainerStatus::Mismatch {
            detail: format!(
                "the transcript records {}, the artifact says {}",
                algorithms(&recorded),
                algorithms(&from_blob.description)
            ),
        };
    }

    // The recipient identifier in the blob is what names the recipient key,
    // which is the form both the recipient fact and a generate_key fact
    // record, so they compare without holding any key.
    let recipient = match from_blob.recipient_key_identifier.as_deref() {
        None => RecipientEvidence::None,
        Some(identifier) => {
            let named = names_recipient(&from_blob.description, identifier);
            match index.recipients.get(step) {
                Some(&(recorded, declared)) if recorded == named => {
                    if declared {
                        RecipientEvidence::Declared
                    } else {
                        RecipientEvidence::Recorded
                    }
                }
                Some(&(recorded, _)) => {
                    return ContainerStatus::Mismatch {
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
                None if index.imported.contains(named.as_str()) => RecipientEvidence::ImportedHere,
                None => RecipientEvidence::None,
            }
        }
    };

    ContainerStatus::Checked {
        algorithms: AlgorithmEvidence::Derived,
        recipient,
        origin,
    }
}

/// Render a blob's recipient identifier the way the transcript names that key.
///
/// A public-key recipient is identified by a digest of its SPKI, which the
/// transcript writes as a `sha256:` fingerprint. A symmetric recipient has no
/// public half, so `KEKRecipientInfo` carries the key's check value instead,
/// which the transcript writes with its own method prefix. Rendering here is
/// what lets one comparison serve both.
fn names_recipient(description: &WrapDescription, identifier: &[u8]) -> String {
    let hex = base16ct::lower::encode_string(identifier);
    match description.recipient_info {
        Some(RecipientInfoKind::Kekri) => format!("{}:{hex}", KeyCheckValue::METHOD),
        _ => format!("sha256:{hex}"),
    }
}

/// What the transcript alone says about the recipient of a wrap.
///
/// Used where the blob names no recipient, either because the scheme carries
/// no identifier or because it was not read. `Declared` and `Recorded` come
/// from comparing two facts, so they need no artifact; `GeneratedHere` does,
/// and is absent here for that reason.
fn declared_recipient(index: &Index<'_>, step: &str) -> RecipientEvidence {
    match index.recipients.get(step) {
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

fn unchecked(reason: impl Into<String>) -> ContainerStatus {
    ContainerStatus::Unchecked {
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
                kind: "generate_key".to_string(),
                backend: None,
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
                backend: None,
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
                file: "wrapped.p7c".to_string(),
                digest: Some(rite_model::Sha256Digest::of(&wrap.blob)),
            },
        ]
    }

    /// A container `encrypt_data` produced, and the facts a run records for it.
    ///
    /// Built through the same backend path the action uses, so the check runs
    /// against real bytes rather than a description written by hand.
    struct Sealed {
        blob: Vec<u8>,
        kek_check_value: String,
        outputs: serde_json::Value,
    }

    static SEALED: LazyLock<Sealed> = LazyLock::new(make_sealed);

    fn make_sealed() -> Sealed {
        let mut backend = rite_openssl::OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Aes256,
                label: "kek".to_string(),
                policy: KeyPolicy {
                    usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
                    ..KeyPolicy::default()
                },
                location_hint: None,
            })
            .unwrap();
        let check_value = kek.check_value.as_ref().unwrap();

        let data_key = backend
            .generate_data_key(&kek.key_id, KeyAlgorithm::Aes256)
            .unwrap();
        let content = rite_openssl::seal_content(data_key.plaintext(), b"an archive").unwrap();
        let blob = rite_sdk::cms::write_kek_enveloped(&rite_sdk::cms::KekEnvelope {
            key_identifier: check_value.as_bytes().to_vec(),
            wrapped_cek: data_key.wrapped().to_vec(),
            nonce: content.nonce,
            ciphertext: content.ciphertext,
            tag: content.tag,
        })
        .unwrap();
        let description = rite_sdk::cms::describe(&blob).unwrap().description;

        Sealed {
            kek_check_value: check_value.to_string(),
            outputs: json!({
                "encrypted_data_fingerprint": rite_runtime::compute_fingerprint(&blob),
                "encryption": description,
            }),
            blob,
        }
    }

    /// An encrypt step is checked on the same terms a wrap gets: the artifact
    /// is re-read, and the key it is addressed to is traced to the step that
    /// made it. Nothing was wrapped, so the origin clause is absent.
    #[test]
    fn an_encrypt_is_checked_against_its_artifact_and_its_recipient() {
        let tmp = tempfile::tempdir().unwrap();
        let sealed = &*SEALED;
        std::fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        std::fs::write(tmp.path().join("artifacts/sealed.p7c"), &sealed.blob).unwrap();

        let facts = vec![
            StepFact::BackendOperation {
                step: StepId::new("gen_kek"),
                kind: "generate_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "key_check_value": sealed.kek_check_value }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("encrypt"),
                kind: "encrypt_data".to_string(),
                backend: None,
                inputs: json!({
                    "scheme": "CMS-AES-256-GCM",
                    "encryption_key": "kek",
                }),
                outputs: sealed.outputs.clone(),
                fingerprint: None,
            },
            StepFact::ArtifactWritten {
                step: StepId::new("encrypt"),
                name: "sealed".to_string(),
                file: "sealed.p7c".to_string(),
                digest: Some(rite_model::Sha256Digest::of(&sealed.blob)),
            },
        ];

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one container check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::GeneratedHere,
                origin: OriginEvidence::None,
            },
            "{}",
            check.describe()
        );
    }

    #[test]
    fn a_wrap_whose_artifact_agrees_with_the_record_is_checked() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let facts = transcript(tmp.path(), wrap, wrap.outputs.clone());

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::Declared,
                origin: OriginEvidence::GeneratedHere,
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

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::Recorded,
                origin: OriginEvidence::GeneratedHere,
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
            kind: "generate_key".to_string(),
            backend: None,
            inputs: json!({}),
            outputs: json!({ "public_key_fingerprint": wrap.recipient_fingerprint }),
            fingerprint: None,
        });

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::GeneratedHere,
                origin: OriginEvidence::GeneratedHere,
            },
            "{}",
            check.describe()
        );
    }

    /// A KEK the ceremony imported is still a KEK the ceremony can open the
    /// blob with, but it received that key rather than making it. The line
    /// says which, because leaving the clause out would report the weaker
    /// custody claim as no claim at all.
    #[test]
    fn a_wrap_to_an_imported_key_says_it_was_imported() {
        let mut backend = rite_openssl::OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .import_key(
                KeySpec {
                    algorithm: KeyAlgorithm::Aes256,
                    label: "kek".to_string(),
                    policy: KeyPolicy::default_for(KeyAlgorithm::Aes256),
                    location_hint: None,
                },
                &[7u8; 32],
                None,
            )
            .unwrap();
        let target = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Rsa2048,
                label: "target".to_string(),
                policy: KeyPolicy {
                    extractable: true,
                    ..KeyPolicy::default()
                },
                location_hint: None,
            })
            .unwrap();
        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();

        let target_fingerprint = rite_runtime::compute_fingerprint(
            backend
                .export_public_key(&target.key_id)
                .unwrap()
                .as_bytes(),
        );
        let check_value = kek.check_value.as_ref().unwrap().to_string();

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        std::fs::write(tmp.path().join("artifacts/wrapped.p7c"), wrapped.data()).unwrap();

        let facts = vec![
            StepFact::BackendOperation {
                step: StepId::new("gen_target"),
                kind: "generate_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "public_key_fingerprint": target_fingerprint }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("import_kek"),
                kind: "import_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "imported_key_check_value": check_value }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("wrap"),
                kind: "wrap_key".to_string(),
                backend: None,
                inputs: json!({
                    "scheme": "CMS-AES-256-GCM",
                    "key_to_wrap_fingerprint": target_fingerprint,
                    "wrapping_key": "kek",
                }),
                outputs: json!({
                    "wrapped_key_fingerprint": rite_runtime::compute_fingerprint(wrapped.data()),
                    "wrap": wrapped.description(),
                }),
                fingerprint: None,
            },
            StepFact::ArtifactWritten {
                step: StepId::new("wrap"),
                name: "wrapped".to_string(),
                file: "wrapped.p7c".to_string(),
                digest: Some(rite_model::Sha256Digest::of(wrapped.data())),
            },
        ];

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::ImportedHere,
                origin: OriginEvidence::GeneratedHere,
            },
            "{}",
            check.describe()
        );
        assert!(
            check
                .describe()
                .contains("addressed to a key imported into this ceremony"),
            "{}",
            check.describe()
        );
    }

    /// A wrap under a symmetric key carries the same evidence as one under a
    /// keypair, and links to its generate step the same way.
    ///
    /// The blob names the KEK by check value rather than by fingerprint, so
    /// the comparison only holds if the identifier is rendered the way the
    /// transcript writes that key. A `sha256:` prefix over a check value would
    /// match nothing and quietly report no recipient evidence at all.
    #[test]
    fn a_wrap_under_a_symmetric_key_traces_to_its_generate_step() {
        let mut backend = rite_openssl::OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Aes256,
                label: "kek".to_string(),
                policy: KeyPolicy::default_for(KeyAlgorithm::Aes256),
                location_hint: None,
            })
            .unwrap();
        let target = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Rsa2048,
                label: "target".to_string(),
                policy: KeyPolicy {
                    extractable: true,
                    ..KeyPolicy::default()
                },
                location_hint: None,
            })
            .unwrap();
        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();

        let target_fingerprint = rite_runtime::compute_fingerprint(
            backend
                .export_public_key(&target.key_id)
                .unwrap()
                .as_bytes(),
        );
        let check_value = kek.check_value.as_ref().unwrap().to_string();

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        std::fs::write(tmp.path().join("artifacts/wrapped.p7c"), wrapped.data()).unwrap();

        let facts = vec![
            StepFact::BackendOperation {
                step: StepId::new("gen_target"),
                kind: "generate_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "public_key_fingerprint": target_fingerprint }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("gen_kek"),
                kind: "generate_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "key_check_value": check_value }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("wrap"),
                kind: "wrap_key".to_string(),
                backend: None,
                inputs: json!({
                    "scheme": "CMS-AES-256-GCM",
                    "key_to_wrap_fingerprint": target_fingerprint,
                    "wrapping_key": "kek",
                }),
                outputs: json!({
                    "wrapped_key_fingerprint": rite_runtime::compute_fingerprint(wrapped.data()),
                    "wrap": wrapped.description(),
                }),
                fingerprint: None,
            },
            StepFact::ArtifactWritten {
                step: StepId::new("wrap"),
                name: "wrapped".to_string(),
                file: "wrapped.p7c".to_string(),
                digest: Some(rite_model::Sha256Digest::of(wrapped.data())),
            },
        ];

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::GeneratedHere,
                origin: OriginEvidence::GeneratedHere,
            },
            "{}",
            check.describe()
        );
    }

    /// A symmetric key as the payload rather than as the recipient, which is
    /// what carrying a KEK to a second backend produces.
    ///
    /// The wrapped key is named by a check value here, so the transcript
    /// records one instead of a fingerprint, and the origin claim has to read
    /// whichever the step wrote. Reading only the fingerprint would report a
    /// key this ceremony generated as one it did not.
    #[test]
    fn a_wrapped_symmetric_key_traces_to_its_generate_step() {
        let mut backend = rite_openssl::OpenSslBackend::try_new("test").unwrap();
        let transport = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Rsa2048,
                label: "transport".to_string(),
                policy: KeyPolicy {
                    usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
                    ..KeyPolicy::default()
                },
                location_hint: None,
            })
            .unwrap();
        let kek = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::Aes256,
                label: "kek".to_string(),
                policy: KeyPolicy {
                    extractable: true,
                    ..KeyPolicy::default_for(KeyAlgorithm::Aes256)
                },
                location_hint: None,
            })
            .unwrap();
        let wrapped = backend
            .wrap(&kek.key_id, &transport.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();

        let check_value = kek.check_value.as_ref().unwrap().to_string();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("artifacts")).unwrap();
        std::fs::write(tmp.path().join("artifacts/wrapped.p7c"), wrapped.data()).unwrap();

        let facts = vec![
            StepFact::BackendOperation {
                step: StepId::new("gen_kek"),
                kind: "generate_key".to_string(),
                backend: None,
                inputs: json!({}),
                outputs: json!({ "key_check_value": check_value }),
                fingerprint: None,
            },
            StepFact::BackendOperation {
                step: StepId::new("wrap"),
                kind: "wrap_key".to_string(),
                backend: None,
                inputs: json!({
                    "scheme": "CMS-AES-256-GCM",
                    "key_to_wrap_fingerprint": serde_json::Value::Null,
                    "key_to_wrap_check_value": check_value,
                    "wrapping_key": "transport",
                }),
                outputs: json!({
                    "wrapped_key_fingerprint": rite_runtime::compute_fingerprint(wrapped.data()),
                    "wrap": wrapped.description(),
                }),
                fingerprint: None,
            },
            StepFact::ArtifactWritten {
                step: StepId::new("wrap"),
                name: "wrapped".to_string(),
                file: "wrapped.p7c".to_string(),
                digest: Some(rite_model::Sha256Digest::of(wrapped.data())),
            },
        ];

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let [check] = checks.as_slice() else {
            panic!("expected one wrap check, got {checks:?}");
        };
        let ContainerStatus::Checked { origin, .. } = &check.status else {
            panic!("{}", check.describe());
        };
        assert_eq!(
            *origin,
            OriginEvidence::GeneratedHere,
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

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::Derived,
                recipient: RecipientEvidence::None,
                origin: OriginEvidence::GeneratedHere,
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

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert_eq!(
            check.status,
            ContainerStatus::Checked {
                algorithms: AlgorithmEvidence::AsInvoked(WrapScheme::RsaAesKeyWrapSha256),
                // The recipient was declared in advance, and that evidence
                // comes from two transcript facts rather than from the blob,
                // so a raw mechanism does not cost it.
                recipient: RecipientEvidence::Declared,
                origin: OriginEvidence::GeneratedHere,
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

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        assert!(
            checks.first().expect("one check").failed(),
            "{:?}",
            checks.first().map(ContainerCheck::describe)
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

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        assert!(checks.first().expect("one check").failed());
    }

    #[test]
    fn a_wrap_without_its_artifact_is_unchecked_not_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let wrap = &*WRAP;
        let facts = transcript(tmp.path(), wrap, wrap.outputs.clone());
        std::fs::remove_file(tmp.path().join("artifacts/wrapped.p7c")).unwrap();

        let checks = check_containers(Some(tmp.path()), &borrow(&facts));
        let check = checks.first().expect("one check");
        assert!(matches!(check.status, ContainerStatus::Unchecked { .. }));
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

        let checks = check_containers(None, &borrow(&facts));
        assert!(matches!(
            checks.first().expect("one check").status,
            ContainerStatus::Unchecked { .. }
        ));
    }
}
