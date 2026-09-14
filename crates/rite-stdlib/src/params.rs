//! Parameter structs for action handlers.

use serde::{Deserialize, Serialize};

/// Params for `clock_check` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClockCheckParams {
    /// Message to display before showing the time.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `confirm` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfirmParams {
    /// Message to display for confirmation.
    #[serde(default)]
    pub message: Option<String>,
}

/// Display format for the `oral_readback` action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadbackFormat {
    /// NATO phonetic alphabet (default).
    #[default]
    #[serde(alias = "nato")]
    NatoPhonetic,
    /// Hex pairs, grouped by 4 bytes.
    Hex,
    /// Raw value, no transformation.
    Raw,
}

impl ReadbackFormat {
    /// Short label suitable for transcript display.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ReadbackFormat::NatoPhonetic => "nato_phonetic",
            ReadbackFormat::Hex => "hex",
            ReadbackFormat::Raw => "raw",
        }
    }
}

/// Params for `oral_readback` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OralReadbackParams {
    /// Instruction shown before the readback, as on the other verification
    /// actions.
    #[serde(default)]
    pub message: Option<String>,
    /// Value to read aloud. Can be a literal string or artifact reference.
    #[serde(default)]
    pub value: Option<String>,
    /// Display format. Defaults to NATO phonetic.
    #[serde(default)]
    pub format: Option<ReadbackFormat>,
    /// Limit number of characters to read (for long values).
    #[serde(default)]
    pub characters: Option<u32>,
    /// If true, only record pass/fail result in evidence (no value recorded).
    #[serde(default)]
    pub sensitive: bool,
}

/// Params for `check_value` action.
///
/// Machine-verified comparison of two values. Use this when both values are known
/// to the system and comparison is deterministic (e.g., hash verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckValueParams {
    /// The computed or actual value to verify (required).
    pub actual: String,
    /// The expected value to compare against (required).
    pub expected: String,
    /// Human-readable description of what is being verified (for transcript/display).
    #[serde(default)]
    pub message: Option<String>,
    /// If true, only record pass/fail result in evidence (no values or lengths).
    #[serde(default)]
    pub sensitive: bool,
}

/// Params for `machine_info` action.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInfoParams {
    /// Include hashed machine ID in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_machine_id: bool,
    /// Include CPU model in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_cpu: bool,
    /// Include OS information in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_os: bool,
    /// Include memory protection status in evidence (default: true).
    #[serde(default = "default_true")]
    pub include_security_features: bool,
    /// Custom message to display before capturing machine info.
    #[serde(default)]
    pub message: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for MachineInfoParams {
    fn default() -> Self {
        Self {
            include_machine_id: true,
            include_cpu: true,
            include_os: true,
            include_security_features: true,
            message: None,
        }
    }
}

/// Params for `attest` action.
#[cfg(feature = "attestation")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestParams {
    /// The attestation statement.
    #[serde(default)]
    pub statement: Option<String>,
}

/// Params for `gather_entropy` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatherEntropyParams {
    /// Instruction shown to the participant describing how to produce the
    /// random value. Defaults to a generic dice suggestion; override per
    /// ceremony to mandate a specific method.
    #[serde(default)]
    pub instruction: Option<String>,
}

/// Params for `generate_key` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyParams {
    /// Cryptographic algorithm (e.g., `"RSA-4096"`, `"ECDSA-P256"`).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// What the key is permitted to do, and whether it may leave the backend.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
    /// Backend-specific slot hint.
    #[serde(default)]
    pub slot: Option<String>,
}

/// The `policy:` block, mirroring [`KeyPolicy`] field for field.
///
/// Every field is optional and falls back to [`KeyPolicy::default`], which is
/// the restrictive choice: a persistent, sensitive, non-extractable key that
/// may sign and verify. A ceremony that wraps a key it generated has to say
/// `extractable: true`, because otherwise the key cannot leave the backend and
/// the wrap step will refuse.
///
/// This is PKCS#11 vocabulary: what the token permits. The `KeyUsage`
/// extension in a certificate is a different thing, settled by `profile:` on
/// `issue_certificate`.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyPolicyParams {
    /// Key survives the session. `CKA_TOKEN`.
    #[serde(default)]
    pub persistent: Option<bool>,
    /// Key material is never revealed in plaintext. `CKA_SENSITIVE`.
    #[serde(default)]
    pub sensitive: Option<bool>,
    /// Key may be wrapped and leave the backend. `CKA_EXTRACTABLE`.
    #[serde(default)]
    pub extractable: Option<bool>,
    /// Key may only be wrapped by a trusted wrapping key.
    /// `CKA_WRAP_WITH_TRUSTED`.
    #[serde(default)]
    pub wrap_with_trusted_only: Option<bool>,
    /// Operations the key is permitted to perform: `sign`, `verify`,
    /// `encrypt`, `decrypt`, `wrap`, `unwrap`, `derive`.
    #[serde(default)]
    pub usages: Option<Vec<String>>,
}

#[cfg(feature = "crypto")]
impl KeyPolicyParams {
    /// Resolve the declared policy against a base.
    ///
    /// The base is the caller's to choose, because what a key may do when the
    /// ceremony says nothing follows from its algorithm: see
    /// [`KeyPolicy::default_for`](rite_sdk::KeyPolicy::default_for).
    ///
    /// # Errors
    ///
    /// Returns the offending name if `usages` holds one that is not a PKCS#11
    /// usage. Resolution rejects those first, so reaching this means the step
    /// was built without going through it.
    pub fn resolve_from(
        &self,
        defaults: &rite_sdk::KeyPolicy,
    ) -> Result<rite_sdk::KeyPolicy, String> {
        let usages = match &self.usages {
            None => defaults.usages,
            Some(names) => {
                let mut usages = rite_sdk::KeyUsages::empty();
                for name in names {
                    usages |= rite_sdk::KeyUsages::usage_named(name)
                        .ok_or_else(|| format!("unknown key usage '{name}'"))?;
                }
                usages
            }
        };
        Ok(rite_sdk::KeyPolicy {
            persistent: self.persistent.unwrap_or(defaults.persistent),
            sensitive: self.sensitive.unwrap_or(defaults.sensitive),
            extractable: self.extractable.unwrap_or(defaults.extractable),
            wrap_with_trusted_only: self
                .wrap_with_trusted_only
                .unwrap_or(defaults.wrap_with_trusted_only),
            usages,
        })
    }
}

#[cfg(feature = "crypto")]
fn default_algorithm() -> String {
    "RSA-4096".to_string()
}

#[cfg(feature = "crypto")]
impl Default for GenerateKeyParams {
    fn default() -> Self {
        Self {
            algorithm: default_algorithm(),
            policy: None,
            slot: None,
        }
    }
}

/// Params for `wrap_key` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WrapKeyParams {
    /// The wrapping scheme, defaulting to `"CMS-AES-256-GCM"`.
    ///
    /// Which encapsulation a scheme takes still follows the recipient key and
    /// is never an author's choice. What the author does choose is where the
    /// blob is going: CMS carries its own algorithm identifiers and is what a
    /// ceremony archives, while the raw mechanisms are what a cloud KMS import
    /// accepts and describe nothing about themselves.
    ///
    /// A raw scheme is a weaker record: `rite verify` cannot re-derive its
    /// algorithms from the artifact, and says so rather than reporting the
    /// wrap as checked.
    ///
    /// The AES schemes wrap under a symmetric key the backend holds, so they
    /// are reachable only from a step reading `wrapping_key:`. They name the
    /// KEK size, because the RFC 3394 and RFC 5649 object identifiers are
    /// per-size and the output carries neither.
    #[serde(default)]
    pub scheme: Option<rite_sdk::WrapScheme>,
    /// The recipient's expected fingerprint, `"sha256:<hex>"` over its SPKI
    /// DER, for a step that reads `recipient:`.
    ///
    /// Declaring it is what turns the recorded recipient from "whatever key
    /// was present" into a value the ceremony committed to in advance. On
    /// mismatch the step fails: a key wrapped to the wrong recipient cannot be
    /// unwrapped again.
    #[serde(default)]
    pub expect_recipient: Option<String>,
}

/// Params for `sign_data` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignDataParams {
    /// Signature algorithm. Defaults to the one implied by the key.
    ///
    /// Worth setting for an RSA key, which can sign under either
    /// `"RSA-PKCS1-SHA256"` (the default) or `"RSA-PSS-SHA256"`. Every other
    /// key type admits exactly one algorithm, so naming it only restates the
    /// key.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `verify_signature` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifySignatureParams {
    /// Signature algorithm. Defaults to the one implied by the public key.
    ///
    /// Required when checking an RSA-PSS signature, since an RSA key alone
    /// does not say which scheme was used.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `unwrap_key` action.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnwrapKeyParams {
    /// What the ceremony is restoring, as a key algorithm name.
    ///
    /// Nothing travels with a wrapped key saying what it is, so a recovered
    /// blob is read as whatever this names. Required to recover a symmetric
    /// key, whose bytes are indistinguishable from any other bytes of the same
    /// length. Optional for a keypair, which names itself once its DER parses,
    /// and checked against what came out when given.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// The expected identity of the recovered key: `"sha256:<hex>"` over its
    /// SPKI DER for a keypair, `"cmac-aes:<hex>"` for a symmetric key.
    ///
    /// Usually the value the origin ceremony's `generate_key` step
    /// recorded. On mismatch the step fails rather than importing a key the
    /// ceremony did not mean to restore.
    #[serde(default)]
    pub expect_key: Option<String>,
    /// Label for the unwrapped key (defaults to `"unwrapped-key"`).
    #[serde(default)]
    pub label: Option<String>,
    /// What the recovered key is permitted to do, and whether it may leave
    /// the backend again.
    ///
    /// Nothing travels with a wrapped key that says what it may do, so the
    /// receiving ceremony declares that. Without a `policy:` the key may sign,
    /// verify and be wrapped again; a key restored to serve as a wrapping key
    /// has to say `usages: [wrap, unwrap]`.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
}

/// The policy a recovered key gets when the step declares none.
///
/// `extractable` is true because this backend has just held the key in the
/// clear, so claiming otherwise would be a claim the run cannot support. The
/// usages are the restrictive default, as they are at generation, and they
/// follow the declared algorithm for the same reason they do there: sign and
/// verify is right for a keypair and impossible for a symmetric key.
///
/// `None` is a ceremony that declared no algorithm, which only a keypair can
/// reach, since a symmetric key cannot be recovered without the declaration.
#[cfg(feature = "crypto")]
#[must_use]
pub fn unwrapped_key_default_policy(
    algorithm: Option<rite_sdk::KeyAlgorithm>,
) -> rite_sdk::KeyPolicy {
    let usages = algorithm.map_or_else(
        || rite_sdk::KeyPolicy::default().usages,
        |algorithm| rite_sdk::KeyPolicy::default_for(algorithm).usages,
    );
    rite_sdk::KeyPolicy {
        extractable: true,
        usages,
        ..rite_sdk::KeyPolicy::default()
    }
}

/// Params for `generate_csr` action.
#[cfg(feature = "pki")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateCsrParams {
    /// Subject as RFC 4514 DN string: `"CN=example.com,O=Acme,C=US"`
    pub subject: String,
    /// Subject Alternative Names: `"DNS:foo.com"`, `"IP:1.2.3.4"`, `"email:u@example.com"`
    #[serde(default)]
    pub san: Option<Vec<String>>,
}

/// Params for `issue_certificate` action.
#[cfg(feature = "pki")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IssueCertificateParams {
    /// Certificate profile controlling extensions.
    /// Supported: `"root_ca"`, `"sub_ca"` (or `"intermediate_ca"`), `"tls_server"`,
    /// `"code_signing"`, `"end_entity"` (default).
    #[serde(default)]
    pub profile: Option<String>,
    /// Certificate validity period in days (default: 3650 = ~10 years).
    #[serde(default)]
    pub validity_days: Option<u32>,
    /// Issuer Common Name override (as `CN=<value>`) when no `issuer_cert`
    /// input is provided. Defaults to the CSR subject, producing a
    /// self-issued certificate.
    #[serde(default)]
    pub issuer_cn: Option<String>,
    /// `pathLenConstraint` for `sub_ca` profile (default: 0).
    #[serde(default)]
    pub path_len: Option<u8>,
}

#[cfg(test)]
mod schema_drift_tests {
    use super::*;
    use rite_model::ActionType;
    use std::collections::BTreeSet;

    /// The keys a params struct actually accepts.
    ///
    /// Every struct here derives `Default` and `Serialize` and none uses
    /// `skip_serializing_if`, so serializing a default value names every field
    /// serde will read.
    fn serde_keys<T: serde::Serialize>(value: T) -> BTreeSet<String> {
        serde_json::to_value(value)
            .expect("params structs serialize")
            .as_object()
            .expect("params structs are objects")
            .keys()
            .cloned()
            .collect()
    }

    fn declared(action: ActionType) -> BTreeSet<String> {
        action
            .known_with_fields()
            .iter()
            .map(|field| (*field).to_string())
            .collect()
    }

    /// `known_with_fields` stands in for these structs across a crate boundary
    /// the resolver cannot see over, so nothing but this test makes the two
    /// agree. The dangerous direction is silent: a field added here and not
    /// there is rejected as unknown, and one removed here and left there goes
    /// back to being dropped without a word.
    #[test]
    fn every_params_struct_matches_the_fields_the_model_declares() {
        for (action, keys) in [
            (
                ActionType::ClockCheck,
                serde_keys(ClockCheckParams::default()),
            ),
            (ActionType::Confirm, serde_keys(ConfirmParams::default())),
            (
                ActionType::CheckValue,
                serde_keys(CheckValueParams {
                    actual: String::new(),
                    expected: String::new(),
                    message: None,
                    sensitive: false,
                }),
            ),
            (
                ActionType::OralReadback,
                serde_keys(OralReadbackParams::default()),
            ),
            (
                ActionType::MachineInfo,
                serde_keys(MachineInfoParams::default()),
            ),
            (ActionType::Attest, serde_keys(AttestParams::default())),
            (
                ActionType::GatherEntropy,
                serde_keys(GatherEntropyParams::default()),
            ),
            #[cfg(feature = "crypto")]
            (
                ActionType::GenerateKey,
                serde_keys(GenerateKeyParams::default()),
            ),
            #[cfg(feature = "crypto")]
            (ActionType::WrapKey, serde_keys(WrapKeyParams::default())),
            #[cfg(feature = "crypto")]
            (
                ActionType::UnwrapKey,
                serde_keys(UnwrapKeyParams::default()),
            ),
            #[cfg(feature = "crypto")]
            (ActionType::SignData, serde_keys(SignDataParams::default())),
            #[cfg(feature = "crypto")]
            (
                ActionType::VerifySignature,
                serde_keys(VerifySignatureParams::default()),
            ),
            #[cfg(feature = "pki")]
            (
                ActionType::GenerateCsr,
                serde_keys(GenerateCsrParams {
                    subject: String::new(),
                    san: None,
                }),
            ),
            #[cfg(feature = "pki")]
            (
                ActionType::IssueCertificate,
                serde_keys(IssueCertificateParams::default()),
            ),
        ] {
            assert_eq!(keys, declared(action), "{action}");
        }
    }

    /// A recovered key's default usages follow what the ceremony declared it
    /// is, because sign and verify is right for a keypair and impossible for a
    /// symmetric key, which exists only to wrap.
    #[cfg(feature = "crypto")]
    #[test]
    fn the_default_policy_for_a_recovered_key_follows_its_algorithm() {
        use rite_sdk::{KeyAlgorithm, KeyUsages};

        let keypair = unwrapped_key_default_policy(Some(KeyAlgorithm::Rsa4096));
        assert_eq!(keypair.usages, KeyUsages::SIGN | KeyUsages::VERIFY);

        let secret = unwrapped_key_default_policy(Some(KeyAlgorithm::Aes256));
        assert_eq!(secret.usages, KeyUsages::WRAP | KeyUsages::UNWRAP);

        // Undeclared is a keypair: a symmetric key cannot be recovered at all
        // without the declaration.
        assert_eq!(
            unwrapped_key_default_policy(None).usages,
            unwrapped_key_default_policy(Some(KeyAlgorithm::Rsa4096)).usages
        );

        // The key was held in the clear here whatever it is, so claiming it
        // cannot leave would be a claim the run does not support.
        assert!(secret.extractable && keypair.extractable);
    }
}
