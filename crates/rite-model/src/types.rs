//! Shared semantic types for the ceremony domain model.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Ceremony metadata (name and optional description).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Human-readable ceremony name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Extract the role type from a role ID.
///
/// `"witness__1"` → `"witness"`, `"operator"` → `"operator"`.
pub fn role_type(id: &str) -> &str {
    id.split_once("__").map_or(id, |(prefix, _)| prefix)
}

/// Derive a display name from a step or section ID.
///
/// Splits on `_` and `-`, title-cases each word, joins with space.
/// `"verify_time"` → `"Verify Time"`, `"generate_root_ca"` → `"Generate Root Ca"`.
///
/// Note: this naive title-casing does not handle acronyms; `"root_ca"` becomes `"Root Ca"`
/// rather than `"Root CA"`. A lookup table for common ceremony acronyms (CA, CSR, PKI, HSM,
/// TPM) could improve this. See `derive_role_name` for the same limitation.
pub fn derive_step_name(id: &str) -> String {
    id.split(['_', '-'])
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Derive a display name from a role ID.
///
/// Title-cases each word (split on `_`, `-`, and `__`), including the discriminator suffix.
/// `"witness__1"` → `"Witness 1"`, `"hsm_operator__primary"` → `"Hsm Operator Primary"`.
pub fn derive_role_name(id: &str) -> String {
    id.replace("__", " ")
        .split(['_', '-', ' '])
        .filter(|s| !s.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Action types available in ceremony steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionType {
    /// Verify system clock is correct before ceremony proceeds.
    ///
    /// Displays current time and requires operator confirmation.
    /// Should be placed as the first step to ensure all timestamps are valid.
    ClockCheck,
    /// Human attests to something with yes/no decision (single person).
    ///
    /// Use when the verification requires human judgment about external state.
    /// Example: "Verify all network cables are disconnected".
    Confirm,
    /// Machine compares two known values and records pass/fail (automatic).
    ///
    /// Use when both values are known to the system and comparison is deterministic.
    /// Example: Compare computed `SHA-256` hash against expected value.
    CheckValue,
    /// Two-party verbal verification: reader speaks value aloud, confirmer verifies.
    ///
    /// Use when a value must be verified against something external (physical label,
    /// document). Supports NATO phonetic alphabet and hex formatting.
    OralReadback,
    /// Capture machine information (hostname, CPU, OS) as evidence.
    ///
    /// Records device identity to prove which machine ran the ceremony.
    /// Should be placed early in ceremony to establish machine context.
    MachineInfo,
    /// A person types a value the ceremony needs and can record: a serial
    /// number read off a device, an address shown on a screen.
    ///
    /// The value becomes a text artifact, so a later step compares it or
    /// prints it, and the transcript carries it. `format:` and the length
    /// fields say what shape the value has, so a slip is refused at the
    /// keyboard rather than found at the end.
    EnterValue,
    /// A person types a secret the ceremony needs and must not record: a
    /// passphrase, a PIN.
    ///
    /// `enter_value` for a value the transcript may not carry. Echo is off,
    /// the artifact is held wiped in memory, and the transcript records that
    /// a secret was entered at this step and nothing derived from it. A step
    /// names it in `reads:`, which borrows the value. An expression in
    /// `with:` copies it into the step's parameters, as it would opened
    /// content.
    EnterSecret,

    /// Generate a key: a keypair for an asymmetric algorithm, one secret for
    /// a symmetric one.
    GenerateKey,
    /// Encrypt a private key under another key so it can leave the machine.
    ///
    /// The OpenSSL backend produces a CMS `AuthEnvelopedData` under
    /// AES-256-GCM. Which encapsulation that takes follows the recipient key,
    /// and the transcript records what the wrap actually did.
    ///
    /// Reads `wrapping_key:` to wrap under a key the backend holds, or
    /// `recipient:` to wrap to a public key held outside the ceremony.
    WrapKey,
    /// Decrypt a wrapped key and import it into a backend under a new label.
    UnwrapKey,
    /// Encrypt content for a recipient, producing an encrypted-data artifact.
    ///
    /// `wrap_key` for bytes that are not a key. The container is the same one,
    /// and the claim is not: a wrap says a key left a backend under protection,
    /// while encrypted content makes no custody claim at all.
    ///
    /// Reads `encryption_key:`, a key-encryption key the backend holds. The key
    /// protects a fresh content-encryption key, and the content is encrypted
    /// under that.
    EncryptData,
    /// Decrypt an encrypted-data artifact back to bytes.
    ///
    /// The bytes become an ordinary artifact, so a later step reads them as a
    /// material: `import_key` lifts them into a key, `check_value` compares
    /// them, `sign_data` signs them.
    DecryptData,
    /// Split a secret into shares of which a threshold reconstruct it.
    ///
    /// Shamir over GF(2^8), the `rite-sss/v1` format, with the polynomial
    /// coefficients drawn from the step's backend. Reads `secret:` and
    /// creates one artifact holding every share, reached as
    /// `${artifact.<name>.share_N}` under a later step's `reads:`. At most
    /// 100 shares. Every subset of `threshold` shares is combined and
    /// checked before the step completes, so a share that leaves the room
    /// has been shown to work; a split with more than 100,000 such subsets
    /// is refused at run time.
    SplitSecret,
    /// Reconstruct a secret from shares `split_secret` made.
    ///
    /// Reads `shares:`, a list of at least two, each a share of a set or a
    /// share a custodian typed back. Each share records how many are
    /// needed, so too few shares is an error before anything is computed.
    /// The result stays in memory and is erased when the run ends, like the
    /// content `decrypt_data` opens.
    CombineShares,
    /// Install key material the ceremony holds as a key of a named algorithm.
    ///
    /// `unwrap_key` without the decrypt. The bytes can be a material carried
    /// into the room or an artifact an earlier step produced, and `algorithm:`
    /// says how to read them, because raw material says nothing about itself.
    ImportKey,
    /// Export public key from keypair.
    ExportPublic,
    /// Sign arbitrary data with a backend-managed key.
    ///
    /// The signature algorithm follows from the key unless `algorithm:` names
    /// another one the key accepts. Requires a backend implementing `SignBackend`.
    SignData,
    /// Verify a signature over data, given the signer's public key.
    ///
    /// Needs no backend: verification takes only a public key, so it works on
    /// evidence the ceremony did not produce. The key may be a bare public key
    /// or a certificate carrying one. Naming a `backend:` delegates the check
    /// to that backend instead.
    VerifySignature,
    /// Formal attestation statement.
    Attest,
    /// Fold human-supplied entropy into the ceremony seed.
    ///
    /// A participant supplies a free-form random value (for example, the
    /// result of rolling physical dice), which is mixed into the entropy
    /// source's ratchet. Any later drawn value reflects the contribution and
    /// stays re-derivable by `rite verify`.
    GatherEntropy,
    /// TPM attestation with PCR measurements and cryptographic quotes.
    ///
    /// Requires the `rite-tpm` backend.
    TpmAttest,

    /// Read X.509 certificate from PIV smart card slot.
    ///
    /// No PIN required; reading certificates is unauthenticated on PIV cards.
    /// Requires a PIV backend.
    PivReadCertificate,
    /// Sign data using PIV smart card on-device key.
    ///
    /// Handles PIN verification internally before signing.
    /// Requires a PIV backend.
    PivSign,
    /// Generate a `YubiKey` attestation certificate for a PIV slot (Yubico extension).
    ///
    /// Slot `F9` signs the key's certificate to prove it was generated on-device.
    /// Requires the `rite-yubikey` backend.
    YubikeyAttestSlot,

    /// Issue an X.509 certificate from a PKCS#10 CSR.
    ///
    /// Takes a CSR and a backend-managed signing key, assembles the `TBSCertificate`,
    /// signs it via the backend's `SignBackend`, and produces a DER-encoded certificate.
    /// Works with any backend implementing `SignBackend` (software, PKCS#11, `YubiKey`).
    IssueCertificate,
    /// Generate a PKCS#10 CSR signed by a backend-managed key.
    ///
    /// Takes a backend-managed signing key and subject parameters, assembles a
    /// `CertReqInfo`, signs it via the backend's `SignBackend`, and produces a
    /// `DER`-encoded `CSR`.
    GenerateCsr,
}

/// Whether an action needs the `backend:` field on its step.
///
/// Three states, not two: an action can also run without a backend and accept
/// one anyway. Verification is the case that forces the distinction, since a
/// signature check needs only a public key but a validated deployment may
/// require it inside the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BackendUsage {
    /// The step must name a backend; omitting it is an error.
    Required,
    /// The step runs in software unless it names a backend, which then does the
    /// work instead. Naming one changes who performs the operation, not what
    /// the step accepts or produces.
    SoftwareUnlessNamed,
    /// The action never uses a backend; naming one is a mistake worth warning about.
    Unused,
}

/// The certificate shape an `issue_certificate` step asks for.
///
/// DSL vocabulary rather than a backend concern: the author writes the name,
/// and the handler turns it into X.509 extensions. `path_len` is a separate
/// parameter, not part of a profile's identity, so this enum carries no
/// run-specific values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CertProfile {
    /// Self-signed CA at the top of a chain.
    RootCa,
    /// CA below another, constrained by `path_len`.
    SubCa,
    /// TLS server certificate.
    TlsServer,
    /// Code-signing certificate.
    CodeSigning,
    /// A leaf with no CA rights and no extended key usage.
    EndEntity,
}

impl fmt::Display for CertProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertProfile::RootCa => write!(f, "root_ca"),
            CertProfile::SubCa => write!(f, "sub_ca"),
            CertProfile::TlsServer => write!(f, "tls_server"),
            CertProfile::CodeSigning => write!(f, "code_signing"),
            CertProfile::EndEntity => write!(f, "end_entity"),
        }
    }
}

impl std::str::FromStr for CertProfile {
    type Err = UnknownCertProfile;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root_ca" => Ok(Self::RootCa),
            // `intermediate_ca` is the same shape under the name the PKI
            // world more often uses for it.
            "sub_ca" | "intermediate_ca" => Ok(Self::SubCa),
            "tls_server" => Ok(Self::TlsServer),
            "code_signing" => Ok(Self::CodeSigning),
            "end_entity" => Ok(Self::EndEntity),
            _ => Err(UnknownCertProfile),
        }
    }
}

/// A `profile:` value naming no certificate shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCertProfile;

impl fmt::Display for UnknownCertProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "supported profiles: root_ca, sub_ca, tls_server, code_signing, end_entity"
        )
    }
}

/// The secret sharing scheme a `split_secret` step names.
///
/// DSL vocabulary, like [`CertProfile`]: the author writes the name and the
/// transcript records it. One scheme today. The enum exists so a second one
/// (a prime field, a verifiable variant, codex32) is a variant rather than a
/// flag, and so a name this build does not implement is refused at `rite
/// check`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum SharingScheme {
    /// Shamir over GF(2^8), one polynomial per byte, the `rite-sss/v1`
    /// share format.
    RiteSssV1,
}

impl SharingScheme {
    /// The name a ceremony writes and the transcript records.
    pub fn as_str(self) -> &'static str {
        match self {
            SharingScheme::RiteSssV1 => "rite-sss/v1",
        }
    }

    /// The most shares a split under this scheme may make.
    ///
    /// A policy limit rather than what the arithmetic allows: a share index
    /// is a byte, so `rite-sss/v1` could evaluate 255 points, and 100 is a
    /// round number well past any split a room of custodians receives. Kept
    /// low on purpose, since raising it later costs nothing and lowering it
    /// would break a ceremony that ran. It also leaves the indexes SLIP-0039
    /// reserves (254 for a digest, 255 for the secret) free for a scheme that
    /// wants them.
    pub fn max_shares(self) -> u8 {
        match self {
            SharingScheme::RiteSssV1 => 100,
        }
    }
}

impl fmt::Display for SharingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<SharingScheme> for String {
    fn from(scheme: SharingScheme) -> Self {
        scheme.as_str().to_string()
    }
}

impl std::str::FromStr for SharingScheme {
    type Err = UnknownSharingScheme;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rite-sss/v1" => Ok(Self::RiteSssV1),
            _ => Err(UnknownSharingScheme),
        }
    }
}

impl TryFrom<String> for SharingScheme {
    type Error = UnknownSharingScheme;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A `scheme:` value naming no sharing scheme this build implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSharingScheme;

impl fmt::Display for UnknownSharingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "supported sharing schemes: rite-sss/v1")
    }
}

impl std::error::Error for UnknownSharingScheme {}

/// What an action requires of its step's `reads:` map.
///
/// See [`ActionType::reads_contract`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadsContract {
    /// Inputs every step of this action must name.
    pub required: &'static [&'static str],
    /// Groups from which exactly one input must be named. Each group holds the
    /// alternatives in the order they should be listed to the author.
    pub exactly_one_of: &'static [&'static [&'static str]],
    /// Inputs a step may name and the action reads when it does.
    ///
    /// Listed so that a key the action would never look at is refused rather
    /// than dropped: a `reads:` entry that nothing reads is a step running
    /// without what its author gave it.
    pub optional: &'static [&'static str],
    /// `with:` fields that mean nothing unless the step also names a given
    /// input, as `(field, input)` pairs.
    ///
    /// Where an action offers two paths over one operation, a parameter can
    /// belong to only one of them. On the other path it would be parsed and
    /// never read, so the step would run without whatever the parameter asked
    /// for. This says which parameter needs which input.
    pub with_field_requires: &'static [(&'static str, &'static str)],
    /// Inputs that hold a list of references rather than one, each with the
    /// fewest entries a step may give.
    ///
    /// For an action that takes a set whose size the ceremony chooses, such
    /// as the shares of a split. Every other input named in this contract
    /// holds one reference, and the resolver reports a list where one is
    /// expected as it reports one where a list is.
    pub lists: &'static [ListInput],
}

/// A `reads:` input that holds a list of references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListInput {
    /// The key under `reads:`.
    pub name: &'static str,
    /// Fewest references the list may hold.
    pub at_least: usize,
}

impl ReadsContract {
    /// The contract of an action that constrains its inputs in neither way.
    pub const NONE: Self = Self::required(&[]);

    /// The contract of an action that requires these inputs and offers no
    /// alternatives between them.
    #[must_use]
    pub const fn required(fields: &'static [&'static str]) -> Self {
        Self {
            required: fields,
            exactly_one_of: &[],
            optional: &[],
            with_field_requires: &[],
            lists: &[],
        }
    }

    /// Whether the input named `key` holds a list under this contract.
    pub fn is_list(&self, key: &str) -> bool {
        self.lists.iter().any(|list| list.name == key)
    }

    /// Whether this contract constrains the `reads:` map at all.
    ///
    /// `with_field_requires` is a rule over `with:`, so it is not counted here.
    pub fn is_empty(&self) -> bool {
        self.required.is_empty()
            && self.exactly_one_of.is_empty()
            && self.optional.is_empty()
            && self.lists.is_empty()
    }

    /// Whether a step of this action may name this input.
    pub fn accepts(&self, key: &str) -> bool {
        self.required.contains(&key)
            || self.optional.contains(&key)
            || self.exactly_one_of.iter().any(|group| group.contains(&key))
            || self.lists.iter().any(|list| list.name == key)
    }
}

impl ActionType {
    /// Every action type, for callers that need to enumerate them.
    ///
    /// Maintained by hand: `#[non_exhaustive]` means no downstream crate can
    /// derive this list, and adding a variant produces no error outside this
    /// crate. Adding one here is what keeps editor completion and any other
    /// catalogue from silently missing it. The test below catches omissions.
    pub const ALL: &'static [ActionType] = &[
        ActionType::ClockCheck,
        ActionType::Confirm,
        ActionType::CheckValue,
        ActionType::OralReadback,
        ActionType::MachineInfo,
        ActionType::EnterValue,
        ActionType::EnterSecret,
        ActionType::GenerateKey,
        ActionType::WrapKey,
        ActionType::UnwrapKey,
        ActionType::ImportKey,
        ActionType::EncryptData,
        ActionType::DecryptData,
        ActionType::SplitSecret,
        ActionType::CombineShares,
        ActionType::ExportPublic,
        ActionType::SignData,
        ActionType::VerifySignature,
        ActionType::Attest,
        ActionType::GatherEntropy,
        ActionType::TpmAttest,
        ActionType::PivReadCertificate,
        ActionType::PivSign,
        ActionType::YubikeyAttestSlot,
        ActionType::IssueCertificate,
        ActionType::GenerateCsr,
    ];

    /// How this action relates to the `backend:` field on its step.
    ///
    /// TODO: Replace this with a nested enum split — `ActionType::Backend(BackendAction)` vs
    /// `ActionType::Local(LocalAction)`, once a home is found for the actions that are
    /// neither. This is a breaking change to every match on `ActionType` variants.
    pub fn backend_usage(self) -> BackendUsage {
        match self {
            ActionType::GenerateKey
            | ActionType::SignData
            | ActionType::WrapKey
            | ActionType::UnwrapKey
            | ActionType::ExportPublic
            | ActionType::GenerateCsr
            | ActionType::IssueCertificate
            | ActionType::PivReadCertificate
            | ActionType::PivSign
            | ActionType::YubikeyAttestSlot
            | ActionType::ImportKey
            | ActionType::EncryptData
            | ActionType::DecryptData
            | ActionType::SplitSecret
            | ActionType::TpmAttest => BackendUsage::Required,

            ActionType::VerifySignature => BackendUsage::SoftwareUnlessNamed,

            ActionType::ClockCheck
            | ActionType::Confirm
            | ActionType::CheckValue
            | ActionType::OralReadback
            | ActionType::MachineInfo
            | ActionType::EnterValue
            | ActionType::EnterSecret
            | ActionType::Attest
            | ActionType::CombineShares
            | ActionType::GatherEntropy => BackendUsage::Unused,
        }
    }

    /// Returns the `with:` field names that are required for this action.
    ///
    /// The resolver reports a diagnostic for each missing field.
    ///
    /// TODO: Replace the stringly-typed `with: serde_json::Value` in `schema::StepBody` with a
    /// typed `WithFields` enum (one variant per action, carrying its required fields as named
    /// struct members). Serde would then enforce required fields at parse time and this method
    /// would no longer be needed. This is a breaking change to the schema and lowering layers.
    pub fn required_with_fields(self) -> &'static [&'static str] {
        match self {
            ActionType::CheckValue => &["actual", "expected"],
            ActionType::GenerateCsr => &["subject"],
            // Raw material carries no description, so the ceremony declares
            // what it is lifting rather than the step guessing.
            ActionType::ImportKey => &["algorithm"],
            ActionType::SplitSecret => &["threshold", "shares"],
            // The label is what the person sees at the keyboard, and there is
            // no default that names what they are being asked for.
            ActionType::EnterValue | ActionType::EnterSecret => &["message"],

            ActionType::ClockCheck
            | ActionType::Confirm
            | ActionType::OralReadback
            | ActionType::MachineInfo
            | ActionType::GenerateKey
            | ActionType::WrapKey
            | ActionType::UnwrapKey
            | ActionType::ExportPublic
            | ActionType::SignData
            | ActionType::VerifySignature
            | ActionType::Attest
            | ActionType::GatherEntropy
            | ActionType::TpmAttest
            | ActionType::PivReadCertificate
            | ActionType::PivSign
            | ActionType::YubikeyAttestSlot
            | ActionType::EncryptData
            | ActionType::DecryptData
            | ActionType::CombineShares
            | ActionType::IssueCertificate => &[],
        }
    }

    /// Every `with:` key this action accepts.
    ///
    /// Nothing else may appear under `with:`. Serde ignores a key it does not
    /// know, so without this a misspelled field, or one that used to exist, is
    /// dropped in silence and the ceremony quietly stops doing what its author
    /// wrote. That is the failure this list exists to prevent, and it covers
    /// typos and removed fields alike rather than naming them one at a time.
    ///
    /// Required keys are the subset in
    /// [`required_with_fields`](Self::required_with_fields); the rest are
    /// optional. Nested keys are not listed: only the top level of the block
    /// is checked, because a nested shape belongs to the handler's own params
    /// type.
    pub fn known_with_fields(self) -> &'static [&'static str] {
        match self {
            ActionType::ClockCheck | ActionType::Confirm => &["message"],
            ActionType::CheckValue => &["actual", "expected", "message", "sensitive"],
            ActionType::OralReadback => &["value", "format", "characters", "message"],
            ActionType::MachineInfo => &[
                "include_machine_id",
                "include_cpu",
                "include_os",
                "include_security_features",
                "message",
            ],
            ActionType::EnterValue | ActionType::EnterSecret => {
                &["message", "format", "length", "min_length", "max_length"]
            }
            ActionType::GenerateKey => &["algorithm", "policy", "slot"],
            ActionType::WrapKey => &["scheme", "expect_recipient"],
            ActionType::UnwrapKey | ActionType::ImportKey => {
                &["algorithm", "expect_key", "label", "policy"]
            }
            ActionType::EncryptData => &["scheme"],
            ActionType::SplitSecret => &["scheme", "threshold", "shares"],
            ActionType::SignData | ActionType::VerifySignature => &["algorithm", "message"],
            ActionType::Attest => &["statement"],
            ActionType::GatherEntropy => &["instruction"],
            ActionType::IssueCertificate => &["profile", "validity_days", "issuer_cn", "path_len"],
            ActionType::GenerateCsr => &["subject", "san"],
            ActionType::PivReadCertificate | ActionType::YubikeyAttestSlot => &["slot", "message"],
            ActionType::PivSign => &["slot", "algorithm", "message"],
            // `export_public` and `decrypt_data` take their inputs through
            // `reads:` alone, and `tpm_attest` has no handler in any build yet,
            // so none of the three has a `with:` shape to accept. For the last,
            // `unsupported_actions` is what reports the step itself.
            ActionType::ExportPublic
            | ActionType::DecryptData
            | ActionType::CombineShares
            | ActionType::TpmAttest => &[],
        }
    }

    /// Returns the `reads:` inputs this action requires, and the groups from
    /// which exactly one input must be named.
    ///
    /// A group is how an action offers two paths over the same operation. The
    /// input the author names selects the path, so naming both is ambiguous and
    /// naming neither leaves the path undetermined. The resolver reports either
    /// on the step.
    pub fn reads_contract(self) -> ReadsContract {
        match self {
            ActionType::WrapKey => ReadsContract {
                required: &["key_to_wrap"],
                exactly_one_of: &[&["wrapping_key", "recipient"]],
                optional: &[],
                // `expect_recipient` is compared against the recipient a wrap
                // is given, and only the external path has one.
                with_field_requires: &[("expect_recipient", "recipient")],
                lists: &[],
            },
            ActionType::UnwrapKey => ReadsContract::required(&["unwrapping_key", "wrapped_data"]),
            ActionType::ImportKey => ReadsContract {
                required: &["key_material"],
                exactly_one_of: &[],
                // What opens an encrypted private key. Read from the store
                // rather than given in `with:`, so the value is borrowed and
                // never copied into the step's parameters.
                optional: &["passphrase"],
                with_field_requires: &[],
                lists: &[],
            },
            ActionType::EncryptData => ReadsContract::required(&["data", "encryption_key"]),
            ActionType::DecryptData => {
                ReadsContract::required(&["encrypted_data", "decryption_key"])
            }
            ActionType::SplitSecret => ReadsContract::required(&["secret"]),
            // Two is the smallest threshold; the shares themselves say
            // whether two is enough, at run time.
            ActionType::CombineShares => ReadsContract {
                required: &[],
                exactly_one_of: &[],
                optional: &[],
                with_field_requires: &[],
                lists: &[ListInput {
                    name: "shares",
                    at_least: 2,
                }],
            },
            ActionType::SignData => ReadsContract::required(&["key", "data"]),
            ActionType::VerifySignature => ReadsContract::required(&["key", "data", "signature"]),
            // Without `issuer_cert` the certificate is self-issued under the
            // CSR's subject; with it, the issuer name and key identifier come
            // from the CA certificate.
            ActionType::IssueCertificate => ReadsContract {
                required: &["signing_key", "csr"],
                exactly_one_of: &[],
                optional: &["issuer_cert"],
                with_field_requires: &[],
                lists: &[],
            },
            ActionType::GenerateCsr => ReadsContract::required(&["signing_key"]),

            ActionType::ClockCheck
            | ActionType::Confirm
            | ActionType::CheckValue
            | ActionType::OralReadback
            | ActionType::MachineInfo
            | ActionType::EnterValue
            | ActionType::EnterSecret
            | ActionType::GenerateKey
            | ActionType::ExportPublic
            | ActionType::Attest
            | ActionType::GatherEntropy
            | ActionType::TpmAttest
            | ActionType::PivReadCertificate
            | ActionType::PivSign
            | ActionType::YubikeyAttestSlot => ReadsContract::NONE,
        }
    }

    /// Short human-readable description of what this action does.
    ///
    /// Used as fallback prose in script generation, TUI step display, and LSP
    /// hover when no explicit `description` or `message` parameter is present.
    pub fn describe(&self) -> &'static str {
        match self {
            ActionType::ClockCheck => "Verify system clock against a reference time.",
            ActionType::Confirm => "Confirm readiness or completion of a manual step.",
            ActionType::CheckValue => "Verify a value matches an expected result.",
            ActionType::OralReadback => "Read back a value aloud for verification.",
            ActionType::MachineInfo => "Record system and environment information.",
            ActionType::EnterValue => "Type a value the ceremony records.",
            ActionType::EnterSecret => "Type a secret the ceremony holds and never records.",
            ActionType::Attest => "Record a signed attestation from a participant.",
            ActionType::GatherEntropy => "Fold human-supplied entropy into the ceremony seed.",
            ActionType::TpmAttest => "Record TPM platform attestation (PCR values).",
            ActionType::GenerateKey => "Generate a cryptographic key.",
            ActionType::ExportPublic => "Export the public component of a keypair.",
            ActionType::SignData => "Sign data with a ceremony key.",
            ActionType::VerifySignature => "Verify a signature against a public key.",
            ActionType::WrapKey => "Encrypt a key under another key for transport.",
            ActionType::UnwrapKey => "Decrypt a wrapped key and import it into a backend.",
            ActionType::GenerateCsr => "Generate a Certificate Signing Request.",
            ActionType::IssueCertificate => "Issue an X.509 certificate from a CSR.",
            ActionType::PivReadCertificate => "Read a certificate from a PIV smart card slot.",
            ActionType::PivSign => "Sign data using a PIV smart card key.",
            ActionType::YubikeyAttestSlot => "Attest a YubiKey PIV slot key.",
            ActionType::ImportKey => "Import a key from material the ceremony holds.",
            ActionType::EncryptData => "Encrypt content under a key held by a backend.",
            ActionType::DecryptData => "Decrypt an encrypted-data artifact back to bytes.",
            ActionType::SplitSecret => {
                "Split a secret into shares a threshold of which reconstruct it."
            }
            ActionType::CombineShares => "Reconstruct a secret from its shares.",
        }
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::ClockCheck => write!(f, "clock_check"),
            ActionType::Confirm => write!(f, "confirm"),
            ActionType::CheckValue => write!(f, "check_value"),
            ActionType::OralReadback => write!(f, "oral_readback"),
            ActionType::MachineInfo => write!(f, "machine_info"),
            ActionType::EnterValue => write!(f, "enter_value"),
            ActionType::EnterSecret => write!(f, "enter_secret"),
            ActionType::GenerateKey => write!(f, "generate_key"),
            ActionType::WrapKey => write!(f, "wrap_key"),
            ActionType::UnwrapKey => write!(f, "unwrap_key"),
            ActionType::ImportKey => write!(f, "import_key"),
            ActionType::EncryptData => write!(f, "encrypt_data"),
            ActionType::DecryptData => write!(f, "decrypt_data"),
            ActionType::SplitSecret => write!(f, "split_secret"),
            ActionType::CombineShares => write!(f, "combine_shares"),
            ActionType::ExportPublic => write!(f, "export_public"),
            ActionType::SignData => write!(f, "sign_data"),
            ActionType::VerifySignature => write!(f, "verify_signature"),
            ActionType::Attest => write!(f, "attest"),
            ActionType::GatherEntropy => write!(f, "gather_entropy"),
            ActionType::TpmAttest => write!(f, "tpm_attest"),
            ActionType::PivReadCertificate => write!(f, "piv_read_certificate"),
            ActionType::PivSign => write!(f, "piv_sign"),
            ActionType::YubikeyAttestSlot => write!(f, "yubikey_attest_slot"),
            ActionType::IssueCertificate => write!(f, "issue_certificate"),
            ActionType::GenerateCsr => write!(f, "generate_csr"),
        }
    }
}

/// Type of output produced by a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputType {
    /// Public key in PEM format.
    PublicKey,
    /// A key wrapped for transport, in the container its scheme names.
    WrappedKey,
    /// Content encrypted for a recipient, in the container its scheme names.
    EncryptedData,
    /// X.509 certificate.
    Certificate,
    /// DNSSEC signed resource record set.
    SignedRrset,
    /// Certificate Transparency Signed Certificate Timestamp.
    Sct,

    // Documents
    /// Generic document.
    Document,
    /// Ceremony log or transcript.
    CeremonyLog,
}

impl std::fmt::Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputType::PublicKey => write!(f, "public_key"),
            OutputType::WrappedKey => write!(f, "wrapped_key"),
            OutputType::EncryptedData => write!(f, "encrypted_data"),
            OutputType::Certificate => write!(f, "certificate"),
            OutputType::SignedRrset => write!(f, "signed_rrset"),
            OutputType::Sct => write!(f, "sct"),
            OutputType::Document => write!(f, "document"),
            OutputType::CeremonyLog => write!(f, "ceremony_log"),
        }
    }
}

impl OutputType {
    /// Returns the default file extension for this output type.
    pub fn default_extension(&self) -> &'static str {
        match self {
            OutputType::PublicKey | OutputType::Certificate => "pem",
            OutputType::WrappedKey
            | OutputType::EncryptedData
            | OutputType::SignedRrset
            | OutputType::Sct => "bin",
            OutputType::Document => "txt",
            OutputType::CeremonyLog => "json",
        }
    }
}

/// Type of a ceremony parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ParameterType {
    /// Text value.
    String,
    /// Date value (`YYYY-MM-DD`).
    Date,
    /// Integer value.
    Integer,
    /// Boolean value.
    Boolean,
}

impl std::fmt::Display for ParameterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterType::String => write!(f, "string"),
            ParameterType::Date => write!(f, "date (YYYY-MM-DD)"),
            ParameterType::Integer => write!(f, "integer"),
            ParameterType::Boolean => write!(f, "boolean (true/false)"),
        }
    }
}

/// Typed preset for common post-ceremony duty categories.
///
/// Provides built-in prose for scripts when no description is given.
/// Use `Custom` for duties that don't fit a preset; description is then required.
///
/// Note: physical handling steps (sealing hardware, etc.) belong as `physical_action`
/// steps in ceremony execution, not here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DutyType {
    /// Return materials to secure storage location.
    ReturnToVault,
    /// Hand key shares to assigned custodians.
    DistributeShares,
    /// Distribute backup media to designated recipients.
    DistributeMedia,
    /// Archive ceremony materials at storage locations.
    ArchiveMaterials,
    /// Publish ceremony record and witness attestations.
    PublishRecord,
    /// Notify stakeholders of ceremony completion.
    NotifyStakeholders,
    /// Import generated keys into operational system.
    ImportKeys,
    /// Free-form duty; description is required.
    Custom,
}

impl DutyType {
    /// Returns the built-in display name for this duty type.
    pub fn display_name(&self) -> &'static str {
        match self {
            DutyType::ReturnToVault => "Return to Vault",
            DutyType::DistributeShares => "Distribute Key Shares",
            DutyType::DistributeMedia => "Distribute Backup Media",
            DutyType::ArchiveMaterials => "Archive Materials",
            DutyType::PublishRecord => "Publish Record",
            DutyType::NotifyStakeholders => "Notify Stakeholders",
            DutyType::ImportKeys => "Import Keys",
            DutyType::Custom => "Custom Duty",
        }
    }

    /// Returns the built-in prose description for this duty type.
    ///
    /// Returns `None` for `Custom` (description must be provided explicitly).
    pub fn built_in_prose(&self) -> Option<&'static str> {
        match self {
            DutyType::ReturnToVault => Some("Return materials to secure storage"),
            DutyType::DistributeShares => Some("Distribute key shares to assigned custodians"),
            DutyType::DistributeMedia => Some("Distribute backup media to designated recipients"),
            DutyType::ArchiveMaterials => {
                Some("Archive ceremony materials at designated storage locations")
            }
            DutyType::PublishRecord => Some("Publish ceremony record and witness attestations"),
            DutyType::NotifyStakeholders => Some("Notify stakeholders of ceremony completion"),
            DutyType::ImportKeys => Some("Import generated keys into operational system"),
            DutyType::Custom => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_type_extracts_prefix() {
        assert_eq!(role_type("witness__1"), "witness");
        assert_eq!(role_type("hsm_operator__primary"), "hsm_operator");
        assert_eq!(role_type("operator"), "operator");
        assert_eq!(role_type("witness__"), "witness");
    }

    #[test]
    fn derive_step_name_title_cases() {
        assert_eq!(derive_step_name("verify_time"), "Verify Time");
        assert_eq!(derive_step_name("generate_root_ca"), "Generate Root Ca");
        assert_eq!(derive_step_name("wrap_root_ca_key"), "Wrap Root Ca Key");
        assert_eq!(derive_step_name("witness1_attest"), "Witness1 Attest");
        assert_eq!(derive_step_name("clock-check"), "Clock Check");
        assert_eq!(derive_step_name("opening"), "Opening");
    }

    #[test]
    fn derive_role_name_title_cases() {
        assert_eq!(derive_role_name("witness__1"), "Witness 1");
        assert_eq!(
            derive_role_name("hsm_operator__primary"),
            "Hsm Operator Primary"
        );
        assert_eq!(derive_role_name("operator"), "Operator");
        assert_eq!(derive_role_name("ceremony-admin"), "Ceremony Admin");
    }

    #[test]
    fn action_type_serde_roundtrip() {
        // `snake_case` rename means these exact strings appear in ceremony YAML.
        // A variant rename or serde attr change breaks YAML parsing silently.
        let cases: &[(ActionType, &str)] = &[
            (ActionType::ClockCheck, "\"clock_check\""),
            (ActionType::Confirm, "\"confirm\""),
            (ActionType::CheckValue, "\"check_value\""),
            (ActionType::OralReadback, "\"oral_readback\""),
            (ActionType::MachineInfo, "\"machine_info\""),
            (ActionType::GenerateKey, "\"generate_key\""),
            (ActionType::WrapKey, "\"wrap_key\""),
            (ActionType::UnwrapKey, "\"unwrap_key\""),
            (ActionType::ImportKey, "\"import_key\""),
            (ActionType::EncryptData, "\"encrypt_data\""),
            (ActionType::DecryptData, "\"decrypt_data\""),
            (ActionType::SplitSecret, "\"split_secret\""),
            (ActionType::CombineShares, "\"combine_shares\""),
            (ActionType::ExportPublic, "\"export_public\""),
            (ActionType::Attest, "\"attest\""),
            (ActionType::TpmAttest, "\"tpm_attest\""),
            (ActionType::PivReadCertificate, "\"piv_read_certificate\""),
            (ActionType::PivSign, "\"piv_sign\""),
            (ActionType::YubikeyAttestSlot, "\"yubikey_attest_slot\""),
            (ActionType::IssueCertificate, "\"issue_certificate\""),
            (ActionType::GenerateCsr, "\"generate_csr\""),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: ActionType = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn action_type_display_matches_serde() {
        // Display is used in transcript output and error messages; serde in YAML parsing.
        // They must agree or transcripts reference action names that differ from YAML.
        let actions = [
            ActionType::ClockCheck,
            ActionType::Confirm,
            ActionType::CheckValue,
            ActionType::OralReadback,
            ActionType::MachineInfo,
            ActionType::GenerateKey,
            ActionType::WrapKey,
            ActionType::UnwrapKey,
            ActionType::ImportKey,
            ActionType::ExportPublic,
            ActionType::Attest,
            ActionType::TpmAttest,
            ActionType::PivReadCertificate,
            ActionType::PivSign,
            ActionType::YubikeyAttestSlot,
            ActionType::IssueCertificate,
            ActionType::GenerateCsr,
        ];
        for action in actions {
            let display = action.to_string();
            let serde_json = serde_json::to_string(&action).unwrap();
            assert_eq!(
                display,
                serde_json.trim_matches('"'),
                "Display and serde disagree for {action:?}"
            );
        }
    }

    #[test]
    fn output_type_serde_roundtrip() {
        // These strings appear in ceremony YAML `output:` blocks and in file extension
        // mapping. A rename breaks both YAML parsing and output file naming.
        let cases: &[(OutputType, &str)] = &[
            (OutputType::PublicKey, "\"public_key\""),
            (OutputType::WrappedKey, "\"wrapped_key\""),
            (OutputType::EncryptedData, "\"encrypted_data\""),
            (OutputType::Certificate, "\"certificate\""),
            (OutputType::Document, "\"document\""),
            (OutputType::CeremonyLog, "\"ceremony_log\""),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: OutputType = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn parameter_type_serde_roundtrip() {
        // These strings appear in ceremony YAML `parameters:` blocks.
        let cases: &[(ParameterType, &str)] = &[
            (ParameterType::String, "\"string\""),
            (ParameterType::Date, "\"date\""),
            (ParameterType::Integer, "\"integer\""),
            (ParameterType::Boolean, "\"boolean\""),
        ];
        for (variant, expected) in cases {
            let serialized = serde_json::to_string(variant).unwrap();
            assert_eq!(serialized, *expected, "serialize {variant:?}");
            let deserialized: ParameterType = serde_json::from_str(expected).unwrap();
            // ParameterType does not implement PartialEq; check the display instead.
            assert_eq!(
                serde_json::to_string(&deserialized).unwrap(),
                *expected,
                "deserialize {expected}"
            );
        }
    }

    #[test]
    fn duty_type_serde_roundtrip() {
        // These strings appear in ceremony YAML `after:` blocks.
        let cases: &[(DutyType, &str)] = &[
            (DutyType::ReturnToVault, "\"return_to_vault\""),
            (DutyType::DistributeShares, "\"distribute_shares\""),
            (DutyType::DistributeMedia, "\"distribute_media\""),
            (DutyType::ArchiveMaterials, "\"archive_materials\""),
            (DutyType::PublishRecord, "\"publish_record\""),
            (DutyType::NotifyStakeholders, "\"notify_stakeholders\""),
            (DutyType::ImportKeys, "\"import_keys\""),
            (DutyType::Custom, "\"custom\""),
        ];
        for (variant, expected) in cases {
            let serialized = serde_json::to_string(variant).unwrap();
            assert_eq!(serialized, *expected, "serialize {variant:?}");
            let deserialized: DutyType = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, *variant, "deserialize {expected}");
        }
    }

    #[test]
    fn duty_type_custom_has_no_built_in_prose() {
        // The runtime branches on this: if built_in_prose returns None, the description
        // field is required. A regression here would panic or produce empty script output.
        assert!(
            DutyType::Custom.built_in_prose().is_none(),
            "Custom duty must have no built-in prose"
        );
        // All other variants must have prose.
        for duty in [
            DutyType::ReturnToVault,
            DutyType::DistributeShares,
            DutyType::DistributeMedia,
            DutyType::ArchiveMaterials,
            DutyType::PublishRecord,
            DutyType::NotifyStakeholders,
            DutyType::ImportKeys,
        ] {
            assert!(
                duty.built_in_prose().is_some(),
                "{duty:?} must have built-in prose"
            );
        }
    }

    /// `ActionType::ALL` is written by hand, so it can fall behind the enum.
    ///
    /// The match below is exhaustive, so adding a variant fails to compile
    /// here. That is the whole mechanism: it puts a compiler error next to the
    /// list an author has to extend. The name check then catches a variant
    /// listed twice, and `rite-ls` compares its own catalogue against `ALL`,
    /// which is what catches one left out.
    /// A required field the action does not accept would be reported as
    /// unknown, which is the opposite of the message intended, and nothing
    /// makes the two lists agree on their own.
    #[test]
    fn every_required_field_is_also_a_known_field() {
        for action in ActionType::ALL {
            let known = action.known_with_fields();
            for field in action.required_with_fields() {
                assert!(
                    known.contains(field),
                    "{action} requires '{field}' and does not accept it"
                );
            }
        }
    }

    #[test]
    fn all_lists_every_action_type() {
        for action in ActionType::ALL {
            match action {
                ActionType::ClockCheck
                | ActionType::Confirm
                | ActionType::CheckValue
                | ActionType::OralReadback
                | ActionType::MachineInfo
                | ActionType::EnterValue
                | ActionType::EnterSecret
                | ActionType::GenerateKey
                | ActionType::WrapKey
                | ActionType::UnwrapKey
                | ActionType::ImportKey
                | ActionType::EncryptData
                | ActionType::DecryptData
                | ActionType::SplitSecret
                | ActionType::CombineShares
                | ActionType::ExportPublic
                | ActionType::SignData
                | ActionType::VerifySignature
                | ActionType::Attest
                | ActionType::GatherEntropy
                | ActionType::TpmAttest
                | ActionType::PivReadCertificate
                | ActionType::PivSign
                | ActionType::YubikeyAttestSlot
                | ActionType::IssueCertificate
                | ActionType::GenerateCsr => {}
            }
        }

        let names: std::collections::BTreeSet<String> =
            ActionType::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(
            names.len(),
            ActionType::ALL.len(),
            "two actions share a DSL name"
        );
    }
}
