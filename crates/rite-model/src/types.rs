//! Shared semantic types for the ceremony domain model.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

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

/// What a step does.
//
// Each variant's documentation is the text ceremony authors read: the schema
// carries it as the action's description, and editors show it on hover. The
// first paragraph is the summary, one sentence. Notes for this code's
// readers go in `//` comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionType {
    /// Check the system clock before the ceremony continues.
    ///
    /// Shows the current system time and asks the operator to confirm that
    /// it is correct. Place it first, so that every recorded time can be
    /// trusted.
    ClockCheck,
    /// Record one person's yes-or-no decision.
    ///
    /// Use it for a check that needs human judgment or knowledge of
    /// something outside the machine, such as "Verify that every network
    /// cable is disconnected".
    Confirm,
    /// Compare two values and fail the step if they do not match.
    ///
    /// Use it for a check the machine can make on its own, such as comparing a
    /// computed SHA-256 digest with an expected one.
    CheckValue,
    /// Have one person read a value aloud for another to check.
    ///
    /// Use it to check a value against something outside the machine, such
    /// as a label or a printed document. The value is shown in the NATO
    /// phonetic alphabet or in hexadecimal.
    OralReadback,
    /// Show a value for someone to copy, then remove it from the screen.
    ///
    /// The operator reveals the value once and confirms that every row is
    /// written down. The transcript records that it was shown, not its value.
    /// `rite script` prints a worksheet for the step. A headless run that is
    /// not a dry run stops here.
    Reveal,
    /// Record which machine runs the ceremony.
    ///
    /// Records details such as the hostname, the processor and the operating
    /// system as evidence. Place it early in the ceremony.
    MachineInfo,
    /// Ask someone to enter a value and record it as an artifact.
    ///
    /// The value is recorded in the transcript. The input format and length
    /// fields constrain what can be entered.
    EnterValue,
    /// Ask someone to enter a secret without recording its value.
    ///
    /// The input is hidden, and the secret is erased from memory when the run
    /// ends. The transcript records that a secret was entered, not its value. A
    /// later step can read it as an input.
    EnterSecret,

    /// Generate a key in a backend.
    GenerateKey,
    /// Encrypt a private key for transport.
    ///
    /// Reads `key_to_wrap` and exactly one of `wrapping_key` or `recipient`.
    WrapKey,
    /// Decrypt a wrapped key and import the recovered key into a backend.
    ///
    /// The wrapped data identifies its scheme. The step checks the recovered
    /// key against `algorithm` when one is given.
    UnwrapKey,
    /// Encrypt data for a key held by a backend or for a public key.
    ///
    /// Reads `data` and exactly one of `encryption_key` or `recipient`. With
    /// `encryption_key`, the backend generates a content-encryption key and
    /// protects it with that key. With `recipient`, an RSA-2048 or RSA-4096
    /// public key held elsewhere, the backend supplies the content-encryption
    /// key's random bytes, which are protected with RSAES-OAEP over SHA-256.
    /// The data itself is not sent to the backend.
    EncryptData,
    /// Decrypt data encrypted by `encrypt_data`, or a CMS file sealed
    /// elsewhere and supplied as a material.
    ///
    /// The step checks that the container names the decryption key. The
    /// result is a byte artifact available to later steps and erased from
    /// memory when the run ends.
    DecryptData,
    /// Split a secret into shares so that `threshold` of them can recover it.
    ///
    /// The step uses the backend for randomness and checks every subset of
    /// `threshold` shares before it completes. The shares are stored in one
    /// artifact, and later steps can read individual shares.
    SplitSecret,
    /// Recover a secret from shares.
    ///
    /// The shares must have the same threshold and length. Shares from
    /// different splits can produce an incorrect result without an error, so
    /// verify the recovered secret separately. The result is erased from memory
    /// when the run ends.
    CombineShares,
    /// Enter a share from its worksheet.
    ///
    /// Each row is checked as it is typed. The step creates a share artifact
    /// for later use by `combine_shares`.
    EnterShare,
    /// Import key material into a backend.
    ///
    /// The material can come from a file or an artifact. The action imports the
    /// bytes as the key type named by `algorithm`.
    ImportKey,
    /// Export a keypair's public key as an artifact.
    ExportPublic,
    /// Sign data with a key held by a backend.
    ///
    /// The key determines the signature algorithm unless `algorithm` names
    /// another one supported by the key.
    // The backend must implement `SignBackend`.
    SignData,
    /// Verify a signature using the signer's public key.
    ///
    /// A backend is optional. Without one, the action verifies in software.
    VerifySignature,
    /// Record a formal statement in the transcript.
    Attest,
    /// Add a participant-supplied random value to the ceremony's entropy.
    ///
    /// Later values drawn from the entropy source depend on this contribution.
    GatherEntropy,
    /// Record a TPM-signed quote of the device's measurements.
    ///
    /// No build of Rite currently supports this action.
    // Requires the `rite-tpm` backend, which does not exist yet.
    TpmAttest,

    /// Read a certificate from a PIV card.
    ///
    /// Reading a certificate from a PIV slot does not require a PIN.
    // Requires a PIV backend.
    PivReadCertificate,
    /// Sign data using a key on a PIV card.
    ///
    /// The step asks for the PIN before signing.
    // Requires a PIV backend.
    PivSign,
    /// Produce a YubiKey attestation for a PIV key.
    ///
    /// The YubiKey attestation key in slot F9 signs a certificate for the key
    /// in the named slot.
    // Requires the `rite-yubikey` backend.
    YubikeyAttestSlot,

    /// Issue an X.509 certificate for a certificate signing request.
    ///
    /// Reads the request and a signing key.
    // Assembles the `TBSCertificate` and signs it through the backend's
    // `SignBackend`, so any backend that signs can issue.
    IssueCertificate,
    /// Create a PKCS#10 certificate signing request.
    ///
    /// The request is built from `subject` and `san`, then signed with a key
    /// held by a backend.
    // Assembles the `CertReqInfo` and signs it through the backend's
    // `SignBackend`.
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
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum CertProfile {
    /// Self-signed CA at the top of a chain.
    RootCa,
    /// CA below another, constrained by `path_len`. Also written
    /// `intermediate_ca`.
    SubCa,
    /// TLS server certificate.
    TlsServer,
    /// Code-signing certificate.
    CodeSigning,
    /// A leaf with no CA rights and no extended key usage.
    EndEntity,
}

crate::types::vocabulary!(CertProfile {
    RootCa => "root_ca",
    SubCa => "sub_ca" | "intermediate_ca",
    TlsServer => "tls_server",
    CodeSigning => "code_signing",
    EndEntity => "end_entity",
});

impl fmt::Display for CertProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for CertProfile {
    type Err = UnknownCertProfile;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or(UnknownCertProfile)
    }
}

impl From<CertProfile> for String {
    fn from(profile: CertProfile) -> Self {
        profile.as_str().to_string()
    }
}

impl TryFrom<String> for CertProfile {
    type Error = UnknownCertProfile;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl schemars::JsonSchema for CertProfile {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CertProfile".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Self::names_schema()
    }
}

/// A `profile:` value naming no certificate shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCertProfile;

impl fmt::Display for UnknownCertProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = CertProfile::ALL.iter().map(|p| p.as_str()).collect();
        write!(f, "supported profiles: {}", names.join(", "))
    }
}

/// A DSL enum a ceremony writes as one of a fixed set of names.
///
/// Parsing and the schema both read the names from here, so an alias is
/// written once and the schema accepts exactly what parsing does.
pub(crate) trait Vocabulary: Copy + 'static {
    /// Every value, in declaration order.
    const VALUES: &'static [Self];
    /// Other names a ceremony may write, and the value each stands for.
    const ALIASES: &'static [(&'static str, Self)] = &[];

    /// The name a ceremony writes and a transcript records.
    fn name(self) -> &'static str;

    /// The value `name` stands for, under its own name or an alias.
    fn from_name(name: &str) -> Option<Self> {
        Self::VALUES
            .iter()
            .map(|&value| (value.name(), value))
            .chain(Self::ALIASES.iter().copied())
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, value)| value)
    }

    /// A string schema that accepts every name and alias.
    fn names_schema() -> schemars::Schema {
        crate::params::names(
            Self::VALUES
                .iter()
                .map(|value| value.name())
                .chain(Self::ALIASES.iter().map(|(alias, _)| *alias)),
        )
    }
}

/// Give a DSL enum its names from one list: `ALL`, `as_str`, and its
/// [`Vocabulary`] impl, aliases written `Variant => "name" | "alias"`.
///
/// `as_str` matches every variant, so a variant left out of the list fails
/// to compile, and `ALL` is complete because it is built from the same list.
macro_rules! vocabulary {
    ($ty:ident { $($variant:ident => $name:literal $(| $alias:literal)*,)+ }) => {
        impl $ty {
            /// Every value, in declaration order.
            pub const ALL: &'static [$ty] = &[$($ty::$variant),+];

            /// The name a ceremony writes and a transcript records.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $($ty::$variant => $name,)+
                }
            }
        }

        impl $crate::types::Vocabulary for $ty {
            const VALUES: &'static [Self] = Self::ALL;
            const ALIASES: &'static [(&'static str, Self)] =
                &[$($(($alias, $ty::$variant),)*)+];

            fn name(self) -> &'static str {
                self.as_str()
            }
        }
    };
}

pub(crate) use vocabulary;

/// Names as a person reads a list of alternatives: `a, b or c`.
pub(crate) fn either<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let names: Vec<&str> = names.collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        Some((last, _)) => (*last).to_string(),
        None => String::new(),
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

crate::types::vocabulary!(SharingScheme {
    RiteSssV1 => "rite-sss/v1",
});

impl SharingScheme {
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

    /// The bytes in front of a share's values: for `rite-sss/v1`, a
    /// version, a threshold and an index.
    #[must_use]
    pub fn header_len(self) -> usize {
        match self {
            SharingScheme::RiteSssV1 => 3,
        }
    }

    /// The length in bytes of one share of a secret of `secret_len` bytes,
    /// as a sheet or a transport holds it: the header, then one byte per
    /// byte of the secret.
    #[must_use]
    pub fn share_len(self, secret_len: usize) -> usize {
        match self {
            SharingScheme::RiteSssV1 => secret_len.saturating_add(self.header_len()),
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
        Self::from_name(s).ok_or(UnknownSharingScheme)
    }
}

impl schemars::JsonSchema for SharingScheme {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SharingScheme".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Self::names_schema()
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
        let names: Vec<&str> = SharingScheme::ALL.iter().map(|s| s.as_str()).collect();
        write!(f, "supported sharing schemes: {}", names.join(", "))
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

    /// Whether this contract constrains the `reads:` map at all.
    ///
    /// `with_field_requires` is a rule over `with:`, so it is not counted here.
    pub fn is_empty(&self) -> bool {
        self.required.is_empty()
            && self.exactly_one_of.is_empty()
            && self.optional.is_empty()
            && self.lists.is_empty()
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
        ActionType::Reveal,
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
        ActionType::EnterShare,
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
            | ActionType::Reveal
            | ActionType::MachineInfo
            | ActionType::EnterValue
            | ActionType::EnterSecret
            | ActionType::Attest
            | ActionType::CombineShares
            | ActionType::EnterShare
            | ActionType::GatherEntropy => BackendUsage::Unused,
        }
    }

    /// Whether the artifact this action creates is shares of a secret, which
    /// `rite check` tells from the step that made it, since the definition
    /// does not say what kind an artifact is.
    pub fn creates_shares(self) -> bool {
        match self {
            ActionType::SplitSecret | ActionType::EnterShare => true,
            ActionType::ClockCheck
            | ActionType::Confirm
            | ActionType::CheckValue
            | ActionType::OralReadback
            | ActionType::Reveal
            | ActionType::MachineInfo
            | ActionType::EnterValue
            | ActionType::EnterSecret
            | ActionType::GenerateKey
            | ActionType::WrapKey
            | ActionType::UnwrapKey
            | ActionType::ImportKey
            | ActionType::EncryptData
            | ActionType::DecryptData
            | ActionType::CombineShares
            | ActionType::ExportPublic
            | ActionType::SignData
            | ActionType::VerifySignature
            | ActionType::GenerateCsr
            | ActionType::IssueCertificate
            | ActionType::PivReadCertificate
            | ActionType::PivSign
            | ActionType::YubikeyAttestSlot
            | ActionType::Attest
            | ActionType::GatherEntropy
            | ActionType::TpmAttest => false,
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
            ActionType::EncryptData => ReadsContract {
                required: &["data"],
                exactly_one_of: &[&["encryption_key", "recipient"]],
                optional: &[],
                // As at `wrap_key`: only the public-key path has a recipient
                // to compare.
                with_field_requires: &[("expect_recipient", "recipient")],
                lists: &[],
            },
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
            ActionType::Reveal => ReadsContract::required(&["value"]),

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
            | ActionType::YubikeyAttestSlot
            | ActionType::EnterShare => ReadsContract::NONE,
        }
    }

    /// What the action does, for ceremony authors: the variant's
    /// documentation, as the schema carries it.
    #[must_use]
    pub fn description(self) -> &'static str {
        static DESCRIPTIONS: OnceLock<HashMap<ActionType, String>> = OnceLock::new();
        DESCRIPTIONS
            .get_or_init(|| {
                let schema = crate::params::generator().into_root_schema_for::<ActionType>();
                schema
                    .get("oneOf")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|variant| {
                        let action = serde_json::from_value(variant.get("const")?.clone()).ok()?;
                        let text = variant.get("description")?.as_str()?;
                        Some((action, text.to_string()))
                    })
                    .collect()
            })
            .get(&self)
            .map_or("", String::as_str)
    }

    /// The first paragraph of [`description`](Self::description), one
    /// sentence.
    #[must_use]
    pub fn summary(self) -> &'static str {
        let description = self.description();
        description
            .split_once("\n\n")
            .map_or(description, |(summary, _)| summary)
    }
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::ClockCheck => write!(f, "clock_check"),
            ActionType::Confirm => write!(f, "confirm"),
            ActionType::CheckValue => write!(f, "check_value"),
            ActionType::OralReadback => write!(f, "oral_readback"),
            ActionType::Reveal => write!(f, "reveal"),
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
            ActionType::EnterShare => write!(f, "enter_share"),
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

/// What kind of output a ceremony produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputType {
    /// A public key.
    PublicKey,
    /// A key wrapped for transport, in the container its scheme names.
    WrappedKey,
    /// Content encrypted for a recipient, in the container its scheme names.
    EncryptedData,
    /// An X.509 certificate.
    Certificate,
    /// A signed DNSSEC resource record set.
    SignedRrset,
    /// A Certificate Transparency signed certificate timestamp.
    Sct,

    // Documents
    /// A document.
    Document,
    /// A ceremony log or transcript.
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

/// What kind of value a ceremony parameter takes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ParameterType {
    /// Text.
    String,
    /// A date in `YYYY-MM-DD` format.
    Date,
    /// A whole number.
    Integer,
    /// A Boolean value, `true` or `false`.
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

/// What kind of duty is done after the run.
///
/// Each kind gives the duty a text for the script, used when it has no
/// `description`. Use `custom` for any other duty, with a `description`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DutyType {
    /// Return materials to secure storage.
    ReturnToVault,
    /// Give the shares to their custodians.
    DistributeShares,
    /// Give the backup media to its recipients.
    DistributeMedia,
    /// Store the ceremony's materials in an archive.
    ArchiveMaterials,
    /// Publish the ceremony record and witness attestations.
    PublishRecord,
    /// Notify stakeholders that the ceremony is complete.
    NotifyStakeholders,
    /// Import the generated keys into the system that uses them.
    ImportKeys,
    /// A duty described in `description`.
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
            (ActionType::Reveal, "\"reveal\""),
            (ActionType::MachineInfo, "\"machine_info\""),
            (ActionType::GenerateKey, "\"generate_key\""),
            (ActionType::WrapKey, "\"wrap_key\""),
            (ActionType::UnwrapKey, "\"unwrap_key\""),
            (ActionType::ImportKey, "\"import_key\""),
            (ActionType::EncryptData, "\"encrypt_data\""),
            (ActionType::DecryptData, "\"decrypt_data\""),
            (ActionType::SplitSecret, "\"split_secret\""),
            (ActionType::CombineShares, "\"combine_shares\""),
            (ActionType::EnterShare, "\"enter_share\""),
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
            ActionType::Reveal,
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

    /// `vocabulary!` builds each `ALL` and `as_str` from one list, so neither
    /// can miss a variant. Each name parses back, and is the name serde
    /// writes, which for a derived serde is a second spelling.
    #[test]
    fn every_vocabulary_lists_every_value_under_its_serde_name() {
        use crate::{Format, RevealFormat};

        fn check<T>(all: &[T])
        where
            T: Copy + PartialEq + std::fmt::Debug + std::fmt::Display + Serialize,
            T: std::str::FromStr,
        {
            for &value in all {
                let name = value.to_string();
                assert!(
                    matches!(name.parse::<T>(), Ok(parsed) if parsed == value),
                    "{name}"
                );
                assert_eq!(serde_json::to_value(value).unwrap(), name.as_str());
            }
        }

        check(CertProfile::ALL);
        check(SharingScheme::ALL);
        check(RevealFormat::ALL);
        check(Format::ALL);
    }

    /// serde, `FromStr` and the schema accept the same names, aliases
    /// included, for every vocabulary whose schema is its names.
    #[test]
    fn a_vocabulary_schema_accepts_what_serde_reads() {
        use crate::params::ReadbackFormat;

        fn check<T>()
        where
            T: Vocabulary + std::fmt::Debug + PartialEq + schemars::JsonSchema,
            T: serde::de::DeserializeOwned,
        {
            let schema = schemars::schema_for!(T);
            let listed: Vec<&str> = schema
                .get("enum")
                .and_then(|names| names.as_array())
                .unwrap()
                .iter()
                .filter_map(|name| name.as_str())
                .collect();
            let named = T::VALUES.iter().map(|&value| (value.name(), value));
            let mut expected = Vec::new();
            for (name, value) in named.chain(T::ALIASES.iter().copied()) {
                assert_eq!(
                    serde_json::from_value::<T>(serde_json::json!(name)).unwrap(),
                    value
                );
                expected.push(name);
            }
            assert_eq!(listed, expected);
        }

        check::<CertProfile>();
        check::<SharingScheme>();
        check::<ReadbackFormat>();
        assert_eq!("intermediate_ca".parse(), Ok(CertProfile::SubCa));
        assert_eq!(
            serde_json::from_value::<ReadbackFormat>(serde_json::json!("nato")).unwrap(),
            ReadbackFormat::NatoPhonetic
        );
    }

    /// `ActionType::ALL` is written by hand, so it can fall behind the enum.
    ///
    /// The match below is exhaustive, so adding a variant fails to compile
    /// here. That is the whole mechanism: it puts a compiler error next to the
    /// list an author has to extend. The name check then catches a variant
    /// listed twice, and `every_action_is_described` compares `ALL` with the
    /// derived schema, which is what catches one left out.
    #[test]
    fn all_lists_every_action_type() {
        for action in ActionType::ALL {
            match action {
                ActionType::ClockCheck
                | ActionType::Confirm
                | ActionType::CheckValue
                | ActionType::OralReadback
                | ActionType::Reveal
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
                | ActionType::EnterShare
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

    /// The schema derived from the enum names every variant, so it holds
    /// `ALL` to the enum; and each action has a description whose summary
    /// is one sentence.
    #[test]
    fn every_action_is_described() {
        let schema = crate::params::generator().into_root_schema_for::<ActionType>();
        let derived: std::collections::BTreeSet<String> = schema
            .get("oneOf")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|variant| variant.get("const")?.as_str().map(str::to_string))
            .collect();
        let listed: std::collections::BTreeSet<String> =
            ActionType::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(
            derived, listed,
            "ActionType::ALL is out of step with the enum"
        );

        for &action in ActionType::ALL {
            let summary = action.summary();
            assert!(
                summary.ends_with('.') && !summary.trim_end_matches('.').contains(". "),
                "{action}: the summary is not one sentence: {summary:?}"
            );
        }
    }
}
