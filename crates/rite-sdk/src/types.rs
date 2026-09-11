//! Data types shared between the runtime and backend implementations.
//!
//! These types form the vocabulary of the backend interface: key specifications,
//! algorithm identifiers, attestation evidence, and hardware-specific metadata.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::backend::BackendError;
use crate::key_material::PublicKeyDer;

/// Opaque key identifier (backend-specific).
///
/// This is an opaque reference to a key managed by a backend. The internal
/// format is backend-specific (e.g., `"slot_9c"` for `YubiKey` PIV, UUID for
/// software backend).
///
/// Ceremony DSL never interprets the contents of a `KeyId`; it is purely a
/// reference that gets passed back to the backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new `KeyId` from a string.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Return the `KeyId` as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Metadata returned after key generation or import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Opaque backend-specific key identifier.
    pub key_id: KeyId,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Human-readable label.
    pub label: String,
    /// Public key, if the backend exports one.
    pub public_key: Option<PublicKeyDer>,
    /// Attestation evidence (if backend supports attestation).
    pub attestation: Option<Attestation>,
}

/// Key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// RSA 2048-bit key.
    Rsa2048,
    /// RSA 4096-bit key.
    Rsa4096,
    /// ECDSA with P-256 curve (secp256r1).
    EcdsaP256,
    /// ECDSA with P-384 curve (secp384r1).
    EcdsaP384,
    /// Ed25519 (`EdDSA`).
    Ed25519,
    /// ML-DSA-44, module-lattice signature at NIST security category 2 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65, module-lattice signature at NIST security category 3 (FIPS 204).
    MlDsa65,
    /// ML-DSA-87, module-lattice signature at NIST security category 5 (FIPS 204).
    MlDsa87,
    /// ML-KEM-512, module-lattice KEM at NIST security category 1 (FIPS 203).
    ///
    /// A KEM encapsulates, it does not sign. Such a key can receive a wrap and
    /// nothing else.
    MlKem512,
    /// ML-KEM-768, module-lattice KEM at NIST security category 3 (FIPS 203).
    MlKem768,
    /// ML-KEM-1024, module-lattice KEM at NIST security category 5 (FIPS 203).
    MlKem1024,
    /// AES 128-bit symmetric key.
    Aes128,
    /// AES 256-bit symmetric key.
    Aes256,
}

impl KeyAlgorithm {
    /// The signature algorithm to use with this key unless told otherwise.
    ///
    /// `None` for symmetric keys, which sign nothing.
    ///
    /// A key algorithm does not always determine a signature algorithm: RSA
    /// keys work with both PKCS#1 v1.5 and PSS, and this picks v1.5 for
    /// interoperability. Everywhere else the pairing is forced, either by the
    /// curve's matching digest strength (RFC 5480) or by the scheme naming its
    /// own digest (Ed25519, ML-DSA).
    #[must_use]
    pub fn default_sign_algorithm(self) -> Option<SignAlgorithm> {
        match self {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => Some(SignAlgorithm::RsaPkcs1Sha256),
            KeyAlgorithm::EcdsaP256 => Some(SignAlgorithm::EcdsaSha256),
            KeyAlgorithm::EcdsaP384 => Some(SignAlgorithm::EcdsaSha384),
            KeyAlgorithm::Ed25519 => Some(SignAlgorithm::Ed25519),
            KeyAlgorithm::MlDsa44 => Some(SignAlgorithm::MlDsa44),
            KeyAlgorithm::MlDsa65 => Some(SignAlgorithm::MlDsa65),
            KeyAlgorithm::MlDsa87 => Some(SignAlgorithm::MlDsa87),
            KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024
            | KeyAlgorithm::Aes128
            | KeyAlgorithm::Aes256 => None,
        }
    }

    /// Whether a key of this algorithm can be the recipient of a wrap.
    ///
    /// A recipient has to be able to receive a content-encryption key, by key
    /// transport, key agreement, or encapsulation. A signature algorithm can
    /// do none of the three, however good a key it otherwise is, and finding
    /// that out mid-ceremony is how it used to surface.
    #[must_use]
    pub fn can_receive_wrap(self) -> bool {
        match self {
            KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa4096
            | KeyAlgorithm::EcdsaP256
            | KeyAlgorithm::EcdsaP384
            | KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024 => true,

            // Ed25519 and ML-DSA sign and nothing else. A symmetric key is a
            // pre-shared KEK, which is a different recipient form than the
            // ones Rite produces.
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::MlDsa44
            | KeyAlgorithm::MlDsa65
            | KeyAlgorithm::MlDsa87
            | KeyAlgorithm::Aes128
            | KeyAlgorithm::Aes256 => false,
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            KeyAlgorithm::Rsa4096 => write!(f, "RSA-4096"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyAlgorithm::EcdsaP384 => write!(f, "ECDSA-P384"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            KeyAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            KeyAlgorithm::MlDsa87 => write!(f, "ML-DSA-87"),
            KeyAlgorithm::MlKem512 => write!(f, "ML-KEM-512"),
            KeyAlgorithm::MlKem768 => write!(f, "ML-KEM-768"),
            KeyAlgorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            KeyAlgorithm::Aes128 => write!(f, "AES-128"),
            KeyAlgorithm::Aes256 => write!(f, "AES-256"),
        }
    }
}

/// Error returned when parsing an SDK algorithm identifier from a string fails.
///
/// Shared across all algorithm enums in this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown value: {0:?}")]
pub struct ParseError(String);

impl std::str::FromStr for KeyAlgorithm {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RSA-2048" => Ok(Self::Rsa2048),
            "RSA-4096" => Ok(Self::Rsa4096),
            "ECDSA-P256" => Ok(Self::EcdsaP256),
            "ECDSA-P384" => Ok(Self::EcdsaP384),
            "Ed25519" => Ok(Self::Ed25519),
            "ML-DSA-44" => Ok(Self::MlDsa44),
            "ML-DSA-65" => Ok(Self::MlDsa65),
            "ML-DSA-87" => Ok(Self::MlDsa87),
            "ML-KEM-512" => Ok(Self::MlKem512),
            "ML-KEM-768" => Ok(Self::MlKem768),
            "ML-KEM-1024" => Ok(Self::MlKem1024),
            "AES-128" => Ok(Self::Aes128),
            "AES-256" => Ok(Self::Aes256),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

impl From<KeyAlgorithm> for String {
    fn from(a: KeyAlgorithm) -> String {
        a.to_string()
    }
}

impl TryFrom<String> for KeyAlgorithm {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

bitflags::bitflags! {
    /// Key usage flags. Maps to PKCS#11 `CKA_SIGN`, `CKA_VERIFY`, etc.
    ///
    /// PIV ignores these (slot determines usage). PKCS#11 requires them at creation.
    /// Using bitflags rather than 7 bools: more compact for serialization, makes
    /// set operations natural, and avoids nonsensical bool combinations.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct KeyUsages: u8 {
        /// Key may be used to sign data.
        const SIGN    = 0b0000_0001;
        /// Key may be used to verify signatures.
        const VERIFY  = 0b0000_0010;
        /// Key may be used to encrypt data.
        const ENCRYPT = 0b0000_0100;
        /// Key may be used to decrypt data.
        const DECRYPT = 0b0000_1000;
        /// Key may be used to wrap other keys.
        const WRAP    = 0b0001_0000;
        /// Key may be used to unwrap other keys.
        const UNWRAP  = 0b0010_0000;
        /// Key may be used to derive other keys.
        const DERIVE  = 0b0100_0000;
    }
}

impl KeyUsages {
    /// Every usage, paired with the name a ceremony writes for it.
    ///
    /// The names are PKCS#11 vocabulary. They say what a key is permitted to do
    /// at the token, which is a different question from the `KeyUsage`
    /// extension a certificate carries.
    pub const NAMED: [(&'static str, KeyUsages); 7] = [
        ("sign", KeyUsages::SIGN),
        ("verify", KeyUsages::VERIFY),
        ("encrypt", KeyUsages::ENCRYPT),
        ("decrypt", KeyUsages::DECRYPT),
        ("wrap", KeyUsages::WRAP),
        ("unwrap", KeyUsages::UNWRAP),
        ("derive", KeyUsages::DERIVE),
    ];

    /// Look up a single usage by its ceremony name.
    ///
    /// Named to avoid colliding with the bitflags-generated `from_name`,
    /// which matches on the `SCREAMING_CASE` constant names instead.
    #[must_use]
    pub fn usage_named(name: &str) -> Option<Self> {
        Self::NAMED
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, usage)| *usage)
    }

    /// The names of the usages in this set, in declaration order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        Self::NAMED
            .iter()
            .filter(|(_, usage)| self.contains(*usage))
            .map(|(name, _)| *name)
            .collect()
    }

    /// Every usage name a ceremony may write, for a message listing what is
    /// available.
    #[must_use]
    pub fn all_names() -> Vec<&'static str> {
        Self::NAMED.iter().map(|(name, _)| *name).collect()
    }

    /// The usages in this set as one phrase, for an error message.
    #[must_use]
    pub fn describe(self) -> String {
        let names = self.names();
        if names.is_empty() {
            "nothing".to_string()
        } else {
            names.join(", ")
        }
    }
}

/// Security and usage policy for a generated or imported key.
///
/// Backends that cannot honour a requested policy MUST return
/// `BackendError::OperationNotPermitted` rather than silently ignoring it.
/// For example, a PIV backend receiving `extractable: true` must reject it
/// because PIV keys are always non-extractable by hardware design.
// Each bool maps directly to a named PKCS#11 boolean attribute (CKA_TOKEN,
// CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_WRAP_WITH_TRUSTED). Converting these
// to two-variant enums would add type noise with no semantic benefit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPolicy {
    /// Key persists after session ends. Always `true` for PIV. `CKA_TOKEN` in PKCS#11.
    pub persistent: bool,
    /// Key material never revealed in plaintext. Always `true` for PIV. `CKA_SENSITIVE`.
    pub sensitive: bool,
    /// Key can be wrapped and exported. Always `false` for PIV. `CKA_EXTRACTABLE`.
    pub extractable: bool,
    /// Key can only be wrapped by a `CKA_TRUSTED` wrapping key. PKCS#11 `CKA_WRAP_WITH_TRUSTED`.
    pub wrap_with_trusted_only: bool,
    /// What operations this key is permitted to perform.
    pub usages: KeyUsages,
}

impl KeyPolicy {
    /// Refuse an operation this policy does not allow.
    ///
    /// The policy is what the ceremony asked for at generation. A token
    /// enforces it itself; a software backend has no token, so it calls this.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::OperationNotPermitted`] when `usage` is absent
    /// from the policy, naming what the key may do instead.
    pub fn require(&self, usage: KeyUsages, operation: &str) -> Result<(), BackendError> {
        if self.usages.contains(usage) {
            return Ok(());
        }
        Err(BackendError::OperationNotPermitted(format!(
            "this key may not {operation}: its policy allows {}. \
             Declare the usage under `policy:` on the step that generates it.",
            self.usages.describe()
        )))
    }
}

impl Default for KeyPolicy {
    /// Most secure configuration for ceremony signing keys:
    /// persistent=true, sensitive=true, extractable=false, sign+verify only.
    fn default() -> Self {
        Self {
            persistent: true,
            sensitive: true,
            extractable: false,
            wrap_with_trusted_only: false,
            usages: KeyUsages::SIGN | KeyUsages::VERIFY,
        }
    }
}

/// Full specification for key generation or import.
///
/// Replaces the `(algorithm, label, slot_hint)` triplet with a structured type
/// that can carry PKCS#11 policy attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySpec {
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Human-readable label.
    pub label: String,
    /// Security and usage policy.
    pub policy: KeyPolicy,
    /// Backend-specific location hint.
    /// PIV: "9c" maps to Signature slot. PKCS#11: slot index or partition label.
    /// Software: ignored.
    pub location_hint: Option<String>,
}

/// PKCS#11 key security attributes read from an HSM after key generation.
///
/// Records HSM-managed attribute state as evidence of key provenance and
/// policy compliance in the ceremony transcript.
// Each bool maps directly to a named PKCS#11 boolean attribute (CKA_ALWAYS_SENSITIVE,
// CKA_NEVER_EXTRACTABLE, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_WRAP_WITH_TRUSTED).
// These are distinct concepts; collapsing them into enums would obscure the PKCS#11 semantics.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySecurityAttributes {
    /// Key was ALWAYS sensitive: never had `CKA_SENSITIVE=false` since creation.
    /// This is the primary provenance indicator for PKCS#11 keys.
    pub always_sensitive: bool,
    /// Key was NEVER extractable: never had `CKA_EXTRACTABLE=true` since creation.
    pub never_extractable: bool,
    /// Current value of `CKA_SENSITIVE`.
    pub sensitive: bool,
    /// Current value of `CKA_EXTRACTABLE`.
    pub extractable: bool,
    /// Key can only be wrapped by a key with `CKA_TRUSTED=true` (`CKA_WRAP_WITH_TRUSTED`).
    pub wrap_with_trusted_only: bool,
    /// What operations this key is permitted to perform (read from key object).
    pub usages: KeyUsages,
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum SignAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1Sha256,
    /// RSASSA-PSS with SHA-256.
    RsaPssSha256,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// Ed25519 (pure `EdDSA`, no hash function).
    Ed25519,
    /// ML-DSA-44 (pure, no pre-hash). FIPS 204.
    MlDsa44,
    /// ML-DSA-65 (pure, no pre-hash). FIPS 204.
    MlDsa65,
    /// ML-DSA-87 (pure, no pre-hash). FIPS 204.
    MlDsa87,
}

impl SignAlgorithm {
    /// A representative key algorithm for this signature algorithm.
    ///
    /// Used where a signature request must be turned into a concrete key
    /// algorithm: selecting a card algorithm, or minting a stand-in key for a
    /// rehearsal. Keeping that mapping here means those callers cannot drift
    /// apart from each other.
    ///
    /// The mapping is deliberately lossy for RSA: both RSA schemes answer
    /// `Rsa2048`, because a signature algorithm does not name a modulus size.
    /// Use [`accepts_key`](Self::accepts_key) to test whether a key may be used
    /// with this algorithm; the equality `alg.key_algorithm() == key` is not
    /// that test and rejects RSA-4096 keys.
    #[must_use]
    pub fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            SignAlgorithm::RsaPkcs1Sha256 | SignAlgorithm::RsaPssSha256 => KeyAlgorithm::Rsa2048,
            SignAlgorithm::EcdsaSha256 => KeyAlgorithm::EcdsaP256,
            SignAlgorithm::EcdsaSha384 => KeyAlgorithm::EcdsaP384,
            SignAlgorithm::Ed25519 => KeyAlgorithm::Ed25519,
            SignAlgorithm::MlDsa44 => KeyAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65 => KeyAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87 => KeyAlgorithm::MlDsa87,
        }
    }

    /// Whether a key of `key_algorithm` may be used with this signature algorithm.
    ///
    /// The compatibility check every signing backend needs, kept in one place.
    /// Curve and parameter set are pinned: ECDSA-SHA256 will not take a P-384
    /// key. Only the RSA schemes span more than one key algorithm, since they
    /// are defined for any modulus size.
    #[must_use]
    pub fn accepts_key(self, key_algorithm: KeyAlgorithm) -> bool {
        match self {
            SignAlgorithm::RsaPkcs1Sha256 | SignAlgorithm::RsaPssSha256 => {
                matches!(key_algorithm, KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096)
            }
            // Every other scheme pins exactly one key algorithm, already named
            // by `key_algorithm`. Reuse it rather than repeating the pairing.
            SignAlgorithm::EcdsaSha256
            | SignAlgorithm::EcdsaSha384
            | SignAlgorithm::Ed25519
            | SignAlgorithm::MlDsa44
            | SignAlgorithm::MlDsa65
            | SignAlgorithm::MlDsa87 => self.key_algorithm() == key_algorithm,
        }
    }
}

impl fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignAlgorithm::RsaPkcs1Sha256 => write!(f, "RSA-PKCS1-SHA256"),
            SignAlgorithm::RsaPssSha256 => write!(f, "RSA-PSS-SHA256"),
            SignAlgorithm::EcdsaSha256 => write!(f, "ECDSA-SHA256"),
            SignAlgorithm::EcdsaSha384 => write!(f, "ECDSA-SHA384"),
            SignAlgorithm::Ed25519 => write!(f, "Ed25519"),
            SignAlgorithm::MlDsa44 => write!(f, "ML-DSA-44"),
            SignAlgorithm::MlDsa65 => write!(f, "ML-DSA-65"),
            SignAlgorithm::MlDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

impl std::str::FromStr for SignAlgorithm {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RSA-PKCS1-SHA256" => Ok(Self::RsaPkcs1Sha256),
            "RSA-PSS-SHA256" => Ok(Self::RsaPssSha256),
            "ECDSA-SHA256" => Ok(Self::EcdsaSha256),
            "ECDSA-SHA384" => Ok(Self::EcdsaSha384),
            "Ed25519" => Ok(Self::Ed25519),
            "ML-DSA-44" => Ok(Self::MlDsa44),
            "ML-DSA-65" => Ok(Self::MlDsa65),
            "ML-DSA-87" => Ok(Self::MlDsa87),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

impl From<SignAlgorithm> for String {
    fn from(a: SignAlgorithm) -> String {
        a.to_string()
    }
}

impl TryFrom<String> for SignAlgorithm {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// An ASN.1 object identifier in dotted-decimal form.
///
/// Wrapping evidence is a set of algorithm identifiers read back out of the
/// produced artifact, so the OID is the value that gets recorded. Held as text
/// because that is what a transcript reader compares against a registry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Oid(String);

impl Oid {
    /// Parse a dotted-decimal OID.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] unless the value is two or more arcs of decimal
    /// digits separated by dots.
    pub fn new(value: &str) -> Result<Self, ParseError> {
        let arcs: Vec<&str> = value.split('.').collect();
        let well_formed = arcs.len() >= 2
            && arcs
                .iter()
                .all(|arc| !arc.is_empty() && arc.bytes().all(|b| b.is_ascii_digit()));
        if well_formed {
            Ok(Self(value.to_owned()))
        } else {
            Err(ParseError(value.to_owned()))
        }
    }

    /// The dotted-decimal form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Oid> for String {
    fn from(oid: Oid) -> String {
        oid.0
    }
}

impl TryFrom<String> for Oid {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Oid::new(&s)
    }
}

/// Well-known OIDs the wrapping paths produce or check.
pub mod oid {
    /// `rsaEncryption`, RSAES-PKCS1-v1.5 key transport (RFC 8017).
    pub const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
    /// `id-RSAES-OAEP` (RFC 8017).
    pub const RSAES_OAEP: &str = "1.2.840.113549.1.1.7";
    /// `dhSinglePass-stdDH-sha1kdf-scheme`, one-pass ECDH with the X9.63 KDF
    /// over SHA-1 (RFC 5753).
    pub const DH_SINGLE_PASS_STDDH_SHA1KDF: &str = "1.3.133.16.840.63.0.2";
    /// `id-aes256-GCM` (RFC 5084).
    pub const AES_256_GCM: &str = "2.16.840.1.101.3.4.1.46";
    /// `id-aes256-CBC` (RFC 3565).
    pub const AES_256_CBC: &str = "2.16.840.1.101.3.4.1.42";
    /// `id-aes256-wrap`, AES Key Wrap with a 256-bit KEK (RFC 3394).
    pub const AES_256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
    /// `id-aes128-wrap`, AES Key Wrap with a 128-bit KEK (RFC 3394).
    pub const AES_128_WRAP: &str = "2.16.840.1.101.3.4.1.5";
    /// `id-aes256-wrap-pad`, AES Key Wrap with Padding (RFC 5649).
    pub const AES_256_WRAP_PAD: &str = "2.16.840.1.101.3.4.1.48";
}

/// How a CMS structure conveys the content-encryption key to its recipient.
///
/// The variants are the `RecipientInfo` CHOICE of RFC 5652 §6.2, plus the
/// KEM alternative RFC 9629 carries inside `OtherRecipientInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipientInfoKind {
    /// `KeyTransRecipientInfo`: the CEK is encrypted under the recipient's
    /// public key.
    Ktri,
    /// `KeyAgreeRecipientInfo`: a shared secret is agreed with the recipient's
    /// key, run through a KDF, and used to wrap the CEK.
    Kari,
    /// `KEKRecipientInfo`: the CEK is wrapped under a previously shared
    /// symmetric key.
    Kekri,
    /// `KEMRecipientInfo` (RFC 9629), carried as `OtherRecipientInfo`.
    Kemri,
    /// `PasswordRecipientInfo`.
    Pwri,
    /// An `OtherRecipientInfo` this build does not recognise.
    Ori,
}

impl fmt::Display for RecipientInfoKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecipientInfoKind::Ktri => write!(f, "ktri"),
            RecipientInfoKind::Kari => write!(f, "kari"),
            RecipientInfoKind::Kekri => write!(f, "kekri"),
            RecipientInfoKind::Kemri => write!(f, "kemri"),
            RecipientInfoKind::Pwri => write!(f, "pwri"),
            RecipientInfoKind::Ori => write!(f, "ori"),
        }
    }
}

/// What a wrap actually did.
///
/// The scheme a step requests names a family. The algorithms inside it move
/// independently: the recipient's key type selects the encapsulation, the
/// content cipher selects the KEK size, and the KDF digest is a library
/// default rather than a property of any key.
///
/// Where the scheme is self-describing this is an observation, re-derivable
/// from the blob alone, which is what makes it evidence. Where it is not, it
/// is what the backend invoked. [`WrapScheme::is_self_describing`] is the
/// difference, and `rite verify` reports the two differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WrapDescription {
    /// How the CEK reaches the recipient, for a scheme built on CMS.
    ///
    /// Absent for a raw mechanism, whose output carries no `RecipientInfo`
    /// and no other ASN.1 structure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_info: Option<RecipientInfoKind>,
    /// The key-encryption algorithm: key transport for `ktri`, the
    /// key-agreement scheme for `kari`.
    pub key_encryption_oid: Oid,
    /// The KDF, where the encapsulation derives a KEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf_oid: Option<Oid>,
    /// The algorithm wrapping the CEK under the derived KEK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek_wrap_oid: Option<Oid>,
    /// The content cipher, for schemes that encrypt the key as CMS content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encryption_oid: Option<Oid>,
}

impl WrapDescription {
    /// Describe a CMS wrap by its recipient info and key-encryption algorithm.
    #[must_use]
    pub fn new(recipient_info: RecipientInfoKind, key_encryption_oid: Oid) -> Self {
        Self {
            recipient_info: Some(recipient_info),
            key_encryption_oid,
            kdf_oid: None,
            kek_wrap_oid: None,
            content_encryption_oid: None,
        }
    }

    /// Describe a raw mechanism, which has no CMS structure around it.
    #[must_use]
    pub fn raw(key_encryption_oid: Oid) -> Self {
        Self {
            recipient_info: None,
            key_encryption_oid,
            kdf_oid: None,
            kek_wrap_oid: None,
            content_encryption_oid: None,
        }
    }

    /// Record the KDF the encapsulation ran.
    #[must_use]
    pub fn with_kdf(mut self, oid: Oid) -> Self {
        self.kdf_oid = Some(oid);
        self
    }

    /// Record the algorithm that wrapped the CEK under the derived KEK.
    #[must_use]
    pub fn with_kek_wrap(mut self, oid: Oid) -> Self {
        self.kek_wrap_oid = Some(oid);
        self
    }

    /// Record the content cipher.
    #[must_use]
    pub fn with_content_encryption(mut self, oid: Oid) -> Self {
        self.content_encryption_oid = Some(oid);
        self
    }

    /// Whether the CMS content was encrypted under an authenticated cipher.
    ///
    /// This asks about a CMS content cipher and nothing else, so it is `false`
    /// for every raw mechanism, including ones that authenticate by other
    /// means. [`WrapScheme::is_authenticated`] is the question to ask of a
    /// scheme.
    #[must_use]
    pub fn content_is_authenticated(&self) -> bool {
        self.content_encryption_oid
            .as_ref()
            .is_some_and(|oid| oid.as_str() == oid::AES_256_GCM)
    }
}

/// The wrapping scheme a step requests, or a backend reports.
///
/// A scheme names a container and the parts of it Rite fixes. What varies
/// with the recipient is recorded in [`WrapDescription`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum WrapScheme {
    /// CMS `AuthEnvelopedData` (RFC 5083) with AES-256-GCM content
    /// encryption. Output: CMS `ContentInfo` DER.
    ///
    /// The encapsulation follows the recipient key: RSA takes key transport,
    /// EC takes the RFC 5753 key-agreement path.
    ///
    /// `CMS-RSA-CBC`, the `EnvelopedData` variant with AES-256-CBC, was
    /// removed. It carried no integrity protection, so unwrapping imported
    /// whatever decrypted; PCI PIN v3.1 requirement 18-3 bans unauthenticated
    /// key encryption. Restoring it would take an authenticated construction
    /// around it, which is what the deployments that do use CBC (X9 TR-34,
    /// AD CS key archival) wrap it in.
    CmsAes256Gcm,
    /// RSAES-OAEP with SHA-256, as raw ciphertext (RFC 8017).
    ///
    /// Output is exactly the modulus size and describes nothing about itself.
    /// The payload ceiling is `k - 2*hLen - 2`: 190 bytes under RSA-2048, 446
    /// under RSA-4096, which fits a symmetric key or an EC private key and
    /// never fits an RSA one. [`Self::RsaAesKeyWrapSha256`] exists for that.
    RsaOaepSha256,
    /// RSA-AES key wrap with SHA-256 (PKCS#11 `CKM_RSA_AES_KEY_WRAP`).
    ///
    /// An ephemeral AES key under RSAES-OAEP, concatenated with the payload
    /// under AES-KWP (RFC 5649). The OAEP part comes first and is exactly the
    /// modulus size, which is how a recipient splits the two.
    ///
    /// This is the shape cloud KMS import expects, and it carries no size
    /// ceiling. The digest is in the name because it is not recoverable from
    /// the bytes and recipients differ: AWS names both `RSA_AES_KEY_WRAP_SHA_256`
    /// and `RSA_AES_KEY_WRAP_SHA_1`, and Azure BYOK specifies SHA-1.
    RsaAesKeyWrapSha256,
}

impl WrapScheme {
    /// The description this scheme fixes, where it fixes one.
    ///
    /// `None` for a self-describing scheme: what a CMS wrap did follows the
    /// recipient key, so it is read out of the artifact rather than known in
    /// advance. A raw mechanism has no such freedom, which is the same fact
    /// that makes its description an assertion.
    ///
    /// This is the one place that says what a raw scheme produces. A backend
    /// builds its description from here rather than restating the OIDs, and
    /// [`permits`](Self::permits) compares against it, so the two cannot
    /// disagree.
    #[must_use]
    pub fn fixed_description(self) -> Option<WrapDescription> {
        // Constructed directly rather than through the validating `Oid::new`:
        // these are this module's own constants, so there is no input to
        // reject and no error a caller could act on.
        let known = |value: &str| Oid(value.to_owned());
        match self {
            WrapScheme::CmsAes256Gcm => None,
            WrapScheme::RsaOaepSha256 => Some(WrapDescription::raw(known(oid::RSAES_OAEP))),
            WrapScheme::RsaAesKeyWrapSha256 => Some(
                WrapDescription::raw(known(oid::RSAES_OAEP))
                    .with_kek_wrap(known(oid::AES_256_WRAP_PAD)),
            ),
        }
    }

    /// Whether a key of this algorithm can receive a wrap under this scheme.
    ///
    /// Narrower than [`KeyAlgorithm::can_receive_wrap`], which answers for CMS,
    /// where the recipient key selects the encapsulation. The raw mechanisms
    /// are RSA constructions and accept nothing else.
    #[must_use]
    pub fn accepts_recipient(self, algorithm: KeyAlgorithm) -> bool {
        match self {
            WrapScheme::CmsAes256Gcm => algorithm.can_receive_wrap(),
            WrapScheme::RsaOaepSha256 | WrapScheme::RsaAesKeyWrapSha256 => match algorithm {
                KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => true,
                KeyAlgorithm::EcdsaP256
                | KeyAlgorithm::EcdsaP384
                | KeyAlgorithm::Ed25519
                | KeyAlgorithm::MlDsa44
                | KeyAlgorithm::MlDsa65
                | KeyAlgorithm::MlDsa87
                | KeyAlgorithm::MlKem512
                | KeyAlgorithm::MlKem768
                | KeyAlgorithm::MlKem1024
                | KeyAlgorithm::Aes128
                | KeyAlgorithm::Aes256 => false,
            },
        }
    }

    /// Whether `description` is one this scheme admits.
    ///
    /// The check is what keeps a recorded scheme from contradicting the
    /// artifact it labels. For a self-describing scheme it is a structural
    /// test against what was read out of the bytes; for a raw mechanism the
    /// description is fixed, so equality is the whole test.
    #[must_use]
    pub fn permits(self, description: &WrapDescription) -> bool {
        if let Some(fixed) = self.fixed_description() {
            return *description == fixed;
        }
        let encapsulation_fits = matches!(
            description.recipient_info,
            Some(RecipientInfoKind::Ktri | RecipientInfoKind::Kari | RecipientInfoKind::Kemri)
        );
        description.content_is_authenticated() && encapsulation_fits
    }

    /// Whether a verifier can re-derive the wrap's algorithms from the bytes.
    ///
    /// This is the line between evidence and assertion. A CMS artifact carries
    /// its own algorithm identifiers, so `rite verify` reads them back and
    /// compares them against the transcript; raw mechanism output carries
    /// nothing, so the recorded algorithms are what the backend reports having
    /// invoked and no offline check can confirm them.
    ///
    /// Matched exhaustively on purpose: a scheme added without answering this
    /// would otherwise default into being treated as evidence.
    #[must_use]
    pub fn is_self_describing(self) -> bool {
        match self {
            WrapScheme::CmsAes256Gcm => true,
            WrapScheme::RsaOaepSha256 | WrapScheme::RsaAesKeyWrapSha256 => false,
        }
    }
}

impl fmt::Display for WrapScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapScheme::CmsAes256Gcm => write!(f, "CMS-AES-256-GCM"),
            WrapScheme::RsaOaepSha256 => write!(f, "RSA-OAEP-SHA256"),
            WrapScheme::RsaAesKeyWrapSha256 => write!(f, "RSA-AES-KEY-WRAP-SHA256"),
        }
    }
}

impl std::str::FromStr for WrapScheme {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CMS-AES-256-GCM" => Ok(Self::CmsAes256Gcm),
            "RSA-OAEP-SHA256" => Ok(Self::RsaOaepSha256),
            "RSA-AES-KEY-WRAP-SHA256" => Ok(Self::RsaAesKeyWrapSha256),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

impl From<WrapScheme> for String {
    fn from(a: WrapScheme) -> String {
        a.to_string()
    }
}

impl TryFrom<String> for WrapScheme {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A wrapped key, the scheme that produced it, and what that wrap did.
///
/// The three are constructed together and read together: a scheme that does
/// not admit the description would label the bytes with something the bytes
/// contradict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "WrappedKeyRepr")]
pub struct WrappedKey {
    scheme: WrapScheme,
    description: WrapDescription,
    data: Vec<u8>,
}

/// Deserialization shape for [`WrappedKey`], re-checked on the way in.
#[derive(Deserialize)]
struct WrappedKeyRepr {
    scheme: WrapScheme,
    description: WrapDescription,
    data: Vec<u8>,
}

impl TryFrom<WrappedKeyRepr> for WrappedKey {
    type Error = IncoherentWrap;

    fn try_from(repr: WrappedKeyRepr) -> Result<Self, Self::Error> {
        WrappedKey::new(repr.scheme, repr.description, repr.data)
    }
}

/// A wrapped key was labelled with a scheme its own description contradicts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("scheme {scheme} does not admit this wrap: {description:?}")]
pub struct IncoherentWrap {
    /// The scheme the wrap was labelled with.
    pub scheme: WrapScheme,
    /// What the artifact says was done.
    pub description: WrapDescription,
}

impl WrappedKey {
    /// Pair wrapped bytes with the scheme and the description of the wrap.
    ///
    /// # Errors
    ///
    /// Returns [`IncoherentWrap`] if the scheme does not admit the
    /// description.
    pub fn new(
        scheme: WrapScheme,
        description: WrapDescription,
        data: Vec<u8>,
    ) -> Result<Self, IncoherentWrap> {
        if scheme.permits(&description) {
            Ok(Self {
                scheme,
                description,
                data,
            })
        } else {
            Err(IncoherentWrap {
                scheme,
                description,
            })
        }
    }

    /// The scheme this key was wrapped under.
    #[must_use]
    pub fn scheme(&self) -> WrapScheme {
        self.scheme
    }

    /// What the wrap did, read back from the artifact.
    #[must_use]
    pub fn description(&self) -> &WrapDescription {
        &self.description
    }

    /// The wrapped bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// The kind of attestation evidence a backend can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttestationKind {
    /// Vendor cert chain proving on-device generation. Independently verifiable
    /// against a public manufacturer root CA.
    /// Examples: `YubiKey` F9 attestation, Thales Luna PKC (Public Key Confirmation).
    HardwareCertChain,
    /// TPM signed quote over PCR values with nonce. Proves platform state.
    TpmQuote,
    /// PKCS#11 attribute flags: `CKA_ALWAYS_SENSITIVE=true` + `CKA_NEVER_EXTRACTABLE=true`.
    /// Trustworthy within the HSM's trust boundary but not independently
    /// cryptographically verifiable.
    Pkcs11Attributes,
}

/// Structured attestation evidence with a discriminant kind.
///
/// The `kind` field tells consumers what they're looking at and how to verify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// What kind of attestation this is.
    pub kind: AttestationKind,
    /// DER-encoded certificate chain. Leaf first, then intermediates, then root (if known).
    /// Empty for `Pkcs11Attributes` kind.
    pub certificates: Vec<Vec<u8>>,
    /// Raw signature bytes (if applicable). None for attribute-based attestation.
    pub signature: Option<Vec<u8>>,
    /// Additional metadata (key attributes, slot info, etc.) for transcript recording.
    pub metadata: serde_json::Value,
}

/// Device information for platform attestation.
///
/// Collected from the system running the ceremony. Machine IDs are hashed
/// (SHA-256) for privacy before inclusion in evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// System hostname.
    pub hostname: String,
    /// Hashed machine ID (SHA-256, format: "sha256:hexhash").
    /// None if machine ID not available on this platform.
    pub machine_id: Option<String>,
    /// CPU model string.
    pub cpu_model: Option<String>,
    /// Operating system name.
    pub os_name: Option<String>,
    /// Operating system version.
    pub os_version: Option<String>,
    /// Kernel version.
    pub kernel_version: Option<String>,
}

/// PIV key slot identifiers.
///
/// Defined by NIST SP 800-73-5 Part 1, Table 4b ("PIV Card Application Card
/// Command Interface: Key References"). These slot assignments are fixed by
/// the standard and MUST NOT be changed.
///
/// # Standard references
/// - NIST SP 800-73-5 Part 1, §3.1.2: Key References
/// - NIST SP 800-73-5 Part 2, §3.2: GENERAL AUTHENTICATE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PivSlot {
    /// Slot 9A: PIV Authentication Key.
    /// Used for card/cardholder authentication (e.g. system login).
    /// PIN required once per session.
    /// [NIST SP 800-73-5 Part 1, §3.1.2]
    Authentication,

    /// Slot 9C: Digital Signature Key.
    /// Used for document/code signing. PIN required before EVERY
    /// private key operation ("PIN Always" access rule).
    /// Data to be signed is hashed off-card.
    /// [NIST SP 800-73-5 Part 1, §3.1.2; Part 2, §3.2.4]
    Signature,

    /// Slot 9D: Key Management Key.
    /// Used for key establishment (encryption/decryption).
    /// PIN required once per session.
    /// [NIST SP 800-73-5 Part 1, §3.1.2]
    KeyManagement,

    /// Slot 9E: Card Authentication Key.
    /// Used for physical access (e.g. PIV-enabled door locks).
    /// NO PIN required for private key operations.
    /// [NIST SP 800-73-5 Part 1, §3.1.2]
    CardAuthentication,

    /// Retired Key Management Key slot.
    ///
    /// Holds a previously used Key Management key for decrypting historical
    /// documents. The inner value is an index in `0..=19`, where 0 corresponds
    /// to PIV key reference 0x82 and 19 corresponds to 0x95.
    ///
    /// Construct with [`PivSlot::retired`] to enforce the valid range.
    /// [NIST SP 800-73-5 Part 1, §3.1.2]
    Retired(u8),
}

impl PivSlot {
    /// Create a retired key management slot from an index in `0..=19`.
    ///
    /// Returns `None` if `index` is out of the valid range.
    /// The 20 retired slots correspond to PIV key references 0x82–0x95.
    pub fn retired(index: u8) -> Option<Self> {
        (index <= 19).then_some(Self::Retired(index))
    }
}

/// Unified certificate addressing across backend types.
///
/// PIV addresses certs by slot. PKCS#11 addresses cert objects by `CKA_LABEL` or `CKA_ID`.
/// Both are "find me the cert for this key"; the addressing differs by backend type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CertRef {
    /// PIV slot identifier (`PivBackend` and `YubikeyBackend`).
    PivSlot(PivSlot),
    /// Human-readable label string (PKCS#11 `CKA_LABEL`, or software backend).
    Label(String),
    /// Raw binary identifier (PKCS#11 `CKA_ID`, typically SHA-1 of public key).
    RawId(Vec<u8>),
}

/// PIN access policy for PIV private key operations.
///
/// Standard PIV defines fixed PIN policies per slot (see `PivSlot` docs).
/// `YubiKey` extends this with per-key configurable policies.
///
/// # Standard references
/// - NIST SP 800-73-5 Part 2, §3.2: access rules per key reference
/// - Yubico PIV documentation: configurable PIN policies (vendor extension)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PivPinPolicy {
    /// Use the slot's default policy per NIST SP 800-73.
    Default,
    /// No PIN required (vendor extension, not standard PIV).
    Never,
    /// PIN verified once per session.
    Once,
    /// PIN verified before every private key operation ("PIN Always").
    Always,
}

/// Physical touch policy for private key operations.
///
/// This is a vendor extension (Yubico), not part of the NIST PIV standard.
/// Standard PIV cards do not have a touch sensor concept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PivTouchPolicy {
    /// Use the slot's default touch policy.
    Default,
    /// No touch required.
    Never,
    /// Touch required for every operation.
    Always,
    /// Touch cached for 15 seconds (Yubico-specific).
    Cached,
}

/// Metadata about a populated PIV slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivSlotInfo {
    /// The PIV slot identifier.
    pub slot: PivSlot,
    /// Key algorithm in this slot (if known).
    pub algorithm: Option<KeyAlgorithm>,
    /// Whether a certificate is stored in this slot.
    /// PIV associates one X.509 certificate with each key slot.
    /// [NIST SP 800-73-5 Part 1, §3.2]
    pub has_certificate: bool,
    /// Origin of the key in this slot.
    pub origin: PivKeyOrigin,
}

/// Origin of a key in a PIV slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PivKeyOrigin {
    /// Key was generated on the device (GENERATE ASYMMETRIC KEY PAIR command).
    /// [NIST SP 800-73-5 Part 2, §3.1]
    Generated,
    /// Key was imported from external material.
    Imported,
    /// Origin unknown (card doesn't report this information).
    Unknown,
}

/// Device identity information for a PIV-compatible smart card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivDeviceInfo {
    /// Device serial number (vendor-specific, not standardized by NIST).
    pub serial: Option<String>,
    /// Firmware version string.
    pub firmware_version: Option<String>,
    /// Form factor description (e.g. "USB-A", "USB-C", "NFC").
    pub form_factor: Option<String>,
}

/// `YubiKey`-specific slot metadata (vendor extension, not NIST PIV).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YubikeySlotMetadata {
    /// PIN policy configured for this slot.
    pub pin_policy: PivPinPolicy,
    /// Touch policy configured for this slot.
    pub touch_policy: PivTouchPolicy,
    /// Origin of the key in this slot.
    pub origin: PivKeyOrigin,
    /// Public key, if the slot reports one.
    pub public_key: Option<PublicKeyDer>,
}

bitflags::bitflags! {
    /// PKCS#11 token capability flags. Maps to the `CKF_*` constants in the PKCS#11 standard.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Pkcs11TokenFlags: u8 {
        /// Token requires login before cryptographic operations (`CKF_LOGIN_REQUIRED`).
        const LOGIN_REQUIRED      = 0b0000_0001;
        /// User PIN has been initialized: `C_InitPIN` has been called (`CKF_USER_PIN_INITIALIZED`).
        const USER_PIN_INITIALIZED = 0b0000_0010;
        /// Token has been initialized: `C_InitToken` has been called (`CKF_TOKEN_INITIALIZED`).
        const TOKEN_INITIALIZED   = 0b0000_0100;
        /// Token is write-protected (`CKF_WRITE_PROTECTED`).
        const WRITE_PROTECTED     = 0b0000_1000;
    }
}

/// PKCS#11 token information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11TokenInfo {
    /// Token label (padded to 32 bytes in PKCS#11, trimmed here).
    pub label: String,
    /// Manufacturer ID.
    pub manufacturer: String,
    /// Token model.
    pub model: String,
    /// Token serial number.
    pub serial: String,
    /// Firmware version string.
    pub firmware_version: String,
    /// Token capability flags.
    pub flags: Pkcs11TokenFlags,
}

/// Opaque PKCS#11 mechanism identifier.
///
/// An enum would be incomplete (hundreds of `CKM_*` values, plus vendor extensions).
/// A string like `"CKM_RSA_PKCS_KEY_PAIR_GEN"` is honest about what we expose.
/// Used only for capability checking ("does this token support X?"), not dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pkcs11Mechanism(String);

impl Pkcs11Mechanism {
    /// Create a new `Pkcs11Mechanism` from a `CKM_*` name string.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Return the mechanism name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Pkcs11Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// TPM (Trusted Platform Module) information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmInfo {
    /// TPM specification version (e.g., "2.0").
    pub version: String,
    /// TPM manufacturer identifier.
    pub manufacturer: String,
    /// Firmware version (if available).
    pub firmware_version: Option<String>,
}

/// PCR (Platform Configuration Register) value.
///
/// The `value` field encodes both the algorithm and the hash in the format
/// `"algorithm:hexhash"` (e.g., `"sha256:abc123..."`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index (0-23 typically).
    pub index: u8,
    /// PCR value in the format `"algorithm:hexhash"` (e.g., `"sha256:abc123..."`).
    pub value: String,
}

/// Backend configuration entry from a ceremony file.
///
/// The `provider` field identifies the backend by its self-declared name
/// (e.g., `"software"`, `"yubikey"`). The remaining YAML keys are flattened
/// into `extra` for backend-specific deserialization.
///
/// Each backend crate defines its own config struct and deserializes from
/// `extra` at startup. This inverts the prior design where the model listed
/// concrete backend variants; backends now declare themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend provider identifier as a lowercase string (e.g., `"software"`).
    pub provider: String,
    /// Backend-specific configuration key/value pairs.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_algorithm_serde_roundtrip() {
        // Serde uses Display strings via `serde(into/try_from)`. These are the canonical
        // strings for ceremony YAML `algorithm:` fields and transcripts.
        let cases: &[(KeyAlgorithm, &str)] = &[
            (KeyAlgorithm::Rsa2048, "\"RSA-2048\""),
            (KeyAlgorithm::Rsa4096, "\"RSA-4096\""),
            (KeyAlgorithm::EcdsaP256, "\"ECDSA-P256\""),
            (KeyAlgorithm::EcdsaP384, "\"ECDSA-P384\""),
            (KeyAlgorithm::Ed25519, "\"Ed25519\""),
            (KeyAlgorithm::MlDsa44, "\"ML-DSA-44\""),
            (KeyAlgorithm::MlDsa65, "\"ML-DSA-65\""),
            (KeyAlgorithm::MlDsa87, "\"ML-DSA-87\""),
            (KeyAlgorithm::MlKem512, "\"ML-KEM-512\""),
            (KeyAlgorithm::MlKem768, "\"ML-KEM-768\""),
            (KeyAlgorithm::MlKem1024, "\"ML-KEM-1024\""),
            (KeyAlgorithm::Aes128, "\"AES-128\""),
            (KeyAlgorithm::Aes256, "\"AES-256\""),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: KeyAlgorithm = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn sign_algorithm_serde_roundtrip() {
        // Serde uses Display strings via `serde(into/try_from)`. These are the canonical
        // strings for ceremony YAML `algorithm:` fields and transcripts.
        let cases: &[(SignAlgorithm, &str)] = &[
            (SignAlgorithm::RsaPkcs1Sha256, "\"RSA-PKCS1-SHA256\""),
            (SignAlgorithm::RsaPssSha256, "\"RSA-PSS-SHA256\""),
            (SignAlgorithm::EcdsaSha256, "\"ECDSA-SHA256\""),
            (SignAlgorithm::EcdsaSha384, "\"ECDSA-SHA384\""),
            (SignAlgorithm::Ed25519, "\"Ed25519\""),
            (SignAlgorithm::MlDsa44, "\"ML-DSA-44\""),
            (SignAlgorithm::MlDsa65, "\"ML-DSA-65\""),
            (SignAlgorithm::MlDsa87, "\"ML-DSA-87\""),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: SignAlgorithm = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn sign_algorithm_from_str_rejects_unknown() {
        assert!("RSA-PKCS1-SHA512".parse::<SignAlgorithm>().is_err());
        assert!("".parse::<SignAlgorithm>().is_err());
        assert!(
            "ecdsa-sha256".parse::<SignAlgorithm>().is_err(),
            "must be case-sensitive"
        );
        assert!(
            "ecdsa_sha256".parse::<SignAlgorithm>().is_err(),
            "the snake_case spelling is not accepted"
        );
    }

    /// The default must be a signature algorithm the key can actually perform,
    /// or actions that derive one would hand backends an impossible request.
    #[test]
    fn every_default_sign_algorithm_accepts_its_own_key() {
        let signing_keys = [
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa4096,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::MlDsa44,
            KeyAlgorithm::MlDsa65,
            KeyAlgorithm::MlDsa87,
        ];
        for key_algorithm in signing_keys {
            let algorithm = key_algorithm
                .default_sign_algorithm()
                .unwrap_or_else(|| panic!("{key_algorithm} must have a default"));
            assert!(
                algorithm.accepts_key(key_algorithm),
                "{key_algorithm} defaults to {algorithm}, which rejects it"
            );
        }

        // Symmetric keys sign nothing.
        assert!(KeyAlgorithm::Aes128.default_sign_algorithm().is_none());
        assert!(KeyAlgorithm::Aes256.default_sign_algorithm().is_none());
    }

    #[test]
    fn sign_algorithm_accepts_key_spans_rsa_sizes_and_pins_everything_else() {
        // RSA signature schemes are defined for any modulus size, so both key
        // sizes are valid. This is what `key_algorithm()` cannot express.
        for algorithm in [SignAlgorithm::RsaPkcs1Sha256, SignAlgorithm::RsaPssSha256] {
            assert!(algorithm.accepts_key(KeyAlgorithm::Rsa2048));
            assert!(algorithm.accepts_key(KeyAlgorithm::Rsa4096));
            assert!(!algorithm.accepts_key(KeyAlgorithm::EcdsaP256));
        }

        // Curves and ML-DSA parameter sets are pinned: a signature algorithm
        // names exactly one key algorithm and rejects its neighbours.
        assert!(SignAlgorithm::EcdsaSha256.accepts_key(KeyAlgorithm::EcdsaP256));
        assert!(!SignAlgorithm::EcdsaSha256.accepts_key(KeyAlgorithm::EcdsaP384));
        assert!(SignAlgorithm::MlDsa65.accepts_key(KeyAlgorithm::MlDsa65));
        assert!(!SignAlgorithm::MlDsa65.accepts_key(KeyAlgorithm::MlDsa87));

        // A signing algorithm never accepts a symmetric key.
        assert!(!SignAlgorithm::Ed25519.accepts_key(KeyAlgorithm::Aes256));
    }

    #[test]
    fn wrap_scheme_serde_roundtrip() {
        // Serde uses Display strings via `serde(into/try_from)`. These strings
        // appear in transcripts.
        let cases: &[(WrapScheme, &str)] = &[
            (WrapScheme::CmsAes256Gcm, "\"CMS-AES-256-GCM\""),
            (WrapScheme::RsaOaepSha256, "\"RSA-OAEP-SHA256\""),
            (
                WrapScheme::RsaAesKeyWrapSha256,
                "\"RSA-AES-KEY-WRAP-SHA256\"",
            ),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: WrapScheme = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn wrap_scheme_from_str_rejects_unknown() {
        assert!("CMS-RSA-XTS".parse::<WrapScheme>().is_err());
        assert!("".parse::<WrapScheme>().is_err());
        assert!(
            "cms-aes-256-gcm".parse::<WrapScheme>().is_err(),
            "must be case-sensitive"
        );
        assert!(
            "CMS-RSA-CBC".parse::<WrapScheme>().is_err(),
            "the unauthenticated CBC scheme is gone, not merely undocumented"
        );
    }

    /// A CMS wrap to an RSA recipient, as OpenSSL 3.6 produces it.
    fn cms_ktri_gcm() -> WrapDescription {
        WrapDescription::new(
            RecipientInfoKind::Ktri,
            Oid::new(oid::RSA_ENCRYPTION).unwrap(),
        )
        .with_content_encryption(Oid::new(oid::AES_256_GCM).unwrap())
    }

    #[test]
    fn oid_rejects_values_that_are_not_dotted_decimal() {
        assert!(Oid::new("2.16.840.1.101.3.4.1.46").is_ok());
        assert!(Oid::new("1.2").is_ok());
        assert!(Oid::new("1").is_err(), "a single arc is not an OID");
        assert!(
            Oid::new("1.2.").is_err(),
            "trailing dot leaves an empty arc"
        );
        assert!(Oid::new("1.2.a").is_err());
        assert!(Oid::new("").is_err());
    }

    #[test]
    fn scheme_admits_only_a_matching_description() {
        assert!(WrapScheme::CmsAes256Gcm.permits(&cms_ktri_gcm()));

        // Same container, CBC content: the scheme fixes GCM, so this is not it.
        let cbc = WrapDescription::new(
            RecipientInfoKind::Ktri,
            Oid::new(oid::RSA_ENCRYPTION).unwrap(),
        )
        .with_content_encryption(Oid::new(oid::AES_256_CBC).unwrap());
        assert!(!WrapScheme::CmsAes256Gcm.permits(&cbc));

        // A symmetric KEK is the KEKRI encapsulation, which this scheme does
        // not produce.
        let kekri = WrapDescription::new(
            RecipientInfoKind::Kekri,
            Oid::new(oid::AES_256_WRAP).unwrap(),
        )
        .with_content_encryption(Oid::new(oid::AES_256_GCM).unwrap());
        assert!(!WrapScheme::CmsAes256Gcm.permits(&kekri));
    }

    #[test]
    fn wrapped_key_rejects_a_scheme_its_description_contradicts() {
        let coherent = WrappedKey::new(WrapScheme::CmsAes256Gcm, cms_ktri_gcm(), vec![1, 2, 3]);
        assert!(coherent.is_ok());

        let unauthenticated = WrapDescription::new(
            RecipientInfoKind::Ktri,
            Oid::new(oid::RSA_ENCRYPTION).unwrap(),
        )
        .with_content_encryption(Oid::new(oid::AES_256_CBC).unwrap());
        let mislabelled = WrappedKey::new(WrapScheme::CmsAes256Gcm, unauthenticated, vec![1, 2, 3]);
        assert!(
            mislabelled.is_err(),
            "bytes must not carry a label they contradict"
        );
    }

    #[test]
    fn wrapped_key_recheck_survives_deserialization() {
        let wrapped =
            WrappedKey::new(WrapScheme::CmsAes256Gcm, cms_ktri_gcm(), vec![9, 9]).unwrap();
        let json = serde_json::to_string(&wrapped).unwrap();
        let back: WrappedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scheme(), WrapScheme::CmsAes256Gcm);
        assert_eq!(back.data(), &[9, 9]);

        // An artifact edited to disagree with itself does not deserialize.
        let tampered = json.replace(oid::AES_256_GCM, oid::AES_256_CBC);
        assert!(serde_json::from_str::<WrappedKey>(&tampered).is_err());
    }

    #[test]
    fn gcm_content_is_the_authenticated_case() {
        assert!(cms_ktri_gcm().content_is_authenticated());
        let cbc = WrapDescription::new(
            RecipientInfoKind::Ktri,
            Oid::new(oid::RSA_ENCRYPTION).unwrap(),
        )
        .with_content_encryption(Oid::new(oid::AES_256_CBC).unwrap());
        assert!(!cbc.content_is_authenticated());
    }

    #[test]
    fn piv_slot_retired_enforces_valid_range() {
        // Indices 0–19 map to PIV key references 0x82–0x95.
        // An out-of-range index would send an invalid reference to PIV hardware.
        assert!(PivSlot::retired(0).is_some(), "index 0 must be valid");
        assert!(
            PivSlot::retired(19).is_some(),
            "index 19 must be valid (last slot 0x95)"
        );
        assert!(
            PivSlot::retired(20).is_none(),
            "index 20 must be rejected (out of range)"
        );
        assert!(
            PivSlot::retired(255).is_none(),
            "index 255 must be rejected"
        );
    }

    #[test]
    fn key_policy_default_is_secure() {
        // The default is documented as the most secure configuration for ceremony signing keys.
        // A regression here (e.g., extractable=true) is a silent security downgrade.
        let policy = KeyPolicy::default();
        assert!(
            policy.persistent,
            "ceremony keys must persist across sessions"
        );
        assert!(policy.sensitive, "ceremony keys must be marked sensitive");
        assert!(
            !policy.extractable,
            "ceremony keys must not be extractable by default"
        );
        assert!(policy.usages.contains(KeyUsages::SIGN));
        assert!(policy.usages.contains(KeyUsages::VERIFY));
        assert!(
            !policy.usages.contains(KeyUsages::ENCRYPT),
            "signing-only default must not permit encryption"
        );
        assert!(
            !policy.usages.contains(KeyUsages::WRAP),
            "signing-only default must not permit wrapping"
        );
    }
}
