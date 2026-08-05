//! Data types shared between the runtime and backend implementations.
//!
//! These types form the vocabulary of the backend interface: key specifications,
//! algorithm identifiers, attestation evidence, and hardware-specific metadata.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Public key in SPKI DER format (if exportable).
    pub public_key: Option<Vec<u8>>,
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
    /// AES 128-bit symmetric key.
    Aes128,
    /// AES 256-bit symmetric key.
    Aes256,
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
#[serde(rename_all = "snake_case")]
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
    /// The key algorithm this signature algorithm is used with.
    ///
    /// This pairing is the shared source of truth for backends that select a
    /// device algorithm from a signature request and for test doubles that
    /// mint stand-in keys, so the two cannot drift apart.
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
}

/// Wrapping algorithm. Determines both the cryptographic method and the output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum WrapAlgorithm {
    /// CMS `EnvelopedData` with RSA PKCS#1 v1.5 + AES-256-CBC (legacy).
    /// Output: CMS `ContentInfo` DER.
    CmsRsaCbc,
    /// CMS `AuthEnvelopedData` with RSA PKCS#1 v1.5 + AES-256-GCM (recommended).
    /// Output: CMS `ContentInfo` DER.
    CmsRsaGcm,
    /// NIST AES Key Wrap (RFC 3394). Requires a symmetric wrapping key.
    /// Output: raw wrapped key bytes (8-byte aligned).
    AesKeyWrap,
    /// NIST AES Key Wrap with Padding (RFC 5649). Requires a symmetric wrapping key.
    /// Output: raw wrapped key bytes (arbitrary length input).
    AesKeyWrapPad,
    /// RSA-OAEP with SHA-256. Output: raw RSA-OAEP encrypted key bytes.
    RsaOaepSha256,
}

impl fmt::Display for WrapAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapAlgorithm::CmsRsaCbc => write!(f, "CMS-RSA-CBC"),
            WrapAlgorithm::CmsRsaGcm => write!(f, "CMS-RSA-GCM"),
            WrapAlgorithm::AesKeyWrap => write!(f, "AES-KW"),
            WrapAlgorithm::AesKeyWrapPad => write!(f, "AES-KWP"),
            WrapAlgorithm::RsaOaepSha256 => write!(f, "RSA-OAEP-SHA256"),
        }
    }
}

impl std::str::FromStr for WrapAlgorithm {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CMS-RSA-CBC" => Ok(Self::CmsRsaCbc),
            "CMS-RSA-GCM" => Ok(Self::CmsRsaGcm),
            "AES-KW" => Ok(Self::AesKeyWrap),
            "AES-KWP" => Ok(Self::AesKeyWrapPad),
            "RSA-OAEP-SHA256" => Ok(Self::RsaOaepSha256),
            _ => Err(ParseError(s.to_owned())),
        }
    }
}

impl From<WrapAlgorithm> for String {
    fn from(a: WrapAlgorithm) -> String {
        a.to_string()
    }
}

impl TryFrom<String> for WrapAlgorithm {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// Output format family, derived from [`WrapAlgorithm`].
///
/// Used for display, artifact metadata, and compatibility checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum WrappedKeyFormat {
    /// CMS `ContentInfo` DER.
    Cms,
    /// Raw AES Key Wrap bytes (RFC 3394 / RFC 5649).
    AesKeyWrap,
    /// Raw RSA-OAEP encrypted bytes.
    RsaOaep,
}

/// A wrapped (encrypted) key with its algorithm and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Algorithm used to wrap the key.
    pub algorithm: WrapAlgorithm,
    /// Wrapped key data (format depends on algorithm).
    pub data: Vec<u8>,
    /// Human-readable hint identifying the intended unwrapping key (for audit).
    pub recipient_hint: Option<String>,
}

impl WrappedKey {
    /// Return the output format family for this wrapped key.
    pub fn format(&self) -> WrappedKeyFormat {
        match self.algorithm {
            WrapAlgorithm::CmsRsaCbc | WrapAlgorithm::CmsRsaGcm => WrappedKeyFormat::Cms,
            WrapAlgorithm::AesKeyWrap | WrapAlgorithm::AesKeyWrapPad => {
                WrappedKeyFormat::AesKeyWrap
            }
            WrapAlgorithm::RsaOaepSha256 => WrappedKeyFormat::RsaOaep,
        }
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
    /// Public key in `SubjectPublicKeyInfo` (SPKI) DER format.
    pub public_key: Option<Vec<u8>>,
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
    fn wrap_algorithm_serde_roundtrip() {
        // Serde uses Display strings via `serde(into/try_from)`. These strings appear
        // in ceremony YAML `algorithm:` fields and transcripts.
        let cases: &[(WrapAlgorithm, &str)] = &[
            (WrapAlgorithm::CmsRsaCbc, "\"CMS-RSA-CBC\""),
            (WrapAlgorithm::CmsRsaGcm, "\"CMS-RSA-GCM\""),
            (WrapAlgorithm::AesKeyWrap, "\"AES-KW\""),
            (WrapAlgorithm::AesKeyWrapPad, "\"AES-KWP\""),
            (WrapAlgorithm::RsaOaepSha256, "\"RSA-OAEP-SHA256\""),
        ];
        for &(variant, expected) in cases {
            let serialized = serde_json::to_string(&variant).unwrap();
            assert_eq!(serialized, expected, "serialize {variant:?}");
            let deserialized: WrapAlgorithm = serde_json::from_str(expected).unwrap();
            assert_eq!(deserialized, variant, "deserialize {expected}");
        }
    }

    #[test]
    fn wrap_algorithm_from_str_rejects_unknown() {
        assert!("CMS-RSA-XTS".parse::<WrapAlgorithm>().is_err());
        assert!("".parse::<WrapAlgorithm>().is_err());
        assert!(
            "cms-rsa-gcm".parse::<WrapAlgorithm>().is_err(),
            "must be case-sensitive"
        );
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
