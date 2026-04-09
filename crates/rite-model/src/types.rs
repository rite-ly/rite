//! Shared semantic types for the ceremony domain model.

use serde::{Deserialize, Serialize};

// ============================================================================
// Ceremony metadata
// ============================================================================

/// Ceremony metadata (name and optional description).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Human-readable ceremony name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ============================================================================
// Role helpers
// ============================================================================

/// Extract the role type from a role ID.
///
/// `"witness__1"` → `"witness"`, `"operator"` → `"operator"`.
pub fn role_type(id: &str) -> &str {
    id.split_once("__").map_or(id, |(prefix, _)| prefix)
}

/// Derive a display name from a role ID.
///
/// Splits on `__`, takes the prefix, then title-cases each word (split on `_` and `-`).
/// `"witness__1"` → `"Witness"`, `"hsm_operator__primary"` → `"Hsm Operator"`.
pub fn derive_role_name(id: &str) -> String {
    role_type(id)
        .split(['_', '-'])
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

// ============================================================================
// Action types
// ============================================================================

/// Action types available in ceremony steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActionType {
    // Verification actions
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
    /// Capture machine information (hostname, `CPU`, OS) as evidence.
    ///
    /// Records device identity to prove which machine ran the ceremony.
    /// Should be placed early in ceremony to establish machine context.
    MachineInfo,

    // Cryptographic actions
    /// Generate `RSA` or `EC` keypair.
    GenerateKeypair,
    /// Wrap key using `CMS` `EnvelopedData`.
    WrapKey,
    /// Unwrap key using `CMS` `EnvelopedData`.
    UnwrapKey,
    /// Export public key from keypair.
    ExportPublic,
    /// Split secret using Shamir's Secret Sharing.
    ShamirSplit,
    /// Reconstruct secret from Shamir shares.
    ShamirCombine,

    // Attestation actions
    /// Formal attestation statement.
    Attest,
    /// `TPM` attestation with `PCR` measurements and cryptographic quotes.
    ///
    /// Requires the `rite-tpm` backend (not available at beta).
    TpmAttest,

    // PIV smart card actions
    /// Read `X.509` certificate from `PIV` smart card slot.
    ///
    /// No `PIN` required — reading certificates is unauthenticated on `PIV` cards.
    /// Requires a `PIV` backend (not available at beta).
    PivReadCertificate,
    /// Sign data using `PIV` smart card on-device key.
    ///
    /// Handles `PIN` verification internally before signing.
    /// Requires a `PIV` backend (not available at beta).
    PivSign,
    /// Generate a `YubiKey` attestation certificate for a `PIV` slot (Yubico extension).
    ///
    /// Slot `F9` signs the key's certificate to prove it was generated on-device.
    /// Requires the `rite-yubikey` backend (not available at beta).
    YubikeyAttestSlot,

    // PKI actions
    /// Issue an `X.509` certificate from a `PKCS#10` `CSR`.
    ///
    /// Takes a `CSR` and a backend-managed signing key, assembles the `TBSCertificate`,
    /// signs it via the backend's `SignBackend`, and produces a `DER`-encoded certificate.
    /// Works with any backend implementing `SignBackend` (software, `PKCS#11`, `YubiKey`).
    IssueCertificate,
    /// Generate a `PKCS#10` `CSR` signed by a backend-managed key.
    ///
    /// Takes a backend-managed signing key and subject parameters, assembles a
    /// `CertReqInfo`, signs it via the backend's `SignBackend`, and produces a
    /// `DER`-encoded `CSR`.
    GenerateCsr,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionType::ClockCheck => write!(f, "clock_check"),
            ActionType::Confirm => write!(f, "confirm"),
            ActionType::CheckValue => write!(f, "check_value"),
            ActionType::OralReadback => write!(f, "oral_readback"),
            ActionType::MachineInfo => write!(f, "machine_info"),
            ActionType::GenerateKeypair => write!(f, "generate_keypair"),
            ActionType::WrapKey => write!(f, "wrap_key"),
            ActionType::UnwrapKey => write!(f, "unwrap_key"),
            ActionType::ExportPublic => write!(f, "export_public"),
            ActionType::ShamirSplit => write!(f, "shamir_split"),
            ActionType::ShamirCombine => write!(f, "shamir_combine"),
            ActionType::Attest => write!(f, "attest"),
            ActionType::TpmAttest => write!(f, "tpm_attest"),
            ActionType::PivReadCertificate => write!(f, "piv_read_certificate"),
            ActionType::PivSign => write!(f, "piv_sign"),
            ActionType::YubikeyAttestSlot => write!(f, "yubikey_attest_slot"),
            ActionType::IssueCertificate => write!(f, "issue_certificate"),
            ActionType::GenerateCsr => write!(f, "generate_csr"),
        }
    }
}

// ============================================================================
// Output types
// ============================================================================

/// Type of output produced by a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputType {
    // Cryptographic outputs
    /// Public key in `PEM` format.
    PublicKey,
    /// Wrapped (encrypted) key in `CMS` format.
    WrappedKey,
    /// `X.509` certificate.
    Certificate,
    /// `DNSSEC` signed resource record set.
    SignedRrset,
    /// Certificate Transparency Signed Certificate Timestamp.
    Sct,
    /// Shamir secret share.
    SecretShare,

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
            OutputType::Certificate => write!(f, "certificate"),
            OutputType::SignedRrset => write!(f, "signed_rrset"),
            OutputType::Sct => write!(f, "sct"),
            OutputType::SecretShare => write!(f, "secret_share"),
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
            OutputType::WrappedKey | OutputType::SignedRrset | OutputType::Sct => "bin",
            OutputType::SecretShare | OutputType::Document => "txt",
            OutputType::CeremonyLog => "json",
        }
    }
}

// ============================================================================
// Parameter types
// ============================================================================

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

// ============================================================================
// Duty types
// ============================================================================

/// Typed preset for common post-ceremony duty categories.
///
/// Provides built-in prose for scripts when no description is given.
/// Use `Custom` for duties that don't fit a preset — description is then required.
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
    /// Free-form duty — description is required.
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
            DutyType::DistributeShares => {
                Some("Distribute key shares to assigned custodians")
            }
            DutyType::DistributeMedia => {
                Some("Distribute backup media to designated recipients")
            }
            DutyType::ArchiveMaterials => {
                Some("Archive ceremony materials at designated storage locations")
            }
            DutyType::PublishRecord => {
                Some("Publish ceremony record and witness attestations")
            }
            DutyType::NotifyStakeholders => {
                Some("Notify stakeholders of ceremony completion")
            }
            DutyType::ImportKeys => Some("Import generated keys into operational system"),
            DutyType::Custom => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

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
    fn derive_role_name_title_cases() {
        assert_eq!(derive_role_name("witness__1"), "Witness");
        assert_eq!(derive_role_name("hsm_operator__primary"), "Hsm Operator");
        assert_eq!(derive_role_name("operator"), "Operator");
        assert_eq!(derive_role_name("ceremony-admin"), "Ceremony Admin");
    }
}
