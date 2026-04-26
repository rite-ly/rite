//! Shared semantic types for the ceremony domain model.

use serde::{Deserialize, Serialize};

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

    /// Generate RSA or EC keypair.
    GenerateKeypair,
    /// Wrap key using CMS `EnvelopedData`.
    WrapKey,
    /// Unwrap key using CMS `EnvelopedData`.
    UnwrapKey,
    /// Export public key from keypair.
    ExportPublic,

    /// Formal attestation statement.
    Attest,
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

impl ActionType {
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
            ActionType::Attest => "Record a signed attestation from a participant.",
            ActionType::TpmAttest => "Record TPM platform attestation (PCR values).",
            ActionType::GenerateKeypair => "Generate an asymmetric keypair.",
            ActionType::ExportPublic => "Export the public component of a keypair.",
            ActionType::WrapKey => "Wrap (encrypt) a key for secure transport.",
            ActionType::UnwrapKey => "Unwrap (decrypt) a transported key.",
            ActionType::GenerateCsr => "Generate a Certificate Signing Request.",
            ActionType::IssueCertificate => "Issue an X.509 certificate from a CSR.",
            ActionType::PivReadCertificate => "Read a certificate from a PIV smart card slot.",
            ActionType::PivSign => "Sign data using a PIV smart card key.",
            ActionType::YubikeyAttestSlot => "Attest a YubiKey PIV slot key.",
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
            ActionType::GenerateKeypair => write!(f, "generate_keypair"),
            ActionType::WrapKey => write!(f, "wrap_key"),
            ActionType::UnwrapKey => write!(f, "unwrap_key"),
            ActionType::ExportPublic => write!(f, "export_public"),
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

/// Type of output produced by a ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutputType {
    /// Public key in PEM format.
    PublicKey,
    /// Wrapped (encrypted) key in CMS format.
    WrappedKey,
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
            OutputType::WrappedKey | OutputType::SignedRrset | OutputType::Sct => "bin",
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
            (ActionType::GenerateKeypair, "\"generate_keypair\""),
            (ActionType::WrapKey, "\"wrap_key\""),
            (ActionType::UnwrapKey, "\"unwrap_key\""),
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
            ActionType::GenerateKeypair,
            ActionType::WrapKey,
            ActionType::UnwrapKey,
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
}
