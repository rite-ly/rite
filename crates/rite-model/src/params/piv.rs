//! Params for the PIV and `YubiKey` actions.

use rite_sdk::SignAlgorithm;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// A PIV slot as a step names it: `9a`, `9c`, `9d`, `9e`, or a retired slot
/// by its key reference in hex, `82` to `95`, optionally after `piv:`.
//
// The set `rite_piv::ops::slot_from_hint` reads, which this crate cannot
// link; its tests hold the two together.
pub const PIV_SLOT: &str = r"^(piv:)?(9[acde]|8[2-9a-fA-F]|9[0-5])$";

const PIV_SLOT_MESSAGE: &str = "'slot' must be a PIV slot: 9a, 9c, 9d, 9e, or a retired slot \
    from 82 to 95";

/// The signature algorithms a PIV card performs. RSA-PSS is absent because
/// PIV cards apply a raw RSA operation and the client-side PSS encoding is
/// not implemented; Ed25519 and ML-DSA because no PIV card does them.
pub const PIV_SIGN_ALGORITHMS: [SignAlgorithm; 3] = [
    SignAlgorithm::EcdsaSha256,
    SignAlgorithm::EcdsaSha384,
    SignAlgorithm::RsaPkcs1Sha256,
];

/// Parameters for the `piv_read_certificate` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PivReadCertificateParams {
    /// PIV slot to read: `9a`, `9c`, `9d`, `9e`, or a retired slot key
    /// reference in hex (`82`..`95`).
    #[schemars(regex(pattern = PIV_SLOT), extend("x-message" = PIV_SLOT_MESSAGE))]
    pub slot: String,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Parameters for the `piv_sign` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PivSignParams {
    /// PIV slot containing the signing key.
    #[serde(default = "default_sign_slot")]
    #[schemars(regex(pattern = PIV_SLOT), extend("x-message" = PIV_SLOT_MESSAGE))]
    pub slot: String,
    /// Signing algorithm: `ECDSA-SHA256`, `ECDSA-SHA384`, `RSA-PKCS1-SHA256`.
    #[serde(default = "default_sign_algorithm")]
    #[schemars(schema_with = "piv_sign_algorithms")]
    pub algorithm: SignAlgorithm,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

fn default_sign_slot() -> String {
    "9c".to_string()
}

fn default_sign_algorithm() -> SignAlgorithm {
    SignAlgorithm::EcdsaSha256
}

fn piv_sign_algorithms(_: &mut SchemaGenerator) -> Schema {
    let mut schema = super::schema::names(PIV_SIGN_ALGORITHMS.iter().map(|a| a.as_str()));
    schema.insert(
        "default".to_string(),
        default_sign_algorithm().as_str().into(),
    );
    schema
}

/// Parameters for the `yubikey_attest_slot` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestSlotParams {
    /// PIV slot to attest (e.g., `9a`, `9c`, `9d`, `9e`).
    #[schemars(regex(pattern = PIV_SLOT), extend("x-message" = PIV_SLOT_MESSAGE))]
    pub slot: String,
    /// Custom message to display before the attestation step.
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_certificate_params_deserializes() {
        let json = serde_json::json!({ "slot": "9a" });
        let params: PivReadCertificateParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.slot, "9a");
        assert!(params.message.is_none());
    }

    #[test]
    fn read_certificate_params_rejects_missing_slot() {
        let json = serde_json::json!({});
        let result = serde_json::from_value::<PivReadCertificateParams>(json);
        assert!(result.is_err());
    }

    #[test]
    fn sign_params_defaults() {
        let json = serde_json::json!({});
        let params: PivSignParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.slot, "9c");
        assert_eq!(params.algorithm, SignAlgorithm::EcdsaSha256);
        assert!(params.message.is_none());
    }

    #[test]
    fn sign_params_explicit_values() {
        let json = serde_json::json!({
            "slot": "9d",
            "algorithm": "RSA-PKCS1-SHA256",
            "message": "Sign the key"
        });
        let params: PivSignParams = serde_json::from_value(json).unwrap();
        assert_eq!(params.slot, "9d");
        assert_eq!(params.algorithm, SignAlgorithm::RsaPkcs1Sha256);
        assert_eq!(params.message.as_deref(), Some("Sign the key"));
    }
}
