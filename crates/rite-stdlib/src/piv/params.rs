//! Parameter types for PIV and `YubiKey` ceremony actions.

use serde::{Deserialize, Serialize};

/// Parameters for the `piv_read_certificate` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivReadCertificateParams {
    /// PIV slot to read: `9a`, `9c`, `9d`, `9e`, or a retired slot key
    /// reference in hex (`82`..`95`).
    pub slot: String,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Parameters for the `piv_sign` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivSignParams {
    /// PIV slot containing the signing key (default: "9c").
    #[serde(default = "default_sign_slot")]
    pub slot: String,
    /// Signing algorithm: `ECDSA-SHA256`, `ECDSA-SHA384`, `RSA-PKCS1-SHA256`.
    #[serde(default = "default_sign_algorithm")]
    pub algorithm: String,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

fn default_sign_slot() -> String {
    "9c".to_string()
}

// Spelled by the SDK enum rather than a literal, so the default cannot drift
// from the names the action parses.
fn default_sign_algorithm() -> String {
    rite_sdk::SignAlgorithm::EcdsaSha256.to_string()
}

/// Parameters for the `yubikey_attest_slot` action.
#[cfg(feature = "yubikey")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestSlotParams {
    /// PIV slot to attest (e.g., `9a`, `9c`, `9d`, `9e`).
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
        assert_eq!(params.algorithm, "ECDSA-SHA256");
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
        assert_eq!(params.algorithm, "RSA-PKCS1-SHA256");
        assert_eq!(params.message.as_deref(), Some("Sign the key"));
    }
}
