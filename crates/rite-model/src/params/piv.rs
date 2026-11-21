//! Params for the PIV and `YubiKey` actions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A PIV slot as a step names it: `9a`, `9c`, `9d`, `9e`, or a retired slot
/// by its key reference in hex, `82` to `95`, optionally after `piv:`.
//
// The set `rite_piv::ops::slot_from_hint` reads, which this crate cannot
// link; its tests hold the two together.
pub const PIV_SLOT: &str = r"^(piv:)?(9[acde]|8[2-9a-fA-F]|9[0-5])$";

const PIV_SLOT_MESSAGE: &str = "'slot' must be a PIV slot: 9a, 9c, 9d, 9e, or a retired slot \
    from 82 to 95";

/// The `with` block of `piv_read_certificate`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PivReadCertificateParams {
    /// The PIV slot to read, such as `9a` or `9c`.
    #[schemars(regex(pattern = PIV_SLOT), extend("x-message" = PIV_SLOT_MESSAGE))]
    pub slot: String,
    /// Shown to the operator when the step starts.
    #[serde(default)]
    pub message: Option<String>,
}

/// The `with` block of `authenticate`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AuthenticateParams {
    /// Shown to the operator before the credential is asked for, such as
    /// which key it unlocks.
    #[serde(default)]
    pub message: Option<String>,
}

/// The `with` block of `yubikey_attest_slot`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AttestSlotParams {
    /// The PIV slot containing the key to attest.
    #[schemars(regex(pattern = PIV_SLOT), extend("x-message" = PIV_SLOT_MESSAGE))]
    pub slot: String,
    /// Shown to the operator when the step starts.
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
}
