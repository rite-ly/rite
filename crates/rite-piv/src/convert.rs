//! Conversions between `yubikey` crate types and Rite backend types.
//!
//! These helpers are `pub` for reuse by `rite-yubikey`.

use rite_sdk::{BackendError, KeyAlgorithm, PivKeyOrigin, PivPinPolicy, PivSlot, PivTouchPolicy};

/// PIV key reference for retired key-management slot index 0.
///
/// NIST SP 800-73-5 assigns the retired slots key references `0x82..=0x95`.
/// Rite's [`PivSlot::Retired`] stores a 0-based index (`0..=19`), while the
/// `yubikey` crate's `RetiredSlotId` uses the raw key reference. The two
/// conversion helpers below bridge the representations.
pub(crate) const RETIRED_KEY_REF_MIN: u8 = 0x82;

/// PIV key reference for retired key-management slot index 19 (NIST SP 800-73-5).
pub(crate) const RETIRED_KEY_REF_MAX: u8 = 0x95;

/// Convert a Rite `PivSlot` to a `yubikey::piv::SlotId`.
///
/// # Errors
///
/// Returns `BackendError::Configuration` when a `Retired` slot index is outside
/// the valid `0..=19` range.
pub fn to_yubikey_slot(slot: PivSlot) -> Result<yubikey::piv::SlotId, BackendError> {
    use yubikey::piv::{RetiredSlotId, SlotId};
    let id = match slot {
        PivSlot::Authentication => SlotId::Authentication,
        PivSlot::Signature => SlotId::Signature,
        PivSlot::KeyManagement => SlotId::KeyManagement,
        PivSlot::CardAuthentication => SlotId::CardAuthentication,
        PivSlot::Retired(index) => {
            let key_ref = RETIRED_KEY_REF_MIN.checked_add(index).ok_or_else(|| {
                BackendError::Configuration(format!(
                    "retired PIV slot index {index} out of range (valid: 0..=19)"
                ))
            })?;
            let retired = RetiredSlotId::try_from(key_ref).map_err(|_| {
                BackendError::Configuration(format!(
                    "retired PIV slot index {index} out of range (valid: 0..=19)"
                ))
            })?;
            SlotId::Retired(retired)
        }
    };
    Ok(id)
}

/// Convert a `yubikey::piv::SlotId` to a Rite `PivSlot`.
///
/// The `yubikey` crate's `SlotId` includes the Attestation slot (F9), which is
/// Yubico-specific and has no standard PIV equivalent; it falls back to
/// `PivSlot::Authentication`.
pub fn from_yubikey_slot(slot: yubikey::piv::SlotId) -> PivSlot {
    use yubikey::piv::SlotId;
    match slot {
        SlotId::Signature => PivSlot::Signature,
        SlotId::KeyManagement => PivSlot::KeyManagement,
        SlotId::CardAuthentication => PivSlot::CardAuthentication,
        SlotId::Retired(r) => PivSlot::Retired(u8::from(r).saturating_sub(RETIRED_KEY_REF_MIN)),
        // PIV Authentication (9A), the Yubico F9 attestation slot, and any
        // future vendor slots all map to Authentication.
        _ => PivSlot::Authentication,
    }
}

/// Convert a `yubikey::piv::AlgorithmId` to a Rite `KeyAlgorithm`, if supported.
pub fn from_yubikey_algorithm(algo: yubikey::piv::AlgorithmId) -> Option<KeyAlgorithm> {
    match algo {
        yubikey::piv::AlgorithmId::Rsa1024 => None, // Not supported by Rite
        yubikey::piv::AlgorithmId::Rsa2048 => Some(KeyAlgorithm::Rsa2048),
        yubikey::piv::AlgorithmId::EccP256 => Some(KeyAlgorithm::EcdsaP256),
        yubikey::piv::AlgorithmId::EccP384 => Some(KeyAlgorithm::EcdsaP384),
    }
}

/// Convert a Rite `KeyAlgorithm` to a `yubikey::piv::AlgorithmId`.
///
/// Returns `None` for algorithms not supported by PIV cards.
pub fn to_yubikey_algorithm(algo: KeyAlgorithm) -> Option<yubikey::piv::AlgorithmId> {
    match algo {
        KeyAlgorithm::Rsa2048 => Some(yubikey::piv::AlgorithmId::Rsa2048),
        KeyAlgorithm::EcdsaP256 => Some(yubikey::piv::AlgorithmId::EccP256),
        KeyAlgorithm::EcdsaP384 => Some(yubikey::piv::AlgorithmId::EccP384),
        // RSA-4096, Ed25519, and symmetric algorithms not supported by standard PIV.
        _ => None,
    }
}

/// Convert a `yubikey::piv::Origin` to a Rite `PivKeyOrigin`.
pub fn from_yubikey_origin(origin: yubikey::piv::Origin) -> PivKeyOrigin {
    match origin {
        yubikey::piv::Origin::Generated => PivKeyOrigin::Generated,
        yubikey::piv::Origin::Imported => PivKeyOrigin::Imported,
    }
}

/// Convert a `yubikey::PinPolicy` to a Rite `PivPinPolicy`.
pub fn from_yubikey_pin_policy(policy: yubikey::PinPolicy) -> PivPinPolicy {
    match policy {
        yubikey::PinPolicy::Default => PivPinPolicy::Default,
        yubikey::PinPolicy::Never => PivPinPolicy::Never,
        yubikey::PinPolicy::Once => PivPinPolicy::Once,
        yubikey::PinPolicy::Always => PivPinPolicy::Always,
    }
}

/// Convert a `yubikey::TouchPolicy` to a Rite `PivTouchPolicy`.
pub fn from_yubikey_touch_policy(policy: yubikey::TouchPolicy) -> PivTouchPolicy {
    match policy {
        yubikey::TouchPolicy::Default => PivTouchPolicy::Default,
        yubikey::TouchPolicy::Never => PivTouchPolicy::Never,
        yubikey::TouchPolicy::Always => PivTouchPolicy::Always,
        yubikey::TouchPolicy::Cached => PivTouchPolicy::Cached,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::{KeyAlgorithm, PivKeyOrigin, PivPinPolicy, PivSlot, PivTouchPolicy};
    use yubikey::piv::{AlgorithmId, Origin};

    // --- Slot conversions ---

    #[test]
    fn slot_roundtrip_standard_slots() {
        let slots = [
            PivSlot::Authentication,
            PivSlot::Signature,
            PivSlot::KeyManagement,
            PivSlot::CardAuthentication,
        ];
        for slot in slots {
            assert_eq!(from_yubikey_slot(to_yubikey_slot(slot).unwrap()), slot);
        }
    }

    #[test]
    fn retired_slot_roundtrip_uses_zero_based_index() {
        // Rite index 0 maps to PIV key reference 0x82, index 19 to 0x95.
        for index in [0_u8, 1, 9, 19] {
            let slot = PivSlot::Retired(index);
            assert_eq!(from_yubikey_slot(to_yubikey_slot(slot).unwrap()), slot);
        }
    }

    #[test]
    fn retired_slot_out_of_range_is_configuration_error() {
        assert!(matches!(
            to_yubikey_slot(PivSlot::Retired(20)).unwrap_err(),
            BackendError::Configuration(_)
        ));
        assert!(matches!(
            to_yubikey_slot(PivSlot::Retired(255)).unwrap_err(),
            BackendError::Configuration(_)
        ));
    }

    #[test]
    fn attestation_slot_falls_back_to_authentication() {
        // The Attestation slot (F9) is Yubico-specific and has no PivSlot equivalent.
        assert_eq!(
            from_yubikey_slot(yubikey::piv::SlotId::Attestation),
            PivSlot::Authentication
        );
    }

    // --- Algorithm conversions ---

    #[test]
    fn algorithm_from_yubikey_maps_all_variants() {
        assert_eq!(from_yubikey_algorithm(AlgorithmId::Rsa1024), None);
        assert_eq!(
            from_yubikey_algorithm(AlgorithmId::Rsa2048),
            Some(KeyAlgorithm::Rsa2048)
        );
        assert_eq!(
            from_yubikey_algorithm(AlgorithmId::EccP256),
            Some(KeyAlgorithm::EcdsaP256)
        );
        assert_eq!(
            from_yubikey_algorithm(AlgorithmId::EccP384),
            Some(KeyAlgorithm::EcdsaP384)
        );
    }

    #[test]
    fn algorithm_to_yubikey_maps_supported_variants() {
        assert_eq!(
            to_yubikey_algorithm(KeyAlgorithm::Rsa2048),
            Some(AlgorithmId::Rsa2048)
        );
        assert_eq!(
            to_yubikey_algorithm(KeyAlgorithm::EcdsaP256),
            Some(AlgorithmId::EccP256)
        );
        assert_eq!(
            to_yubikey_algorithm(KeyAlgorithm::EcdsaP384),
            Some(AlgorithmId::EccP384)
        );
    }

    #[test]
    fn algorithm_to_yubikey_rejects_unsupported() {
        assert_eq!(to_yubikey_algorithm(KeyAlgorithm::Rsa4096), None);
        assert_eq!(to_yubikey_algorithm(KeyAlgorithm::Ed25519), None);
    }

    // --- Origin conversion ---

    #[test]
    fn origin_from_yubikey() {
        assert_eq!(
            from_yubikey_origin(Origin::Generated),
            PivKeyOrigin::Generated
        );
        assert_eq!(
            from_yubikey_origin(Origin::Imported),
            PivKeyOrigin::Imported
        );
    }

    // --- PinPolicy mapping ---

    #[test]
    fn pin_policy_from_yubikey() {
        assert_eq!(
            from_yubikey_pin_policy(yubikey::PinPolicy::Default),
            PivPinPolicy::Default
        );
        assert_eq!(
            from_yubikey_pin_policy(yubikey::PinPolicy::Never),
            PivPinPolicy::Never
        );
        assert_eq!(
            from_yubikey_pin_policy(yubikey::PinPolicy::Once),
            PivPinPolicy::Once
        );
        assert_eq!(
            from_yubikey_pin_policy(yubikey::PinPolicy::Always),
            PivPinPolicy::Always
        );
    }

    // --- TouchPolicy mapping ---

    #[test]
    fn touch_policy_from_yubikey() {
        assert_eq!(
            from_yubikey_touch_policy(yubikey::TouchPolicy::Default),
            PivTouchPolicy::Default
        );
        assert_eq!(
            from_yubikey_touch_policy(yubikey::TouchPolicy::Never),
            PivTouchPolicy::Never
        );
        assert_eq!(
            from_yubikey_touch_policy(yubikey::TouchPolicy::Always),
            PivTouchPolicy::Always
        );
        assert_eq!(
            from_yubikey_touch_policy(yubikey::TouchPolicy::Cached),
            PivTouchPolicy::Cached
        );
    }
}
