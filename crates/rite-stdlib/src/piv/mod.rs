//! PIV smart-card and `YubiKey` ceremony actions.
//!
//! These actions are backend-agnostic: they drive any backend that implements
//! the relevant `rite-sdk` capability traits (`CertStoreBackend`, `SignBackend`,
//! `PivBackend`, `YubikeyBackend`). Slot-hint parsing is shared from `rite-piv`.

mod read_certificate;
mod sign;

pub use read_certificate::PivReadCertificateAction;
pub use sign::PivSignAction;

#[cfg(feature = "yubikey")]
mod attest;
#[cfg(feature = "yubikey")]
pub use attest::YubikeyAttestSlotAction;

#[cfg(test)]
mod tests {
    /// The schema checks a slot with a pattern, since the model cannot link
    /// `rite-piv`; the two must accept the same names. The check is the one
    /// `rite check` runs, with the engine that enforces the pattern.
    #[test]
    fn the_slot_pattern_accepts_what_the_slot_parser_reads() {
        let check =
            rite_model::validate::params_check(rite_model::ActionType::PivReadCertificate).unwrap();
        let mut names: Vec<String> = (0u8..=255)
            .flat_map(|byte| [format!("{byte:02x}"), format!("{byte:02X}")])
            .collect();
        names.extend(names.clone().into_iter().map(|name| format!("piv:{name}")));
        names.extend(
            [
                "", "9", "9aa", "piv:", "x9a", "082", "+82", "piv:095", " 82",
            ]
            .map(String::from),
        );
        for name in names {
            assert_eq!(
                check
                    .validate(&serde_json::json!({ "slot": name }))
                    .is_empty(),
                rite_piv::ops::slot_from_hint(&name).is_ok(),
                "{name}"
            );
        }
    }
}
