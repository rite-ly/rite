//! Static metadata for all ActionType variants.
//!
//! Single source of truth for action names, short descriptions (completion popups),
//! and long descriptions (hover tooltips). Update when `ActionType` changes.
//!
//! Kept as a plain static list rather than generated from the enum to avoid
//! adding proc-macro or strum dependencies.

pub struct ActionMeta {
    pub name: &'static str,
    /// Short description shown in completion popups.
    pub short: &'static str,
    /// Full description shown in hover tooltips.
    pub long: &'static str,
}

pub static ALL: &[ActionMeta] = &[
    ActionMeta {
        name: "clock_check",
        short: "Verify system clock is correct before ceremony proceeds",
        long: "Verify system clock is correct before ceremony proceeds. Displays current time and requires operator confirmation.",
    },
    ActionMeta {
        name: "confirm",
        short: "Human attests to something with yes/no decision (single person)",
        long: "Human attests to something with yes/no decision (single person). Use when the verification requires human judgment about external state.",
    },
    ActionMeta {
        name: "check_value",
        short: "Machine compares two known values and records pass/fail (automatic)",
        long: "Machine compares two known values and records pass/fail (automatic). Use when both values are known to the system and comparison is deterministic.",
    },
    ActionMeta {
        name: "oral_readback",
        short: "Two-party verbal verification: reader speaks, confirmer verifies",
        long: "Two-party verbal verification: reader speaks value aloud, confirmer verifies. Supports NATO phonetic alphabet and hex formatting.",
    },
    ActionMeta {
        name: "machine_info",
        short: "Capture machine information (hostname, CPU, OS) as evidence",
        long: "Capture machine information (hostname, CPU, OS) as evidence. Records device identity to prove which machine ran the ceremony.",
    },
    ActionMeta {
        name: "generate_keypair",
        short: "Generate RSA or EC keypair",
        long: "Generate RSA or EC keypair.",
    },
    ActionMeta {
        name: "wrap_key",
        short: "Wrap key using CMS EnvelopedData",
        long: "Wrap key using CMS EnvelopedData.",
    },
    ActionMeta {
        name: "unwrap_key",
        short: "Unwrap key using CMS EnvelopedData",
        long: "Unwrap key using CMS EnvelopedData.",
    },
    ActionMeta {
        name: "export_public",
        short: "Export public key from keypair",
        long: "Export public key from keypair.",
    },
    ActionMeta {
        name: "sign_data",
        short: "Sign data with a backend-managed key",
        long: "Sign arbitrary data with a backend-managed key. The signature algorithm follows from the key unless `algorithm:` names another one the key accepts.",
    },
    ActionMeta {
        name: "verify_signature",
        short: "Verify a signature against a public key",
        long: "Verify a signature over data, given the signer's public key. Needs no backend, so it works on evidence the ceremony did not produce; naming a `backend:` delegates the check to that backend.",
    },
    ActionMeta {
        name: "attest",
        short: "Formal attestation statement",
        long: "Formal attestation statement.",
    },
    ActionMeta {
        name: "gather_entropy",
        short: "Fold human-supplied entropy into the ceremony seed",
        long: "Fold human-supplied entropy into the ceremony seed. A participant supplies a free-form random value, such as the result of rolling physical dice, which is mixed into the entropy source's ratchet.",
    },
    ActionMeta {
        name: "tpm_attest",
        short: "TPM attestation with PCR measurements and cryptographic quotes",
        long: "TPM attestation with PCR measurements and cryptographic quotes. Requires --features=tpm. Provides hardware-backed proof of software state and device identity.",
    },
    ActionMeta {
        name: "piv_read_certificate",
        short: "Read X.509 certificate from PIV smart card slot",
        long: "Read X.509 certificate from PIV smart card slot. No PIN required; reading certificates is unauthenticated on PIV cards.",
    },
    ActionMeta {
        name: "piv_sign",
        short: "Sign data using PIV smart card on-device key",
        long: "Sign data using PIV smart card on-device key. Handles PIN verification internally before signing.",
    },
    ActionMeta {
        name: "yubikey_attest_slot",
        short: "Generate YubiKey attestation certificate for a PIV slot",
        long: "Generate a YubiKey attestation certificate for a PIV slot (Yubico extension). Slot F9 signs the key's certificate to prove it was generated on-device.",
    },
    ActionMeta {
        name: "issue_certificate",
        short: "Issue an X.509 certificate from a PKCS#10 CSR",
        long: "Issue an X.509 certificate from a PKCS#10 CSR. Takes a CSR and a backend-managed signing key, assembles the TBSCertificate, signs via the backend.",
    },
    ActionMeta {
        name: "generate_csr",
        short: "Generate a PKCS#10 CSR signed by a backend-managed key",
        long: "Generate a PKCS#10 CSR signed by a backend-managed key. Takes a backend-managed signing key and subject parameters, assembles and signs a CertReqInfo.",
    },
];

/// Look up the hover description for a known action name.
pub fn hover_description(name: &str) -> Option<&'static str> {
    ALL.iter().find(|a| a.name == name).map(|a| a.long)
}

#[cfg(test)]
mod tests {
    use super::ALL;
    use rite_model::ActionType;
    use std::collections::BTreeSet;

    /// Completion offers exactly the actions the runtime has.
    ///
    /// This list is static, so nothing in the compiler ties it to `ActionType`:
    /// a new action would otherwise be invisible in the editor while working
    /// perfectly at run time, and a removed one would still be suggested.
    #[test]
    fn catalogue_matches_the_action_types() {
        let catalogued: BTreeSet<&str> = ALL.iter().map(|a| a.name).collect();
        let defined: BTreeSet<String> = ActionType::ALL.iter().map(ToString::to_string).collect();
        let defined: BTreeSet<&str> = defined.iter().map(String::as_str).collect();

        assert_eq!(
            catalogued, defined,
            "editor action catalogue is out of step with ActionType"
        );
    }
}
