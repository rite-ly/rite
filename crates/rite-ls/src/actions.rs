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
        name: "generate_key",
        short: "Generate a key through a backend",
        long: "Generate a key through a backend. `algorithm:` selects what kind: a keypair for RSA, EC, Ed25519, ML-DSA or ML-KEM, one secret for AES. A symmetric key has no public half, so it can only ever be a wrapping key, and the transcript records it by a key check value rather than by a fingerprint. `policy:` says what the key is permitted to do in PKCS#11 terms, defaulting to sign and verify for a keypair and to wrap and unwrap for a symmetric key.",
    },
    ActionMeta {
        name: "wrap_key",
        short: "Encrypt a key under another key for transport",
        long: "Encrypt a private key under another key so it can leave the machine. `scheme:` names the container, defaulting to CMS AuthEnvelopedData under AES-256-GCM; the raw RSA mechanisms are what a cloud KMS import accepts, and the AES mechanisms wrap under a symmetric key the backend holds. Which encapsulation a CMS wrap takes follows the recipient key, and the transcript records what the wrap actually did. Reads `wrapping_key:` to wrap under a key the backend holds, or `recipient:` to wrap to a public key held outside the ceremony.",
    },
    ActionMeta {
        name: "unwrap_key",
        short: "Decrypt a wrapped key and import it into a backend",
        long: "Decrypt a wrapped key and import it into a backend under a new label. The scheme comes from the wrapped artifact rather than the ceremony, so it cannot disagree with the bytes being decrypted. Nothing travels with a wrapped key saying what it is, so `algorithm:` declares that: it is required to recover a symmetric key, whose bytes look like any others of the same length, and checked against what came out for a keypair. `expect_key:` names the key the ceremony means to restore, as a `sha256:` fingerprint for a keypair or a `cmac-aes:` check value for a symmetric key.",
    },
    ActionMeta {
        name: "import_key",
        short: "Import a key from material the ceremony holds",
        long: "Install key material the ceremony already holds as a key of a named algorithm. `unwrap_key` without the decrypt: the bytes can be a material carried into the room or an artifact an earlier step produced. `algorithm:` is required, because raw material says nothing about itself: a symmetric algorithm reads the bytes as the key itself, every other one reads them as PKCS#8 DER. `expect_key:` names what the ceremony means to lift, as a `sha256:` fingerprint for a keypair or a `cmac-aes:` check value for a symmetric key, and is the only evidence available about material this ceremony did not itself produce. `policy:` says what the imported key may do.",
    },
    ActionMeta {
        name: "encrypt_data",
        short: "Encrypt content under a key held by a backend",
        long: "Encrypt bytes into a container only the named key opens. `wrap_key` for content that is not a key, and a separate verb because the claim differs: a wrap says a key left a backend under protection, while encrypted content makes no custody claim. Reads `data:` and `encryption_key:`, a 256-bit symmetric key the backend holds. The backend produces a fresh content-encryption key and a copy of it only that key opens, and the content is encrypted under the first, so the content itself never reaches the backend. `scheme:` names the container and defaults to `CMS-AES-256-GCM`, which is the only one this action writes.",
    },
    ActionMeta {
        name: "decrypt_data",
        short: "Decrypt an encrypted-data artifact back to bytes",
        long: "Open a container `encrypt_data` produced. Reads `encrypted_data:` and `decryption_key:`, the key the container is addressed to, which is checked by its check value before anything is decrypted. What comes out is an ordinary byte artifact, so a later step reads it the way it reads a material: `import_key` lifts it into a key, `check_value` compares it, `sign_data` signs it.",
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
        long: "Verify a signature over data, given the signer's public key. The key may be a keypair, a bare public key, or a certificate carrying one. Needs no backend; name a `backend:` to delegate the check to it.",
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
        let catalogued: BTreeSet<String> = ALL.iter().map(|a| a.name.to_string()).collect();
        let defined: BTreeSet<String> = ActionType::ALL.iter().map(ToString::to_string).collect();

        assert_eq!(
            catalogued, defined,
            "editor action catalogue is out of step with ActionType"
        );
    }
}
