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
        short: "Check the system clock before continuing",
        long: "Show the current system time and ask the operator to confirm that it is correct before the ceremony continues.",
    },
    ActionMeta {
        name: "confirm",
        short: "Record one person's yes-or-no attestation",
        long: "Ask one person to make a yes-or-no decision and record it. Use this when verifying something that requires human judgment or knowledge of external conditions.",
    },
    ActionMeta {
        name: "check_value",
        short: "Compare two values and record whether they match",
        long: "Compare two values known to the ceremony and record whether they match. Use this for a deterministic check that does not require human judgment.",
    },
    ActionMeta {
        name: "oral_readback",
        short: "Have one person read a value aloud for another to verify",
        long: "One person reads the value aloud; a second person confirms it. Supports the NATO phonetic alphabet and hexadecimal formatting.",
    },
    ActionMeta {
        name: "machine_info",
        short: "Record machine details as evidence",
        long: "Record details such as the hostname, processor, and operating system as evidence of which machine ran the ceremony.",
    },
    ActionMeta {
        name: "enter_value",
        short: "Enter a value and record it as an artifact",
        long: "Ask someone to enter a value, such as a serial number read off a device or an address shown on screen. The value becomes a text artifact under `creates:` and appears in the transcript. Set `format:` to `text` (the default), `digits`, `alphanumeric`, `hex`, `base64`, or `{ pattern: \"...\" }`. Use `length:` or `min_length:`/`max_length:` to constrain its size: text limits are in characters, while encoded formats use bytes. The entry rules are shown before typing, and invalid input is rejected. Hex and base64 input is stored as decoded bytes.",
    },
    ActionMeta {
        name: "enter_secret",
        short: "Enter a secret without recording its value",
        long: "Ask someone to enter a secret, such as a passphrase or PIN. Input is hidden, the artifact created by this step is erased from memory when the run ends, and the transcript records only that a secret was entered. Later steps can refer to it in `reads:`; for example, `import_key` accepts it as `passphrase:` when opening an encrypted private key. This action supports the same `format:`, `length:`, `min_length:`, and `max_length:` options as `enter_value`, plus `format: paper32` for values copied from a sheet. Paper32 input is checked row by row, with correctable errors identified; the artifact contains the decoded bytes.",
    },
    ActionMeta {
        name: "generate_key",
        short: "Generate a key using a backend",
        long: "Generate a key using the selected backend. Set `algorithm:` to choose an RSA, EC, Ed25519, ML-DSA, or ML-KEM keypair, or an AES symmetric key. Symmetric keys have no public component and can only be used for wrapping; the transcript identifies them by a key check value rather than a fingerprint. In PKCS#11 terms, `policy:` sets the key's permitted uses. By default, keypairs can sign and verify, while symmetric keys can wrap and unwrap.",
    },
    ActionMeta {
        name: "wrap_key",
        short: "Protect a private key for transport",
        long: "Encrypt a private key so it can be transferred off the machine. Set `scheme:` to choose the container; the default is CMS AuthEnvelopedData with AES-256-GCM. Raw RSA mechanisms can be used for cloud KMS imports, while AES mechanisms wrap the key with a symmetric key held by the backend. For CMS, the recipient key determines the encapsulation, and the transcript records the scheme actually used. Set `wrapping_key:` to use a backend-managed key, or `recipient:` to use an external public key.",
    },
    ActionMeta {
        name: "unwrap_key",
        short: "Decrypt a wrapped key and import it into a backend",
        long: "Decrypt a wrapped key and import the result into the backend under a new label. The wrapping scheme is read from the artifact, ensuring it matches the data being decrypted. Because a wrapped key does not identify its algorithm, set `algorithm:` to declare it. This is essential for symmetric keys, whose bytes do not reveal their type, and is checked against the recovered keypair. Set `expect_key:` to identify the key being restored: use a `sha256:` fingerprint for a keypair or a `cmac-aes:` check value for a symmetric key.",
    },
    ActionMeta {
        name: "import_key",
        short: "Import key material into a backend",
        long: "Import key material the ceremony already holds into the backend as a key of the specified algorithm. Unlike `unwrap_key`, this action does not decrypt: the bytes can come from a material carried into the room or from an artifact an earlier step produced. `algorithm:` is required because the bytes do not identify their own type. For a symmetric algorithm, the bytes are the key; for other algorithms, they must be PKCS#8 DER. Set `expect_key:` to check the imported key against its `sha256:` fingerprint (keypairs) or `cmac-aes:` check value (symmetric keys). This is the only evidence available about material the ceremony did not produce. Set `policy:` to control the imported key's permitted uses.",
    },
    ActionMeta {
        name: "encrypt_data",
        short: "Encrypt content with a backend-managed key",
        long: "Encrypt bytes into a container for a 256-bit symmetric key managed by the backend. Use `wrap_key` for keys; this action encrypts other content and makes no custody claim: a wrap says a key left a backend under protection, encrypted content does not. Set `data:` and `encryption_key:`. The backend creates a fresh content-encryption key, encrypts the content with it, then protects that key for the specified encryption key. The content itself is never sent to the backend. Set `scheme:` to choose the container; the default and only supported output format is `CMS-AES-256-GCM`.",
    },
    ActionMeta {
        name: "decrypt_data",
        short: "Decrypt an encrypted-data artifact",
        long: "Open a container created by `encrypt_data`. The action reads `encrypted_data:` and `decryption_key:`; it checks the key's check value before decrypting. The result is a byte artifact that later steps can use—for example, `import_key` can import it, `check_value` can compare it, or `sign_data` can sign it. The bytes are erased from memory when the run ends.",
    },
    ActionMeta {
        name: "split_secret",
        short: "Split a secret into shares for threshold recovery",
        long: "Split `secret:`, any byte artifact or material, into shares using Shamir secret sharing over GF(2^8) (the `rite-sss/v1` format). `threshold:` and `shares:` are required: the number of shares needed to recover the secret and the total number to create, each from 2 to 100. The step's backend supplies the random polynomial coefficients, so it must generate random bytes. Rite checks every threshold-sized subset before completing the split and refuses a split that would require checking more than 100,000 subsets. `rite check` does not count these subsets; a dry run does. The shares are stored in one artifact. Refer to an individual share in a later step's `reads:` as `${artifact.<name>.share_N}`; shares cannot be used in `with:` expressions. `scheme:` defaults to the only format this build supports.",
    },
    ActionMeta {
        name: "combine_shares",
        short: "Reconstruct a secret from its shares",
        long: "Set `shares:` to at least two shares created by `split_secret` or entered from custodians' sheets. Each share carries its threshold and index, so this action needs no `with:` parameters and rejects too few shares before reconstruction. Shares with different thresholds or secret lengths are rejected. Shares from separate splits with the same threshold and length cannot be distinguished, so include a later check of the recovered value in your ceremony. The recovered secret stays in memory and is erased when the run ends.",
    },
    ActionMeta {
        name: "reveal",
        short: "Show a value for someone to copy, then remove it from the screen",
        long: "Set `value:` to a byte artifact or share, such as `${artifact.shares.share_N}`. Rite displays it once: the operator reveals it, confirms that every row is written down, and the window closes. `message:` is required and explains what the value is and what to do with it. `format:` defaults to `paper32`, which prints rows of 28 base-32 characters and 4 parity characters using an alphabet without I, L, O, or U; it can correct one wrong character or recover two unreadable characters in a row. Use `hex` for hexadecimal output. The transcript records that the value was shown, not the value itself. `rite script` creates a worksheet for the step; `note:` is printed on it. Set `length:` in bytes to match the value and print the right number of rows; for a share, use the secret's length, excluding the share's three header bytes. Rite refuses a value with a different length. A dry run rehearses the step; a non-dry headless run stops because no operator is present to copy the value.",
    },
    ActionMeta {
        name: "enter_share",
        short: "Enter a share from its worksheet, one row at a time",
        long: "Use this action to enter a share from a worksheet generated by `rite script`. `message:` is required and identifies the sheet; `note:` is shown with the rows. `format:` defaults to `paper32`: each row is checked as it is typed, one wrong character is corrected and identified, and up to two unreadable characters can be entered as `?`. A row that needs more characters is requested again. Set `format: hex` for a hexadecimal worksheet. Rite rejects entries that do not decode to a share. Set `length:` to the secret's length in bytes to require the expected number of rows and reject a share for a different-sized secret. The action creates a share artifact for `combine_shares`, referenced as `${artifact.<name>}`. The transcript records the share's index and any repaired rows, never the share contents. A headless run stops here because no operator is present to enter the share.",
    },
    ActionMeta {
        name: "export_public",
        short: "Export a keypair's public key as an artifact",
        long: "Extract the public key from a keypair and store it as an artifact.",
    },
    ActionMeta {
        name: "sign_data",
        short: "Sign data using a key managed by a backend",
        long: "Sign data using a key managed by the selected backend. The signature algorithm is chosen from the key unless `algorithm:` specifies another algorithm the key supports.",
    },
    ActionMeta {
        name: "verify_signature",
        short: "Verify a signature using the signer's public key",
        long: "Check a signature over data using the signer's public key. The key can be a keypair, a public key, or a certificate containing one. Verification does not require a backend; set `backend:` to have one perform the check.",
    },
    ActionMeta {
        name: "attest",
        short: "Record a formal attestation",
        long: "Record an attestation statement in the ceremony transcript.",
    },
    ActionMeta {
        name: "gather_entropy",
        short: "Add participant-supplied entropy to the ceremony seed",
        long: "Ask a participant to provide a random value, such as the result of rolling physical dice, and mix it into the ceremony's entropy source.",
    },
    ActionMeta {
        name: "tpm_attest",
        short: "Attest to TPM measurements and device identity",
        long: "Use the TPM to produce a cryptographic quote over PCR measurements, providing hardware-backed evidence of the device's software state and identity. Available with the `tpm` feature.",
    },
    ActionMeta {
        name: "piv_read_certificate",
        short: "Read an X.509 certificate from a PIV card",
        long: "Read an X.509 certificate from a slot on a PIV smart card. No PIN is needed; PIV certificates can be read without authentication.",
    },
    ActionMeta {
        name: "piv_sign",
        short: "Sign data with a key on a PIV card",
        long: "Sign data using a key stored on a PIV smart card. The action handles PIN verification before signing.",
    },
    ActionMeta {
        name: "yubikey_attest_slot",
        short: "Attest that a PIV key was generated on a YubiKey",
        long: "Use Yubico's attestation extension to generate an attestation certificate for a PIV slot. The YubiKey's F9 key signs the slot key's certificate, providing evidence that the key was generated on the device.",
    },
    ActionMeta {
        name: "issue_certificate",
        short: "Issue an X.509 certificate from a CSR",
        long: "Create an X.509 certificate from a PKCS#10 certificate signing request (CSR), then sign it with a key managed by the selected backend.",
    },
    ActionMeta {
        name: "generate_csr",
        short: "Create and sign a PKCS#10 certificate request",
        long: "Create a PKCS#10 certificate signing request (CSR) from the subject parameters and sign it with a key managed by the selected backend.",
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
