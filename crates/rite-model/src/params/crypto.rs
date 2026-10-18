//! Params for the key and data actions.

use serde::{Deserialize, Serialize};

/// Params for `generate_key` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyParams {
    /// Cryptographic algorithm (e.g., `"RSA-4096"`, `"ECDSA-P256"`).
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// What the key is permitted to do, and whether it may leave the backend.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
    /// Backend-specific slot hint.
    #[serde(default)]
    pub slot: Option<String>,
}

/// The `policy:` block, mirroring [`KeyPolicy`] field for field.
///
/// Every field is optional and falls back to the restrictive choice: a
/// persistent, sensitive, non-extractable key. The usages fall back to what the
/// algorithm permits, by
/// [`KeyPolicy::default_for`](rite_sdk::KeyPolicy::default_for), so a keypair
/// may sign and verify and a symmetric key may wrap and unwrap. A ceremony that
/// wraps a key it generated has to say `extractable: true`, because otherwise
/// the key cannot leave the backend and the wrap step will refuse.
///
/// This is PKCS#11 vocabulary: what the token permits. The `KeyUsage`
/// extension in a certificate is a different thing, settled by `profile:` on
/// `issue_certificate`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyPolicyParams {
    /// Key survives the session. `CKA_TOKEN`.
    #[serde(default)]
    pub persistent: Option<bool>,
    /// Key material is never revealed in plaintext. `CKA_SENSITIVE`.
    #[serde(default)]
    pub sensitive: Option<bool>,
    /// Key may be wrapped and leave the backend. `CKA_EXTRACTABLE`.
    #[serde(default)]
    pub extractable: Option<bool>,
    /// Key may only be wrapped by a trusted wrapping key.
    /// `CKA_WRAP_WITH_TRUSTED`.
    #[serde(default)]
    pub wrap_with_trusted_only: Option<bool>,
    /// Operations the key is permitted to perform: `sign`, `verify`,
    /// `encrypt`, `decrypt`, `wrap`, `unwrap`, `derive`.
    #[serde(default)]
    pub usages: Option<Vec<String>>,
}

impl KeyPolicyParams {
    /// Resolve the declared policy against a base.
    ///
    /// The base is the caller's to choose, because what a key may do when the
    /// ceremony says nothing follows from its algorithm: see
    /// [`KeyPolicy::default_for`](rite_sdk::KeyPolicy::default_for).
    ///
    /// # Errors
    ///
    /// Returns the offending name if `usages` holds one that is not a PKCS#11
    /// usage. Resolution rejects those first, so reaching this means the step
    /// was built without going through it.
    pub fn resolve_from(
        &self,
        defaults: &rite_sdk::KeyPolicy,
    ) -> Result<rite_sdk::KeyPolicy, String> {
        let usages = match &self.usages {
            None => defaults.usages,
            Some(names) => {
                let mut usages = rite_sdk::KeyUsages::empty();
                for name in names {
                    usages |= rite_sdk::KeyUsages::usage_named(name)
                        .ok_or_else(|| format!("unknown key usage '{name}'"))?;
                }
                usages
            }
        };
        Ok(rite_sdk::KeyPolicy {
            persistent: self.persistent.unwrap_or(defaults.persistent),
            sensitive: self.sensitive.unwrap_or(defaults.sensitive),
            extractable: self.extractable.unwrap_or(defaults.extractable),
            wrap_with_trusted_only: self
                .wrap_with_trusted_only
                .unwrap_or(defaults.wrap_with_trusted_only),
            usages,
        })
    }
}

fn default_algorithm() -> String {
    "RSA-4096".to_string()
}

impl Default for GenerateKeyParams {
    fn default() -> Self {
        Self {
            algorithm: default_algorithm(),
            policy: None,
            slot: None,
        }
    }
}

/// Params for `wrap_key` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WrapKeyParams {
    /// The wrapping scheme, defaulting to `"CMS-AES-256-GCM"`.
    ///
    /// Which encapsulation a scheme takes still follows the recipient key and
    /// is never an author's choice. What the author does choose is where the
    /// blob is going: CMS carries its own algorithm identifiers and is what a
    /// ceremony archives, while the raw mechanisms are what a cloud KMS import
    /// accepts and describe nothing about themselves.
    ///
    /// A raw scheme is a weaker record: `rite verify` cannot re-derive its
    /// algorithms from the artifact, and says so rather than reporting the
    /// wrap as checked.
    ///
    /// The AES schemes wrap under a symmetric key the backend holds, so they
    /// are reachable only from a step reading `wrapping_key:`. They name the
    /// KEK size, because the RFC 3394 and RFC 5649 object identifiers are
    /// per-size and the output carries neither.
    #[serde(default)]
    pub scheme: Option<rite_sdk::WrapScheme>,
    /// The recipient's expected fingerprint, `"sha256:<hex>"` over its SPKI
    /// DER, for a step that reads `recipient:`.
    ///
    /// Declaring it is what turns the recorded recipient from "whatever key
    /// was present" into a value the ceremony committed to in advance. On
    /// mismatch the step fails: a key wrapped to the wrong recipient cannot be
    /// unwrapped again.
    #[serde(default)]
    pub expect_recipient: Option<String>,
}

/// Params for `sign_data` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignDataParams {
    /// Signature algorithm. Defaults to the one implied by the key.
    ///
    /// Worth setting for an RSA key, which can sign under either
    /// `"RSA-PKCS1-SHA256"` (the default) or `"RSA-PSS-SHA256"`. Every other
    /// key type admits exactly one algorithm, so naming it only restates the
    /// key.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `verify_signature` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifySignatureParams {
    /// Signature algorithm. Defaults to the one implied by the public key.
    ///
    /// Required when checking an RSA-PSS signature, since an RSA key alone
    /// does not say which scheme was used.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `unwrap_key` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnwrapKeyParams {
    /// What the ceremony is restoring, as a key algorithm name.
    ///
    /// Nothing travels with a wrapped key saying what it is, so a recovered
    /// blob is read as whatever this names. Required to recover a symmetric
    /// key, whose bytes are indistinguishable from any other bytes of the same
    /// length. Optional for a keypair, which names itself once its DER parses,
    /// and checked against what came out when given.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// The expected identity of the recovered key: `"sha256:<hex>"` over its
    /// SPKI DER for a keypair, `"cmac-aes:<hex>"` for a symmetric key.
    ///
    /// Usually the value the origin ceremony's `generate_key` step
    /// recorded. On mismatch the step fails rather than importing a key the
    /// ceremony did not mean to restore.
    #[serde(default)]
    pub expect_key: Option<String>,
    /// Label for the unwrapped key (defaults to `"unwrapped-key"`).
    #[serde(default)]
    pub label: Option<String>,
    /// What the recovered key is permitted to do, and whether it may leave
    /// the backend again.
    ///
    /// Nothing travels with a wrapped key that says what it may do, so the
    /// receiving ceremony declares that. Without a `policy:` the key may sign,
    /// verify and be wrapped again; a key restored to serve as a wrapping key
    /// has to say `usages: [wrap, unwrap]`.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
}

/// Params for `import_key` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportKeyParams {
    /// What the bytes are, as a key algorithm name.
    ///
    /// Required, because raw material says nothing about itself: a symmetric
    /// algorithm reads the bytes as the key itself, every other one reads them
    /// as PKCS#8 DER. `unwrap_key` can leave this out for a keypair because the
    /// artifact it reads carries a description; an artifact of plain bytes
    /// carries nothing.
    pub algorithm: String,
    /// The expected identity of the imported key: `"sha256:<hex>"` over its
    /// SPKI DER for a keypair, `"cmac-aes:<hex>"` for a symmetric key.
    ///
    /// Optional, since a ceremony may be lifting material whose identity it
    /// learns only afterwards. Where it is known it is the only evidence
    /// available about material this ceremony did not itself produce.
    #[serde(default)]
    pub expect_key: Option<String>,
    /// Label for the imported key (defaults to `"imported-key"`).
    #[serde(default)]
    pub label: Option<String>,
    /// What the imported key is permitted to do, and whether it may leave the
    /// backend again.
    ///
    /// Nothing travels with raw key material saying what it may do, so the
    /// ceremony declares it, exactly as at `unwrap_key`.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
}

/// Params for `encrypt_data` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptDataParams {
    /// The container, defaulting to `"CMS-AES-256-GCM"`.
    ///
    /// The only value this action accepts today. It is written out rather than
    /// implied because a second content cipher means a second container, and a
    /// ceremony that names the one it used stays readable when there are two.
    #[serde(default)]
    pub scheme: Option<rite_sdk::WrapScheme>,
}
