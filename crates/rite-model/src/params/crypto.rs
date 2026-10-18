//! Params for the key and data actions.

use rite_sdk::{KeyAlgorithm, KeyUsages, SignAlgorithm, WrapScheme};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// Params for `generate_key` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GenerateKeyParams {
    /// Cryptographic algorithm (e.g., `"RSA-4096"`, `"ECDSA-P256"`).
    #[serde(default = "default_algorithm")]
    pub algorithm: KeyAlgorithm,
    /// What the key is permitted to do, and whether it may leave the backend.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
    /// Backend-specific slot hint.
    #[serde(default)]
    pub slot: Option<String>,
}

/// The `policy:` block, mirroring [`KeyPolicy`](rite_sdk::KeyPolicy) field
/// for field.
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
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
    pub usages: Option<Vec<KeyUsage>>,
}

impl KeyPolicyParams {
    /// Resolve the declared policy against a base.
    ///
    /// The base is the caller's to choose, because what a key may do when the
    /// ceremony says nothing follows from its algorithm: see
    /// [`KeyPolicy::default_for`](rite_sdk::KeyPolicy::default_for).
    #[must_use]
    pub fn resolve_from(&self, defaults: &rite_sdk::KeyPolicy) -> rite_sdk::KeyPolicy {
        let usages = self.usages.as_ref().map_or(defaults.usages, |usages| {
            usages
                .iter()
                .fold(KeyUsages::empty(), |all, usage| all | usage.0)
        });
        rite_sdk::KeyPolicy {
            persistent: self.persistent.unwrap_or(defaults.persistent),
            sensitive: self.sensitive.unwrap_or(defaults.sensitive),
            extractable: self.extractable.unwrap_or(defaults.extractable),
            wrap_with_trusted_only: self
                .wrap_with_trusted_only
                .unwrap_or(defaults.wrap_with_trusted_only),
            usages,
        }
    }
}

/// One name under `policy: { usages: [...] }`, a PKCS#11 usage.
///
/// What the token permits the key to do. The X.509 `KeyUsage` extension is a
/// different thing and comes from `profile:` on `issue_certificate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct KeyUsage(KeyUsages);

impl KeyUsage {
    /// The one usage this name stands for.
    #[must_use]
    pub fn usage(self) -> KeyUsages {
        self.0
    }
}

impl From<KeyUsage> for String {
    fn from(usage: KeyUsage) -> String {
        usage.0.describe()
    }
}

impl TryFrom<String> for KeyUsage {
    type Error = String;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        KeyUsages::usage_named(&name).map(KeyUsage).ok_or_else(|| {
            format!(
                "unknown key usage '{name}'. Supported: {}",
                KeyUsages::all_names().join(", ")
            )
        })
    }
}

impl JsonSchema for KeyUsage {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "KeyUsage".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        super::schema::names(KeyUsages::all_names().into_iter())
    }
}

fn default_algorithm() -> KeyAlgorithm {
    KeyAlgorithm::Rsa4096
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
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
    pub scheme: Option<WrapScheme>,
    /// The recipient's expected fingerprint, `"sha256:<hex>"` over its SPKI
    /// DER, for a step that reads `recipient:`.
    ///
    /// Declaring it is what turns the recorded recipient from "whatever key
    /// was present" into a value the ceremony committed to in advance. On
    /// mismatch the step fails: a key wrapped to the wrong recipient cannot be
    /// unwrapped again.
    //
    // A value in any other shape can never equal what the runtime computes,
    // which renders every fingerprint in lowercase, so the step would fail in
    // the room, after the keys exist.
    #[serde(default)]
    #[schemars(
        regex(pattern = r"^sha256:[0-9a-f]{64}$"),
        extend(
            "x-message" = "'expect_recipient' must be a fingerprint of the form \
                'sha256:<64 lowercase hex digits>'"
        )
    )]
    pub expect_recipient: Option<String>,
}

/// Params for `sign_data` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SignDataParams {
    /// Signature algorithm. Defaults to the one implied by the key.
    ///
    /// Worth setting for an RSA key, which can sign under either
    /// `"RSA-PKCS1-SHA256"` (the default) or `"RSA-PSS-SHA256"`. Every other
    /// key type admits exactly one algorithm, so naming it only restates the
    /// key.
    #[serde(default)]
    pub algorithm: Option<SignAlgorithm>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Params for `verify_signature` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VerifySignatureParams {
    /// Signature algorithm. Defaults to the one implied by the public key.
    ///
    /// Required when checking an RSA-PSS signature, since an RSA key alone
    /// does not say which scheme was used.
    #[serde(default)]
    pub algorithm: Option<SignAlgorithm>,
    /// Optional display message.
    #[serde(default)]
    pub message: Option<String>,
}

/// The identity of a key a ceremony declares in advance, in whichever form
/// the key has one.
///
/// A value in neither form can never equal what the runtime computes, so the
/// mismatch is reported before the room rather than during it.
const KEY_IDENTITY: &str = r"^(sha256:[0-9a-f]{64}|cmac-aes:[0-9a-f]{6})$";

/// Params for `unwrap_key` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UnwrapKeyParams {
    /// What the ceremony is restoring, as a key algorithm name.
    ///
    /// Nothing travels with a wrapped key saying what it is, so a recovered
    /// blob is read as whatever this names. Required to recover a symmetric
    /// key, whose bytes are indistinguishable from any other bytes of the same
    /// length. Optional for a keypair, which names itself once its DER parses,
    /// and checked against what came out when given.
    #[serde(default)]
    pub algorithm: Option<KeyAlgorithm>,
    /// The expected identity of the recovered key: `"sha256:<hex>"` over its
    /// SPKI DER for a keypair, `"cmac-aes:<hex>"` for a symmetric key.
    ///
    /// Usually the value the origin ceremony's `generate_key` step
    /// recorded. On mismatch the step fails rather than importing a key the
    /// ceremony did not mean to restore.
    #[serde(default)]
    #[schemars(
        regex(pattern = KEY_IDENTITY),
        extend("x-message" = EXPECT_KEY_MESSAGE)
    )]
    pub expect_key: Option<String>,
    /// Label for the unwrapped key.
    #[serde(default = "unwrapped_key_label")]
    pub label: String,
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

const EXPECT_KEY_MESSAGE: &str = "'expect_key' must name the key either as \
    'sha256:<64 lowercase hex digits>', the fingerprint of a public key, or as \
    'cmac-aes:<6 lowercase hex digits>', the check value of a symmetric key";

fn unwrapped_key_label() -> String {
    "unwrapped-key".to_string()
}

impl Default for UnwrapKeyParams {
    fn default() -> Self {
        Self {
            algorithm: None,
            expect_key: None,
            label: unwrapped_key_label(),
            policy: None,
        }
    }
}

/// Params for `import_key` action.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ImportKeyParams {
    /// What the bytes are, as a key algorithm name.
    ///
    /// Required, because raw material says nothing about itself: a symmetric
    /// algorithm reads the bytes as the key itself, every other one reads them
    /// as PKCS#8 DER. `unwrap_key` can leave this out for a keypair because the
    /// artifact it reads carries a description; an artifact of plain bytes
    /// carries nothing.
    pub algorithm: KeyAlgorithm,
    /// The expected identity of the imported key: `"sha256:<hex>"` over its
    /// SPKI DER for a keypair, `"cmac-aes:<hex>"` for a symmetric key.
    ///
    /// Optional, since a ceremony may be lifting material whose identity it
    /// learns only afterwards. Where it is known it is the only evidence
    /// available about material this ceremony did not itself produce.
    #[serde(default)]
    #[schemars(
        regex(pattern = KEY_IDENTITY),
        extend("x-message" = EXPECT_KEY_MESSAGE)
    )]
    pub expect_key: Option<String>,
    /// Label for the imported key.
    #[serde(default = "imported_key_label")]
    pub label: String,
    /// What the imported key is permitted to do, and whether it may leave the
    /// backend again.
    ///
    /// Nothing travels with raw key material saying what it may do, so the
    /// ceremony declares it, exactly as at `unwrap_key`.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
}

fn imported_key_label() -> String {
    "imported-key".to_string()
}

/// Params for `encrypt_data` action.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EncryptDataParams {
    /// The container, defaulting to `"CMS-AES-256-GCM"`.
    ///
    /// The only value this action accepts today. It is written out rather than
    /// implied because a second content cipher means a second container, and a
    /// ceremony that names the one it used stays readable when there are two.
    //
    // Narrower than `wrap_key`'s vocabulary on purpose: the container is the
    // only thing `encrypt_data` writes.
    #[serde(default)]
    #[schemars(schema_with = "content_schemes")]
    pub scheme: Option<WrapScheme>,
}

/// The schemes that carry content, which are the ones `encrypt_data` writes.
fn content_schemes(_: &mut SchemaGenerator) -> Schema {
    super::schema::names(
        WrapScheme::ALL
            .iter()
            .filter(|scheme| scheme.carries_content())
            .map(|scheme| scheme.as_str()),
    )
}
