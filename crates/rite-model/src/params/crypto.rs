//! Params for the key and data actions.

use rite_sdk::{KeyAlgorithm, KeyUsages, SignAlgorithm, WrapScheme};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

/// The `with` block of `generate_key`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GenerateKeyParams {
    /// The algorithm of the key to generate. Defaults to `RSA-4096`.
    #[serde(default = "default_algorithm")]
    pub algorithm: KeyAlgorithm,
    /// The key's permitted operations and whether it can be exported from the
    /// backend. A key used by a later `wrap_key` step must be extractable.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
    /// A backend-specific location for the key, such as a PIV slot or PKCS#11
    /// slot. The software backend ignores this field.
    #[serde(default)]
    pub slot: Option<String>,
}

/// What a key may do, in PKCS#11 terms.
///
/// A field left out takes the restrictive choice: the key is persistent,
/// sensitive and not extractable, and its usages are what its algorithm
/// permits, sign and verify for a keypair, wrap and unwrap for an AES key.
/// The key usage in a certificate is a different thing, set by `profile` on
/// `issue_certificate`.
//
// Mirrors `rite_sdk::KeyPolicy` field for field; the usages fall back to
// `KeyPolicy::default_for`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct KeyPolicyParams {
    /// Whether the key remains available after the session ends.
    #[serde(default)]
    pub persistent: Option<bool>,
    /// Whether the backend marks the key as sensitive and prevents plaintext
    /// access.
    #[serde(default)]
    pub sensitive: Option<bool>,
    /// Whether the key may be exported from the backend.
    #[serde(default)]
    pub extractable: Option<bool>,
    /// Whether the key may be wrapped only by a trusted key.
    #[serde(default)]
    pub wrap_with_trusted_only: Option<bool>,
    /// The operations the key may perform, such as `sign` or `unwrap`.
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

/// The `with` block of `wrap_key`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct WrapKeyParams {
    /// The wrapping scheme to use. Defaults to `CMS-AES-256-GCM`.
    //
    // The AES schemes name the size because the RFC 3394 and RFC 5649 object
    // identifiers are per size and the output carries neither.
    #[serde(default)]
    pub scheme: Option<WrapScheme>,
    /// The expected fingerprint of the recipient's public key, in the form
    /// `sha256:<64 lowercase hex digits>`. The step fails if the recipient key
    /// does not match.
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

/// The `with` block of `sign_data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SignDataParams {
    /// The signature algorithm to use. If omitted, it is inferred from the key.
    #[serde(default)]
    pub algorithm: Option<SignAlgorithm>,
    /// Shown to the operator when the step starts.
    #[serde(default)]
    pub message: Option<String>,
}

/// The `with` block of `verify_signature`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VerifySignatureParams {
    /// The signature algorithm to use. If omitted, it is inferred from the key.
    /// For an RSA-PSS signature, specify this field because an RSA key does not
    /// identify that scheme.
    #[serde(default)]
    pub algorithm: Option<SignAlgorithm>,
    /// Shown to the operator when the step starts.
    #[serde(default)]
    pub message: Option<String>,
}

/// The identity of a key a ceremony declares in advance, in whichever form
/// the key has one.
///
/// A value in neither form can never equal what the runtime computes, so the
/// mismatch is reported before the room rather than during it.
const KEY_IDENTITY: &str = r"^(sha256:[0-9a-f]{64}|cmac-aes:[0-9a-f]{6})$";

/// The `with` block of `unwrap_key`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UnwrapKeyParams {
    /// The algorithm of the recovered key. Required for a symmetric key;
    /// optional for a keypair, whose algorithm can be read from the key.
    #[serde(default)]
    pub algorithm: Option<KeyAlgorithm>,
    /// The expected identity of the key: a `sha256:` fingerprint for a keypair
    /// or a `cmac-aes:` check value for a symmetric key. The step fails if the
    /// key does not match.
    #[serde(default)]
    #[schemars(
        regex(pattern = KEY_IDENTITY),
        extend("x-message" = EXPECT_KEY_MESSAGE)
    )]
    pub expect_key: Option<String>,
    /// The label to assign to the key. Defaults to `unwrapped-key`.
    #[serde(default = "unwrapped_key_label")]
    pub label: String,
    /// The operations the recovered key may perform and whether it may be
    /// exported from the backend. Without this field, the key may sign, verify,
    /// and be wrapped again. To use it as a wrapping key, set `usages: [wrap,
    /// unwrap]`.
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

/// The `with` block of `import_key`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ImportKeyParams {
    /// The algorithm of the key the bytes hold.
    ///
    /// For an AES algorithm the bytes are the key; for any other they are
    /// PKCS#8 DER.
    pub algorithm: KeyAlgorithm,
    /// The expected identity of the key: a `sha256:` fingerprint for a keypair
    /// or a `cmac-aes:` check value for a symmetric key. The step fails if the
    /// key does not match.
    #[serde(default)]
    #[schemars(
        regex(pattern = KEY_IDENTITY),
        extend("x-message" = EXPECT_KEY_MESSAGE)
    )]
    pub expect_key: Option<String>,
    /// The label to assign to the key. Defaults to `imported-key`.
    #[serde(default = "imported_key_label")]
    pub label: String,
    /// The operations the imported key may perform and whether it may be
    /// exported from the backend.
    #[serde(default)]
    pub policy: Option<KeyPolicyParams>,
}

fn imported_key_label() -> String {
    "imported-key".to_string()
}

/// The `with` block of `encrypt_data`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct EncryptDataParams {
    /// The scheme used to encrypt the data. Defaults to `CMS-AES-256-GCM`.
    //
    // Named, because a second content cipher means a second container, and
    // a ceremony that names the one it used stays readable when there are two.
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
