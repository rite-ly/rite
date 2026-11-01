//! Read a CMS artifact back into a description of the wrap that produced it.
//!
//! The wrapping algorithms are not derivable from the wrapping key: the KEK
//! size follows the content cipher, and the ECDH KDF digest is a library
//! default. So the evidence has to come from the DER itself, which is also
//! what an independent verifier has. This module walks that DER far enough to
//! name the algorithm identifiers and the recipient, and no further; it never
//! decrypts and never touches key material.
//!
//! Rite writes one recipient per wrap, so a `RecipientInfo` set is described by
//! its first member. A foreign blob addressed to several recipients is
//! described by the first of them, and the others are not reported.

use std::fmt;

use crate::der;
use crate::key_material::PublicKeyDer;
use crate::types::{
    KeyAlgorithm, KeyCheckValue, KeyFingerprint, Oid, RecipientInfoKind, WrapDescription, oid,
};

/// `id-envelopedData` (RFC 5652 §6).
const ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
/// `id-ct-authEnvelopedData` (RFC 5083).
const AUTH_ENVELOPED_DATA: &str = "1.2.840.113549.1.9.16.1.23";
/// `id-ori-kem` (RFC 9629 §3), the `OtherRecipientInfo` carrying a KEM.
const ORI_KEM: &str = "1.2.840.113549.1.9.16.13.3";

/// A CMS artifact could not be read as a wrap.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("CMS artifact is not readable as a wrap: {0}")]
pub struct CmsReadError(String);

/// What a CMS artifact says about the wrap that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsFacts {
    /// The algorithm identifiers, as recorded on the wrap.
    pub description: WrapDescription,
    /// What the artifact names its recipient by. `None` when the recipient is
    /// named by issuer and serial, which identifies a certificate rather than
    /// a key.
    pub recipient_key_identifier: Option<RecipientIdentifier>,
}

/// The bytes a CMS container names its recipient by: `kekid.keyIdentifier` in
/// a `KEKRecipientInfo`, the `subjectKeyIdentifier` rid in a
/// `KeyTransRecipientInfo`, the `rKeyId` subject key identifier in a
/// `KeyAgreeRecipientInfo`.
///
/// Opaque. A container Rite writes carries a [`KeyCheckValue`] or a
/// [`KeyFingerprint`] here, and one written elsewhere carries whatever its
/// writer chose, an [`Rfc5280KeyId`](crate::Rfc5280KeyId) more often than not.
/// Nothing in the bytes says which, their length included: 32 bytes need not
/// be a SHA-256, and a SHA-256 need not be over the SPKI. So the bytes are
/// never read as a name. They are compared with a name a key has:
/// [`names_key`](Self::names_key) with the key at hand, or
/// [`is_fingerprint`](Self::is_fingerprint) and
/// [`is_check_value`](Self::is_check_value) with a name the transcript
/// recorded.
///
/// Rendered as bare hex, since a `sha256:` or `cmac-aes:` prefix would claim
/// to know what the bytes are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientIdentifier(Vec<u8>);

impl RecipientIdentifier {
    /// Bytes a writer chose to name a recipient by.
    ///
    /// Nothing is checked, since nothing is claimed: the bytes name a key only
    /// once they match one.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes as the container carries them.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether these bytes name `key`, by either name it goes by in a
    /// container: its [`KeyFingerprint`], which Rite writes, or its
    /// [`Rfc5280KeyId`](crate::Rfc5280KeyId), which a container sealed to a
    /// certificate usually carries.
    #[must_use]
    pub fn names_key(&self, key: &PublicKeyDer) -> bool {
        // The SPKI parsed when `key` was built, so the identifier derives; a
        // key that somehow did not would not be named by it either.
        self.is_fingerprint(&key.fingerprint())
            || key
                .rfc5280_key_identifier()
                .is_ok_and(|id| self.0 == id.as_bytes())
    }

    /// Whether these bytes are `fingerprint`.
    ///
    /// For comparing a container with a recorded name, where no key is at
    /// hand. A container naming the same key by its RFC 5280 identifier does
    /// not match, because that name cannot be derived from a fingerprint.
    #[must_use]
    pub fn is_fingerprint(&self, fingerprint: &KeyFingerprint) -> bool {
        self.0 == fingerprint.as_bytes()
    }

    /// Whether these bytes are `check_value`.
    #[must_use]
    pub fn is_check_value(&self, check_value: &KeyCheckValue) -> bool {
        self.0 == check_value.as_bytes()
    }
}

impl From<KeyFingerprint> for RecipientIdentifier {
    fn from(fingerprint: KeyFingerprint) -> Self {
        Self(fingerprint.as_bytes().to_vec())
    }
}

impl From<&KeyCheckValue> for RecipientIdentifier {
    fn from(check_value: &KeyCheckValue) -> Self {
        Self(check_value.as_bytes().to_vec())
    }
}

impl fmt::Display for RecipientIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base16ct::lower::encode_string(&self.0))
    }
}

/// Read a CMS `ContentInfo` DER into the facts of its wrap.
///
/// # Errors
///
/// Returns [`CmsReadError`] if the bytes are not a definite-length DER
/// `ContentInfo` carrying `EnvelopedData` or `AuthEnvelopedData` with at
/// least one recipient.
pub fn describe(der: &[u8]) -> Result<CmsFacts, CmsReadError> {
    let (content_info, rest) = read_tlv(der)?;
    if !rest.is_empty() {
        return Err(err("trailing bytes after ContentInfo"));
    }
    let body = content_info.expect_tag(TAG_SEQUENCE, "ContentInfo")?;

    let (content_type, after_type) = read_tlv(body)?;
    let content_type = oid_of(&content_type, "ContentInfo.contentType")?;
    match content_type.as_str() {
        ENVELOPED_DATA | AUTH_ENVELOPED_DATA => {}
        other => {
            return Err(err(format!(
                "content type {other} is not an enveloped structure"
            )));
        }
    }

    let (explicit_content, _) = read_tlv(after_type)?;
    let content = explicit_content.expect_tag(TAG_CONTEXT_0_CONSTRUCTED, "ContentInfo.content")?;
    let (enveloped, _) = read_tlv(content)?;
    let enveloped = enveloped.expect_tag(TAG_SEQUENCE, "EnvelopedData")?;

    // version, then the optional implicit [0] originatorInfo, then the
    // recipient set and the encrypted content.
    let (_version, after_version) = read_tlv(enveloped)?;
    let (next, after_next) = read_tlv(after_version)?;
    let (recipients, after_recipients) = if next.tag == TAG_CONTEXT_0_CONSTRUCTED {
        read_tlv(after_next)?
    } else {
        (next, after_next)
    };
    let recipients = recipients.expect_tag(TAG_SET, "recipientInfos")?;

    let (first_recipient, _) = read_tlv(recipients)?;
    let recipient = read_recipient(&first_recipient)?;

    let (encrypted_content_info, _) = read_tlv(after_recipients)?;
    let content_encryption = content_encryption_oid(&encrypted_content_info)?;

    Ok(CmsFacts {
        description: recipient
            .description
            .with_content_encryption(content_encryption),
        recipient_key_identifier: recipient.key_identifier,
    })
}

/// What one `RecipientInfo` contributes to the description.
struct RecipientFacts {
    description: WrapDescription,
    key_identifier: Option<RecipientIdentifier>,
}

fn read_recipient(info: &Tlv<'_>) -> Result<RecipientFacts, CmsReadError> {
    match info.tag {
        TAG_SEQUENCE => {
            let ktri = read_ktri(info.value)?;
            let algorithm = algorithm_oid(&ktri.algorithm, "keyEncryptionAlgorithm")?;
            // The description names the OAEP identifier and not its
            // parameters, so OAEP over SHA-1 would describe exactly as OAEP
            // over SHA-256 does, and a record of one would check as the other.
            // Only the parameters this crate writes and opens are described.
            if algorithm.as_str() == oid::RSAES_OAEP {
                require_rsaes_oaep_sha256(&ktri.algorithm)?;
            }
            Ok(RecipientFacts {
                description: WrapDescription::new(RecipientInfoKind::Ktri, algorithm),
                key_identifier: ktri
                    .key_identifier
                    .map(|bytes| RecipientIdentifier(bytes.to_vec())),
            })
        }
        TAG_CONTEXT_1_CONSTRUCTED => read_kari(info.value),
        TAG_CONTEXT_2_CONSTRUCTED => {
            let kekri = read_kekri(info.value)?;
            Ok(RecipientFacts {
                description: WrapDescription::new(RecipientInfoKind::Kekri, kekri.algorithm),
                key_identifier: Some(RecipientIdentifier(kekri.key_identifier.to_vec())),
            })
        }
        TAG_CONTEXT_3_CONSTRUCTED => Err(err("PasswordRecipientInfo is not a key wrap")),
        TAG_CONTEXT_4_CONSTRUCTED => read_ori(info.value),
        other => Err(err(format!("unknown RecipientInfo tag 0x{other:02x}"))),
    }
}

/// The fields of a `KeyTransRecipientInfo` (RFC 5652 §6.2.1).
struct Ktri<'a> {
    /// The subject key identifier, or `None` when the recipient is named by
    /// issuer and serial, which identifies a certificate rather than a key.
    key_identifier: Option<&'a [u8]>,
    algorithm: Tlv<'a>,
    encrypted_key: &'a [u8],
}

/// Walk a `KeyTransRecipientInfo`: version, rid, keyEncryptionAlgorithm,
/// encryptedKey.
///
/// One walker for describing and opening, for the reason [`read_kekri`] gives.
/// It reads the structure exactly, so a blob `rite verify` describes is one
/// the opener would also read.
fn read_ktri(body: &[u8]) -> Result<Ktri<'_>, CmsReadError> {
    let (version, after_version) = read_tlv(body)?;
    let (rid, after_rid) = read_tlv(after_version)?;
    let (algorithm, after_algorithm) = read_tlv(after_rid)?;
    let (encrypted_key, after_encrypted_key) = read_tlv(after_algorithm)?;
    if !after_encrypted_key.is_empty() {
        return Err(err(
            "KeyTransRecipientInfo carries bytes after encryptedKey",
        ));
    }

    // rid is either IssuerAndSerialNumber or the implicit [0]
    // subjectKeyIdentifier, and RFC 5652 §6.2.1 ties the version to which:
    // 0 for the first, 2 for the second.
    let key_identifier = (rid.tag == TAG_CONTEXT_0_PRIMITIVE).then_some(rid.value);
    let (form, expected) = if key_identifier.is_some() {
        ("subject key identifier", 2)
    } else {
        ("issuer and serial number", 0)
    };
    if version.expect_tag(TAG_INTEGER, "KeyTransRecipientInfo.version")? != [expected] {
        return Err(err(format!(
            "a KeyTransRecipientInfo naming its key by {form} must be version {expected}"
        )));
    }

    Ok(Ktri {
        key_identifier,
        algorithm,
        encrypted_key: encrypted_key.expect_tag(TAG_OCTET_STRING, "encryptedKey")?,
    })
}

/// Admit exactly RSAES-OAEP with SHA-256, MGF1 over SHA-256, and the empty
/// label, which is what [`KeyProtection::RsaOaepSha256`] is.
///
/// Every field of `RSAES-OAEP-params` defaults to SHA-1 (RFC 8017 A.2.1), so
/// an absent field is a different algorithm rather than an unspecified one,
/// and each is checked by what it says rather than by being there.
///
/// Every element is read exactly, with nothing after it, so two encodings that
/// differ only in trailing bytes are not both admitted as the same algorithm.
fn require_rsaes_oaep_sha256(algorithm: &Tlv<'_>) -> Result<(), CmsReadError> {
    let (identifier, parameters) = exact_algorithm_parts(algorithm, "keyEncryptionAlgorithm")?;
    match identifier.as_str() {
        oid::RSAES_OAEP => {}
        oid::RSA_ENCRYPTION => {
            // A reader that answers differently to a bad padding and a good
            // one is the oracle Bleichenbacher's attack queries, so this one
            // does not open the padding at all.
            return Err(err(
                "the key transport is RSAES-PKCS1-v1_5, which this reader does not open",
            ));
        }
        other => {
            return Err(err(format!(
                "key transport algorithm {other} is not id-RSAES-OAEP"
            )));
        }
    }

    let parameters =
        parameters.ok_or_else(|| err("RSAES-OAEP without parameters is OAEP over SHA-1"))?;
    let fields = parameters.expect_tag(TAG_SEQUENCE, "RSAES-OAEP-params")?;

    let (hash, after_hash) = read_tlv(fields)
        .ok()
        .filter(|(field, _)| field.tag == TAG_CONTEXT_0_CONSTRUCTED)
        .ok_or_else(|| err("RSAES-OAEP-params names no hashFunc, which means SHA-1"))?;
    require_sha256(&sole_element(hash.value, "hashFunc")?, "hashFunc")?;

    let (mask, after_mask) = read_tlv(after_hash)
        .ok()
        .filter(|(field, _)| field.tag == TAG_CONTEXT_1_CONSTRUCTED)
        .ok_or_else(|| {
            err("RSAES-OAEP-params names no maskGenFunc, which means MGF1 over SHA-1")
        })?;
    let (mask_function, mask_parameters) =
        exact_algorithm_parts(&sole_element(mask.value, "maskGenFunc")?, "maskGenFunc")?;
    if mask_function.as_str() != oid::MGF1 {
        return Err(err(format!("maskGenFunc {mask_function} is not id-mgf1")));
    }
    let mask_hash =
        mask_parameters.ok_or_else(|| err("maskGenFunc names MGF1 with no hash function"))?;
    require_sha256(&mask_hash, "maskGenFunc")?;

    if !after_mask.is_empty() {
        // DER omits a field equal to its DEFAULT, so a pSourceFunc that is
        // present names a label other than the empty one.
        return Err(err(
            "RSAES-OAEP-params carries a pSourceFunc, which names a label this reader does not use",
        ));
    }
    Ok(())
}

/// Admit an `AlgorithmIdentifier` naming SHA-256.
///
/// RFC 4055 §2.1 has a reader accept the parameters absent or NULL, since
/// implementations write both.
fn require_sha256(identifier: &Tlv<'_>, field: &str) -> Result<(), CmsReadError> {
    let (digest, parameters) = exact_algorithm_parts(identifier, field)?;
    if digest.as_str() != oid::SHA_256 {
        return Err(err(format!(
            "{field} is {digest}, and this reader opens RSAES-OAEP over SHA-256"
        )));
    }
    match parameters {
        None
        | Some(Tlv {
            tag: TAG_NULL,
            value: [],
        }) => Ok(()),
        Some(_) => Err(err(format!("{field}: SHA-256 takes no parameters"))),
    }
}

/// The fields of a `KEKRecipientInfo` (RFC 5652 §6.2.3).
struct Kekri<'a> {
    key_identifier: &'a [u8],
    algorithm: Oid,
    encrypted_key: &'a [u8],
}

/// Walk a `KEKRecipientInfo`: version, kekid, keyEncryptionAlgorithm,
/// encryptedKey.
///
/// The recipient is a key both sides already hold, so there is no public key
/// and nothing to name one by. `kekid.keyIdentifier` is what identifies it,
/// and Rite puts the key's check value there, which is the same value the
/// transcript records and a token displays.
///
/// One walker for both readers: describing a wrap needs the identifier and the
/// algorithm, opening one needs the identifier and the encrypted key, and two
/// functions stepping through the same structure would be two places to get
/// the field order wrong.
///
/// Read exactly, as [`read_ktri`] is: version 4, which RFC 5652 §6.2.3 fixes,
/// and nothing after `encryptedKey`.
fn read_kekri(body: &[u8]) -> Result<Kekri<'_>, CmsReadError> {
    let (version, after_version) = read_tlv(body)?;
    let (kekid, after_kekid) = read_tlv(after_version)?;
    let (algorithm, after_algorithm) = read_tlv(after_kekid)?;
    let (encrypted_key, after_encrypted_key) = read_tlv(after_algorithm)?;
    if version.expect_tag(TAG_INTEGER, "KEKRecipientInfo.version")? != [4] {
        return Err(err("a KEKRecipientInfo must be version 4"));
    }
    if !after_encrypted_key.is_empty() {
        return Err(err("KEKRecipientInfo carries bytes after encryptedKey"));
    }

    let (key_identifier, after_identifier) =
        read_tlv(kekid.expect_tag(TAG_SEQUENCE, "KEKIdentifier")?)?;
    key_identifier_options(after_identifier, "KEKIdentifier")?;
    Ok(Kekri {
        key_identifier: key_identifier.expect_tag(TAG_OCTET_STRING, "kekid.keyIdentifier")?,
        algorithm: algorithm_oid(&algorithm, "keyEncryptionAlgorithm")?,
        encrypted_key: encrypted_key.expect_tag(TAG_OCTET_STRING, "encryptedKey")?,
    })
}

/// What may follow the key identifier in a `KEKIdentifier` or an `rKeyId`
/// (`field` names which): a `date` (`GeneralizedTime`), then an `other`
/// (`OtherKeyAttribute`, a SEQUENCE), each optional, and nothing else.
///
/// Both are legitimate in a container sealed elsewhere and neither changes
/// which key opens it, so they are admitted and not read.
fn key_identifier_options(mut rest: &[u8], field: &str) -> Result<(), CmsReadError> {
    for tag in [TAG_GENERALIZED_TIME, TAG_SEQUENCE] {
        if let Some(&next) = rest.first()
            && next == tag
        {
            rest = read_tlv(rest)?.1;
        }
    }
    if rest.is_empty() {
        Ok(())
    } else {
        Err(err(format!(
            "{field} carries bytes after its optional fields"
        )))
    }
}

/// `KeyAgreeRecipientInfo`: version, [0] originator, [1] ukm OPTIONAL,
/// keyEncryptionAlgorithm, recipientEncryptedKeys.
///
/// RFC 5753 folds the KDF into the key-encryption OID itself, so the KDF is
/// named there rather than in a field of its own. The algorithm's parameter
/// is the identifier of the wrap applied to the CEK under the derived KEK.
fn read_kari(body: &[u8]) -> Result<RecipientFacts, CmsReadError> {
    let kari = read_kari_fields(body)?;
    let (scheme, parameters) = algorithm_parts(&kari.algorithm, "keyEncryptionAlgorithm")?;
    let mut description = WrapDescription::new(RecipientInfoKind::Kari, scheme);
    if let Some(parameters) = parameters {
        description = description.with_kek_wrap(algorithm_oid(&parameters, "keyWrapAlgorithm")?);
    }
    Ok(RecipientFacts {
        description,
        key_identifier: kari
            .key_identifier
            .map(|bytes| RecipientIdentifier(bytes.to_vec())),
    })
}

/// The fields of a `KeyAgreeRecipientInfo` (RFC 5652 §6.2.2), with the first
/// key it addresses.
struct Kari<'a> {
    /// The `OriginatorIdentifierOrKey` CHOICE element.
    originator: Tlv<'a>,
    /// The `ukm`'s octets, when present.
    ukm: Option<&'a [u8]>,
    algorithm: Tlv<'a>,
    /// The first recipient key's subject key identifier, or `None` when it is
    /// named by issuer and serial.
    key_identifier: Option<&'a [u8]>,
    /// The first recipient key's encrypted key.
    encrypted_key: &'a [u8],
    /// Whether `recipientEncryptedKeys` addresses further keys after the
    /// first.
    more_keys: bool,
}

/// Read the fields of a `KeyAgreeRecipientInfo`.
///
/// Requires version 3 and reads the structure to its end. When
/// `recipientEncryptedKeys` contains several entries, returns the first.
/// Opening refuses a `KeyAgreeRecipientInfo` that addresses more than one key.
fn read_kari_fields(body: &[u8]) -> Result<Kari<'_>, CmsReadError> {
    let (version, after_version) = read_tlv(body)?;
    if version.expect_tag(TAG_INTEGER, "KeyAgreeRecipientInfo.version")? != [3] {
        return Err(err("a KeyAgreeRecipientInfo must be version 3"));
    }
    let (originator, after_originator) = read_tlv(after_version)?;
    let originator = sole_element(
        originator.expect_tag(
            TAG_CONTEXT_0_CONSTRUCTED,
            "KeyAgreeRecipientInfo.originator",
        )?,
        "KeyAgreeRecipientInfo.originator",
    )?;

    let (next, after_next) = read_tlv(after_originator)?;
    let (ukm, (algorithm, after_algorithm)) = if next.tag == TAG_CONTEXT_1_CONSTRUCTED {
        let ukm = sole_element(next.value, "ukm")?.expect_tag(TAG_OCTET_STRING, "ukm")?;
        (Some(ukm), read_tlv(after_next)?)
    } else {
        (None, (next, after_next))
    };

    let (recipient_keys, after_keys) = read_tlv(after_algorithm)?;
    if !after_keys.is_empty() {
        return Err(err(
            "KeyAgreeRecipientInfo carries bytes after recipientEncryptedKeys",
        ));
    }
    let recipient_keys = recipient_keys.expect_tag(TAG_SEQUENCE, "recipientEncryptedKeys")?;
    let (recipient_key, more) = read_tlv(recipient_keys)?;
    let (rid, after_rid) =
        read_tlv(recipient_key.expect_tag(TAG_SEQUENCE, "RecipientEncryptedKey")?)?;
    let encrypted_key = sole_element(after_rid, "RecipientEncryptedKey")?
        .expect_tag(TAG_OCTET_STRING, "encryptedKey")?;

    // rid is an IssuerAndSerialNumber or the implicit [0]
    // RecipientKeyIdentifier, whose optional date and other follow the
    // identifier exactly as they do in a KEKIdentifier.
    let key_identifier = if rid.tag == TAG_CONTEXT_0_CONSTRUCTED {
        let (identifier, after_identifier) = read_tlv(rid.value)?;
        key_identifier_options(after_identifier, "rKeyId")?;
        Some(identifier.expect_tag(TAG_OCTET_STRING, "rKeyId.subjectKeyIdentifier")?)
    } else {
        rid.expect_tag(TAG_SEQUENCE, "rid.issuerAndSerialNumber")?;
        None
    };

    // Every further entry is read as a RecipientEncryptedKey, so trailing
    // bytes are malformed DER rather than a second key.
    let mut rest = more;
    while !rest.is_empty() {
        let (further, after) = read_tlv(rest)?;
        further.expect_tag(TAG_SEQUENCE, "RecipientEncryptedKey")?;
        rest = after;
    }

    Ok(Kari {
        originator,
        ukm,
        algorithm,
        key_identifier,
        encrypted_key,
        more_keys: !more.is_empty(),
    })
}

/// Read an uncompressed EC point from an `originatorKey`.
///
/// Accepts only `id-ecPublicKey` with absent or NULL parameters. A named
/// curve is refused because this reader takes the curve from the recipient's
/// key.
fn originator_point<'a>(originator: &Tlv<'a>) -> Result<&'a [u8], CmsReadError> {
    let body = match originator.tag {
        TAG_CONTEXT_1_CONSTRUCTED => originator.value,
        _ => {
            return Err(err(
                "the originator is named rather than given as a key, and an ephemeral key is \
                 what the agreement needs",
            ));
        }
    };
    let (algorithm, after_algorithm) = read_tlv(body)?;
    let (identifier, parameters) = exact_algorithm_parts(&algorithm, "originatorKey.algorithm")?;
    if identifier.as_str() != oid::ID_EC_PUBLIC_KEY {
        return Err(err(format!(
            "the originator key is {identifier}, and this reader agrees over id-ecPublicKey"
        )));
    }
    match parameters {
        None
        | Some(Tlv {
            tag: TAG_NULL,
            value: [],
        }) => {}
        Some(_) => {
            return Err(err(
                "the originator key names its curve, which this reader does not open",
            ));
        }
    }
    let key = sole_element(after_algorithm, "originatorKey")?
        .expect_tag(TAG_BIT_STRING, "originatorKey.publicKey")?;
    match key.split_first() {
        Some((0, point @ [0x04, ..])) => Ok(point),
        Some((0, [_, ..])) => Err(err(
            "the originator key's point is compressed, and Rite accepts EC points uncompressed",
        )),
        _ => Err(err(
            "originatorKey.publicKey is not a whole number of bytes",
        )),
    }
}

/// The KDF a `keyEncryptionAlgorithm` names, admitting only AES-256 key wrap
/// under it, which is the wrap this crate writes and opens.
///
/// RFC 5753 folds the KDF into the scheme's identifier and makes the wrap its
/// parameter. The wrap identifier takes no parameters (RFC 3565 §2.3.2).
fn agreement_kdf(algorithm: &Tlv<'_>) -> Result<X963Kdf, CmsReadError> {
    let (scheme, parameters) = exact_algorithm_parts(algorithm, "keyEncryptionAlgorithm")?;
    let kdf = match scheme.as_str() {
        oid::DH_SINGLE_PASS_STDDH_SHA256KDF => X963Kdf::Sha256,
        oid::DH_SINGLE_PASS_STDDH_SHA384KDF => X963Kdf::Sha384,
        oid::DH_SINGLE_PASS_STDDH_SHA1KDF => {
            return Err(err(
                "the key agreement derives its key with SHA-1, which this reader does not open",
            ));
        }
        other => {
            return Err(err(format!(
                "key agreement scheme {other} is not ECDH with the X9.63 KDF over SHA-256 or \
                 SHA-384"
            )));
        }
    };
    let wrap = parameters.ok_or_else(|| err("the key agreement names no key wrap"))?;
    let (wrap, wrap_parameters) = exact_algorithm_parts(&wrap, "keyWrapAlgorithm")?;
    if wrap.as_str() != oid::AES_256_WRAP || wrap_parameters.is_some() {
        return Err(err(format!(
            "key wrap algorithm {wrap} is not id-aes256-wrap without parameters"
        )));
    }
    Ok(kdf)
}

/// `OtherRecipientInfo`: an `oriType` OID and a value read according to it.
fn read_ori(body: &[u8]) -> Result<RecipientFacts, CmsReadError> {
    let (oid, after_oid) = read_tlv(body)?;
    let oid = oid_of(&oid, "OtherRecipientInfo.oriType")?;
    if oid.as_str() != ORI_KEM {
        // A form this build does not know: name it and read no further,
        // rather than guess at a structure whose shape is defined elsewhere.
        return Ok(RecipientFacts {
            description: WrapDescription::new(RecipientInfoKind::Ori, oid),
            key_identifier: None,
        });
    }
    let (kemri, _) = read_tlv(after_oid)?;
    read_kemri(kemri.expect_tag(TAG_SEQUENCE, "KEMRecipientInfo")?)
}

/// `KEMRecipientInfo` (RFC 9629 §3): version, rid, kem, kemct, kdf,
/// kekLength, [0] ukm OPTIONAL, wrap, encryptedKey.
///
/// Unlike the key-agreement form, a KEM names its KDF in a field of its own,
/// which is what the `kdf_oid` on a description is for.
fn read_kemri(body: &[u8]) -> Result<RecipientFacts, CmsReadError> {
    let (_version, after_version) = read_tlv(body)?;
    let (rid, after_rid) = read_tlv(after_version)?;
    let (kem, after_kem) = read_tlv(after_rid)?;
    let (_kemct, after_kemct) = read_tlv(after_kem)?;
    let (kdf, after_kdf) = read_tlv(after_kemct)?;
    let (_kek_length, after_kek_length) = read_tlv(after_kdf)?;

    let (next, after_next) = read_tlv(after_kek_length)?;
    let (wrap, _) = if next.tag == TAG_CONTEXT_0_CONSTRUCTED {
        read_tlv(after_next)?
    } else {
        (next, after_next)
    };

    let description = WrapDescription::new(
        RecipientInfoKind::Kemri,
        algorithm_oid(&kem, "KEMRecipientInfo.kem")?,
    )
    .with_kdf(algorithm_oid(&kdf, "KEMRecipientInfo.kdf")?)
    .with_kek_wrap(algorithm_oid(&wrap, "KEMRecipientInfo.wrap")?);

    Ok(RecipientFacts {
        description,
        key_identifier: (rid.tag == TAG_CONTEXT_0_PRIMITIVE)
            .then(|| RecipientIdentifier(rid.value.to_vec())),
    })
}

/// The one element `bytes` holds, refusing anything after it.
fn sole_element<'a>(bytes: &'a [u8], field: &str) -> Result<Tlv<'a>, CmsReadError> {
    let (element, rest) = read_tlv(bytes)?;
    if rest.is_empty() {
        Ok(element)
    } else {
        Err(err(format!("{field} carries bytes after its value")))
    }
}

/// [`algorithm_parts`], refusing anything after the parameters.
fn exact_algorithm_parts<'a>(
    algorithm: &Tlv<'a>,
    field: &str,
) -> Result<(Oid, Option<Tlv<'a>>), CmsReadError> {
    let body = algorithm.expect_tag(TAG_SEQUENCE, field)?;
    let (oid, rest) = read_tlv(body)?;
    let oid = oid_of(&oid, field)?;
    if rest.is_empty() {
        return Ok((oid, None));
    }
    Ok((oid, Some(sole_element(rest, field)?)))
}

/// The content cipher, from `EncryptedContentInfo`: contentType,
/// contentEncryptionAlgorithm, then the optional encrypted content.
fn content_encryption_oid(info: &Tlv<'_>) -> Result<Oid, CmsReadError> {
    let body = info.expect_tag(TAG_SEQUENCE, "encryptedContentInfo")?;
    let (_content_type, after_type) = read_tlv(body)?;
    let (algorithm, _) = read_tlv(after_type)?;
    algorithm_oid(&algorithm, "contentEncryptionAlgorithm")
}

/// The `algorithm` field of an `AlgorithmIdentifier`.
fn algorithm_oid(algorithm: &Tlv<'_>, field: &str) -> Result<Oid, CmsReadError> {
    Ok(algorithm_parts(algorithm, field)?.0)
}

/// The `algorithm` and `parameters` fields of an `AlgorithmIdentifier`.
fn algorithm_parts<'a>(
    algorithm: &Tlv<'a>,
    field: &str,
) -> Result<(Oid, Option<Tlv<'a>>), CmsReadError> {
    let body = algorithm.expect_tag(TAG_SEQUENCE, field)?;
    let (oid, rest) = read_tlv(body)?;
    let oid = oid_of(&oid, field)?;
    let parameters = if rest.is_empty() {
        None
    } else {
        Some(read_tlv(rest)?.0)
    };
    Ok((oid, parameters))
}

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0_PRIMITIVE: u8 = 0x80;
const TAG_CONTEXT_0_CONSTRUCTED: u8 = 0xa0;
const TAG_CONTEXT_1_CONSTRUCTED: u8 = 0xa1;
const TAG_CONTEXT_2_CONSTRUCTED: u8 = 0xa2;
const TAG_CONTEXT_3_CONSTRUCTED: u8 = 0xa3;
const TAG_CONTEXT_4_CONSTRUCTED: u8 = 0xa4;

/// One DER element: its tag and the bytes of its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// The value bytes, if the element carries the expected tag.
    fn expect_tag(&self, tag: u8, field: &str) -> Result<&'a [u8], CmsReadError> {
        if self.tag == tag {
            Ok(self.value)
        } else {
            Err(err(format!(
                "{field}: expected tag 0x{tag:02x}, found 0x{:02x}",
                self.tag
            )))
        }
    }
}

/// Split one element off the front of `input`, returning it and the remainder.
///
/// Definite-length DER only: an indefinite length is BER, which no CMS
/// structure Rite produces or accepts uses.
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), CmsReadError> {
    let (&tag, after_tag) = input.split_first().ok_or_else(|| err("truncated tag"))?;
    let (&first_length, after_first) = after_tag
        .split_first()
        .ok_or_else(|| err("truncated length"))?;

    let (length, after_length) = match first_length {
        short if short < 0x80 => (usize::from(short), after_first),
        0x80 => return Err(err("indefinite length is BER, not DER")),
        long => {
            let count = usize::from(long & 0x7f);
            if count > std::mem::size_of::<usize>() {
                return Err(err("length does not fit in a usize"));
            }
            let (bytes, rest) = after_first
                .split_at_checked(count)
                .ok_or_else(|| err("truncated long-form length"))?;
            let length = bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            (length, rest)
        }
    };

    let (value, rest) = after_length
        .split_at_checked(length)
        .ok_or_else(|| err("value runs past the end of the input"))?;
    Ok((Tlv { tag, value }, rest))
}

/// Decode an OBJECT IDENTIFIER element into dotted-decimal form.
///
/// X.690 §8.19: every arc is base-128 with a continuation bit, and the first
/// subidentifier packs the first two arcs as `40 * first + second`. That
/// packed value is a subidentifier like any other, so it may span several
/// bytes: `2.100` encodes as `0x81 0x34`, not as a single byte.
fn oid_of(element: &Tlv<'_>, field: &str) -> Result<Oid, CmsReadError> {
    let bytes = element.expect_tag(TAG_OID, field)?;

    let mut subidentifiers = Vec::new();
    let mut value: u64 = 0;
    let mut pending = false;
    for &byte in bytes {
        value = value
            .checked_mul(128)
            .and_then(|shifted| shifted.checked_add(u64::from(byte & 0x7f)))
            .ok_or_else(|| err(format!("{field}: OID arc overflows")))?;
        pending = byte & 0x80 != 0;
        if !pending {
            subidentifiers.push(value);
            value = 0;
        }
    }
    if pending {
        return Err(err(format!("{field}: OID ends mid-arc")));
    }

    let (&packed, rest) = subidentifiers
        .split_first()
        .ok_or_else(|| err(format!("{field}: empty OID")))?;
    // The first arc is 0, 1 or 2, and only arc 2 may carry a second arc above
    // 39, which is why the packed value cannot simply be divided.
    let (first, second) = match packed.checked_sub(80) {
        Some(above) => (2, above),
        None => (packed / 40, packed % 40),
    };

    let mut arcs = vec![first.to_string(), second.to_string()];
    arcs.extend(rest.iter().map(u64::to_string));
    Oid::new(&arcs.join(".")).map_err(|e| err(format!("{field}: {e}")))
}

fn err(message: impl Into<String>) -> CmsReadError {
    CmsReadError(message.into())
}

/// `id-data` (RFC 5652 §4), the content type of a wrapped key.
const DATA: &str = "1.2.840.113549.1.7.1";

/// The authentication tag lengths `GCMParameters.aes-ICVlen` may name, in
/// bytes (RFC 5084 §3.2: `AES-GCM-ICVlen ::= INTEGER (12 | 13 | 14 | 15 | 16)`).
const GCM_ICV_LENGTHS: std::ops::RangeInclusive<usize> = 12..=16;

/// The tag length Rite writes.
///
/// The longest the profile allows, and the one OpenSSL itself writes, so a
/// blob of ours and a blob of theirs differ in no field.
pub const GCM_ICV_LEN: usize = 16;

/// The one recipient an [`Envelope`] is addressed to, in the `RecipientInfo`
/// form its key takes, with the protected content-encryption key that form
/// carries.
///
/// Each form carries its own fields, so a reader can determine how to open it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecipientInfo {
    /// A `KEKRecipientInfo` under `id-aes256-wrap`, for a symmetric key both
    /// sides hold. Rite names the key by its [`KeyCheckValue`].
    Kek {
        /// `kekid.keyIdentifier`.
        key_identifier: RecipientIdentifier,
        /// The CEK under RFC 3394 AES Key Wrap.
        wrapped_key: Vec<u8>,
    },
    /// A version 2 `KeyTransRecipientInfo` under RSAES-OAEP over SHA-256, for
    /// an RSA public key. Rite names the key by its [`KeyFingerprint`].
    KeyTransport {
        /// The `subjectKeyIdentifier` rid.
        key_identifier: RecipientIdentifier,
        /// The CEK under RSAES-OAEP.
        encrypted_key: Vec<u8>,
    },
    /// A `KeyAgreeRecipientInfo` under one-pass ECDH, for an EC public key.
    KeyAgreement(KeyAgreeRecipient),
}

impl RecipientInfo {
    /// What names the recipient key.
    #[must_use]
    pub fn key_identifier(&self) -> &RecipientIdentifier {
        match self {
            Self::Kek { key_identifier, .. } | Self::KeyTransport { key_identifier, .. } => {
                key_identifier
            }
            Self::KeyAgreement(agreed) => &agreed.key_identifier,
        }
    }

    /// The `RecipientInfo` CHOICE this is.
    #[must_use]
    pub fn kind(&self) -> RecipientInfoKind {
        match self {
            Self::Kek { .. } => RecipientInfoKind::Kekri,
            Self::KeyTransport { .. } => RecipientInfoKind::Ktri,
            Self::KeyAgreement(_) => RecipientInfoKind::Kari,
        }
    }
}

/// A content-encryption key protected with ECDH in a CMS
/// `KeyAgreeRecipientInfo` (RFC 5753).
///
/// The sender creates an ephemeral key pair on the recipient's curve and
/// computes ECDH with the recipient's public key. The X9.63 KDF uses the
/// agreed secret and [`shared_info`](Self::shared_info) to derive a
/// 256-bit key-encryption key. AES Key Wrap protects the content-encryption
/// key with that key.
///
/// To open the container, the recipient computes ECDH with its private key
/// and the ephemeral public key. The ephemeral point is carried in the
/// container; [`ephemeral_key`](Self::ephemeral_key) builds an SPKI for it
/// using the recipient's curve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAgreeRecipient {
    /// The `subjectKeyIdentifier` in the `rKeyId` rid.
    pub key_identifier: RecipientIdentifier,
    /// The ephemeral public key's point, in the SEC 1 encoding the
    /// `originatorKey` carries.
    pub ephemeral_point: Vec<u8>,
    /// The user keying material, when the sender supplied some. Rite writes
    /// none; the agreement is fresh because the ephemeral key is.
    pub ukm: Option<Vec<u8>>,
    /// The KDF the scheme names.
    pub kdf: X963Kdf,
    /// The CEK under AES-256 Key Wrap.
    pub wrapped_key: Vec<u8>,
}

/// The length of the key-encryption key the agreement derives, in bytes:
/// AES-256 key wrap, the one wrap this module writes under it.
pub const AGREED_KEK_LEN: usize = 32;

impl KeyAgreeRecipient {
    /// The `ECC-CMS-SharedInfo` the KDF takes (RFC 5753 §7.2): the wrap
    /// algorithm, the `ukm` when present, and the length of the derived key
    /// in bits.
    ///
    /// Binding the wrap algorithm and length into the derivation means a key
    /// derived for one wrap cannot be reused for another.
    ///
    /// # Errors
    ///
    /// Returns [`CmsReadError`] if this module's wrap identifier fails to
    /// encode, which is unreachable.
    pub fn shared_info(&self) -> Result<Vec<u8>, CmsReadError> {
        let bits = u32::try_from(AGREED_KEK_LEN * 8).unwrap_or(u32::MAX);
        let mut fields = vec![der::sequence(&[encoded_oid(oid::AES_256_WRAP)?])];
        if let Some(ukm) = &self.ukm {
            fields.push(der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &der::octet_string(ukm)));
        }
        fields.push(der::tlv(
            TAG_CONTEXT_2_CONSTRUCTED,
            &der::octet_string(&bits.to_be_bytes()),
        ));
        Ok(der::sequence(&fields))
    }

    /// The ephemeral public key, on the curve of `recipient`, the key it was
    /// agreed with.
    ///
    /// # Errors
    ///
    /// Returns [`CmsReadError`] if `recipient` is not an EC key, or if the
    /// point does not form a public key on its curve.
    pub fn ephemeral_key(&self, recipient: &PublicKeyDer) -> Result<PublicKeyDer, CmsReadError> {
        let algorithm = recipient.algorithm().map_err(|e| err(e.to_string()))?;
        let (curve, _) = agreement_curve(algorithm).ok_or_else(|| {
            err(format!(
                "a key agreement is addressed to a P-256 or P-384 key, and the recipient is \
                 {algorithm}"
            ))
        })?;
        let spki = der::sequence(&[
            der::sequence(&[encoded_oid(oid::ID_EC_PUBLIC_KEY)?, encoded_oid(curve)?]),
            der::tlv(
                TAG_BIT_STRING,
                &[&[0u8][..], &self.ephemeral_point].concat(),
            ),
        ]);
        PublicKeyDer::new(spki).map_err(|e| err(format!("the ephemeral key: {e}")))
    }
}

/// The curve identifier and the KDF of a key agreement with a key of
/// `algorithm`, if it is one this module writes for.
///
/// The one table of agreement curves, matched exhaustively, so a key
/// algorithm added to this crate is placed here or refused here at compile
/// time, for sealing and opening alike.
fn agreement_curve(algorithm: KeyAlgorithm) -> Option<(&'static str, X963Kdf)> {
    match algorithm {
        KeyAlgorithm::EcdsaP256 => Some((oid::SECP256R1, X963Kdf::Sha256)),
        KeyAlgorithm::EcdsaP384 => Some((oid::SECP384R1, X963Kdf::Sha384)),
        KeyAlgorithm::Rsa2048
        | KeyAlgorithm::Rsa4096
        | KeyAlgorithm::Ed25519
        | KeyAlgorithm::MlDsa44
        | KeyAlgorithm::MlDsa65
        | KeyAlgorithm::MlDsa87
        | KeyAlgorithm::MlKem512
        | KeyAlgorithm::MlKem768
        | KeyAlgorithm::MlKem1024
        | KeyAlgorithm::Aes128
        | KeyAlgorithm::Aes256 => None,
    }
}

/// The X9.63 KDF used to derive a key-encryption key for a CMS key agreement.
///
/// RFC 5753 §7.1.4 pairs SHA-256 with P-256 and SHA-384 with P-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum X963Kdf {
    /// `dhSinglePass-stdDH-sha256kdf-scheme`.
    Sha256,
    /// `dhSinglePass-stdDH-sha384kdf-scheme`.
    Sha384,
}

impl X963Kdf {
    /// The KDF RFC 5753 pairs with the curve of `recipient`, if it is an EC
    /// key on a curve this module writes for.
    #[must_use]
    pub fn for_recipient(recipient: KeyAlgorithm) -> Option<Self> {
        agreement_curve(recipient).map(|(_, kdf)| kdf)
    }

    /// The scheme identifier a `keyEncryptionAlgorithm` names for it.
    fn scheme(self) -> &'static str {
        match self {
            Self::Sha256 => oid::DH_SINGLE_PASS_STDDH_SHA256KDF,
            Self::Sha384 => oid::DH_SINGLE_PASS_STDDH_SHA384KDF,
        }
    }
}

impl fmt::Display for X963Kdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("the X9.63 KDF over SHA-256"),
            Self::Sha384 => f.write_str("the X9.63 KDF over SHA-384"),
        }
    }
}

/// The parts of an `AuthEnvelopedData` addressed to one recipient.
///
/// The [`RecipientInfo`] carries the protected content-encryption key in the
/// form its recipient takes. The content is the same whichever it is.
///
/// Carried as a struct rather than assembled in place because the same fields
/// are written on the way out and read on the way back, and a field the two
/// sides disagree about is the defect this shape makes impossible.
///
/// The crypto is the caller's: this module puts bytes in a structure and takes
/// them out again, and never holds a key.
///
/// ```
/// use rite_sdk::KeyCheckValue;
/// use rite_sdk::cms::{self, Envelope, RecipientInfo};
///
/// // Values a backend produces: the KEK's check value, the CEK wrapped under
/// // the KEK, and the content under that CEK.
/// let check_value: KeyCheckValue = "cmac-aes:763cbc".parse()?;
/// let envelope = Envelope {
///     recipient: RecipientInfo::Kek {
///         key_identifier: (&check_value).into(),
///         wrapped_key: vec![0x11; 40],
///     },
///     nonce: vec![0x22; 12],
///     ciphertext: vec![0x33; 64],
///     tag: vec![0x44; cms::GCM_ICV_LEN],
/// };
///
/// let der = cms::write_auth_enveloped(&envelope)?;
/// assert_eq!(cms::read_auth_enveloped(&der)?, envelope);
///
/// // And the same bytes describe the wrap that produced them.
/// let facts = cms::describe(&der)?;
/// assert!(
///     facts
///         .recipient_key_identifier
///         .is_some_and(|named| named.is_check_value(&check_value))
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The recipient and the content-encryption key protected for it. Rite
    /// names a symmetric key by its check value and a public key by its
    /// fingerprint; a container read back carries what its writer put there.
    pub recipient: RecipientInfo,
    /// The 12-byte AES-GCM nonce.
    pub nonce: Vec<u8>,
    /// The content under AES-256-GCM.
    pub ciphertext: Vec<u8>,
    /// The AES-GCM authentication tag. Its length is what
    /// `GCMParameters.aes-ICVlen` names, so the two cannot disagree.
    pub tag: Vec<u8>,
}

/// Write an `AuthEnvelopedData` addressed to one recipient.
///
/// RFC 5083 for the structure, RFC 5652 §6.2 for the recipient, RFC 5084 for
/// the `GCMParameters` the content algorithm carries.
///
/// # Errors
///
/// Returns [`CmsReadError`] if the tag is not a length RFC 5084 admits, if a
/// key agreement carries no ephemeral point, or if one of this module's own
/// object identifiers fails to encode, which is unreachable.
pub fn write_auth_enveloped(envelope: &Envelope) -> Result<Vec<u8>, CmsReadError> {
    if !GCM_ICV_LENGTHS.contains(&envelope.tag.len()) {
        return Err(err(format!(
            "a {}-byte authentication tag is not one RFC 5084 admits",
            envelope.tag.len()
        )));
    }
    assemble_auth_enveloped(envelope, recipient_info(envelope)?)
}

/// The `ContentInfo` around one encoded `RecipientInfo` and the envelope's
/// content.
fn assemble_auth_enveloped(
    envelope: &Envelope,
    recipient: Vec<u8>,
) -> Result<Vec<u8>, CmsReadError> {
    // EncryptedContentInfo. The content is implicit [0], not an OCTET STRING,
    // which is the tag a reader of this structure has to expect.
    let content = der::sequence(&[
        encoded_oid(DATA)?,
        der::sequence(&[
            encoded_oid(oid::AES_256_GCM)?,
            der::sequence(&[
                der::octet_string(&envelope.nonce),
                der::small_integer(u8::try_from(envelope.tag.len()).unwrap_or(0)),
            ]),
        ]),
        der::tlv(TAG_CONTEXT_0_PRIMITIVE, &envelope.ciphertext),
    ]);

    // AuthEnvelopedData: version 0, no originatorInfo, no authAttrs, no
    // unauthAttrs. Version is 0 because nothing here is a structure that
    // RFC 5083 requires a higher one for.
    let auth_enveloped = der::sequence(&[
        der::small_integer(0),
        der::set_of(&[recipient]),
        content,
        der::octet_string(&envelope.tag),
    ]);

    Ok(der::sequence(&[
        encoded_oid(AUTH_ENVELOPED_DATA)?,
        der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &auth_enveloped),
    ]))
}

/// The one `RecipientInfo` an envelope carries.
fn recipient_info(envelope: &Envelope) -> Result<Vec<u8>, CmsReadError> {
    match &envelope.recipient {
        // KEKRecipientInfo, tagged [2] in the RecipientInfo CHOICE. Version is
        // always 4 (RFC 5652 §6.2.3). The algorithm is `id-aes256-wrap`,
        // matching the 256-bit KEK Rite writes.
        RecipientInfo::Kek {
            key_identifier,
            wrapped_key,
        } => Ok(der::tlv(
            TAG_CONTEXT_2_CONSTRUCTED,
            &[
                der::small_integer(4),
                der::sequence(&[der::octet_string(key_identifier.as_bytes())]),
                der::sequence(&[encoded_oid(oid::AES_256_WRAP)?]),
                der::octet_string(wrapped_key),
            ]
            .concat(),
        )),
        // KeyTransRecipientInfo, the untagged SEQUENCE in the CHOICE. Version
        // 2 because the rid is a subjectKeyIdentifier (RFC 5652 §6.2.1), which
        // names the key itself, so no certificate is needed to address it.
        RecipientInfo::KeyTransport {
            key_identifier,
            encrypted_key,
        } => Ok(der::sequence(&[
            der::small_integer(2),
            der::tlv(TAG_CONTEXT_0_PRIMITIVE, key_identifier.as_bytes()),
            rsaes_oaep_sha256()?,
            der::octet_string(encrypted_key),
        ])),
        RecipientInfo::KeyAgreement(agreed) => key_agree_recipient_info(agreed),
    }
}

/// A `KeyAgreeRecipientInfo`, tagged [1] in the `RecipientInfo` CHOICE, as
/// OpenSSL writes one: version 3 (RFC 5652 §6.2.2), the ephemeral key as an
/// `originatorKey` under `id-ecPublicKey` with the parameters absent, and the
/// wrap identifier without parameters. The recipient is named by `rKeyId`,
/// whose subject key identifier names the key itself, as a `ktri`'s does.
fn key_agree_recipient_info(agreed: &KeyAgreeRecipient) -> Result<Vec<u8>, CmsReadError> {
    // The reader refuses a public key with no point, so the writer does too.
    if agreed.ephemeral_point.is_empty() {
        return Err(err("a key agreement needs the ephemeral key's point"));
    }
    let originator_key = der::tlv(
        TAG_CONTEXT_1_CONSTRUCTED,
        &[
            der::sequence(&[encoded_oid(oid::ID_EC_PUBLIC_KEY)?]),
            der::tlv(
                TAG_BIT_STRING,
                &[&[0u8][..], &agreed.ephemeral_point].concat(),
            ),
        ]
        .concat(),
    );
    let mut fields = vec![
        der::small_integer(3),
        der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &originator_key),
    ];
    if let Some(ukm) = &agreed.ukm {
        fields.push(der::tlv(TAG_CONTEXT_1_CONSTRUCTED, &der::octet_string(ukm)));
    }
    fields.push(der::sequence(&[
        encoded_oid(agreed.kdf.scheme())?,
        der::sequence(&[encoded_oid(oid::AES_256_WRAP)?]),
    ]));
    fields.push(der::sequence(&[der::sequence(&[
        der::tlv(
            TAG_CONTEXT_0_CONSTRUCTED,
            &der::octet_string(agreed.key_identifier.as_bytes()),
        ),
        der::octet_string(&agreed.wrapped_key),
    ])]));
    Ok(der::tlv(TAG_CONTEXT_1_CONSTRUCTED, &fields.concat()))
}

/// `id-RSAES-OAEP` with SHA-256 for the digest and for MGF1, and the empty
/// label.
///
/// RFC 4055 §4.1, encoded as OpenSSL writes it: the SHA-256 identifiers carry
/// no parameters, and `pSourceFunc` is omitted because it equals its DEFAULT.
fn rsaes_oaep_sha256() -> Result<Vec<u8>, CmsReadError> {
    let sha256 = der::sequence(&[encoded_oid(oid::SHA_256)?]);
    let mgf1 = der::sequence(&[encoded_oid(oid::MGF1)?, sha256.clone()]);
    Ok(der::sequence(&[
        encoded_oid(oid::RSAES_OAEP)?,
        der::sequence(&[
            der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &sha256),
            der::tlv(TAG_CONTEXT_1_CONSTRUCTED, &mgf1),
        ]),
    ]))
}

/// One of this module's object identifiers, encoded.
fn encoded_oid(dotted: &str) -> Result<Vec<u8>, CmsReadError> {
    der::object_identifier(dotted)
        .ok_or_else(|| err(format!("{dotted} is not an object identifier")))
}

/// Read back what [`write_auth_enveloped`] wrote.
///
/// Accepts an `AuthEnvelopedData` with AES-256-GCM content, no `authAttrs`,
/// and a single recipient, in one of the [`RecipientInfo`] forms, naming its
/// key by subject key identifier. That is what the OpenSSL CLI writes for the
/// same inputs.
///
/// `authAttrs` is refused rather than skipped. RFC 5083 makes it the AEAD's
/// additional authenticated data, so a blob carrying it authenticates bytes
/// this decrypt would not feed to the tag, and opening one by ignoring the
/// field would either fail confusingly or, worse, treat attributes as
/// unauthenticated that the producer meant to bind.
///
/// # Errors
///
/// Returns [`CmsReadError`] if the bytes are not that structure. The
/// algorithms are checked here rather than assumed, because the caller is
/// about to decrypt with whatever this returns.
pub fn read_auth_enveloped(der_bytes: &[u8]) -> Result<Envelope, CmsReadError> {
    let (content_info, rest) = read_tlv(der_bytes)?;
    if !rest.is_empty() {
        return Err(err("trailing bytes after ContentInfo"));
    }
    let body = content_info.expect_tag(TAG_SEQUENCE, "ContentInfo")?;
    let (content_type, after_type) = read_tlv(body)?;
    if oid_of(&content_type, "ContentInfo.contentType")?.as_str() != AUTH_ENVELOPED_DATA {
        return Err(err("not an AuthEnvelopedData"));
    }

    let (explicit, _) = read_tlv(after_type)?;
    let (auth_enveloped, _) =
        read_tlv(explicit.expect_tag(TAG_CONTEXT_0_CONSTRUCTED, "ContentInfo.content")?)?;
    let auth_enveloped = auth_enveloped.expect_tag(TAG_SEQUENCE, "AuthEnvelopedData")?;

    // version, then the optional implicit [0] originatorInfo, which `describe`
    // also steps over. Rite writes none, and a foreign blob carrying one is
    // still one this can open.
    let (_version, after_version) = read_tlv(auth_enveloped)?;
    let (next, after_next) = read_tlv(after_version)?;
    let (recipients, after_recipients) = if next.tag == TAG_CONTEXT_0_CONSTRUCTED {
        read_tlv(after_next)?
    } else {
        (next, after_next)
    };
    let recipients = recipients.expect_tag(TAG_SET, "recipientInfos")?;

    let (recipient, more) = read_tlv(recipients)?;
    if !more.is_empty() {
        // Rite writes one. Several would mean choosing which key to try, and
        // silently taking the first is how a blob opens with the wrong one.
        return Err(err("more than one recipient"));
    }
    let recipient = openable_recipient(&recipient)?;

    let (content_info, after_content) = read_tlv(after_recipients)?;
    let (nonce, icv_len, ciphertext) =
        read_gcm_content(content_info.expect_tag(TAG_SEQUENCE, "authEncryptedContentInfo")?)?;

    let (mac, _) = read_tlv(after_content)?;
    if mac.tag == TAG_CONTEXT_1_CONSTRUCTED {
        // authAttrs. RFC 5083 makes these the AEAD's additional authenticated
        // data, which this decrypt leaves empty, so opening such a blob would
        // compute the tag over different bytes than the producer did. Named
        // here, since `expected mac` would send a reader looking at the wrong
        // field.
        return Err(err(
            "this AuthEnvelopedData carries authAttrs, which are part of what its \
             tag authenticates and which this reader does not cover",
        ));
    }
    let tag = mac.expect_tag(TAG_OCTET_STRING, "mac")?;
    if tag.len() != icv_len {
        // The structure would then describe a tag other than the one it
        // carries, and the decrypt would run against whichever the caller
        // happened to use.
        return Err(err(format!(
            "GCMParameters names a {icv_len}-byte tag and the mac is {} bytes",
            tag.len()
        )));
    }

    Ok(Envelope {
        recipient,
        nonce,
        ciphertext,
        tag: tag.to_vec(),
    })
}

/// A recipient this crate can open, with what names it and its protected CEK.
///
/// The algorithms are checked here rather than in the walkers, because
/// describing a foreign blob should report the algorithm it names, and only
/// opening one has to insist on the algorithm this crate can run. The
/// exception is RSAES-OAEP, whose parameters [`describe`] checks too, since
/// the description has no field for them.
fn openable_recipient(recipient: &Tlv<'_>) -> Result<RecipientInfo, CmsReadError> {
    match recipient.tag {
        TAG_CONTEXT_2_CONSTRUCTED => {
            let kekri = read_kekri(recipient.value)?;
            if kekri.algorithm.as_str() != oid::AES_256_WRAP {
                return Err(err(format!(
                    "key encryption algorithm {} is not id-aes256-wrap",
                    kekri.algorithm
                )));
            }
            Ok(RecipientInfo::Kek {
                key_identifier: RecipientIdentifier(kekri.key_identifier.to_vec()),
                wrapped_key: kekri.encrypted_key.to_vec(),
            })
        }
        TAG_SEQUENCE => {
            let ktri = read_ktri(recipient.value)?;
            require_rsaes_oaep_sha256(&ktri.algorithm)?;
            // A key is matched by an identifier derived from it, and there is
            // no certificate here to match an issuer and serial against.
            let key_identifier = ktri.key_identifier.ok_or_else(|| {
                err(
                    "the recipient is named by issuer and serial number, which identifies a \
                     certificate rather than a key",
                )
            })?;
            Ok(RecipientInfo::KeyTransport {
                key_identifier: RecipientIdentifier(key_identifier.to_vec()),
                encrypted_key: ktri.encrypted_key.to_vec(),
            })
        }
        TAG_CONTEXT_1_CONSTRUCTED => {
            let kari = read_kari_fields(recipient.value)?;
            if kari.more_keys {
                // As for several recipients: choosing which key to try is how
                // a blob opens with the wrong one.
                return Err(err(
                    "this KeyAgreeRecipientInfo addresses more than one key",
                ));
            }
            let kdf = agreement_kdf(&kari.algorithm)?;
            let ephemeral_point = originator_point(&kari.originator)?;
            // As for a key transport recipient: no certificate is here to
            // match an issuer and serial against.
            let key_identifier = kari.key_identifier.ok_or_else(|| {
                err(
                    "the recipient is named by issuer and serial number, which identifies a \
                     certificate rather than a key",
                )
            })?;
            Ok(RecipientInfo::KeyAgreement(KeyAgreeRecipient {
                key_identifier: RecipientIdentifier(key_identifier.to_vec()),
                ephemeral_point: ephemeral_point.to_vec(),
                ukm: kari.ukm.map(<[u8]>::to_vec),
                kdf,
                wrapped_key: kari.encrypted_key.to_vec(),
            }))
        }
        TAG_CONTEXT_4_CONSTRUCTED => Err(err(
            "the recipient is an OtherRecipientInfo, which this reader does not open",
        )),
        other => Err(err(format!(
            "RecipientInfo tag 0x{other:02x} is not a recipient this reader opens"
        ))),
    }
}

/// The nonce, the declared tag length, and the ciphertext out of an AES-GCM
/// `EncryptedContentInfo`.
fn read_gcm_content(body: &[u8]) -> Result<(Vec<u8>, usize, Vec<u8>), CmsReadError> {
    let (_content_type, after_type) = read_tlv(body)?;
    let (algorithm, after_algorithm) = read_tlv(after_type)?;

    let (algorithm_body, parameters) = algorithm_parts(&algorithm, "contentEncryptionAlgorithm")?;
    if algorithm_body.as_str() != oid::AES_256_GCM {
        return Err(err(format!(
            "content encryption algorithm {algorithm_body} is not id-aes256-GCM"
        )));
    }
    let parameters = parameters.ok_or_else(|| err("AES-GCM content carries no GCMParameters"))?;
    let (nonce, after_nonce) = read_tlv(parameters.expect_tag(TAG_SEQUENCE, "GCMParameters")?)?;
    let nonce = nonce.expect_tag(TAG_OCTET_STRING, "GCMParameters.aes-nonce")?;

    // aes-ICVlen carries a DEFAULT of 12, so an absent field means 12 rather
    // than an unspecified length. OpenSSL writes 16 explicitly.
    let icv_len = match read_tlv(after_nonce) {
        Ok((field, _)) => usize::from(
            *field
                .expect_tag(TAG_INTEGER, "GCMParameters.aes-ICVlen")?
                .first()
                .ok_or_else(|| err("GCMParameters.aes-ICVlen is empty"))?,
        ),
        Err(_) => 12,
    };
    if !GCM_ICV_LENGTHS.contains(&icv_len) {
        // A shorter tag is a weaker one, and a decrypt would accept it without
        // noticing, so the profile's floor is enforced here.
        return Err(err(format!(
            "GCMParameters names a {icv_len}-byte tag, which RFC 5084 does not admit"
        )));
    }

    let (content, _) = read_tlv(after_algorithm)?;
    Ok((
        nonce.to_vec(),
        icv_len,
        content
            .expect_tag(TAG_CONTEXT_0_PRIMITIVE, "encryptedContent")?
            .to_vec(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use base64ct::Encoding as _;

    #[test]
    fn reads_a_dotted_oid_from_its_der_encoding() {
        // id-aes256-GCM, 2.16.840.1.101.3.4.1.46: the first byte packs 2.16 as
        // 40*2+16 = 96, and 840 spans two base-128 bytes.
        let der = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e,
        ];
        let (element, rest) = read_tlv(&der).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            oid_of(&element, "test").unwrap().as_str(),
            "2.16.840.1.101.3.4.1.46"
        );
    }

    /// X.690 packs the first two arcs into one subidentifier, and that
    /// subidentifier spans several bytes as soon as it exceeds 127. Reading
    /// only its first byte decodes `2.100.3` as something else entirely.
    #[test]
    fn reads_a_first_arc_that_spans_two_bytes() {
        // 2.100.3: the packed first subidentifier is 40*2 + 100 = 180,
        // encoded as 0x81 0x34.
        let der = [0x06, 0x03, 0x81, 0x34, 0x03];
        let (element, _) = read_tlv(&der).unwrap();
        assert_eq!(oid_of(&element, "test").unwrap().as_str(), "2.100.3");
    }

    #[test]
    fn reads_a_long_form_length() {
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend(std::iter::repeat_n(0xaa, 0x80));
        let (element, rest) = read_tlv(&der).unwrap();
        assert_eq!(element.value.len(), 0x80);
        assert!(rest.is_empty());
    }

    #[test]
    fn refuses_indefinite_length_and_truncation() {
        assert!(read_tlv(&[0x30, 0x80, 0x00, 0x00]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x01]).is_err());
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[]).is_err());
    }

    /// The `EnvelopedData` of RFC 4134 section 5.1, verbatim as section 5.3
    /// carries it in an S/MIME body.
    ///
    /// Line breaks follow the RFC text so the constant can be diffed against
    /// it by eye. Decoded, it is 290 bytes and matches the offsets the RFC
    /// prints beside its own ASN.1 dump.
    const RFC4134_ENVELOPED_DATA: &str = concat!(
        "MIIBHgYJKoZIhvcNAQcDoIIBDzCCAQsCAQAxgcAwgb0CAQAwJjASMRAwDgYDVQQDEwdDYXJ",
        "sUlNBAhBGNGvHgABWvBHTbi7NXXHQMA0GCSqGSIb3DQEBAQUABIGAC3EN5nGIiJi2lsGPcP",
        "2iJ97a4e8kbKQz36zg6Z2i0yx6zYC4mZ7mX7FBs3IWg+f6KgCLx3M1eCbWx8+MDFbbpXadC",
        "DgO8/nUkUNYeNxJtuzubGgzoyEd8Ch4H/dd9gdzTd+taTEgS0ipdSJuNnkVY4/M652jKKHR",
        "LFf02hosdR8wQwYJKoZIhvcNAQcBMBQGCCqGSIb3DQMHBAgtaMXpRwZRNYAgDsiSf8Z9P43",
        "LrY4OxUk660cu1lXeCSFOSOpOJ7FuVyU=",
    );

    fn sample_envelope() -> Envelope {
        Envelope {
            recipient: RecipientInfo::Kek {
                key_identifier: RecipientIdentifier(vec![0x76, 0x3c, 0xbc]),
                wrapped_key: vec![0x11; 40],
            },
            nonce: vec![0x22; 12],
            ciphertext: vec![0x33; 64],
            tag: vec![0x44; 16],
        }
    }

    /// The writer and the reader are one contract, so what goes in comes out.
    #[test]
    fn a_kek_envelope_round_trips() {
        let envelope = sample_envelope();
        let der = write_auth_enveloped(&envelope).unwrap();
        assert_eq!(read_auth_enveloped(&der).unwrap(), envelope);
    }

    /// And `describe` reads the same bytes as a wrap, which is what puts the
    /// algorithms in the transcript and in front of `rite verify`.
    #[test]
    fn a_kek_envelope_describes_itself() {
        let der = write_auth_enveloped(&sample_envelope()).unwrap();
        let facts = describe(&der).unwrap();

        assert_eq!(
            facts.description.recipient_info,
            Some(RecipientInfoKind::Kekri)
        );
        assert_eq!(
            facts.description.key_encryption_oid.as_str(),
            crate::types::oid::AES_256_WRAP
        );
        assert_eq!(
            facts
                .description
                .content_encryption_oid
                .as_ref()
                .map(Oid::as_str),
            Some(crate::types::oid::AES_256_GCM)
        );
        assert_eq!(
            facts.recipient_key_identifier,
            Some(RecipientIdentifier(vec![0x76, 0x3c, 0xbc])),
            "the recipient is named by the key's check value"
        );
    }

    /// The content type is `id-data`, the generic one, so the container is
    /// not key-specific: what it carries is bytes.
    #[test]
    fn a_kek_envelope_carries_bytes_under_the_generic_content_type() {
        let der = write_auth_enveloped(&sample_envelope()).unwrap();
        let data_oid = crate::der::object_identifier(DATA).unwrap();
        assert!(
            der.windows(data_oid.len()).any(|w| w == data_oid),
            "the encrypted content is id-data, not a key-specific type"
        );
    }

    /// A long body crosses the boundary where DER switches to the long-form
    /// length, which is where a hand-written encoder stops agreeing with a
    /// reader.
    #[test]
    fn a_kek_envelope_round_trips_across_the_length_boundary() {
        for size in [0, 1, 127, 128, 129, 255, 256, 1024, 65_536] {
            let envelope = Envelope {
                ciphertext: vec![0x5a; size],
                ..sample_envelope()
            };
            let der = write_auth_enveloped(&envelope).unwrap();
            assert_eq!(
                read_auth_enveloped(&der).unwrap(),
                envelope,
                "a {size}-byte content did not survive the round trip"
            );
        }
    }

    /// The tag length is written from the tag, so the two cannot disagree, and
    /// a length outside the profile is refused rather than written.
    #[test]
    fn a_kek_envelope_carries_the_tag_length_it_declares() {
        for length in [12usize, 13, 14, 15, 16] {
            let envelope = Envelope {
                tag: vec![0x44; length],
                ..sample_envelope()
            };
            let der = write_auth_enveloped(&envelope).unwrap();
            assert_eq!(read_auth_enveloped(&der).unwrap().tag.len(), length);
        }
        for length in [0usize, 8, 11, 17] {
            let envelope = Envelope {
                tag: vec![0x44; length],
                ..sample_envelope()
            };
            assert!(
                write_auth_enveloped(&envelope).is_err(),
                "a {length}-byte tag is not one RFC 5084 admits"
            );
        }
    }

    /// An envelope whose CEK went to an RSA public key, named by the SHA-256
    /// of its SPKI.
    fn key_transport_envelope() -> Envelope {
        Envelope {
            recipient: RecipientInfo::KeyTransport {
                key_identifier: RecipientIdentifier(vec![0x89; 32]),
                encrypted_key: vec![0x11; 256],
            },
            ..sample_envelope()
        }
    }

    /// An envelope whose CEK is wrapped under a key agreed with a P-256 key.
    fn key_agreement_envelope() -> Envelope {
        Envelope {
            recipient: RecipientInfo::KeyAgreement(KeyAgreeRecipient {
                key_identifier: RecipientIdentifier(vec![0x89; 32]),
                ephemeral_point: [&[0x04][..], &[0x5c; 64]].concat(),
                ukm: None,
                kdf: X963Kdf::Sha256,
                wrapped_key: vec![0x11; 40],
            }),
            ..sample_envelope()
        }
    }

    #[test]
    fn a_key_agreement_envelope_round_trips() {
        let envelope = key_agreement_envelope();
        let der = write_auth_enveloped(&envelope).unwrap();
        assert_eq!(read_auth_enveloped(&der).unwrap(), envelope);

        // With user keying material and the other KDF.
        let RecipientInfo::KeyAgreement(agreed) = envelope.recipient else {
            unreachable!()
        };
        let envelope = Envelope {
            recipient: RecipientInfo::KeyAgreement(KeyAgreeRecipient {
                ukm: Some(vec![0x7e; 64]),
                kdf: X963Kdf::Sha384,
                ..agreed.clone()
            }),
            ..sample_envelope()
        };
        let der = write_auth_enveloped(&envelope).unwrap();
        assert_eq!(read_auth_enveloped(&der).unwrap(), envelope);

        // What the reader would refuse, the writer refuses.
        let pointless = Envelope {
            recipient: RecipientInfo::KeyAgreement(KeyAgreeRecipient {
                ephemeral_point: Vec::new(),
                ..agreed
            }),
            ..sample_envelope()
        };
        assert!(write_auth_enveloped(&pointless).is_err());
    }

    #[test]
    fn a_key_agreement_envelope_describes_itself() {
        let der = write_auth_enveloped(&key_agreement_envelope()).unwrap();
        let facts = describe(&der).unwrap();

        assert_eq!(
            facts.description.recipient_info,
            Some(RecipientInfoKind::Kari)
        );
        assert_eq!(
            facts.description.key_encryption_oid.as_str(),
            oid::DH_SINGLE_PASS_STDDH_SHA256KDF
        );
        assert_eq!(
            facts.description.kek_wrap_oid.as_ref().map(Oid::as_str),
            Some(oid::AES_256_WRAP)
        );
        assert_eq!(
            facts.recipient_key_identifier,
            Some(RecipientIdentifier(vec![0x89; 32]))
        );
        assert!(crate::types::WrapScheme::CmsAes256Gcm.permits(&facts.description));
    }

    /// The `ECC-CMS-SharedInfo` OpenSSL feeds its KDF for a 256-bit wrap key
    /// and no ukm: the wrap identifier, then `[2]` holding the length in bits.
    #[test]
    fn the_shared_info_binds_the_wrap_and_its_length() {
        let RecipientInfo::KeyAgreement(agreed) = key_agreement_envelope().recipient else {
            unreachable!()
        };
        assert_eq!(
            agreed.shared_info().unwrap(),
            [
                0x30, 0x15, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01,
                0x2d, 0xa2, 0x06, 0x04, 0x04, 0x00, 0x00, 0x01, 0x00,
            ]
        );

        let with_ukm = KeyAgreeRecipient {
            ukm: Some(vec![0xab, 0xcd]),
            ..agreed
        };
        let encoded = with_ukm.shared_info().unwrap();
        assert_eq!(
            encoded.get(15..21),
            Some(&[0xa0, 0x04, 0x04, 0x02, 0xab, 0xcd][..]),
            "the ukm is entityUInfo, [0], between the wrap and the length"
        );
    }

    #[test]
    fn a_key_transport_envelope_round_trips() {
        let envelope = key_transport_envelope();
        let der = write_auth_enveloped(&envelope).unwrap();
        assert_eq!(read_auth_enveloped(&der).unwrap(), envelope);
    }

    /// `describe` reports the form and names the key the way `rite verify`
    /// matches it, so a ktri is checked on the terms a kekri is.
    #[test]
    fn a_key_transport_envelope_describes_itself() {
        let der = write_auth_enveloped(&key_transport_envelope()).unwrap();
        let facts = describe(&der).unwrap();

        assert_eq!(
            facts.description.recipient_info,
            Some(RecipientInfoKind::Ktri)
        );
        assert_eq!(
            facts.description.key_encryption_oid.as_str(),
            oid::RSAES_OAEP
        );
        assert_eq!(facts.description.kek_wrap_oid, None);
        assert_eq!(
            facts.recipient_key_identifier,
            Some(RecipientIdentifier(vec![0x89; 32]))
        );
        assert!(crate::types::WrapScheme::CmsAes256Gcm.permits(&facts.description));
    }

    /// The `AlgorithmIdentifier` OpenSSL 4.0.3 writes for `openssl cms
    /// -encrypt -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256
    /// -keyopt rsa_mgf1_md:sha256`, recorded from its output.
    ///
    /// The parameters admit more than one encoding, since a SHA-256 identifier
    /// may carry NULL or nothing, and writing the same bytes as the most
    /// widely deployed reader leaves no room for one that is strict about it.
    const OPENSSL_RSAES_OAEP_SHA256: [u8; 58] = [
        // AlgorithmIdentifier { id-RSAES-OAEP, RSAES-OAEP-params {
        0x30, 0x38, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x30, 0x2b,
        // [0] hashFunc { id-sha256 }
        0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        // [1] maskGenFunc { id-mgf1, { id-sha256 } } } }
        0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];

    #[test]
    fn writes_the_oaep_parameters_openssl_writes() {
        assert_eq!(rsaes_oaep_sha256().unwrap(), OPENSSL_RSAES_OAEP_SHA256);
    }

    /// A ktri with `algorithm` in place of the one Rite writes, otherwise
    /// well-formed.
    fn with_key_transport_algorithm(algorithm: Vec<u8>) -> Vec<u8> {
        let envelope = key_transport_envelope();
        let RecipientInfo::KeyTransport {
            key_identifier,
            encrypted_key,
        } = &envelope.recipient
        else {
            unreachable!()
        };
        let ktri = der::sequence(&[
            der::small_integer(2),
            der::tlv(TAG_CONTEXT_0_PRIMITIVE, key_identifier.as_bytes()),
            algorithm,
            der::octet_string(encrypted_key),
        ]);
        assemble_auth_enveloped(&envelope, ktri).unwrap()
    }

    /// Every field of `RSAES-OAEP-params` defaults to SHA-1, so each one is
    /// read for what it says, and only OAEP over SHA-256 throughout opens.
    #[test]
    fn opening_admits_only_oaep_over_sha256() {
        let oid = |dotted: &str| der::object_identifier(dotted).unwrap();
        let sha1 = der::sequence(&[oid("1.3.14.3.2.26")]);
        let sha256 = der::sequence(&[oid(super::oid::SHA_256)]);
        let sha256_null = der::sequence(&[oid(super::oid::SHA_256), vec![TAG_NULL, 0x00]]);
        let mgf1 = |hash: &[u8]| {
            der::tlv(
                TAG_CONTEXT_1_CONSTRUCTED,
                &der::sequence(&[oid(super::oid::MGF1), hash.to_vec()]),
            )
        };
        let oaep = |fields: &[Vec<u8>]| {
            der::sequence(&[oid(super::oid::RSAES_OAEP), der::sequence(fields)])
        };
        let hash = |identifier: &[u8]| der::tlv(TAG_CONTEXT_0_CONSTRUCTED, identifier);

        // A NULL parameter on SHA-256 is the other encoding RFC 4055 admits.
        let accepted = oaep(&[hash(&sha256_null), mgf1(&sha256_null)]);
        assert_eq!(
            read_auth_enveloped(&with_key_transport_algorithm(accepted))
                .unwrap()
                .recipient
                .kind(),
            RecipientInfoKind::Ktri
        );

        let refused = [
            (
                "PKCS#1 v1.5",
                der::sequence(&[oid(super::oid::RSA_ENCRYPTION), vec![TAG_NULL, 0x00]]),
                "PKCS1-v1_5",
            ),
            (
                "OAEP with no parameters",
                der::sequence(&[oid(super::oid::RSAES_OAEP)]),
                "SHA-1",
            ),
            (
                "OAEP over SHA-1",
                oaep(&[hash(&sha1), mgf1(&sha256)]),
                "hashFunc",
            ),
            ("no hashFunc", oaep(&[mgf1(&sha256)]), "hashFunc"),
            (
                "MGF1 over SHA-1",
                oaep(&[hash(&sha256), mgf1(&sha1)]),
                "maskGenFunc",
            ),
            ("no maskGenFunc", oaep(&[hash(&sha256)]), "maskGenFunc"),
            (
                "a label",
                oaep(&[
                    hash(&sha256),
                    mgf1(&sha256),
                    der::tlv(
                        TAG_CONTEXT_2_CONSTRUCTED,
                        &der::sequence(&[oid("1.2.840.113549.1.1.9"), der::octet_string(b"label")]),
                    ),
                ]),
                "pSourceFunc",
            ),
        ];
        for (case, algorithm, named) in refused {
            let der = with_key_transport_algorithm(algorithm);
            let error = read_auth_enveloped(&der).unwrap_err().to_string();
            assert!(error.contains(named), "{case}: {error}");
            // Describing reports the algorithm a foreign blob names, so
            // PKCS#1 v1.5 still describes. OAEP with other parameters does
            // not, because its description would be the same as OAEP over
            // SHA-256 and a verifier comparing the two would pass it.
            let described = describe(&der);
            if case == "PKCS#1 v1.5" {
                assert!(described.is_ok(), "{case}: describe should still read it");
            } else {
                let error = described.err().map(|e| e.to_string()).unwrap_or_default();
                assert!(error.contains(named), "{case}: describe gave {error:?}");
            }
        }
    }

    /// A container's identifier names a key by its fingerprint or its RFC 5280
    /// identifier, and by no other digest of it.
    #[test]
    fn a_recipient_identifier_names_a_key_by_either_of_its_names_only() {
        use sha2::Digest as _;
        use x509_cert::der::Decode as _;

        let key =
            crate::CertificateDer::new(include_bytes!("../tests/vectors/p256.cert.der").to_vec())
                .unwrap()
                .public_key()
                .unwrap();
        let other =
            PublicKeyDer::new(include_bytes!("../tests/vectors/p384.spki.der").to_vec()).unwrap();

        let by_fingerprint = RecipientIdentifier::from(key.fingerprint());
        let by_rfc5280 =
            RecipientIdentifier(key.rfc5280_key_identifier().unwrap().as_bytes().to_vec());
        assert!(by_fingerprint.names_key(&key));
        assert!(by_rfc5280.names_key(&key));
        assert!(!by_fingerprint.names_key(&other));
        assert!(!by_rfc5280.names_key(&other));

        // 32 bytes derived from the key are not its fingerprint unless they
        // are that digest: here the SHA-256 of the key bits alone.
        let bits = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(key.as_bytes())
            .unwrap()
            .subject_public_key
            .raw_bytes()
            .to_vec();
        let lookalike = RecipientIdentifier(sha2::Sha256::digest(&bits).to_vec());
        assert!(!lookalike.names_key(&key));

        // Without the key, only the fingerprint can be compared.
        assert!(by_fingerprint.is_fingerprint(&key.fingerprint()));
        assert!(!by_rfc5280.is_fingerprint(&key.fingerprint()));
    }

    /// A `KEKRecipientInfo` is read as exactly as a `KeyTransRecipientInfo`:
    /// version 4, nothing after `encryptedKey`, and in `kekid` only the two
    /// optional fields RFC 5652 defines.
    #[test]
    fn a_kek_recipient_is_read_exactly() {
        let envelope = sample_envelope();
        let kekri = |version: u8, kekid_extra: &[Vec<u8>], trailing: &[u8]| {
            let mut kekid = vec![der::octet_string(
                envelope.recipient.key_identifier().as_bytes(),
            )];
            kekid.extend_from_slice(kekid_extra);
            let mut body = [
                der::small_integer(version),
                der::sequence(&kekid),
                der::sequence(&[der::object_identifier(super::oid::AES_256_WRAP).unwrap()]),
                der::octet_string(&[0x11; 40]),
            ]
            .concat();
            body.extend_from_slice(trailing);
            assemble_auth_enveloped(&envelope, der::tlv(TAG_CONTEXT_2_CONSTRUCTED, &body)).unwrap()
        };
        let date = der::tlv(TAG_GENERALIZED_TIME, b"20261026120000Z");

        assert!(read_auth_enveloped(&kekri(4, &[], &[])).is_ok());
        // A date in kekid names when the key was made, not which key it is.
        assert!(read_auth_enveloped(&kekri(4, &[date], &[])).is_ok());

        for (der, named) in [
            (kekri(0, &[], &[]), "version 4"),
            (kekri(4, &[], &[0x05, 0x00]), "after encryptedKey"),
            (
                kekri(4, &[vec![0x05, 0x00]], &[]),
                "after its optional fields",
            ),
        ] {
            let error = read_auth_enveloped(&der).unwrap_err().to_string();
            assert!(error.contains(named), "{error}");
            let error = describe(&der)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(error.contains(named), "describe gave {error:?}");
        }
    }

    /// Opening reads the structure exactly: two encodings that differ only in
    /// a field DER fixes are not both admitted as the same container.
    #[test]
    fn opening_refuses_a_key_transport_recipient_that_is_not_der() {
        let envelope = key_transport_envelope();
        let ktri = |version: u8, algorithm: Vec<u8>, trailing: &[u8]| {
            let mut body = [
                der::small_integer(version),
                der::tlv(
                    TAG_CONTEXT_0_PRIMITIVE,
                    envelope.recipient.key_identifier().as_bytes(),
                ),
                algorithm,
                der::octet_string(&[0x11; 256]),
            ]
            .concat();
            body.extend_from_slice(trailing);
            assemble_auth_enveloped(&envelope, der::tlv(TAG_SEQUENCE, &body)).unwrap()
        };
        let oaep = rsaes_oaep_sha256().unwrap();

        assert!(read_auth_enveloped(&ktri(2, oaep.clone(), &[])).is_ok());

        // The structure is checked by the walker both readers share, so
        // describing refuses what opening refuses.
        for (der, named) in [
            (ktri(0, oaep.clone(), &[]), "version 2"),
            (ktri(2, oaep.clone(), &[0x05, 0x00]), "after encryptedKey"),
        ] {
            let error = read_auth_enveloped(&der).unwrap_err().to_string();
            assert!(error.contains(named), "{error}");
            let error = describe(&der)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(error.contains(named), "describe gave {error:?}");
        }

        // A NULL slipped in after the SHA-256 identifier inside hashFunc.
        let oid = |dotted: &str| der::object_identifier(dotted).unwrap();
        let sha256 = der::sequence(&[oid(super::oid::SHA_256)]);
        let padded_hash = der::tlv(
            TAG_CONTEXT_0_CONSTRUCTED,
            &[sha256.clone(), vec![TAG_NULL, 0x00]].concat(),
        );
        let mgf1 = der::tlv(
            TAG_CONTEXT_1_CONSTRUCTED,
            &der::sequence(&[oid(super::oid::MGF1), sha256]),
        );
        let algorithm = der::sequence(&[
            oid(super::oid::RSAES_OAEP),
            der::sequence(&[padded_hash, mgf1]),
        ]);
        let error = read_auth_enveloped(&ktri(2, algorithm, &[]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("hashFunc"), "{error}");
    }

    /// The fields of a `KeyAgreeRecipientInfo`, each encoded, to build one
    /// that differs from what the writer produces in one field.
    struct KariFields {
        version: u8,
        originator: Vec<u8>,
        algorithm: Vec<u8>,
        keys: Vec<u8>,
    }

    fn oid(dotted: &str) -> Vec<u8> {
        der::object_identifier(dotted).unwrap()
    }

    /// An `originatorKey` under `id-ecPublicKey` with `parameters`.
    fn originator_key(parameters: &[Vec<u8>]) -> Vec<u8> {
        let mut algorithm = vec![oid(super::oid::ID_EC_PUBLIC_KEY)];
        algorithm.extend_from_slice(parameters);
        let point = der::tlv(TAG_BIT_STRING, &[&[0u8, 0x04][..], &[0x5c; 64]].concat());
        der::tlv(
            TAG_CONTEXT_1_CONSTRUCTED,
            &[der::sequence(&algorithm), point].concat(),
        )
    }

    fn agreement_scheme(kdf: &str, wrap: &str) -> Vec<u8> {
        der::sequence(&[oid(kdf), der::sequence(&[oid(wrap)])])
    }

    fn recipient_keys(rids: &[Vec<u8>]) -> Vec<u8> {
        let keys: Vec<_> = rids
            .iter()
            .map(|rid| der::sequence(&[rid.clone(), der::octet_string(&[0x11; 40])]))
            .collect();
        der::sequence(&keys)
    }

    fn rkeyid() -> Vec<u8> {
        der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &der::octet_string(&[0x89; 32]))
    }

    impl KariFields {
        /// What the writer produces for [`key_agreement_envelope`].
        fn written() -> Self {
            Self {
                version: 3,
                originator: originator_key(&[]),
                algorithm: agreement_scheme(
                    super::oid::DH_SINGLE_PASS_STDDH_SHA256KDF,
                    super::oid::AES_256_WRAP,
                ),
                keys: recipient_keys(&[rkeyid()]),
            }
        }

        fn container(self) -> Vec<u8> {
            let body = [
                der::small_integer(self.version),
                der::tlv(TAG_CONTEXT_0_CONSTRUCTED, &self.originator),
                self.algorithm,
                self.keys,
            ]
            .concat();
            assemble_auth_enveloped(
                &key_agreement_envelope(),
                der::tlv(TAG_CONTEXT_1_CONSTRUCTED, &body),
            )
            .unwrap()
        }
    }

    /// The key agreement recipient is read as exactly as the others, by the
    /// walker describing and opening share.
    #[test]
    fn a_key_agreement_recipient_is_read_exactly() {
        assert_eq!(
            read_auth_enveloped(&KariFields::written().container()).unwrap(),
            key_agreement_envelope()
        );
        // RFC 5753 admits a NULL for the originator key's parameters too.
        let with_null = KariFields {
            originator: originator_key(&[vec![TAG_NULL, 0x00]]),
            ..KariFields::written()
        };
        assert!(read_auth_enveloped(&with_null.container()).is_ok());

        let trailing_rkeyid = der::tlv(
            TAG_CONTEXT_0_CONSTRUCTED,
            &[der::octet_string(&[0x89; 32]), vec![TAG_NULL, 0x00]].concat(),
        );
        for (fields, named) in [
            (
                KariFields {
                    version: 2,
                    ..KariFields::written()
                },
                "version 3",
            ),
            (
                KariFields {
                    keys: recipient_keys(&[trailing_rkeyid]),
                    ..KariFields::written()
                },
                "rKeyId carries bytes",
            ),
            (
                KariFields {
                    keys: der::sequence(&[
                        der::sequence(&[rkeyid(), der::octet_string(&[0x11; 40])]),
                        vec![TAG_NULL, 0x00],
                    ]),
                    ..KariFields::written()
                },
                "RecipientEncryptedKey",
            ),
        ] {
            let der = fields.container();
            let error = read_auth_enveloped(&der).unwrap_err().to_string();
            assert!(error.contains(named), "{error}");
            let error = describe(&der)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default();
            assert!(error.contains(named), "describe gave {error:?}");
        }
    }

    /// Only the scheme this crate runs opens: ECDH with the X9.63 KDF over
    /// SHA-256 or SHA-384, under AES-256 key wrap, from an ephemeral key whose
    /// curve is the recipient's, to a key named by its identifier. A foreign
    /// container naming anything else is still described.
    #[test]
    fn opening_admits_only_the_agreement_this_crate_runs() {
        let issuer_and_serial = der::sequence(&[der::sequence(&[]), der::small_integer(1)]);
        for (fields, named) in [
            (
                KariFields {
                    algorithm: agreement_scheme(
                        super::oid::DH_SINGLE_PASS_STDDH_SHA1KDF,
                        super::oid::AES_256_WRAP,
                    ),
                    ..KariFields::written()
                },
                "SHA-1",
            ),
            (
                KariFields {
                    algorithm: agreement_scheme(
                        super::oid::DH_SINGLE_PASS_STDDH_SHA256KDF,
                        super::oid::AES_128_WRAP,
                    ),
                    ..KariFields::written()
                },
                "id-aes256-wrap",
            ),
            (
                KariFields {
                    originator: originator_key(&[oid(super::oid::SECP256R1)]),
                    ..KariFields::written()
                },
                "names its curve",
            ),
            (
                KariFields {
                    originator: der::tlv(
                        TAG_CONTEXT_1_CONSTRUCTED,
                        &[
                            der::sequence(&[oid(super::oid::ID_EC_PUBLIC_KEY)]),
                            der::tlv(TAG_BIT_STRING, &[&[0u8, 0x02][..], &[0x5c; 32]].concat()),
                        ]
                        .concat(),
                    ),
                    ..KariFields::written()
                },
                "point is compressed",
            ),
            (
                KariFields {
                    originator: der::tlv(TAG_CONTEXT_0_PRIMITIVE, &[0x89; 20]),
                    ..KariFields::written()
                },
                "named rather than given",
            ),
            (
                KariFields {
                    keys: recipient_keys(&[issuer_and_serial]),
                    ..KariFields::written()
                },
                "issuer and serial",
            ),
            (
                KariFields {
                    keys: recipient_keys(&[rkeyid(), rkeyid()]),
                    ..KariFields::written()
                },
                "more than one key",
            ),
        ] {
            let der = fields.container();
            assert!(describe(&der).is_ok());
            let error = read_auth_enveloped(&der).unwrap_err().to_string();
            assert!(error.contains(named), "{error}");
        }
    }

    /// The ephemeral key takes the recipient's curve, and only an EC recipient
    /// has one.
    #[test]
    fn the_ephemeral_key_is_on_the_recipients_curve() {
        // A P-256 public key: the generator point, which is on the curve.
        let generator = [
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let agreed = KeyAgreeRecipient {
            ephemeral_point: generator.to_vec(),
            ..match key_agreement_envelope().recipient {
                RecipientInfo::KeyAgreement(agreed) => agreed,
                RecipientInfo::Kek { .. } | RecipientInfo::KeyTransport { .. } => unreachable!(),
            }
        };
        let recipient = agreed.ephemeral_key(&p256_public_key(&generator)).unwrap();
        assert_eq!(recipient.algorithm().unwrap(), KeyAlgorithm::EcdsaP256);
        assert_eq!(recipient, p256_public_key(&generator));

        let ed25519 = PublicKeyDer::new(der::sequence(&[
            der::sequence(&[der::object_identifier("1.3.101.112").unwrap()]),
            der::tlv(TAG_BIT_STRING, &[0u8; 33]),
        ]))
        .unwrap();
        let error = agreed.ephemeral_key(&ed25519).unwrap_err().to_string();
        assert!(
            error.contains("addressed to a P-256 or P-384 key"),
            "{error}"
        );
    }

    fn p256_public_key(point: &[u8]) -> PublicKeyDer {
        PublicKeyDer::new(der::sequence(&[
            der::sequence(&[
                der::object_identifier(super::oid::ID_EC_PUBLIC_KEY).unwrap(),
                der::object_identifier(super::oid::SECP256R1).unwrap(),
            ]),
            der::tlv(TAG_BIT_STRING, &[&[0u8][..], point].concat()),
        ]))
        .unwrap()
    }

    /// Reading is the half that takes untrusted bytes, so it refuses what it
    /// cannot vouch for rather than guessing.
    #[test]
    fn reading_refuses_what_is_not_this_structure() {
        let der = write_auth_enveloped(&sample_envelope()).unwrap();

        assert!(read_auth_enveloped(&[]).is_err(), "empty input");
        assert!(
            read_auth_enveloped(&der[..der.len() - 1]).is_err(),
            "truncated input"
        );
        let mut trailing = der.clone();
        trailing.push(0x00);
        assert!(read_auth_enveloped(&trailing).is_err(), "trailing bytes");

        // The RFC 4134 example is a real CMS artifact of a different shape.
        let other = base64ct::Base64::decode_vec(RFC4134_ENVELOPED_DATA).unwrap();
        assert!(
            read_auth_enveloped(&other).is_err(),
            "an EnvelopedData under CBC with a PKCS#1 v1.5 recipient is not this"
        );
    }

    /// Read a published CMS artifact this codebase had no hand in producing.
    ///
    /// The round-trip tests in `rite-openssl` only prove the reader agrees
    /// with the encoder sitting next to it. This one is a third party's bytes,
    /// checked by two independent implementors before the RFC shipped, and it
    /// exercises the branch OpenSSL never takes for Rite: a recipient named by
    /// issuer and serial number rather than by key identifier.
    #[test]
    fn reads_the_rfc_4134_enveloped_data_example() {
        let der = base64ct::Base64::decode_vec(RFC4134_ENVELOPED_DATA).unwrap();
        assert_eq!(der.len(), 290, "RFC 4134 section 5.1 is 290 bytes");

        let facts = describe(&der).unwrap();
        assert_eq!(
            facts.description.recipient_info,
            Some(RecipientInfoKind::Ktri)
        );
        assert_eq!(
            facts.description.key_encryption_oid.as_str(),
            crate::types::oid::RSA_ENCRYPTION
        );
        assert_eq!(
            facts
                .description
                .content_encryption_oid
                .as_ref()
                .map(Oid::as_str),
            Some("1.2.840.113549.3.7"),
            "des-EDE3-CBC, as the RFC's dump names it"
        );
        assert_eq!(
            facts.description.kek_wrap_oid, None,
            "no KEK in key transport"
        );
        assert_eq!(
            facts.recipient_key_identifier, None,
            "this recipient is named by issuer and serial, which identifies a \
             certificate rather than a key"
        );

        // The reader describes what it found without vouching for it. This
        // artifact predates authenticated encryption, and the scheme Rite
        // produces refuses to label it.
        assert!(!facts.description.content_is_authenticated());
        assert!(!crate::types::WrapScheme::CmsAes256Gcm.permits(&facts.description));
    }

    /// A CMS wrap to an ML-KEM recipient, recorded rather than generated.
    ///
    /// Produced by the OpenSSL 3.6.3 command line on 2026-09-06, outside this
    /// codebase:
    ///
    /// ```text
    /// openssl genpkey -algorithm ML-KEM-768 -out kem.pem
    /// openssl pkey -in kem.pem -pubout -out kem_pub.pem
    /// openssl x509 -new -force_pubkey kem_pub.pem -key ca.pem \
    ///     -subj "/CN=rite-keywrap" -days 1 -out kem.crt
    /// openssl cms -encrypt -keyid -aes-256-gcm -binary -outform DER \
    ///     -in secret -out ml_kem_768_authenveloped.der kem.crt
    /// ```
    ///
    /// RFC 9629 ships no test vectors, so this is the closest thing available:
    /// a third party's bytes at a known version. It also keeps the KEM branch
    /// covered on a build with no ML-KEM provider, where the round-trip test in
    /// `rite-openssl` is compiled out entirely.
    #[test]
    fn reads_a_recorded_ml_kem_recipient() {
        let der = include_bytes!("../tests/fixtures/ml_kem_768_authenveloped.der");
        let facts = describe(der).unwrap();
        let description = &facts.description;

        assert_eq!(description.recipient_info, Some(RecipientInfoKind::Kemri));
        // id-alg-ml-kem-768, NIST CSOR.
        assert_eq!(
            description.key_encryption_oid.as_str(),
            "2.16.840.1.101.3.4.4.2"
        );
        // id-alg-hkdf-with-sha256, RFC 8619. A KEM names its KDF separately,
        // which is what that field on a description exists for.
        assert_eq!(
            description.kdf_oid.as_ref().map(Oid::as_str),
            Some("1.2.840.113549.1.9.16.3.28")
        );
        assert_eq!(
            description.kek_wrap_oid.as_ref().map(Oid::as_str),
            Some(crate::types::oid::AES_256_WRAP)
        );
        assert!(description.content_is_authenticated());
        assert!(
            facts.recipient_key_identifier.is_some(),
            "the blob names its recipient by key id"
        );
    }

    /// A blob carrying `authAttrs` is refused, by name.
    ///
    /// RFC 5083 makes those attributes the AEAD's additional authenticated
    /// data, which this reader leaves empty, so opening one would compute the
    /// tag over different bytes than its producer did. The fixture is a
    /// conforming structure: `openssl cms -decrypt -secretkey` returns its
    /// payload, and flipping one byte inside the attribute makes OpenSSL refuse
    /// it, so the field really is covered by the tag.
    #[test]
    fn refuses_an_auth_enveloped_data_carrying_auth_attrs() {
        let der = base64ct::Base64::decode_vec(concat!(
            "MIHGBgsqhkiG9w0BCRABF6CBtjCBswIBADFEokICAQQwBgQEAQIDBDALBglg",
            "hkgBZQMEAS0EKHQahB32AHvkD3mve3AQWdpTNQ/d825fM9NJOwFCxtF9DZJ4",
            "PXsjRgcwOgYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwDAwMDAwMDAwMD",
            "AwMCARCADbWcgkV4nh1cv9wwVfGhGjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN",
            "AQcBBBCiz7sY6w+LFX3mIoJbWngX",
        ))
        .unwrap();

        let error = read_auth_enveloped(&der).unwrap_err();
        assert!(
            error.to_string().contains("authAttrs"),
            "the refusal should name the field: {error}"
        );

        // `describe` reads only the recipient, which this structure has, so it
        // still reports the wrap rather than refusing it.
        let facts = describe(&der).expect("the recipient is readable either way");
        assert_eq!(
            facts.description.recipient_info,
            Some(RecipientInfoKind::Kekri)
        );
    }

    #[test]
    fn refuses_bytes_that_are_not_an_enveloped_structure() {
        // A SEQUENCE holding the signedData OID rather than an enveloped one.
        let der = [
            0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
        ];
        let error = describe(&der).unwrap_err();
        assert!(
            error.to_string().contains("1.2.840.113549.1.7.2"),
            "the error should name what was found: {error}"
        );
    }
}
