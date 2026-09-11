//! Read a CMS artifact back into a description of the wrap that produced it.
//!
//! The wrapping algorithms are not derivable from the wrapping key: the KEK
//! size follows the content cipher, and the ECDH KDF digest is a library
//! default. So the evidence has to come from the DER itself, which is also
//! what an independent verifier has. This module walks that DER far enough to
//! name the algorithm identifiers and the recipient, and no further; it never
//! decrypts and never touches key material.

use crate::types::{Oid, RecipientInfoKind, WrapDescription};

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
    /// The recipient's subject key identifier, when the artifact names the
    /// recipient that way. `None` when the recipient is named by issuer and
    /// serial, which identifies a certificate rather than a key.
    pub recipient_key_identifier: Option<Vec<u8>>,
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
struct Recipient {
    description: WrapDescription,
    key_identifier: Option<Vec<u8>>,
}

fn read_recipient(info: &Tlv<'_>) -> Result<Recipient, CmsReadError> {
    match info.tag {
        TAG_SEQUENCE => read_ktri(info.value),
        TAG_CONTEXT_1_CONSTRUCTED => read_kari(info.value),
        TAG_CONTEXT_2_CONSTRUCTED => Err(err(
            "KEKRecipientInfo: the recipient is a pre-shared symmetric key",
        )),
        TAG_CONTEXT_3_CONSTRUCTED => Err(err("PasswordRecipientInfo is not a key wrap")),
        TAG_CONTEXT_4_CONSTRUCTED => read_ori(info.value),
        other => Err(err(format!("unknown RecipientInfo tag 0x{other:02x}"))),
    }
}

/// `KeyTransRecipientInfo`: version, rid, keyEncryptionAlgorithm, encryptedKey.
fn read_ktri(body: &[u8]) -> Result<Recipient, CmsReadError> {
    let (_version, after_version) = read_tlv(body)?;
    let (rid, after_rid) = read_tlv(after_version)?;
    let (algorithm, _) = read_tlv(after_rid)?;

    // rid is either IssuerAndSerialNumber or the implicit [0] subjectKeyIdentifier.
    let key_identifier = (rid.tag == TAG_CONTEXT_0_PRIMITIVE).then(|| rid.value.to_vec());

    Ok(Recipient {
        description: WrapDescription::new(
            RecipientInfoKind::Ktri,
            algorithm_oid(&algorithm, "keyEncryptionAlgorithm")?,
        ),
        key_identifier,
    })
}

/// `KeyAgreeRecipientInfo`: version, [0] originator, [1] ukm OPTIONAL,
/// keyEncryptionAlgorithm, recipientEncryptedKeys.
///
/// RFC 5753 folds the KDF into the key-encryption OID itself, so the KDF is
/// named there rather than in a field of its own. The algorithm's parameter
/// is the identifier of the wrap applied to the CEK under the derived KEK.
fn read_kari(body: &[u8]) -> Result<Recipient, CmsReadError> {
    let (_version, after_version) = read_tlv(body)?;
    let (originator, after_originator) = read_tlv(after_version)?;
    if originator.tag != TAG_CONTEXT_0_CONSTRUCTED {
        return Err(err("KeyAgreeRecipientInfo without an originator"));
    }
    let (next, after_next) = read_tlv(after_originator)?;
    let (algorithm, after_algorithm) = if next.tag == TAG_CONTEXT_1_CONSTRUCTED {
        read_tlv(after_next)?
    } else {
        (next, after_next)
    };

    let (scheme, parameters) = algorithm_parts(&algorithm, "keyEncryptionAlgorithm")?;
    let mut description = WrapDescription::new(RecipientInfoKind::Kari, scheme);
    if let Some(parameters) = parameters {
        description = description.with_kek_wrap(algorithm_oid(&parameters, "keyWrapAlgorithm")?);
    }

    let (recipient_keys, _) = read_tlv(after_algorithm)?;
    Ok(Recipient {
        description,
        key_identifier: agreed_key_identifier(recipient_keys.value)?,
    })
}

/// `RecipientEncryptedKeys`: a SEQUENCE OF `RecipientEncryptedKey`, whose rid
/// is either an `IssuerAndSerialNumber` or `[0] RecipientKeyIdentifier`.
fn agreed_key_identifier(body: &[u8]) -> Result<Option<Vec<u8>>, CmsReadError> {
    let (first, _) = read_tlv(body)?;
    let (rid, _) = read_tlv(first.expect_tag(TAG_SEQUENCE, "RecipientEncryptedKey")?)?;
    if rid.tag != TAG_CONTEXT_0_CONSTRUCTED {
        return Ok(None);
    }
    let (key_id, _) = read_tlv(rid.value)?;
    Ok(Some(
        key_id
            .expect_tag(TAG_OCTET_STRING, "subjectKeyIdentifier")?
            .to_vec(),
    ))
}

/// `OtherRecipientInfo`: an `oriType` OID and a value read according to it.
fn read_ori(body: &[u8]) -> Result<Recipient, CmsReadError> {
    let (oid, after_oid) = read_tlv(body)?;
    let oid = oid_of(&oid, "OtherRecipientInfo.oriType")?;
    if oid.as_str() != ORI_KEM {
        // A form this build does not know: name it and read no further,
        // rather than guess at a structure whose shape is defined elsewhere.
        return Ok(Recipient {
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
fn read_kemri(body: &[u8]) -> Result<Recipient, CmsReadError> {
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

    Ok(Recipient {
        description,
        key_identifier: (rid.tag == TAG_CONTEXT_0_PRIMITIVE).then(|| rid.value.to_vec()),
    })
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

const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
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
