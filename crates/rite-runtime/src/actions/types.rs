//! Core types for action handling.

use base64ct::{Base64, Encoding};

use rite_sdk::{
    CertificateDer, EncryptedData, KeyAlgorithm, KeyCheckValue, KeyId, PublicKeyDer, WrapScheme,
    WrappedKey,
};

/// Runtime representation of an artifact.
#[derive(Debug)]
pub enum ArtifactValue {
    /// Cryptographic key managed by a backend (software, HSM, `YubiKey`).
    /// The private key never leaves the backend - only references are stored.
    BackendKey {
        /// Name of the backend that owns this key (e.g., "software", "yubikey1").
        backend_name: String,
        /// Backend-specific key identifier (opaque, e.g., UUID or "`slot_9c`").
        key_id: KeyId,
        /// Algorithm for type checking and evidence.
        algorithm: KeyAlgorithm,
        /// Public key (None for non-exportable HSM keys).
        public_key: Option<PublicKeyDer>,
        /// Key check value, for a symmetric key.
        ///
        /// What the key answers to where a keypair is answered for by its
        /// public half. A ceremony reaches it as `${artifact.kek.kcv | hex}`,
        /// which is how a custodian compares it against what the token shows.
        check_value: Option<KeyCheckValue>,
    },
    /// Wrapped key, with the scheme it was wrapped under and the algorithms
    /// the wrap actually used. The container follows the scheme; the OpenSSL
    /// backend produces a CMS `ContentInfo`.
    WrappedKey(WrappedKey),
    /// Content encrypted for a recipient, in the container its scheme names.
    ///
    /// Distinct from [`WrappedKey`](ArtifactValue::WrappedKey) even though the
    /// bytes have the same shape. What differs is the claim: a wrapped key left
    /// a backend under protection, and encrypted content says nothing about
    /// custody. The type is what keeps a document from reaching a step that
    /// installs keys.
    EncryptedData(EncryptedData),
    /// Exported public key.
    PublicKey(PublicKeyDer),
    /// Binary content from files or inline data (documents, crypto materials).
    /// Used for hashing, cryptographic operations, and verification.
    Bytes(Vec<u8>),

    /// Display text for physical item references (USB drives, tamper bags, etc.).
    /// Used in messages and prompts when referencing physical objects.
    Text(String),

    /// X.509 certificate. Stored as DER; displayed and serialized as PEM.
    Certificate(CertificateDer),
}

impl std::fmt::Display for ArtifactValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Real cryptographic artifacts
            ArtifactValue::BackendKey {
                backend_name,
                key_id,
                algorithm,
                public_key,
                check_value,
            } => {
                // Output backend key metadata and public key if available
                if let Some(pub_key) = public_key {
                    write!(
                        f,
                        "BackendKey(backend={backend_name}, key_id={}, algorithm={algorithm:?})\n{}",
                        key_id.as_str(),
                        encode_pem("PUBLIC KEY", pub_key.as_bytes())
                    )
                } else if let Some(check_value) = check_value {
                    // A symmetric key has no public half to be missing, and the
                    // check value is what names it everywhere else. Saying
                    // `not_exportable` here would read as a backend refusing an
                    // export that was never possible.
                    write!(
                        f,
                        "BackendKey(backend={backend_name}, key_id={}, algorithm={algorithm:?}, kcv={check_value})",
                        key_id.as_str()
                    )
                } else {
                    write!(
                        f,
                        "BackendKey(backend={backend_name}, key_id={}, algorithm={algorithm:?}, public_key=not_exportable)",
                        key_id.as_str()
                    )
                }
            }
            ArtifactValue::WrappedKey(wrapped) => match pem_label(wrapped.scheme()) {
                Some(label) => write!(f, "{}", encode_pem(label, wrapped.data())),
                // Raw mechanism output has no PEM form; say what it is and how
                // big rather than printing bytes that look like a document.
                None => write!(
                    f,
                    "WrappedKey({}, {} bytes)",
                    wrapped.scheme(),
                    wrapped.data().len()
                ),
            },
            ArtifactValue::EncryptedData(encrypted) => write!(
                f,
                "EncryptedData({}, {} bytes)",
                encrypted.scheme(),
                encrypted.data().len()
            ),
            ArtifactValue::PublicKey(key) => {
                let pem = encode_pem("PUBLIC KEY", key.as_bytes());
                write!(f, "{pem}")
            }
            // Materials
            ArtifactValue::Bytes(bytes) => {
                let len = bytes.len();
                write!(f, "Bytes({len} bytes)")
            }
            ArtifactValue::Text(text) => {
                write!(f, "Text({text})")
            }

            ArtifactValue::Certificate(certificate) => {
                let pem = encode_pem("CERTIFICATE", certificate.as_bytes());
                write!(f, "{pem}")
            }
        }
    }
}

/// Encode bytes as base64 (standard alphabet with padding).
/// Uses constant-time encoding from `RustCrypto` `base64ct`.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

/// The PEM label for a wrapped key, where the container has one.
///
/// `None` for a raw mechanism: its output is bare ciphertext with no structure
/// and no registered PEM type, and inventing a label would produce a file that
/// looks like something a tool can read and is not.
fn pem_label(scheme: WrapScheme) -> Option<&'static str> {
    match scheme {
        WrapScheme::CmsAes256Gcm => Some("CMS"),
        _ => None,
    }
}

/// Write out a container the way a recipient reads it.
///
/// Shared by a wrapped key and encrypted content, because the scheme decides
/// the encoding and the two carry the same schemes. `kind` names the artifact
/// in the error, so a wrong `format:` says which artifact it was written on.
fn serialize_container(
    scheme: WrapScheme,
    data: &[u8],
    format: Option<&str>,
    kind: &str,
) -> Result<SerializedArtifact, String> {
    let (mime, ext) = match scheme {
        WrapScheme::CmsAes256Gcm => ("application/pkcs7-mime", "p7c"),
        _ => ("application/octet-stream", "bin"),
    };
    match format.unwrap_or("der") {
        "der" => Ok(SerializedArtifact {
            bytes: data.to_vec(),
            mime_type: Some(mime.to_string()),
            extension: ext,
        }),
        "pem" => {
            let label = pem_label(scheme).ok_or_else(|| {
                format!(
                    "{scheme} produces raw bytes, which have no PEM form. Write it as 'der', \
                     which is what a recipient imports."
                )
            })?;
            Ok(SerializedArtifact {
                bytes: encode_pem(label, data).into_bytes(),
                mime_type: Some("application/x-pem-file".to_string()),
                extension: "pem",
            })
        }
        other => Err(format!(
            "Invalid format '{other}' for {kind} (valid: der, pem)"
        )),
    }
}

/// Encode DER bytes as PEM with given label.
pub(crate) fn encode_pem(label: &str, der_bytes: &[u8]) -> String {
    let b64 = base64_encode(der_bytes);
    // Split into 64-character lines (PEM standard)
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();

    let body = lines.join("\n");
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----")
}

/// A serialized artifact ready for output.
///
/// Contains both the serialized bytes and metadata about the content.
/// Produced by calling `artifact.serialize(format)`.
///
/// Metadata includes:
/// - MIME type (see <https://pki-tutorial.readthedocs.io/en/latest/mime.html>)
/// - File extension appropriate for the format
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedArtifact {
    /// Serialized content bytes.
    pub bytes: Vec<u8>,
    /// MIME type for the artifact in the specified format.
    pub mime_type: Option<String>,
    /// File extension appropriate for the format (without leading dot).
    pub extension: &'static str,
}

impl ArtifactValue {
    /// Serialize artifact to bytes with metadata.
    ///
    /// Returns a `SerializedArtifact` containing both the serialized bytes
    /// and metadata (MIME type, file extension) appropriate for the format.
    ///
    /// Applies sensible defaults if format is None, then validates strictly.
    ///
    /// Supported formats by artifact type:
    /// - `WrappedKey`: "der" (default), "pem"
    /// - `PublicKey`: "pem" (default), "der", "base64"
    /// - `RsaKeypair`: "pem" (default), "der" (private key in PKCS#8)
    /// - Other artifacts: text representation (format ignored)
    ///
    /// MIME type references:
    /// - application/pkcs7-mime: CMS/PKCS#7 (RFC 5273)
    /// - application/pkcs8: PKCS#8 private keys (RFC 5958)
    /// - application/x-pem-file: PEM-encoded files
    /// - application/x-x509-ca-cert: X.509 certificates (Netscape)
    /// - text/plain: Text artifacts
    ///
    /// Returns an error if an unsupported format is specified.
    pub fn serialize(&self, format: Option<&str>) -> Result<SerializedArtifact, String> {
        match self {
            ArtifactValue::WrappedKey(wrapped) => {
                serialize_container(wrapped.scheme(), wrapped.data(), format, "WrappedKey")
            }
            ArtifactValue::EncryptedData(encrypted) => serialize_container(
                encrypted.scheme(),
                encrypted.data(),
                format,
                "EncryptedData",
            ),

            ArtifactValue::PublicKey(key) => serialize_der(key.as_bytes(), &PUBLIC_KEY, format),

            ArtifactValue::BackendKey { public_key, .. } => match public_key {
                Some(key) => serialize_der(key.as_bytes(), &PUBLIC_KEY, format),
                None => Err("Cannot export public key from non-exportable backend key".to_string()),
            },

            ArtifactValue::Bytes(bytes) => Ok(SerializedArtifact {
                bytes: bytes.clone(),
                mime_type: Some("application/octet-stream".to_string()),
                extension: "bin",
            }),
            ArtifactValue::Text(text) => Ok(SerializedArtifact {
                bytes: text.as_bytes().to_vec(),
                mime_type: Some("text/plain".to_string()),
                extension: "txt",
            }),

            ArtifactValue::Certificate(certificate) => {
                serialize_der(certificate.as_bytes(), &CERTIFICATE, format)
            }
        }
    }
}

/// How one kind of DER artifact renders.
///
/// Public keys and certificates take the same three formats and differ only in
/// their PEM label, their DER media type, and how they are named when a format
/// is refused, so [`serialize_der`] holds the ladder once.
struct DerArtifact {
    pem_label: &'static str,
    der_mime: &'static str,
    name: &'static str,
}

/// x509-ca-cert by convention: no official media type exists for bare SPKI DER.
const PUBLIC_KEY: DerArtifact = DerArtifact {
    pem_label: "PUBLIC KEY",
    der_mime: "application/x-x509-ca-cert",
    name: "a public key",
};

const CERTIFICATE: DerArtifact = DerArtifact {
    pem_label: "CERTIFICATE",
    der_mime: "application/pkix-cert",
    name: "a certificate",
};

/// Render DER material in the format a ceremony asked for, PEM by default.
fn serialize_der(
    der: &[u8],
    artifact: &DerArtifact,
    format: Option<&str>,
) -> Result<SerializedArtifact, String> {
    let fmt = format.unwrap_or("pem");
    match fmt {
        "pem" => Ok(SerializedArtifact {
            bytes: encode_pem(artifact.pem_label, der).into_bytes(),
            mime_type: Some("application/x-pem-file".to_string()),
            extension: "pem",
        }),
        "der" => Ok(SerializedArtifact {
            bytes: der.to_vec(),
            mime_type: Some(artifact.der_mime.to_string()),
            extension: "der",
        }),
        "base64" => Ok(SerializedArtifact {
            bytes: base64_encode(der).into_bytes(),
            mime_type: Some("text/plain".to_string()),
            extension: "txt",
        }),
        _ => Err(format!(
            "Invalid format '{fmt}' for {} (valid: pem, der, base64)",
            artifact.name
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A P-256 public key in SPKI DER, so the artifact holds a real one.
    ///
    /// Reproduce with:
    /// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 |
    ///  openssl pkey -pubout -outform DER`
    const P256_SPKI: &[u8] = include_bytes!("testdata/p256.spki.der");

    #[test]
    fn a_public_key_serializes_as_pem_by_default_and_der_on_request() {
        let public_der = P256_SPKI.to_vec();
        let public_key =
            ArtifactValue::PublicKey(PublicKeyDer::new(public_der.clone()).expect("valid SPKI"));

        // Default format
        let serialized = public_key.serialize(None).unwrap();
        assert_eq!(serialized.extension, "pem");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-pem-file".to_string())
        );

        // Explicit PEM
        let serialized = public_key.serialize(Some("pem")).unwrap();
        assert_eq!(serialized.extension, "pem");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-pem-file".to_string())
        );

        // DER
        let serialized = public_key.serialize(Some("der")).unwrap();
        assert_eq!(
            serialized.bytes, public_der,
            "DER format should output raw key data"
        );
        assert_eq!(serialized.extension, "der");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-x509-ca-cert".to_string())
        );

        // Base64
        let serialized = public_key.serialize(Some("base64")).unwrap();
        assert_eq!(serialized.extension, "txt");
        assert_eq!(serialized.mime_type, Some("text/plain".to_string()));

        // Invalid format
        let result = public_key.serialize(Some("json"));
        assert!(result.is_err(), "Invalid format should return error");
        assert!(
            result.unwrap_err().contains("Invalid format 'json'"),
            "Error message should mention invalid format"
        );
    }

    #[test]
    fn a_wrapped_key_serializes_as_der_by_default_and_pem_on_request() {
        let cms_data = b"CMS_DATA".to_vec();
        let description = rite_sdk::WrapDescription::new(
            rite_sdk::RecipientInfoKind::Ktri,
            rite_sdk::Oid::new(rite_sdk::oid::RSA_ENCRYPTION).unwrap(),
        )
        .with_content_encryption(rite_sdk::Oid::new(rite_sdk::oid::AES_256_GCM).unwrap());
        let wrapped = ArtifactValue::WrappedKey(
            WrappedKey::new(WrapScheme::CmsAes256Gcm, description, cms_data.clone()).unwrap(),
        );

        // Default format
        let serialized = wrapped.serialize(None).unwrap();
        assert_eq!(
            serialized.bytes, cms_data,
            "Default format should output raw CMS data"
        );
        assert_eq!(serialized.extension, "p7c");
        assert_eq!(
            serialized.mime_type,
            Some("application/pkcs7-mime".to_string())
        );

        // Explicit DER
        let serialized = wrapped.serialize(Some("der")).unwrap();
        assert_eq!(serialized.bytes, cms_data);
        assert_eq!(serialized.extension, "p7c");
        assert_eq!(
            serialized.mime_type,
            Some("application/pkcs7-mime".to_string())
        );

        // PEM
        let serialized = wrapped.serialize(Some("pem")).unwrap();
        let pem_str = String::from_utf8(serialized.bytes).unwrap();
        assert!(
            pem_str.contains("-----BEGIN CMS-----"),
            "PEM should contain CMS header"
        );
        assert_eq!(serialized.extension, "pem");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-pem-file".to_string())
        );

        // Invalid format
        let result = wrapped.serialize(Some("base64"));
        assert!(result.is_err(), "Invalid format should return error");
        assert!(
            result.unwrap_err().contains("Invalid format 'base64'"),
            "Error message should mention invalid format"
        );
    }
}
