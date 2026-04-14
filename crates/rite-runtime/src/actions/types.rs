//! Core types for action handling.

use base64ct::{Base64, Encoding};
use secrecy::SecretBox;

use rite_sdk::{KeyAlgorithm, KeyId, WrapAlgorithm};

/// Output format for public keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// DER binary format.
    Der,
    /// PEM text format.
    Pem,
}

/// Runtime representation of an artifact.
#[non_exhaustive]
#[derive(Debug)]
pub enum ArtifactValue {
    // ========================================================================
    // Real cryptographic artifacts
    // ========================================================================
    /// Cryptographic key managed by a backend (software, HSM, `YubiKey`).
    /// The private key never leaves the backend - only references are stored.
    BackendKey {
        /// Name of the backend that owns this key (e.g., "software", "yubikey1").
        backend_name: String,
        /// Backend-specific key identifier (opaque, e.g., UUID or "`slot_9c`").
        key_id: KeyId,
        /// Algorithm for type checking and evidence.
        algorithm: KeyAlgorithm,
        /// Public key in SPKI DER format (None for non-exportable HSM keys).
        public_key: Option<Vec<u8>>,
    },
    /// Wrapped key (CMS `EnvelopedData`, AES Key Wrap, or RSA-OAEP).
    WrappedKey {
        /// Wrapped key bytes (format depends on algorithm).
        data: Vec<u8>,
        /// Wrapping algorithm used.
        algorithm: WrapAlgorithm,
    },
    /// Exported public key.
    PublicKey {
        /// Public key bytes (SPKI DER format).
        key_data: Vec<u8>,
        /// Output format.
        format: KeyFormat,
    },
    /// Shamir secret shares.
    ShamirShares {
        /// Individual shares (each is a secret).
        shares: Vec<SecretBox<Vec<u8>>>,
        /// Minimum shares required to reconstruct (threshold).
        threshold: u32,
        /// Total number of shares.
        total: u32,
        /// Share identifiers (hex-encoded x-coordinates).
        share_ids: Vec<String>,
    },

    // ========================================================================
    // Materials (loaded from files or inline)
    // ========================================================================
    /// Binary content from files or inline data (documents, crypto materials).
    /// Used for hashing, cryptographic operations, and verification.
    Bytes(Vec<u8>),

    /// Display text for physical item references (USB drives, tamper bags, etc.).
    /// Used in messages and prompts when referencing physical objects.
    Text(String),

    /// X.509 certificate produced by `issue_certificate` action.
    /// Stored as DER bytes; displayed and serialized as PEM.
    Certificate {
        /// Certificate bytes in DER format.
        der: Vec<u8>,
    },
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
                ..
            } => {
                // Output backend key metadata and public key if available
                if let Some(pub_key) = public_key {
                    write!(
                        f,
                        "BackendKey(backend={backend_name}, key_id={}, algorithm={algorithm:?})\n{}",
                        key_id.as_str(),
                        encode_pem("PUBLIC KEY", pub_key)
                    )
                } else {
                    write!(
                        f,
                        "BackendKey(backend={backend_name}, key_id={}, algorithm={algorithm:?}, public_key=not_exportable)",
                        key_id.as_str()
                    )
                }
            }
            ArtifactValue::WrappedKey { data, algorithm } => {
                let label = match algorithm {
                    WrapAlgorithm::CmsRsaCbc | WrapAlgorithm::CmsRsaGcm => "CMS",
                    _ => "WRAPPED KEY",
                };
                let pem = encode_pem(label, data);
                write!(f, "{pem}")
            }
            ArtifactValue::PublicKey {
                key_data,
                format: KeyFormat::Pem,
            } => {
                let pem = encode_pem("PUBLIC KEY", key_data);
                write!(f, "{pem}")
            }
            ArtifactValue::PublicKey {
                key_data,
                format: KeyFormat::Der,
            } => {
                // DER is binary, output as base64
                let encoded = base64_encode(key_data);
                write!(f, "{encoded}")
            }
            ArtifactValue::ShamirShares {
                threshold,
                total,
                share_ids,
                ..
            } => {
                write!(
                    f,
                    "ShamirShares({threshold}-of-{total}, ids: {share_ids:?})"
                )
            }

            // Materials
            ArtifactValue::Bytes(bytes) => {
                let len = bytes.len();
                write!(f, "Bytes({len} bytes)")
            }
            ArtifactValue::Text(text) => {
                write!(f, "Text({text})")
            }

            ArtifactValue::Certificate { der } => {
                let pem = encode_pem("CERTIFICATE", der);
                write!(f, "{pem}")
            }
        }
    }
}

/// Encode bytes as base64 (standard alphabet with padding).
/// Uses constant-time encoding from `RustCrypto` `base64ct`.
// TODO(rite-stdlib): audit whether stdlib needs this pub
pub(crate) fn base64_encode(data: &[u8]) -> String {
    Base64::encode_string(data)
}

/// Encode DER bytes as PEM with given label.
// TODO(rite-stdlib): audit whether stdlib needs this pub
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
    #[allow(clippy::too_many_lines)]
    pub fn serialize(&self, format: Option<&str>) -> Result<SerializedArtifact, String> {
        match self {
            // ========================================================================
            // WrappedKey: CMS EnvelopedData
            // ========================================================================
            ArtifactValue::WrappedKey { data, algorithm } => {
                let fmt = format.unwrap_or("der");
                let (mime, ext) = match algorithm {
                    WrapAlgorithm::CmsRsaCbc | WrapAlgorithm::CmsRsaGcm => {
                        ("application/pkcs7-mime", "p7c")
                    }
                    _ => ("application/octet-stream", "bin"),
                };
                match fmt {
                    "der" => Ok(SerializedArtifact {
                        bytes: data.clone(),
                        mime_type: Some(mime.to_string()),
                        extension: ext,
                    }),
                    "pem" => {
                        let label = match algorithm {
                            WrapAlgorithm::CmsRsaCbc | WrapAlgorithm::CmsRsaGcm => "CMS",
                            _ => "WRAPPED KEY",
                        };
                        Ok(SerializedArtifact {
                            bytes: encode_pem(label, data).into_bytes(),
                            mime_type: Some("application/x-pem-file".to_string()),
                            extension: "pem",
                        })
                    }
                    _ => Err(format!(
                        "Invalid format '{fmt}' for WrappedKey (valid: der, pem)"
                    )),
                }
            }

            // ========================================================================
            // PublicKey: SPKI format
            // ========================================================================
            ArtifactValue::PublicKey { key_data, .. } => {
                let fmt = format.unwrap_or("pem");
                match fmt {
                    "pem" => Ok(SerializedArtifact {
                        bytes: encode_pem("PUBLIC KEY", key_data).into_bytes(),
                        mime_type: Some("application/x-pem-file".to_string()),
                        extension: "pem",
                    }),
                    "der" => Ok(SerializedArtifact {
                        bytes: key_data.clone(),
                        // Note: Using x509-ca-cert as conventional type for DER public keys
                        // No official MIME type exists for bare SPKI DER
                        mime_type: Some("application/x-x509-ca-cert".to_string()),
                        extension: "der",
                    }),
                    "base64" => Ok(SerializedArtifact {
                        bytes: base64_encode(key_data).into_bytes(),
                        mime_type: Some("text/plain".to_string()),
                        extension: "txt",
                    }),
                    _ => Err(format!(
                        "Invalid format '{fmt}' for PublicKey (valid: pem, der, base64)"
                    )),
                }
            }

            // ========================================================================
            // BackendKey: Only public key is exportable
            // ========================================================================
            ArtifactValue::BackendKey { public_key, .. } => {
                if let Some(pub_key) = public_key {
                    // Public key is available - serialize like PublicKey
                    let fmt = format.unwrap_or("pem");
                    match fmt {
                        "pem" => Ok(SerializedArtifact {
                            bytes: encode_pem("PUBLIC KEY", pub_key).into_bytes(),
                            mime_type: Some("application/x-pem-file".to_string()),
                            extension: "pem",
                        }),
                        "der" => Ok(SerializedArtifact {
                            bytes: pub_key.clone(),
                            mime_type: Some("application/x-x509-ca-cert".to_string()),
                            extension: "der",
                        }),
                        "base64" => Ok(SerializedArtifact {
                            bytes: base64_encode(pub_key).into_bytes(),
                            mime_type: Some("text/plain".to_string()),
                            extension: "txt",
                        }),
                        _ => Err(format!(
                            "Invalid format '{fmt}' for BackendKey (valid: pem, der, base64)"
                        )),
                    }
                } else {
                    Err("Cannot export public key from non-exportable backend key".to_string())
                }
            }

            // ========================================================================
            // Text-based artifacts
            // ========================================================================
            ArtifactValue::ShamirShares { .. } => Ok(SerializedArtifact {
                bytes: self.to_string().into_bytes(),
                mime_type: Some("text/plain".to_string()),
                extension: "txt",
            }),

            // ========================================================================
            // Materials: Binary content and text references
            // ========================================================================
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

            // ========================================================================
            // Certificate: DER or PEM
            // ========================================================================
            ArtifactValue::Certificate { der } => {
                let fmt = format.unwrap_or("pem");
                match fmt {
                    "pem" => Ok(SerializedArtifact {
                        bytes: encode_pem("CERTIFICATE", der).into_bytes(),
                        mime_type: Some("application/x-pem-file".to_string()),
                        extension: "pem",
                    }),
                    "der" => Ok(SerializedArtifact {
                        bytes: der.clone(),
                        mime_type: Some("application/pkix-cert".to_string()),
                        extension: "der",
                    }),
                    _ => Err(format!(
                        "Invalid format '{fmt}' for Certificate (valid: pem, der)"
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_format_validation() {
        let public_der = b"PUBLIC_KEY_DER_DATA".to_vec();
        let public_key = ArtifactValue::PublicKey {
            key_data: public_der.clone(),
            format: KeyFormat::Pem,
        };

        // Test default format (PEM)
        let serialized = public_key.serialize(None).unwrap();
        assert_eq!(serialized.extension, "pem");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-pem-file".to_string())
        );

        // Test explicit PEM format
        let serialized = public_key.serialize(Some("pem")).unwrap();
        assert_eq!(serialized.extension, "pem");
        assert_eq!(
            serialized.mime_type,
            Some("application/x-pem-file".to_string())
        );

        // Test DER format
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

        // Test base64 format
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
    fn test_wrapped_key_format_validation() {
        let cms_data = b"CMS_DATA".to_vec();
        let wrapped = ArtifactValue::WrappedKey {
            data: cms_data.clone(),
            algorithm: WrapAlgorithm::CmsRsaGcm,
        };

        // Test default format (DER)
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

        // Test explicit DER format
        let serialized = wrapped.serialize(Some("der")).unwrap();
        assert_eq!(serialized.bytes, cms_data);
        assert_eq!(serialized.extension, "p7c");
        assert_eq!(
            serialized.mime_type,
            Some("application/pkcs7-mime".to_string())
        );

        // Test PEM format
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
