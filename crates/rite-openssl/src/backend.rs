//! OpenSSL backend implementation.
//!
//! Uses the `openssl` crate for all cryptographic operations. Keys are stored
//! as OpenSSL `PKey<Private>` objects — OpenSSL manages key memory and frees
//! it on drop (no `secrecy` crate needed).

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::cms::CmsContentInfo;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::symm::Cipher;
use openssl::x509::{X509Builder, X509NameBuilder};
use rite_sdk::{
    Backend, BackendError, KeyAlgorithm, KeyId, KeyMetadata, KeySpec, KeyStoreBackend,
    KeyTransportBackend, RandomBackend, SignAlgorithm, SignBackend, WrapAlgorithm, WrappedKey,
};
use std::collections::HashMap;

/// OpenSSL-based cryptographic backend.
///
/// Stores keys in memory as OpenSSL `PKey<Private>` objects. The private key
/// material is managed by OpenSSL and freed on drop — no explicit zeroization
/// is needed since OpenSSL handles this internally.
pub struct OpenSslBackend {
    name: String,
    keys: HashMap<KeyId, StoredKey>,
}

/// A key stored in the OpenSSL backend.
struct StoredKey {
    algorithm: KeyAlgorithm,
    label: String,
    /// OpenSSL private key (manages its own memory).
    pkey: PKey<Private>,
    /// Cached `SubjectPublicKeyInfo` DER for export.
    public_der: Vec<u8>,
}

impl OpenSslBackend {
    /// Create a new OpenSSL backend.
    ///
    /// Returns `Ok` always — no hardware initialization is needed.
    pub fn try_new(name: &str) -> Result<Self, BackendError> {
        Ok(Self {
            name: name.to_string(),
            keys: HashMap::new(),
        })
    }

    /// Find a stored key by ID.
    fn get_key(&self, key_id: &KeyId) -> Result<&StoredKey, BackendError> {
        self.keys
            .get(key_id)
            .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
    }

    /// Store a private key and return its metadata.
    ///
    /// Encodes the public key to DER, assigns a UUID key ID, inserts the key, and returns
    /// the `KeyMetadata` — the common closing sequence of generate, import, and unwrap.
    fn store_key(
        &mut self,
        algorithm: KeyAlgorithm,
        label: String,
        pkey: PKey<Private>,
    ) -> Result<KeyMetadata, BackendError> {
        let public_der = pkey
            .public_key_to_der()
            .map_err(|e| ossl_err("Public key DER encoding", &e))?;
        let mut id_bytes = [0u8; 16];
        openssl::rand::rand_bytes(&mut id_bytes).map_err(|e| ossl_err("Generate key ID", &e))?;
        let key_id = KeyId::new(base16ct::lower::encode_string(&id_bytes));
        let public_key = public_der.clone();
        self.keys.insert(
            key_id.clone(),
            StoredKey {
                algorithm,
                label: label.clone(),
                pkey,
                public_der,
            },
        );
        Ok(KeyMetadata {
            key_id,
            algorithm,
            label,
            public_key: Some(public_key),
            attestation: None,
        })
    }
}

impl Backend for OpenSslBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn provider(&self) -> &'static str {
        "openssl"
    }

    fn fingerprint(&self) -> String {
        format!("openssl-backend={}", self.name)
    }

    rite_sdk::backend_capabilities!(
        as_keystore_mut: KeyStoreBackend,
        as_sign_mut: SignBackend,
        as_transport_mut: KeyTransportBackend,
        as_random_mut: RandomBackend,
    );
}

/// Map an OpenSSL error to a `BackendError`.
fn ossl_err(context: &str, e: &openssl::error::ErrorStack) -> BackendError {
    BackendError::Other(format!("{context}: {e}"))
}

/// Detect the key algorithm from an OpenSSL private key by inspecting the RSA modulus size.
///
/// `Rsa::size()` returns the modulus size in bytes (256 for RSA-2048, 512 for RSA-4096).
fn detect_key_algorithm(pkey: &PKey<Private>) -> Result<KeyAlgorithm, BackendError> {
    let rsa = pkey
        .rsa()
        .map_err(|_| BackendError::Other("Unwrapped key is not RSA".to_string()))?;
    match rsa.size() {
        256 => Ok(KeyAlgorithm::Rsa2048),
        512 => Ok(KeyAlgorithm::Rsa4096),
        n => Err(BackendError::UnsupportedAlgorithm(format!(
            "RSA modulus size {n} bytes ({} bits) not supported (expected 2048 or 4096 bits)",
            n.saturating_mul(8)
        ))),
    }
}

impl KeyStoreBackend for OpenSslBackend {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let pkey = match spec.algorithm {
            KeyAlgorithm::Rsa2048 => {
                let rsa = Rsa::generate(2048).map_err(|e| ossl_err("RSA-2048 keygen", &e))?;
                PKey::from_rsa(rsa).map_err(|e| ossl_err("PKey from RSA-2048", &e))?
            }
            KeyAlgorithm::Rsa4096 => {
                let rsa = Rsa::generate(4096).map_err(|e| ossl_err("RSA-4096 keygen", &e))?;
                PKey::from_rsa(rsa).map_err(|e| ossl_err("PKey from RSA-4096", &e))?
            }
            other => {
                return Err(BackendError::UnsupportedAlgorithm(format!(
                    "Algorithm {other:?} not yet implemented for OpenSslBackend"
                )));
            }
        };
        self.store_key(spec.algorithm, spec.label, pkey)
    }

    fn import_private_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError> {
        // Try PKCS#8 DER first (standard format), then fall back to traditional RSA DER.
        // OpenSSL's private_key_to_der() outputs traditional format, but external callers
        // may provide PKCS#8.
        let pkey = PKey::private_key_from_der(key_bytes).or_else(|_| {
            Rsa::private_key_from_der(key_bytes)
                .and_then(PKey::from_rsa)
                .map_err(|e| {
                    BackendError::InvalidKeyFormat(format!(
                        "Invalid private key (tried PKCS#8 and traditional RSA DER): {e}"
                    ))
                })
        })?;
        self.store_key(spec.algorithm, spec.label, pkey)
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, BackendError> {
        let key = self.get_key(key_id)?;
        Ok(key.public_der.clone())
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        Ok(self
            .keys
            .iter()
            .map(|(key_id, stored_key)| KeyMetadata {
                key_id: key_id.clone(),
                algorithm: stored_key.algorithm,
                label: stored_key.label.clone(),
                public_key: Some(stored_key.public_der.clone()),
                attestation: None,
            })
            .collect())
    }

    fn delete_key(&mut self, key_id: &KeyId) -> Result<(), BackendError> {
        self.keys
            .remove(key_id)
            .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))?;
        Ok(())
    }
}

impl SignBackend for OpenSslBackend {
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        let key = self.get_key(key_id)?;

        match key.algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
                let mut signer = Signer::new(MessageDigest::sha256(), &key.pkey)
                    .map_err(|e| ossl_err("Create signer", &e))?;

                match algorithm {
                    SignAlgorithm::RsaPkcs1Sha256 => {
                        signer
                            .set_rsa_padding(Padding::PKCS1)
                            .map_err(|e| ossl_err("Set PKCS1 padding", &e))?;
                    }
                    SignAlgorithm::RsaPssSha256 => {
                        signer
                            .set_rsa_padding(Padding::PKCS1_PSS)
                            .map_err(|e| ossl_err("Set PSS padding", &e))?;
                        signer
                            .set_rsa_mgf1_md(MessageDigest::sha256())
                            .map_err(|e| ossl_err("Set MGF1 MD", &e))?;
                    }
                    other => {
                        return Err(BackendError::UnsupportedAlgorithm(format!(
                            "Sign algorithm {other:?} not supported for RSA keys"
                        )));
                    }
                }

                signer
                    .sign_oneshot_to_vec(message)
                    .map_err(|e| ossl_err("Sign operation", &e))
            }
            other => Err(BackendError::UnsupportedAlgorithm(format!(
                "Signing not yet implemented for algorithm {other:?}"
            ))),
        }
    }

    fn verify(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        let key = self.get_key(key_id)?;

        match key.algorithm {
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
                let pub_pkey = PKey::public_key_from_der(&key.public_der)
                    .map_err(|e| ossl_err("Decode public key", &e))?;

                let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_pkey)
                    .map_err(|e| ossl_err("Create verifier", &e))?;

                match algorithm {
                    SignAlgorithm::RsaPkcs1Sha256 => {
                        verifier
                            .set_rsa_padding(Padding::PKCS1)
                            .map_err(|e| ossl_err("Set PKCS1 padding", &e))?;
                    }
                    SignAlgorithm::RsaPssSha256 => {
                        verifier
                            .set_rsa_padding(Padding::PKCS1_PSS)
                            .map_err(|e| ossl_err("Set PSS padding", &e))?;
                        verifier
                            .set_rsa_mgf1_md(MessageDigest::sha256())
                            .map_err(|e| ossl_err("Set MGF1 MD", &e))?;
                    }
                    other => {
                        return Err(BackendError::UnsupportedAlgorithm(format!(
                            "Verify algorithm {other:?} not supported for RSA keys"
                        )));
                    }
                }

                Ok(verifier
                    .verify_oneshot(signature, message)
                    .map_err(|e| ossl_err("Verify operation", &e))?)
            }
            other => Err(BackendError::UnsupportedAlgorithm(format!(
                "Verification not yet implemented for algorithm {other:?}"
            ))),
        }
    }
}

impl RandomBackend for OpenSslBackend {
    fn generate_random(&mut self, len: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; len];
        openssl::rand::rand_bytes(&mut buf).map_err(|e| ossl_err("Generate random bytes", &e))?;
        Ok(buf)
    }
}

/// Create an ephemeral self-signed X.509 certificate from a private key.
///
/// OpenSSL's CMS encrypt API requires an X.509 certificate (not a bare public key).
/// This cert is only used to satisfy the CMS API — it's never stored or validated.
fn self_signed_cert(pkey: &PKeyRef<Private>) -> Result<openssl::x509::X509, BackendError> {
    build_cert(pkey, pkey)
}

/// Create a CMS recipient certificate carrying an external public key.
///
/// OpenSSL's CMS encrypt only reads the subject public key from the cert — it never
/// validates the cert signature. We sign with a throwaway key so we can embed any
/// public key as the subject without needing the matching private key.
fn cert_for_public_key(recipient_public_key: &[u8]) -> Result<openssl::x509::X509, BackendError> {
    let recipient_pub = PKey::public_key_from_der(recipient_public_key)
        .or_else(|_| PKey::public_key_from_pem(recipient_public_key))
        .map_err(|e| ossl_err("Parse recipient public key (DER or PEM)", &e))?;

    // Generate a throwaway key just for signing the cert.
    // CMS encrypt does NOT verify the cert signature — it only reads the public key.
    let signing_rsa =
        Rsa::generate(2048).map_err(|e| ossl_err("Generate throwaway signing key", &e))?;
    let signing_key =
        PKey::from_rsa(signing_rsa).map_err(|e| ossl_err("Wrap throwaway signing key", &e))?;

    build_cert(&signing_key, &recipient_pub)
}

/// Build an X.509 cert with the given subject public key, signed by the given signing key.
fn build_cert(
    signing_key: &PKeyRef<Private>,
    subject_pub: &PKeyRef<impl openssl::pkey::HasPublic>,
) -> Result<openssl::x509::X509, BackendError> {
    let mut builder = X509Builder::new().map_err(|e| ossl_err("X509 builder", &e))?;
    builder
        .set_version(2)
        .map_err(|e| ossl_err("X509 set version", &e))?;
    builder
        .set_pubkey(subject_pub)
        .map_err(|e| ossl_err("X509 set pubkey", &e))?;

    let mut name_builder = X509NameBuilder::new().map_err(|e| ossl_err("X509 name builder", &e))?;
    name_builder
        .append_entry_by_text("CN", "rite-keywrap")
        .map_err(|e| ossl_err("X509 set CN", &e))?;
    let name = name_builder.build();

    builder
        .set_issuer_name(&name)
        .map_err(|e| ossl_err("X509 set issuer", &e))?;
    builder
        .set_subject_name(&name)
        .map_err(|e| ossl_err("X509 set subject", &e))?;

    let serial = BigNum::from_u32(1)
        .and_then(|bn| bn.to_asn1_integer())
        .map_err(|e| ossl_err("X509 serial number", &e))?;
    builder
        .set_serial_number(&serial)
        .map_err(|e| ossl_err("X509 set serial", &e))?;

    let not_before =
        Asn1Time::days_from_now(0).map_err(|e| ossl_err("X509 not_before time", &e))?;
    let not_after =
        Asn1Time::days_from_now(365).map_err(|e| ossl_err("X509 not_after time", &e))?;
    builder
        .set_not_before(&not_before)
        .map_err(|e| ossl_err("X509 set not_before", &e))?;
    builder
        .set_not_after(&not_after)
        .map_err(|e| ossl_err("X509 set not_after", &e))?;

    builder
        .sign(signing_key, MessageDigest::sha256())
        .map_err(|e| ossl_err("X509 sign", &e))?;

    Ok(builder.build())
}

/// CMS-encrypt key material to a recipient certificate.
///
/// Shared by `wrap` (self-signed cert from KEK) and `wrap_to_public` (cert from external
/// public key). OpenSSL CMS requires an X.509 certificate, not a bare public key.
fn cms_encrypt(
    cert: openssl::x509::X509,
    key_material: &[u8],
    algorithm: WrapAlgorithm,
) -> Result<Vec<u8>, BackendError> {
    let cipher = match algorithm {
        WrapAlgorithm::CmsRsaGcm => Cipher::aes_256_gcm(),
        WrapAlgorithm::CmsRsaCbc => Cipher::aes_256_cbc(),
        _ => {
            return Err(BackendError::UnsupportedAlgorithm(format!(
                "OpenSSL backend only supports CMS wrapping algorithms, got {algorithm:?}"
            )));
        }
    };

    let mut certs = openssl::stack::Stack::new().map_err(|e| ossl_err("Create cert stack", &e))?;
    certs
        .push(cert)
        .map_err(|e| ossl_err("Push cert to stack", &e))?;

    let cms = CmsContentInfo::encrypt(
        &certs,
        key_material,
        cipher,
        openssl::cms::CMSOptions::BINARY,
    )
    .map_err(|e| ossl_err("CMS encrypt", &e))?;

    cms.to_der().map_err(|e| ossl_err("CMS to DER", &e))
}

impl KeyTransportBackend for OpenSslBackend {
    fn wrap(
        &mut self,
        key_id: &KeyId,
        wrapping_key_id: &KeyId,
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        let kek = self.get_key(wrapping_key_id)?;
        let target = self.get_key(key_id)?;

        let cert = self_signed_cert(&kek.pkey)?;
        let key_material = target
            .pkey
            .private_key_to_der()
            .map_err(|e| ossl_err("Export key material for wrapping", &e))?;

        let data = cms_encrypt(cert, &key_material, algorithm)?;
        Ok(WrappedKey {
            algorithm,
            data,
            recipient_hint: Some(wrapping_key_id.to_string()),
        })
    }

    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
    ) -> Result<KeyMetadata, BackendError> {
        // Scope the immutable borrow of `kek` so it ends before `store_key` needs `&mut self`.
        let key_material = {
            let kek = self.get_key(unwrapping_key_id)?;
            // Re-create the ephemeral cert from the same key — CMS decrypt needs it
            // to find the matching recipient.
            let cert = self_signed_cert(&kek.pkey)?;
            let cms = CmsContentInfo::from_der(&wrapped.data)
                .map_err(|e| ossl_err("Parse CMS DER", &e))?;
            cms.decrypt(&kek.pkey, &cert)
                .map_err(|e| ossl_err("CMS decrypt", &e))?
        };

        // The decrypted key material comes from private_key_to_der() which produces
        // the traditional/type-specific format (not PKCS#8). Try both formats.
        let pkey = PKey::private_key_from_der(&key_material)
            .or_else(|_| Rsa::private_key_from_der(&key_material).and_then(PKey::from_rsa))
            .map_err(|e| ossl_err("Parse unwrapped key material", &e))?;

        let key_algorithm = detect_key_algorithm(&pkey)?;
        self.store_key(key_algorithm, label.to_string(), pkey)
    }

    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient_pub_key: &[u8],
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        let target = self.get_key(key_id)?;

        let cert = cert_for_public_key(recipient_pub_key)?;
        let key_material = target
            .pkey
            .private_key_to_der()
            .map_err(|e| ossl_err("Export key material for wrapping", &e))?;

        let data = cms_encrypt(cert, &key_material, algorithm)?;
        Ok(WrappedKey {
            algorithm,
            data,
            recipient_hint: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rite_sdk::{KeyPolicy, KeySpec};

    fn spec(algorithm: KeyAlgorithm, label: &str) -> KeySpec {
        KeySpec {
            algorithm,
            label: label.to_string(),
            policy: KeyPolicy::default(),
            location_hint: None,
        }
    }

    #[test]
    fn test_generate_rsa2048() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "test-key-2048"))
            .unwrap();
        assert_eq!(metadata.algorithm, KeyAlgorithm::Rsa2048);
        assert_eq!(metadata.label, "test-key-2048");
        assert!(metadata.public_key.is_some());
        assert!(metadata.attestation.is_none());
    }

    #[test]
    fn test_generate_rsa4096() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "test-key-4096"))
            .unwrap();
        assert_eq!(metadata.algorithm, KeyAlgorithm::Rsa4096);
        assert_eq!(metadata.label, "test-key-4096");
        assert!(metadata.public_key.is_some());
        assert!(metadata.attestation.is_none());
    }

    #[test]
    fn test_list_keys() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        assert_eq!(backend.list_keys().unwrap().len(), 0);
        backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "key1"))
            .unwrap();
        let keys = backend.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].label, "key1");
    }

    #[test]
    fn test_delete_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "key1"))
            .unwrap();
        backend.delete_key(&metadata.key_id).unwrap();
        assert_eq!(backend.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn test_sign_and_verify_pkcs1() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "signing-key"))
            .unwrap();

        let message = b"Hello, world!";
        let signature = backend
            .sign(&metadata.key_id, message, SignAlgorithm::RsaPkcs1Sha256)
            .unwrap();

        let valid = backend
            .verify(
                &metadata.key_id,
                message,
                &signature,
                SignAlgorithm::RsaPkcs1Sha256,
            )
            .unwrap();
        assert!(valid);

        // Wrong message should fail.
        let invalid = backend
            .verify(
                &metadata.key_id,
                b"Different message",
                &signature,
                SignAlgorithm::RsaPkcs1Sha256,
            )
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_sign_and_verify_pss() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "signing-key"))
            .unwrap();

        let message = b"Hello, world!";
        let signature = backend
            .sign(&metadata.key_id, message, SignAlgorithm::RsaPssSha256)
            .unwrap();

        let valid = backend
            .verify(
                &metadata.key_id,
                message,
                &signature,
                SignAlgorithm::RsaPssSha256,
            )
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_backend_fingerprint() {
        let backend = OpenSslBackend::try_new("my-backend").unwrap();
        assert_eq!(backend.name(), "my-backend");
        assert_eq!(backend.provider(), "openssl");
        assert_eq!(backend.fingerprint(), "openssl-backend=my-backend");
    }

    #[test]
    fn test_wrap_unwrap_rsa_cbc() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend.unwrap(&wrapped, &kek.key_id, "unwrapped").unwrap();

        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_unwrap_rsa_gcm() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaGcm)
            .unwrap();
        let unwrapped = backend.unwrap(&wrapped, &kek.key_id, "unwrapped").unwrap();

        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_unwrap_detects_rsa2048() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target-2048"))
            .unwrap();
        assert_eq!(target.algorithm, KeyAlgorithm::Rsa2048);

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaGcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped-2048")
            .unwrap();

        assert_eq!(
            unwrapped.algorithm,
            KeyAlgorithm::Rsa2048,
            "Unwrapped key should be detected as RSA-2048"
        );
    }

    #[test]
    fn test_wrap_key_to_public_der() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();

        let recipient = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "recipient"))
            .unwrap();
        let recipient_pub_der = backend.export_public_key(&recipient.key_id).unwrap();

        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap_to_public(&target.key_id, &recipient_pub_der, WrapAlgorithm::CmsRsaGcm)
            .unwrap();
        assert!(!wrapped.data.is_empty());

        let unwrapped = backend
            .unwrap(&wrapped, &recipient.key_id, "unwrapped")
            .unwrap();
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_wrong_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let key_a = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "key-a"))
            .unwrap();
        let key_b = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "key-b"))
            .unwrap();
        let plaintext_key = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "plaintext"))
            .unwrap();

        let wrapped = backend
            .wrap(
                &plaintext_key.key_id,
                &key_a.key_id,
                WrapAlgorithm::CmsRsaCbc,
            )
            .unwrap();

        // Attempt to unwrap with key_b (wrong key) — must fail.
        let result = backend.unwrap(&wrapped, &key_b.key_id, "unwrapped");
        assert!(
            result.is_err(),
            "Expected error when unwrapping with wrong key"
        );
    }

    #[test]
    fn test_unwrap_corrupted_cms() {
        // GCM provides AEAD: any modification to the ciphertext or its tag causes
        // decryption to fail, making it the right algorithm for this test.
        // CBC has no authentication, so bit-flips in the encrypted-content region
        // produce garbled output without triggering an error.
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let mut wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaGcm)
            .unwrap();

        // Flip a byte in the middle of the CMS blob.
        let mid = wrapped.data.len() / 2;
        wrapped.data[mid] ^= 0xff;

        let result = backend.unwrap(&wrapped, &kek.key_id, "unwrapped");
        assert!(
            result.is_err(),
            "Expected error when unwrapping corrupted CMS"
        );
    }

    #[test]
    fn test_import_and_sign() {
        let rsa = Rsa::generate(2048).unwrap();
        let original_pkey = PKey::from_rsa(rsa).unwrap();
        let pkcs8_der = original_pkey.private_key_to_pkcs8().unwrap();
        let pub_der = original_pkey.public_key_to_der().unwrap();
        let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();

        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let meta = backend
            .import_private_key(spec(KeyAlgorithm::Rsa2048, "imported"), &pkcs8_der)
            .unwrap();

        let message = b"import round-trip verification message";
        let signature = backend
            .sign(&meta.key_id, message, SignAlgorithm::RsaPkcs1Sha256)
            .unwrap();

        // Verify using the original public key (not retrieved from backend).
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_pkey).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        let valid = verifier.verify_oneshot(&signature, message).unwrap();
        assert!(
            valid,
            "Signature produced by imported key must verify against original public key"
        );
    }

    #[test]
    fn test_wrap_key_to_public_pem() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();

        let recipient = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "recipient"))
            .unwrap();
        let recipient_pub_der = backend.export_public_key(&recipient.key_id).unwrap();
        let recipient_pkey = openssl::pkey::PKey::public_key_from_der(&recipient_pub_der).unwrap();
        let recipient_pub_pem = recipient_pkey.public_key_to_pem().unwrap();

        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap_to_public(&target.key_id, &recipient_pub_pem, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &recipient.key_id, "unwrapped")
            .unwrap();

        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_generate_random() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();

        let bytes = backend.generate_random(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // Two calls should produce different results (with overwhelming probability)
        let bytes2 = backend.generate_random(32).unwrap();
        assert_ne!(bytes, bytes2);
    }
}
