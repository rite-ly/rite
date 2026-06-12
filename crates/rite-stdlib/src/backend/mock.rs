//! Mock backend for testing and dry-run.
//!
//! The mock presents the full backend capability surface so it can stand in
//! for any provider during a dry-run rehearsal. Cryptographic operations are
//! delegated to an embedded software [`OpenSslBackend`](rite_openssl::OpenSslBackend)
//! so the artifacts it produces (DER public keys, signatures, CSRs, wrapped
//! keys) are structurally valid and parse and verify like the real thing.
//! Device-semantic operations (attestation cert chains, PIV slot metadata,
//! `YubiKey` management) are deterministic stubs: clearly synthetic, since a
//! rehearsal cannot speak to absent hardware.
//!
//! ## Capabilities
//!
//! - Crypto (`KeyStore`, `Sign`, `KeyTransport`, `Random`): delegated to OpenSSL,
//!   available only with the `openssl` feature. Without it the mock exposes no
//!   crypto, so a crypto step fails loudly rather than producing invalid bytes.
//! - Device-semantic (`Attest`, `CertStore`, `PIV`, `YubiKey`): deterministic stubs.
//!
//! ## Use Cases
//!
//! - Dry-run rehearsal: run a ceremony end to end without real hardware.
//! - CI smoke tests and reproducible development without a backend device.

use rite_sdk::{
    Attestation, AttestationBackend, AttestationKind, Backend, BackendError, CertRef,
    CertStoreBackend, KeyAlgorithm, KeyId, PivBackend, PivDeviceInfo, PivKeyOrigin, PivPinPolicy,
    PivSlot, PivSlotInfo, PivTouchPolicy, YubikeyBackend, YubikeySlotMetadata,
};

#[cfg(feature = "openssl")]
use rite_openssl::OpenSslBackend;
#[cfg(feature = "openssl")]
use rite_sdk::{
    KeyMetadata, KeySpec, KeyStoreBackend, KeyTransportBackend, RandomBackend, SignAlgorithm,
    SignBackend, WrapAlgorithm, WrappedKey,
};

/// Mock backend for testing and dry-run.
///
/// Crypto is delegated to an embedded [`OpenSslBackend`](rite_openssl::OpenSslBackend);
/// device-semantic operations are stubbed.
pub struct MockBackend {
    name: String,
    seed: String,
    /// Embedded software backend that performs the real cryptographic work.
    #[cfg(feature = "openssl")]
    crypto: OpenSslBackend,
}

impl std::fmt::Debug for MockBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `OpenSslBackend` is not `Debug` (it holds private key material), so
        // the embedded crypto backend is intentionally omitted.
        f.debug_struct("MockBackend")
            .field("name", &self.name)
            .field("seed", &self.seed)
            .finish_non_exhaustive()
    }
}

impl MockBackend {
    /// Create a new mock backend with the given name and seed.
    ///
    /// The seed is retained for the backend fingerprint. Cryptographic
    /// operations are delegated to an embedded OpenSSL backend (when the
    /// `openssl` feature is enabled) and are therefore not seed-derived.
    // `OpenSslBackend::try_new` is documented infallible (no hardware to open).
    #[allow(clippy::expect_used)]
    pub fn new(name: String, seed: String) -> Self {
        Self {
            #[cfg(feature = "openssl")]
            crypto: OpenSslBackend::try_new(&name).expect("OpenSslBackend::try_new is infallible"),
            name,
            seed,
        }
    }
}

impl Backend for MockBackend {
    fn name(&self) -> &str {
        &self.name
    }

    #[allow(clippy::unnecessary_literal_bound)]
    fn provider(&self) -> &str {
        "mock"
    }

    fn fingerprint(&self) -> String {
        format!("mock-backend={}+seed={}", self.name, self.seed)
    }

    rite_sdk::backend_capabilities!(
        #[cfg(feature = "openssl")]
        as_keystore_mut: KeyStoreBackend,
        #[cfg(feature = "openssl")]
        as_sign_mut: SignBackend,
        #[cfg(feature = "openssl")]
        as_transport_mut: KeyTransportBackend,
        #[cfg(feature = "openssl")]
        as_random_mut: RandomBackend,
        as_attest_mut: AttestationBackend,
        as_certstore_mut: CertStoreBackend,
        as_piv_mut: PivBackend,
        as_yubikey_mut: YubikeyBackend,
    );
}

// ---------------------------------------------------------------------------
// Crypto: delegated to the embedded OpenSSL backend.
// ---------------------------------------------------------------------------

#[cfg(feature = "openssl")]
impl KeyStoreBackend for MockBackend {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        self.crypto.generate_key(spec)
    }

    fn import_private_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError> {
        self.crypto.import_private_key(spec, key_bytes)
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, BackendError> {
        self.crypto.export_public_key(key_id)
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        self.crypto.list_keys()
    }

    fn delete_key(&mut self, key_id: &KeyId) -> Result<(), BackendError> {
        self.crypto.delete_key(key_id)
    }
}

#[cfg(feature = "openssl")]
impl SignBackend for MockBackend {
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        self.crypto.sign(key_id, message, algorithm)
    }

    fn verify(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        self.crypto.verify(key_id, message, signature, algorithm)
    }
}

#[cfg(feature = "openssl")]
impl KeyTransportBackend for MockBackend {
    fn wrap(
        &mut self,
        key_id: &KeyId,
        wrapping_key_id: &KeyId,
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        self.crypto.wrap(key_id, wrapping_key_id, algorithm)
    }

    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
    ) -> Result<KeyMetadata, BackendError> {
        self.crypto.unwrap(wrapped, unwrapping_key_id, label)
    }

    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient_pub_key: &[u8],
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        self.crypto
            .wrap_to_public(key_id, recipient_pub_key, algorithm)
    }
}

#[cfg(feature = "openssl")]
impl RandomBackend for MockBackend {
    fn generate_random(&mut self, len: usize) -> Result<Vec<u8>, BackendError> {
        self.crypto.generate_random(len)
    }
}

// ---------------------------------------------------------------------------
// Device-semantic surface: deterministic, clearly-synthetic stubs.
// ---------------------------------------------------------------------------

impl AttestationBackend for MockBackend {
    fn attest_key(&self, key_id: &KeyId) -> Result<Attestation, BackendError> {
        Ok(Attestation {
            kind: AttestationKind::HardwareCertChain,
            certificates: vec![
                b"MOCK_ATTESTATION_CERT_1".to_vec(),
                b"MOCK_ATTESTATION_CERT_2".to_vec(),
            ],
            signature: Some(b"MOCK_ATTESTATION_SIGNATURE".to_vec()),
            metadata: serde_json::json!({
                "mock": true,
                "backend": self.name,
                "key_id": key_id.as_str(),
            }),
        })
    }
}

impl CertStoreBackend for MockBackend {
    fn store_cert(&mut self, _cert_ref: &CertRef, _cert_der: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn read_cert(&self, _cert_ref: &CertRef) -> Result<Vec<u8>, BackendError> {
        Ok(b"MOCK_CERTIFICATE_DER".to_vec())
    }

    fn delete_cert(&mut self, _cert_ref: &CertRef) -> Result<(), BackendError> {
        Ok(())
    }
}

impl PivBackend for MockBackend {
    fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
        Ok(vec![
            PivSlotInfo {
                slot: PivSlot::Authentication,
                algorithm: Some(KeyAlgorithm::EcdsaP256),
                has_certificate: true,
                origin: PivKeyOrigin::Generated,
            },
            PivSlotInfo {
                slot: PivSlot::Signature,
                algorithm: Some(KeyAlgorithm::Rsa2048),
                has_certificate: true,
                origin: PivKeyOrigin::Generated,
            },
        ])
    }

    fn verify_pin(&mut self, _pin: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn change_pin(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn pin_retries(&mut self) -> Result<u32, BackendError> {
        Ok(3)
    }

    fn unblock_pin(&mut self, _puk: &[u8], _new_pin: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn device_info(&self) -> Result<PivDeviceInfo, BackendError> {
        Ok(PivDeviceInfo {
            serial: Some("MOCK-12345678".to_string()),
            firmware_version: Some("5.7.1".to_string()),
            form_factor: Some("USB-A".to_string()),
        })
    }
}

impl YubikeyBackend for MockBackend {
    fn attest_slot(&self, _slot: PivSlot) -> Result<Vec<u8>, BackendError> {
        Ok(b"MOCK_ATTESTATION_CERT_DER".to_vec())
    }

    fn authenticate_management(&mut self, _mgm_key: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn change_management_key(&mut self, _current: &[u8], _new: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    fn slot_metadata(&self, _slot: PivSlot) -> Result<YubikeySlotMetadata, BackendError> {
        Ok(YubikeySlotMetadata {
            pin_policy: PivPinPolicy::Once,
            touch_policy: PivTouchPolicy::Never,
            origin: PivKeyOrigin::Generated,
            public_key: Some(b"MOCK_PUBLIC_KEY_SPKI".to_vec()),
        })
    }

    fn block_puk(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_includes_name_and_seed() {
        let backend = MockBackend::new("my-backend".to_string(), "my-seed".to_string());
        let fingerprint = backend.fingerprint();
        assert!(fingerprint.contains("my-backend"));
        assert!(fingerprint.contains("my-seed"));
    }

    #[test]
    fn attestation_is_synthetic_but_well_formed() {
        let backend = MockBackend::new("test".to_string(), "seed".to_string());
        let attestation = backend.attest_key(&KeyId::new("k-1")).unwrap();
        assert!(!attestation.certificates.is_empty());
        assert!(attestation.signature.is_some());
        assert_eq!(
            attestation.metadata.get("mock"),
            Some(&serde_json::json!(true))
        );
    }

    #[cfg(feature = "openssl")]
    mod crypto {
        use super::*;
        use rite_sdk::KeyPolicy;

        fn spec(algorithm: KeyAlgorithm, label: &str) -> KeySpec {
            KeySpec {
                algorithm,
                label: label.to_string(),
                policy: KeyPolicy::default(),
                location_hint: None,
            }
        }

        #[test]
        fn generate_key_exports_a_non_empty_public_key() {
            let mut backend = MockBackend::new("test".to_string(), "seed".to_string());
            let key = backend
                .generate_key(spec(KeyAlgorithm::Rsa2048, "k"))
                .unwrap();
            let public = key.public_key.expect("public key present");
            assert!(!public.is_empty());
        }

        #[test]
        fn sign_then_verify_roundtrips() {
            let mut backend = MockBackend::new("test".to_string(), "seed".to_string());
            let key = backend
                .generate_key(spec(KeyAlgorithm::Rsa2048, "signing-key"))
                .unwrap();

            let message = b"Hello, ceremony!";
            let signature = backend
                .sign(&key.key_id, message, SignAlgorithm::RsaPkcs1Sha256)
                .unwrap();

            assert!(
                backend
                    .verify(
                        &key.key_id,
                        message,
                        &signature,
                        SignAlgorithm::RsaPkcs1Sha256
                    )
                    .unwrap()
            );
            assert!(
                !backend
                    .verify(
                        &key.key_id,
                        b"tampered",
                        &signature,
                        SignAlgorithm::RsaPkcs1Sha256
                    )
                    .unwrap()
            );
        }

        #[test]
        fn wrap_then_unwrap_roundtrips() {
            let mut backend = MockBackend::new("test".to_string(), "seed".to_string());
            let kek = backend
                .generate_key(spec(KeyAlgorithm::Rsa4096, "wrapping-key"))
                .unwrap();
            let target = backend
                .generate_key(spec(KeyAlgorithm::Rsa4096, "data-key"))
                .unwrap();

            let wrapped = backend
                .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaGcm)
                .unwrap();
            let unwrapped = backend
                .unwrap(&wrapped, &kek.key_id, "unwrapped-key")
                .unwrap();
            assert_eq!(unwrapped.label, "unwrapped-key");
        }

        #[test]
        fn list_keys_reflects_generated_keys() {
            let mut backend = MockBackend::new("test".to_string(), "seed".to_string());
            backend
                .generate_key(spec(KeyAlgorithm::Rsa2048, "key1"))
                .unwrap();
            backend
                .generate_key(spec(KeyAlgorithm::EcdsaP256, "key2"))
                .unwrap();
            assert_eq!(backend.list_keys().unwrap().len(), 2);
        }
    }
}
