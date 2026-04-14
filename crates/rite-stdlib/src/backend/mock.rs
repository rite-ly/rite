//! Mock backend for testing and dry-run.
//!
//! This backend provides deterministic mock cryptographic operations for
//! testing and dry-run scenarios. All operations are fast and reproducible
//! based on the seed.
//!
//! ## Capabilities
//!
//! - **`KeyStore`**: ✓ (mock generation with deterministic IDs)
//! - **Sign**: ✓ (deterministic mock signatures)
//! - **`KeyTransport`**: ✓ (mock wrapped keys)
//! - **Attest**: ✓ (mock attestation)
//! - **`CertStore`**: ✓ (mock certificate storage)
//! - **Random**: ✓ (deterministic random bytes)
//! - **PIV**: ✓ (mock PIV operations)
//! - **`YubiKey`**: ✓ (mock `YubiKey` extensions)
//!
//! ## Use Cases
//!
//! - CI/CD testing (no real crypto needed)
//! - Dry-run mode (fast ceremony simulation)
//! - Reproducible test fixtures
//! - Development without hardware

use rite_sdk::{
    Attestation, AttestationBackend, AttestationKind, Backend, BackendError, CertRef,
    CertStoreBackend, KeyAlgorithm, KeyId, KeyMetadata, KeySpec, KeyStoreBackend,
    KeyTransportBackend, PivBackend, PivDeviceInfo, PivKeyOrigin, PivPinPolicy, PivSlot,
    PivSlotInfo, PivTouchPolicy, RandomBackend, SignAlgorithm, SignBackend, WrapAlgorithm,
    WrappedKey, YubikeyBackend, YubikeySlotMetadata,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Mock backend for testing and dry-run.
#[derive(Debug)]
pub struct MockBackend {
    name: String,
    seed: String,
    keys: HashMap<KeyId, MockKey>,
    key_counter: u64,
}

/// A mock key stored in the backend.
#[derive(Debug, Clone)]
struct MockKey {
    algorithm: KeyAlgorithm,
    label: String,
    /// Deterministic "public key" derived from seed + label.
    public_key: Vec<u8>,
}

impl MockBackend {
    /// Create a new mock backend with the given name and seed.
    ///
    /// The seed is used to generate deterministic keys and signatures.
    /// Same seed + same operations = same results.
    pub fn new(name: String, seed: String) -> Self {
        Self {
            name,
            seed,
            keys: HashMap::new(),
            key_counter: 0,
        }
    }

    /// Generate a deterministic "key" from seed and label.
    ///
    /// This is not a real cryptographic key, just a deterministic blob
    /// for testing purposes.
    fn deterministic_key_material(&self, algorithm: KeyAlgorithm, label: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.as_bytes());
        hasher.update(label.as_bytes());
        hasher.update(format!("{algorithm:?}").as_bytes());
        hasher.finalize().to_vec()
    }

    /// Generate a deterministic signature.
    fn deterministic_signature(&self, key_id: &KeyId, message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.as_bytes());
        hasher.update(key_id.as_str().as_bytes());
        hasher.update(message);
        hasher.update(b"SIGNATURE");
        hasher.finalize().to_vec()
    }

    /// Store a key and return its new `KeyId`.
    fn store_key(
        &mut self,
        prefix: &str,
        algorithm: KeyAlgorithm,
        label: String,
        public_key: Vec<u8>,
    ) -> KeyId {
        self.key_counter = self.key_counter.saturating_add(1);
        let key_id = KeyId::new(format!("{prefix}-{}", self.key_counter));
        self.keys.insert(
            key_id.clone(),
            MockKey {
                algorithm,
                label,
                public_key,
            },
        );
        key_id
    }

    /// Find a stored key by ID.
    fn get_key(&self, key_id: &KeyId) -> Result<&MockKey, BackendError> {
        self.keys
            .get(key_id)
            .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
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
        as_keystore_mut: KeyStoreBackend,
        as_sign_mut: SignBackend,
        as_transport_mut: KeyTransportBackend,
        as_attest_mut: AttestationBackend,
        as_certstore_mut: CertStoreBackend,
        as_random_mut: RandomBackend,
        as_piv_mut: PivBackend,
        as_yubikey_mut: YubikeyBackend,
    );
}

impl KeyStoreBackend for MockBackend {
    fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let algorithm = spec.algorithm;
        let label = spec.label;

        let public_key = self.deterministic_key_material(algorithm, &label);
        let public_key_copy = public_key.clone();
        let key_id = self.store_key("mock-key", algorithm, label.clone(), public_key);

        Ok(KeyMetadata {
            key_id,
            algorithm,
            label,
            public_key: Some(public_key_copy),
            attestation: Some(Attestation {
                kind: AttestationKind::HardwareCertChain,
                certificates: vec![b"MOCK_ATTESTATION_CERT".to_vec()],
                signature: Some(b"MOCK_ATTESTATION_SIG".to_vec()),
                metadata: serde_json::json!({
                    "mock": true,
                    "backend": "MockBackend",
                    "algorithm": format!("{:?}", algorithm),
                }),
            }),
        })
    }

    fn import_private_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError> {
        let algorithm = spec.algorithm;
        let label = spec.label;
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        let public_key = hasher.finalize().to_vec();
        let public_key_copy = public_key.clone();
        let key_id = self.store_key("mock-imported", algorithm, label.clone(), public_key);

        Ok(KeyMetadata {
            key_id,
            algorithm,
            label,
            public_key: Some(public_key_copy),
            attestation: None,
        })
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, BackendError> {
        let key = self.get_key(key_id)?;
        Ok(key.public_key.clone())
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        Ok(self
            .keys
            .iter()
            .map(|(key_id, mock_key)| KeyMetadata {
                key_id: key_id.clone(),
                algorithm: mock_key.algorithm,
                label: mock_key.label.clone(),
                public_key: Some(mock_key.public_key.clone()),
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

impl SignBackend for MockBackend {
    fn sign(
        &mut self,
        key_id: &KeyId,
        message: &[u8],
        _algorithm: SignAlgorithm,
    ) -> Result<Vec<u8>, BackendError> {
        let _ = self.get_key(key_id)?;
        Ok(self.deterministic_signature(key_id, message))
    }

    fn verify(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signature: &[u8],
        _algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        let _ = self.get_key(key_id)?;
        let expected = self.deterministic_signature(key_id, message);
        Ok(signature == expected.as_slice())
    }
}

impl KeyTransportBackend for MockBackend {
    fn wrap(
        &mut self,
        key_id: &KeyId,
        wrapping_key_id: &KeyId,
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        let _ = self.get_key(wrapping_key_id)?;
        let key = self.get_key(key_id)?;

        let mut hasher = Sha256::new();
        hasher.update(self.seed.as_bytes());
        hasher.update(wrapping_key_id.as_str().as_bytes());
        hasher.update(key_id.as_str().as_bytes());
        hasher.update(&key.public_key);
        hasher.update(b"WRAPPED");

        Ok(WrappedKey {
            algorithm,
            data: hasher.finalize().to_vec(),
            recipient_hint: Some(wrapping_key_id.to_string()),
        })
    }

    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
    ) -> Result<KeyMetadata, BackendError> {
        let _ = self.get_key(unwrapping_key_id)?;

        let mut hasher = Sha256::new();
        hasher.update(&wrapped.data);
        hasher.update(b"UNWRAPPED");
        let public_key = hasher.finalize().to_vec();
        let public_key_copy = public_key.clone();
        let key_algorithm = KeyAlgorithm::Rsa4096;
        let owned_label = label.to_string();
        let key_id = self.store_key(
            "mock-unwrapped",
            key_algorithm,
            owned_label.clone(),
            public_key,
        );

        Ok(KeyMetadata {
            key_id,
            algorithm: key_algorithm,
            label: owned_label,
            public_key: Some(public_key_copy),
            attestation: None,
        })
    }
}

impl RandomBackend for MockBackend {
    fn generate_random(&mut self, len: usize) -> Result<Vec<u8>, BackendError> {
        let mut hasher = Sha256::new();
        hasher.update(self.seed.as_bytes());
        hasher.update(b"RANDOM");
        hasher.update(len.to_le_bytes());
        let hash = hasher.finalize();
        Ok(hash.get(..len.min(32)).unwrap_or_default().to_vec())
    }
}

impl AttestationBackend for MockBackend {
    fn attest_key(&self, key_id: &KeyId) -> Result<Attestation, BackendError> {
        let key = self.get_key(key_id)?;

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
                "algorithm": format!("{:?}", key.algorithm),
                "label": key.label,
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
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
    fn test_deterministic_key_generation() {
        let mut backend1 = MockBackend::new("test".to_string(), "seed123".to_string());
        let mut backend2 = MockBackend::new("test".to_string(), "seed123".to_string());

        let key1 = backend1
            .generate_key(spec(KeyAlgorithm::Rsa4096, "my-key"))
            .unwrap();
        let key2 = backend2
            .generate_key(spec(KeyAlgorithm::Rsa4096, "my-key"))
            .unwrap();

        assert_eq!(key1.public_key, key2.public_key);
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let mut backend1 = MockBackend::new("test".to_string(), "seed1".to_string());
        let mut backend2 = MockBackend::new("test".to_string(), "seed2".to_string());

        let key1 = backend1
            .generate_key(spec(KeyAlgorithm::Rsa4096, "my-key"))
            .unwrap();
        let key2 = backend2
            .generate_key(spec(KeyAlgorithm::Rsa4096, "my-key"))
            .unwrap();

        assert_ne!(key1.public_key, key2.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut backend = MockBackend::new("test".to_string(), "seed".to_string());

        let key = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "signing-key"))
            .unwrap();

        let message = b"Hello, world!";
        let signature = backend
            .sign(&key.key_id, message, SignAlgorithm::RsaPkcs1Sha256)
            .unwrap();

        let valid = backend
            .verify(
                &key.key_id,
                message,
                &signature,
                SignAlgorithm::RsaPkcs1Sha256,
            )
            .unwrap();
        assert!(valid);

        let invalid = backend
            .verify(
                &key.key_id,
                b"Different",
                &signature,
                SignAlgorithm::RsaPkcs1Sha256,
            )
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_wrap_and_unwrap() {
        let mut backend = MockBackend::new("test".to_string(), "seed".to_string());

        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "wrapping-key"))
            .unwrap();
        let key_to_wrap = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "data-key"))
            .unwrap();

        let wrapped = backend
            .wrap(&key_to_wrap.key_id, &kek.key_id, WrapAlgorithm::CmsRsaGcm)
            .unwrap();

        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped-key")
            .unwrap();

        assert_eq!(unwrapped.label, "unwrapped-key");
    }

    #[test]
    fn test_attestation() {
        let mut backend = MockBackend::new("test".to_string(), "seed".to_string());

        let key = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "test-key"))
            .unwrap();

        let attestation = backend.attest_key(&key.key_id).unwrap();

        assert!(!attestation.certificates.is_empty());
        assert!(attestation.signature.is_some());
        assert_eq!(
            attestation.metadata.get("mock"),
            Some(&serde_json::json!(true))
        );
    }

    #[test]
    fn test_fingerprint_includes_seed() {
        let backend = MockBackend::new("my-backend".to_string(), "my-seed".to_string());
        let fingerprint = backend.fingerprint();

        assert!(fingerprint.contains("my-backend"));
        assert!(fingerprint.contains("my-seed"));
    }

    #[test]
    fn test_list_keys() {
        let mut backend = MockBackend::new("test".to_string(), "seed".to_string());

        backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "key1"))
            .unwrap();
        backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "key2"))
            .unwrap();

        let keys = backend.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
    }
}
