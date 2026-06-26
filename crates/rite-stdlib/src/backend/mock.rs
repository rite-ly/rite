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
    KeyMetadata, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, RandomBackend,
    SignAlgorithm, SignBackend, WrapAlgorithm, WrappedKey,
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
    /// Synthetic stand-in keys, keyed by the reference a ceremony signs with.
    ///
    /// A real card has keys provisioned before the ceremony (slot `9c`, say).
    /// A rehearsal never generated them, so the first signature against an
    /// unknown reference lazily mints a stand-in key of the matching algorithm
    /// here, letting the whole ceremony be walked without hardware.
    #[cfg(feature = "openssl")]
    stand_in_keys: std::collections::BTreeMap<String, KeyId>,
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
            #[cfg(feature = "openssl")]
            stand_in_keys: std::collections::BTreeMap::new(),
            name,
            seed,
        }
    }

    /// Return the backing key for `key_id`, minting a synthetic stand-in of the
    /// algorithm implied by `algorithm` the first time it is seen.
    ///
    /// Used by [`SignBackend::sign`] so a rehearsal can sign with a reference
    /// (a PIV slot, say) whose key was provisioned outside the ceremony.
    #[cfg(feature = "openssl")]
    fn stand_in_key(
        &mut self,
        key_id: &KeyId,
        algorithm: SignAlgorithm,
    ) -> Result<KeyId, BackendError> {
        if let Some(backing) = self.stand_in_keys.get(key_id.as_str()) {
            return Ok(backing.clone());
        }
        // The signature -> key algorithm pairing is owned by the SDK so the
        // stand-in cannot drift from what real backends select.
        let meta = self.crypto.generate_key(KeySpec {
            algorithm: algorithm.key_algorithm(),
            label: format!("mock-stand-in:{key_id}"),
            policy: KeyPolicy::default(),
            location_hint: None,
        })?;
        self.stand_in_keys
            .insert(key_id.as_str().to_string(), meta.key_id.clone());
        Ok(meta.key_id)
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
        match self.crypto.sign(key_id, message, algorithm) {
            // The reference points at a key the rehearsal never generated, such
            // as a pre-provisioned hardware slot. Stand in a synthetic key so
            // the signing step can still be walked end to end.
            Err(BackendError::KeyNotFound(_)) => {
                let backing = self.stand_in_key(key_id, algorithm)?;
                self.crypto.sign(&backing, message, algorithm)
            }
            result => result,
        }
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
        fn sign_lazily_provisions_a_stand_in_for_unknown_references() {
            // A slot-addressed reference (piv:9c) was never generated in the
            // rehearsal; signing must still succeed via a synthetic stand-in.
            let mut backend = MockBackend::new("token".to_string(), "seed".to_string());
            let slot = KeyId::new("piv:9c");

            let sig = backend
                .sign(&slot, b"release manifest", SignAlgorithm::EcdsaSha256)
                .expect("stand-in signing succeeds");
            assert!(!sig.is_empty());

            // A second signature reuses the same stand-in key.
            let again = backend
                .sign(&slot, b"another payload", SignAlgorithm::EcdsaSha256)
                .expect("stand-in is reused");
            assert!(!again.is_empty());
            assert_eq!(backend.stand_in_keys.len(), 1);
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
