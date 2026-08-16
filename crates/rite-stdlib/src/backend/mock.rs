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
    PivSlot, PivSlotInfo, PivTouchPolicy, PublicKeyDer, YubikeyBackend, YubikeySlotMetadata,
};

#[cfg(feature = "openssl")]
use rite_openssl::OpenSslBackend;
#[cfg(feature = "openssl")]
use rite_sdk::{
    KeyMetadata, KeyPolicy, KeySpec, KeyStoreBackend, KeyTransportBackend, RandomBackend,
    SignAlgorithm, SignBackend, VerifyBackend, WrapAlgorithm, WrappedKey,
};

/// The private half of the key a mock PIV slot holds, in PKCS#8 DER.
///
/// A rehearsal models a slot provisioned before the ceremony, so the mock
/// imports this at construction rather than minting something unrelated.
/// Committing the private half is what lets the slot's key, its certificate,
/// and the signatures it produces be one keypair: a rehearsal that signs with
/// the slot and verifies against the slot certificate succeeds, as it would on
/// hardware. A stand-in that merely looked right would fail that check as
/// "signature does not match", which reads like an integrity failure rather
/// than the absent hardware it is.
///
/// Secret only in form. It guards nothing and is committed deliberately.
const MOCK_SLOT_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/mock-slot-key.pkcs8.der");

/// The public half of [`MOCK_SLOT_PRIVATE_KEY`], in SPKI DER.
///
/// Committed separately so a build without the `openssl` feature, which has no
/// crypto backend to import the private half into, can still report slot
/// contents. `the_slot_fixtures_are_one_keypair` holds the two together.
const MOCK_SLOT_PUBLIC_KEY: &[u8] = include_bytes!("fixtures/mock-slot-key.spki.der");

/// The certificate for [`MOCK_SLOT_PUBLIC_KEY`], self-signed and long-dated.
const MOCK_SLOT_CERTIFICATE: &[u8] = include_bytes!("fixtures/mock-slot-cert.der");

/// The certificate `yubikey_attest_slot` reports, standing in for the one a
/// device signs with its Yubico-rooted attestation key.
///
/// A different keypair from the slot's, because an attestation certificate is
/// issued by the device about the slot, not by the slot. Clearly synthetic: a
/// rehearsal cannot produce a chain to the real Yubico root.
const MOCK_ATTESTATION_CERTIFICATE: &[u8] = include_bytes!("fixtures/mock-attestation-cert.der");

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
    /// The imported [`MOCK_SLOT_PRIVATE_KEY`], which backs every P-256
    /// stand-in so signatures match the slot certificate the mock reports.
    #[cfg(feature = "openssl")]
    slot_key: KeyId,
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
    // `OpenSslBackend::try_new` is documented infallible (no hardware to open),
    // and the slot key is a committed fixture that `the_slot_fixtures_are_one_keypair`
    // proves importable.
    #[allow(clippy::expect_used)]
    pub fn new(name: String, seed: String) -> Self {
        #[cfg(feature = "openssl")]
        let mut crypto =
            OpenSslBackend::try_new(&name).expect("OpenSslBackend::try_new is infallible");
        #[cfg(feature = "openssl")]
        let slot_key = crypto
            .import_private_key(
                KeySpec {
                    algorithm: KeyAlgorithm::EcdsaP256,
                    label: "mock-piv-slot".to_string(),
                    policy: KeyPolicy::default(),
                    location_hint: None,
                },
                MOCK_SLOT_PRIVATE_KEY,
            )
            .expect("the committed slot key fixture is a P-256 PKCS#8 key")
            .key_id;

        Self {
            #[cfg(feature = "openssl")]
            crypto,
            #[cfg(feature = "openssl")]
            stand_in_keys: std::collections::BTreeMap::new(),
            #[cfg(feature = "openssl")]
            slot_key,
            name,
            seed,
        }
    }

    /// Return the backing key for `key_id`, minting a synthetic stand-in of the
    /// algorithm implied by `algorithm` the first time it is seen.
    ///
    /// Used by [`SignBackend::sign`] so a rehearsal can sign with a reference
    /// (a PIV slot, say) whose key was provisioned outside the ceremony.
    ///
    /// P-256 references resolve to the slot key, the one the mock also reports
    /// through [`CertStoreBackend::read_cert`] and slot metadata, so a signature
    /// it produces verifies against the certificate a rehearsal just read. Other
    /// algorithms have no committed slot key and get a fresh stand-in.
    #[cfg(feature = "openssl")]
    fn stand_in_key(
        &mut self,
        key_id: &KeyId,
        algorithm: SignAlgorithm,
    ) -> Result<KeyId, BackendError> {
        if algorithm.key_algorithm() == KeyAlgorithm::EcdsaP256 {
            return Ok(self.slot_key.clone());
        }
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
        as_verify_mut: VerifyBackend,
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

    fn export_public_key(&self, key_id: &KeyId) -> Result<PublicKeyDer, BackendError> {
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
}

#[cfg(feature = "openssl")]
impl VerifyBackend for MockBackend {
    fn verify_public_key(
        &mut self,
        key: &PublicKeyDer,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        self.crypto
            .verify_public_key(key, message, signature, algorithm)
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
        recipient_pub_key: &PublicKeyDer,
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
        Ok(MOCK_SLOT_CERTIFICATE.to_vec())
    }

    fn delete_cert(&mut self, _cert_ref: &CertRef) -> Result<(), BackendError> {
        Ok(())
    }
}

impl PivBackend for MockBackend {
    // Every slot reports the one committed slot keypair, so both are P-256.
    // Declaring an algorithm the mock cannot then sign or read a certificate
    // under is what made a rehearsal fail as a signature mismatch.
    fn list_slots(&self) -> Result<Vec<PivSlotInfo>, BackendError> {
        Ok([PivSlot::Authentication, PivSlot::Signature]
            .into_iter()
            .map(|slot| PivSlotInfo {
                slot,
                algorithm: Some(KeyAlgorithm::EcdsaP256),
                has_certificate: true,
                origin: PivKeyOrigin::Generated,
            })
            .collect())
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
        Ok(MOCK_ATTESTATION_CERTIFICATE.to_vec())
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
            // A fixture that stopped parsing is a broken mock, not a slot
            // holding no key, so it fails rather than reporting `None`.
            public_key: Some(PublicKeyDer::new(MOCK_SLOT_PUBLIC_KEY.to_vec())?),
        })
    }

    fn block_puk(&mut self) -> Result<(), BackendError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::CertificateDer;

    #[test]
    fn fingerprint_includes_name_and_seed() {
        let backend = MockBackend::new("my-backend".to_string(), "my-seed".to_string());
        let fingerprint = backend.fingerprint();
        assert!(fingerprint.contains("my-backend"));
        assert!(fingerprint.contains("my-seed"));
    }

    /// The committed fixtures must describe one keypair, or a rehearsal that
    /// signs with the slot and verifies against the slot certificate fails as a
    /// signature mismatch. Nothing else notices if they drift apart.
    #[cfg(feature = "openssl")]
    #[test]
    fn the_slot_fixtures_are_one_keypair() {
        let backend = MockBackend::new("token".to_string(), "seed".to_string());

        let imported = backend
            .crypto
            .export_public_key(&backend.slot_key)
            .expect("the slot key was imported at construction");
        let published = PublicKeyDer::new(MOCK_SLOT_PUBLIC_KEY.to_vec())
            .expect("the slot public key fixture is SPKI DER");
        assert_eq!(
            imported, published,
            "mock-slot-key.pkcs8.der and mock-slot-key.spki.der are different keys"
        );

        let certificate = CertificateDer::new(MOCK_SLOT_CERTIFICATE.to_vec())
            .expect("the slot certificate fixture is X.509 DER");
        assert_eq!(
            certificate.public_key().unwrap(),
            published,
            "mock-slot-cert.der carries a key the slot does not hold"
        );
    }

    /// A rehearsal reads the slot certificate, signs with the slot, and checks
    /// one against the other. That is the path a mismatched fixture breaks.
    #[cfg(feature = "openssl")]
    #[test]
    fn a_slot_signature_verifies_against_the_slot_certificate() {
        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());

        let certificate = CertificateDer::new(
            backend
                .read_cert(&CertRef::PivSlot(PivSlot::Signature))
                .unwrap(),
        )
        .expect("the mock reads a real certificate");
        let signature = backend
            .sign(
                &KeyId::new("piv:9c"),
                b"release manifest",
                SignAlgorithm::EcdsaSha256,
            )
            .expect("the mock signs for an unprovisioned slot reference");

        assert!(
            backend
                .verify_public_key(
                    &certificate.public_key().unwrap(),
                    b"release manifest",
                    &signature,
                    SignAlgorithm::EcdsaSha256,
                )
                .unwrap(),
            "a slot signature must verify under the slot certificate"
        );
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
            assert_eq!(public.algorithm().unwrap(), KeyAlgorithm::Rsa2048);
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

            let public = key.public_key.expect("public key present");
            assert!(
                backend
                    .verify_public_key(&public, message, &signature, SignAlgorithm::RsaPkcs1Sha256)
                    .unwrap()
            );
            assert!(
                !backend
                    .verify_public_key(
                        &public,
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
            // rehearsal; signing must still succeed. RSA has no committed slot
            // key, so it is the case that exercises the minting path.
            let mut backend = MockBackend::new("token".to_string(), "seed".to_string());
            let slot = KeyId::new("piv:9a");

            let sig = backend
                .sign(&slot, b"release manifest", SignAlgorithm::RsaPkcs1Sha256)
                .expect("stand-in signing succeeds");
            assert!(!sig.is_empty());

            // A second signature reuses the same stand-in key.
            let again = backend
                .sign(&slot, b"another payload", SignAlgorithm::RsaPkcs1Sha256)
                .expect("stand-in is reused");
            assert!(!again.is_empty());
            assert_eq!(backend.stand_in_keys.len(), 1);
        }

        /// P-256 references resolve to the slot key rather than minting, so the
        /// signature matches the certificate the mock reports for that slot.
        #[test]
        fn a_p256_reference_signs_with_the_slot_key() {
            let mut backend = MockBackend::new("token".to_string(), "seed".to_string());

            backend
                .sign(
                    &KeyId::new("piv:9c"),
                    b"release manifest",
                    SignAlgorithm::EcdsaSha256,
                )
                .expect("the slot key signs");
            assert!(
                backend.stand_in_keys.is_empty(),
                "a P-256 slot reference must not mint a key of its own"
            );
        }

        #[test]
        fn list_keys_reflects_generated_keys() {
            let mut backend = MockBackend::new("test".to_string(), "seed".to_string());
            // The slot key is imported at construction, so it is already there.
            let before = backend.list_keys().unwrap().len();
            backend
                .generate_key(spec(KeyAlgorithm::Rsa2048, "key1"))
                .unwrap();
            backend
                .generate_key(spec(KeyAlgorithm::EcdsaP256, "key2"))
                .unwrap();
            assert_eq!(backend.list_keys().unwrap().len(), before + 2);
        }
    }
}
