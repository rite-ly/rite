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
    AccessPolicy, AccessWhen, Attestation, AttestationBackend, Backend, BackendError, CertRef,
    CertStoreBackend, KeyAlgorithm, KeyId, ManagementKey, ManagementKeyAlgorithm,
    ManagementSession, PinDefaults, PivBackend, PivDeviceInfo, PivKeyOrigin, PivPinPolicy, PivSlot,
    PivSlotInfo, PivTouchPolicy, PublicKeyDer, YubikeyBackend, YubikeySlotMetadata,
};

#[cfg(feature = "openssl")]
use rite_openssl::OpenSslBackend;
#[cfg(feature = "openssl")]
use rite_sdk::{
    DataKey, KeyAgreementBackend, KeyDecryptBackend, KeyMetadata, KeyPolicy, KeyProtection,
    KeySpec, KeyStoreBackend, KeyTransportBackend, KeyUsages, RandomBackend, SecretKeyValue,
    SignAlgorithm, SignBackend, VerifyBackend, WrapScheme, WrappedKey,
};
#[cfg(feature = "openssl")]
use zeroize::Zeroizing;

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
#[cfg(feature = "openssl")]
const MOCK_SLOT_PRIVATE_KEY: &[u8] = include_bytes!("fixtures/mock-slot-key.pkcs8.der");

/// The public half of [`MOCK_SLOT_PRIVATE_KEY`], in SPKI DER.
///
/// Committed separately so a build without the `openssl` feature, which has no
/// crypto backend to import the private half into, can still report slot
/// contents. `the_slot_fixtures_are_one_keypair` holds the two together.
const MOCK_SLOT_PUBLIC_KEY: &[u8] = include_bytes!("fixtures/mock-slot-key.spki.der");

/// The certificate for [`MOCK_SLOT_PUBLIC_KEY`], self-signed and long-dated.
const MOCK_SLOT_CERTIFICATE: &[u8] = include_bytes!("fixtures/mock-slot-cert.der");

/// The policy of a key standing in for one a device holds: every usage.
///
/// A PIV slot carries no usage attribute, the slot is its usage, so a slot's
/// key signs or agrees as the ceremony asks. A stand-in with the default
/// signing policy would refuse the agreement that opens content sealed to it.
#[cfg(feature = "openssl")]
fn slot_policy() -> KeyPolicy {
    KeyPolicy {
        usages: KeyUsages::all(),
        ..KeyPolicy::default()
    }
}

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
    /// The access policy of each key a step generated, as a card reports it
    /// back: what the step asked for, the slot's default for the rest.
    #[cfg(feature = "openssl")]
    access: std::collections::HashMap<KeyId, AccessPolicy>,
    /// The stand-in for a YubiKey's F9 key, which signs the mock's
    /// attestations, imported at the first one.
    #[cfg(feature = "pki")]
    attestation_key: Option<KeyId>,
    /// Keys a step imported, which the mock refuses to attest, as a YubiKey
    /// does. A held key's origin is not known to a rehearsal: the mock
    /// attests it, and the card refuses it if it was imported.
    #[cfg(feature = "pki")]
    imported: std::collections::HashSet<KeyId>,
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
            .import_key(
                KeySpec {
                    algorithm: KeyAlgorithm::EcdsaP256,
                    label: "mock-piv-slot".to_string(),
                    policy: slot_policy(),
                    location_hint: None,
                },
                MOCK_SLOT_PRIVATE_KEY,
                None,
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
            #[cfg(feature = "openssl")]
            access: std::collections::HashMap::new(),
            #[cfg(feature = "pki")]
            attestation_key: None,
            #[cfg(feature = "pki")]
            imported: std::collections::HashSet::new(),
            name,
            seed,
        }
    }

    /// Hold a stand-in for each key a ceremony declares this backend already
    /// holds, `(id, algorithm)`, so a rehearsal reads, signs with and agrees
    /// with it under the declared id.
    ///
    /// A P-256 key is the committed slot key, as for an undeclared reference
    /// signed with; another algorithm gets a fresh key of that algorithm.
    ///
    /// # Errors
    ///
    /// Returns what generating a stand-in returns, and
    /// [`BackendError::UnsupportedOperation`] in a build without the `openssl`
    /// feature, which has no crypto to stand in with.
    pub fn with_held_keys(self, held: &[(KeyId, KeyAlgorithm)]) -> Result<Self, BackendError> {
        #[cfg(feature = "openssl")]
        {
            let mut this = self;
            for (key_id, algorithm) in held {
                this.stand_in_key(key_id, *algorithm)?;
            }
            Ok(this)
        }
        #[cfg(not(feature = "openssl"))]
        if held.is_empty() {
            Ok(self)
        } else {
            Err(BackendError::UnsupportedOperation(
                "the mock holds keys only in a build with the 'openssl' feature".to_string(),
            ))
        }
    }

    /// The key backing `key_id`: its own, or the stand-in for a declared
    /// held key.
    #[cfg(feature = "openssl")]
    fn backing(&self, key_id: &KeyId) -> KeyId {
        self.stand_in_keys
            .get(key_id.as_str())
            .cloned()
            .unwrap_or_else(|| key_id.clone())
    }

    /// Return the backing key for `key_id`, minting a synthetic stand-in of
    /// `algorithm` the first time it is seen.
    ///
    /// Used for the keys a ceremony declares, and by [`SignBackend::sign`] so a
    /// rehearsal can sign with a reference (a PIV slot, say) whose key was
    /// provisioned outside the ceremony. A stand-in permits every usage, as a
    /// PIV slot carries no usage attribute.
    ///
    /// P-256 references resolve to the slot key, the one the mock also reports
    /// through [`CertStoreBackend::read_cert`] and slot metadata, so a signature
    /// it produces verifies against the certificate a rehearsal just read. Other
    /// algorithms have no committed slot key and get a fresh stand-in.
    #[cfg(feature = "openssl")]
    fn stand_in_key(
        &mut self,
        key_id: &KeyId,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyId, BackendError> {
        if let Some(backing) = self.stand_in_keys.get(key_id.as_str()) {
            return Ok(backing.clone());
        }
        let backing = if algorithm == KeyAlgorithm::EcdsaP256 {
            self.slot_key.clone()
        } else {
            self.crypto
                .generate_key(KeySpec {
                    algorithm,
                    label: format!("mock-stand-in:{key_id}"),
                    policy: slot_policy(),
                    location_hint: None,
                })?
                .key_id
        };
        self.stand_in_keys
            .insert(key_id.as_str().to_string(), backing.clone());
        Ok(backing)
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
        as_agreement_mut: KeyAgreementBackend,
        #[cfg(feature = "openssl")]
        as_key_decrypt_mut: KeyDecryptBackend,
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
    /// Accepts the access values a `YubiKey` does, on the keypairs it holds,
    /// and reports them back as it would: the slot's default PIN policy and
    /// no touch for an axis left out. The software key under it enforces
    /// none of them.
    fn generate_key(&mut self, mut spec: KeySpec) -> Result<KeyMetadata, BackendError> {
        let declared = spec.policy.access;
        let reported = if spec.algorithm.is_symmetric() {
            if !declared.is_empty() {
                return Err(BackendError::OperationNotPermitted(format!(
                    "a PIV device holds no {} key to give an access policy",
                    spec.algorithm
                )));
            }
            None
        } else {
            declared.to_piv()?;
            let slot = spec
                .location_hint
                .as_deref()
                .and_then(PivSlot::from_hint)
                .unwrap_or(PivSlot::GENERATE_DEFAULT);
            Some(AccessPolicy {
                authentication: declared
                    .authentication
                    .or_else(|| AccessWhen::from_pin_policy(slot.default_pin_policy())),
                presence: declared.presence.or(Some(AccessWhen::Never)),
            })
        };
        spec.policy.access = AccessPolicy::default();
        let metadata = self.crypto.generate_key(spec)?;
        if let Some(reported) = reported {
            self.access.insert(metadata.key_id.clone(), reported);
        }
        Ok(metadata)
    }

    fn access_policy(&self, key_id: &KeyId) -> Result<Option<AccessPolicy>, BackendError> {
        Ok(self.access.get(key_id).copied())
    }

    fn import_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<KeyMetadata, BackendError> {
        let metadata = self.crypto.import_key(spec, key_bytes, passphrase)?;
        #[cfg(feature = "pki")]
        self.imported.insert(metadata.key_id.clone());
        Ok(metadata)
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<PublicKeyDer, BackendError> {
        self.crypto.export_public_key(&self.backing(key_id))
    }

    fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
        self.crypto.list_keys()
    }

    fn delete_key(&mut self, key_id: &KeyId) -> Result<(), BackendError> {
        self.crypto.delete_key(key_id)?;
        self.access.remove(key_id);
        #[cfg(feature = "pki")]
        self.imported.remove(key_id);
        Ok(())
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
                // The signature -> key algorithm pairing is owned by the SDK so the
                // stand-in cannot drift from what real backends select.
                let backing = self.stand_in_key(key_id, algorithm.key_algorithm())?;
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
        scheme: WrapScheme,
    ) -> Result<WrappedKey, BackendError> {
        self.crypto.wrap(key_id, wrapping_key_id, scheme)
    }

    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
        policy: KeyPolicy,
        expected: Option<KeyAlgorithm>,
    ) -> Result<KeyMetadata, BackendError> {
        self.crypto
            .unwrap(wrapped, unwrapping_key_id, label, policy, expected)
    }

    fn generate_data_key(
        &mut self,
        kek: &KeyId,
        algorithm: KeyAlgorithm,
    ) -> Result<DataKey, BackendError> {
        self.crypto.generate_data_key(kek, algorithm)
    }

    fn open_data_key(
        &mut self,
        kek: &KeyId,
        wrapped: &[u8],
        protection: KeyProtection,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        self.crypto.open_data_key(kek, wrapped, protection)
    }

    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient: &rite_sdk::cms::Recipient,
        scheme: WrapScheme,
    ) -> Result<WrappedKey, BackendError> {
        self.crypto.wrap_to_public(key_id, recipient, scheme)
    }

    fn export_secret_key(&mut self, key_id: &KeyId) -> Result<SecretKeyValue, BackendError> {
        self.crypto.export_secret_key(key_id)
    }
}

#[cfg(feature = "openssl")]
impl KeyAgreementBackend for MockBackend {
    fn agree(
        &mut self,
        key_id: &KeyId,
        peer: &PublicKeyDer,
    ) -> Result<rite_sdk::AgreedSecret, BackendError> {
        self.crypto.agree(&self.backing(key_id), peer)
    }
}

#[cfg(feature = "openssl")]
impl KeyDecryptBackend for MockBackend {
    fn decrypt_key(
        &mut self,
        key_id: &KeyId,
        encrypted: &[u8],
        protection: KeyProtection,
    ) -> Result<Zeroizing<Vec<u8>>, BackendError> {
        self.crypto
            .decrypt_key(&self.backing(key_id), encrypted, protection)
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

/// A YubiKey PIV attestation in form, under the rehearsal root: see
/// [`super::mock_attestation`].
impl AttestationBackend for MockBackend {
    #[cfg(feature = "pki")]
    fn attest_key(&mut self, key_id: &KeyId) -> Result<Attestation, BackendError> {
        if self.imported.contains(key_id) {
            return Err(BackendError::OperationNotPermitted(format!(
                "key {key_id} was imported, and a YubiKey attests only keys it generated"
            )));
        }
        let public_key = self.export_public_key(key_id)?;
        let signer = if let Some(signer) = &self.attestation_key {
            signer.clone()
        } else {
            let signer = self
                .crypto
                .import_key(
                    KeySpec {
                        algorithm: super::mock_attestation::F9_ALGORITHM,
                        label: "mock-attestation-f9".to_string(),
                        policy: KeyPolicy::default(),
                        location_hint: None,
                    },
                    super::mock_attestation::MOCK_ATTESTATION_F9_KEY,
                    None,
                )?
                .key_id;
            self.attestation_key = Some(signer.clone());
            signer
        };
        let access = self.access.get(key_id).copied().unwrap_or_default();
        super::mock_attestation::attest(key_id.as_str(), &public_key, access, |tbs, algorithm| {
            self.crypto.sign(&signer, tbs, algorithm)
        })
    }

    #[cfg(not(feature = "pki"))]
    fn attest_key(&mut self, _key_id: &KeyId) -> Result<Attestation, BackendError> {
        Err(BackendError::UnsupportedOperation(
            "the mock attests only in a build with the 'pki' feature".to_string(),
        ))
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
    /// Accepts any key, as a card of firmware 5.7 with an AES-192 key would
    /// the right one, and reports it as the default only when the step
    /// presents the default.
    fn authenticate_management(
        &mut self,
        key: ManagementKey<'_>,
    ) -> Result<ManagementSession, BackendError> {
        Ok(ManagementSession {
            algorithm: ManagementKeyAlgorithm::Aes192,
            is_default: Some(matches!(key, ManagementKey::FactoryDefault)),
        })
    }

    /// Says nothing: the mock accepts any PIN, so whether it is the
    /// factory one means nothing.
    fn pin_defaults(&self) -> Result<PinDefaults, BackendError> {
        Ok(PinDefaults::default())
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
    #[cfg(feature = "openssl")]
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

    /// The attestation names the key the mock holds, which for a generated
    /// key is a fresh one, and chains to the rehearsal root as OpenSSL builds
    /// a chain.
    #[cfg(feature = "pki")]
    #[test]
    fn an_attestation_names_the_key_and_chains_to_the_rehearsal_root() {
        use super::super::mock_attestation::MOCK_ATTESTATION_ROOT;
        use openssl::stack::Stack;
        use openssl::x509::store::X509StoreBuilder;
        use openssl::x509::{X509, X509StoreContext, X509StoreContextRef};

        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());
        let key = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::EcdsaP384,
                label: "generated".to_string(),
                policy: KeyPolicy::default(),
                location_hint: None,
            })
            .unwrap();
        let attestation = backend.attest_key(&key.key_id).unwrap();

        assert_eq!(
            attestation.leaf().public_key().unwrap(),
            backend.export_public_key(&key.key_id).unwrap()
        );

        let x509 = |der: &[u8]| X509::from_der(der).unwrap();
        let mut store = X509StoreBuilder::new().unwrap();
        store.add_cert(x509(MOCK_ATTESTATION_ROOT)).unwrap();
        let store = store.build();
        let mut untrusted = Stack::new().unwrap();
        untrusted
            .push(x509(attestation.issuers().first().unwrap().as_bytes()))
            .unwrap();
        let leaf = x509(attestation.leaf().as_bytes());
        let mut context = X509StoreContext::new().unwrap();
        let verified = context
            .init(&store, &leaf, &untrusted, X509StoreContextRef::verify_cert)
            .unwrap();
        assert!(verified, "{}", context.error());
    }

    /// The attestation states the access policy the step that generated the
    /// key set, as a card's does, so a rehearsal's claims match the run's.
    #[cfg(feature = "pki")]
    #[test]
    fn an_attestation_states_the_policy_the_key_was_generated_with() {
        use x509_cert::der::Decode;

        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());
        let policy = KeyPolicy {
            access: AccessPolicy {
                authentication: Some(AccessWhen::PerUse),
                presence: Some(AccessWhen::Cached),
            },
            ..KeyPolicy::default()
        };
        let key = backend
            .generate_key(KeySpec {
                algorithm: KeyAlgorithm::EcdsaP256,
                label: "signing".to_string(),
                policy,
                location_hint: Some("9a".to_string()),
            })
            .unwrap();
        let attestation = backend.attest_key(&key.key_id).unwrap();

        let leaf = x509_cert::Certificate::from_der(attestation.leaf().as_bytes()).unwrap();
        let stated = leaf
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .find(|extension| extension.extn_id == rite_sdk::yubico_oid::POLICY)
            .expect("a Yubico policy extension");
        // PIN always (3), touch cached (3): not 9A's defaults, once and never.
        assert_eq!(stated.extn_value.as_bytes(), [3, 3]);
    }

    /// A rehearsal stops where the card would: at attesting an imported key.
    #[cfg(feature = "pki")]
    #[test]
    fn an_imported_key_is_not_attested() {
        let mut backend = MockBackend::new("token".to_string(), "seed".to_string());
        let imported = backend
            .import_key(
                KeySpec {
                    algorithm: KeyAlgorithm::EcdsaP256,
                    label: "imported".to_string(),
                    policy: KeyPolicy::default(),
                    location_hint: None,
                },
                MOCK_SLOT_PRIVATE_KEY,
                None,
            )
            .unwrap();
        let error = backend.attest_key(&imported.key_id).unwrap_err();
        assert!(
            matches!(error, BackendError::OperationNotPermitted(_)),
            "{error}"
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
            // The mock delegates to OpenSSL, policy enforcement included, so
            // a rehearsal refuses exactly what the real run would.
            let kek = backend
                .generate_key(KeySpec {
                    policy: KeyPolicy {
                        usages: rite_sdk::KeyUsages::WRAP | rite_sdk::KeyUsages::UNWRAP,
                        ..KeyPolicy::default()
                    },
                    ..spec(KeyAlgorithm::Rsa4096, "wrapping-key")
                })
                .unwrap();
            let target = backend
                .generate_key(KeySpec {
                    policy: KeyPolicy {
                        extractable: true,
                        ..KeyPolicy::default()
                    },
                    ..spec(KeyAlgorithm::Rsa4096, "data-key")
                })
                .unwrap();

            let wrapped = backend
                .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
                .unwrap();
            let unwrapped = backend
                .unwrap(
                    &wrapped,
                    &kek.key_id,
                    "unwrapped-key",
                    crate::params::installed_key_default_policy(None),
                    None,
                )
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
            assert_eq!(
                backend.stand_in_keys.get("piv:9c"),
                Some(&backend.slot_key),
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
