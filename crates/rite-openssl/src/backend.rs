//! OpenSSL backend implementation.
//!
//! Uses the `openssl` crate for all cryptographic operations. Keys are stored
//! as OpenSSL `PKey<Private>` objects; OpenSSL manages that key memory and
//! frees it on drop. Key material serialized *out* of OpenSSL (DER buffers
//! for wrapping/unwrapping) lives in ordinary Rust allocations and is wiped
//! explicitly with `Zeroizing` before release.

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::cms::CmsContentInfo;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::symm::Cipher;
use openssl::x509::{X509Builder, X509NameBuilder};
use rite_sdk::{
    Backend, BackendError, KeyAlgorithm, KeyId, KeyMetadata, KeySpec, KeyStoreBackend,
    KeyTransportBackend, RandomBackend, SignAlgorithm, SignBackend, WrapAlgorithm, WrappedKey,
};
use std::collections::HashMap;
use zeroize::Zeroizing;

/// OpenSSL-based cryptographic backend.
///
/// Stores keys in memory as OpenSSL `PKey<Private>` objects. That private key
/// material is managed by OpenSSL and wiped on drop. Plaintext private-key
/// DER produced during wrap/unwrap, however, lives in Rust-side buffers and
/// is zeroized explicitly when dropped.
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
    /// Returns always `Ok`, as no hardware initialization is needed.
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
    /// the `KeyMetadata`: the common closing sequence of generate, import, and unwrap.
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

    /// Always returns `"openssl"`. Use this value in ceremony files to select this backend.
    fn provider(&self) -> &'static str {
        "openssl"
    }

    /// Returns `"openssl-backend=<name>+openssl=<version>"`.
    ///
    /// The OpenSSL version is the runtime version of the linked library,
    /// which may differ from the version used at compile time.
    fn fingerprint(&self) -> String {
        let version = openssl::version::version()
            .split_whitespace()
            .nth(1)
            .unwrap_or("unknown");
        format!("openssl-backend={}+openssl={}", self.name, version)
    }

    rite_sdk::backend_capabilities!(
        /// Supports RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519, and
        /// (with OpenSSL 3.5+) ML-DSA-44/65/87 key generation and storage.
        as_keystore_mut: KeyStoreBackend,
        /// Supports RSA-PKCS1-v1.5 (SHA-256), RSA-PSS (SHA-256), ECDSA
        /// (SHA-256/SHA-384), Ed25519, and (with OpenSSL 3.5+) ML-DSA-44/65/87
        /// signing.
        as_sign_mut: SignBackend,
        /// Supports CMS-RSA-GCM and CMS-RSA-CBC key wrapping and unwrapping.
        as_transport_mut: KeyTransportBackend,
        /// Provides cryptographically secure random bytes via the OpenSSL CSPRNG.
        as_random_mut: RandomBackend,
    );
}

/// Map an OpenSSL error to a `BackendError`.
fn ossl_err(context: &str, e: &openssl::error::ErrorStack) -> BackendError {
    BackendError::Other(format!("{context}: {e}"))
}

/// Reject a signature request whose algorithm does not match the stored key.
///
/// Runs once at the top of `sign` and `verify`, so the per-key-type arms below
/// only have to select an OpenSSL primitive. `operation` names the caller for
/// the error message ("Sign" or "Verify").
fn check_key_accepted(
    operation: &str,
    algorithm: SignAlgorithm,
    key_algorithm: KeyAlgorithm,
) -> Result<(), BackendError> {
    if algorithm.accepts_key(key_algorithm) {
        return Ok(());
    }
    Err(BackendError::UnsupportedAlgorithm(format!(
        "{operation} algorithm {algorithm} not supported for {key_algorithm} keys"
    )))
}

/// Recover the `KeyAlgorithm` of a key from the key object itself.
///
/// Needed wherever the algorithm is not carried alongside the key: CMS
/// `EnvelopedData` holds the raw key bytes as opaque content, and a bare SPKI
/// public key arrives with no ceremony metadata attached.
fn key_algorithm_of<T: HasPublic>(pkey: &PKeyRef<T>) -> Result<KeyAlgorithm, BackendError> {
    match pkey.id() {
        Id::RSA => match pkey.bits() {
            2048 => Ok(KeyAlgorithm::Rsa2048),
            4096 => Ok(KeyAlgorithm::Rsa4096),
            bits => Err(BackendError::UnsupportedAlgorithm(format!(
                "RSA key size {bits} bits not supported (expected 2048 or 4096)"
            ))),
        },
        Id::EC => {
            let ec_key = pkey.ec_key().map_err(|e| ossl_err("Read EC key", &e))?;
            let nid = ec_key
                .group()
                .curve_name()
                .ok_or_else(|| BackendError::Other("EC key has no named curve".to_string()))?;
            match nid {
                Nid::X9_62_PRIME256V1 => Ok(KeyAlgorithm::EcdsaP256),
                Nid::SECP384R1 => Ok(KeyAlgorithm::EcdsaP384),
                _ => Err(BackendError::UnsupportedAlgorithm(format!(
                    "EC curve {nid:?} is not supported (expected P-256 or P-384)"
                ))),
            }
        }
        Id::ED25519 => Ok(KeyAlgorithm::Ed25519),
        _ => {
            #[cfg(ossl350)]
            for (algorithm, key_type) in ML_DSA_KEY_TYPES {
                if pkey.is_a(key_type) {
                    return Ok(algorithm);
                }
            }

            Err(BackendError::UnsupportedAlgorithm(
                "Key is not RSA, a supported EC curve, Ed25519, or ML-DSA".to_string(),
            ))
        }
    }
}

/// Seed length shared by every ML-DSA parameter set (FIPS 204 xi is 32 bytes).
#[cfg(ossl350)]
const ML_DSA_SEED_LEN: usize = 32;

/// The ML-DSA parameter sets, paired with their OpenSSL provider key types.
///
/// Single source of truth for the mapping in both directions: key generation
/// looks up a key type, and CMS unwrap probes each one to recover the algorithm.
#[cfg(ossl350)]
const ML_DSA_KEY_TYPES: [(KeyAlgorithm, openssl::pkey::KeyType); 3] = [
    (KeyAlgorithm::MlDsa44, openssl::pkey::KeyType::ML_DSA_44),
    (KeyAlgorithm::MlDsa65, openssl::pkey::KeyType::ML_DSA_65),
    (KeyAlgorithm::MlDsa87, openssl::pkey::KeyType::ML_DSA_87),
];

/// Generate an ML-DSA keypair.
///
/// FIPS 204 derives the entire keypair deterministically from a 32-byte seed.
/// `EVP_PKEY_fromdata` with a `seed` parameter is the only generation route the
/// `openssl` crate exposes without raw FFI, so the seed is drawn from the
/// OpenSSL CSPRNG here and wiped once the provider has expanded it.
#[cfg(ossl350)]
fn generate_ml_dsa(algorithm: KeyAlgorithm) -> Result<PKey<Private>, BackendError> {
    let key_type = ML_DSA_KEY_TYPES
        .iter()
        .find(|(candidate, _)| *candidate == algorithm)
        .map(|(_, key_type)| *key_type)
        .ok_or_else(|| {
            BackendError::UnsupportedAlgorithm(format!(
                "{algorithm} is not an ML-DSA parameter set"
            ))
        })?;
    let mut seed = Zeroizing::new(vec![0u8; ML_DSA_SEED_LEN]);
    openssl::rand::rand_bytes(&mut seed).map_err(|e| ossl_err("ML-DSA seed generation", &e))?;
    PKey::private_key_from_seed(None, key_type, None, &seed)
        .map_err(|e| ossl_err("ML-DSA key generation", &e))
}

#[cfg(not(ossl350))]
fn generate_ml_dsa(_algorithm: KeyAlgorithm) -> Result<PKey<Private>, BackendError> {
    Err(unsupported_ml_dsa("key generation"))
}

/// Refuse ML-DSA on a build whose OpenSSL has no provider for it.
///
/// The signing and verification paths below are generic: `digest_for` already
/// routes ML-DSA to the digest-free `EVP_DigestSign` path that FIPS 204 needs,
/// so no separate implementation is required. What a pre-3.5 build does need is
/// this, an error naming the missing provider instead of whatever OpenSSL
/// reports when handed a key type it does not know.
#[cfg(not(ossl350))]
fn check_ml_dsa_available(algorithm: SignAlgorithm, operation: &str) -> Result<(), BackendError> {
    if matches!(
        algorithm,
        SignAlgorithm::MlDsa44 | SignAlgorithm::MlDsa65 | SignAlgorithm::MlDsa87
    ) {
        return Err(unsupported_ml_dsa(operation));
    }
    Ok(())
}

/// Refuse ML-DSA on a build whose OpenSSL has no provider for it.
///
/// This build has one, so every algorithm is available.
#[cfg(ossl350)]
#[allow(clippy::unnecessary_wraps)]
fn check_ml_dsa_available(_algorithm: SignAlgorithm, _operation: &str) -> Result<(), BackendError> {
    Ok(())
}

/// The RSA padding controls `Signer` and `Verifier` both have, which the
/// `openssl` crate does not express through a shared trait.
trait RsaPadding {
    fn padding(&mut self, padding: Padding) -> Result<(), openssl::error::ErrorStack>;
    fn mgf1_md(&mut self, md: MessageDigest) -> Result<(), openssl::error::ErrorStack>;
}

impl RsaPadding for Signer<'_> {
    fn padding(&mut self, padding: Padding) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_padding(padding)
    }
    fn mgf1_md(&mut self, md: MessageDigest) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_mgf1_md(md)
    }
}

impl RsaPadding for Verifier<'_> {
    fn padding(&mut self, padding: Padding) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_padding(padding)
    }
    fn mgf1_md(&mut self, md: MessageDigest) -> Result<(), openssl::error::ErrorStack> {
        self.set_rsa_mgf1_md(md)
    }
}

/// Apply the padding scheme an RSA algorithm names. A no-op for everything else.
///
/// PKCS#1 v1.5 is OpenSSL's default, but it is set explicitly so the scheme is
/// never left to a library default that could change.
fn apply_rsa_padding<T: RsaPadding>(
    operation: &mut T,
    algorithm: SignAlgorithm,
) -> Result<(), BackendError> {
    match algorithm {
        SignAlgorithm::RsaPkcs1Sha256 => operation
            .padding(Padding::PKCS1)
            .map_err(|e| ossl_err("Set PKCS1 padding", &e)),
        SignAlgorithm::RsaPssSha256 => {
            operation
                .padding(Padding::PKCS1_PSS)
                .map_err(|e| ossl_err("Set PSS padding", &e))?;
            operation
                .mgf1_md(MessageDigest::sha256())
                .map_err(|e| ossl_err("Set MGF1 MD", &e))
        }
        _ => Ok(()),
    }
}

/// The message digest an algorithm signs over, or `None` for the digest-free
/// schemes that take the message whole (Ed25519, ML-DSA).
fn digest_for(algorithm: SignAlgorithm) -> Option<MessageDigest> {
    match algorithm {
        SignAlgorithm::EcdsaSha384 => Some(MessageDigest::sha384()),
        SignAlgorithm::Ed25519
        | SignAlgorithm::MlDsa44
        | SignAlgorithm::MlDsa65
        | SignAlgorithm::MlDsa87 => None,
        _ => Some(MessageDigest::sha256()),
    }
}

/// Sign `message` with a private key.
///
/// The caller has already checked that the key and algorithm agree, so this
/// only selects an OpenSSL primitive.
fn sign_with_key(
    pkey: &PKeyRef<Private>,
    message: &[u8],
    algorithm: SignAlgorithm,
) -> Result<Vec<u8>, BackendError> {
    check_ml_dsa_available(algorithm, "signing")?;

    let mut signer = match digest_for(algorithm) {
        Some(digest) => Signer::new(digest, pkey),
        None => Signer::new_without_digest(pkey),
    }
    .map_err(|e| ossl_err("Create signer", &e))?;
    apply_rsa_padding(&mut signer, algorithm)?;
    signer
        .sign_oneshot_to_vec(message)
        .map_err(|e| ossl_err("Sign operation", &e))
}

/// Verify `signature` over `message` with a public key.
///
/// The caller has already checked that the key and algorithm agree, so this
/// only selects an OpenSSL primitive.
fn verify_with_key<T: HasPublic>(
    pkey: &PKeyRef<T>,
    message: &[u8],
    signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    check_ml_dsa_available(algorithm, "verification")?;

    let mut verifier = match digest_for(algorithm) {
        Some(digest) => Verifier::new(digest, pkey),
        None => Verifier::new_without_digest(pkey),
    }
    .map_err(|e| ossl_err("Create verifier", &e))?;
    apply_rsa_padding(&mut verifier, algorithm)?;
    verifier
        .verify_oneshot(signature, message)
        .map_err(|e| ossl_err("Verify operation", &e))
}

/// Read the key algorithm out of an SPKI DER public key.
///
/// A public key that arrives as bytes carries no metadata, so callers that must
/// know what they are holding (to pick a signature algorithm, say) recover it
/// from the key structure.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] for a key type this crate
/// does not handle, and [`BackendError::Other`] when the key cannot be parsed.
pub fn public_key_algorithm(public_der: &[u8]) -> Result<KeyAlgorithm, BackendError> {
    let pkey =
        PKey::public_key_from_der(public_der).map_err(|e| ossl_err("Decode public key", &e))?;
    key_algorithm_of(&pkey)
}

/// Verify a signature against an SPKI DER public key, without a backend.
///
/// Verification needs only the public key, so this takes no [`OpenSslBackend`]
/// and no [`KeyId`]. Signatures from signing-only devices (PIV cards, HSMs) are
/// therefore checked through the same path as software keys.
///
/// The key is required to match `algorithm`. Without that check, a caller who
/// took the algorithm from an untrusted source (a CSR's `signatureAlgorithm`,
/// say) could hand over an RSA key labelled as ECDSA and have OpenSSL quietly
/// verify it as RSA.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] when the key and algorithm
/// disagree, or when the algorithm is absent from this build (ML-DSA on an
/// OpenSSL older than 3.5), and [`BackendError::Other`] when the public key or
/// signature cannot be parsed.
pub fn verify_signature(
    public_der: &[u8],
    message: &[u8],
    signature: &[u8],
    algorithm: SignAlgorithm,
) -> Result<bool, BackendError> {
    let pkey =
        PKey::public_key_from_der(public_der).map_err(|e| ossl_err("Decode public key", &e))?;
    check_key_accepted("Verify", algorithm, key_algorithm_of(&pkey)?)?;
    verify_with_key(&pkey, message, signature, algorithm)
}

/// Error for an ML-DSA `operation` on a build linked against OpenSSL below 3.5.
///
/// Reports the runtime version, which is the one that actually lacks the
/// provider and the one an operator can act on.
#[cfg(not(ossl350))]
fn unsupported_ml_dsa(operation: &str) -> BackendError {
    BackendError::UnsupportedAlgorithm(format!(
        "ML-DSA {operation} requires OpenSSL 3.5 or newer, but this build links OpenSSL {}",
        openssl::version::version()
    ))
}

/// Parse a private key from DER bytes, trying PKCS#8, traditional PKCS#1 (RSA), and
/// traditional SEC1 (EC) in sequence.
///
/// `private_key_to_der()` emits PKCS#1 for RSA and SEC1 for EC keys. OpenSSL's
/// `d2i_AutoPrivateKey` (called by `PKey::private_key_from_der`) handles PKCS#8 and
/// PKCS#1 RSA but not SEC1 EC — the third leg covers that gap.
fn parse_private_key_der(bytes: &[u8]) -> Result<PKey<Private>, BackendError> {
    PKey::private_key_from_der(bytes)
        .or_else(|_| Rsa::private_key_from_der(bytes).and_then(PKey::from_rsa))
        .or_else(|_| EcKey::private_key_from_der(bytes).and_then(PKey::from_ec_key))
        .map_err(|e| ossl_err("Parse private key material", &e))
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
            KeyAlgorithm::EcdsaP256 | KeyAlgorithm::EcdsaP384 => {
                let (nid, name) = if spec.algorithm == KeyAlgorithm::EcdsaP384 {
                    (Nid::SECP384R1, "ECDSA-P384")
                } else {
                    (Nid::X9_62_PRIME256V1, "ECDSA-P256")
                };
                let group = EcGroup::from_curve_name(nid)
                    .map_err(|e| ossl_err(&format!("Load {name} group"), &e))?;
                let ec_key =
                    EcKey::generate(&group).map_err(|e| ossl_err(&format!("{name} keygen"), &e))?;
                PKey::from_ec_key(ec_key).map_err(|e| ossl_err(&format!("PKey from {name}"), &e))?
            }
            KeyAlgorithm::Ed25519 => {
                PKey::generate_ed25519().map_err(|e| ossl_err("Ed25519 keygen", &e))?
            }
            KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
                generate_ml_dsa(spec.algorithm)?
            }
            other => {
                return Err(BackendError::UnsupportedAlgorithm(format!(
                    "Algorithm {other} not yet implemented for OpenSslBackend"
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
        let pkey = parse_private_key_der(key_bytes)?;
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
        check_key_accepted("Sign", algorithm, key.algorithm)?;
        sign_with_key(&key.pkey, message, algorithm)
    }

    fn verify(
        &self,
        key_id: &KeyId,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        let key = self.get_key(key_id)?;
        check_key_accepted("Verify", algorithm, key.algorithm)?;
        // The stored private key carries its public half, so there is nothing
        // to decode: `public_der` exists for export, not for verification.
        verify_with_key(&key.pkey, message, signature, algorithm)
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
/// This cert is only used to satisfy the CMS API; it is never stored or validated.
fn self_signed_cert(pkey: &PKeyRef<Private>) -> Result<openssl::x509::X509, BackendError> {
    build_cert(pkey, pkey)
}

/// Create a CMS recipient certificate carrying an external public key.
///
/// OpenSSL's CMS encrypt only reads the subject public key from the cert; it never
/// validates the cert signature. We sign with a throwaway key so we can embed any
/// public key as the subject without needing the matching private key.
fn cert_for_public_key(recipient_public_key: &[u8]) -> Result<openssl::x509::X509, BackendError> {
    let recipient_pub = PKey::public_key_from_der(recipient_public_key)
        .or_else(|_| PKey::public_key_from_pem(recipient_public_key))
        .map_err(|e| ossl_err("Parse recipient public key (DER or PEM)", &e))?;

    // Generate a throwaway key just for signing the cert.
    // CMS encrypt does NOT verify the cert signature; it only reads the public key.
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

/// CMS-encrypt `key_material` to a recipient certificate.
///
/// Shared by `wrap` (self-signed cert built from the KEK) and `wrap_to_public` (cert built
/// from an external public key). OpenSSL's `CMS_encrypt` selects the key-encapsulation
/// mechanism automatically based on the recipient certificate's public key type:
///
/// **RSA recipient — `KeyTransportRecipientInfo` (RFC 5652 §6.2)**
/// The content-encryption key (CEK) is encrypted directly under the recipient's RSA public
/// key using RSAES-PKCS1-v1.5. This is the default in OpenSSL's `CMS_encrypt`; OAEP
/// would require `CMS_KEY_PARAM` flags and is not used here.
///
/// **EC P-256 recipient — `KeyAgreementRecipientInfo` (RFC 5753 §3.1)**
/// OpenSSL generates an ephemeral P-256 key pair, performs one-pass ECDH between the
/// ephemeral private key and the recipient's static public key, then feeds the shared
/// secret into the ANSI X9.63 KDF (SHA-256) to produce a 128-bit key-encryption key.
/// That KEK wraps the CEK with AES-128-KeyWrap (RFC 3394). The algorithm identifier in
/// the CMS blob is `dhSinglePass-stdDH-sha256kdf-scheme` (OID 1.3.132.1.11.1).
///
/// The `algorithm` parameter controls only the **content** cipher (AES-256-GCM or
/// AES-256-CBC); the key-encapsulation path above is orthogonal to it.
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

        // A self-signed cert built from the KEK lets OpenSSL select the right
        // encapsulation: RSA KEK → RSAES-PKCS1-v1.5, EC P-256 KEK → RFC 5753 ECDH.
        let cert = self_signed_cert(&kek.pkey)?;
        // Zeroizing: this buffer holds the plaintext private key in DER form;
        // wipe it on drop rather than leaving it in freed heap memory.
        let key_material = Zeroizing::new(
            target
                .pkey
                .private_key_to_der()
                .map_err(|e| ossl_err("Export key material for wrapping", &e))?,
        );

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
        // Zeroizing: the decrypted output is the plaintext private key in DER
        // form; wipe it on drop rather than leaving it in freed heap memory.
        let key_material = Zeroizing::new({
            let kek = self.get_key(unwrapping_key_id)?;
            // Re-create the ephemeral cert from the same key; CMS decrypt needs it
            // to find the matching recipient.
            let cert = self_signed_cert(&kek.pkey)?;
            let cms = CmsContentInfo::from_der(&wrapped.data)
                .map_err(|e| ossl_err("Parse CMS DER", &e))?;
            cms.decrypt(&kek.pkey, &cert)
                .map_err(|e| ossl_err("CMS decrypt", &e))?
        });

        let pkey = parse_private_key_der(&key_material)?;

        let key_algorithm = key_algorithm_of(&pkey)?;
        self.store_key(key_algorithm, label.to_string(), pkey)
    }

    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient_pub_key: &[u8],
        algorithm: WrapAlgorithm,
    ) -> Result<WrappedKey, BackendError> {
        let target = self.get_key(key_id)?;

        // OpenSSL reads only the subject public key for CMS encapsulation and never
        // validates the cert's self-signature — the throwaway RSA signing key inside
        // cert_for_public_key works regardless of whether the recipient key is RSA or EC.
        let cert = cert_for_public_key(recipient_pub_key)?;
        // Zeroizing: this buffer holds the plaintext private key in DER form;
        // wipe it on drop rather than leaving it in freed heap memory.
        let key_material = Zeroizing::new(
            target
                .pkey
                .private_key_to_der()
                .map_err(|e| ossl_err("Export key material for wrapping", &e))?,
        );

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
    fn test_generate_ecdsa_p256() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "test-key-p256"))
            .unwrap();
        assert_eq!(metadata.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(metadata.label, "test-key-p256");
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
    fn test_sign_and_verify_ecdsa_p256() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "signing-key-p256"))
            .unwrap();

        let message = b"Hello, ECDSA!";
        let signature = backend
            .sign(&metadata.key_id, message, SignAlgorithm::EcdsaSha256)
            .unwrap();

        let valid = backend
            .verify(
                &metadata.key_id,
                message,
                &signature,
                SignAlgorithm::EcdsaSha256,
            )
            .unwrap();
        assert!(valid);
    }

    /// Every signature family the backend claims must round-trip through
    /// `sign` and `verify`, including the two digest-free schemes whose OpenSSL
    /// path differs (Ed25519 and, above, ML-DSA).
    #[test]
    fn signs_and_verifies_every_supported_algorithm() {
        let cases: &[(KeyAlgorithm, SignAlgorithm)] = &[
            (KeyAlgorithm::Rsa2048, SignAlgorithm::RsaPkcs1Sha256),
            (KeyAlgorithm::Rsa2048, SignAlgorithm::RsaPssSha256),
            (KeyAlgorithm::EcdsaP256, SignAlgorithm::EcdsaSha256),
            (KeyAlgorithm::EcdsaP384, SignAlgorithm::EcdsaSha384),
            (KeyAlgorithm::Ed25519, SignAlgorithm::Ed25519),
        ];

        for &(key_algorithm, algorithm) in cases {
            let mut backend = OpenSslBackend::try_new("test").unwrap();
            let metadata = backend
                .generate_key(spec(key_algorithm, "signing-key"))
                .unwrap();
            let message = b"ceremony transcript";

            let signature = backend
                .sign(&metadata.key_id, message, algorithm)
                .unwrap_or_else(|e| panic!("{key_algorithm} signs with {algorithm}: {e}"));

            assert!(
                backend
                    .verify(&metadata.key_id, message, &signature, algorithm)
                    .unwrap(),
                "{key_algorithm} must verify its own {algorithm} signature"
            );
            assert!(
                !backend
                    .verify(&metadata.key_id, b"tampered", &signature, algorithm)
                    .unwrap(),
                "{key_algorithm} must reject a {algorithm} signature over other data"
            );

            // The same signature must check out through the backend-free entry
            // point, which is what actions and CSR checking use.
            let public_der = metadata.public_key.as_ref().unwrap();
            assert!(verify_signature(public_der, message, &signature, algorithm).unwrap());
        }
    }

    /// `verify_signature` takes its algorithm from the caller, which for CSR
    /// checking means from the document being checked. A key of another family
    /// must be refused rather than verified under whatever scheme it fits.
    #[test]
    fn backend_free_verification_refuses_a_key_of_the_wrong_family() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "rsa-key"))
            .unwrap();
        let message = b"data";
        let signature = backend
            .sign(&metadata.key_id, message, SignAlgorithm::RsaPkcs1Sha256)
            .unwrap();
        let public_der = metadata.public_key.as_ref().unwrap();

        let err = verify_signature(public_der, message, &signature, SignAlgorithm::EcdsaSha256)
            .unwrap_err();
        assert!(
            matches!(err, BackendError::UnsupportedAlgorithm(_)),
            "{err:?}"
        );
    }

    /// An RSA signature scheme is defined for any modulus size, so the shared
    /// compatibility check must not pin RSA requests to one key size.
    #[test]
    fn signs_with_an_rsa_4096_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::Rsa4096, "signing-key-4096"))
            .unwrap();

        let message = b"Hello, large modulus!";
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
    }

    /// A key of the wrong family is refused before any OpenSSL primitive is
    /// selected, and the error names both sides in their DSL spelling.
    #[test]
    fn rejects_a_signature_algorithm_the_key_cannot_perform() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "signing-key-p256"))
            .unwrap();

        let err = backend
            .sign(&metadata.key_id, b"data", SignAlgorithm::RsaPkcs1Sha256)
            .unwrap_err();

        let BackendError::UnsupportedAlgorithm(message) = err else {
            panic!("expected an unsupported-algorithm error, got {err:?}");
        };
        assert!(message.contains("RSA-PKCS1-SHA256"), "{message}");
        assert!(message.contains("ECDSA-P256"), "{message}");
    }

    #[test]
    fn test_backend_fingerprint() {
        let backend = OpenSslBackend::try_new("my-backend").unwrap();
        assert_eq!(backend.name(), "my-backend");
        assert_eq!(backend.provider(), "openssl");
        assert!(
            backend
                .fingerprint()
                .starts_with("openssl-backend=my-backend+openssl="),
            "fingerprint should include backend name and OpenSSL version: {}",
            backend.fingerprint()
        );
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

        // Attempt to unwrap with key_b (wrong key); must fail.
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

    // EC key-transport round-trip tests.
    //
    // All three combinations of (content key type, KEK type) are exercised:
    //   RSA content + EC KEK  → RFC 5753 ECDH encapsulation
    //   EC content  + RSA KEK → RSAES-PKCS1-v1.5 encapsulation, SEC1 payload
    //   EC content  + EC KEK  → RFC 5753 ECDH encapsulation, SEC1 payload

    #[test]
    fn test_wrap_rsa_content_with_ec_kek() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        // EC P-256 KEK → OpenSSL uses RFC 5753 ECDH key encapsulation.
        let kek = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "rsa-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend.unwrap(&wrapped, &kek.key_id, "unwrapped").unwrap();

        assert_eq!(unwrapped.algorithm, KeyAlgorithm::Rsa2048);
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_ec_content_with_rsa_kek() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        // RSA KEK → RSAES-PKCS1-v1.5 encapsulation; the payload is an EC private key
        // serialised in SEC1 (traditional EC DER), recovered via the EcKey fallback parser.
        let kek = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "rsa-kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend.unwrap(&wrapped, &kek.key_id, "unwrapped").unwrap();

        assert_eq!(unwrapped.algorithm, KeyAlgorithm::EcdsaP256);
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_ec_content_with_ec_kek() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        // Both keys are EC P-256: RFC 5753 ECDH encapsulation wraps an SEC1 payload.
        let kek = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend.unwrap(&wrapped, &kek.key_id, "unwrapped").unwrap();

        assert_eq!(unwrapped.algorithm, KeyAlgorithm::EcdsaP256);
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_ec_content_to_ec_public_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        // wrap_to_public with an EC recipient: the throwaway cert carries the EC public key
        // as its subject, triggering RFC 5753 ECDH encapsulation in CMS.
        let recipient = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-recipient"))
            .unwrap();
        let recipient_pub = backend.export_public_key(&recipient.key_id).unwrap();

        let target = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap_to_public(&target.key_id, &recipient_pub, WrapAlgorithm::CmsRsaCbc)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &recipient.key_id, "unwrapped")
            .unwrap();

        assert_eq!(unwrapped.algorithm, KeyAlgorithm::EcdsaP256);
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

    /// Every ML-DSA parameter set, with the FIPS 204 sizes each one fixes.
    #[cfg(ossl350)]
    const ML_DSA_PARAMS: [(KeyAlgorithm, SignAlgorithm, usize, usize); 3] = [
        (KeyAlgorithm::MlDsa44, SignAlgorithm::MlDsa44, 1312, 2420),
        (KeyAlgorithm::MlDsa65, SignAlgorithm::MlDsa65, 1952, 3309),
        (KeyAlgorithm::MlDsa87, SignAlgorithm::MlDsa87, 2592, 4627),
    ];

    /// Known-answer test for seed-derived key generation.
    ///
    /// FIPS 204 expands the keypair deterministically from the 32-byte seed, so
    /// a fixed seed pins an exact public key. The expected digests are an
    /// independent cross-check produced with the OpenSSL CLI
    /// (`openssl genpkey -algorithm ML-DSA-NN -pkeyopt hexseed:...`), which
    /// exercises the provider through a different entry point than the
    /// `EVP_PKEY_fromdata` path the backend uses.
    #[test]
    #[cfg(ossl350)]
    fn ml_dsa_seed_derivation_matches_known_answer() {
        use openssl::hash::{MessageDigest, hash};

        let seed: [u8; ML_DSA_SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected = [
            (
                KeyAlgorithm::MlDsa44,
                "837832708c5236d951581f1fddf2b79991b3424a0486d16da1ddad0fd69701be",
            ),
            (
                KeyAlgorithm::MlDsa65,
                "b8b62131bfbe84433efb2273d7f5b87f7a22854a2cfd366fc2aead86d837c52d",
            ),
            (
                KeyAlgorithm::MlDsa87,
                "07e57c4f14dbad1267f621ec3777b4e2e6c4fbc4c22fbb87510ff8e0b3c6a642",
            ),
        ];

        // Zipped against the production table so a reordering there is caught
        // rather than silently pairing a digest with the wrong parameter set.
        for ((algorithm, key_type), (expected_algorithm, expected_digest)) in
            ML_DSA_KEY_TYPES.into_iter().zip(expected)
        {
            assert_eq!(algorithm, expected_algorithm);
            let pkey = PKey::private_key_from_seed(None, key_type, None, &seed).unwrap();
            let spki = pkey.public_key_to_der().unwrap();
            let digest = hash(MessageDigest::sha256(), &spki).unwrap();
            assert_eq!(
                base16ct::lower::encode_string(&digest),
                expected_digest,
                "{algorithm} public key does not match the known answer for this seed"
            );
        }
    }

    #[test]
    #[cfg(ossl350)]
    fn ml_dsa_generate_sign_and_verify_roundtrip() {
        for (key_algorithm, sign_algorithm, public_len, signature_len) in ML_DSA_PARAMS {
            let mut backend = OpenSslBackend::try_new("test").unwrap();
            let metadata = backend.generate_key(spec(key_algorithm, "pq-key")).unwrap();

            assert_eq!(metadata.algorithm, key_algorithm);
            let public_key = metadata.public_key.as_ref().unwrap();
            // SPKI wraps the raw public key in an AlgorithmIdentifier header,
            // so the encoding is a little longer than the FIPS 204 figure.
            assert!(
                public_key.len() > public_len,
                "{key_algorithm} SPKI ({}) should exceed the raw public key ({public_len})",
                public_key.len()
            );

            let message = b"ceremony transcript digest";
            let signature = backend
                .sign(&metadata.key_id, message, sign_algorithm)
                .unwrap();
            assert_eq!(signature.len(), signature_len, "{key_algorithm}");

            assert!(
                backend
                    .verify(&metadata.key_id, message, &signature, sign_algorithm)
                    .unwrap(),
                "{key_algorithm} signature should verify"
            );
            assert!(
                !backend
                    .verify(&metadata.key_id, b"tampered", &signature, sign_algorithm)
                    .unwrap(),
                "{key_algorithm} signature should not verify against a different message"
            );
        }
    }

    /// ML-DSA signing is hedged by default: it mixes fresh randomness into every
    /// signature, so the same key over the same message yields different bytes.
    /// Ceremony assertions must therefore verify signatures, never compare them.
    #[test]
    #[cfg(ossl350)]
    fn ml_dsa_signing_is_hedged() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::MlDsa65, "pq-key"))
            .unwrap();

        let message = b"same message";
        let first = backend
            .sign(&metadata.key_id, message, SignAlgorithm::MlDsa65)
            .unwrap();
        let second = backend
            .sign(&metadata.key_id, message, SignAlgorithm::MlDsa65)
            .unwrap();

        assert_ne!(first, second);
        assert!(
            backend
                .verify(&metadata.key_id, message, &first, SignAlgorithm::MlDsa65)
                .unwrap()
        );
        assert!(
            backend
                .verify(&metadata.key_id, message, &second, SignAlgorithm::MlDsa65)
                .unwrap()
        );
    }

    /// Each parameter set is its own signature scheme, so a request naming a
    /// different one is rejected rather than silently signing.
    #[test]
    #[cfg(ossl350)]
    fn ml_dsa_rejects_mismatched_parameter_set() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::MlDsa65, "pq-key"))
            .unwrap();

        let result = backend.sign(&metadata.key_id, b"data", SignAlgorithm::MlDsa87);
        assert!(matches!(result, Err(BackendError::UnsupportedAlgorithm(_))));
    }

    /// Two independently generated keys must differ, confirming the seed is
    /// drawn fresh per key rather than fixed.
    #[test]
    #[cfg(ossl350)]
    fn ml_dsa_generation_uses_a_fresh_seed() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let first = backend
            .generate_key(spec(KeyAlgorithm::MlDsa65, "key-a"))
            .unwrap();
        let second = backend
            .generate_key(spec(KeyAlgorithm::MlDsa65, "key-b"))
            .unwrap();

        assert_ne!(first.public_key, second.public_key);
    }
}
