//! OpenSSL backend implementation.
//!
//! Uses the `openssl` crate for all cryptographic operations. Keys are stored
//! as OpenSSL `PKey<Private>` objects; OpenSSL manages that key memory and
//! frees it on drop. Key material serialized *out* of OpenSSL (DER buffers
//! for wrapping/unwrapping) lives in ordinary Rust allocations and is wiped
//! explicitly with `Zeroizing` before release.

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::cipher::Cipher as WrapCipher;
use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
use openssl::cms::CmsContentInfo;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};
use openssl::symm::Cipher;
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};
use rite_sdk::{
    Backend, BackendError, KeyAlgorithm, KeyId, KeyMetadata, KeyPolicy, KeySpec, KeyStoreBackend,
    KeyTransportBackend, KeyUsages, PublicKeyDer, RandomBackend, SignAlgorithm, SignBackend,
    VerifyBackend, WrapScheme, WrappedKey,
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
    /// Cached public key for export.
    public_der: PublicKeyDer,
    /// What this key was generated to be allowed to do.
    ///
    /// A software backend has no token to enforce this for it, so the checks
    /// live in the operations below. Storing the policy is what makes them
    /// possible at all: without it, a declared policy would be a comment.
    policy: KeyPolicy,
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
        policy: KeyPolicy,
    ) -> Result<KeyMetadata, BackendError> {
        let public_der = PublicKeyDer::new(
            pkey.public_key_to_der()
                .map_err(|e| ossl_err("Public key DER encoding", &e))?,
        )?;
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
                policy,
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
        /// Verifies signatures for every algorithm this build can sign with.
        as_verify_mut: VerifyBackend,
        /// Wraps and unwraps under CMS-AES-256-GCM, to an RSA or EC recipient.
        /// Both paths export the target key to DER in process memory before
        /// encrypting it, so they suit software keys rather than keys held
        /// inside a hardware boundary.
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
            for (algorithm, key_type) in ML_DSA_KEY_TYPES.iter().chain(ML_KEM_KEY_TYPES.iter()) {
                if pkey.is_a(*key_type) {
                    return Ok(*algorithm);
                }
            }

            Err(BackendError::UnsupportedAlgorithm(
                "Key is not RSA, a supported EC curve, Ed25519, ML-DSA, or ML-KEM".to_string(),
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

/// Seed length shared by every ML-KEM parameter set.
///
/// FIPS 203 derives the keypair from `d || z`, 32 bytes each.
#[cfg(ossl350)]
const ML_KEM_SEED_LEN: usize = 64;

/// The ML-KEM parameter sets, paired with their OpenSSL provider key types.
#[cfg(ossl350)]
const ML_KEM_KEY_TYPES: [(KeyAlgorithm, openssl::pkey::KeyType); 3] = [
    (KeyAlgorithm::MlKem512, openssl::pkey::KeyType::ML_KEM_512),
    (KeyAlgorithm::MlKem768, openssl::pkey::KeyType::ML_KEM_768),
    (KeyAlgorithm::MlKem1024, openssl::pkey::KeyType::ML_KEM_1024),
];

/// Generate an ML-KEM keypair.
///
/// Same route as ML-DSA: the provider expands a seed drawn here from the
/// OpenSSL CSPRNG, which is then wiped.
#[cfg(ossl350)]
fn generate_ml_kem(algorithm: KeyAlgorithm) -> Result<PKey<Private>, BackendError> {
    let key_type = ML_KEM_KEY_TYPES
        .iter()
        .find(|(candidate, _)| *candidate == algorithm)
        .map(|(_, key_type)| *key_type)
        .ok_or_else(|| {
            BackendError::UnsupportedAlgorithm(format!(
                "{algorithm} is not an ML-KEM parameter set"
            ))
        })?;
    let mut seed = Zeroizing::new(vec![0u8; ML_KEM_SEED_LEN]);
    openssl::rand::rand_bytes(&mut seed).map_err(|e| ossl_err("ML-KEM seed generation", &e))?;
    PKey::private_key_from_seed(None, key_type, None, &seed)
        .map_err(|e| ossl_err("ML-KEM key generation", &e))
}

#[cfg(not(ossl350))]
fn generate_ml_kem(algorithm: KeyAlgorithm) -> Result<PKey<Private>, BackendError> {
    Err(BackendError::UnsupportedAlgorithm(format!(
        "{algorithm} needs a build linked against OpenSSL 3.5 or later"
    )))
}

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
/// PKCS#1 v1.5 is set explicitly rather than left to OpenSSL's default. The
/// wildcard arm is safe because `digest_for` runs first and refuses any
/// algorithm it does not name.
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
///
/// An algorithm this function does not name is refused rather than given a
/// default digest, which would sign over the wrong message and still produce a
/// signature that looks valid. `SignAlgorithm` is `#[non_exhaustive]`, so no
/// compiler error marks this function when a variant is added.
///
/// # Errors
///
/// Returns [`BackendError::UnsupportedAlgorithm`] for an algorithm this
/// function does not name.
fn digest_for(algorithm: SignAlgorithm) -> Result<Option<MessageDigest>, BackendError> {
    match algorithm {
        SignAlgorithm::RsaPkcs1Sha256
        | SignAlgorithm::RsaPssSha256
        | SignAlgorithm::EcdsaSha256 => Ok(Some(MessageDigest::sha256())),
        SignAlgorithm::EcdsaSha384 => Ok(Some(MessageDigest::sha384())),
        SignAlgorithm::Ed25519
        | SignAlgorithm::MlDsa44
        | SignAlgorithm::MlDsa65
        | SignAlgorithm::MlDsa87 => Ok(None),
        _ => Err(BackendError::UnsupportedAlgorithm(format!(
            "{algorithm} has no digest mapping in the OpenSSL backend"
        ))),
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

    let mut signer = match digest_for(algorithm)? {
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

    let mut verifier = match digest_for(algorithm)? {
        Some(digest) => Verifier::new(digest, pkey),
        None => Verifier::new_without_digest(pkey),
    }
    .map_err(|e| ossl_err("Create verifier", &e))?;
    apply_rsa_padding(&mut verifier, algorithm)?;
    verifier
        .verify_oneshot(signature, message)
        .map_err(|e| ossl_err("Verify operation", &e))
}

/// Verify a signature against an SPKI DER public key, without a backend.
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
            KeyAlgorithm::MlKem512 | KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => {
                generate_ml_kem(spec.algorithm)?
            }
            other => {
                return Err(BackendError::UnsupportedAlgorithm(format!(
                    "Algorithm {other} not yet implemented for OpenSslBackend"
                )));
            }
        };
        self.store_key(spec.algorithm, spec.label, pkey, spec.policy)
    }

    fn import_private_key(
        &mut self,
        spec: KeySpec,
        key_bytes: &[u8],
    ) -> Result<KeyMetadata, BackendError> {
        let pkey = parse_private_key_der(key_bytes)?;
        self.store_key(spec.algorithm, spec.label, pkey, spec.policy)
    }

    fn export_public_key(&self, key_id: &KeyId) -> Result<PublicKeyDer, BackendError> {
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
        key.policy.require(KeyUsages::SIGN, "sign")?;
        check_key_accepted("Sign", algorithm, key.algorithm)?;
        sign_with_key(&key.pkey, message, algorithm)
    }
}

impl VerifyBackend for OpenSslBackend {
    fn verify_public_key(
        &mut self,
        key: &PublicKeyDer,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> Result<bool, BackendError> {
        verify_signature(key.as_bytes(), message, signature, algorithm)
    }
}

impl RandomBackend for OpenSslBackend {
    fn generate_random(&mut self, len: usize) -> Result<Vec<u8>, BackendError> {
        let mut buf = vec![0u8; len];
        openssl::rand::rand_bytes(&mut buf).map_err(|e| ossl_err("Generate random bytes", &e))?;
        Ok(buf)
    }
}

/// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
const SUBJECT_KEY_IDENTIFIER_OID: &str = "2.5.29.14";

/// Refuse to hand out private key material the policy keeps inside.
///
/// Both wrap paths export the target key to DER before encrypting it, so a key
/// generated as non-extractable cannot be wrapped by this backend at all.
/// `extractable: false` is the default, so a ceremony that wraps a key it
/// generated has to say otherwise.
fn permits_export(key: &StoredKey) -> Result<(), BackendError> {
    if key.policy.extractable {
        return Ok(());
    }
    Err(BackendError::OperationNotPermitted(format!(
        "key '{}' was generated as non-extractable, so it cannot be wrapped. \
         Add `policy: {{ extractable: true }}` to the step that generates it, \
         or leave the key where it is.",
        key.label
    )))
}

/// Create a CMS recipient certificate carrying a public key.
///
/// OpenSSL's CMS encrypt API requires an X.509 certificate rather than a bare
/// public key, and reads only the subject public key from it. The certificate
/// is never stored, and its signature is never validated.
///
/// The signature therefore comes from a throwaway key, never from the
/// recipient's own. Signing with the recipient key would silently require it
/// to be a signing key, which excludes every KEM. An ML-KEM key encapsulates
/// and cannot sign at all.
fn cert_for_public_key(
    recipient_public_key: &PKeyRef<impl openssl::pkey::HasPublic>,
) -> Result<openssl::x509::X509, BackendError> {
    // Refuse a key that cannot receive a wrap here, where the key type is
    // known and the message can name the problem. Left to OpenSSL, an Ed25519
    // recipient fails as "operation not supported for this keytype", and an
    // X25519 one encrypts and only fails later while serialising the result.
    let algorithm = key_algorithm_of(recipient_public_key)?;
    if !algorithm.can_receive_wrap() {
        return Err(BackendError::UnsupportedAlgorithm(format!(
            "{algorithm} cannot receive a wrap: it signs but does not encapsulate. \
             Wrap to an RSA, EC or ML-KEM key instead."
        )));
    }

    let signing_key = throwaway_signer()?;
    build_cert(&signing_key, recipient_public_key)
}

/// A signing key for a certificate nobody verifies.
///
/// P-256 rather than RSA because the signature is never checked and the key is
/// discarded with the certificate: the only property that matters is that
/// producing it is cheap, and RSA-2048 generation is some two hundred times
/// slower.
fn throwaway_signer() -> Result<PKey<Private>, BackendError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| ossl_err("Load P-256 group", &e))?;
    let key = EcKey::generate(&group).map_err(|e| ossl_err("Generate throwaway signer", &e))?;
    PKey::from_ec_key(key).map_err(|e| ossl_err("Wrap throwaway signer", &e))
}

/// The SHA-256 digest of a public key's SPKI DER.
///
/// Used as the certificate's subject key identifier, which CMS then carries as
/// the recipient identifier. It is the same digest `compute_fingerprint`
/// records for a public key, so a transcript's recipient fingerprint and a
/// blob's `rid` are the same value and can be compared.
fn spki_digest(
    subject_pub: &PKeyRef<impl openssl::pkey::HasPublic>,
) -> Result<Vec<u8>, BackendError> {
    let spki = subject_pub
        .public_key_to_der()
        .map_err(|e| ossl_err("Export subject public key", &e))?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &spki)
        .map_err(|e| ossl_err("Digest subject public key", &e))?;
    Ok(digest.to_vec())
}

/// Build an X.509 cert with the given subject public key, signed by the given signing key.
///
/// The cert carries a subject key identifier derived from that public key.
/// CMS uses it to name the recipient, so a blob identifies the key it was
/// wrapped to and unwrapping under the wrong key fails as a missing recipient
/// rather than as a cipher error.
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

    // extnValue for subjectKeyIdentifier is a DER OCTET STRING wrapping the
    // identifier, so the digest is prefixed with its own tag and length.
    let key_identifier = spki_digest(subject_pub)?;
    let length = u8::try_from(key_identifier.len())
        .map_err(|_| BackendError::Other("subject key identifier is too long".to_string()))?;
    let mut extn_value = vec![0x04, length];
    extn_value.extend_from_slice(&key_identifier);
    let extn_value = Asn1OctetString::new_from_bytes(&extn_value)
        .map_err(|e| ossl_err("Encode subject key identifier", &e))?;
    let ski_oid = Asn1Object::from_str(SUBJECT_KEY_IDENTIFIER_OID)
        .map_err(|e| ossl_err("Look up subjectKeyIdentifier OID", &e))?;
    let ski = X509Extension::new_from_der(&ski_oid, false, &extn_value)
        .map_err(|e| ossl_err("Build subject key identifier extension", &e))?;
    builder
        .append_extension(ski)
        .map_err(|e| ossl_err("X509 add subject key identifier", &e))?;

    builder
        .sign(signing_key, MessageDigest::sha256())
        .map_err(|e| ossl_err("X509 sign", &e))?;

    Ok(builder.build())
}

/// CMS-encrypt `key_material` to a recipient certificate, and read back what
/// the encryption did.
///
/// Shared by `wrap` (recipient cert built from the KEK) and `wrap_to_public`
/// (recipient cert built from an external public key); both come from
/// [`cert_for_public_key`]. `CMS_encrypt` selects the key-encapsulation path
/// from the recipient certificate's public key type, so the scheme does not
/// determine it: the same scheme takes the key-agreement path below for an EC
/// recipient.
///
/// The content cipher is AES-256-GCM, which produces `AuthEnvelopedData`
/// (RFC 5083). `CMS_USE_KEYID` names the recipient by the certificate's
/// subject key identifier rather than by issuer and serial.
///
/// **RSA recipient, `KeyTransRecipientInfo` (RFC 5652 §6.2)**
/// The content-encryption key (CEK) is encrypted directly under the recipient's RSA public
/// key using RSAES-PKCS1-v1.5. OAEP requires setting a padding mode on the recipient's
/// `EVP_PKEY_CTX`, which needs the `CMS_KEY_PARAM` partial-envelope path that rust-openssl
/// does not expose.
///
/// **EC recipient, `KeyAgreeRecipientInfo` (RFC 5753 §3.1)**
/// OpenSSL generates an ephemeral key on the recipient's curve, performs one-pass ECDH
/// against the recipient's static public key, and feeds the shared secret into the ANSI
/// X9.63 KDF to derive a key-encryption key that wraps the CEK with AES Key Wrap
/// (RFC 3394). The KDF digest is SHA-1, `dhSinglePass-stdDH-sha1kdf-scheme`
/// (OID 1.3.133.16.840.63.0.2): OpenSSL falls back to SHA-1 when no digest is set, and
/// setting one needs the same `CMS_KEY_PARAM` path. The KEK size follows the content
/// cipher, so AES-256-GCM gives `id-aes256-wrap`.
fn cms_encrypt(cert: openssl::x509::X509, key_material: &[u8]) -> Result<WrappedKey, BackendError> {
    let mut certs = openssl::stack::Stack::new().map_err(|e| ossl_err("Create cert stack", &e))?;
    certs
        .push(cert)
        .map_err(|e| ossl_err("Push cert to stack", &e))?;

    let cms = CmsContentInfo::encrypt(
        &certs,
        key_material,
        Cipher::aes_256_gcm(),
        openssl::cms::CMSOptions::BINARY | openssl::cms::CMSOptions::USE_KEYID,
    )
    .map_err(|e| ossl_err("CMS encrypt", &e))?;

    let data = cms.to_der().map_err(|e| ossl_err("CMS to DER", &e))?;
    let facts =
        rite_sdk::cms::describe(&data).map_err(|e| BackendError::InvalidData(e.to_string()))?;
    WrappedKey::new(WrapScheme::CmsAes256Gcm, facts.description, data)
        .map_err(|e| BackendError::InvalidData(e.to_string()))
}

/// The target key in the encoding a recipient expects.
///
/// PKCS#8 `PrivateKeyInfo` rather than the algorithm-native form: PKCS#11
/// names it the recommended encoding for a wrapped private key, cloud KMS
/// import rejects PKCS#1, and one encoding means an unwrapping implementation
/// needs no per-algorithm branch.
///
/// Zeroizing: this buffer holds the plaintext private key; wipe it on drop
/// rather than leaving it in freed heap memory.
fn wrappable_key_material(target: &StoredKey) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    Ok(Zeroizing::new(target.pkey.private_key_to_pkcs8().map_err(
        |e| ossl_err("Export key material for wrapping", &e),
    )?))
}

/// RSAES-OAEP with SHA-256 over `payload`, as raw ciphertext.
///
/// The output is exactly the modulus size. The payload ceiling is
/// `k - 2*hLen - 2`, and an over-size payload is refused by OpenSSL rather
/// than truncated; the message here names the ceiling and the way past it,
/// because the alternative is an operator reading "data too large for key
/// size" in the middle of a ceremony.
fn rsa_oaep_encrypt(
    recipient: &PKeyRef<impl openssl::pkey::HasPublic>,
    payload: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let capacity = oaep_capacity(recipient)?;
    if payload.len() > capacity {
        return Err(BackendError::InvalidData(format!(
            "this key is {} bytes and RSA-OAEP under this recipient carries at most \
             {capacity}. Wrap it with {} instead, which has no such ceiling.",
            payload.len(),
            WrapScheme::RsaAesKeyWrapSha256
        )));
    }
    let mut ctx = PkeyCtx::new(recipient).map_err(|e| ossl_err("RSA-OAEP context", &e))?;
    ctx.encrypt_init()
        .map_err(|e| ossl_err("RSA-OAEP encrypt init", &e))?;
    configure_oaep(&mut ctx)?;
    let mut out = Vec::new();
    ctx.encrypt_to_vec(payload, &mut out)
        .map_err(|e| ossl_err("RSA-OAEP encrypt", &e))?;
    Ok(out)
}

/// Undo [`rsa_oaep_encrypt`].
fn rsa_oaep_decrypt(
    recipient: &PKeyRef<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let mut ctx = PkeyCtx::new(recipient).map_err(|e| ossl_err("RSA-OAEP context", &e))?;
    ctx.decrypt_init()
        .map_err(|e| ossl_err("RSA-OAEP decrypt init", &e))?;
    configure_oaep(&mut ctx)?;
    let mut out = Zeroizing::new(Vec::new());
    ctx.decrypt_to_vec(ciphertext, &mut out)
        .map_err(|e| ossl_err("RSA-OAEP decrypt", &e))?;
    Ok(out)
}

/// SHA-256 for both the OAEP digest and MGF1.
///
/// Set on every OAEP context, encrypt and decrypt alike. The digest is not
/// recoverable from the ciphertext, so the two sides have to agree out of
/// band, and the scheme name is where that agreement is written down.
fn configure_oaep<T>(ctx: &mut PkeyCtx<T>) -> Result<(), BackendError> {
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)
        .map_err(|e| ossl_err("Set OAEP padding", &e))?;
    ctx.set_rsa_oaep_md(Md::sha256())
        .map_err(|e| ossl_err("Set OAEP digest", &e))?;
    ctx.set_rsa_mgf1_md(Md::sha256())
        .map_err(|e| ossl_err("Set OAEP MGF1 digest", &e))
}

/// The largest payload RSAES-OAEP with SHA-256 carries under this key.
///
/// RFC 8017 §7.1.1: `k - 2*hLen - 2`, so 190 bytes under RSA-2048 and 446
/// under RSA-4096.
fn oaep_capacity(key: &PKeyRef<impl openssl::pkey::HasPublic>) -> Result<usize, BackendError> {
    const SHA256_LEN: usize = 32;
    let modulus_bytes = key.size();
    modulus_bytes
        .checked_sub(2 * SHA256_LEN + 2)
        .ok_or_else(|| {
            BackendError::UnsupportedAlgorithm(format!(
                "a {modulus_bytes}-byte key is too small to carry an RSA-OAEP payload"
            ))
        })
}

/// AES Key Wrap with Padding (RFC 5649), under a KEK of any AES size.
///
/// `FLAG_WRAP_ALLOW` is set because OpenSSL's legacy path refuses a wrap
/// cipher without it. The provider path in 3.x does not need it, and setting
/// it changes nothing there.
fn aes_kwp(kek: &[u8], input: &[u8], encrypting: bool) -> Result<Vec<u8>, BackendError> {
    let mut ctx = CipherCtx::new().map_err(|e| ossl_err("AES-KWP context", &e))?;
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    let cipher = match kek.len() {
        16 => WrapCipher::aes_128_wrap_pad(),
        24 => WrapCipher::aes_192_wrap_pad(),
        32 => WrapCipher::aes_256_wrap_pad(),
        other => {
            return Err(BackendError::InvalidData(format!(
                "an AES key wrap needs a 16, 24 or 32 byte KEK, not {other}"
            )));
        }
    };
    if encrypting {
        ctx.encrypt_init(Some(cipher), Some(kek), None)
            .map_err(|e| ossl_err("AES-KWP wrap init", &e))?;
    } else {
        ctx.decrypt_init(Some(cipher), Some(kek), None)
            .map_err(|e| ossl_err("AES-KWP unwrap init", &e))?;
    }
    let mut out = Vec::new();
    ctx.cipher_update_vec(input, &mut out)
        .map_err(|e| ossl_err("AES-KWP update", &e))?;
    ctx.cipher_final_vec(&mut out)
        .map_err(|e| ossl_err("AES-KWP final", &e))?;
    Ok(out)
}

/// Wrap `payload` under `recipient` with the scheme's raw mechanism.
///
/// Unlike the CMS path, nothing here reads its own output back: raw mechanism
/// bytes carry no algorithm identifiers, so the description is what was
/// invoked. [`WrapScheme::is_self_describing`] is what tells a verifier that.
fn raw_wrap(
    recipient: &PKeyRef<impl openssl::pkey::HasPublic>,
    payload: &[u8],
    scheme: WrapScheme,
) -> Result<WrappedKey, BackendError> {
    let algorithm = key_algorithm_of(recipient)?;
    if !scheme.accepts_recipient(algorithm) {
        return Err(BackendError::UnsupportedAlgorithm(format!(
            "{scheme} needs an RSA recipient, and this one is {algorithm}"
        )));
    }
    let description = scheme.fixed_description().ok_or_else(|| {
        BackendError::UnsupportedAlgorithm(format!(
            "{scheme} is not a raw mechanism this backend produces"
        ))
    })?;

    let data = if scheme == WrapScheme::RsaOaepSha256 {
        rsa_oaep_encrypt(recipient, payload)?
    } else {
        // PKCS#11 §2.1.21: an ephemeral AES key under OAEP, then the
        // payload under AES-KWP, concatenated with the OAEP part first.
        // A recipient splits them by the modulus size, so no framing is
        // written and none may be.
        let mut ephemeral = Zeroizing::new(vec![0u8; 32]);
        openssl::rand::rand_bytes(&mut ephemeral)
            .map_err(|e| ossl_err("Generate ephemeral AES key", &e))?;
        let mut data = rsa_oaep_encrypt(recipient, &ephemeral)?;
        data.extend_from_slice(&aes_kwp(&ephemeral, payload, true)?);
        data
    };

    WrappedKey::new(scheme, description, data).map_err(|e| BackendError::InvalidData(e.to_string()))
}

/// Wrap `material` to `recipient` under `scheme`.
///
/// Matched on the scheme rather than branching on
/// [`WrapScheme::is_self_describing`]: a scheme this backend gains has to be
/// given a path here, and the compiler is what asks.
fn wrap_under(
    recipient: &PKeyRef<impl openssl::pkey::HasPublic>,
    material: &[u8],
    scheme: WrapScheme,
) -> Result<WrappedKey, BackendError> {
    match scheme {
        WrapScheme::CmsAes256Gcm => cms_encrypt(cert_for_public_key(recipient)?, material),
        WrapScheme::RsaOaepSha256 | WrapScheme::RsaAesKeyWrapSha256 => {
            raw_wrap(recipient, material, scheme)
        }
        other => Err(BackendError::UnsupportedAlgorithm(format!(
            "this backend does not wrap with {other}"
        ))),
    }
}

/// Undo [`raw_wrap`].
fn raw_unwrap(
    recipient: &PKeyRef<Private>,
    wrapped: &WrappedKey,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    match wrapped.scheme() {
        WrapScheme::RsaOaepSha256 => rsa_oaep_decrypt(recipient, wrapped.data()),
        WrapScheme::RsaAesKeyWrapSha256 => {
            let modulus_bytes = recipient.size();
            let (encapsulated, wrapped_payload) = wrapped
                .data()
                .split_at_checked(modulus_bytes)
                .ok_or_else(|| {
                    BackendError::InvalidData(format!(
                        "a {} key wrap is shorter than the {modulus_bytes}-byte \
                         encapsulation it should start with",
                        wrapped.scheme()
                    ))
                })?;
            let ephemeral = rsa_oaep_decrypt(recipient, encapsulated)?;
            Ok(Zeroizing::new(aes_kwp(&ephemeral, wrapped_payload, false)?))
        }
        other => Err(BackendError::UnsupportedAlgorithm(format!(
            "{other} is not a raw mechanism this backend unwraps"
        ))),
    }
}

impl KeyTransportBackend for OpenSslBackend {
    fn wrap(
        &mut self,
        key_id: &KeyId,
        wrapping_key_id: &KeyId,
        scheme: WrapScheme,
    ) -> Result<WrappedKey, BackendError> {
        let kek = self.get_key(wrapping_key_id)?;
        let target = self.get_key(key_id)?;
        kek.policy.require(KeyUsages::WRAP, "wrap another key")?;
        permits_export(target)?;

        let key_material = wrappable_key_material(target)?;

        // Under CMS the certificate carrying the KEK's public half is what
        // lets OpenSSL select the encapsulation from the key type: RSA takes
        // RSAES-PKCS1-v1.5, EC P-256 takes RFC 5753 ECDH, ML-KEM takes RFC
        // 9629 KEMRecipientInfo.
        wrap_under(&kek.pkey, &key_material, scheme)
    }

    fn unwrap(
        &mut self,
        wrapped: &WrappedKey,
        unwrapping_key_id: &KeyId,
        label: &str,
        policy: KeyPolicy,
    ) -> Result<KeyMetadata, BackendError> {
        // Scope the immutable borrow of `kek` so it ends before `store_key` needs `&mut self`.
        // Zeroizing: the decrypted output is the plaintext private key in DER
        // form; wipe it on drop rather than leaving it in freed heap memory.
        let key_material = {
            let kek = self.get_key(unwrapping_key_id)?;
            kek.policy.require(KeyUsages::UNWRAP, "unwrap a key")?;
            match wrapped.scheme() {
                WrapScheme::CmsAes256Gcm => {
                    // Re-create the ephemeral cert from the same key; CMS
                    // decrypt needs it to find the matching recipient, which it
                    // does by the subject key identifier rather than by any
                    // signature.
                    let cert = cert_for_public_key(&kek.pkey)?;
                    let cms = CmsContentInfo::from_der(wrapped.data())
                        .map_err(|e| ossl_err("Parse CMS DER", &e))?;
                    Zeroizing::new(
                        cms.decrypt(&kek.pkey, &cert)
                            .map_err(|e| ossl_err("CMS decrypt", &e))?,
                    )
                }
                _ => raw_unwrap(&kek.pkey, wrapped)?,
            }
        };

        let pkey = parse_private_key_der(&key_material)?;

        let key_algorithm = key_algorithm_of(&pkey)?;
        self.store_key(key_algorithm, label.to_string(), pkey, policy)
    }

    fn wrap_to_public(
        &mut self,
        key_id: &KeyId,
        recipient_pub_key: &PublicKeyDer,
        scheme: WrapScheme,
    ) -> Result<WrappedKey, BackendError> {
        let target = self.get_key(key_id)?;
        permits_export(target)?;

        let recipient_pub = PKey::public_key_from_der(recipient_pub_key.as_bytes())
            .map_err(|e| ossl_err("Parse recipient public key", &e))?;
        let key_material = wrappable_key_material(target)?;

        wrap_under(&recipient_pub, &key_material, scheme)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rite_sdk::{KeyPolicy, KeySpec, RecipientInfoKind};

    fn spec(algorithm: KeyAlgorithm, label: &str) -> KeySpec {
        KeySpec {
            algorithm,
            label: label.to_string(),
            policy: KeyPolicy::default(),
            location_hint: None,
        }
    }

    /// The policy the `unwrap_key` action hands a recovered key when the
    /// ceremony declares none.
    fn restored() -> KeyPolicy {
        KeyPolicy {
            extractable: true,
            ..KeyPolicy::default()
        }
    }

    /// A key a ceremony intends to wrap, so it has to be allowed to leave.
    fn extractable(algorithm: KeyAlgorithm, label: &str) -> KeySpec {
        KeySpec {
            policy: KeyPolicy {
                extractable: true,
                ..KeyPolicy::default()
            },
            ..spec(algorithm, label)
        }
    }

    /// A key-encryption key, which wraps and unwraps rather than signs.
    fn kek(algorithm: KeyAlgorithm, label: &str) -> KeySpec {
        KeySpec {
            policy: KeyPolicy {
                usages: KeyUsages::WRAP | KeyUsages::UNWRAP,
                ..KeyPolicy::default()
            },
            ..spec(algorithm, label)
        }
    }

    /// Check a signature against the key's exported public half.
    ///
    /// Verification deliberately does not go back through the key object that
    /// produced the signature. Reusing it would let a bug in export or in SPKI
    /// encoding pass unnoticed, which is the pairing every consumer of these
    /// keys actually relies on.
    fn check(
        metadata: &KeyMetadata,
        message: &[u8],
        signature: &[u8],
        algorithm: SignAlgorithm,
    ) -> bool {
        let public = metadata
            .public_key
            .as_ref()
            .expect("software keys always export a public half");
        verify_signature(public.as_bytes(), message, signature, algorithm)
            .expect("verification must run")
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

    /// The `VerifyBackend` impl must agree with the free function it wraps.
    ///
    /// Everything else here checks signatures through `verify_signature`
    /// directly, so without this the trait impl the runtime dispatches to would
    /// go unexercised in this crate.
    #[test]
    fn verifies_through_the_backend_capability() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let metadata = backend
            .generate_key(spec(KeyAlgorithm::EcdsaP256, "signing-key"))
            .unwrap();
        let message = b"ceremony transcript";
        let signature = backend
            .sign(&metadata.key_id, message, SignAlgorithm::EcdsaSha256)
            .unwrap();
        let public = metadata.public_key.clone().unwrap();

        assert!(
            backend
                .verify_public_key(&public, message, &signature, SignAlgorithm::EcdsaSha256)
                .unwrap()
        );
        assert!(
            !backend
                .verify_public_key(&public, b"tampered", &signature, SignAlgorithm::EcdsaSha256)
                .unwrap()
        );
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
                check(&metadata, message, &signature, algorithm),
                "{key_algorithm} must verify its own {algorithm} signature"
            );
            assert!(
                !check(&metadata, b"tampered", &signature, algorithm),
                "{key_algorithm} must reject a {algorithm} signature over other data"
            );
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

        let err = verify_signature(
            public_der.as_bytes(),
            message,
            &signature,
            SignAlgorithm::EcdsaSha256,
        )
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

        assert!(check(
            &metadata,
            message,
            &signature,
            SignAlgorithm::RsaPkcs1Sha256
        ));
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
    fn test_wrap_unwrap_rsa_gcm() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped", restored())
            .unwrap();

        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_unwrap_detects_rsa2048() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa4096, "kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target-2048"))
            .unwrap();
        assert_eq!(target.algorithm, KeyAlgorithm::Rsa2048);

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped-2048", restored())
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
            .generate_key(kek(KeyAlgorithm::Rsa2048, "recipient"))
            .unwrap();
        let recipient_pub_der = backend.export_public_key(&recipient.key_id).unwrap();

        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap_to_public(&target.key_id, &recipient_pub_der, WrapScheme::CmsAes256Gcm)
            .unwrap();
        assert!(!wrapped.data().is_empty());

        let unwrapped = backend
            .unwrap(&wrapped, &recipient.key_id, "unwrapped", restored())
            .unwrap();
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_wrong_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let key_a = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "key-a"))
            .unwrap();
        let key_b = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "key-b"))
            .unwrap();
        let plaintext_key = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "plaintext"))
            .unwrap();

        let wrapped = backend
            .wrap(
                &plaintext_key.key_id,
                &key_a.key_id,
                WrapScheme::CmsAes256Gcm,
            )
            .unwrap();

        // Attempt to unwrap with key_b (wrong key); must fail.
        let result = backend.unwrap(&wrapped, &key_b.key_id, "unwrapped", restored());
        assert!(
            result.is_err(),
            "Expected error when unwrapping with wrong key"
        );
    }

    /// The default policy is the restrictive one, so a ceremony that means to
    /// wrap a key has to say so at the step that generates it. Before this,
    /// the policy was recorded and then ignored.
    #[test]
    fn refuses_to_wrap_a_key_generated_as_non_extractable() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "stays-put"))
            .unwrap();

        let error = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap_err();
        assert!(
            error.to_string().contains("non-extractable"),
            "unexpected error: {error}"
        );

        // And the same key cannot leave by the other path either.
        let recipient = backend.export_public_key(&kek.key_id).unwrap();
        let error = backend
            .wrap_to_public(&target.key_id, &recipient, WrapScheme::CmsAes256Gcm)
            .unwrap_err();
        assert!(error.to_string().contains("non-extractable"));
    }

    /// A signing key is not a wrapping key, and the usage set says which.
    #[test]
    fn refuses_to_wrap_under_a_key_with_no_wrap_usage() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let signing_only = backend
            .generate_key(spec(KeyAlgorithm::Rsa2048, "signing-only"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let error = backend
            .wrap(
                &target.key_id,
                &signing_only.key_id,
                WrapScheme::CmsAes256Gcm,
            )
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("may not wrap another key"), "{message}");
        assert!(
            message.contains("sign, verify"),
            "the message should say what the policy does allow: {message}"
        );
    }

    /// The same set gates signing, so a key generated to wrap cannot sign.
    #[test]
    fn refuses_to_sign_with_a_key_that_has_no_sign_usage() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let wrapping_only = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "wrapping-only"))
            .unwrap();

        let error = backend
            .sign(
                &wrapping_only.key_id,
                b"message",
                SignAlgorithm::RsaPkcs1Sha256,
            )
            .unwrap_err();
        assert!(error.to_string().contains("may not sign"), "{error}");
    }

    #[test]
    fn a_wrap_names_the_recipient_key_it_was_made_for() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();

        // The recipient identifier is the SHA-256 of the KEK's SPKI, so a
        // reader holding the public key can tell which blob is theirs.
        let facts = rite_sdk::cms::describe(wrapped.data()).unwrap();
        let kek_public = backend.export_public_key(&kek.key_id).unwrap();
        let expected = openssl::hash::hash(MessageDigest::sha256(), kek_public.as_bytes()).unwrap();
        assert_eq!(
            facts.recipient_key_identifier.as_deref(),
            Some(&expected[..])
        );
    }

    #[test]
    fn the_description_matches_the_bytes_for_both_recipient_key_types() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        // An RSA recipient takes key transport, with no KEK of its own.
        let rsa_kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "rsa-kek"))
            .unwrap();
        let wrapped = backend
            .wrap(&target.key_id, &rsa_kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let description = wrapped.description();
        assert_eq!(description.recipient_info, Some(RecipientInfoKind::Ktri));
        assert_eq!(
            description.key_encryption_oid.as_str(),
            rite_sdk::oid::RSA_ENCRYPTION
        );
        assert_eq!(description.kek_wrap_oid, None);
        assert!(description.content_is_authenticated());

        // An EC recipient takes key agreement, and the KEK wrap follows the
        // 256-bit content cipher.
        let ec_kek = backend
            .generate_key(kek(KeyAlgorithm::EcdsaP256, "ec-kek"))
            .unwrap();
        let wrapped = backend
            .wrap(&target.key_id, &ec_kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let description = wrapped.description();
        assert_eq!(description.recipient_info, Some(RecipientInfoKind::Kari));
        assert_eq!(
            description.key_encryption_oid.as_str(),
            rite_sdk::oid::DH_SINGLE_PASS_STDDH_SHA1KDF,
            "OpenSSL falls back to the SHA-1 KDF, which the record must not hide"
        );
        assert_eq!(
            description.kek_wrap_oid.as_ref().map(rite_sdk::Oid::as_str),
            Some(rite_sdk::oid::AES_256_WRAP)
        );
    }

    #[test]
    fn test_unwrap_corrupted_cms() {
        // GCM authenticates the content, so any modification to the ciphertext
        // or its tag fails decryption rather than yielding garbled key bytes
        // the backend would then import.
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();

        // Flip a byte in the middle of the CMS blob.
        let mut data = wrapped.data().to_vec();
        let mid = data.len() / 2;
        data[mid] ^= 0xff;
        let wrapped =
            WrappedKey::new(wrapped.scheme(), wrapped.description().clone(), data).unwrap();

        let result = backend.unwrap(&wrapped, &kek.key_id, "unwrapped", restored());
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
            .generate_key(kek(KeyAlgorithm::EcdsaP256, "ec-kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "rsa-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped", restored())
            .unwrap();

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
            .generate_key(kek(KeyAlgorithm::Rsa2048, "rsa-kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped", restored())
            .unwrap();

        assert_eq!(unwrapped.algorithm, KeyAlgorithm::EcdsaP256);
        let unwrapped_pub = backend.export_public_key(&unwrapped.key_id).unwrap();
        assert_eq!(original_pub, unwrapped_pub);
    }

    #[test]
    fn test_wrap_ec_content_with_ec_kek() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        // Both keys are EC P-256: RFC 5753 ECDH encapsulation wraps an SEC1 payload.
        let kek = backend
            .generate_key(kek(KeyAlgorithm::EcdsaP256, "ec-kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "unwrapped", restored())
            .unwrap();

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
            .generate_key(kek(KeyAlgorithm::EcdsaP256, "ec-recipient"))
            .unwrap();
        let recipient_pub = backend.export_public_key(&recipient.key_id).unwrap();

        let target = backend
            .generate_key(extractable(KeyAlgorithm::EcdsaP256, "ec-target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap_to_public(&target.key_id, &recipient_pub, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &recipient.key_id, "unwrapped", restored())
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
                public_key.as_bytes().len() > public_len,
                "{key_algorithm} SPKI ({}) should exceed the raw public key ({public_len})",
                public_key.as_bytes().len()
            );

            let message = b"ceremony transcript digest";
            let signature = backend
                .sign(&metadata.key_id, message, sign_algorithm)
                .unwrap();
            assert_eq!(signature.len(), signature_len, "{key_algorithm}");

            assert!(
                check(&metadata, message, &signature, sign_algorithm),
                "{key_algorithm} signature should verify"
            );
            assert!(
                !check(&metadata, b"tampered", &signature, sign_algorithm),
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
        assert!(check(&metadata, message, &first, SignAlgorithm::MlDsa65));
        assert!(check(&metadata, message, &second, SignAlgorithm::MlDsa65));
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
            .generate_key(kek(KeyAlgorithm::MlDsa65, "key-a"))
            .unwrap();
        let second = backend
            .generate_key(kek(KeyAlgorithm::MlDsa65, "key-b"))
            .unwrap();

        assert_ne!(first.public_key, second.public_key);
    }

    /// A recovered key gets the receiving ceremony's policy, not the origin's:
    /// nothing travels with a wrapped key that says what it may do. Without
    /// this, a restored key could never serve as a wrapping key again.
    #[test]
    fn a_restored_key_takes_the_policy_the_step_declares() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let transport = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "transport"))
            .unwrap();
        let backup = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "backup-kek"))
            .unwrap();
        let wrapped = backend
            .wrap(&backup.key_id, &transport.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let payload = backend
            .generate_key(extractable(KeyAlgorithm::EcdsaP256, "payload"))
            .unwrap();

        let default_policy = backend
            .unwrap(&wrapped, &transport.key_id, "restored-default", restored())
            .unwrap();
        let refused = backend
            .wrap(
                &payload.key_id,
                &default_policy.key_id,
                WrapScheme::CmsAes256Gcm,
            )
            .unwrap_err();
        assert!(
            refused.to_string().contains("may not wrap"),
            "the default policy does not grant wrapping: {refused}"
        );

        let declared = backend
            .unwrap(
                &wrapped,
                &transport.key_id,
                "restored-kek",
                KeyPolicy {
                    usages: KeyUsages::WRAP | KeyUsages::UNWRAP,
                    ..restored()
                },
            )
            .unwrap();
        backend
            .wrap(&payload.key_id, &declared.key_id, WrapScheme::CmsAes256Gcm)
            .expect("a key restored as a wrapping key wraps");
    }

    /// RFC 5649 section 6, both published vectors, byte for byte.
    ///
    /// AES-KWP is half of `RSA-AES-KEY-WRAP`, so a wrong implementation would
    /// still round-trip against itself and only fail against a recipient. A
    /// published vector is what catches that here rather than in the field.
    #[test]
    fn aes_kwp_matches_the_rfc_5649_vectors() {
        // Section 6.1: a 192-bit KEK and a 20-octet payload.
        let kek = base16ct::lower::decode_vec("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
            .unwrap();
        let payload =
            base16ct::lower::decode_vec("c37b7e6492584340bed12207808941155068f738").unwrap();
        let expected = base16ct::lower::decode_vec(
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
        )
        .unwrap();
        assert_eq!(aes_kwp(&kek, &payload, true).unwrap(), expected);
        assert_eq!(aes_kwp(&kek, &expected, false).unwrap(), payload);

        // Section 6.2: the same KEK, a 7-octet payload, so padding dominates.
        let payload = base16ct::lower::decode_vec("466f7250617369").unwrap();
        let expected = base16ct::lower::decode_vec("afbeb0f07dfbf5419200f2ccb50bb24f").unwrap();
        assert_eq!(aes_kwp(&kek, &payload, true).unwrap(), expected);
        assert_eq!(aes_kwp(&kek, &expected, false).unwrap(), payload);
    }

    /// AES-KWP rejects a tampered blob rather than returning plaintext, which
    /// is the property `WrapScheme::is_authenticated` claims for the schemes
    /// built on it.
    #[test]
    fn aes_kwp_refuses_a_tampered_blob() {
        let kek = [7u8; 32];
        let mut wrapped = aes_kwp(&kek, b"a key that matters", true).unwrap();
        wrapped[4] ^= 0x01;
        assert!(aes_kwp(&kek, &wrapped, false).is_err());
    }

    /// The ceiling is a property of the modulus, and an over-size payload has
    /// to be refused with a message an author can act on, not with OpenSSL's
    /// "data too large for key size".
    #[test]
    fn rsa_oaep_names_its_ceiling_rather_than_truncating() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        assert_eq!(oaep_capacity(&key).unwrap(), 190);

        assert!(rsa_oaep_encrypt(&key, &[0u8; 190]).is_ok());
        let error = rsa_oaep_encrypt(&key, &[0u8; 191]).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("at most 190"), "{message}");
        assert!(
            message.contains("RSA-AES-KEY-WRAP-SHA256"),
            "the message names the way past the ceiling: {message}"
        );
    }

    /// The composition PKCS#11 specifies: the OAEP part first, exactly the
    /// modulus size, then AES-KWP over the payload, with no framing between
    /// them. A recipient splits by that length, so the sizes are the contract.
    #[test]
    fn rsa_aes_key_wrap_lays_the_two_parts_out_as_the_spec_says() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "transport"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::RsaAesKeyWrapSha256)
            .unwrap();

        // RSA-2048 encapsulation, then a KWP blob that is a multiple of 8.
        assert!(wrapped.data().len() > 256);
        assert_eq!((wrapped.data().len() - 256) % 8, 0);
    }

    /// Both raw schemes round-trip, and what comes back is the key that went
    /// in rather than merely something that parses.
    #[test]
    fn the_raw_schemes_round_trip_a_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::Rsa2048, "transport"))
            .unwrap();

        for (scheme, algorithm) in [
            // P-256 is 138 bytes as PKCS#8, inside RSA-2048's 190-byte ceiling.
            (WrapScheme::RsaOaepSha256, KeyAlgorithm::EcdsaP256),
            // RSA-2048 is 1218 bytes, which only the hybrid carries.
            (WrapScheme::RsaAesKeyWrapSha256, KeyAlgorithm::Rsa2048),
        ] {
            let target = backend
                .generate_key(extractable(algorithm, "target"))
                .unwrap();
            let original = backend.export_public_key(&target.key_id).unwrap();

            let wrapped = backend.wrap(&target.key_id, &kek.key_id, scheme).unwrap();

            let restored = backend
                .unwrap(&wrapped, &kek.key_id, "restored", restored())
                .unwrap();
            assert_eq!(
                original,
                backend.export_public_key(&restored.key_id).unwrap(),
                "{scheme} did not return the key that went in"
            );
        }
    }

    /// The wrapped payload is PKCS#8, which is what PKCS#11 specifies and what
    /// every cloud KMS import expects. PKCS#1 is ~26 bytes shorter for RSA and
    /// starts straight into the modulus.
    #[test]
    fn the_wrapped_payload_is_pkcs8() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();
        let material = wrappable_key_material(backend.get_key(&target.key_id).unwrap()).unwrap();

        // PKCS#8 PrivateKeyInfo opens with version 0 then an AlgorithmIdentifier;
        // PKCS#1 RSAPrivateKey opens with version 0 then the modulus INTEGER.
        let header = base16ct::lower::encode_string(&material[..16]);
        assert!(
            header.contains("020100300d06092a864886f7"),
            "expected version 0 then a PKCS#8 AlgorithmIdentifier, found {header}"
        );
        assert!(
            openssl::pkey::PKey::private_key_from_pkcs8(&material).is_ok(),
            "the bytes parse as PKCS#8"
        );
    }

    /// A KEM key cannot sign, so it could not be its own certificate's signer.
    /// With that requirement gone, it wraps like any other recipient.
    #[test]
    #[cfg(ossl350)]
    fn wraps_and_unwraps_under_an_ml_kem_key() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::MlKem768, "kem-kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::EcdsaP256, "target"))
            .unwrap();
        let original_pub = backend.export_public_key(&target.key_id).unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let unwrapped = backend
            .unwrap(&wrapped, &kek.key_id, "restored", restored())
            .unwrap();

        assert_eq!(
            original_pub,
            backend.export_public_key(&unwrapped.key_id).unwrap()
        );
    }

    /// The record has to name the post-quantum path for what it is, and a KEM
    /// is the one encapsulation that carries its KDF in a field of its own.
    #[test]
    #[cfg(ossl350)]
    fn records_the_kem_algorithms_the_blob_carries() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let kek = backend
            .generate_key(kek(KeyAlgorithm::MlKem768, "kem-kek"))
            .unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        let wrapped = backend
            .wrap(&target.key_id, &kek.key_id, WrapScheme::CmsAes256Gcm)
            .unwrap();
        let description = wrapped.description();

        assert_eq!(description.recipient_info, Some(RecipientInfoKind::Kemri));
        assert_eq!(description.key_encryption_oid.as_str(), ML_KEM_768_OID);
        assert_eq!(
            description.kdf_oid.as_ref().map(rite_sdk::Oid::as_str),
            Some(HKDF_SHA256_OID)
        );
        assert_eq!(
            description.kek_wrap_oid.as_ref().map(rite_sdk::Oid::as_str),
            Some(rite_sdk::oid::AES_256_WRAP)
        );
        assert!(description.content_is_authenticated());

        // And the recipient is named the same way every other wrap names one.
        let facts = rite_sdk::cms::describe(wrapped.data()).unwrap();
        let kek_public = backend.export_public_key(&kek.key_id).unwrap();
        let expected = openssl::hash::hash(MessageDigest::sha256(), kek_public.as_bytes()).unwrap();
        assert_eq!(
            facts.recipient_key_identifier.as_deref(),
            Some(&expected[..])
        );
    }

    /// An Ed25519 key used to fail inside the certificate builder with a
    /// digest complaint, which said nothing about the actual problem.
    #[test]
    #[cfg(ossl350)]
    fn refuses_a_recipient_that_cannot_encapsulate() {
        let mut backend = OpenSslBackend::try_new("test").unwrap();
        let target = backend
            .generate_key(extractable(KeyAlgorithm::Rsa2048, "target"))
            .unwrap();

        // Given the WRAP usage, so the refusal that follows is about the
        // algorithm rather than about the policy.
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::MlDsa65] {
            let signer = backend.generate_key(kek(algorithm, "signer")).unwrap();
            let error = backend
                .wrap(&target.key_id, &signer.key_id, WrapScheme::CmsAes256Gcm)
                .unwrap_err();
            let message = error.to_string();
            assert!(
                message.contains("does not encapsulate"),
                "unhelpful error for {algorithm}: {message}"
            );
        }
    }

    /// `id-alg-ml-kem-768` (NIST CSOR 2.16.840.1.101.3.4.4.2).
    #[cfg(ossl350)]
    const ML_KEM_768_OID: &str = "2.16.840.1.101.3.4.4.2";
    /// `id-alg-hkdf-with-sha256` (RFC 8619).
    #[cfg(ossl350)]
    const HKDF_SHA256_OID: &str = "1.2.840.113549.1.9.16.3.28";
}
