//! Public key and certificate byte strings, with their encoding in the type.
//!
//! Key material reaches a ceremony as bytes, and the same `Vec<u8>` could hold
//! an SPKI public key, a PEM armouring of one, or a whole X.509 certificate.
//! [`PublicKeyDer`] and [`CertificateDer`] separate those, so a certificate
//! cannot be handed to something expecting a key and fail deep inside an ASN.1
//! parser.
//!
//! Both validate their structure at construction. Neither checks the algorithm
//! is one Rite supports: a key Rite cannot verify under is still a well-formed
//! key, and rejecting it here would put every future algorithm behind an SDK
//! release.
//!
//! [`CertificateDer::public_key`] is the only conversion between the two. It is
//! a method rather than a `From` impl because reading a signer's key out of
//! their certificate is a decision the caller makes, not a coercion.

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use x509_cert::der::asn1::UintRef;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::oid::db::DB;
use x509_cert::der::oid::db::fips203::{ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024};
use x509_cert::der::oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use x509_cert::der::oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1,
};
use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
use x509_cert::der::{AnyRef, Decode, Encode, Reader, SliceReader};
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use crate::backend::BackendError;
use crate::types::{KeyAlgorithm, KeyFingerprint, Rfc5280KeyId};

/// A public key in `SubjectPublicKeyInfo` (SPKI) DER form.
///
/// The one encoding a public key travels in inside Rite. PEM belongs at the
/// edges, where a key is read from a file or written to one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct PublicKeyDer(Vec<u8>);

impl PublicKeyDer {
    /// Wrap SPKI DER bytes after checking they parse, in canonical form.
    ///
    /// Takes ownership because callers hold the bytes a backend or a parser
    /// just produced, and the type keeps them.
    ///
    /// DER gives one structure one encoding, but an RSA SPKI has two
    /// structures: RFC 3279 §2.3.1 gives `rsaEncryption` NULL parameters, and
    /// readers, OpenSSL among them, also accept the parameters absent. Both are
    /// one key, and a [`KeyFingerprint`] of each would differ, so absent
    /// parameters are written as NULL here. The result is the encoding
    /// OpenSSL exports, which is what a backend holding the private half
    /// reports.
    ///
    /// An EC key has two encodings for the same point: uncompressed,
    /// `04 || x || y`, and compressed, `02` or `03` followed by `x` alone.
    /// They would have different fingerprints, and conversion requires curve
    /// arithmetic this crate does not carry. A compressed key is refused rather
    /// than converted, so the fingerprint an operator computes from their own
    /// bytes is the one Rite records.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are not a
    /// `SubjectPublicKeyInfo`, which is what a certificate or a PEM armouring
    /// arriving here looks like, and when an EC key's point is not
    /// uncompressed.
    pub fn new(der: Vec<u8>) -> Result<Self, BackendError> {
        let spki = SubjectPublicKeyInfoRef::from_der(&der).map_err(|e| {
            BackendError::InvalidKeyFormat(format!("not a SubjectPublicKeyInfo: {e}"))
        })?;
        if spki.algorithm.oid == ID_EC_PUBLIC_KEY
            && spki.subject_public_key.as_bytes().and_then(<[u8]>::first) != Some(&0x04)
        {
            return Err(BackendError::InvalidKeyFormat(
                "the EC public key's point is compressed, and Rite accepts EC keys uncompressed"
                    .to_string(),
            ));
        }
        if spki.algorithm.oid == RSA_ENCRYPTION && spki.algorithm.parameters.is_none() {
            let canonical = SubjectPublicKeyInfoRef {
                algorithm: AlgorithmIdentifierRef {
                    oid: RSA_ENCRYPTION,
                    parameters: Some(AnyRef::NULL),
                },
                subject_public_key: spki.subject_public_key,
            }
            .to_der()
            .map_err(|e| {
                BackendError::InvalidKeyFormat(format!("RSA public key cannot be re-encoded: {e}"))
            })?;
            return Ok(Self(canonical));
        }
        Ok(Self(der))
    }

    /// Read a public key out of whatever a ceremony hands over.
    ///
    /// Accepts the four shapes a signer's key arrives in: SPKI DER, SPKI PEM,
    /// certificate DER, and certificate PEM. A key loaded from a file is PEM
    /// more often than not, and a counterparty usually sends a certificate
    /// rather than a bare key, so refusing either would push the conversion
    /// onto the ceremony author.
    ///
    /// Use [`PublicKeyDer::new`] where the encoding is already known; this is
    /// for the boundary where it is not.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are none of
    /// the four, naming what was accepted.
    pub fn from_key_material(bytes: &[u8]) -> Result<Self, BackendError> {
        // PEM says what it holds, so the label decides and a wrong one is worth
        // reporting: a private key armoured here would otherwise come back as
        // unreadable bytes.
        if let Ok((label, der)) = x509_cert::der::pem::decode_vec(bytes) {
            return match label {
                "PUBLIC KEY" => Self::new(der),
                "CERTIFICATE" => certificate_public_key(&der),
                other => Err(BackendError::InvalidKeyFormat(format!(
                    "PEM block is labelled '{other}', expected 'PUBLIC KEY' or 'CERTIFICATE'"
                ))),
            };
        }

        // DER says nothing about itself, so try both shapes, and report both
        // reasons when neither parses.
        let key_error = match Self::new(bytes.to_vec()) {
            Ok(key) => return Ok(key),
            Err(e) => e,
        };
        certificate_public_key(bytes).map_err(|e| {
            BackendError::InvalidKeyFormat(format!(
                "not a public key or certificate, in DER or PEM (as a key: {key_error}; as a \
                 certificate: {e})"
            ))
        })
    }

    /// Read a public key from a file declared to hold one: SPKI, in DER or
    /// PEM.
    ///
    /// Stricter than [`PublicKeyDer::from_key_material`], which also reads
    /// the key out of a certificate. A file declared as a public key that
    /// holds a certificate is a declaration to correct, not a conversion to
    /// make.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are not an
    /// SPKI, or a PEM block names something else.
    pub fn from_file(bytes: &[u8]) -> Result<Self, BackendError> {
        if let Ok((label, der)) = x509_cert::der::pem::decode_vec(bytes) {
            return match label {
                "PUBLIC KEY" => Self::new(der),
                other => Err(BackendError::InvalidKeyFormat(format!(
                    "PEM block is labelled '{other}', expected 'PUBLIC KEY'"
                ))),
            };
        }
        Self::new(bytes.to_vec())
    }

    /// The SPKI DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rite's name for this key.
    #[must_use]
    pub fn fingerprint(&self) -> KeyFingerprint {
        KeyFingerprint::of_spki(&self.0)
    }

    /// The name X.509 tooling derives for this key, for recognising it in a
    /// structure someone else wrote.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] if the SPKI cannot be read,
    /// which every constructor already rules out.
    pub fn rfc5280_key_identifier(&self) -> Result<Rfc5280KeyId, BackendError> {
        let spki = SubjectPublicKeyInfoRef::from_der(&self.0)
            .map_err(|e| BackendError::InvalidKeyFormat(format!("SPKI is unreadable: {e}")))?;
        let identifier = SubjectKeyIdentifier::try_from(spki).map_err(|e| {
            BackendError::InvalidKeyFormat(format!("key identifier cannot be derived: {e}"))
        })?;
        let bytes = identifier.0.as_bytes().try_into().map_err(|_| {
            BackendError::InvalidKeyFormat("key identifier is not a SHA-1 digest".to_string())
        })?;
        Ok(Rfc5280KeyId::new(bytes))
    }

    /// The key algorithm, read from the key's own structure.
    ///
    /// Key bytes carry no ceremony metadata, so a caller that must know what it
    /// is holding, to pick a signature algorithm for instance, recovers it from
    /// the `AlgorithmIdentifier`. RSA is the one case the identifier does not
    /// settle: it names rsaEncryption without a size, so the modulus decides.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::UnsupportedAlgorithm`] for a key type or size
    /// Rite has no [`KeyAlgorithm`] for, and [`BackendError::InvalidKeyFormat`]
    /// when an RSA key's modulus cannot be read.
    pub fn algorithm(&self) -> Result<KeyAlgorithm, BackendError> {
        // Every constructor parses, so this cannot fail. It is written as a
        // fallible parse rather than an unwrap because the method returns
        // `Result` for unsupported algorithms anyway.
        let spki = SubjectPublicKeyInfoRef::from_der(&self.0)
            .map_err(|e| BackendError::InvalidKeyFormat(format!("SPKI is unreadable: {e}")))?;

        match spki.algorithm.oid {
            RSA_ENCRYPTION => {
                let key = spki.subject_public_key.as_bytes().ok_or_else(|| {
                    BackendError::InvalidKeyFormat(
                        "RSA public key is not a whole number of bytes".to_string(),
                    )
                })?;
                rsa_algorithm(key)
            }
            ID_EC_PUBLIC_KEY => match spki.algorithm.parameters_oid() {
                Ok(SECP_256_R_1) => Ok(KeyAlgorithm::EcdsaP256),
                Ok(SECP_384_R_1) => Ok(KeyAlgorithm::EcdsaP384),
                Ok(curve) => Err(BackendError::UnsupportedAlgorithm(format!(
                    "EC curve {} is not supported (expected P-256 or P-384)",
                    named(curve)
                ))),
                Err(e) => Err(BackendError::InvalidKeyFormat(format!(
                    "EC key does not name a curve: {e}"
                ))),
            },
            ID_ED_25519 => Ok(KeyAlgorithm::Ed25519),
            ID_ML_DSA_44 => Ok(KeyAlgorithm::MlDsa44),
            ID_ML_DSA_65 => Ok(KeyAlgorithm::MlDsa65),
            ID_ML_DSA_87 => Ok(KeyAlgorithm::MlDsa87),
            ID_ALG_ML_KEM_512 => Ok(KeyAlgorithm::MlKem512),
            ID_ALG_ML_KEM_768 => Ok(KeyAlgorithm::MlKem768),
            ID_ALG_ML_KEM_1024 => Ok(KeyAlgorithm::MlKem1024),
            oid => Err(BackendError::UnsupportedAlgorithm(format!(
                "public key algorithm {} is not supported",
                named(oid)
            ))),
        }
    }

    /// Returns the EC point and curve named by this public key's SPKI.
    ///
    /// The point is in SEC 1 uncompressed form. This method checks the encoding
    /// and length, but not whether the point lies on the curve.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::UnsupportedAlgorithm`] if the key is not on a
    /// supported EC curve, or [`BackendError::InvalidKeyFormat`] if its SPKI
    /// or point encoding is invalid.
    pub fn ec_point(&self) -> Result<EcPoint, BackendError> {
        let algorithm = self.algorithm()?;
        let curve = EcCurve::of(algorithm).ok_or_else(|| {
            BackendError::UnsupportedAlgorithm(format!("{algorithm} is not an EC key"))
        })?;
        let spki = SubjectPublicKeyInfoRef::from_der(&self.0)
            .map_err(|e| BackendError::InvalidKeyFormat(format!("SPKI is unreadable: {e}")))?;
        let point = spki.subject_public_key.as_bytes().ok_or_else(|| {
            BackendError::InvalidKeyFormat("EC point is not a whole number of bytes".to_string())
        })?;
        // `new` has refused a compressed point, so only the length is left.
        if point.len() != curve.point_len() {
            return Err(BackendError::InvalidKeyFormat(format!(
                "a {curve} point is {} bytes uncompressed, and this one is {}",
                curve.point_len(),
                point.len()
            )));
        }
        Ok(EcPoint {
            curve,
            point: point.to_vec(),
        })
    }
}

/// A supported EC curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EcCurve {
    /// NIST P-256, `secp256r1`.
    P256,
    /// NIST P-384, `secp384r1`.
    P384,
}

impl EcCurve {
    /// Returns the curve for an EC key algorithm, or `None` for other algorithms.
    #[must_use]
    pub fn of(algorithm: KeyAlgorithm) -> Option<Self> {
        match algorithm {
            KeyAlgorithm::EcdsaP256 => Some(Self::P256),
            KeyAlgorithm::EcdsaP384 => Some(Self::P384),
            KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa4096
            | KeyAlgorithm::Ed25519
            | KeyAlgorithm::MlDsa44
            | KeyAlgorithm::MlDsa65
            | KeyAlgorithm::MlDsa87
            | KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024
            | KeyAlgorithm::Aes128
            | KeyAlgorithm::Aes256 => None,
        }
    }

    /// Returns the EC key algorithm for this curve.
    #[must_use]
    pub fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::P256 => KeyAlgorithm::EcdsaP256,
            Self::P384 => KeyAlgorithm::EcdsaP384,
        }
    }

    /// Returns the field-element length in bytes.
    #[must_use]
    pub fn field_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    /// Returns the length in bytes of the group order, which sizes an ECDSA
    /// `r` and `s`.
    ///
    /// It equals [`field_len`](Self::field_len) on these curves, but measures
    /// the order rather than a coordinate.
    #[must_use]
    pub fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    /// Returns the SEC 1 uncompressed point length in bytes.
    #[must_use]
    pub fn point_len(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
        }
    }
}

impl std::fmt::Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        })
    }
}

/// An EC public point in SEC 1 uncompressed form.
///
/// The point's encoding and length are checked when it is constructed.
/// Whether it lies on the curve must be checked before passing it to a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcPoint {
    curve: EcCurve,
    point: Vec<u8>,
}

impl EcPoint {
    /// Returns the point's curve.
    #[must_use]
    pub fn curve(&self) -> EcCurve {
        self.curve
    }

    /// Returns the point in SEC 1 uncompressed form.
    #[must_use]
    pub fn sec1_uncompressed(&self) -> &[u8] {
        &self.point
    }
}

impl From<PublicKeyDer> for Vec<u8> {
    fn from(key: PublicKeyDer) -> Self {
        key.0
    }
}

impl TryFrom<Vec<u8>> for PublicKeyDer {
    type Error = BackendError;

    fn try_from(der: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(der)
    }
}

/// An X.509 certificate in DER form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct CertificateDer(Vec<u8>);

impl CertificateDer {
    /// Wrap certificate DER bytes after checking they parse.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are not an
    /// X.509 certificate.
    pub fn new(der: Vec<u8>) -> Result<Self, BackendError> {
        Certificate::from_der(&der).map_err(|e| {
            BackendError::InvalidKeyFormat(format!("not an X.509 certificate: {e}"))
        })?;
        Ok(Self(der))
    }

    /// Read a certificate out of whatever a ceremony hands over.
    ///
    /// Accepts certificate DER and certificate PEM. Certificates reach a
    /// ceremony from files and counterparties, where PEM is the common
    /// encoding, so the sniff belongs here rather than at each call site.
    ///
    /// The counterpart to [`PublicKeyDer::from_key_material`]. Both exist so
    /// that deciding what an encoding is happens in one place per type.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are neither,
    /// or when a PEM block names something other than a certificate.
    pub fn from_key_material(bytes: &[u8]) -> Result<Self, BackendError> {
        if let Ok((label, der)) = x509_cert::der::pem::decode_vec(bytes) {
            return match label {
                "CERTIFICATE" => Self::new(der),
                other => Err(BackendError::InvalidKeyFormat(format!(
                    "PEM block is labelled '{other}', expected 'CERTIFICATE'"
                ))),
            };
        }
        Self::new(bytes.to_vec())
    }

    /// The certificate DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The subject public key, as SPKI DER.
    ///
    /// A signer's public key usually reaches a ceremony inside a certificate
    /// rather than on its own: `piv_read_certificate` pulls one off a card, and
    /// a counterparty sends one. This lets a step name the certificate instead
    /// of the author extracting the key first.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the certificate or its
    /// subject public key cannot be re-encoded.
    pub fn public_key(&self) -> Result<PublicKeyDer, BackendError> {
        certificate_public_key(&self.0)
    }
}

/// Read the subject public key out of certificate DER.
///
/// Takes bytes rather than a [`CertificateDer`] so a caller that only wants the
/// key does not have to build, and validate, a certificate wrapper it will drop
/// on the next line.
fn certificate_public_key(der: &[u8]) -> Result<PublicKeyDer, BackendError> {
    let certificate = Certificate::from_der(der)
        .map_err(|e| BackendError::InvalidKeyFormat(format!("not an X.509 certificate: {e}")))?;
    let spki = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .map_err(|e| {
            BackendError::InvalidKeyFormat(format!(
                "certificate's public key cannot be encoded: {e}"
            ))
        })?;
    PublicKeyDer::new(spki)
}

impl From<CertificateDer> for Vec<u8> {
    fn from(certificate: CertificateDer) -> Self {
        certificate.0
    }
}

impl TryFrom<Vec<u8>> for CertificateDer {
    type Error = BackendError;

    fn try_from(der: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(der)
    }
}

/// An OID with its registered name where one is known, as
/// `secp521r1 (1.3.132.0.35)`, so a refusal says what the key is to someone
/// who does not read OIDs, and still gives the number to search for.
fn named(oid: ObjectIdentifier) -> String {
    // The registry const-oid carries has no entry for the Bitcoin curve, and
    // keys on it are common enough to be offered.
    const SECP_256_K_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
    let name = if oid == SECP_256_K_1 {
        Some("secp256k1")
    } else {
        DB.by_oid(&oid)
    };
    match name {
        Some(name) => format!("{name} ({oid})"),
        None => oid.to_string(),
    }
}

/// Classify an RSA key by its modulus size.
///
/// `key` is the `subjectPublicKey` payload, an `RSAPublicKey` sequence of
/// modulus and public exponent (RFC 8017 appendix A.1.1).
fn rsa_algorithm(key: &[u8]) -> Result<KeyAlgorithm, BackendError> {
    let mut reader = SliceReader::new(key).map_err(|e| {
        BackendError::InvalidKeyFormat(format!("RSA public key is unreadable: {e}"))
    })?;
    let modulus_bits = reader
        .sequence(|body| {
            let modulus: UintRef<'_> = body.decode()?;
            Ok::<_, x509_cert::der::Error>(bit_length(modulus.as_bytes()))
        })
        .map_err(|e| BackendError::InvalidKeyFormat(format!("RSA modulus cannot be read: {e}")))?;

    match modulus_bits {
        2048 => Ok(KeyAlgorithm::Rsa2048),
        4096 => Ok(KeyAlgorithm::Rsa4096),
        bits => Err(BackendError::UnsupportedAlgorithm(format!(
            "RSA key size {bits} bits not supported (expected 2048 or 4096)"
        ))),
    }
}

/// Bit length of a big-endian integer with leading zero bytes already stripped.
///
/// Saturates rather than wrapping. A modulus long enough to overflow is not a
/// supported key size either way, so it reaches the same rejection.
fn bit_length(magnitude: &[u8]) -> u32 {
    let Some((&top, rest)) = magnitude.split_first() else {
        return 0;
    };

    u32::try_from(rest.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(8)
        .saturating_add(u8::BITS.saturating_sub(top.leading_zeros()))
}

/// Read a certificate signing request from a file: PKCS#10, in DER or PEM,
/// returned as DER.
///
/// # Errors
///
/// Returns [`BackendError::InvalidKeyFormat`] when the bytes are not a
/// PKCS#10 request, or a PEM block names something else.
pub fn csr_from_file(bytes: &[u8]) -> Result<Vec<u8>, BackendError> {
    let der = match x509_cert::der::pem::decode_vec(bytes) {
        Ok(("CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST", der)) => der,
        Ok((other, _)) => {
            return Err(BackendError::InvalidKeyFormat(format!(
                "PEM block is labelled '{other}', expected 'CERTIFICATE REQUEST'"
            )));
        }
        Err(_) => bytes.to_vec(),
    };
    x509_cert::request::CertReq::from_der(&der).map_err(|e| {
        BackendError::InvalidKeyFormat(format!("not a certificate signing request: {e}"))
    })?;
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPKI DER for one key per algorithm, produced with OpenSSL and pinned as
    /// bytes. Generating them at test time would let a change in Rite's own key
    /// generation move the expected answer along with the input.
    ///
    /// Reproduce with, for each algorithm:
    /// `openssl genpkey -algorithm <alg> | openssl pkey -pubout -outform DER`
    mod vectors {
        pub const RSA_2048: &[u8] = include_bytes!("../tests/vectors/rsa2048.spki.der");
        pub const RSA_4096: &[u8] = include_bytes!("../tests/vectors/rsa4096.spki.der");
        pub const P256: &[u8] = include_bytes!("../tests/vectors/p256.spki.der");
        pub const P384: &[u8] = include_bytes!("../tests/vectors/p384.spki.der");
        pub const ED25519: &[u8] = include_bytes!("../tests/vectors/ed25519.spki.der");
        pub const ML_DSA_44: &[u8] = include_bytes!("../tests/vectors/mldsa44.spki.der");
        pub const ML_DSA_65: &[u8] = include_bytes!("../tests/vectors/mldsa65.spki.der");
        pub const ML_DSA_87: &[u8] = include_bytes!("../tests/vectors/mldsa87.spki.der");
        pub const ML_KEM_512: &[u8] = include_bytes!("../tests/vectors/mlkem512.spki.der");
        pub const ML_KEM_768: &[u8] = include_bytes!("../tests/vectors/mlkem768.spki.der");
        pub const ML_KEM_1024: &[u8] = include_bytes!("../tests/vectors/mlkem1024.spki.der");
        pub const P521: &[u8] = include_bytes!("../tests/vectors/p521.spki.der");
        pub const ED448: &[u8] = include_bytes!("../tests/vectors/ed448.spki.der");
        pub const CERTIFICATE: &[u8] = include_bytes!("../tests/vectors/p256.cert.der");
    }

    /// The identifier OpenSSL wrote into the vector certificate's subject key
    /// identifier extension, read back with `openssl x509 -ext
    /// subjectKeyIdentifier`, is the one derived from the key it certifies.
    #[test]
    fn derives_the_key_identifier_openssl_writes() {
        let certificate = CertificateDer::new(vectors::CERTIFICATE.to_vec()).unwrap();
        let identifier = certificate
            .public_key()
            .unwrap()
            .rfc5280_key_identifier()
            .unwrap();
        assert_eq!(
            identifier.as_bytes(),
            &[
                0x6f, 0x60, 0xee, 0x1f, 0xc5, 0x1e, 0x6e, 0xce, 0xad, 0xba, 0x96, 0xa2, 0x3d, 0xa0,
                0x40, 0xaf, 0x22, 0x0a, 0x09, 0xa6
            ]
        );
    }

    #[test]
    fn reads_the_algorithm_out_of_each_key_type() {
        let cases = [
            (vectors::RSA_2048, KeyAlgorithm::Rsa2048),
            (vectors::RSA_4096, KeyAlgorithm::Rsa4096),
            (vectors::P256, KeyAlgorithm::EcdsaP256),
            (vectors::P384, KeyAlgorithm::EcdsaP384),
            (vectors::ED25519, KeyAlgorithm::Ed25519),
            (vectors::ML_DSA_44, KeyAlgorithm::MlDsa44),
            (vectors::ML_DSA_65, KeyAlgorithm::MlDsa65),
            (vectors::ML_DSA_87, KeyAlgorithm::MlDsa87),
            (vectors::ML_KEM_512, KeyAlgorithm::MlKem512),
            (vectors::ML_KEM_768, KeyAlgorithm::MlKem768),
            (vectors::ML_KEM_1024, KeyAlgorithm::MlKem1024),
        ];

        for (der, expected) in cases {
            let key = PublicKeyDer::new(der.to_vec()).expect("vector is valid SPKI");
            assert_eq!(key.algorithm().unwrap(), expected);
        }
    }

    /// A refusal names what the key is, with the OID to search for.
    #[test]
    fn names_a_curve_or_algorithm_rite_has_no_key_type_for() {
        let cases = [
            (
                vectors::P521,
                "EC curve secp521r1 (1.3.132.0.35) is not supported",
            ),
            (
                vectors::ED448,
                "public key algorithm id-Ed448 (1.3.101.113) is not supported",
            ),
        ];

        for (der, says) in cases {
            let key = PublicKeyDer::new(der.to_vec()).expect("vector is valid SPKI");
            let err = key.algorithm().unwrap_err();
            assert!(
                matches!(err, BackendError::UnsupportedAlgorithm(_)),
                "{err:?}"
            );
            assert!(err.to_string().contains(says), "{err}");
        }
    }

    #[test]
    fn reads_the_point_out_of_an_ec_key() {
        for (der, curve, len) in [
            (vectors::P256, EcCurve::P256, 32),
            (vectors::P384, EcCurve::P384, 48),
        ] {
            let point = PublicKeyDer::new(der.to_vec()).unwrap().ec_point().unwrap();
            let bits = SubjectPublicKeyInfoRef::from_der(der)
                .unwrap()
                .subject_public_key
                .raw_bytes();
            assert_eq!(point.curve(), curve);
            assert_eq!(point.curve().field_len(), len);
            assert_eq!(point.curve().scalar_len(), len);
            assert_eq!(point.sec1_uncompressed().len(), point.curve().point_len());
            assert_eq!(EcCurve::of(curve.key_algorithm()), Some(curve));
            assert_eq!(point.sec1_uncompressed(), bits);
            assert_eq!(point.sec1_uncompressed().first(), Some(&0x04));
        }
    }

    #[test]
    fn a_key_that_is_not_ec_has_no_point() {
        for der in [vectors::RSA_2048, vectors::ED25519, vectors::ML_DSA_44] {
            let error = PublicKeyDer::new(der.to_vec())
                .unwrap()
                .ec_point()
                .unwrap_err();
            assert!(
                matches!(error, BackendError::UnsupportedAlgorithm(_)),
                "{error:?}"
            );
        }
    }

    /// A P-256 SPKI whose point has lost its last byte: uncompressed, so
    /// `new` accepts it, but too short for the curve.
    #[test]
    fn refuses_a_point_too_short_for_its_curve() {
        let spki = SubjectPublicKeyInfoRef::from_der(vectors::P256).unwrap();
        let bits = spki.subject_public_key.raw_bytes();
        let (_, truncated) = bits.split_last().unwrap();
        let der = SubjectPublicKeyInfoRef {
            algorithm: spki.algorithm,
            subject_public_key: x509_cert::der::asn1::BitStringRef::from_bytes(truncated).unwrap(),
        }
        .to_der()
        .unwrap();

        let error = PublicKeyDer::new(der).unwrap().ec_point().unwrap_err();
        assert!(
            matches!(&error, BackendError::InvalidKeyFormat(m) if m.contains("65 bytes")),
            "{error:?}"
        );
    }

    /// The mistake the type exists to prevent. Certificate DER handed to an SPKI
    /// parser fails with an ASN.1 tag error from inside the provider, far from
    /// the call that supplied it.
    #[test]
    fn rejects_a_certificate_offered_as_a_public_key() {
        let err = PublicKeyDer::new(vectors::CERTIFICATE.to_vec()).unwrap_err();
        assert!(
            err.to_string().contains("not a SubjectPublicKeyInfo"),
            "{err}"
        );
    }

    #[test]
    fn reads_the_public_key_out_of_a_certificate() {
        let certificate =
            CertificateDer::new(vectors::CERTIFICATE.to_vec()).expect("vector is a certificate");
        let key = certificate.public_key().unwrap();
        assert_eq!(key.algorithm().unwrap(), KeyAlgorithm::EcdsaP256);
        assert_eq!(key.as_bytes(), vectors::P256);
    }

    #[test]
    fn rejects_a_public_key_offered_as_a_certificate() {
        assert!(CertificateDer::new(vectors::P256.to_vec()).is_err());
    }

    /// Trailing bytes after a valid key are a truncation or splice, not a key.
    #[test]
    fn rejects_trailing_data() {
        let mut der = vectors::P256.to_vec();
        der.push(0);
        assert!(PublicKeyDer::new(der).is_err());
    }

    #[test]
    fn rejects_empty_and_truncated_input() {
        assert!(PublicKeyDer::new(Vec::new()).is_err());
        let truncated = vectors::P256
            .get(..10)
            .expect("vector is longer than 10 bytes");
        assert!(PublicKeyDer::new(truncated.to_vec()).is_err());
    }

    /// Serde round-trips through the raw bytes, and validates on the way in.
    #[test]
    fn deserializing_rejects_bytes_that_are_not_a_key() {
        let key = PublicKeyDer::new(vectors::P256.to_vec()).unwrap();
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<PublicKeyDer>(&json).unwrap(), key);

        let certificate_json = serde_json::to_string(vectors::CERTIFICATE).unwrap();
        assert!(serde_json::from_str::<PublicKeyDer>(&certificate_json).is_err());
    }

    /// PEM armour a DER body under `label`, the way a file on disk carries it.
    fn armour(label: &str, der: &[u8]) -> Vec<u8> {
        x509_cert::der::pem::encode_string(label, x509_cert::der::pem::LineEnding::LF, der)
            .expect("armouring is infallible for a valid label")
            .into_bytes()
    }

    /// The four shapes a signer's key arrives in must all resolve to the key.
    #[test]
    fn reads_a_key_from_der_and_pem_and_certificates() {
        let expected = PublicKeyDer::new(vectors::P256.to_vec()).unwrap();

        let sources = [
            vectors::P256.to_vec(),
            armour("PUBLIC KEY", vectors::P256),
            vectors::CERTIFICATE.to_vec(),
            armour("CERTIFICATE", vectors::CERTIFICATE),
        ];

        for source in sources {
            assert_eq!(PublicKeyDer::from_key_material(&source).unwrap(), expected);
        }
    }

    /// A PEM block naming something else is an authoring mistake worth saying
    /// out loud: a private key here would otherwise fail as unreadable bytes.
    #[test]
    fn refuses_a_pem_block_that_is_not_a_key_or_certificate() {
        let private = armour("PRIVATE KEY", vectors::P256);
        let err = PublicKeyDer::from_key_material(&private).unwrap_err();
        assert!(err.to_string().contains("PRIVATE KEY"), "{err}");
    }

    #[test]
    fn refuses_key_material_that_is_neither() {
        let err = PublicKeyDer::from_key_material(b"just some bytes").unwrap_err();
        assert!(
            err.to_string().contains("public key or certificate"),
            "{err}"
        );
    }

    /// A certificate arrives in DER or PEM, and both must reach the same value.
    #[test]
    fn reads_a_certificate_from_der_and_pem() {
        let expected = CertificateDer::new(vectors::CERTIFICATE.to_vec()).unwrap();

        for source in [
            vectors::CERTIFICATE.to_vec(),
            armour("CERTIFICATE", vectors::CERTIFICATE),
        ] {
            assert_eq!(
                CertificateDer::from_key_material(&source).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn refuses_a_pem_block_that_is_not_a_certificate() {
        let key = armour("PUBLIC KEY", vectors::P256);
        let err = CertificateDer::from_key_material(&key).unwrap_err();
        assert!(err.to_string().contains("PUBLIC KEY"), "{err}");
    }

    /// The vector with its NULL parameters left out, which OpenSSL also reads.
    fn rsa_without_parameters() -> Vec<u8> {
        let spki = SubjectPublicKeyInfoRef::from_der(vectors::RSA_2048).unwrap();
        SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: RSA_ENCRYPTION,
                parameters: None,
            },
            subject_public_key: spki.subject_public_key,
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn an_rsa_key_without_parameters_is_kept_as_openssl_exports_it() {
        let supplied = rsa_without_parameters();
        assert_ne!(supplied, vectors::RSA_2048);

        let key = PublicKeyDer::new(supplied).unwrap();
        assert_eq!(key.as_bytes(), vectors::RSA_2048);
        assert_eq!(
            key.fingerprint(),
            PublicKeyDer::new(vectors::RSA_2048.to_vec())
                .unwrap()
                .fingerprint()
        );
    }

    /// The P-256 vector with its point compressed: `02` or `03` by the parity
    /// of y, then x.
    fn p256_compressed() -> Vec<u8> {
        let spki = SubjectPublicKeyInfoRef::from_der(vectors::P256).unwrap();
        let (_, coordinates) = spki
            .subject_public_key
            .as_bytes()
            .unwrap()
            .split_first()
            .unwrap();
        let (x, y) = coordinates.split_at(32);
        let prefix = 0x02 | (y.last().unwrap() & 0x01);
        let compressed = [&[prefix][..], x].concat();
        SubjectPublicKeyInfoRef {
            algorithm: spki.algorithm,
            subject_public_key: x509_cert::der::asn1::BitStringRef::from_bytes(&compressed)
                .unwrap(),
        }
        .to_der()
        .unwrap()
    }

    /// A compressed point is the same key under another encoding, so it would
    /// have another fingerprint. It is refused, naming the conversion.
    #[test]
    fn an_ec_key_is_accepted_only_with_its_point_uncompressed() {
        assert!(PublicKeyDer::new(vectors::P256.to_vec()).is_ok());
        let error = PublicKeyDer::new(p256_compressed())
            .unwrap_err()
            .to_string();
        assert!(error.contains("compressed"), "{error}");
        let error = PublicKeyDer::from_key_material(&p256_compressed())
            .unwrap_err()
            .to_string();
        assert!(error.contains("point is compressed"), "{error}");
    }

    #[test]
    fn a_fingerprint_is_the_sha256_of_the_spki() {
        use sha2::Digest as _;
        let key = PublicKeyDer::new(vectors::P256.to_vec()).unwrap();
        let digest: [u8; 32] = sha2::Sha256::digest(vectors::P256).into();
        assert_eq!(key.fingerprint().as_bytes(), &digest);
        assert_eq!(
            key.fingerprint().to_string(),
            format!("sha256:{}", base16ct::lower::encode_string(&digest))
        );
    }

    #[test]
    fn bit_length_counts_from_the_top_set_bit() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0x01]), 1);
        assert_eq!(bit_length(&[0x80]), 8);
        assert_eq!(bit_length(&[0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x0f, 0xff]), 12);
    }
}
