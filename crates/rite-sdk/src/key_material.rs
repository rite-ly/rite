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
use x509_cert::der::oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use x509_cert::der::oid::db::rfc5912::{
    ID_EC_PUBLIC_KEY, RSA_ENCRYPTION, SECP_256_R_1, SECP_384_R_1,
};
use x509_cert::der::oid::db::rfc8410::ID_ED_25519;
use x509_cert::der::{Decode, Encode, Reader, SliceReader};
use x509_cert::spki::SubjectPublicKeyInfoRef;

use crate::backend::BackendError;
use crate::types::KeyAlgorithm;

/// A public key in `SubjectPublicKeyInfo` (SPKI) DER form.
///
/// The one encoding a public key travels in inside Rite. PEM belongs at the
/// edges, where a key is read from a file or written to one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct PublicKeyDer(Vec<u8>);

impl PublicKeyDer {
    /// Wrap SPKI DER bytes after checking they parse.
    ///
    /// Takes ownership because callers hold the bytes a backend or a parser
    /// just produced, and the type keeps them.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when the bytes are not a
    /// `SubjectPublicKeyInfo`, which is what a certificate or a PEM armouring
    /// arriving here looks like.
    pub fn new(der: Vec<u8>) -> Result<Self, BackendError> {
        SubjectPublicKeyInfoRef::from_der(&der).map_err(|e| {
            BackendError::InvalidKeyFormat(format!("not a SubjectPublicKeyInfo: {e}"))
        })?;
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

        // DER says nothing about itself, so try both shapes.
        if let Ok(key) = Self::new(bytes.to_vec()) {
            return Ok(key);
        }
        // Neither shape parsed. The certificate attempt carries the more useful
        // reason, since bytes that reach here and are close to valid are far
        // more often a certificate than a bare key.
        certificate_public_key(bytes).map_err(|e| {
            BackendError::InvalidKeyFormat(format!(
                "not a public key or certificate, in DER or PEM ({e})"
            ))
        })
    }

    /// The SPKI DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
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
                    "EC curve {curve} is not supported (expected P-256 or P-384)"
                ))),
                Err(e) => Err(BackendError::InvalidKeyFormat(format!(
                    "EC key does not name a curve: {e}"
                ))),
            },
            ID_ED_25519 => Ok(KeyAlgorithm::Ed25519),
            ID_ML_DSA_44 => Ok(KeyAlgorithm::MlDsa44),
            ID_ML_DSA_65 => Ok(KeyAlgorithm::MlDsa65),
            ID_ML_DSA_87 => Ok(KeyAlgorithm::MlDsa87),
            oid => Err(BackendError::UnsupportedAlgorithm(format!(
                "public key algorithm {oid} is not supported"
            ))),
        }
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
        pub const CERTIFICATE: &[u8] = include_bytes!("../tests/vectors/p256.cert.der");
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
        ];

        for (der, expected) in cases {
            let key = PublicKeyDer::new(der.to_vec()).expect("vector is valid SPKI");
            assert_eq!(key.algorithm().unwrap(), expected);
        }
    }

    /// The mistake the type exists to prevent. Certificate DER used to reach an
    /// SPKI parser and fail with an ASN.1 tag error from inside the provider.
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

    #[test]
    fn bit_length_counts_from_the_top_set_bit() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0x01]), 1);
        assert_eq!(bit_length(&[0x80]), 8);
        assert_eq!(bit_length(&[0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x0f, 0xff]), 12);
    }
}
