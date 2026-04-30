//! OID constants shared across PKI actions.

use der::{Any, asn1::ObjectIdentifier};
use rite_sdk::{KeyAlgorithm, SignAlgorithm};
use x509_cert::spki::AlgorithmIdentifier;

/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub(super) const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
pub(super) const ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// id-extensionRequest (1.2.840.113549.1.9.14): PKCS#9, used in CSR attributes
pub(super) const EXTENSION_REQUEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

/// id-ce-subjectAltName (2.5.29.17)
pub(super) const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.17");

pub(super) fn sig_profile_for_algorithm(
    key_algorithm: KeyAlgorithm,
) -> Result<(SignAlgorithm, AlgorithmIdentifier<Any>, &'static str), String> {
    match key_algorithm {
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => Ok((
            SignAlgorithm::RsaPkcs1Sha256,
            AlgorithmIdentifier {
                oid: SHA256_WITH_RSA_ENCRYPTION,
                // RSA algorithm identifiers carry explicit NULL parameters per RFC 3279.
                parameters: Some(Any::null()),
            },
            "sha256WithRSAEncryption",
        )),
        KeyAlgorithm::EcdsaP256 => Ok((
            SignAlgorithm::EcdsaSha256,
            AlgorithmIdentifier {
                oid: ECDSA_WITH_SHA256,
                // RFC 5758: ECDSA-with-SHA2 identifiers use absent parameters.
                parameters: None,
            },
            "ecdsa-with-SHA256",
        )),
        other => Err(format!(
            "key algorithm '{other}' is not supported for PKI signing yet"
        )),
    }
}
