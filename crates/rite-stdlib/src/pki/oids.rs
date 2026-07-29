//! OID constants shared across PKI actions.

use rite_sdk::{KeyAlgorithm, SignAlgorithm};
use x509_cert::der::{Any, asn1::ObjectIdentifier};
use x509_cert::spki::AlgorithmIdentifier;

/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub(super) const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
pub(super) const ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)
pub(super) const ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)
pub(super) const ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// id-ml-dsa-87 (2.16.840.1.101.3.4.3.19)
pub(super) const ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

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
        // FIPS 204 fixes one signature scheme per parameter set, with no hash
        // or padding left to choose, so the key algorithm fully determines the
        // signature algorithm identifier. Parameters are absent.
        KeyAlgorithm::MlDsa44 | KeyAlgorithm::MlDsa65 | KeyAlgorithm::MlDsa87 => {
            let (sign_algorithm, oid, name) = match key_algorithm {
                KeyAlgorithm::MlDsa44 => (SignAlgorithm::MlDsa44, ML_DSA_44, "ML-DSA-44"),
                KeyAlgorithm::MlDsa65 => (SignAlgorithm::MlDsa65, ML_DSA_65, "ML-DSA-65"),
                _ => (SignAlgorithm::MlDsa87, ML_DSA_87, "ML-DSA-87"),
            };
            Ok((
                sign_algorithm,
                AlgorithmIdentifier {
                    oid,
                    parameters: None,
                },
                name,
            ))
        }
        other => Err(format!(
            "key algorithm '{other}' is not supported for PKI signing yet"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ML-DSA identifiers are a wire contract: they appear in every
    /// certificate and CSR the runtime emits, so they are pinned by value
    /// rather than by whatever the constants happen to hold.
    #[test]
    fn ml_dsa_signature_identifiers_are_stable() {
        let cases = [
            (
                KeyAlgorithm::MlDsa44,
                "2.16.840.1.101.3.4.3.17",
                "ML-DSA-44",
            ),
            (
                KeyAlgorithm::MlDsa65,
                "2.16.840.1.101.3.4.3.18",
                "ML-DSA-65",
            ),
            (
                KeyAlgorithm::MlDsa87,
                "2.16.840.1.101.3.4.3.19",
                "ML-DSA-87",
            ),
        ];

        for (key_algorithm, expected_oid, expected_name) in cases {
            let (sign_algorithm, identifier, name) =
                sig_profile_for_algorithm(key_algorithm).unwrap();

            assert_eq!(identifier.oid.to_string(), expected_oid);
            assert_eq!(name, expected_name);
            // Absent parameters, not NULL: ML-DSA has nothing to parameterise.
            assert!(identifier.parameters.is_none());
            // The parameter set round-trips, so a signing request cannot end up
            // on a different one than the key.
            assert_eq!(sign_algorithm.key_algorithm(), key_algorithm);
        }
    }
}
