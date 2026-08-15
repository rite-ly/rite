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

/// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
pub(super) const ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// id-Ed25519 (1.3.101.112)
pub(super) const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)
pub(super) const ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)
pub(super) const ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// id-ml-dsa-87 (2.16.840.1.101.3.4.3.19)
pub(super) const ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

/// The X.509 signature identifier for each algorithm Rite signs and accepts.
///
/// One table drives both directions: what to stamp on outgoing certificates and
/// what to accept on incoming CSRs. Two lists could drift, leaving Rite unable
/// to verify the CSRs it generates itself.
///
/// Membership is ceremony **policy**, not what the provider can do. OpenSSL
/// verifies md5WithRSA and SHA-1 happily; a key ceremony should accept neither.
///
/// `null_parameters` distinguishes RFC 3279, where RSA identifiers carry an
/// explicit NULL, from RFC 5758 and RFC 8410, where the parameters are absent.
const SIGNATURE_IDENTIFIERS: [(SignAlgorithm, ObjectIdentifier, bool, &str); 7] = [
    (
        SignAlgorithm::RsaPkcs1Sha256,
        SHA256_WITH_RSA_ENCRYPTION,
        true,
        "sha256WithRSAEncryption",
    ),
    (
        SignAlgorithm::EcdsaSha256,
        ECDSA_WITH_SHA256,
        false,
        "ecdsa-with-SHA256",
    ),
    (
        SignAlgorithm::EcdsaSha384,
        ECDSA_WITH_SHA384,
        false,
        "ecdsa-with-SHA384",
    ),
    (SignAlgorithm::Ed25519, ED25519, false, "Ed25519"),
    (SignAlgorithm::MlDsa44, ML_DSA_44, false, "ML-DSA-44"),
    (SignAlgorithm::MlDsa65, ML_DSA_65, false, "ML-DSA-65"),
    (SignAlgorithm::MlDsa87, ML_DSA_87, false, "ML-DSA-87"),
];

/// The signature profile to use when signing with a key of `key_algorithm`.
///
/// Which signature algorithm suits a key is the SDK's decision, shared with the
/// signing actions; this adds only the X.509 encoding of that choice.
pub(super) fn sig_profile_for_algorithm(
    key_algorithm: KeyAlgorithm,
) -> Result<(SignAlgorithm, AlgorithmIdentifier<Any>, &'static str), String> {
    let sign_algorithm = key_algorithm.default_sign_algorithm().ok_or_else(|| {
        format!("key algorithm '{key_algorithm}' is not supported for PKI signing yet")
    })?;
    let (identifier, name) = signature_identifier(sign_algorithm).ok_or_else(|| {
        format!("signature algorithm '{sign_algorithm}' has no X.509 identifier in Rite")
    })?;
    Ok((sign_algorithm, identifier, name))
}

/// The X.509 identifier and display name for a signature algorithm.
fn signature_identifier(
    algorithm: SignAlgorithm,
) -> Option<(AlgorithmIdentifier<Any>, &'static str)> {
    SIGNATURE_IDENTIFIERS
        .iter()
        .find(|(candidate, ..)| *candidate == algorithm)
        .map(|(_, oid, null_parameters, name)| {
            (
                AlgorithmIdentifier {
                    oid: *oid,
                    parameters: null_parameters.then(Any::null),
                },
                *name,
            )
        })
}

/// Resolve a CSR `signatureAlgorithm` OID against the table above.
pub(super) fn verifiable_sign_algorithm(oid: ObjectIdentifier) -> Option<SignAlgorithm> {
    SIGNATURE_IDENTIFIERS
        .iter()
        .find(|(_, candidate, ..)| *candidate == oid)
        .map(|(algorithm, ..)| *algorithm)
}

/// The accepted algorithm names, for an error message listing what is allowed.
pub(super) fn verifiable_algorithm_names() -> String {
    SIGNATURE_IDENTIFIERS
        .iter()
        .map(|(algorithm, ..)| algorithm.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every key algorithm Rite can sign with must reach an X.509 identifier.
    ///
    /// The SDK decides which signature algorithm suits a key; this module
    /// decides how to encode it. A key algorithm that gains a default in the
    /// SDK without an identifier here would fail at certificate-issuing time.
    #[test]
    fn every_signing_key_algorithm_has_an_identifier() {
        let signing_keys = [
            KeyAlgorithm::Rsa2048,
            KeyAlgorithm::Rsa4096,
            KeyAlgorithm::EcdsaP256,
            KeyAlgorithm::EcdsaP384,
            KeyAlgorithm::Ed25519,
            KeyAlgorithm::MlDsa44,
            KeyAlgorithm::MlDsa65,
            KeyAlgorithm::MlDsa87,
        ];
        for key_algorithm in signing_keys {
            let (sign_algorithm, ..) = sig_profile_for_algorithm(key_algorithm)
                .unwrap_or_else(|e| panic!("{key_algorithm}: {e}"));
            // What Rite stamps on a certificate is what it accepts on a CSR.
            assert_eq!(
                verifiable_sign_algorithm(
                    signature_identifier(sign_algorithm)
                        .expect("identifier")
                        .0
                        .oid
                ),
                Some(sign_algorithm),
                "{key_algorithm} signs with {sign_algorithm}, which is not accepted on a CSR"
            );
        }

        // Symmetric keys sign nothing, and must say so rather than panic.
        assert!(sig_profile_for_algorithm(KeyAlgorithm::Aes256).is_err());
    }

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
