//! A backend-held key presented to the `x509_cert` certificate builder.

use signature::Keypair;
use x509_cert::der::Document;
use x509_cert::spki::{
    AlgorithmIdentifierOwned, DynSignatureAlgorithmIdentifier, EncodePublicKey,
    SubjectPublicKeyInfoOwned,
};

/// Public half of the backend-held issuing key.
#[derive(Clone)]
pub(crate) struct IssuingPublicKey(SubjectPublicKeyInfoOwned);

impl EncodePublicKey for IssuingPublicKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<Document> {
        Document::try_from(&self.0)
    }
}

/// Presents a backend's issuing key to the `x509_cert` builder.
///
/// The builder needs the issuing key's public half and its signature
/// algorithm identifier; the signature itself is produced by the backend
/// between `Builder::finalize` and `Builder::assemble`, so this type holds
/// no private key material.
pub(crate) struct BackendIssuingKey {
    public_key: IssuingPublicKey,
    signature_algorithm: AlgorithmIdentifierOwned,
}

impl BackendIssuingKey {
    /// The issuing key whose public half is `public_key`, signing under
    /// `signature_algorithm`.
    pub(crate) fn new(
        public_key: SubjectPublicKeyInfoOwned,
        signature_algorithm: AlgorithmIdentifierOwned,
    ) -> Self {
        Self {
            public_key: IssuingPublicKey(public_key),
            signature_algorithm,
        }
    }
}

impl Keypair for BackendIssuingKey {
    type VerifyingKey = IssuingPublicKey;

    fn verifying_key(&self) -> IssuingPublicKey {
        self.public_key.clone()
    }
}

impl DynSignatureAlgorithmIdentifier for BackendIssuingKey {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<AlgorithmIdentifierOwned> {
        Ok(self.signature_algorithm.clone())
    }
}
