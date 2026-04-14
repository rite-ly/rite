//! OID constants shared across PKI actions.

use der::asn1::ObjectIdentifier;

/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub(super) const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// id-extensionRequest (1.2.840.113549.1.9.14) — PKCS#9, used in CSR attributes
pub(super) const EXTENSION_REQUEST_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

/// id-ce-subjectAltName (2.5.29.17)
pub(super) const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.17");
