//! Key attestation: a device's signed statement about one of its keys.
//!
//! The statement is signed by a key the operator does not control, the
//! device vendor's, so it is evidence a ceremony can carry to someone who
//! trusts that vendor and not the operator. What it claims and how its claims
//! are laid out depend on the vendor, which [`AttestationFormat`] names.
//!
//! This module holds the evidence only. Checking it, the chain to a vendor
//! root and the claims against what a ceremony requires, is a separate step
//! that needs no device.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::names::names;
use crate::types::ParseError;
use crate::{BackendError, CertificateDer};

/// The format of an attestation: who signs it and how its claims are laid
/// out, so a verifier knows which parser reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
#[non_exhaustive]
pub enum AttestationFormat {
    /// A YubiKey PIV attestation: an X.509 certificate over the slot's public
    /// key, issued by the device's attestation key in slot F9, followed by
    /// that key's certificate. Claims are Yubico extensions under
    /// `1.3.6.1.4.1.41482.3`. A YubiKey attests only keys it generated, so the
    /// certificate's existence is the claim of origin.
    YubicoPiv,
}

names!(AttestationFormat {
    YubicoPiv => "yubico-piv/v1",
});

/// The Yubico extensions on a YubiKey PIV attestation certificate.
pub mod yubico_oid {
    use x509_cert::der::asn1::ObjectIdentifier;

    /// The firmware version, which every attestation certificate carries.
    pub const FIRMWARE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
    /// The device's serial number.
    pub const SERIAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
    /// The key's PIN and touch policies, one byte each.
    pub const POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");
    /// The device's form factor.
    pub const FORM_FACTOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.9");
}

impl AttestationFormat {
    /// The format of a chain whose first certificate is `leaf`, read from
    /// what the leaf carries.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidData`] when the leaf is in no format
    /// Rite reads.
    fn recognise(leaf: &CertificateDer) -> Result<Self, BackendError> {
        let certificate = Certificate::from_der(leaf.as_bytes())
            .map_err(|e| BackendError::InvalidData(format!("not an X.509 certificate: {e}")))?;
        let yubico = certificate
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .any(|extension| extension.extn_id == yubico_oid::FIRMWARE);
        if yubico {
            Ok(Self::YubicoPiv)
        } else {
            Err(BackendError::InvalidData(
                "the first certificate is not a key attestation in a format Rite reads; \
                 Rite reads YubiKey PIV attestations"
                    .to_string(),
            ))
        }
    }

    /// How many certificates an attestation in this format holds.
    const fn chain_length(self) -> usize {
        match self {
            // The slot's certificate and the device's own.
            Self::YubicoPiv => 2,
        }
    }
}

/// A device's signed statement about one of its keys, as the device gave it.
///
/// The certificates come leaf first: the statement about the key, then the
/// certificates of the device that issued it. Nothing here says the chain is
/// trustworthy; verifying it against vendor roots is a separate step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    format: AttestationFormat,
    leaf: CertificateDer,
    issuers: Vec<CertificateDer>,
}

impl Attestation {
    /// Evidence in `format`, leaf first.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidData`] when the number of certificates
    /// is not the one the format has.
    pub fn new(
        format: AttestationFormat,
        certificates: Vec<CertificateDer>,
    ) -> Result<Self, BackendError> {
        let expected = format.chain_length();
        let given = certificates.len();
        let mut certificates = certificates.into_iter();
        match certificates.next() {
            Some(leaf) if given == expected => Ok(Self {
                format,
                leaf,
                issuers: certificates.collect(),
            }),
            _ => Err(BackendError::InvalidData(format!(
                "a {format} attestation holds {expected} certificates, the key's and the \
                 device's, and {given} were given"
            ))),
        }
    }

    /// Read an attestation from a file: certificates in PEM, leaf first.
    ///
    /// The format is recognised from the leaf.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidKeyFormat`] when a block is not a
    /// certificate, and [`BackendError::InvalidData`] when the chain is in no
    /// format Rite reads or has the wrong length. `ykman piv keys attest`
    /// writes the leaf alone; the error says to append the device's
    /// certificate.
    pub fn from_key_material(bytes: &[u8]) -> Result<Self, BackendError> {
        let certificates = CertificateDer::list_from_key_material(bytes)?;
        let leaf = certificates
            .first()
            .ok_or_else(|| BackendError::InvalidData("no certificate found".to_string()))?;
        let format = AttestationFormat::recognise(leaf)?;
        match certificates.len().cmp(&format.chain_length()) {
            // `ykman piv keys attest` writes the leaf alone.
            Ordering::Less => Err(BackendError::InvalidData(
                "the file holds the attestation certificate alone; append the device's \
                 certificate from slot F9, both in PEM (ykman piv certificates export f9 -)"
                    .to_string(),
            )),
            Ordering::Greater => Err(BackendError::InvalidData(format!(
                "the file holds {} certificates, and a {format} attestation is the key's and \
                 the device's alone; remove the vendor's intermediate and root certificates, \
                 which are not part of what the device gave",
                certificates.len()
            ))),
            Ordering::Equal => Self::new(format, certificates),
        }
    }

    /// The format, which says how to read the claims.
    #[must_use]
    pub fn format(&self) -> AttestationFormat {
        self.format
    }

    /// The certificates, leaf first.
    pub fn certificates(&self) -> impl Iterator<Item = &CertificateDer> {
        std::iter::once(&self.leaf).chain(&self.issuers)
    }

    /// The statement about the key.
    #[must_use]
    pub fn leaf(&self) -> &CertificateDer {
        &self.leaf
    }

    /// The certificates of the device that issued the statement, nearest
    /// first: for a YubiKey, its F9 certificate.
    #[must_use]
    pub fn issuers(&self) -> &[CertificateDer] {
        &self.issuers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A YubiKey-style attestation, leaf and device certificate, made for
    /// these tests under a throwaway root: no real device's.
    const BUNDLE: &[u8] = include_bytes!("../tests/vectors/yubico-piv-attestation.pem");

    #[test]
    fn reads_a_bundle_and_recognises_its_format() {
        let attestation = Attestation::from_key_material(BUNDLE).expect("the bundle reads");
        assert_eq!(attestation.format(), AttestationFormat::YubicoPiv);
        assert_eq!(attestation.certificates().count(), 2);
        assert_eq!(attestation.certificates().next(), Some(attestation.leaf()));
        assert_eq!(attestation.issuers().len(), 1);
    }

    #[test]
    fn says_to_append_the_device_certificate_to_a_lone_leaf() {
        let text = std::str::from_utf8(BUNDLE).unwrap();
        let (leaf, _) = text.split_once("-----END CERTIFICATE-----").unwrap();
        let alone = format!("{leaf}-----END CERTIFICATE-----\n");
        let error = Attestation::from_key_material(alone.as_bytes()).expect_err("one is too few");
        assert!(error.to_string().contains("slot F9"), "{error}");
    }

    #[test]
    fn refuses_a_chain_in_no_known_format() {
        // The device certificate first: it carries no Yubico claim.
        let attestation = Attestation::from_key_material(BUNDLE).expect("the bundle reads");
        let device = attestation
            .issuers()
            .first()
            .expect("the device certificate");
        let error = AttestationFormat::recognise(device).expect_err("not a Yubico leaf");
        assert!(error.to_string().contains("format Rite reads"), "{error}");
    }

    #[test]
    fn refuses_a_chain_of_the_wrong_length() {
        let attestation = Attestation::from_key_material(BUNDLE).expect("the bundle reads");
        let mut three: Vec<CertificateDer> = attestation.certificates().cloned().collect();
        three.push(attestation.leaf().clone());
        assert!(Attestation::new(AttestationFormat::YubicoPiv, three).is_err());
    }

    #[test]
    fn says_to_remove_the_vendor_certificates_from_a_longer_file() {
        let text = std::str::from_utf8(BUNDLE).unwrap();
        let (_, device) = text.split_once("-----END CERTIFICATE-----").unwrap();
        // The device certificate again, standing in for a vendor intermediate.
        let longer = format!("{text}{}", device.trim_start());
        let error =
            Attestation::from_key_material(longer.as_bytes()).expect_err("three is too many");
        assert!(
            error.to_string().contains("intermediate and root"),
            "{error}"
        );
    }

    #[test]
    fn the_format_name_is_versioned() {
        assert_eq!(AttestationFormat::YubicoPiv.as_str(), "yubico-piv/v1");
        assert_eq!(
            "yubico-piv/v1".parse::<AttestationFormat>().ok(),
            Some(AttestationFormat::YubicoPiv)
        );
    }
}
