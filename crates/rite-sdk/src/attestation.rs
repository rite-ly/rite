//! A device's signed statement about a key.
//!
//! The format determines how the evidence and its claims are represented.
//! Rite currently reads `yubico-piv/v1`.
//!
//! This module holds the evidence and reads its claims. Checking the chain
//! against trusted roots and checking claims against ceremony requirements
//! are separate operations.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::names::names;
use crate::types::ParseError;
use crate::{AccessWhen, BackendError, CertificateDer};

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
    /// The device is FIPS certified: present only on the F9 certificate.
    pub const FIPS_CERTIFIED: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.10");
    /// The device is CSPN certified: present only on the F9 certificate.
    pub const CSPN_CERTIFIED: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.11");
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
        let yubico = extensions(leaf)?
            .iter()
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

    /// Whether `chain`, leaf first, runs through this attestation's own
    /// certificates. The claims are read from them, so a chain checked
    /// through look-alikes found elsewhere vouches for none of them.
    #[must_use]
    pub fn is_start_of(&self, chain: &[CertificateDer]) -> bool {
        let mut chain = chain.iter();
        self.certificates().all(|own| chain.next() == Some(own))
    }

    /// What the attestation states about its key and the device, read as its
    /// format lays the claims out.
    ///
    /// Reading the claims says nothing about who made them: only a chain to
    /// a root the reader trusts does.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidData`] when a certificate does not
    /// parse, or a claim is there twice or with the wrong length.
    pub fn claims(&self) -> Result<AttestedClaims, BackendError> {
        match self.format {
            AttestationFormat::YubicoPiv => {
                let device = self.issuers.first().ok_or_else(|| {
                    BackendError::InvalidData("the attestation has no F9 certificate".to_string())
                })?;
                yubico::claims(&extensions(&self.leaf)?, &extensions(device)?)
            }
        }
    }
}

/// The extensions of `certificate`, none if it carries none.
fn extensions(
    certificate: &CertificateDer,
) -> Result<Vec<x509_cert::ext::Extension>, BackendError> {
    let parsed = Certificate::from_der(certificate.as_bytes())
        .map_err(|e| BackendError::InvalidData(format!("not an X.509 certificate: {e}")))?;
    Ok(parsed
        .tbs_certificate()
        .extensions()
        .cloned()
        .unwrap_or_default())
}

/// What an attestation states about its key and the device holding it.
///
/// Every value is the one stated. A claim the evidence does not make is
/// `None`, never a default, so a requirement on it fails rather than passes
/// on an assumption.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AttestedClaims {
    /// Where the key was made.
    pub origin: AttestedOrigin,
    /// When the device asks for the PIN, or another authentication, before
    /// using the key.
    pub authentication: Option<StatedAccess>,
    /// When the device asks for a touch before using the key.
    pub presence: Option<StatedAccess>,
    /// The device's firmware.
    pub firmware: Option<FirmwareVersion>,
    /// The device's serial number.
    pub serial: Option<u32>,
    /// The device's form factor.
    pub form_factor: Option<FormFactor>,
    /// Certifications the device's own certificate states, such as `FIPS`.
    pub certifications: Vec<&'static str>,
}

/// Where an attested key was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttestedOrigin {
    /// On the device, which never let the private key out.
    Generated,
}

/// An access policy as an attestation states it: a value of the policy
/// type, or a code Rite does not model, such as a biometric policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatedAccess {
    /// A value a ceremony can require.
    Value(AccessWhen),
    /// A code the format defines and Rite does not model; no requirement
    /// accepts it.
    Unmodelled(u8),
}

impl fmt::Display for StatedAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => f.write_str(value.as_str()),
            Self::Unmodelled(code) => write!(f, "unmodelled ({code:#04x})"),
        }
    }
}

/// A device's firmware version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion {
    /// Major version.
    pub major: u8,
    /// Minor version.
    pub minor: u8,
    /// Patch version.
    pub patch: u8,
}

impl fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A YubiKey's form factor, as its attestation codes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormFactor(pub u8);

impl fmt::Display for FormFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The low four bits name the shape; 0x80 marks a FIPS device and
        // 0x40 a Security Key, as `ykman` reads them.
        let shape = match self.0 & 0x0f {
            1 => "USB-A keychain",
            2 => "USB-A nano",
            3 => "USB-C keychain",
            4 => "USB-C nano",
            5 => "USB-C and Lightning",
            6 => "USB-A Bio",
            7 => "USB-C Bio",
            _ => return write!(f, "unknown ({:#04x})", self.0),
        };
        f.write_str(shape)?;
        if self.0 & 0x80 != 0 {
            f.write_str(", FIPS")?;
        }
        if self.0 & 0x40 != 0 {
            f.write_str(", Security Key")?;
        }
        Ok(())
    }
}

/// The claims of a YubiKey PIV attestation: Yubico extensions, the key's
/// from the leaf and the device's certifications from F9.
mod yubico {
    use x509_cert::der::Decode;
    use x509_cert::der::asn1::ObjectIdentifier;
    use x509_cert::ext::Extension;

    use super::{
        AccessWhen, AttestedClaims, AttestedOrigin, BackendError, FirmwareVersion, FormFactor,
        StatedAccess, yubico_oid,
    };
    use crate::{PivPinPolicy, PivTouchPolicy};

    /// The claims in `leaf`'s extensions and `device`'s, F9's.
    pub(super) fn claims(
        leaf: &[Extension],
        device: &[Extension],
    ) -> Result<AttestedClaims, BackendError> {
        let firmware = value(leaf, yubico_oid::FIRMWARE)?
            .map(|bytes| match <[u8; 3]>::try_from(bytes) {
                Ok([major, minor, patch]) => Ok(FirmwareVersion {
                    major,
                    minor,
                    patch,
                }),
                Err(_) => Err(wrong_length("firmware", 3, bytes)),
            })
            .transpose()?;
        let serial = value(leaf, yubico_oid::SERIAL)?
            .map(|bytes| {
                u32::from_der(bytes).map_err(|e| {
                    BackendError::InvalidData(format!(
                        "the attestation's serial is not a DER integer: {e}"
                    ))
                })
            })
            .transpose()?;
        let (authentication, presence) = match value(leaf, yubico_oid::POLICY)? {
            Some(bytes) => match <[u8; 2]>::try_from(bytes) {
                Ok([pin, touch]) => (Some(pin_policy(pin)), Some(touch_policy(touch))),
                Err(_) => return Err(wrong_length("policy", 2, bytes)),
            },
            None => (None, None),
        };
        let form_factor = value(leaf, yubico_oid::FORM_FACTOR)?
            .map(|bytes| match <[u8; 1]>::try_from(bytes) {
                Ok([code]) => Ok(FormFactor(code)),
                Err(_) => Err(wrong_length("form factor", 1, bytes)),
            })
            .transpose()?;
        let mut certifications = Vec::new();
        if value(device, yubico_oid::FIPS_CERTIFIED)?.is_some() {
            certifications.push("FIPS");
        }
        if value(device, yubico_oid::CSPN_CERTIFIED)?.is_some() {
            certifications.push("CSPN");
        }
        Ok(AttestedClaims {
            // A YubiKey attests only keys it generated.
            origin: AttestedOrigin::Generated,
            authentication,
            presence,
            firmware,
            serial,
            form_factor,
            certifications,
        })
    }

    /// The value of the one extension `oid` names, if the certificate
    /// carries it.
    fn value(
        extensions: &[Extension],
        oid: ObjectIdentifier,
    ) -> Result<Option<&[u8]>, BackendError> {
        let mut found = extensions
            .iter()
            .filter(|extension| extension.extn_id == oid);
        let first = found.next();
        if found.next().is_some() {
            return Err(BackendError::InvalidData(format!(
                "the attestation carries extension {oid} twice"
            )));
        }
        Ok(first.map(|extension| extension.extn_value.as_bytes()))
    }

    fn wrong_length(claim: &str, expected: usize, bytes: &[u8]) -> BackendError {
        BackendError::InvalidData(format!(
            "the attestation's {claim} is {} bytes, not {expected}",
            bytes.len()
        ))
    }

    /// The PIN policy stated as `code`.
    fn pin_policy(code: u8) -> StatedAccess {
        PivPinPolicy::from_attestation_code(code)
            .and_then(AccessWhen::from_pin_policy)
            .map_or(StatedAccess::Unmodelled(code), StatedAccess::Value)
    }

    /// The touch policy stated as `code`.
    fn touch_policy(code: u8) -> StatedAccess {
        PivTouchPolicy::from_attestation_code(code)
            .and_then(AccessWhen::from_touch_policy)
            .map_or(StatedAccess::Unmodelled(code), StatedAccess::Value)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use x509_cert::der::asn1::OctetString;

        fn extension(oid: ObjectIdentifier, value: &[u8]) -> Extension {
            Extension {
                extn_id: oid,
                critical: false,
                extn_value: OctetString::new(value).unwrap(),
            }
        }

        fn leaf(policy: &[u8]) -> Vec<Extension> {
            vec![
                extension(yubico_oid::FIRMWARE, &[5, 7, 1]),
                // DER INTEGER 32456360.
                extension(yubico_oid::SERIAL, &[0x02, 0x04, 0x01, 0xef, 0x3e, 0xa8]),
                extension(yubico_oid::POLICY, policy),
                extension(yubico_oid::FORM_FACTOR, &[0x83]),
            ]
        }

        #[test]
        fn reads_every_claim_as_stated() {
            let device = [extension(yubico_oid::FIPS_CERTIFIED, &[])];
            let claims = claims(&leaf(&[3, 3]), &device).unwrap();
            assert_eq!(claims.origin, AttestedOrigin::Generated);
            assert_eq!(
                claims.authentication,
                Some(StatedAccess::Value(AccessWhen::PerUse))
            );
            assert_eq!(
                claims.presence,
                Some(StatedAccess::Value(AccessWhen::Cached))
            );
            assert_eq!(claims.firmware.unwrap().to_string(), "5.7.1");
            assert_eq!(claims.serial, Some(32_456_360));
            assert_eq!(
                claims.form_factor.unwrap().to_string(),
                "USB-C keychain, FIPS"
            );
            assert_eq!(claims.certifications, ["FIPS"]);
        }

        #[test]
        fn a_code_rite_does_not_model_is_reported_as_such() {
            let claims = claims(&leaf(&[4, 1]), &[]).unwrap();
            assert_eq!(claims.authentication, Some(StatedAccess::Unmodelled(4)));
            assert_eq!(
                claims.presence,
                Some(StatedAccess::Value(AccessWhen::Never))
            );
        }

        #[test]
        fn a_claim_left_out_is_none_not_a_default() {
            let only_firmware = [extension(yubico_oid::FIRMWARE, &[4, 3, 0])];
            let claims = claims(&only_firmware, &[]).unwrap();
            assert_eq!(claims.authentication, None);
            assert_eq!(claims.serial, None);
            assert!(claims.certifications.is_empty());
        }

        #[test]
        fn refuses_a_claim_of_the_wrong_length_or_given_twice() {
            let error = claims(&leaf(&[3]), &[]).unwrap_err();
            assert!(
                error.to_string().contains("policy is 1 bytes, not 2"),
                "{error}"
            );
            let mut twice = leaf(&[3, 3]);
            twice.push(extension(yubico_oid::POLICY, &[1, 1]));
            let error = claims(&twice, &[]).unwrap_err();
            assert!(error.to_string().contains("twice"), "{error}");
        }

        #[test]
        fn a_form_factor_reads_its_shape_under_its_flags() {
            assert_eq!(FormFactor(0x43).to_string(), "USB-C keychain, Security Key");
            assert_eq!(FormFactor(0x87).to_string(), "USB-C Bio, FIPS");
            assert_eq!(FormFactor(0x00).to_string(), "unknown (0x00)");
        }

        #[test]
        fn certifications_count_on_the_device_certificate_only() {
            let mut on_leaf = leaf(&[3, 3]);
            on_leaf.push(extension(yubico_oid::FIPS_CERTIFIED, &[]));
            assert!(claims(&on_leaf, &[]).unwrap().certifications.is_empty());
        }
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
