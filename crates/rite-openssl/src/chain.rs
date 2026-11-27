//! Certificate chain checks against roots a ceremony names.

use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509, X509StoreContext, X509VerifyResult};
use rite_sdk::{BackendError, CertificateDer};

/// The chain OpenSSL built from a leaf to one of the roots it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// Leaf first, the root last; never empty.
    certificates: Vec<CertificateDer>,
}

impl VerifiedChain {
    /// The certificates of the chain, leaf first, the matching root last.
    #[must_use]
    pub fn certificates(&self) -> &[CertificateDer] {
        &self.certificates
    }

    /// The root the chain ends at: the one of the roots given that it
    /// matched.
    #[must_use]
    pub fn root(&self) -> Option<&CertificateDer> {
        self.certificates.last()
    }
}

/// Whether a chain was built to a trusted root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainOutcome {
    /// It was, through these certificates.
    Trusted(VerifiedChain),
    /// It was not, for the reason given.
    Refused(String),
}

/// Check that `leaf` chains to one of `roots` at the instant `at`, a Unix
/// time, through `untrusted` certificates.
///
/// Only `roots` are trust anchors. A certificate in `untrusted` never is,
/// even if it is self-signed; a chain that stops short of a root is refused.
/// No purpose is checked. The time is explicit so a repeated check can use
/// the same instant.
///
/// An issuer that is not marked as a CA is refused.
///
/// # Errors
///
/// Returns [`BackendError::Other`] when OpenSSL cannot parse a certificate or
/// set up the check.
pub fn verify_certificate_chain(
    leaf: &CertificateDer,
    untrusted: &[CertificateDer],
    roots: &[CertificateDer],
    at: i64,
) -> Result<ChainOutcome, BackendError> {
    let fail = |what: &str, e: &openssl::error::ErrorStack| {
        BackendError::Other(format!("certificate chain check: {what}: {e}"))
    };
    let parse = |certificate: &CertificateDer| {
        X509::from_der(certificate.as_bytes()).map_err(|e| fail("certificate", &e))
    };

    let mut store = X509StoreBuilder::new().map_err(|e| fail("store", &e))?;
    for root in roots {
        store
            .add_cert(parse(root)?)
            .map_err(|e| fail("adding a root", &e))?;
    }
    let mut param = X509VerifyParam::new().map_err(|e| fail("parameters", &e))?;
    param.set_time(at);
    store
        .set_param(&param)
        .map_err(|e| fail("parameters", &e))?;
    let store = store.build();

    let mut chain = Stack::new().map_err(|e| fail("untrusted list", &e))?;
    for certificate in untrusted {
        chain
            .push(parse(certificate)?)
            .map_err(|e| fail("untrusted list", &e))?;
    }
    let leaf = parse(leaf)?;

    let mut context = X509StoreContext::new().map_err(|e| fail("context", &e))?;
    let built = context
        .init(&store, &leaf, &chain, |context| {
            if !context.verify_cert()? {
                return Ok(Err(refusal(context.error(), context.error_depth())));
            }
            let built = match context.chain() {
                Some(chain) => chain
                    .iter()
                    .map(openssl::x509::X509Ref::to_der)
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            };
            Ok(Ok(built))
        })
        .map_err(|e| fail("verifying", &e))?;
    let built = match built {
        Ok(built) => built,
        Err(reason) => return Ok(ChainOutcome::Refused(reason)),
    };
    let certificates = built
        .into_iter()
        .map(CertificateDer::new)
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Ok(ChainOutcome::Refused(
            "OpenSSL accepted the chain and reported no certificates".to_string(),
        ));
    }
    Ok(ChainOutcome::Trusted(VerifiedChain { certificates }))
}

/// What [`verify_certificate_chain`] checks with and how, for a record: the
/// OpenSSL version this build runs and the settings the check uses.
#[must_use]
pub fn chain_verifier() -> String {
    format!(
        "{}; partial chains off, no purpose check",
        openssl::version::version()
    )
}

/// Why OpenSSL refused, said for an attestation: `depth` 0 is the leaf.
fn refusal(error: X509VerifyResult, depth: u32) -> String {
    // An issuer without CA:TRUE.
    if error.as_raw() == openssl_sys::X509_V_ERR_INVALID_CA {
        return format!(
            "the certificate at depth {depth} issues another without being marked as a CA"
        );
    }
    format!(
        "{} (at depth {depth}, 0 being the leaf)",
        error.error_string()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::X509NameBuilder;
    use openssl::x509::extension::BasicConstraints;

    /// 2030-01-01, inside every test certificate's validity.
    const AT: i64 = 1_893_456_000;

    fn key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A certificate for `subject`'s key, issued by `issuer` (itself when
    /// `None`), a CA when `ca`.
    fn certificate(
        name: &str,
        subject: &PKey<Private>,
        issuer: Option<(&X509, &PKey<Private>)>,
        ca: bool,
    ) -> X509 {
        let mut x509_name = X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("CN", name).unwrap();
        let x509_name = x509_name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&x509_name).unwrap();
        builder.set_pubkey(subject).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(AT - 86_400).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(AT + 86_400).unwrap())
            .unwrap();
        if ca {
            builder
                .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        let (issuer_name, signer) = match issuer {
            Some((certificate, key)) => (certificate.subject_name().to_owned().unwrap(), key),
            None => (x509_name, subject),
        };
        builder.set_issuer_name(&issuer_name).unwrap();
        builder.sign(signer, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    fn der(certificate: &X509) -> CertificateDer {
        CertificateDer::new(certificate.to_der().unwrap()).unwrap()
    }

    /// Root, intermediate, device certificate and leaf, as a YubiKey of
    /// firmware 5.7.4 and later chains.
    struct Chain {
        root: X509,
        intermediate: X509,
        device: X509,
        leaf: X509,
    }

    fn chain(device_is_ca: bool) -> Chain {
        let (root_key, intermediate_key, device_key) = (key(), key(), key());
        let root = certificate("Root", &root_key, None, true);
        let intermediate = certificate(
            "Intermediate",
            &intermediate_key,
            Some((&root, &root_key)),
            true,
        );
        let device = certificate(
            "Device",
            &device_key,
            Some((&intermediate, &intermediate_key)),
            device_is_ca,
        );
        let leaf = certificate("Leaf", &key(), Some((&device, &device_key)), false);
        Chain {
            root,
            intermediate,
            device,
            leaf,
        }
    }

    #[test]
    fn builds_the_chain_through_untrusted_certificates_to_a_root() {
        let c = chain(true);
        let outcome = verify_certificate_chain(
            &der(&c.leaf),
            &[der(&c.device), der(&c.intermediate)],
            &[der(&c.root)],
            AT,
        )
        .unwrap();
        let ChainOutcome::Trusted(verified) = outcome else {
            panic!("refused: {outcome:?}");
        };
        let expected = [&c.leaf, &c.device, &c.intermediate, &c.root].map(der);
        assert_eq!(verified.certificates(), expected);
        assert_eq!(verified.root(), Some(&der(&c.root)));
    }

    #[test]
    fn an_untrusted_certificate_is_never_an_anchor() {
        let c = chain(true);
        // The intermediate is in the untrusted list and the root missing: a
        // chain stopping at the intermediate is refused.
        let outcome = verify_certificate_chain(
            &der(&c.leaf),
            &[der(&c.device), der(&c.intermediate)],
            &[],
            AT,
        )
        .unwrap();
        assert!(matches!(outcome, ChainOutcome::Refused(_)), "{outcome:?}");
        // Nor is the device certificate, though it issued the leaf.
        let outcome =
            verify_certificate_chain(&der(&c.leaf), &[], &[der(&c.intermediate)], AT).unwrap();
        assert!(matches!(outcome, ChainOutcome::Refused(_)), "{outcome:?}");
    }

    #[test]
    fn checks_at_the_time_given() {
        let c = chain(true);
        let outcome = verify_certificate_chain(
            &der(&c.leaf),
            &[der(&c.device), der(&c.intermediate)],
            &[der(&c.root)],
            AT + 10 * 86_400,
        )
        .unwrap();
        let ChainOutcome::Refused(reason) = outcome else {
            panic!("an expired chain was trusted");
        };
        assert!(reason.contains("expired"), "{reason}");
    }

    #[test]
    fn names_an_issuer_that_is_not_a_ca() {
        let c = chain(false);
        let outcome = verify_certificate_chain(
            &der(&c.leaf),
            &[der(&c.device), der(&c.intermediate)],
            &[der(&c.root)],
            AT,
        )
        .unwrap();
        let ChainOutcome::Refused(reason) = outcome else {
            panic!("a chain through a non-CA issuer was trusted");
        };
        assert!(reason.contains("marked as a CA"), "{reason}");
    }
}
