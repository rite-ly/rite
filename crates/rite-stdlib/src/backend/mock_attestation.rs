//! The attestation a mock backend gives: a YubiKey PIV attestation in form,
//! under a rehearsal root.
//!
//! The leaf is issued at attest time over the key's actual public key, so the
//! statement names the key a rehearsal holds, which is a fresh key for most
//! algorithms. It is signed by a committed stand-in for a YubiKey's F9 key,
//! whose certificate chains to [`MOCK_ATTESTATION_ROOT`]. Both private keys
//! are public by being committed: anyone can make a chain to the mock root,
//! so it proves nothing beyond the shape of the evidence.

use rite_sdk::{
    AccessPolicy, AccessWhen, Attestation, AttestationFormat, BackendError, CertificateDer,
    KeyAlgorithm, PivSlot, PivTouchPolicy, PublicKeyDer, SignAlgorithm,
};
use x509_cert::Certificate;
use x509_cert::builder::{Builder, CertificateBuilder, profile::BuilderProfile};
use x509_cert::der::asn1::{BitString, OctetString};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::{TbsCertificate, time::Validity};

use rite_sdk::yubico_oid::{FIRMWARE, FORM_FACTOR, POLICY, SERIAL};

use crate::pki::issuing_key::BackendIssuingKey;
use crate::pki::oids::sig_profile_for_algorithm;

/// The self-signed root a mock attestation chains to, in DER.
///
/// Made for rehearsals with `openssl req -x509` (P-256, CA, 100 years); its
/// private key was not kept.
pub const MOCK_ATTESTATION_ROOT: &[u8] = include_bytes!("fixtures/mock-attestation-root.der");

/// The stand-in for a YubiKey's F9 certificate, issued by
/// [`MOCK_ATTESTATION_ROOT`] as a CA with path length 0, in DER.
pub(super) const MOCK_ATTESTATION_F9: &[u8] = include_bytes!("fixtures/mock-attestation-f9.der");

/// The private half of [`MOCK_ATTESTATION_F9`], in PKCS#8 DER. Secret only in
/// form, like the slot key: committed so a rehearsal can issue leaves.
pub(super) const MOCK_ATTESTATION_F9_KEY: &[u8] =
    include_bytes!("fixtures/mock-attestation-f9.pkcs8.der");

/// The algorithm of [`MOCK_ATTESTATION_F9_KEY`].
pub(super) const F9_ALGORITHM: KeyAlgorithm = KeyAlgorithm::EcdsaP256;

/// Issue a mock attestation for `public_key`, the key behind `key_id`.
///
/// `sign` signs the TBS certificate with [`MOCK_ATTESTATION_F9_KEY`] under the
/// algorithm it is given. The stated policies are `access`, what the step that
/// generated the key set, and the default ones of the slot `key_id` names (or
/// of 9A for a key that names none) for the rest; the firmware, serial and
/// form factor are zero, so no reader takes them for a device's.
pub(super) fn attest(
    key_id: &str,
    public_key: &PublicKeyDer,
    access: AccessPolicy,
    sign: impl FnOnce(&[u8], SignAlgorithm) -> Result<Vec<u8>, BackendError>,
) -> Result<Attestation, BackendError> {
    let invalid = |what: &str, e: &dyn std::fmt::Display| {
        BackendError::InvalidData(format!("mock attestation: {what}: {e}"))
    };
    let f9 = Certificate::from_der(MOCK_ATTESTATION_F9)
        .map_err(|e| invalid("the F9 fixture does not parse", &e))?;
    let slot = PivSlot::from_hint(key_id).unwrap_or(PivSlot::GENERATE_DEFAULT);
    let profile = LeafProfile {
        issuer: f9.tbs_certificate().subject().clone(),
        subject: format!("CN=YubiKey PIV Attestation {:02x}", slot.key_reference())
            .parse()
            .map_err(|e| invalid("subject", &e))?,
        extensions: extensions(slot, access).map_err(|e| invalid("extensions", &e))?,
    };
    let spki = SubjectPublicKeyInfoOwned::from_der(public_key.as_bytes())
        .map_err(|e| invalid("the key's public half", &e))?;
    // A device copies its F9 certificate's dates, so the leaf carries no time.
    let validity: Validity = *f9.tbs_certificate().validity();
    let serial = SerialNumber::new(&[1]).map_err(|e| invalid("serial", &e))?;

    let (sign_algorithm, identifier, _) =
        sig_profile_for_algorithm(F9_ALGORITHM).map_err(|e| invalid("signature", &e))?;
    let issuing_key = BackendIssuingKey::new(
        f9.tbs_certificate().subject_public_key_info().clone(),
        identifier,
    );
    let mut builder = CertificateBuilder::new(profile, serial, validity, spki)
        .map_err(|e| invalid("builder", &e))?;
    let tbs = builder
        .finalize(&issuing_key)
        .map_err(|e| invalid("TBS encoding", &e))?;
    let signature = sign(&tbs, sign_algorithm)?;
    let signature = BitString::from_bytes(&signature).map_err(|e| invalid("signature", &e))?;
    let leaf = builder
        .assemble(signature, &issuing_key)
        .map_err(|e| invalid("assembly", &e))?
        .to_der()
        .map_err(|e| invalid("DER encoding", &e))?;

    Attestation::new(
        AttestationFormat::YubicoPiv,
        vec![
            CertificateDer::new(leaf)?,
            CertificateDer::new(MOCK_ATTESTATION_F9.to_vec())?,
        ],
    )
}

/// The Yubico extensions for a key in `slot` under `access`, as a device
/// writes them: the firmware as three bytes, the serial as a DER integer, the
/// PIN and touch policies as one byte each, the form factor as one byte. An
/// axis `access` leaves out, or a value a `YubiKey` cannot enforce, states the
/// slot's default.
fn extensions(
    slot: PivSlot,
    access: AccessPolicy,
) -> Result<Vec<Extension>, x509_cert::der::Error> {
    let pin = access
        .authentication
        .and_then(AccessWhen::to_pin_policy)
        .unwrap_or(slot.default_pin_policy())
        .attestation_code();
    // Touch is never by default on every slot.
    let touch = access
        .presence
        .and_then(AccessWhen::to_touch_policy)
        .unwrap_or(PivTouchPolicy::Never)
        .attestation_code();
    let serial = 0u32.to_der()?;
    [
        (FIRMWARE, vec![0, 0, 0]),
        (SERIAL, serial),
        (POLICY, vec![pin, touch]),
        (FORM_FACTOR, vec![0]),
    ]
    .into_iter()
    .map(|(extn_id, value)| {
        Ok(Extension {
            extn_id,
            critical: false,
            extn_value: OctetString::new(value)?,
        })
    })
    .collect()
}

/// The builder profile of a mock leaf: names and the Yubico extensions, and
/// nothing else, as a device issues it.
struct LeafProfile {
    issuer: Name,
    subject: Name,
    extensions: Vec<Extension>,
}

impl BuilderProfile for LeafProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(self.extensions.clone())
    }
}
