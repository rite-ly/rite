//! The forms a public key arrives in at a step that reads one: a recipient of
//! `wrap_key` or `encrypt_data`, the key of `verify_signature`.
//!
//! The algorithm rows give the key one way, as the SPKI DER file. These are
//! the other ways a ceremony meets the same key, each a row of its family's
//! shape table, so a form the step does not take is a refusal stated like any
//! other.

use std::path::PathBuf;

use rite_runtime::ArtifactValue;
use rite_sdk::{CertificateDer, PublicKeyDer};
use x509_cert::der::pem;

use crate::keys::{TestKey, fixtures_dir, read};
use crate::session::{Refused, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The SPKI as DER bytes from a file, as the algorithm rows give it.
    SpkiDer,
    /// The SPKI armoured as `PUBLIC KEY`, the usual file a counterparty sends.
    SpkiPem,
    /// A certificate carrying the key, as DER bytes from a file.
    CertificateDer,
    /// The same, armoured as `CERTIFICATE`.
    CertificatePem,
    /// A public key artifact, as `export_public` produces.
    PublicKey,
    /// A certificate artifact, as `issue_certificate` or
    /// `piv_read_certificate` produces.
    Certificate,
    /// The keypair itself, held by the backend.
    Keypair,
}

impl Shape {
    pub const ALL: &'static [Shape] = &[
        Shape::SpkiDer,
        Shape::SpkiPem,
        Shape::CertificateDer,
        Shape::CertificatePem,
        Shape::PublicKey,
        Shape::Certificate,
        Shape::Keypair,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Shape::SpkiDer => "spki-der",
            Shape::SpkiPem => "spki-pem",
            Shape::CertificateDer => "certificate-der",
            Shape::CertificatePem => "certificate-pem",
            Shape::PublicKey => "public-key",
            Shape::Certificate => "certificate",
            Shape::Keypair => "keypair",
        }
    }
}

/// The keys the shape tables use, each with a committed self-signed
/// certificate under `fixtures/certificates/`.
pub const CERTIFIED: &[TestKey] = &[TestKey::P256];

pub fn certificates_dir() -> PathBuf {
    fixtures_dir().join("certificates")
}

pub fn certificate_path(key: TestKey) -> PathBuf {
    certificates_dir().join(format!("{}.crt.der", key.stem()))
}

impl Session {
    /// Put `key`'s public half in place as `id`, in `shape`. A keypair is
    /// imported with `usages`; every other shape is a material.
    pub fn present(
        &mut self,
        shape: Shape,
        key: TestKey,
        id: &str,
        usages: &[&str],
    ) -> Result<(), Refused> {
        let spki = || key.public().expect("a shaped key is a keypair");
        let certificate = || read(&certificate_path(key));
        let value = match shape {
            Shape::Keypair => return self.import_for(key, id, usages, false),
            Shape::SpkiDer => ArtifactValue::Bytes(spki()),
            Shape::SpkiPem => ArtifactValue::Bytes(pem("PUBLIC KEY", &spki())),
            Shape::CertificateDer => ArtifactValue::Bytes(certificate()),
            Shape::CertificatePem => ArtifactValue::Bytes(pem("CERTIFICATE", &certificate())),
            Shape::PublicKey => {
                ArtifactValue::PublicKey(PublicKeyDer::new(spki()).expect("the SPKI parses"))
            }
            Shape::Certificate => ArtifactValue::Certificate(
                CertificateDer::new(certificate()).expect("the certificate parses"),
            ),
        };
        self.add(id, value);
        Ok(())
    }
}

/// `der` armoured under `label` (RFC 7468).
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    pem::encode_string(label, pem::LineEnding::LF, der)
        .expect("DER armours")
        .into_bytes()
}
