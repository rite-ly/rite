//! How a container names a public-key recipient, and who finds the recipient
//! by that name.
//!
//! A `KeyTransRecipientInfo` or a `KeyAgreeRecipientInfo` names its recipient
//! by subject key identifier or by issuer and serial number. The holder's
//! tools look for that name: Rite derives the names a key goes by and compares,
//! `openssl cms -decrypt -recip` compares with the certificate it is given, and
//! `openssl cms -decrypt -inkey` alone compares with nothing and tries the key.
//!
//! A certificate's subject key identifier is whatever its issuer chose: the
//! SHA-1 of RFC 5280 method 1 from OpenSSL's defaults, the truncated SHA-256 of
//! RFC 7093 method 1 from Let's Encrypt, other bytes from another issuer, or
//! none at all. Each row is one recipient, in one of those certificates, and
//! one writer; it becomes four tests:
//!
//! - `::names`: the bytes the container names the recipient by, compared with
//!   the SHA-1 of the key's bits or the certificate's identifier, as OpenSSL
//!   reads them.
//! - `::rite_opens`: `decrypt_data` with the recipient's key.
//! - `::openssl_opens_with_key`: `openssl cms -decrypt -inkey`.
//! - `::openssl_opens_with_certificate`: the same with `-recip` and the
//!   recipient's certificate.
//!
//! Every certificate is made by the command line, so the rows need it and are
//! skipped without it. A row's certificate and container are made once and
//! shared by its four tests.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use libtest_mimic::Trial;
use rite_model::FileKind;
use rite_runtime::ArtifactValue;
use rite_sdk::{CertificateDer, cms};
use rite_stdlib::{EncryptDataAction, WrapKeyAction};
use serde_json::json;
use x509_cert::der::Decode;
use x509_cert::spki::SubjectPublicKeyInfoRef;

use super::cases::{KDF_SHA256, OAEP_SHA256};
use super::model::{Payload, ReadStep};
use super::{check_opened, run_open, ski_of};
use crate::cli::{Cli, arg};
use crate::harness::{Skip, trial};
use crate::keys::TestKey;
use crate::session::Session;

/// The subject key identifier in the recipient's certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ski {
    /// The SHA-1 of the public key's bits, RFC 5280 method 1: OpenSSL's
    /// default, and most issuers'.
    Rfc5280,
    /// The leftmost 160 bits of their SHA-256, RFC 7093 method 1, which Let's
    /// Encrypt writes.
    Rfc7093,
    /// Bytes derived from nothing a reader has.
    Foreign,
    /// No subject key identifier.
    Absent,
}

impl Ski {
    fn name(self) -> &'static str {
        match self {
            Ski::Rfc5280 => "ski-rfc5280",
            Ski::Rfc7093 => "ski-rfc7093",
            Ski::Foreign => "ski-foreign",
            Ski::Absent => "no-ski",
        }
    }

    /// The `subjectKeyIdentifier` value the command line writes.
    fn extension(self, key: TestKey) -> String {
        match self {
            Ski::Rfc5280 => "hash".to_string(),
            Ski::Rfc7093 => {
                let digest = openssl::sha::sha256(&public_bits(key));
                base16ct::upper::encode_string(&digest[..20])
            }
            Ski::Foreign => "5A".repeat(20),
            Ski::Absent => "none".to_string(),
        }
    }
}

/// The bits of `key`'s public key, which both RFC 5280 and RFC 7093 hash.
pub(super) fn public_bits(key: TestKey) -> Vec<u8> {
    let spki = key.public().expect("a recipient is a keypair");
    let spki = SubjectPublicKeyInfoRef::from_der(&spki).expect("the SPKI parses");
    spki.subject_public_key
        .as_bytes()
        .expect("a public key is whole bytes")
        .to_vec()
}

/// What a writer is given to address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Given {
    /// The public key alone, as SPKI DER.
    Key,
    /// The certificate, as a `certificate` artifact.
    Certificate,
    /// The certificate, as a DER file read as bytes.
    CertificateFile,
}

/// Who writes the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writer {
    /// `encrypt_data` with `recipient:`.
    Rite(Given),
    /// `wrap_key` with `recipient:`, of a key whose PKCS#8 is the payload.
    RiteWraps(Given),
    /// `openssl cms -encrypt -recip` with the certificate, `-keyid` or not.
    OpenSsl { keyid: bool },
}

/// What the container names the recipient by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    /// The SHA-1 of the key's bits, RFC 5280 method 1: what OpenSSL would put
    /// in a certificate for it.
    Rfc5280,
    /// The certificate's subject key identifier.
    CertificateSki,
    /// The certificate's issuer and serial number.
    IssuerAndSerial,
}

/// Whether a reader opens the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opens {
    Yes,
    /// It does not, and says this.
    No(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub key: TestKey,
    pub certificate: Ski,
    pub writer: Writer,
    pub named: Named,
    pub rite: Opens,
    pub openssl_with_certificate: Opens,
}

impl Row {
    fn name(&self) -> String {
        let writer = match self.writer {
            Writer::Rite(Given::Key) => "rite::to-key",
            Writer::Rite(Given::Certificate) => "rite::to-certificate",
            Writer::Rite(Given::CertificateFile) => "rite::to-certificate-file",
            Writer::RiteWraps(Given::Key) => "rite-wrap::to-key",
            Writer::RiteWraps(Given::Certificate) => "rite-wrap::to-certificate",
            Writer::RiteWraps(Given::CertificateFile) => "rite-wrap::to-certificate-file",
            Writer::OpenSsl { keyid: true } => "openssl::keyid",
            Writer::OpenSsl { keyid: false } => "openssl::issuer-serial",
        };
        format!(
            "recipient_id::{writer}::{}::{}",
            self.key.stem(),
            self.certificate.name()
        )
    }
}

const NOT_ADDRESSED: &str = "addressed to the key identified by";
const ISSUER_SERIAL: &str = "issuer and serial number";
/// What `openssl cms -decrypt -recip` says when no recipient names its
/// certificate.
const NO_MATCH: &str = "Error decrypting CMS";

/// A row without its key: the certificate, the writer, the name the container
/// gives, and whether Rite and `openssl -recip` open it. `openssl -inkey`
/// opens every one.
type Case = (Ski, Writer, Named, Opens, Opens);

use Named::{CertificateSki, IssuerAndSerial, Rfc5280};
use Opens::{No, Yes};
use Writer::{OpenSsl, Rite, RiteWraps};

const KEYID: Writer = OpenSsl { keyid: true };
const ISSUER: Writer = OpenSsl { keyid: false };

/// RSA-2048 is key transport and P-256 key agreement; both name the
/// recipient the same ways, so each key gets every case.
#[rustfmt::skip]
const CASES: &[Case] = &[
    // Given the key alone, Rite names it as OpenSSL would in a certificate, so
    // a certificate made the usual way finds it, and one made another way
    // does not.
    (Ski::Rfc5280, Rite(Given::Key), Rfc5280, Yes, Yes),
    (Ski::Rfc7093, Rite(Given::Key), Rfc5280, Yes, No(NO_MATCH)),
    // Given the certificate, Rite names the recipient as the certificate does,
    // whichever way it is passed.
    (Ski::Rfc5280, Rite(Given::Certificate), CertificateSki, Yes, Yes),
    (Ski::Rfc5280, Rite(Given::CertificateFile), CertificateSki, Yes, Yes),
    (Ski::Rfc7093, Rite(Given::Certificate), CertificateSki, Yes, Yes),
    // An identifier no key derives still finds the certificate, but Rite,
    // holding only the key, cannot tell it is addressed to it.
    (Ski::Foreign, Rite(Given::Certificate), CertificateSki, No(NOT_ADDRESSED), Yes),
    // A certificate with no identifier names nothing; the key is named as if
    // given alone, and `-recip` has nothing to compare it with.
    (Ski::Absent, Rite(Given::Certificate), Rfc5280, Yes, No(NO_MATCH)),
    // `wrap_key` names its recipient as `encrypt_data` does.
    (Ski::Rfc5280, RiteWraps(Given::Key), Rfc5280, Yes, Yes),
    (Ski::Rfc5280, RiteWraps(Given::Certificate), CertificateSki, Yes, Yes),
    (Ski::Rfc7093, RiteWraps(Given::CertificateFile), CertificateSki, Yes, Yes),
    // What `openssl cms -encrypt` writes, and Rite reads.
    (Ski::Rfc5280, KEYID, CertificateSki, Yes, Yes),
    (Ski::Rfc7093, KEYID, CertificateSki, Yes, Yes),
    (Ski::Foreign, KEYID, CertificateSki, No(NOT_ADDRESSED), Yes),
    (Ski::Rfc5280, ISSUER, IssuerAndSerial, No(ISSUER_SERIAL), Yes),
    (Ski::Absent, ISSUER, IssuerAndSerial, No(ISSUER_SERIAL), Yes),
];

fn rows() -> impl Iterator<Item = Row> {
    [TestKey::Rsa2048, TestKey::P256]
        .into_iter()
        .flat_map(|key| {
            CASES.iter().map(
                move |&(certificate, writer, named, rite, with_certificate)| Row {
                    key,
                    certificate,
                    writer,
                    named,
                    rite,
                    openssl_with_certificate: with_certificate,
                },
            )
        })
}

pub fn trials() -> Vec<Trial> {
    rows()
        .flat_map(|row| {
            let name = row.name();
            let skip = || {
                Cli::get()
                    .is_none()
                    .then(|| Skip::Cli("no openssl command line".into()))
            };
            let shared = Shared::default();
            let (names, rite, with_key, with_certificate) =
                (shared.clone(), shared.clone(), shared.clone(), shared);
            vec![
                trial(format!("{name}::names"), skip(), move || {
                    check_named(&row, &names)
                }),
                trial(format!("{name}::rite_opens"), skip(), move || {
                    rite_opens(&row, &rite)
                }),
                trial(
                    format!("{name}::openssl_opens_with_key"),
                    skip(),
                    move || openssl_opens(&row, &with_key, false),
                ),
                trial(
                    format!("{name}::openssl_opens_with_certificate"),
                    skip(),
                    move || openssl_opens(&row, &with_certificate, true),
                ),
            ]
        })
        .collect()
}

/// A row's certificate and container, in a directory of their own.
struct Sealed {
    _dir: tempfile::TempDir,
    certificate: PathBuf,
    certificate_der: Vec<u8>,
    container: Vec<u8>,
    container_path: PathBuf,
}

/// What a row's tests share: its container, sealed by whichever test runs
/// first.
type Shared = Arc<OnceLock<Result<Sealed, String>>>;

fn sealed<'a>(row: &Row, shared: &'a Shared) -> Result<&'a Sealed, String> {
    shared
        .get_or_init(|| seal(row))
        .as_ref()
        .map_err(Clone::clone)
}

fn seal(row: &Row) -> Result<Sealed, String> {
    let cli = Cli::get().expect("skipped without the command line");
    let dir = tempfile::tempdir().expect("a temporary directory");
    let certificate = certify(cli, dir.path(), row)?;
    let certificate_der = CertificateDer::from_key_material(
        &std::fs::read(&certificate).expect("the certificate is read"),
    )
    .expect("the certificate parses");
    let container = match row.writer {
        Writer::Rite(given) => rite_seals(row.key, given, &certificate_der)?,
        Writer::RiteWraps(given) => rite_wraps(row.key, given, &certificate_der)?,
        Writer::OpenSsl { keyid } => openssl_seals(cli, dir.path(), row.key, keyid, &certificate)?,
    };
    let container_path = dir.path().join("sealed.der");
    std::fs::write(&container_path, &container).expect("the container is written");
    Ok(Sealed {
        _dir: dir,
        certificate,
        certificate_der: certificate_der.as_bytes().to_vec(),
        container,
        container_path,
    })
}

/// A self-signed certificate for the row's key, with its subject key
/// identifier, as PEM.
fn certify(cli: &Cli, dir: &Path, row: &Row) -> Result<PathBuf, String> {
    let out = dir.join("recipient.crt");
    cli.run(&[
        "req",
        "-new",
        "-x509",
        "-key",
        arg(&row.key.private_path()),
        "-keyform",
        "DER",
        "-subj",
        "/CN=recipient",
        "-days",
        "1",
        "-addext",
        &format!(
            "subjectKeyIdentifier={}",
            row.certificate.extension(row.key)
        ),
        "-out",
        arg(&out),
    ])?;
    Ok(out)
}

fn payload() -> Vec<u8> {
    Payload::P256.key().private()
}

/// The recipient as `given`, put in place as `recipient`.
fn present(session: &mut Session, key: TestKey, given: Given, certificate: &CertificateDer) {
    let recipient = match given {
        Given::Key => ArtifactValue::Bytes(key.public().expect("a keypair")),
        Given::Certificate => ArtifactValue::Certificate(certificate.clone()),
        Given::CertificateFile => ArtifactValue::Bytes(certificate.as_bytes().to_vec()),
    };
    session.add("recipient", recipient);
}

fn rite_seals(key: TestKey, given: Given, certificate: &CertificateDer) -> Result<Vec<u8>, String> {
    let mut session = Session::new();
    session.add("payload", ArtifactValue::Bytes(payload()));
    present(&mut session, key, given, certificate);
    session
        .run(
            &EncryptDataAction,
            "sealed",
            &[("data", "payload"), ("recipient", "recipient")],
            &json!({}),
        )
        .map_err(|(at, e)| format!("encrypt_data failed at {at:?}: {e}"))?;
    match session.artifact("sealed") {
        ArtifactValue::EncryptedData(sealed) => Ok(sealed.data().to_vec()),
        other => Err(format!("encrypt_data produced {other:?}")),
    }
}

fn rite_wraps(key: TestKey, given: Given, certificate: &CertificateDer) -> Result<Vec<u8>, String> {
    let mut session = Session::new();
    session
        .import(Payload::P256.key(), "payload", true)
        .map_err(|(at, e)| format!("the payload import failed at {at:?}: {e}"))?;
    present(&mut session, key, given, certificate);
    session
        .run(
            &WrapKeyAction,
            "sealed",
            &[("key_to_wrap", "payload"), ("recipient", "recipient")],
            &json!({}),
        )
        .map_err(|(at, e)| format!("wrap_key failed at {at:?}: {e}"))?;
    match session.artifact("sealed") {
        ArtifactValue::WrappedKey(wrapped) => Ok(wrapped.data().to_vec()),
        other => Err(format!("wrap_key produced {other:?}")),
    }
}

fn openssl_seals(
    cli: &Cli,
    dir: &Path,
    key: TestKey,
    keyid: bool,
    certificate: &Path,
) -> Result<Vec<u8>, String> {
    let payload_path = dir.join("payload.bin");
    std::fs::write(&payload_path, payload()).expect("the payload is written");
    let out = dir.join("sealed.der");
    let mut args = vec![
        "cms",
        "-encrypt",
        "-binary",
        "-aes-256-gcm",
        "-outform",
        "DER",
        "-in",
        arg(&payload_path),
        "-out",
        arg(&out),
        "-recip",
        arg(certificate),
    ];
    if keyid {
        args.push("-keyid");
    }
    args.extend_from_slice(match key {
        TestKey::Rsa2048 => OAEP_SHA256,
        _ => KDF_SHA256,
    });
    cli.run(&args)?;
    Ok(std::fs::read(&out).expect("the container is read"))
}

fn check_named(row: &Row, shared: &Shared) -> Result<(), String> {
    let sealed = sealed(row, shared)?;
    let facts = cms::describe(&sealed.container).map_err(|e| e.to_string())?;
    let found = facts
        .recipient_key_identifier
        .map(|id| id.as_bytes().to_vec());
    let expected = match row.named {
        Named::Rfc5280 => Some(openssl::sha::sha1(&public_bits(row.key)).to_vec()),
        Named::CertificateSki => Some(
            ski_of(&sealed.certificate_der)
                .ok_or("the row names the certificate's identifier, and it has none")?,
        ),
        Named::IssuerAndSerial => None,
    };
    if found == expected {
        Ok(())
    } else {
        let hex = |bytes: &Option<Vec<u8>>| {
            bytes.as_deref().map_or_else(
                || "issuer and serial".to_string(),
                base16ct::lower::encode_string,
            )
        };
        Err(format!(
            "the container names {}, and the row expects {:?}: {}",
            hex(&found),
            row.named,
            hex(&expected)
        ))
    }
}

fn rite_opens(row: &Row, shared: &Shared) -> Result<(), String> {
    let sealed = sealed(row, shared)?;
    // What `wrap_key` writes, `unwrap_key` opens.
    let (step, kind) = match row.writer {
        Writer::RiteWraps(_) => (ReadStep::UnwrapKey, FileKind::WrappedKey),
        _ => (ReadStep::DecryptData, FileKind::EncryptedData),
    };
    let mut session = Session::new();
    let attempt = session
        .import(row.key, "key", false)
        .and_then(|()| session.add_file("container", kind, sealed.container.clone()))
        .and_then(|()| run_open(&mut session, step, "container", "key", Payload::P256));
    match (row.rite, attempt) {
        (Opens::Yes, Ok(())) => check_opened(
            &session,
            step,
            "container",
            ("key", row.key.public()),
            Payload::P256,
        ),
        (Opens::Yes, Err((at, e))) => Err(format!("the read failed at {at:?}: {e}")),
        (Opens::No(_), Ok(())) => Err("the read opened it, and the row says it does not".into()),
        (Opens::No(says), Err((_, e))) if e.contains(says) => Ok(()),
        (Opens::No(says), Err((_, e))) => {
            Err(format!("the read refused it, without saying '{says}': {e}"))
        }
    }
}

fn openssl_opens(row: &Row, shared: &Shared, with_certificate: bool) -> Result<(), String> {
    let cli = Cli::get().expect("skipped without the command line");
    let sealed = sealed(row, shared)?;
    let key = row.key.private_path();
    let mut args = vec![
        "cms",
        "-decrypt",
        "-binary",
        "-inform",
        "DER",
        "-in",
        arg(&sealed.container_path),
        "-inkey",
        arg(&key),
        "-keyform",
        "DER",
    ];
    if with_certificate {
        args.extend(["-recip", arg(&sealed.certificate)]);
    }
    // `-inkey` alone tries the key whatever the name, so it opens every row.
    let expected = if with_certificate {
        row.openssl_with_certificate
    } else {
        Opens::Yes
    };
    match (expected, cli.run(&args)) {
        (Opens::Yes, Ok(content)) if content == payload() => Ok(()),
        (Opens::Yes, Ok(_)) => Err("the command line recovered other bytes".into()),
        (Opens::Yes, Err(e)) => Err(e),
        (Opens::No(_), Ok(_)) => {
            Err("the command line opened it, and the row says it does not".into())
        }
        (Opens::No(says), Err(e)) if e.contains(says) => Ok(()),
        (Opens::No(says), Err(e)) => Err(format!(
            "the command line failed without saying '{says}': {e}"
        )),
    }
}
