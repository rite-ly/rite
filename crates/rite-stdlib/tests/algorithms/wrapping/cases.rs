//! The wrapping rows, written out.
//!
//! A case names a step, a key and what must happen, nothing about how the
//! test gets there. Adding a row is the whole of adding a case. The coverage
//! checks in `coverage.rs` fail when a key or a scheme has no row.
//!
//! An outcome is stated from the outside: the forms below are the algorithm
//! identifiers the standards give, not values read from Rite's code.

use rite_sdk::oid;
use rite_sdk::{RecipientInfoKind, WrapScheme};

use super::model::{Fixture, Form, Path, Payload, Read, Recipient, Write, WriteCase, WriteStep};
use crate::keys::TestKey;
use crate::outcome::{Expected, NO_SUCH_ALGORITHM, Refusal, Stage, Why, always};
use crate::session::Source;
use crate::shape::Shape;

// ── Forms ────────────────────────────────────────────────────────────────────

/// `KeyTransRecipientInfo` under RSAES-OAEP (RFC 8017), AES-256-GCM content
/// (RFC 5084).
const KTRI_OAEP: Form = Form::Cms {
    recipient: RecipientInfoKind::Ktri,
    key_encryption: oid::RSAES_OAEP,
    kdf: None,
    kek_wrap: None,
    content: oid::AES_256_GCM,
};

/// `KeyAgreeRecipientInfo` under `dhSinglePass-stdDH-sha256kdf-scheme` (RFC
/// 5753) and `id-aes256-wrap` (RFC 3565).
const KARI_SHA256: Form = Form::Cms {
    recipient: RecipientInfoKind::Kari,
    key_encryption: oid::DH_SINGLE_PASS_STDDH_SHA256KDF,
    kdf: None,
    kek_wrap: Some(oid::AES_256_WRAP),
    content: oid::AES_256_GCM,
};

/// The same under `dhSinglePass-stdDH-sha384kdf-scheme`, RFC 6318's profile
/// for P-384.
const KARI_SHA384: Form = Form::Cms {
    recipient: RecipientInfoKind::Kari,
    key_encryption: oid::DH_SINGLE_PASS_STDDH_SHA384KDF,
    kdf: None,
    kek_wrap: Some(oid::AES_256_WRAP),
    content: oid::AES_256_GCM,
};

/// `KEKRecipientInfo` under `id-aes256-wrap`.
const KEKRI: Form = Form::Cms {
    recipient: RecipientInfoKind::Kekri,
    key_encryption: oid::AES_256_WRAP,
    kdf: None,
    kek_wrap: None,
    content: oid::AES_256_GCM,
};

/// `id-alg-hkdf-with-sha256` (RFC 8619), the KDF OpenSSL names in a
/// `KEMRecipientInfo`.
const HKDF_SHA256: &str = "1.2.840.113549.1.9.16.3.28";

/// `KEMRecipientInfo` (RFC 9629) under ML-KEM (RFC 9936, `id-alg-ml-kem-*`
/// from NIST CSOR), HKDF with SHA-256, and `id-aes256-wrap`.
const fn kemri(kem: &'static str) -> Form {
    Form::Cms {
        recipient: RecipientInfoKind::Kemri,
        key_encryption: kem,
        kdf: Some(HKDF_SHA256),
        kek_wrap: Some(oid::AES_256_WRAP),
        content: oid::AES_256_GCM,
    }
}
const KEMRI_512: Form = kemri("2.16.840.1.101.3.4.4.1");
const KEMRI_768: Form = kemri("2.16.840.1.101.3.4.4.2");
const KEMRI_1024: Form = kemri("2.16.840.1.101.3.4.4.3");

// ── Outcomes ─────────────────────────────────────────────────────────────────

const fn writes(form: Form) -> Expected<Write> {
    always(Write::Writes(form))
}

const fn write_fails(why: Why, at: Stage, says: &'static str) -> Expected<Write> {
    always(Write::Fails(why, Refusal { at, says }))
}

const OPENS: Expected<Read> = always(Read::Opens);

const fn read_fails(why: Why, at: Stage, says: &'static str) -> Expected<Read> {
    always(Read::Fails(why, Refusal { at, says }))
}

use Stage::{Check, Import, Step};
use Why::{Refused, Unsupported};

/// A key that signs and cannot be a recipient, in the words both write steps
/// use.
const CANNOT_RECEIVE: &str = "cannot be a recipient: it only signs";

/// `unwrap_key` reads only a wrapped key a step of the same run produced, so
/// a container from outside is refused before its form is looked at. When it
/// accepts a material, every fixture's `unwrap_key` row changes, which is the
/// point.
const UNWRAP_READS_NO_MATERIAL: Expected<Read> =
    read_fails(Unsupported, Step, "must be a WrappedKey");

// ── Write cases ──────────────────────────────────────────────────────────────

const fn case(step: WriteStep, path: Path, key: TestKey, expect: Expected<Write>) -> WriteCase {
    WriteCase {
        step,
        path,
        key,
        scheme: None,
        payload: Payload::P256,
        expect,
    }
}

const fn scheme(
    path: Path,
    key: TestKey,
    scheme: &'static str,
    payload: Payload,
    expect: Expected<Write>,
) -> WriteCase {
    WriteCase {
        step: WriteStep::WrapKey,
        path,
        key,
        scheme: Some(scheme),
        payload,
        expect,
    }
}

/// A P-256 recipient whose key arrives in `shape`.
const fn shaped(step: WriteStep, shape: Shape, expect: Expected<Write>) -> WriteCase {
    case(step, Path::Recipient(shape), TestKey::P256, expect)
}

/// A recipient as the algorithm rows give it, its SPKI DER file.
const PUBLIC: Path = Path::Recipient(Shape::SpkiDer);

/// A key the backend holds, imported, and one it generated.
const HELD: Path = Path::Held(Source::Imported);
const GENERATED: Path = Path::Held(Source::Generated);
use TestKey as K;
use WriteStep::{EncryptData, WrapKey};

// One row per line, so a case reads across and a diff names the row.
#[rustfmt::skip]
pub const WRITES: &[WriteCase] = &[
    // wrap_key to a key the backend holds, under CMS-AES-256-GCM.
    case(WrapKey, HELD, K::Rsa2048, writes(KTRI_OAEP)),
    case(WrapKey, GENERATED, K::Rsa2048, writes(KTRI_OAEP)),
    case(WrapKey, HELD, K::Rsa4096, writes(KTRI_OAEP)),
    case(WrapKey, GENERATED, K::Rsa4096, writes(KTRI_OAEP)),
    case(WrapKey, HELD, K::P256, writes(KARI_SHA256)),
    case(WrapKey, GENERATED, K::P256, writes(KARI_SHA256)),
    case(WrapKey, HELD, K::P384, writes(KARI_SHA384)),
    case(WrapKey, GENERATED, K::P384, writes(KARI_SHA384)),
    case(WrapKey, HELD, K::MlKem512, writes(KEMRI_512)),
    case(WrapKey, GENERATED, K::MlKem512, writes(KEMRI_512)),
    case(WrapKey, HELD, K::MlKem768, writes(KEMRI_768)),
    case(WrapKey, GENERATED, K::MlKem768, writes(KEMRI_768)),
    case(WrapKey, HELD, K::MlKem1024, writes(KEMRI_1024)),
    case(WrapKey, GENERATED, K::MlKem1024, writes(KEMRI_1024)),
    case(WrapKey, HELD, K::Aes256, writes(KEKRI)),
    case(WrapKey, GENERATED, K::Aes256, writes(KEKRI)),
    case(WrapKey, HELD, K::Aes128, write_fails(Unsupported, Step, "needs a 256-bit KEK")),
    case(WrapKey, GENERATED, K::Aes128, write_fails(Unsupported, Step, "needs a 256-bit KEK")),
    case(WrapKey, HELD, K::Ed25519, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, GENERATED, K::Ed25519, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, HELD, K::MlDsa44, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, GENERATED, K::MlDsa44, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, HELD, K::MlDsa65, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, GENERATED, K::MlDsa65, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, HELD, K::MlDsa87, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, GENERATED, K::MlDsa87, write_fails(Refused, Step, CANNOT_RECEIVE)),
    // The compressed encoding of a P-256 key, which Rite refuses: the same key
    // would have a second fingerprint.
    case(WrapKey, HELD, K::P256Compressed, write_fails(Refused, Import, "the EC public key's point is compressed")),
    case(WrapKey, HELD, K::BrainpoolP256r1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::BrainpoolP384r1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::SlhDsaSha2_128s, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::Rsa1024, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::Rsa3072, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::RsaPss2048, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::P521, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::Secp256k1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::Ed448, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::X25519, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::X448, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(WrapKey, HELD, K::Aes192, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    // wrap_key to a public key read as a material.
    case(WrapKey, PUBLIC, K::Rsa2048, writes(KTRI_OAEP)),
    case(WrapKey, PUBLIC, K::Rsa4096, writes(KTRI_OAEP)),
    case(WrapKey, PUBLIC, K::P256, writes(KARI_SHA256)),
    case(WrapKey, PUBLIC, K::P384, writes(KARI_SHA384)),
    case(WrapKey, PUBLIC, K::MlKem512, writes(KEMRI_512)),
    case(WrapKey, PUBLIC, K::MlKem768, writes(KEMRI_768)),
    case(WrapKey, PUBLIC, K::MlKem1024, writes(KEMRI_1024)),
    case(WrapKey, PUBLIC, K::Ed25519, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, PUBLIC, K::MlDsa44, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, PUBLIC, K::MlDsa65, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, PUBLIC, K::MlDsa87, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(WrapKey, PUBLIC, K::P256Compressed, write_fails(Refused, Step, "the EC public key's point is compressed")),
    case(WrapKey, PUBLIC, K::BrainpoolP256r1, write_fails(Unsupported, Step, "EC curve brainpoolP256r1 (1.3.36.3.3.2.8.1.1.7) is not supported")),
    case(WrapKey, PUBLIC, K::BrainpoolP384r1, write_fails(Unsupported, Step, "EC curve brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11) is not supported")),
    case(WrapKey, PUBLIC, K::SlhDsaSha2_128s, write_fails(Unsupported, Step, "public key algorithm id-slh-dsa-sha2-128s (2.16.840.1.101.3.4.3.20) is not supported")),
    case(WrapKey, PUBLIC, K::Rsa1024, write_fails(Unsupported, Step, "RSA key size 1024 bits not supported")),
    case(WrapKey, PUBLIC, K::Rsa3072, write_fails(Unsupported, Step, "RSA key size 3072 bits not supported")),
    case(WrapKey, PUBLIC, K::RsaPss2048, write_fails(Unsupported, Step, "public key algorithm id-RSASSA-PSS (1.2.840.113549.1.1.10) is not supported")),
    case(WrapKey, PUBLIC, K::P521, write_fails(Unsupported, Step, "EC curve secp521r1 (1.3.132.0.35) is not supported")),
    case(WrapKey, PUBLIC, K::Secp256k1, write_fails(Unsupported, Step, "EC curve secp256k1 (1.3.132.0.10) is not supported")),
    case(WrapKey, PUBLIC, K::Ed448, write_fails(Unsupported, Step, "public key algorithm id-Ed448 (1.3.101.113) is not supported")),
    case(WrapKey, PUBLIC, K::X25519, write_fails(Unsupported, Step, "public key algorithm id-X25519 (1.3.101.110) is not supported")),
    case(WrapKey, PUBLIC, K::X448, write_fails(Unsupported, Step, "public key algorithm id-X448 (1.3.101.111) is not supported")),
    // wrap_key under the raw mechanisms.
    scheme(HELD, K::Rsa2048, "RSA-OAEP-SHA256", Payload::P256, writes(Form::Raw(WrapScheme::RsaOaepSha256))),
    scheme(HELD, K::Rsa4096, "RSA-OAEP-SHA256", Payload::P256, writes(Form::Raw(WrapScheme::RsaOaepSha256))),
    scheme(HELD, K::P256, "RSA-OAEP-SHA256", Payload::P256, write_fails(Refused, Step, "needs an RSA recipient")),
    scheme(HELD, K::Rsa2048, "RSA-OAEP-SHA256", Payload::Rsa2048, write_fails(Refused, Step, "carries at most 190")),
    scheme(PUBLIC, K::Rsa2048, "RSA-OAEP-SHA256", Payload::P256, writes(Form::Raw(WrapScheme::RsaOaepSha256))),
    scheme(HELD, K::Rsa2048, "RSA-AES-KEY-WRAP-SHA256", Payload::P256, writes(Form::Raw(WrapScheme::RsaAesKeyWrapSha256))),
    scheme(PUBLIC, K::Rsa4096, "RSA-AES-KEY-WRAP-SHA256", Payload::P256, writes(Form::Raw(WrapScheme::RsaAesKeyWrapSha256))),
    scheme(HELD, K::Aes128, "AES-128-KW", Payload::Aes256, writes(Form::Raw(WrapScheme::Aes128Kw))),
    scheme(HELD, K::Aes256, "AES-256-KW", Payload::Aes256, writes(Form::Raw(WrapScheme::Aes256Kw))),
    scheme(HELD, K::Aes256, "AES-256-KW", Payload::P256, write_fails(Refused, Step, "a multiple of 8 bytes and at least 16")),
    scheme(HELD, K::Aes128, "AES-256-KW", Payload::Aes256, write_fails(Refused, Step, "AES-256-KW wraps under")),
    scheme(HELD, K::Aes128, "AES-128-KWP", Payload::P256, writes(Form::Raw(WrapScheme::Aes128Kwp))),
    scheme(HELD, K::Aes256, "AES-256-KWP", Payload::P256, writes(Form::Raw(WrapScheme::Aes256Kwp))),
    // Schemes Rite has no name for.
    scheme(HELD, K::Rsa2048, "RSA-OAEP-SHA1", Payload::P256, write_fails(Unsupported, Check, "'with.scheme' must be one of: CMS-AES-256-GCM")),
    scheme(HELD, K::Rsa2048, "RSA-AES-KEY-WRAP-SHA1", Payload::P256, write_fails(Unsupported, Check, "'with.scheme' must be one of: CMS-AES-256-GCM")),
    scheme(HELD, K::Aes256, "AES-192-KWP", Payload::P256, write_fails(Unsupported, Check, "'with.scheme' must be one of: CMS-AES-256-GCM")),
    // encrypt_data to a key the backend holds: a symmetric key only.
    case(EncryptData, HELD, K::Aes256, writes(KEKRI)),
    case(EncryptData, GENERATED, K::Aes256, writes(KEKRI)),
    case(EncryptData, HELD, K::Aes128, write_fails(Unsupported, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::Aes128, write_fails(Unsupported, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::Aes192, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::Rsa2048, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::Rsa2048, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::Rsa4096, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::Rsa4096, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::P256, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::P256, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::P384, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::P384, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::Ed25519, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::Ed25519, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlDsa44, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlDsa44, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlDsa65, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlDsa65, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlDsa87, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlDsa87, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlKem512, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlKem512, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlKem768, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlKem768, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::MlKem1024, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, GENERATED, K::MlKem1024, write_fails(Refused, Step, "encrypts to a 256-bit symmetric key")),
    case(EncryptData, HELD, K::P256Compressed, write_fails(Refused, Import, "the EC public key's point is compressed")),
    case(EncryptData, HELD, K::BrainpoolP256r1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::BrainpoolP384r1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::SlhDsaSha2_128s, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::Rsa1024, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::Rsa3072, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::RsaPss2048, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::P521, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::Secp256k1, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::Ed448, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::X25519, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    case(EncryptData, HELD, K::X448, write_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    // encrypt_data to a public key read as a material.
    case(EncryptData, PUBLIC, K::Rsa2048, writes(KTRI_OAEP)),
    case(EncryptData, PUBLIC, K::Rsa4096, writes(KTRI_OAEP)),
    case(EncryptData, PUBLIC, K::P256, writes(KARI_SHA256)),
    case(EncryptData, PUBLIC, K::P384, writes(KARI_SHA384)),
    case(EncryptData, PUBLIC, K::MlKem512, write_fails(Unsupported, Step, "encrypts to an RSA-2048, RSA-4096, P-256 or P-384 public key, and the recipient is ML-KEM-512")),
    case(EncryptData, PUBLIC, K::MlKem768, write_fails(Unsupported, Step, "encrypts to an RSA-2048, RSA-4096, P-256 or P-384 public key, and the recipient is ML-KEM-768")),
    case(EncryptData, PUBLIC, K::MlKem1024, write_fails(Unsupported, Step, "encrypts to an RSA-2048, RSA-4096, P-256 or P-384 public key, and the recipient is ML-KEM-1024")),
    case(EncryptData, PUBLIC, K::Ed25519, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(EncryptData, PUBLIC, K::MlDsa44, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(EncryptData, PUBLIC, K::MlDsa65, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(EncryptData, PUBLIC, K::MlDsa87, write_fails(Refused, Step, CANNOT_RECEIVE)),
    case(EncryptData, PUBLIC, K::P256Compressed, write_fails(Refused, Step, "the EC public key's point is compressed")),
    case(EncryptData, PUBLIC, K::BrainpoolP256r1, write_fails(Unsupported, Step, "EC curve brainpoolP256r1 (1.3.36.3.3.2.8.1.1.7) is not supported")),
    case(EncryptData, PUBLIC, K::BrainpoolP384r1, write_fails(Unsupported, Step, "EC curve brainpoolP384r1 (1.3.36.3.3.2.8.1.1.11) is not supported")),
    case(EncryptData, PUBLIC, K::SlhDsaSha2_128s, write_fails(Unsupported, Step, "public key algorithm id-slh-dsa-sha2-128s (2.16.840.1.101.3.4.3.20) is not supported")),
    case(EncryptData, PUBLIC, K::Rsa1024, write_fails(Unsupported, Step, "RSA key size 1024 bits not supported")),
    case(EncryptData, PUBLIC, K::Rsa3072, write_fails(Unsupported, Step, "RSA key size 3072 bits not supported")),
    case(EncryptData, PUBLIC, K::RsaPss2048, write_fails(Unsupported, Step, "public key algorithm id-RSASSA-PSS (1.2.840.113549.1.1.10) is not supported")),
    case(EncryptData, PUBLIC, K::P521, write_fails(Unsupported, Step, "EC curve secp521r1 (1.3.132.0.35) is not supported")),
    case(EncryptData, PUBLIC, K::Secp256k1, write_fails(Unsupported, Step, "EC curve secp256k1 (1.3.132.0.10) is not supported")),
    case(EncryptData, PUBLIC, K::Ed448, write_fails(Unsupported, Step, "public key algorithm id-Ed448 (1.3.101.113) is not supported")),
    case(EncryptData, PUBLIC, K::X25519, write_fails(Unsupported, Step, "public key algorithm id-X25519 (1.3.101.110) is not supported")),
    case(EncryptData, PUBLIC, K::X448, write_fails(Unsupported, Step, "public key algorithm id-X448 (1.3.101.111) is not supported")),
];

// ── Containers written elsewhere ─────────────────────────────────────────────

/// RSAES-OAEP with SHA-256 for the digest and MGF1, which `openssl cms` writes
/// only when told.
const OAEP_SHA256: &[&str] = &[
    "-keyopt",
    "rsa_padding_mode:oaep",
    "-keyopt",
    "rsa_oaep_md:sha256",
    "-keyopt",
    "rsa_mgf1_md:sha256",
];
const KDF_SHA256: &[&str] = &["-keyopt", "ecdh_kdf_md:sha256"];
const KDF_SHA384: &[&str] = &["-keyopt", "ecdh_kdf_md:sha384"];
const KDF_SHA512: &[&str] = &["-keyopt", "ecdh_kdf_md:sha512"];
const NONE: &[&str] = &[];

const GCM: &[&str] = &["-aes-256-gcm"];

const fn to(key: TestKey, keyopts: &'static [&'static str]) -> Recipient {
    Recipient::Key { key, keyopts }
}

/// The identifiers a fixture's bytes are checked for, beyond those in
/// `rite_sdk::oid`.
mod id {
    pub const SHA_1: &str = "1.3.14.3.2.26";
    pub const SHA_384: &str = "2.16.840.1.101.3.4.2.2";
    pub const SHA_512: &str = "2.16.840.1.101.3.4.2.3";
    /// `id-at-commonName`, which only an issuer name carries here: a recipient
    /// named by key identifier has no name in it.
    pub const COMMON_NAME: &str = "2.5.4.3";
    pub const DH_SHA512KDF: &str = "1.3.132.1.11.3";
    pub const COFACTOR_DH_SHA256KDF: &str = "1.3.132.1.14.1";
    pub const AES_192_WRAP: &str = "2.16.840.1.101.3.4.1.25";
    pub const AES_128_GCM: &str = "2.16.840.1.101.3.4.1.6";
    pub const AES_128_CBC: &str = "2.16.840.1.101.3.4.1.2";
    pub const AES_192_CBC: &str = "2.16.840.1.101.3.4.1.22";
    pub const DES_EDE3_CBC: &str = "1.2.840.113549.3.7";
    pub const PWRI_KEK: &str = "1.2.840.113549.1.9.16.3.9";
    pub const PBKDF2: &str = "1.2.840.113549.1.5.12";
    pub const ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
}

use oid::{
    AES_128_WRAP, AES_256_CBC, AES_256_GCM, AES_256_WRAP,
    DH_SINGLE_PASS_STDDH_SHA1KDF as DH_SHA1KDF, DH_SINGLE_PASS_STDDH_SHA256KDF as DH_SHA256KDF,
    DH_SINGLE_PASS_STDDH_SHA384KDF as DH_SHA384KDF, MGF1, RSA_ENCRYPTION, RSAES_OAEP, SHA_256,
};

/// The other forms a recipient's key arrives in, under one key. The rows
/// above give every key as its SPKI DER file.
#[rustfmt::skip]
pub const RECIPIENT_SHAPES: &[WriteCase] = &[
    shaped(WrapKey, Shape::SpkiPem, writes(KARI_SHA256)),
    shaped(WrapKey, Shape::CertificateDer, writes(KARI_SHA256)),
    shaped(WrapKey, Shape::CertificatePem, writes(KARI_SHA256)),
    shaped(WrapKey, Shape::PublicKey, writes(KARI_SHA256)),
    shaped(WrapKey, Shape::Certificate, writes(KARI_SHA256)),
    shaped(WrapKey, Shape::Keypair, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::SpkiPem, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::CertificateDer, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::CertificatePem, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::PublicKey, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::Certificate, writes(KARI_SHA256)),
    shaped(EncryptData, Shape::Keypair, writes(KARI_SHA256)),
];

pub const FIXTURES: &[Fixture] = &[
    // Key transport.
    Fixture {
        name: "ktri-rsa-2048-oaep-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, SHA_256, MGF1, AES_256_GCM],
        lacks: &[RSA_ENCRYPTION, id::COMMON_NAME],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        name: "ktri-rsa-4096-oaep-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa4096, OAEP_SHA256)],
        opened_with: K::Rsa4096,
        holds: &[RSAES_OAEP, SHA_256, MGF1, AES_256_GCM],
        lacks: &[RSA_ENCRYPTION],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        name: "ktri-rsa-1024-oaep-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa1024, OAEP_SHA256)],
        opened_with: K::Rsa1024,
        holds: &[RSAES_OAEP, SHA_256],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    Fixture {
        name: "ktri-rsa-3072-oaep-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa3072, OAEP_SHA256)],
        opened_with: K::Rsa3072,
        holds: &[RSAES_OAEP, SHA_256],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    Fixture {
        // OAEP's parameters all default to SHA-1, so the encoding names none.
        name: "ktri-rsa-2048-oaep-sha1",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa2048, &["-keyopt", "rsa_padding_mode:oaep"])],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, AES_256_GCM],
        lacks: &[id::SHA_1, SHA_256, id::SHA_384, id::SHA_512, MGF1],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "names no hashFunc, which means SHA-1"),
    },
    Fixture {
        name: "ktri-rsa-2048-oaep-sha384",
        content: GCM,
        keyid: true,
        recipients: &[to(
            K::Rsa2048,
            &[
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha384",
                "-keyopt",
                "rsa_mgf1_md:sha384",
            ],
        )],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, id::SHA_384, MGF1],
        lacks: &[SHA_256],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "hashFunc is 2.16.840.1.101.3.4.2.2, and this reader opens RSAES-OAEP over SHA-256",
        ),
    },
    Fixture {
        name: "ktri-rsa-2048-oaep-sha512",
        content: GCM,
        keyid: true,
        recipients: &[to(
            K::Rsa2048,
            &[
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha512",
                "-keyopt",
                "rsa_mgf1_md:sha512",
            ],
        )],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, id::SHA_512, MGF1],
        lacks: &[SHA_256],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "hashFunc is 2.16.840.1.101.3.4.2.3, and this reader opens RSAES-OAEP over SHA-256",
        ),
    },
    Fixture {
        // The digest and the mask function need not agree. MGF1 over SHA-1 is
        // the default, so the encoding names no mask function.
        name: "ktri-rsa-2048-oaep-sha256-mgf1-sha1",
        content: GCM,
        keyid: true,
        recipients: &[to(
            K::Rsa2048,
            &[
                "-keyopt",
                "rsa_padding_mode:oaep",
                "-keyopt",
                "rsa_oaep_md:sha256",
                "-keyopt",
                "rsa_mgf1_md:sha1",
            ],
        )],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, SHA_256],
        lacks: &[MGF1, id::SHA_1],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "names no maskGenFunc, which means MGF1 over SHA-1",
        ),
    },
    Fixture {
        name: "ktri-rsa-2048-pkcs1-v1_5",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa2048, NONE)],
        opened_with: K::Rsa2048,
        holds: &[RSA_ENCRYPTION, AES_256_GCM],
        lacks: &[RSAES_OAEP],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "RSAES-PKCS1-v1_5"),
    },
    Fixture {
        name: "ktri-rsa-2048-oaep-sha256-issuer-serial",
        content: GCM,
        keyid: false,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, SHA_256, id::COMMON_NAME],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "issuer and serial"),
    },
    // Key agreement. The curve is not in the container: the originator key
    // takes the recipient's.
    Fixture {
        name: "kari-p-256-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P256, KDF_SHA256)],
        opened_with: K::P256,
        holds: &[DH_SHA256KDF, AES_256_WRAP, AES_256_GCM],
        lacks: &[id::COMMON_NAME],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        name: "kari-p-384-sha384",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P384, KDF_SHA384)],
        opened_with: K::P384,
        holds: &[DH_SHA384KDF, AES_256_WRAP, AES_256_GCM],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        // Not the profile RFC 6318 gives P-384, and nothing in RFC 5753 ties
        // a digest to a curve, so Rite opens it.
        name: "kari-p-384-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P384, KDF_SHA256)],
        opened_with: K::P384,
        holds: &[DH_SHA256KDF, AES_256_WRAP],
        lacks: &[DH_SHA384KDF],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        name: "kari-p-256-sha1",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P256, NONE)],
        opened_with: K::P256,
        holds: &[DH_SHA1KDF, AES_256_WRAP],
        lacks: &[DH_SHA256KDF],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "SHA-1"),
    },
    Fixture {
        name: "kari-p-256-sha512",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P256, KDF_SHA512)],
        opened_with: K::P256,
        holds: &[id::DH_SHA512KDF, AES_256_WRAP],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "key agreement scheme 1.3.132.1.11.3 is not ECDH",
        ),
    },
    Fixture {
        name: "kari-p-256-cofactor-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(
            K::P256,
            &[
                "-keyopt",
                "ecdh_kdf_md:sha256",
                "-keyopt",
                "ecdh_cofactor_mode:1",
            ],
        )],
        opened_with: K::P256,
        holds: &[id::COFACTOR_DH_SHA256KDF, AES_256_WRAP],
        lacks: &[DH_SHA256KDF],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "key agreement scheme 1.3.132.1.14.1 is not ECDH",
        ),
    },
    Fixture {
        name: "kari-p-256-sha256-issuer-serial",
        content: GCM,
        keyid: false,
        recipients: &[to(K::P256, KDF_SHA256)],
        opened_with: K::P256,
        holds: &[DH_SHA256KDF, id::COMMON_NAME],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "issuer and serial"),
    },
    Fixture {
        // Sealed to the compressed encoding of `p-256`, and opened with the
        // same key in its uncompressed encoding: the container names the key
        // by the identifier of the encoding it was sealed to.
        name: "kari-p-256-compressed-recipient",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P256Compressed, KDF_SHA256)],
        opened_with: K::P256,
        holds: &[DH_SHA256KDF, AES_256_WRAP],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Refused, Step, "is addressed to the key identified by"),
    },
    Fixture {
        name: "kari-p-521-sha512",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P521, KDF_SHA512)],
        opened_with: K::P521,
        holds: &[id::DH_SHA512KDF],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    Fixture {
        name: "kari-secp256k1-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Secp256k1, KDF_SHA256)],
        opened_with: K::Secp256k1,
        holds: &[DH_SHA256KDF],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    Fixture {
        name: "kari-brainpool-p256r1-sha256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::BrainpoolP256r1, KDF_SHA256)],
        opened_with: K::BrainpoolP256r1,
        holds: &[DH_SHA256KDF],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    // A symmetric recipient.
    Fixture {
        name: "kekri-aes-256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Aes256, NONE)],
        opened_with: K::Aes256,
        holds: &[AES_256_WRAP, AES_256_GCM],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: OPENS,
    },
    Fixture {
        name: "kekri-aes-128",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Aes128, NONE)],
        opened_with: K::Aes128,
        holds: &[AES_128_WRAP],
        lacks: &[AES_256_WRAP],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "2.16.840.1.101.3.4.1.5 is not id-aes256-wrap",
        ),
    },
    Fixture {
        name: "kekri-aes-192",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Aes192, NONE)],
        opened_with: K::Aes192,
        holds: &[id::AES_192_WRAP],
        lacks: &[],
        unwrap_key: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
        decrypt_data: read_fails(Unsupported, Check, NO_SUCH_ALGORITHM),
    },
    // A KEM.
    Fixture {
        name: "kemri-ml-kem-768",
        content: GCM,
        keyid: true,
        recipients: &[to(K::MlKem768, NONE)],
        opened_with: K::MlKem768,
        holds: &[id::ML_KEM_768, HKDF_SHA256, AES_256_WRAP],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "OtherRecipientInfo, which this reader does not open",
        ),
    },
    // A password. OpenSSL derives the key-encryption key under the content
    // cipher, and does so only for a CBC one, so this fixture is also an
    // `EnvelopedData`.
    Fixture {
        name: "pwri-aes-256-cbc",
        content: &["-aes-256-cbc"],
        keyid: true,
        recipients: &[Recipient::Password("rite-test")],
        opened_with: K::Aes256,
        holds: &[id::PWRI_KEK, id::PBKDF2, AES_256_CBC],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "PasswordRecipientInfo is not a key wrap"),
    },
    // The content cipher. CBC carries no integrity protection; Rite writes no
    // CBC (PCI PIN v3.1, 18-3) and is to accept it on input, which a policy
    // level may then refuse.
    Fixture {
        name: "content-aes-128-gcm",
        content: &["-aes-128-gcm"],
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[id::AES_128_GCM],
        lacks: &[AES_256_GCM],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "\"content_encryption_oid\":\"2.16.840.1.101.3.4.1.6\"",
        ),
    },
    Fixture {
        name: "content-aes-256-cbc",
        content: &["-aes-256-cbc"],
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[AES_256_CBC],
        lacks: &[AES_256_GCM],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "\"content_encryption_oid\":\"2.16.840.1.101.3.4.1.42\"",
        ),
    },
    // CBC under the other AES key sizes, as older producers write them.
    Fixture {
        name: "content-aes-128-cbc",
        content: &["-aes-128-cbc"],
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[id::AES_128_CBC],
        lacks: &[AES_256_GCM, AES_256_CBC],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "\"content_encryption_oid\":\"2.16.840.1.101.3.4.1.2\"",
        ),
    },
    // CBC under the other AES key sizes, as older producers write them.
    Fixture {
        name: "content-aes-192-cbc",
        content: &["-aes-192-cbc"],
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[id::AES_192_CBC],
        lacks: &[AES_256_GCM, AES_256_CBC],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "\"content_encryption_oid\":\"2.16.840.1.101.3.4.1.22\"",
        ),
    },
    Fixture {
        name: "content-des-ede3-cbc",
        content: &["-des3"],
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[id::DES_EDE3_CBC],
        lacks: &[AES_256_GCM],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(
            Unsupported,
            Step,
            "\"content_encryption_oid\":\"1.2.840.113549.3.7\"",
        ),
    },
    // The recipient set.
    Fixture {
        name: "two-recipients-rsa-2048-p-256",
        content: GCM,
        keyid: true,
        recipients: &[to(K::Rsa2048, OAEP_SHA256), to(K::P256, KDF_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, DH_SHA256KDF],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "more than one recipient"),
    },
    Fixture {
        // The key that opens it is the second recipient, so a reader that
        // takes the first cannot pass.
        name: "two-recipients-p-256-rsa-2048",
        content: GCM,
        keyid: true,
        recipients: &[to(K::P256, KDF_SHA256), to(K::Rsa2048, OAEP_SHA256)],
        opened_with: K::Rsa2048,
        holds: &[RSAES_OAEP, DH_SHA256KDF],
        lacks: &[],
        unwrap_key: UNWRAP_READS_NO_MATERIAL,
        decrypt_data: read_fails(Unsupported, Step, "more than one recipient"),
    },
];

/// Forms Rite writes that no read step opens from a container another
/// implementation wrote, each with the reason. A form opened from one fails
/// the coverage test until it leaves this list.
pub const NOT_OPENED_FROM_ELSEWHERE: &[(Form, &str)] = &[
    (
        KEMRI_512,
        "decrypt_data has no KEM reader, and unwrap_key reads no material",
    ),
    (
        KEMRI_768,
        "decrypt_data has no KEM reader, and unwrap_key reads no material",
    ),
    (
        KEMRI_1024,
        "decrypt_data has no KEM reader, and unwrap_key reads no material",
    ),
];
