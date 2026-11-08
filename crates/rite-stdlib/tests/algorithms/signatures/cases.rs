//! The signature rows, written out.
//!
//! A scheme is stated as the command line runs it, from the standards
//! (RFC 8017 for RSA, FIPS 186-5 for ECDSA, RFC 8032 for `EdDSA`, FIPS 204 for
//! ML-DSA), not from Rite's code. The algorithm names in `Signs` and
//! `Verifies` are what Rite records, and the coverage checks hold them to
//! Rite's own list.

use super::model::{Encoding, Scheme, ShapeCase, Sign, SignCase, SignatureFixture, Verify};
use crate::keys::TestKey;
use crate::outcome::{Expected, NO_SUCH_ALGORITHM, Refusal, Stage, Why, always};
use crate::session::Source;
use crate::shape::Shape;

// ── Schemes ──────────────────────────────────────────────────────────────────

/// RSASSA-PKCS1-v1_5 under `digest`, with a modulus of `bytes`.
const fn pkcs1(digest: &'static str, bytes: usize) -> Scheme {
    Scheme {
        digest: Some(digest),
        pkeyopts: &["rsa_padding_mode:pkcs1"],
        encoding: Encoding::Bytes(bytes),
    }
}

/// RSASSA-PSS with SHA-256, MGF1 over SHA-256 and a salt as long as the
/// hash: the profile RFC 8017 recommends and most producers write.
const fn pss_sha256(bytes: usize) -> Scheme {
    Scheme {
        digest: Some("sha256"),
        pkeyopts: &[
            "rsa_padding_mode:pss",
            "rsa_mgf1_md:sha256",
            "rsa_pss_saltlen:digest",
        ],
        encoding: Encoding::Bytes(bytes),
    }
}

const fn ecdsa(digest: &'static str, scalar: usize) -> Scheme {
    Scheme {
        digest: Some(digest),
        pkeyopts: &[],
        encoding: Encoding::Der { scalar },
    }
}

/// A scheme over the whole message, with a signature of `bytes`.
const fn whole(bytes: usize) -> Scheme {
    Scheme {
        digest: None,
        pkeyopts: &[],
        encoding: Encoding::Bytes(bytes),
    }
}

const RSA_2048: usize = 256;
const RSA_4096: usize = 512;
const ED25519: usize = 64;
const ML_DSA_44: usize = 2420;
const ML_DSA_65: usize = 3309;
const ML_DSA_87: usize = 4627;

// ── Outcomes ─────────────────────────────────────────────────────────────────

const fn signs(algorithm: &'static str, scheme: Scheme) -> Expected<Sign> {
    always(Sign::Signs(algorithm, scheme))
}

const fn sign_fails(why: Why, at: Stage, says: &'static str) -> Expected<Sign> {
    always(Sign::Fails(why, Refusal { at, says }))
}

const fn verifies(algorithm: &'static str) -> Expected<Verify> {
    always(Verify::Verifies(algorithm))
}

const fn verify_fails(why: Why, says: &'static str) -> Expected<Verify> {
    // `verify_signature` takes the key as a material, so nothing is imported
    // and a refusal is the step's, unless `rite check` refuses it first.
    always(Verify::Fails(
        why,
        Refusal {
            at: Stage::Step,
            says,
        },
    ))
}

const fn verify_unchecked(why: Why, says: &'static str) -> Expected<Verify> {
    always(Verify::Fails(
        why,
        Refusal {
            at: Stage::Check,
            says,
        },
    ))
}

use Stage::{Check, Import, Step};
use Why::{Refused, Unsupported};

/// A key whose type cannot sign, held for what it can do.
const CANNOT_SIGN: &str = "cannot produce signatures";

/// How `rite check` refuses a signature algorithm Rite has no name for.
const NO_SUCH_SIGNATURE: &str = "'with.algorithm' must be one of: RSA-PKCS1-SHA256";

/// An `algorithm:` the key does not take.
const NOT_WITH_THIS_KEY: &str = "cannot be used with";

/// A signature that verifies under some other scheme than the one checked.
const NO_MATCH: &str = "does not match";

/// `verify_signature` reads a key whose type Rite has no name for.
const CANNOT_VERIFY: &str = "uses an algorithm Rite cannot verify";

/// Rite holds an EC point uncompressed only, so one key has one
/// fingerprint. A rule about key identity, not about the algorithm.
const COMPRESSED: &str = "point is compressed";

// ── sign_data ────────────────────────────────────────────────────────────────

const fn sign(key: TestKey, expect: Expected<Sign>) -> SignCase {
    SignCase {
        source: Source::Imported,
        key,
        algorithm: None,
        expect,
    }
}

const fn sign_as(key: TestKey, algorithm: &'static str, expect: Expected<Sign>) -> SignCase {
    SignCase {
        source: Source::Imported,
        key,
        algorithm: Some(algorithm),
        expect,
    }
}

/// A key `generate_key` makes, under its default algorithm.
const fn generated(key: TestKey, expect: Expected<Sign>) -> SignCase {
    SignCase {
        source: Source::Generated,
        key,
        algorithm: None,
        expect,
    }
}

use TestKey as K;

// One row per line, so a case reads across and a diff names the row.
#[rustfmt::skip]
pub const SIGNS: &[SignCase] = &[
    // Each key under its default algorithm.
    sign(K::Rsa2048, signs("RSA-PKCS1-SHA256", pkcs1("sha256", RSA_2048))),
    sign(K::Rsa4096, signs("RSA-PKCS1-SHA256", pkcs1("sha256", RSA_4096))),
    sign(K::P256, signs("ECDSA-SHA256", ecdsa("sha256", 32))),
    sign(K::P384, signs("ECDSA-SHA384", ecdsa("sha384", 48))),
    sign(K::Ed25519, signs("Ed25519", whole(ED25519))),
    sign(K::MlDsa44, signs("ML-DSA-44", whole(ML_DSA_44))),
    sign(K::MlDsa65, signs("ML-DSA-65", whole(ML_DSA_65))),
    sign(K::MlDsa87, signs("ML-DSA-87", whole(ML_DSA_87))),
    sign(K::P256Compressed, sign_fails(Refused, Import, COMPRESSED)),
    sign(K::Rsa1024, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::Rsa3072, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::RsaPss2048, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::P521, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::Secp256k1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::BrainpoolP256r1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::BrainpoolP384r1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::Ed448, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    sign(K::SlhDsaSha2_128s, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    // Keys whose type cannot sign.
    sign(K::MlKem512, sign_fails(Refused, Step, CANNOT_SIGN)),
    sign(K::MlKem768, sign_fails(Refused, Step, CANNOT_SIGN)),
    sign(K::MlKem1024, sign_fails(Refused, Step, CANNOT_SIGN)),
    sign(K::Aes128, sign_fails(Refused, Step, CANNOT_SIGN)),
    sign(K::Aes256, sign_fails(Refused, Step, CANNOT_SIGN)),
    sign(K::Aes192, sign_fails(Refused, Check, NO_SUCH_ALGORITHM)),
    sign(K::X25519, sign_fails(Refused, Check, NO_SUCH_ALGORITHM)),
    sign(K::X448, sign_fails(Refused, Check, NO_SUCH_ALGORITHM)),
    // An algorithm named on the step.
    sign_as(K::Rsa2048, "RSA-PSS-SHA256", signs("RSA-PSS-SHA256", pss_sha256(RSA_2048))),
    sign_as(K::Rsa4096, "RSA-PSS-SHA256", signs("RSA-PSS-SHA256", pss_sha256(RSA_4096))),
    sign_as(K::Rsa2048, "RSA-PKCS1-SHA256", signs("RSA-PKCS1-SHA256", pkcs1("sha256", RSA_2048))),
    // A pairing FIPS 186-5 allows, which Rite pins to one hash per curve.
    sign_as(K::P256, "ECDSA-SHA384", sign_fails(Unsupported, Step, NOT_WITH_THIS_KEY)),
    sign_as(K::P384, "ECDSA-SHA256", sign_fails(Unsupported, Step, NOT_WITH_THIS_KEY)),
    sign_as(K::Rsa2048, "RSA-PSS-SHA384", sign_fails(Unsupported, Check, NO_SUCH_SIGNATURE)),
    sign_as(K::Rsa2048, "RSA-PKCS1-SHA512", sign_fails(Unsupported, Check, NO_SUCH_SIGNATURE)),
    // SHA-1 signatures are not made anew (NIST SP 800-131A).
    sign_as(K::Rsa2048, "RSA-PKCS1-SHA1", sign_fails(Refused, Check, NO_SUCH_SIGNATURE)),
    sign_as(K::P256, "ECDSA-SHA1", sign_fails(Refused, Check, NO_SUCH_SIGNATURE)),
    sign_as(K::Rsa2048, "ECDSA-SHA256", sign_fails(Refused, Step, NOT_WITH_THIS_KEY)),
    // Each signing type `generate_key` is asked for, as most ceremonies make
    // their keys.
    generated(K::Rsa2048, signs("RSA-PKCS1-SHA256", pkcs1("sha256", RSA_2048))),
    generated(K::Rsa4096, signs("RSA-PKCS1-SHA256", pkcs1("sha256", RSA_4096))),
    generated(K::P256, signs("ECDSA-SHA256", ecdsa("sha256", 32))),
    generated(K::P384, signs("ECDSA-SHA384", ecdsa("sha384", 48))),
    generated(K::Ed25519, signs("Ed25519", whole(ED25519))),
    generated(K::MlDsa44, signs("ML-DSA-44", whole(ML_DSA_44))),
    generated(K::MlDsa65, signs("ML-DSA-65", whole(ML_DSA_65))),
    generated(K::MlDsa87, signs("ML-DSA-87", whole(ML_DSA_87))),
    generated(K::Rsa1024, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::Rsa3072, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::RsaPss2048, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::P521, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::Secp256k1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::BrainpoolP256r1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::BrainpoolP384r1, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::Ed448, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
    generated(K::SlhDsaSha2_128s, sign_fails(Unsupported, Check, NO_SUCH_ALGORITHM)),
];

// ── verify_signature, over signatures from elsewhere ─────────────────────────

/// RSASSA-PSS with SHA-256 under other choices of salt and mask.
const PSS_SALT_MAX: Scheme = Scheme {
    digest: Some("sha256"),
    pkeyopts: &[
        "rsa_padding_mode:pss",
        "rsa_mgf1_md:sha256",
        "rsa_pss_saltlen:max",
    ],
    encoding: Encoding::Bytes(RSA_2048),
};
const PSS_MGF1_SHA1: Scheme = Scheme {
    digest: Some("sha256"),
    pkeyopts: &[
        "rsa_padding_mode:pss",
        "rsa_mgf1_md:sha1",
        "rsa_pss_saltlen:digest",
    ],
    encoding: Encoding::Bytes(RSA_2048),
};

/// ECDSA over P-256 and SHA-256, as fixed-width `r || s`.
const ECDSA_P1363: Scheme = Scheme {
    digest: Some("sha256"),
    pkeyopts: &[],
    encoding: Encoding::P1363 { scalar: 32 },
};

/// ML-DSA-44 with a non-empty context string (FIPS 204, section 5.2).
const ML_DSA_44_CONTEXT: Scheme = Scheme {
    digest: None,
    pkeyopts: &["context-string:rite"],
    encoding: Encoding::Bytes(ML_DSA_44),
};

const fn signed(
    name: &'static str,
    key: TestKey,
    scheme: Scheme,
    algorithm: Option<&'static str>,
    expect: Expected<Verify>,
) -> SignatureFixture {
    SignatureFixture {
        name,
        key,
        scheme,
        algorithm,
        expect,
    }
}

const PSS: Option<&str> = Some("RSA-PSS-SHA256");
const DEFAULT: Option<&str> = None;

#[rustfmt::skip]
pub const FIXTURES: &[SignatureFixture] = &[
    signed("rsa-2048-pkcs1-sha256", K::Rsa2048, pkcs1("sha256", RSA_2048), DEFAULT, verifies("RSA-PKCS1-SHA256")),
    signed("rsa-4096-pkcs1-sha256", K::Rsa4096, pkcs1("sha256", RSA_4096), DEFAULT, verifies("RSA-PKCS1-SHA256")),
    signed("rsa-2048-pss-sha256", K::Rsa2048, pss_sha256(RSA_2048), PSS, verifies("RSA-PSS-SHA256")),
    signed("rsa-4096-pss-sha256", K::Rsa4096, pss_sha256(RSA_4096), PSS, verifies("RSA-PSS-SHA256")),
    // The largest salt the modulus allows, which older producers write.
    signed("rsa-2048-pss-sha256-salt-max", K::Rsa2048, PSS_SALT_MAX, PSS, verifies("RSA-PSS-SHA256")),
    signed("rsa-2048-pss-sha256-mgf1-sha1", K::Rsa2048, PSS_MGF1_SHA1, PSS, verify_fails(Unsupported, NO_MATCH)),
    signed("rsa-2048-pkcs1-sha1", K::Rsa2048, pkcs1("sha1", RSA_2048), Some("RSA-PKCS1-SHA1"), verify_unchecked(Unsupported, NO_SUCH_SIGNATURE)),
    signed("rsa-2048-pkcs1-sha384", K::Rsa2048, pkcs1("sha384", RSA_2048), Some("RSA-PKCS1-SHA384"), verify_unchecked(Unsupported, NO_SUCH_SIGNATURE)),
    signed("rsa-2048-pkcs1-sha512", K::Rsa2048, pkcs1("sha512", RSA_2048), Some("RSA-PKCS1-SHA512"), verify_unchecked(Unsupported, NO_SUCH_SIGNATURE)),
    signed("rsa-3072-pkcs1-sha256", K::Rsa3072, pkcs1("sha256", 384), DEFAULT, verify_fails(Unsupported, "RSA key size 3072 bits not supported")),
    // An RSA key restricted to PSS by its SPKI (RFC 4055).
    signed("rsa-pss-2048-pss-sha256", K::RsaPss2048, pss_sha256(RSA_2048), PSS, verify_fails(Unsupported, "public key algorithm 1.2.840.113549.1.1.10 is not supported")),
    signed("rsa-1024-pkcs1-sha256", K::Rsa1024, pkcs1("sha256", 128), DEFAULT, verify_fails(Unsupported, "RSA key size 1024 bits not supported")),
    signed("p-256-sha256", K::P256, ecdsa("sha256", 32), DEFAULT, verifies("ECDSA-SHA256")),
    signed("p-384-sha384", K::P384, ecdsa("sha384", 48), DEFAULT, verifies("ECDSA-SHA384")),
    // OpenSSL fails to parse r || s as DER, and Rite passes its error on as
    // is, naming neither the encoding nor what it expects.
    signed("p-256-sha256-p1363", K::P256, ECDSA_P1363, DEFAULT, verify_fails(Unsupported, "Verify operation: OpenSSL error")),
    signed("p-256-sha384", K::P256, ecdsa("sha384", 32), Some("ECDSA-SHA384"), verify_fails(Unsupported, NOT_WITH_THIS_KEY)),
    signed("p-384-sha256", K::P384, ecdsa("sha256", 48), Some("ECDSA-SHA256"), verify_fails(Unsupported, NOT_WITH_THIS_KEY)),
    signed("p-256-sha1", K::P256, ecdsa("sha1", 32), Some("ECDSA-SHA1"), verify_unchecked(Unsupported, NO_SUCH_SIGNATURE)),
    signed("p-256-compressed-sha256", K::P256Compressed, ecdsa("sha256", 32), DEFAULT, verify_fails(Refused, COMPRESSED)),
    signed("p-521-sha512", K::P521, ecdsa("sha512", 66), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
    signed("secp256k1-sha256", K::Secp256k1, ecdsa("sha256", 32), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
    signed("brainpool-p256r1-sha256", K::BrainpoolP256r1, ecdsa("sha256", 32), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
    signed("brainpool-p384r1-sha384", K::BrainpoolP384r1, ecdsa("sha384", 48), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
    signed("ed25519", K::Ed25519, whole(ED25519), DEFAULT, verifies("Ed25519")),
    signed("ed448", K::Ed448, whole(114), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
    signed("ml-dsa-44", K::MlDsa44, whole(ML_DSA_44), DEFAULT, verifies("ML-DSA-44")),
    signed("ml-dsa-65", K::MlDsa65, whole(ML_DSA_65), DEFAULT, verifies("ML-DSA-65")),
    signed("ml-dsa-87", K::MlDsa87, whole(ML_DSA_87), DEFAULT, verifies("ML-DSA-87")),
    signed("ml-dsa-44-context", K::MlDsa44, ML_DSA_44_CONTEXT, DEFAULT, verify_fails(Unsupported, NO_MATCH)),
    // One parameter set stands for the family; its signature is 7856 bytes.
    signed("slh-dsa-sha2-128s", K::SlhDsaSha2_128s, whole(7856), DEFAULT, verify_fails(Unsupported, CANNOT_VERIFY)),
];

// ── verify_signature, with the key in other forms ────────────────────────────

const fn shaped(shape: Shape) -> ShapeCase {
    ShapeCase {
        fixture: "p-256-sha256",
        shape,
        expect: verifies("ECDSA-SHA256"),
    }
}

/// The other forms the signer's key arrives in, under one fixture. The rows
/// above give every key as its SPKI DER file.
pub const KEY_SHAPES: &[ShapeCase] = &[
    shaped(Shape::SpkiPem),
    shaped(Shape::CertificateDer),
    shaped(Shape::CertificatePem),
    shaped(Shape::PublicKey),
    shaped(Shape::Certificate),
    shaped(Shape::Keypair),
];
