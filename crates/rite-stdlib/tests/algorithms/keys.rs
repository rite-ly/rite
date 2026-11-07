//! The keys the matrix uses, committed under `fixtures/keys/`.
//!
//! Committed rather than generated per run, for three reasons. A run then
//! needs no key generation the linked OpenSSL might lack: a 3.5 build cannot
//! generate ML-KEM, and nothing in Rite generates X448. The containers under
//! `fixtures/cms/` are sealed to these exact keys. And RSA-4096 generation
//! would dominate the run time.
//!
//! These keys protect nothing. They exist so that a test can open what was
//! sealed to them.

use std::path::PathBuf;

use rite_sdk::KeyAlgorithm;

/// A key the matrix can name, whether or not Rite supports its algorithm.
///
/// The unsupported ones are what lets a case say how Rite refuses them, and
/// what turns that case into a failure on the day Rite starts to support one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestKey {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    /// An RSA key whose SPKI names `id-RSASSA-PSS` (RFC 4055) rather than
    /// `rsaEncryption`, restricting it to PSS signatures, as
    /// `genpkey -algorithm RSA-PSS` makes and some CAs issue.
    RsaPss2048,
    P256,
    /// [`TestKey::P256`] itself, with its point compressed in both
    /// encodings: the same key under the second encoding SEC 1 allows.
    P256Compressed,
    P384,
    P521,
    Secp256k1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    Ed25519,
    Ed448,
    X25519,
    X448,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /// One parameter set stands for SLH-DSA (FIPS 205), a family Rite does
    /// not support; the others would refuse the same way.
    SlhDsaSha2_128s,
    MlKem512,
    MlKem768,
    MlKem1024,
    Aes128,
    Aes192,
    Aes256,
    /// The P-256 key `wrap_key` wraps, and the content of every container.
    PayloadP256,
    /// The AES-256 key wrapped under AES-KW, which takes only whole 64-bit
    /// blocks, which no PKCS#8 key is guaranteed to be.
    PayloadAes256,
    /// An RSA-2048 key, whose PKCS#8 is larger than raw RSA-OAEP carries.
    PayloadRsa2048,
}

/// How a key is made when the fixtures are regenerated.
pub enum Generate {
    /// `openssl genpkey` with these arguments.
    Genpkey(&'static [&'static str]),
    /// This many random bytes.
    Random(usize),
    /// The same key as another, with its EC point compressed.
    Compressed(TestKey),
}

impl TestKey {
    pub const ALL: &'static [TestKey] = &[
        TestKey::Rsa1024,
        TestKey::Rsa2048,
        TestKey::Rsa3072,
        TestKey::Rsa4096,
        TestKey::RsaPss2048,
        TestKey::P256,
        TestKey::P256Compressed,
        TestKey::P384,
        TestKey::P521,
        TestKey::Secp256k1,
        TestKey::BrainpoolP256r1,
        TestKey::BrainpoolP384r1,
        TestKey::Ed25519,
        TestKey::Ed448,
        TestKey::X25519,
        TestKey::X448,
        TestKey::MlDsa44,
        TestKey::MlDsa65,
        TestKey::MlDsa87,
        TestKey::SlhDsaSha2_128s,
        TestKey::MlKem512,
        TestKey::MlKem768,
        TestKey::MlKem1024,
        TestKey::Aes128,
        TestKey::Aes192,
        TestKey::Aes256,
        TestKey::PayloadP256,
        TestKey::PayloadAes256,
        TestKey::PayloadRsa2048,
    ];

    /// The file name under `fixtures/keys/`, without extension, and the name
    /// a test reports the key by.
    pub fn stem(self) -> &'static str {
        match self {
            TestKey::Rsa1024 => "rsa-1024",
            TestKey::Rsa2048 => "rsa-2048",
            TestKey::Rsa3072 => "rsa-3072",
            TestKey::Rsa4096 => "rsa-4096",
            TestKey::RsaPss2048 => "rsa-pss-2048",
            TestKey::P256 => "p-256",
            TestKey::P256Compressed => "p-256-compressed",
            TestKey::P384 => "p-384",
            TestKey::P521 => "p-521",
            TestKey::Secp256k1 => "secp256k1",
            TestKey::BrainpoolP256r1 => "brainpool-p256r1",
            TestKey::BrainpoolP384r1 => "brainpool-p384r1",
            TestKey::Ed25519 => "ed25519",
            TestKey::Ed448 => "ed448",
            TestKey::X25519 => "x25519",
            TestKey::X448 => "x448",
            TestKey::MlDsa44 => "ml-dsa-44",
            TestKey::MlDsa65 => "ml-dsa-65",
            TestKey::MlDsa87 => "ml-dsa-87",
            TestKey::SlhDsaSha2_128s => "slh-dsa-sha2-128s",
            TestKey::MlKem512 => "ml-kem-512",
            TestKey::MlKem768 => "ml-kem-768",
            TestKey::MlKem1024 => "ml-kem-1024",
            TestKey::Aes128 => "aes-128",
            TestKey::Aes192 => "aes-192",
            TestKey::Aes256 => "aes-256",
            TestKey::PayloadP256 => "payload-p-256",
            TestKey::PayloadAes256 => "payload-aes-256",
            TestKey::PayloadRsa2048 => "payload-rsa-2048",
        }
    }

    /// The algorithm as a ceremony writes it in `algorithm:`.
    ///
    /// For a supported key this is Rite's own name, which a coverage test
    /// checks. For an unsupported one it is the name Rite would most likely
    /// give it, so the case exercises the refusal a ceremony author meets.
    pub fn algorithm_name(self) -> &'static str {
        match self {
            TestKey::Rsa1024 => "RSA-1024",
            TestKey::Rsa2048 | TestKey::PayloadRsa2048 => "RSA-2048",
            TestKey::Rsa3072 => "RSA-3072",
            TestKey::Rsa4096 => "RSA-4096",
            TestKey::RsaPss2048 => "RSA-PSS-2048",
            TestKey::P256 | TestKey::P256Compressed | TestKey::PayloadP256 => "ECDSA-P256",
            TestKey::P384 => "ECDSA-P384",
            TestKey::P521 => "ECDSA-P521",
            TestKey::Secp256k1 => "ECDSA-SECP256K1",
            TestKey::BrainpoolP256r1 => "ECDSA-BRAINPOOLP256R1",
            TestKey::BrainpoolP384r1 => "ECDSA-BRAINPOOLP384R1",
            TestKey::Ed25519 => "Ed25519",
            TestKey::Ed448 => "Ed448",
            TestKey::X25519 => "X25519",
            TestKey::X448 => "X448",
            TestKey::MlDsa44 => "ML-DSA-44",
            TestKey::MlDsa65 => "ML-DSA-65",
            TestKey::MlDsa87 => "ML-DSA-87",
            TestKey::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            TestKey::MlKem512 => "ML-KEM-512",
            TestKey::MlKem768 => "ML-KEM-768",
            TestKey::MlKem1024 => "ML-KEM-1024",
            TestKey::Aes128 => "AES-128",
            TestKey::Aes192 => "AES-192",
            TestKey::Aes256 | TestKey::PayloadAes256 => "AES-256",
        }
    }

    /// Rite's algorithm for this key, or `None` where Rite has none.
    pub fn rite(self) -> Option<KeyAlgorithm> {
        match self {
            TestKey::Rsa2048 | TestKey::PayloadRsa2048 => Some(KeyAlgorithm::Rsa2048),
            TestKey::Rsa4096 => Some(KeyAlgorithm::Rsa4096),
            // A compressed key is still a P-256 key, which Rite names. What
            // it refuses is the encoding, and the cases say so.
            TestKey::P256 | TestKey::P256Compressed | TestKey::PayloadP256 => {
                Some(KeyAlgorithm::EcdsaP256)
            }
            TestKey::P384 => Some(KeyAlgorithm::EcdsaP384),
            TestKey::Ed25519 => Some(KeyAlgorithm::Ed25519),
            TestKey::MlDsa44 => Some(KeyAlgorithm::MlDsa44),
            TestKey::MlDsa65 => Some(KeyAlgorithm::MlDsa65),
            TestKey::MlDsa87 => Some(KeyAlgorithm::MlDsa87),
            TestKey::MlKem512 => Some(KeyAlgorithm::MlKem512),
            TestKey::MlKem768 => Some(KeyAlgorithm::MlKem768),
            TestKey::MlKem1024 => Some(KeyAlgorithm::MlKem1024),
            TestKey::Aes128 => Some(KeyAlgorithm::Aes128),
            TestKey::Aes256 | TestKey::PayloadAes256 => Some(KeyAlgorithm::Aes256),
            TestKey::Rsa1024
            | TestKey::Rsa3072
            | TestKey::RsaPss2048
            | TestKey::P521
            | TestKey::Secp256k1
            | TestKey::BrainpoolP256r1
            | TestKey::BrainpoolP384r1
            | TestKey::Ed448
            | TestKey::SlhDsaSha2_128s
            | TestKey::X25519
            | TestKey::X448
            | TestKey::Aes192 => None,
        }
    }

    /// Whether this key is what a case seals rather than one it seals to.
    pub fn is_payload(self) -> bool {
        matches!(
            self,
            TestKey::PayloadP256 | TestKey::PayloadAes256 | TestKey::PayloadRsa2048
        )
    }

    pub fn is_symmetric(self) -> bool {
        matches!(self.generate(), Generate::Random(_))
    }

    /// Whether this key is another encoding of an imported key, so no case
    /// generates one of it.
    pub fn is_compressed(self) -> bool {
        matches!(self.generate(), Generate::Compressed(_))
    }

    /// Whether the key's type is a signature scheme, whatever Rite makes of
    /// it.
    pub fn is_signing(self) -> bool {
        matches!(
            self,
            TestKey::Rsa1024
                | TestKey::Rsa2048
                | TestKey::Rsa3072
                | TestKey::Rsa4096
                | TestKey::RsaPss2048
                | TestKey::P256
                | TestKey::P256Compressed
                | TestKey::P384
                | TestKey::P521
                | TestKey::Secp256k1
                | TestKey::BrainpoolP256r1
                | TestKey::BrainpoolP384r1
                | TestKey::Ed25519
                | TestKey::Ed448
                | TestKey::MlDsa44
                | TestKey::MlDsa65
                | TestKey::MlDsa87
                | TestKey::SlhDsaSha2_128s
                | TestKey::PayloadP256
                | TestKey::PayloadRsa2048
        )
    }

    /// What the key may do when a wrapping case holds it in the backend.
    ///
    /// The usage each operation needs, so that a refusal a case expects is the
    /// algorithm's and not the policy's: a key that may not wrap would be
    /// refused for that before its type was ever looked at.
    pub fn usages(self) -> &'static [&'static str] {
        match self {
            // An EC key opens by key agreement, which PKCS#11 permits under
            // CKA_DERIVE.
            TestKey::P256
            | TestKey::P256Compressed
            | TestKey::P384
            | TestKey::P521
            | TestKey::Secp256k1
            | TestKey::BrainpoolP256r1
            | TestKey::BrainpoolP384r1
            | TestKey::X25519
            | TestKey::X448 => &["wrap", "derive"],
            TestKey::PayloadP256 | TestKey::PayloadRsa2048 => &["sign", "verify"],
            TestKey::Rsa1024
            | TestKey::Rsa2048
            | TestKey::Rsa3072
            | TestKey::Rsa4096
            | TestKey::RsaPss2048
            | TestKey::Ed25519
            | TestKey::Ed448
            | TestKey::MlDsa44
            | TestKey::MlDsa65
            | TestKey::MlDsa87
            | TestKey::SlhDsaSha2_128s
            | TestKey::MlKem512
            | TestKey::MlKem768
            | TestKey::MlKem1024
            | TestKey::Aes128
            | TestKey::Aes192
            | TestKey::Aes256
            | TestKey::PayloadAes256 => &["wrap", "unwrap"],
        }
    }

    pub fn generate(self) -> Generate {
        match self {
            TestKey::Rsa1024 => {
                Generate::Genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024"])
            }
            TestKey::Rsa2048 | TestKey::PayloadRsa2048 => {
                Generate::Genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"])
            }
            TestKey::Rsa3072 => {
                Generate::Genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"])
            }
            TestKey::Rsa4096 => {
                Generate::Genpkey(&["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"])
            }
            TestKey::RsaPss2048 => {
                Generate::Genpkey(&["-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"])
            }
            TestKey::P256 | TestKey::PayloadP256 => {
                Generate::Genpkey(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"])
            }
            TestKey::P256Compressed => Generate::Compressed(TestKey::P256),
            TestKey::P384 => {
                Generate::Genpkey(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"])
            }
            TestKey::P521 => {
                Generate::Genpkey(&["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"])
            }
            TestKey::Secp256k1 => Generate::Genpkey(&[
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:secp256k1",
            ]),
            TestKey::BrainpoolP256r1 => Generate::Genpkey(&[
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:brainpoolP256r1",
            ]),
            TestKey::BrainpoolP384r1 => Generate::Genpkey(&[
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:brainpoolP384r1",
            ]),
            TestKey::Ed25519 => Generate::Genpkey(&["-algorithm", "ED25519"]),
            TestKey::Ed448 => Generate::Genpkey(&["-algorithm", "ED448"]),
            TestKey::X25519 => Generate::Genpkey(&["-algorithm", "X25519"]),
            TestKey::X448 => Generate::Genpkey(&["-algorithm", "X448"]),
            TestKey::MlDsa44 => Generate::Genpkey(&["-algorithm", "ML-DSA-44"]),
            TestKey::MlDsa65 => Generate::Genpkey(&["-algorithm", "ML-DSA-65"]),
            TestKey::MlDsa87 => Generate::Genpkey(&["-algorithm", "ML-DSA-87"]),
            TestKey::SlhDsaSha2_128s => Generate::Genpkey(&["-algorithm", "SLH-DSA-SHA2-128s"]),
            TestKey::MlKem512 => Generate::Genpkey(&["-algorithm", "ML-KEM-512"]),
            TestKey::MlKem768 => Generate::Genpkey(&["-algorithm", "ML-KEM-768"]),
            TestKey::MlKem1024 => Generate::Genpkey(&["-algorithm", "ML-KEM-1024"]),
            TestKey::Aes128 => Generate::Random(16),
            TestKey::Aes192 => Generate::Random(24),
            TestKey::Aes256 | TestKey::PayloadAes256 => Generate::Random(32),
        }
    }

    /// The private key as `import_key` takes it: PKCS#8 DER for a keypair,
    /// the key itself for a symmetric key.
    pub fn private(self) -> Vec<u8> {
        read(&self.private_path())
    }

    /// The SPKI DER of a keypair's public half; `None` for a symmetric key.
    pub fn public(self) -> Option<Vec<u8>> {
        (!self.is_symmetric()).then(|| read(&self.public_path()))
    }

    pub fn private_path(self) -> PathBuf {
        let extension = if self.is_symmetric() {
            "key"
        } else {
            "key.der"
        };
        keys_dir().join(format!("{}.{extension}", self.stem()))
    }

    pub fn public_path(self) -> PathBuf {
        keys_dir().join(format!("{}.pub.der", self.stem()))
    }
}

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/algorithms/fixtures")
}

pub fn keys_dir() -> PathBuf {
    fixtures_dir().join("keys")
}

pub fn read(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        panic!(
            "{} cannot be read ({e}). Regenerate the fixtures: see fixtures/README.md",
            path.display()
        )
    })
}
