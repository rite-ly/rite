//! What a signature row says: which key, which algorithm, and what must
//! happen.

use crate::keys::TestKey;
use crate::outcome::{Expected, Refusal, Why};
use crate::session::Source;
use crate::shape::Shape;

/// A signature scheme stated as the `openssl pkeyutl` command line runs it,
/// which is how the matrix checks a signature Rite made and makes one Rite
/// must check, without Rite's code in either.
#[derive(Debug, Clone, Copy)]
pub struct Scheme {
    /// `-digest`: the hash signed over, or `None` for a scheme that takes the
    /// message whole (`EdDSA`, ML-DSA).
    pub digest: Option<&'static str>,
    /// `-pkeyopt` arguments: RSA padding, PSS salt and mask, an ML-DSA
    /// context.
    pub pkeyopts: &'static [&'static str],
    pub encoding: Encoding,
}

/// The shape of the signature bytes.
#[derive(Debug, Clone, Copy)]
pub enum Encoding {
    /// An ECDSA `Ecdsa-Sig-Value`, a DER `SEQUENCE` of two `INTEGER`s, each
    /// no longer than the curve's scalar.
    Der { scalar: usize },
    /// The same two integers as fixed-width big-endian values side by side
    /// (IEEE P1363), as JOSE, `WebCrypto` and PKCS#11 write ECDSA. The command
    /// line writes DER, so a fixture in this encoding is converted from it.
    P1363 { scalar: usize },
    /// A fixed length: the modulus for RSA, the scheme's size otherwise.
    Bytes(usize),
}

/// What `sign_data` must do.
#[derive(Debug, Clone, Copy)]
pub enum Sign {
    /// It signs, recording the algorithm under Rite's name, in this scheme.
    Signs(&'static str, Scheme),
    Fails(Why, Refusal),
}

/// What `verify_signature` must do.
#[derive(Debug, Clone, Copy)]
pub enum Verify {
    /// It accepts the signature, recording the algorithm under Rite's name.
    Verifies(&'static str),
    Fails(Why, Refusal),
}

/// One `sign_data` step: where its key comes from, the key's type, the
/// `algorithm:` it names, and what must happen.
#[derive(Debug, Clone, Copy)]
pub struct SignCase {
    pub source: Source,
    pub key: TestKey,
    /// `algorithm:` as a ceremony writes it, so a name Rite does not know can
    /// be a case. `None` leaves the key's default.
    pub algorithm: Option<&'static str>,
    pub expect: Expected<Sign>,
}

impl SignCase {
    pub fn name(&self) -> String {
        let row = format!("sign_data::{}::{}", self.source.name(), self.key.stem());
        match self.algorithm {
            None => row,
            Some(algorithm) => format!("{row}::{algorithm}"),
        }
    }
}

/// A fixture verified with its key in another form than the SPKI DER file.
#[derive(Debug, Clone, Copy)]
pub struct ShapeCase {
    /// The name of a row of `FIXTURES`.
    pub fixture: &'static str,
    pub shape: Shape,
    pub expect: Expected<Verify>,
}

/// A signature made outside Rite by `openssl pkeyutl -sign` over
/// [`crate::signatures::MESSAGE`], committed under `fixtures/signatures/`.
///
/// The fields are the command, so regenerating a fixture and reading what it
/// is are the same table.
#[derive(Debug, Clone, Copy)]
pub struct SignatureFixture {
    /// The file name under `fixtures/signatures/`, without `.sig`.
    pub name: &'static str,
    /// The key that signs it, whose public half `verify_signature` is given.
    pub key: TestKey,
    pub scheme: Scheme,
    /// `algorithm:` on the `verify_signature` step; `None` leaves the key's
    /// default.
    pub algorithm: Option<&'static str>,
    pub expect: Expected<Verify>,
}
