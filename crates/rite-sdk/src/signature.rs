//! The encodings a signature arrives in.
//!
//! An ECDSA signature is two integers, `r` and `s`, written in one of two
//! ways: DER, a `SEQUENCE` of two `INTEGER`s, which X.509, CMS and OpenSSL
//! use; or the two values side by side at the width of the curve, as IEEE
//! 1363 defines it and JOSE, Web Crypto and most PKCS#11 tools write it. Rite
//! signs in DER, and a verifier reads DER, so a signature that arrives in the
//! other form is rewritten as DER first.
//!
//! Valid DER is read as DER first. The rewrite carries the same two integers,
//! so it accepts no signature that would not verify in DER. The one input both
//! readings fit is an `r || s` whose bytes also happen to form two minimal DER
//! `INTEGER`s, around one in 2^40: it is read as DER and fails to verify,
//! which refuses a good signature and never accepts a bad one.

use std::borrow::Cow;

use x509_cert::der::asn1::UintRef;
use x509_cert::der::{Decode, Encode};

use crate::{BackendError, EcCurve, SignAlgorithm};

/// `signature` in the encoding a verifier reads for `algorithm`.
///
/// For ECDSA, a DER signature is returned as it is, and `r || s` at the
/// width of the curve is rewritten as DER. Every other algorithm has one
/// encoding, and its signature is returned as it is.
///
/// # Errors
///
/// Returns [`BackendError::InvalidData`] for an ECDSA signature that is
/// neither DER nor `r || s` of the curve's width.
pub fn in_der(algorithm: SignAlgorithm, signature: &[u8]) -> Result<Cow<'_, [u8]>, BackendError> {
    let Some(width) = scalar_width(algorithm) else {
        return Ok(Cow::Borrowed(signature));
    };
    let der = read_der(signature);
    if der.is_ok() {
        return Ok(Cow::Borrowed(signature));
    }
    if let Some((r, s)) = signature.split_at_checked(width)
        && s.len() == width
    {
        return der_of(r, s).map(Cow::Owned);
    }
    // Bytes that open with a SEQUENCE tag were most likely meant as DER, so
    // the refusal says what in them is not.
    let why = match der {
        Err(reason) if signature.first() == Some(&SEQUENCE) => {
            format!(". Read as DER: {reason}")
        }
        _ => String::new(),
    };
    Err(BackendError::InvalidData(format!(
        "{algorithm} takes a DER signature, or r || s in {} bytes, and this one is {} bytes \
         and neither{why}",
        width.saturating_mul(2),
        signature.len()
    )))
}

/// The DER tag of a `SEQUENCE`.
const SEQUENCE: u8 = 0x30;

/// The width of `r` and of `s` in the fixed-width encoding, from the one
/// curve the algorithm signs with, or `None` for an algorithm that is not
/// ECDSA. [`SignAlgorithm::key_algorithm`] and [`EcCurve::of`] both list
/// every variant, so a new ECDSA scheme is placed at compile time.
fn scalar_width(algorithm: SignAlgorithm) -> Option<usize> {
    EcCurve::of(algorithm.key_algorithm()).map(EcCurve::scalar_len)
}

/// Whether `bytes` are exactly a DER `SEQUENCE` of two `INTEGER`s, with
/// nothing after it, and if not, why.
fn read_der(bytes: &[u8]) -> Result<(), String> {
    let integers = Vec::<UintRef<'_>>::from_der(bytes).map_err(|e| e.to_string())?;
    match integers.len() {
        2 => Ok(()),
        n => Err(format!(
            "a signature is two INTEGERs, and this SEQUENCE holds {n}"
        )),
    }
}

fn der_of(r: &[u8], s: &[u8]) -> Result<Vec<u8>, BackendError> {
    let integer = |value| {
        UintRef::new(value)
            .map_err(|e| BackendError::InvalidData(format!("ECDSA signature value: {e}")))
    };
    vec![integer(r)?, integer(s)?]
        .to_der()
        .map_err(|e| BackendError::InvalidData(format!("ECDSA signature as DER: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `r` with its high bit set, so its DER `INTEGER` needs a leading zero,
    /// and `s` with leading zeroes, which DER drops.
    fn p256_raw() -> Vec<u8> {
        let mut raw = vec![0x80; 32];
        raw.extend([0x00, 0x00, 0x01]);
        raw.extend([0x02; 29]);
        raw
    }

    #[test]
    fn rewrites_r_and_s_as_der() {
        let raw = p256_raw();
        let der = in_der(SignAlgorithm::EcdsaSha256, &raw).unwrap();
        let mut expected = vec![0x30, 0x43, 0x02, 0x21, 0x00];
        expected.extend([0x80; 32]);
        expected.extend([0x02, 0x1e, 0x01]);
        expected.extend([0x02; 29]);
        assert_eq!(der.as_ref(), expected.as_slice());
        assert!(matches!(der, Cow::Owned(_)));
    }

    #[test]
    fn passes_der_through_unchanged() {
        let der = in_der(SignAlgorithm::EcdsaSha256, &p256_raw())
            .unwrap()
            .into_owned();
        let again = in_der(SignAlgorithm::EcdsaSha256, &der).unwrap();
        assert!(matches!(again, Cow::Borrowed(bytes) if bytes == der.as_slice()));
    }

    #[test]
    fn reads_the_width_from_the_algorithms_curve() {
        let raw = vec![0x01; 96];
        assert!(in_der(SignAlgorithm::EcdsaSha384, &raw).is_ok());
        let error = in_der(SignAlgorithm::EcdsaSha256, &raw).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid data: ECDSA-SHA256 takes a DER signature, or r || s in 64 bytes, and \
             this one is 96 bytes and neither"
        );
    }

    /// Bytes that open as a `SEQUENCE` were meant as DER, and the refusal
    /// says what is wrong with them.
    #[test]
    fn says_why_bytes_that_open_as_der_are_not() {
        let error = in_der(SignAlgorithm::EcdsaSha256, &[0x30, 0x03, 0x02, 0x01, 0x01])
            .unwrap_err()
            .to_string();
        assert!(
            error.ends_with(
                "and neither. Read as DER: a signature is two INTEGERs, and this SEQUENCE holds 1"
            ),
            "{error}"
        );
    }

    #[test]
    fn reads_as_der_only_two_minimal_integers() {
        assert!(read_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_ok());
        // An `INTEGER` with a leading zero it does not need.
        assert!(read_der(&[0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x01]).is_err());
        // One integer, three, and bytes after the sequence.
        assert!(read_der(&[0x30, 0x03, 0x02, 0x01, 0x01]).is_err());
        assert!(
            read_der(&[
                0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01
            ])
            .is_err()
        );
        assert!(read_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]).is_err());
    }

    #[test]
    fn leaves_other_algorithms_alone() {
        let bytes = [0x01; 7];
        for algorithm in [SignAlgorithm::Ed25519, SignAlgorithm::RsaPkcs1Sha256] {
            let out = in_der(algorithm, &bytes).unwrap();
            assert!(matches!(out, Cow::Borrowed(b) if b == bytes));
        }
    }
}
