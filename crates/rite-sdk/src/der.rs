//! The DER a CMS structure is written in, and nothing more.
//!
//! Self-contained on purpose. It knows how to put a tag, a length and a body
//! together, and it knows nothing about CMS, keys or ciphers. Everything here
//! is under a hundred lines so that the one place Rite hand-writes ASN.1 can be
//! read in full before trusting it.
//!
//! Definite-length form only, which is what DER requires and what
//! [`crate::cms`]'s reader accepts. There is no decoder here: the reader has
//! its own walker, built for untrusted input.

/// The DER length octets for a body of `len` bytes.
///
/// Short form below 128, long form above, with no leading zero byte, as X.690
/// §8.1.3 requires of DER.
fn length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![u8::try_from(len).unwrap_or(0x7f)];
    }
    // DER's long form carries the fewest octets that hold the value, so the
    // leading zeroes of the native representation come off. The branch above
    // means at least one octet is left.
    let body: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|byte| *byte == 0)
        .collect();
    let mut out = Vec::with_capacity(body.len().saturating_add(1));
    // The count of length octets fits in seven bits for any body a machine
    // holds, so the high bit is free to mark the long form.
    out.push(0x80 | u8::try_from(body.len()).unwrap_or(0x7f));
    out.extend_from_slice(&body);
    out
}

/// A tag, its length, and its body.
#[must_use]
pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len().saturating_add(6));
    out.push(tag);
    out.extend_from_slice(&length(body.len()));
    out.extend_from_slice(body);
    out
}

/// `SEQUENCE` of already-encoded elements.
#[must_use]
pub fn sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &elements.concat())
}

/// `SET OF` already-encoded elements.
///
/// The caller orders them. Rite writes one element, so there is nothing to
/// sort; a `SET OF` with several would need DER's ordering rule applied first.
#[must_use]
pub fn set_of(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &elements.concat())
}

/// `OCTET STRING`.
#[must_use]
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// `INTEGER`, for the small non-negative values a CMS version or length is.
#[must_use]
pub fn small_integer(value: u8) -> Vec<u8> {
    // A value above 127 would need a leading zero to stay positive. Nothing
    // here writes one, and a silent sign flip is worse than a wider encoding.
    if value < 0x80 {
        tlv(0x02, &[value])
    } else {
        tlv(0x02, &[0x00, value])
    }
}

/// `OBJECT IDENTIFIER`, from dotted decimal.
///
/// Returns `None` for anything that is not two or more numeric arcs with the
/// first below 3 and, where the first is below 2, the second below 40. Callers
/// pass this crate's own constants, so the failure is unreachable in practice
/// and is a `None` rather than a panic because this crate forbids panicking.
#[must_use]
pub fn object_identifier(dotted: &str) -> Option<Vec<u8>> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc| arc.parse().ok())
        .collect::<Option<_>>()?;
    let (&first, rest) = arcs.split_first()?;
    let (&second, rest) = rest.split_first()?;
    if first > 2 || (first < 2 && second >= 40) {
        return None;
    }
    // X.690 §8.19.4: the first two arcs share one subidentifier.
    let mut body = base128(first.saturating_mul(40).saturating_add(second));
    for &arc in rest {
        body.extend_from_slice(&base128(arc));
    }
    Some(tlv(0x06, &body))
}

/// One subidentifier: base-128, big-endian, continuation bit on every octet
/// but the last.
fn base128(mut value: u64) -> Vec<u8> {
    let mut out = vec![u8::try_from(value & 0x7f).unwrap_or(0)];
    value >>= 7;
    while value > 0 {
        out.push(u8::try_from(value & 0x7f).unwrap_or(0) | 0x80);
        value >>= 7;
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_short_and_long_lengths() {
        assert_eq!(tlv(0x04, &[]), vec![0x04, 0x00]);
        assert_eq!(tlv(0x04, &[0xaa]), vec![0x04, 0x01, 0xaa]);
        // 127 is the last short form, 128 the first long one.
        assert!(tlv(0x04, &[0; 127]).starts_with(&[0x04, 0x7f]));
        assert!(tlv(0x04, &[0; 128]).starts_with(&[0x04, 0x81, 0x80]));
        assert!(tlv(0x04, &[0; 256]).starts_with(&[0x04, 0x82, 0x01, 0x00]));

        // The header is all that changes, so the whole encoding is the header
        // plus the body and nothing else.
        assert_eq!(tlv(0x04, &[0; 300]).len(), 300 + 4);
    }

    /// The published encodings of the identifiers this crate writes, from
    /// X.690 §8.19 and the registry entries themselves.
    #[test]
    fn writes_the_known_object_identifiers() {
        // X.690 §8.19.5's own example, 2.100.3, whose second arc needs two
        // octets. Rite writes no such OID; it is here because the multi-octet
        // path is the one a hand-rolled encoder gets wrong.
        assert_eq!(
            object_identifier("2.100.3").unwrap(),
            vec![0x06, 0x03, 0x81, 0x34, 0x03]
        );
        // id-aes256-wrap, 2.16.840.1.101.3.4.1.45.
        assert_eq!(
            object_identifier(crate::types::oid::AES_256_WRAP).unwrap(),
            vec![
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2d
            ]
        );
        // id-aes256-GCM, 2.16.840.1.101.3.4.1.46.
        assert_eq!(
            object_identifier(crate::types::oid::AES_256_GCM).unwrap(),
            vec![
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2e
            ]
        );
        // pkcs7-data, 1.2.840.113549.1.7.1.
        assert_eq!(
            object_identifier("1.2.840.113549.1.7.1").unwrap(),
            vec![
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01
            ]
        );
    }

    #[test]
    fn refuses_what_is_not_an_object_identifier() {
        for bad in ["", "1", "1.x", "3.0.1", "1.40.1"] {
            assert!(object_identifier(bad).is_none(), "{bad} was accepted");
        }
    }

    #[test]
    fn writes_integers_that_stay_positive() {
        assert_eq!(small_integer(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(small_integer(4), vec![0x02, 0x01, 0x04]);
        assert_eq!(small_integer(12), vec![0x02, 0x01, 0x0c]);
        assert_eq!(small_integer(0x80), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn nests_constructed_types() {
        assert_eq!(
            sequence(&[small_integer(1), octet_string(&[0xff])]),
            vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 0xff]
        );
        assert_eq!(
            set_of(&[small_integer(1)]),
            vec![0x31, 0x03, 0x02, 0x01, 0x01]
        );
    }
}
