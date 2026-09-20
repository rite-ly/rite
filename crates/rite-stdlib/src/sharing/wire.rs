//! The byte layout of a share, for a file or a transport.
//!
//! `[version][threshold][index] || y`, version `0x01`. The version belongs
//! to this container and not to the share: a share is its three parts, and
//! a later layout (one that carries an identifier, say) is a second version
//! here rather than a change to the arithmetic. A paper encoding is another
//! container again, and reads the parts directly so it can lay them out.
//!
//! Minus the first two bytes, this is the plain TSS share of
//! draft-mcgrew-tss-03 section 3, `index || y`.

use super::gf256::{Share, ShareError};

/// The version byte this layout starts with.
const VERSION: u8 = 1;

/// Bytes in front of the `y` values: version, threshold, index.
const HEADER_LEN: usize = 3;

/// Lay a share out as bytes.
pub fn encode(share: &Share) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN.saturating_add(share.secret_len()));
    bytes.push(VERSION);
    bytes.push(share.threshold());
    bytes.push(share.index());
    bytes.extend_from_slice(share.y());
    bytes
}

/// Read a share back from bytes this module laid out.
pub fn decode(bytes: &[u8]) -> Result<Share, WireError> {
    let (&version, rest) = bytes.split_first().ok_or(WireError::TooShort)?;
    if version != VERSION {
        return Err(WireError::UnknownVersion(version));
    }
    let (&threshold, rest) = rest.split_first().ok_or(WireError::TooShort)?;
    let (&index, y) = rest.split_first().ok_or(WireError::TooShort)?;
    Share::new(threshold, index, y.to_vec()).map_err(WireError::Share)
}

/// Why bytes did not read as a share.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// Fewer than the three header bytes.
    #[error("a share starts with three bytes: version, threshold and index")]
    TooShort,
    /// The first byte is not a version this build reads.
    #[error("share layout version {0} is not one this build reads")]
    UnknownVersion(u8),
    /// The header read, and the parts it names are not a share.
    #[error(transparent)]
    Share(ShareError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_round_trips_through_the_layout() {
        let share = Share::new(2, 3, vec![0xB9, 0xFA]).unwrap();
        let bytes = encode(&share);
        assert_eq!(bytes, [1, 2, 3, 0xB9, 0xFA]);
        assert_eq!(decode(&bytes).unwrap(), share);
    }

    #[test]
    fn the_layout_refuses_what_it_cannot_read() {
        assert_eq!(decode(&[1, 2]), Err(WireError::TooShort));
        assert_eq!(decode(&[2, 2, 1, 0]), Err(WireError::UnknownVersion(2)));
        assert_eq!(decode(&[1, 2, 1]), Err(WireError::Share(ShareError::Empty)));
        assert_eq!(
            decode(&[1, 1, 1, 0]),
            Err(WireError::Share(ShareError::ThresholdBelowTwo(1)))
        );
        assert_eq!(
            decode(&[1, 2, 0, 0]),
            Err(WireError::Share(ShareError::IndexZero))
        );
    }
}
