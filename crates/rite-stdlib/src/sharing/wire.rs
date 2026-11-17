//! The byte layout of a share, for a file or a transport.
//!
//! `[version][threshold][index] || y`. The version byte names the scheme the
//! share was made under, and so the layout of what follows it: `0x01` is
//! `rite-sss/v1`. The split chooses the scheme, the share set remembers it,
//! and [`encode`] writes that scheme's layout; [`decode`] reads every version
//! this build knows and says which scheme it found. A later layout (one that
//! carries an identifier, say) is a second scheme and a second version byte,
//! not a change to this one.
//!
//! A share written in this layout is meant to be read back years later, by
//! a later build or by hand, so the `rite-sss/v1` layout does not change.
//! A paper encoding is another container again, and reads the parts directly
//! so it can lay them out.
//!
//! Minus the first two bytes, this is the plain TSS share of
//! draft-mcgrew-tss-03 section 3, `index || y`.

use rite_model::SharingScheme;

use super::gf256::{Share, ShareError};

/// Lay a share made under `scheme` out as bytes.
pub fn encode(scheme: SharingScheme, share: &Share) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(scheme.share_len(share.secret_len()));
    bytes.push(scheme.version_byte());
    bytes.push(share.threshold());
    bytes.push(share.index());
    bytes.extend_from_slice(share.y());
    bytes
}

/// A share read back from bytes, and the scheme its version byte names.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    /// The scheme the share was made under.
    pub scheme: SharingScheme,
    /// The share.
    pub share: Share,
}

/// Read a share back from bytes laid out by [`encode`], under any scheme
/// this build reads.
///
/// # Errors
///
/// Says why the bytes are not a share: too short, a version this build does
/// not read, or parts that do not make a share.
pub fn decode(bytes: &[u8]) -> Result<Decoded, WireError> {
    let (&version, rest) = bytes.split_first().ok_or(WireError::TooShort)?;
    let scheme =
        SharingScheme::from_version_byte(version).ok_or(WireError::UnknownVersion(version))?;
    let (&threshold, rest) = rest.split_first().ok_or(WireError::TooShort)?;
    let (&index, y) = rest.split_first().ok_or(WireError::TooShort)?;
    let share = Share::new(threshold, index, y.to_vec()).map_err(WireError::Share)?;
    Ok(Decoded { scheme, share })
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
        let bytes = encode(SharingScheme::RiteSssV1, &share);
        assert_eq!(bytes, [1, 2, 3, 0xB9, 0xFA]);
        assert_eq!(bytes.len(), SharingScheme::RiteSssV1.share_len(2));
        assert_eq!(
            decode(&bytes).unwrap(),
            Decoded {
                scheme: SharingScheme::RiteSssV1,
                share
            }
        );
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
