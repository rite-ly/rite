//! A share as rows of characters written on paper and typed back.
//!
//! The wire layout of the share, `[version][threshold][index] || y`, as
//! paper32 ([`rite_model::paper32`]): rows of 28 base-32 characters and 4
//! of parity. A 32-byte secret gives two rows of 32 characters. A wrong
//! character in a row is corrected and named; two unreadable ones are
//! recovered; a row that needs more is refused by name, for the person to
//! read again from the sheet.
//!
//! The version byte is the wire container's, and it says what follows it,
//! so a later layout (one without the threshold, say) is a second version
//! read by the same decoder. What the sheet is labelled is printed on it,
//! not coded into the rows.

use rite_model::paper32::{self, Repair};
use zeroize::Zeroizing;

use super::gf256::Share;
use super::wire::{self, WireError};

/// Write a share as rows, one string with no separators.
pub fn encode(share: &Share) -> String {
    let bytes = Zeroizing::new(wire::encode(share));
    paper32::encode(&bytes)
}

/// A share read back from rows a person typed, and what it took.
#[derive(Debug)]
pub struct Read {
    /// The share.
    pub share: Share,
    /// The rows that needed repair, in order, for the person to check.
    pub repaired: Vec<Repair>,
}

/// Read a share back from rows a person typed.
///
/// # Errors
///
/// Says what is wrong with the text and where, so the person can look
/// there and type again, or that the bytes inside are not a share.
pub fn decode(text: &str) -> Result<Read, PaperError> {
    let decoded = paper32::decode(text).map_err(PaperError::Text)?;
    let share = wire::decode(&decoded.bytes).map_err(PaperError::Layout)?;
    Ok(Read {
        share,
        repaired: decoded.repaired,
    })
}

/// Why rows did not read as a share.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PaperError {
    /// The rows are malformed, or one cannot be repaired.
    #[error("{0}")]
    Text(paper32::RowError),
    /// The rows read, and the bytes inside are not a share.
    #[error(transparent)]
    Layout(WireError),
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::sharing::gf256::ShareError;
    use rite_model::paper32::{RepairKind, RowError};

    #[test]
    fn a_share_round_trips_through_paper() {
        let share = Share::new(2, 3, vec![0xB9, 0xFA, 0x07, 0xE1, 0x85]).unwrap();
        let text = encode(&share);
        let read = decode(&text).unwrap();
        assert_eq!(read.share, share);
        assert!(read.repaired.is_empty());
        assert_eq!(decode(&text.to_ascii_lowercase()).unwrap().share, share);
        assert_eq!(decode(&format!("  {text}\n")).unwrap().share, share);
    }

    #[test]
    fn a_seed_share_is_two_rows_of_thirty_two() {
        let share = Share::new(2, 1, vec![0x5A; 32]).unwrap();
        assert_eq!(encode(&share).len(), 64);
        let long = Share::new(2, 1, vec![0x5A; 64]).unwrap();
        assert_eq!(decode(&encode(&long)).unwrap().share, long);
    }

    #[test]
    fn a_wrong_character_is_corrected_and_the_row_named() {
        let share = Share::new(3, 2, vec![0x11; 16]).unwrap();
        let text = encode(&share);
        let mut chars: Vec<char> = text.chars().collect();
        chars[20] = if chars[20] == 'Q' { 'R' } else { 'Q' };
        let wrong: String = chars.iter().collect();
        let read = decode(&wrong).unwrap();
        assert_eq!(read.share, share);
        assert_eq!(read.repaired.len(), 1);
        assert_eq!(read.repaired[0].kind, RepairKind::Wrong { position: 20 });
        assert!(
            read.repaired[0]
                .to_string()
                .starts_with("row 1: character 21 was wrong"),
            "{}",
            read.repaired[0]
        );
    }

    #[test]
    fn what_is_not_a_share_is_refused_by_name() {
        // Well-formed rows whose bytes name threshold 1.
        let text = paper32::encode(&[1u8, 1, 1, 0xAA]);
        assert!(matches!(
            decode(&text),
            Err(PaperError::Layout(WireError::Share(
                ShareError::ThresholdBelowTwo(1)
            )))
        ));
        assert!(matches!(
            decode("ABCD"),
            Err(PaperError::Text(RowError::Shape { characters: 4 }))
        ));
    }
}
