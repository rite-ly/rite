//! How a value is written out for a person: the encodings `reveal` shows,
//! and the shape each gives a sheet of paper.
//!
//! The shape is a property of the encoding and not of the value, so
//! `rite script` prints it before the ceremony runs: how many
//! characters make a row, how many of those are parity, how characters
//! group for the eye, what the alphabet is and what the encoding is
//! called. Only the number of rows depends on the value, and a sheet does
//! not need it when every row has the same shape.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::paper32;

/// An encoding a value is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
#[cfg_attr(
    test,
    schemars(description = "The encoding a value is written on paper in.")
)]
#[non_exhaustive]
pub enum RevealFormat {
    /// Rows of 32 base-32 characters, 28 of data and 4 of parity, from an
    /// alphabet without `I`, `L`, `O` and `U`; a wrong character in a row
    /// is corrected, two unreadable ones recovered. The default. See
    /// [`paper32`].
    #[cfg_attr(
        test,
        schemars(
            description = "Rows of 32 base-32 characters, 28 of data and 4 of parity; a wrong \
            character in a row is corrected."
        )
    )]
    Paper32,
    /// Two hexadecimal digits per byte, upper case, in rows of 32.
    #[cfg_attr(
        test,
        schemars(description = "Two hexadecimal digits per byte, in rows of 32.")
    )]
    Hex,
}

impl RevealFormat {
    /// The name a ceremony writes.
    pub fn as_str(self) -> &'static str {
        match self {
            RevealFormat::Paper32 => "paper32",
            RevealFormat::Hex => "hex",
        }
    }

    /// The shape a sheet takes for this encoding.
    pub fn layout(self) -> Layout {
        match self {
            RevealFormat::Paper32 => Layout {
                format: self,
                group: 4,
                row: paper32::ROW_DATA,
                parity: paper32::ROW_PARITY,
                alphabet: "Digits and letters, never I, L, O or U; upper or lower case".to_string(),
                algorithm: "Paper32: rows of 28 characters and 4 of parity, Reed-Solomon over \
                            GF(32)"
                    .to_string(),
            },
            RevealFormat::Hex => Layout {
                format: self,
                group: 4,
                row: 32,
                parity: 0,
                alphabet: "Digits 0 to 9 and letters A to F".to_string(),
                algorithm: "Hexadecimal, two characters per byte".to_string(),
            },
        }
    }

    /// The shape a `reveal` step gives from its definition: its format, or
    /// the default.
    pub fn layout_for(format: Option<Self>) -> Layout {
        format.unwrap_or(RevealFormat::Paper32).layout()
    }

    /// Rows a value of `bytes` bytes takes.
    pub fn rows(self, bytes: usize) -> usize {
        let layout = self.layout();
        self.characters(bytes)
            .div_ceil(layout.row.saturating_add(layout.parity).max(1))
    }

    /// One row as typed, checked on its own: the characters it should be,
    /// and the repair it took, in words. `row` is its number from 1, and
    /// `more` says rows are known to follow it.
    ///
    /// Every row but the last is full, since a row's place in the value is
    /// its position: a short row is the last one, and one with rows after
    /// it is a row with characters missing.
    ///
    /// ```
    /// use rite_model::RevealFormat;
    ///
    /// let row = RevealFormat::Paper32.read_row("E9MQ 8S8P H8B", 1, false).unwrap();
    /// assert_eq!(row.text.as_str(), "E9MQ8S8PH8B");
    /// assert!(!row.full);
    /// // A short row where more are to come has characters missing.
    /// assert!(RevealFormat::Paper32.read_row("E9MQ8S8PH8B", 1, true).is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// What is wrong with the row, in words, for the person to fix.
    pub fn read_row(self, text: &str, row: usize, more: bool) -> Result<TypedRow, String> {
        let read = self.read_one_row(text, row)?;
        let full = self.layout().row.saturating_add(self.layout().parity);
        let characters = read.text.chars().count();
        if more && characters < full {
            return Err(format!(
                "{characters} characters; every row but the last has {full}"
            ));
        }
        Ok(TypedRow {
            full: characters == full,
            ..read
        })
    }

    fn read_one_row(self, text: &str, row: usize) -> Result<TypedRow, String> {
        match self {
            RevealFormat::Paper32 => paper32::read_row(text, row)
                .map(|read| TypedRow {
                    text: read.text,
                    repair: read.repair.map(|r| r.to_string()),
                    full: false,
                })
                .map_err(|e| e.to_string()),
            RevealFormat::Hex => {
                let digits = hex_digits(text)?;
                let row_len = self.layout().row;
                if digits.is_empty() {
                    return Err("nothing to read".to_string());
                }
                if digits.len() > row_len {
                    return Err(format!(
                        "{} characters; a row has at most {row_len}",
                        digits.len()
                    ));
                }
                Ok(TypedRow {
                    text: digits,
                    repair: None,
                    full: false,
                })
            }
        }
    }

    /// A whole value as typed, rows one after another: its bytes, and the
    /// repairs it took, in words.
    ///
    /// # Errors
    ///
    /// What is wrong with the text, in words.
    pub fn decode(self, text: &str) -> Result<TypedValue, String> {
        match self {
            RevealFormat::Paper32 => paper32::decode(text)
                .map(|decoded| TypedValue {
                    bytes: decoded.bytes,
                    repaired: decoded.repaired.iter().map(ToString::to_string).collect(),
                })
                .map_err(|e| e.to_string()),
            RevealFormat::Hex => {
                let digits = hex_digits(text)?;
                if digits.len() % 2 != 0 {
                    return Err(format!(
                        "{} hexadecimal digits; a byte is two",
                        digits.len()
                    ));
                }
                let bytes = digits
                    .as_bytes()
                    .chunks(2)
                    .map(|pair| {
                        std::str::from_utf8(pair)
                            .ok()
                            .and_then(|p| u8::from_str_radix(p, 16).ok())
                            .unwrap_or(0)
                    })
                    .collect();
                Ok(TypedValue {
                    bytes: Zeroizing::new(bytes),
                    repaired: Vec::new(),
                })
            }
        }
    }

    /// Characters a value of `bytes` bytes takes, parity included.
    pub fn characters(self, bytes: usize) -> usize {
        match self {
            RevealFormat::Paper32 => {
                let symbols = bytes.saturating_mul(8).div_ceil(5);
                let rows = symbols.div_ceil(paper32::ROW_DATA);
                symbols.saturating_add(rows.saturating_mul(paper32::ROW_PARITY))
            }
            RevealFormat::Hex => bytes.saturating_mul(2),
        }
    }
}

impl fmt::Display for RevealFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A row [`RevealFormat::read_row`] read.
#[derive(Debug)]
pub struct TypedRow {
    /// The row as it should read, upper case, without separators.
    pub text: Zeroizing<String>,
    /// The repair it took, in words.
    pub repair: Option<String>,
    /// Whether the row has every character a row can have. A row that
    /// does not is the last one.
    pub full: bool,
}

/// A value [`RevealFormat::decode`] read.
#[derive(Debug)]
pub struct TypedValue {
    /// The bytes, wiped when dropped.
    pub bytes: Zeroizing<Vec<u8>>,
    /// The repairs, in words, one per row that took one.
    pub repaired: Vec<String>,
}

/// Hexadecimal digits in upper case, separators dropped.
fn hex_digits(text: &str) -> Result<Zeroizing<String>, String> {
    let mut digits = Zeroizing::new(String::with_capacity(text.len()));
    for (position, c) in text.chars().enumerate() {
        match c {
            ' ' | '-' | '|' | '\t' | '\n' | '\r' | '.' => {}
            c if c.is_ascii_hexdigit() => digits.push(c.to_ascii_uppercase()),
            _ => {
                return Err(format!(
                    "character {} is not a hexadecimal digit (0 to 9, A to F)",
                    position.saturating_add(1)
                ));
            }
        }
    }
    Ok(digits)
}

/// A `format:` value that names no encoding this build shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRevealFormat(pub String);

impl fmt::Display for UnknownRevealFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "'{}' is not a format; use paper32 or hex", self.0)
    }
}

impl std::error::Error for UnknownRevealFormat {}

impl FromStr for RevealFormat {
    type Err = UnknownRevealFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "paper32" => Ok(RevealFormat::Paper32),
            "hex" => Ok(RevealFormat::Hex),
            other => Err(UnknownRevealFormat(other.to_string())),
        }
    }
}

/// The shape a written value takes: what a sheet pre-prints and how a
/// screen lays the characters out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// The encoding.
    pub format: RevealFormat,
    /// Characters per group, for the eye.
    pub group: usize,
    /// Data characters in a full row.
    pub row: usize,
    /// Parity characters closing every row; zero when there are none.
    pub parity: usize,
    /// What the characters can be, in words.
    pub alphabet: String,
    /// What the encoding is called, in small print.
    pub algorithm: String,
}

impl Default for Layout {
    fn default() -> Self {
        RevealFormat::Paper32.layout()
    }
}

impl Layout {
    /// Split a written value into rows, each its data in groups and its
    /// parity, for a screen to style each part.
    pub fn rows<'a>(&self, text: &'a str) -> Vec<Row<'a>> {
        let row_len = self.row.saturating_add(self.parity).max(1);
        text.as_bytes()
            .chunks(row_len)
            .map(|chunk| {
                let line = std::str::from_utf8(chunk).unwrap_or_default();
                let data_len = line.len().saturating_sub(self.parity);
                let (data, parity) = line.split_at(data_len.min(line.len()));
                let groups = data
                    .as_bytes()
                    .chunks(self.group.max(1))
                    .map(|g| std::str::from_utf8(g).unwrap_or_default())
                    .collect();
                Row { groups, parity }
            })
            .collect()
    }
}

/// One row of a written value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row<'a> {
    /// The data, grouped.
    pub groups: Vec<&'a str>,
    /// The parity characters, possibly empty.
    pub parity: &'a str,
}

/// Bytes as upper-case hex.
pub fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, b| {
            let _ = write!(out, "{b:02X}");
            out
        },
    )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_row_is_checked_on_its_own_and_a_value_read_whole() {
        // 30 bytes: a full row of 28 and 4, then 20 and 4.
        let bytes = [0x5A; 30];
        let text = paper32::encode(&bytes);
        let (first, second) = text.split_at(32);
        let row = RevealFormat::Paper32.read_row(first, 1, true).unwrap();
        assert_eq!(row.text.as_str(), first);
        assert!(row.repair.is_none());
        assert!(row.full);

        let mut slipped: Vec<char> = second.to_ascii_lowercase().chars().collect();
        slipped[3] = if slipped[3] == 'a' { 'b' } else { 'a' };
        let slipped: String = slipped.iter().collect();
        let row = RevealFormat::Paper32.read_row(&slipped, 2, false).unwrap();
        assert_eq!(row.text.as_str(), second);
        assert!(!row.full);
        assert!(row.repair.unwrap().starts_with("row 2: character 4"));
        assert!(RevealFormat::Paper32.read_row("ABCD", 1, false).is_err());
        // The short last row, where the sheet says more rows follow.
        let refused = RevealFormat::Paper32.read_row(second, 1, true).unwrap_err();
        assert!(
            refused.contains("every row but the last has 32"),
            "{refused}"
        );

        let value = RevealFormat::Paper32
            .decode(&format!("{first}\n{slipped}"))
            .unwrap();
        assert_eq!(*value.bytes, bytes);
        assert_eq!(value.repaired.len(), 1);

        let hex = RevealFormat::Hex.read_row("de ad-be ef", 1, false).unwrap();
        assert_eq!(hex.text.as_str(), "DEADBEEF");
        assert!(!hex.full);
        assert!(RevealFormat::Hex.read_row("DEAG", 1, false).is_err());
        assert!(RevealFormat::Hex.read_row("DEADBEEF", 1, true).is_err());
        assert_eq!(
            *RevealFormat::Hex.decode("DEAD\nbeef").unwrap().bytes,
            [0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert!(RevealFormat::Hex.decode("DEA").is_err());
        assert_eq!(RevealFormat::Paper32.rows(35), 2);
        assert_eq!(RevealFormat::Hex.rows(35), 3);
    }

    #[test]
    fn a_paper32_string_splits_into_rows_of_groups_and_parity() {
        let layout = RevealFormat::Paper32.layout();
        let text = paper32::encode(&[0x5A; 35]);
        let rows = layout.rows(&text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].groups.len(), 7);
        assert!(rows[0].groups.iter().all(|g| g.len() == 4));
        assert_eq!(rows[0].parity.len(), 4);
        assert_eq!(rows[1].parity.len(), 4);
        assert_eq!(RevealFormat::Paper32.characters(35), 64);
        assert_eq!(RevealFormat::Paper32.characters(32), 60);
        assert_eq!(RevealFormat::Paper32.characters(1), 6);
    }

    #[test]
    fn hex_has_no_parity() {
        let layout = RevealFormat::Hex.layout();
        let rows = layout.rows("DEADBEEF01");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].groups, ["DEAD", "BEEF", "01"]);
        assert_eq!(rows[0].parity, "");
        assert_eq!(hex_upper(&[0xde, 0xad]), "DEAD");
        assert_eq!(RevealFormat::Hex.characters(5), 10);
    }

    #[test]
    fn a_format_is_named_and_parsed() {
        assert_eq!("paper32".parse(), Ok(RevealFormat::Paper32));
        assert_eq!(RevealFormat::Hex.to_string(), "hex");
        assert_eq!(
            "words".parse::<RevealFormat>().unwrap_err().to_string(),
            "'words' is not a format; use paper32 or hex"
        );
    }
}
