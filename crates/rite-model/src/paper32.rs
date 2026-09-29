//! Paper32: bytes as rows of base-32 characters a person writes down and
//! types back, with parity that repairs a slip and refuses a row it cannot
//! repair.
//!
//! The alphabet is Crockford's base 32, `0-9` and the letters without
//! `I`, `L`, `O` and `U`, one character per five bits. The decoder takes
//! either case and reads `O` as `0` and `I` or `L` as `1`, since those are
//! what a hand writes for them; a `?` is a character the person could not
//! read, an erasure, and so is a `U`, which stands for one character but
//! not which. Spaces and separators between groups are ignored; any other
//! character is refused where it stands.
//!
//! The characters go in rows of 32: 28 of data and 4 of parity, the last
//! row shorter and still ending in its 4 parity characters. Each row is a
//! Reed-Solomon codeword over GF(32): the data characters fix a polynomial
//! of degree below their count, evaluated at the first points of a fixed
//! order of the 32 field elements, and the parity characters are that
//! polynomial at the last four points. Any four characters of a row
//! determine the other 28, so a row repairs one wrong character or two
//! unreadable ones and still has two characters of parity to check the
//! repair against. Beyond that it is refused by name: a row that cannot
//! be trusted is one the person reads again, not one the code guesses.
//!
//! A correct sheet decodes without any of this: drop the last four
//! characters of each row and read the rest as base 32.

use std::fmt;

use zeroize::Zeroizing;

/// The alphabet, in five-bit order.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Data characters in a full row.
pub const ROW_DATA: usize = 28;

/// Parity characters closing every row.
pub const ROW_PARITY: usize = 4;

/// Characters in a full row.
pub const ROW_LEN: usize = ROW_DATA + ROW_PARITY;

/// Unreadable characters a row may recover, keeping two characters of
/// parity to check the recovery. One wrong character is the other case.
const MAX_ERASURES: usize = 2;

// ── GF(32) ──────────────────────────────────────────────────────────────────

/// The field polynomial, x^5 + x^2 + 1.
const POLY: u8 = 0b10_0101;

/// Multiply in GF(32).
const fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a & 31;
    let mut b = b & 31;
    let mut product = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            product ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0b10_0000 != 0 {
            a ^= POLY;
        }
    }
    product & 31
}

/// The inverses in GF(32), found once by looking: the field is small.
#[allow(clippy::indexing_slicing)] // `a` is below 32 by the loop's bound
const INVERSES: [u8; 32] = {
    let mut table = [0u8; 32];
    let mut a = 1u8;
    while a < 32 {
        let mut x = 1u8;
        while x < 32 {
            if gf_mul(a, x) == 1 {
                table[a as usize] = x;
            }
            x += 1;
        }
        a += 1;
    }
    table
};

/// The inverse in GF(32); zero has none and gives zero.
fn gf_inv(a: u8) -> u8 {
    INVERSES.get(usize::from(a & 31)).copied().unwrap_or(0)
}

/// The value at `x` of the polynomial through `points`, by Lagrange.
fn interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut basis = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                basis = gf_mul(basis, gf_mul(x ^ xj, gf_inv(xi ^ xj)));
            }
        }
        result ^= gf_mul(yi, basis);
    }
    result
}

// ── rows of paper32 ────────────────────────────────────────────────────────────────

/// The evaluation point of position `i` in a row: the field element `i`,
/// data at 0 to 27, parity at 28 to 31.
fn point(position: usize) -> u8 {
    u8::try_from(position & 31).unwrap_or(0)
}

/// The parity of `data`, the row's polynomial at the four parity points.
fn parity(data: &[u8]) -> [u8; ROW_PARITY] {
    let points: Vec<(u8, u8)> = data
        .iter()
        .enumerate()
        .map(|(i, &d)| (point(i), d))
        .collect();
    let mut out = [0u8; ROW_PARITY];
    for (k, slot) in out.iter_mut().enumerate() {
        *slot = interpolate(&points, point(ROW_DATA.saturating_add(k)));
    }
    out
}

/// Five-bit values of `bytes`, the last padded with zero bits.
fn to_symbols(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(u8::try_from((acc >> bits) & 31).unwrap_or(0));
        }
    }
    if bits > 0 {
        out.push(u8::try_from((acc << (5u32.saturating_sub(bits))) & 31).unwrap_or(0));
    }
    out
}

/// Bytes from five-bit values; the padding must be shorter than a
/// character and zero.
fn from_symbols(symbols: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(symbols.len().saturating_mul(5) / 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &s in symbols {
        acc = (acc << 5) | u32::from(s & 31);
        bits = bits.saturating_add(5);
        while bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    if bits >= 5 || (acc << (8u32.saturating_sub(bits))) & 0xff != 0 {
        return None;
    }
    Some(out)
}

/// Write bytes as rows, one string with no separators. Grouping for the
/// eye is the caller's, since it does not take part in the encoding.
///
/// Four bytes are seven characters of data, the last padded with zero
/// bits, and four of parity:
///
/// ```
/// use rite_model::paper32;
///
/// assert_eq!(paper32::encode(b"rite"), "E9MQ8S8PH8B");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    let symbols = Zeroizing::new(to_symbols(bytes));
    let mut out = String::with_capacity(symbols.len().saturating_add(ROW_LEN).saturating_mul(2));
    for data in symbols.chunks(ROW_DATA) {
        for &s in data {
            out.push(letter(s));
        }
        for p in parity(data) {
            out.push(letter(p));
        }
    }
    out
}

fn letter(symbol: u8) -> char {
    ALPHABET
        .get(usize::from(symbol & 31))
        .map_or('0', |&b| char::from(b))
}

/// What one character of the text is.
enum Read {
    /// A separator between groups: nothing.
    Separator,
    /// A character the person could not read.
    Erasure,
    /// A character of the alphabet, or one usually written for it.
    Value(u8),
    /// A character with no place here.
    Unknown,
}

fn read(c: char) -> Read {
    let c = c.to_ascii_uppercase();
    match c {
        ' ' | '-' | '|' | '\t' | '\n' | '\r' | '.' => Read::Separator,
        // U is outside the alphabet but stands for one character, most
        // often a V: unreadable, so the row still recovers it.
        '?' | 'U' => Read::Erasure,
        'O' => Read::Value(0),
        'I' | 'L' => Read::Value(1),
        _ => ALPHABET
            .iter()
            .position(|&x| char::from(x) == c)
            .and_then(|p| u8::try_from(p).ok())
            .map_or(Read::Unknown, Read::Value),
    }
}

/// Read rows back. The result carries the bytes and what was repaired,
/// so the person can be told which rows needed it.
///
/// # Errors
///
/// A character outside the alphabet, a row that cannot be repaired (more
/// than one wrong character or two unreadable ones), a shape that is not
/// rows, or a length that is not bytes, each named.
///
/// Case, separators and the letters a hand writes for digits are read
/// through; a wrong character is repaired and its row named:
///
/// ```
/// use rite_model::paper32;
///
/// let clean = paper32::decode("e9mq 8s8 | ph8b").unwrap();
/// assert_eq!(*clean.bytes, *b"rite");
/// assert!(clean.repaired.is_empty());
///
/// // The fifth character miscopied: still "rite", with row 1 named.
/// let slipped = paper32::decode("E9MQ9S8PH8B").unwrap();
/// assert_eq!(*slipped.bytes, *b"rite");
/// assert_eq!(slipped.repaired[0].row, 1);
/// ```
pub fn decode(text: &str) -> Result<Decoded, RowError> {
    let mut symbols: Vec<Option<u8>> = Vec::with_capacity(text.len());
    for (position, c) in text.chars().enumerate() {
        match read(c) {
            Read::Separator => {}
            Read::Erasure => symbols.push(None),
            Read::Value(v) => symbols.push(Some(v)),
            Read::Unknown => return Err(RowError::Character { position }),
        }
    }
    if symbols.is_empty() {
        return Err(RowError::Empty);
    }
    let tail = symbols.len() % ROW_LEN;
    if tail != 0 && tail <= ROW_PARITY {
        return Err(RowError::Shape {
            characters: symbols.len(),
        });
    }

    let mut data = Zeroizing::new(Vec::with_capacity(symbols.len()));
    let mut repaired = Vec::new();
    for (index, row) in symbols.chunks(ROW_LEN).enumerate() {
        let row_number = index.saturating_add(1);
        let (fixed, repair) = repair_row(row).ok_or(RowError::Row {
            row: row_number,
            unreadable: row.iter().filter(|s| s.is_none()).count(),
        })?;
        if let Some(repair) = repair {
            repaired.push(Repair {
                row: row_number,
                kind: repair,
            });
        }
        data.extend_from_slice(
            fixed
                .get(..row.len().saturating_sub(ROW_PARITY))
                .unwrap_or(&[]),
        );
    }
    let bytes = from_symbols(&data).ok_or(RowError::Padding)?;
    Ok(Decoded {
        bytes: Zeroizing::new(bytes),
        repaired,
    })
}

/// One row as typed, read on its own, for a frontend that takes a value a
/// row at a time and says at once which row needs another look. [`decode`]
/// reads the whole value; this checks a row the same way. `row` is the
/// row's number from 1, for the repair and the error to name.
///
/// # Errors
///
/// A character outside the alphabet, a row too short or too long to be
/// one, or a row that cannot be repaired.
///
/// Two characters the person could not read, typed as `?` or `U`, are
/// recovered:
///
/// ```
/// use rite_model::paper32;
///
/// let row = paper32::read_row("E9?Q8S8PU8B", 1).unwrap();
/// assert_eq!(row.text.as_str(), "E9MQ8S8PH8B");
/// assert!(row.repair.is_some());
/// ```
pub fn read_row(text: &str, row: usize) -> Result<RowRead, RowError> {
    let mut symbols: Vec<Option<u8>> = Vec::with_capacity(ROW_LEN);
    for (position, c) in text.chars().enumerate() {
        match read(c) {
            Read::Separator => {}
            Read::Erasure => symbols.push(None),
            Read::Value(v) => symbols.push(Some(v)),
            Read::Unknown => return Err(RowError::Character { position }),
        }
    }
    if symbols.is_empty() {
        return Err(RowError::Empty);
    }
    if symbols.len() <= ROW_PARITY || symbols.len() > ROW_LEN {
        return Err(RowError::Shape {
            characters: symbols.len(),
        });
    }
    let (fixed, repair) = repair_row(&symbols).ok_or(RowError::Row {
        row,
        unreadable: symbols.iter().filter(|s| s.is_none()).count(),
    })?;
    Ok(RowRead {
        text: Zeroizing::new(fixed.iter().map(|&s| letter(s)).collect()),
        repair: repair.map(|kind| Repair { row, kind }),
    })
}

/// What [`read_row`] read.
#[derive(Debug)]
pub struct RowRead {
    /// The row as it should read, in the alphabet's own characters.
    pub text: Zeroizing<String>,
    /// The repair it took, if any.
    pub repair: Option<Repair>,
}

/// The row as it should read, and what it took: nothing, or one repair.
/// `None` when no single repair makes it check.
fn repair_row(row: &[Option<u8>]) -> Option<(Vec<u8>, Option<RepairKind>)> {
    let erased: Vec<usize> = row
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.is_none().then_some(i))
        .collect();
    if erased.len() > MAX_ERASURES {
        return None;
    }
    let data_len = row.len().saturating_sub(ROW_PARITY);

    // Fill the erasures from the readable characters, then check.
    let filled = fill(row, &erased, data_len)?;
    if checks(&filled, data_len) {
        let repair = (!erased.is_empty()).then_some(RepairKind::Unreadable {
            count: erased.len(),
        });
        return Some((filled, repair));
    }
    if !erased.is_empty() {
        // An unreadable character and a wrong one are more than the row
        // can vouch for.
        return None;
    }

    // One wrong character: the one position that, treated as unreadable,
    // gives a row that checks. Two positions would mean the row is
    // ambiguous, which a single wrong character never is.
    let mut found: Option<(usize, Vec<u8>)> = None;
    for position in 0..row.len() {
        let candidate = fill(row, &[position], data_len)?;
        if checks(&candidate, data_len) && candidate.get(position) != row.get(position)?.as_ref() {
            if found.is_some() {
                return None;
            }
            found = Some((position, candidate));
        }
    }
    let (position, fixed) = found?;
    Some((fixed, Some(RepairKind::Wrong { position })))
}

/// The row with the given positions recomputed from the others: every
/// readable character is a point of the row's polynomial, and any
/// `data_len` of them determine it.
fn fill(row: &[Option<u8>], holes: &[usize], data_len: usize) -> Option<Vec<u8>> {
    let known: Vec<(u8, u8)> = row
        .iter()
        .enumerate()
        .filter(|(i, s)| s.is_some() && !holes.contains(i))
        .filter_map(|(i, s)| s.map(|v| (row_point(i, row.len()), v)))
        .take(data_len)
        .collect();
    if known.len() < data_len {
        return None;
    }
    let mut out = Vec::with_capacity(row.len());
    for (i, s) in row.iter().enumerate() {
        match s {
            Some(v) if !holes.contains(&i) => out.push(*v),
            _ => out.push(interpolate(&known, row_point(i, row.len()))),
        }
    }
    Some(out)
}

/// The evaluation point of position `i` in a row of `len` characters: the
/// data points from 0, the parity points from 28, whatever the row's
/// length.
fn row_point(i: usize, len: usize) -> u8 {
    let data_len = len.saturating_sub(ROW_PARITY);
    if i < data_len {
        point(i)
    } else {
        point(ROW_DATA.saturating_add(i.saturating_sub(data_len)))
    }
}

/// Whether the row's parity is the parity of its data.
fn checks(row: &[u8], data_len: usize) -> bool {
    let (data, given) = row.split_at(data_len.min(row.len()));
    parity(data) == given
}

/// What [`decode`] read.
#[derive(Debug)]
pub struct Decoded {
    /// The bytes, wiped when dropped.
    pub bytes: Zeroizing<Vec<u8>>,
    /// The rows that needed repair, in order.
    pub repaired: Vec<Repair>,
}

/// A repair made to one row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair {
    /// The row, from 1.
    pub row: usize,
    /// What was repaired.
    pub kind: RepairKind,
}

/// What a row needed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepairKind {
    /// One character was wrong, at this position in the row, from 0.
    Wrong {
        /// Position in the row.
        position: usize,
    },
    /// This many characters were unreadable and recovered.
    Unreadable {
        /// How many.
        count: usize,
    },
}

impl fmt::Display for Repair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RepairKind::Wrong { position } => write!(
                f,
                "row {}: character {} was wrong and has been corrected; check it against the sheet",
                self.row,
                position.saturating_add(1)
            ),
            RepairKind::Unreadable { count } => write!(
                f,
                "row {}: {count} unreadable character{} recovered",
                self.row,
                if count == 1 { "" } else { "s" }
            ),
        }
    }
}

/// Why rows did not read back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowError {
    /// Nothing but separators.
    Empty,
    /// Not a digit, a letter, a `?` or a separator, at this position in the
    /// text.
    Character {
        /// Zero-based position in the text as given.
        position: usize,
    },
    /// The character count is not rows: a last row must hold at least one
    /// data character before its four of parity.
    Shape {
        /// Characters read.
        characters: usize,
    },
    /// A row with more wrong or unreadable characters than it can repair.
    Row {
        /// The row, from 1.
        row: usize,
        /// Characters in it marked unreadable.
        unreadable: usize,
    },
    /// The data does not end on a whole byte.
    Padding,
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "nothing to read"),
            Self::Character { position } => write!(
                f,
                "character {} is not a digit or a letter; write ? for one that cannot be read",
                position.saturating_add(1)
            ),
            Self::Shape { characters } => write!(
                f,
                "{characters} characters do not make rows of 32; a last row has at least 5"
            ),
            Self::Row { row, unreadable } => match unreadable {
                0 => write!(
                    f,
                    "row {row} does not check and has more than one wrong character; read it \
                     again from the sheet"
                ),
                1 | 2 => write!(
                    f,
                    "row {row} has {unreadable} unreadable and still does not check, so another \
                     character is wrong; a row recovers two unreadable or one wrong, not both; \
                     read it again from the sheet"
                ),
                _ => write!(
                    f,
                    "row {row} has {unreadable} unreadable characters and recovers at most two; \
                     read it again from the sheet"
                ),
            },
            Self::Padding => write!(f, "the characters do not end on a whole byte"),
        }
    }
}

impl std::error::Error for RowError {}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn the_field_has_inverses_and_the_polynomial_is_primitive() {
        for a in 1..32u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "{a}");
        }
        // 2 generates the multiplicative group: 31 distinct powers.
        let mut seen = std::collections::BTreeSet::new();
        let mut x = 1u8;
        for _ in 0..31 {
            seen.insert(x);
            x = gf_mul(x, 2);
        }
        assert_eq!(seen.len(), 31);
        assert_eq!(x, 1);
    }

    #[test]
    fn a_row_is_its_data_and_four_parity_characters() {
        let text = encode(&[0u8; 35]);
        assert_eq!(text.len(), 64);
        assert_eq!(&text[..28], "0".repeat(28));
        assert_eq!(&text[28..32], "0000");
        let text = encode(&[0xFF; 35]);
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn bytes_round_trip_at_every_length() {
        for len in 0..=100usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i.wrapping_mul(53).wrapping_add(7) & 0xff).unwrap())
                .collect();
            let text = encode(&bytes);
            let rows = len.saturating_mul(8).div_ceil(5).div_ceil(ROW_DATA);
            assert_eq!(
                text.len(),
                len.saturating_mul(8).div_ceil(5) + rows * ROW_PARITY,
                "{len}"
            );
            if len == 0 {
                assert_eq!(decode(&text).unwrap_err(), RowError::Empty);
                continue;
            }
            let decoded = decode(&text).unwrap_or_else(|e| panic!("{len}: {e}"));
            assert_eq!(*decoded.bytes, bytes, "{len}");
            assert!(decoded.repaired.is_empty());
        }
    }

    #[test]
    fn case_confusions_and_separators_are_read_through() {
        let bytes = b"a value to write";
        let text = encode(bytes);
        let grouped: String = text
            .to_ascii_lowercase()
            .as_bytes()
            .chunks(4)
            .map(|g| std::str::from_utf8(g).unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(*decode(&grouped).unwrap().bytes, bytes);
        // O for 0, I and L for 1.
        let confused = text.replace('0', "O").replace('1', "l");
        assert_eq!(*decode(&confused).unwrap().bytes, bytes);
        // U is read as unreadable and recovered.
        let mut chars: Vec<char> = text.chars().collect();
        chars[0] = 'u';
        let with_u: String = chars.iter().collect();
        let decoded = decode(&with_u).unwrap();
        assert_eq!(*decoded.bytes, bytes);
        assert_eq!(
            decoded.repaired,
            vec![Repair {
                row: 1,
                kind: RepairKind::Unreadable { count: 1 }
            }]
        );
        // Any other character is refused where it stands.
        chars[0] = '#';
        let outside: String = chars.iter().collect();
        assert_eq!(
            decode(&outside).unwrap_err(),
            RowError::Character { position: 0 }
        );
    }

    #[test]
    fn one_wrong_character_anywhere_in_a_row_is_corrected_and_named() {
        let bytes = [0x5A; 35];
        let text = encode(&bytes);
        let chars: Vec<char> = text.chars().collect();
        for position in 0..chars.len() {
            let mut wrong = chars.clone();
            wrong[position] = if wrong[position] == 'Q' { 'R' } else { 'Q' };
            let wrong: String = wrong.into_iter().collect();
            let decoded = decode(&wrong).unwrap_or_else(|e| panic!("position {position}: {e}"));
            assert_eq!(*decoded.bytes, bytes, "position {position}");
            assert_eq!(
                decoded.repaired,
                [Repair {
                    row: position / ROW_LEN + 1,
                    kind: RepairKind::Wrong {
                        position: position % ROW_LEN
                    }
                }],
                "position {position}"
            );
        }
    }

    #[test]
    fn two_unreadable_characters_in_a_row_are_recovered() {
        let bytes = b"thirty-two bytes of some secret!";
        let text = encode(bytes);
        let mut chars: Vec<char> = text.chars().collect();
        chars[3] = '?';
        chars[30] = '?';
        chars[40] = '?';
        let smudged: String = chars.iter().collect();
        let decoded = decode(&smudged).unwrap();
        assert_eq!(*decoded.bytes, bytes);
        assert_eq!(decoded.repaired.len(), 2);
        assert_eq!(
            decoded.repaired[0].to_string(),
            "row 1: 2 unreadable characters recovered"
        );
        assert_eq!(
            decoded.repaired[1],
            Repair {
                row: 2,
                kind: RepairKind::Unreadable { count: 1 }
            }
        );
    }

    #[test]
    fn a_row_beyond_repair_is_refused_by_name() {
        let text = encode(&[0x33; 35]);
        let mut chars: Vec<char> = text.chars().collect();
        // Two wrong characters in row 2.
        chars[35] = if chars[35] == 'A' { 'B' } else { 'A' };
        chars[50] = if chars[50] == 'A' { 'B' } else { 'A' };
        let wrong: String = chars.iter().collect();
        assert_eq!(
            decode(&wrong).unwrap_err(),
            RowError::Row {
                row: 2,
                unreadable: 0
            }
        );
        // Three unreadable in row 1.
        let mut chars: Vec<char> = text.chars().collect();
        chars[0] = '?';
        chars[1] = '?';
        chars[2] = '?';
        let smudged: String = chars.iter().collect();
        assert_eq!(
            decode(&smudged).unwrap_err(),
            RowError::Row {
                row: 1,
                unreadable: 3
            }
        );
        // One wrong and one unreadable in a row.
        let mut chars: Vec<char> = text.chars().collect();
        chars[5] = '?';
        chars[9] = if chars[9] == 'A' { 'B' } else { 'A' };
        let mixed: String = chars.iter().collect();
        let err = decode(&mixed).unwrap_err();
        assert_eq!(
            err,
            RowError::Row {
                row: 1,
                unreadable: 1
            }
        );
        assert!(err.to_string().contains("not both"));
    }

    #[test]
    fn a_shape_that_is_not_rows_is_refused() {
        assert_eq!(
            decode("ABCD").unwrap_err(),
            RowError::Shape { characters: 4 }
        );
        assert_eq!(
            decode(&"A".repeat(34)).unwrap_err(),
            RowError::Shape { characters: 34 }
        );
        assert_eq!(decode(" - ").unwrap_err(), RowError::Empty);
    }
}
