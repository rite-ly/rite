//! BIP-39: bytes as words from the English list, as a hardware wallet
//! shows its recovery phrase and takes it back.
//!
//! The bytes are the wallet's entropy, 16 to 32 bytes in steps of 4. The
//! first byte of their SHA-256 digest supplies a checksum of one bit per
//! 32 bits of entropy, appended to them; the result is read eleven bits at
//! a time, most significant first, each an index into the 2048 words of
//! the English list. 32 bytes are 24 words, 16 bytes are 12.
//!
//! The words, not the entropy, are what a wallet derives its keys from,
//! so the same entropy in another language's list is a different wallet.
//! This module knows the English list only, which is the one hardware
//! wallets use.
//!
//! The decoder takes either case and the first four letters of a word,
//! which the list keeps unique and which metal backup plates carry. A word
//! it does not find, a count that is not a phrase and a checksum that does
//! not match are refused, each by the word's position and never by the
//! word, since the words are a secret.

use std::fmt;
use std::sync::LazyLock;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The English list, one word per line, in index order.
const ENGLISH: &str = include_str!("bip39-english.txt");

/// The longest word in the list, in letters.
pub const WORD_MAX: usize = 8;

/// The words of the English list, in index order.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| ENGLISH.lines().collect());

/// Bits each word carries.
const WORD_BITS: usize = 11;

/// Words in a phrase for `bytes` bytes of entropy, rounded up for a length
/// that is not one: three words per four bytes.
pub fn words_for(bytes: usize) -> usize {
    bytes.saturating_mul(3).div_ceil(4)
}

/// Bytes of entropy a phrase of `words` words carries: four per three words.
pub fn bytes_for(words: usize) -> usize {
    words.saturating_mul(4) / 3
}

/// Whether `bytes` bytes of entropy make a phrase: 16 to 32 in steps of 4.
pub fn is_entropy_len(bytes: usize) -> bool {
    (16..=32).contains(&bytes) && bytes.is_multiple_of(4)
}

/// The fewest words a phrase has.
pub const MIN_WORDS: usize = 12;

/// The most words a phrase has.
pub const MAX_WORDS: usize = 24;

/// The word counts a phrase may have, as a person reads them.
pub const PHRASE_LENGTHS: &str = "12, 15, 18, 21 or 24";

/// Whether a phrase may have `words` words: 12 to 24 in steps of 3.
pub fn is_phrase_len(words: usize) -> bool {
    (MIN_WORDS..=MAX_WORDS).contains(&words) && words.is_multiple_of(3)
}

/// The word counts a phrase may have, shortest first.
pub fn phrase_lengths() -> impl Iterator<Item = usize> {
    (MIN_WORDS..=MAX_WORDS).filter(|&n| is_phrase_len(n))
}

/// Write entropy as a phrase, words separated by single spaces.
///
/// ```
/// use rite_model::bip39;
///
/// let phrase = bip39::encode(&[0u8; 16]).unwrap();
/// assert!(phrase.starts_with("abandon abandon"));
/// assert!(phrase.ends_with("about"));
/// ```
///
/// # Errors
///
/// The length, when it is not one BIP-39 has a phrase for.
pub fn encode(bytes: &[u8]) -> Result<Zeroizing<String>, Bip39Error> {
    if !is_entropy_len(bytes.len()) {
        return Err(Bip39Error::Entropy { bytes: bytes.len() });
    }
    // The checksum is the leading bits of the digest's first byte, so the
    // stream is the entropy and that byte, of which the words take only
    // as many bits as the checksum has.
    let mut stream = Zeroizing::new(bytes.to_vec());
    stream.push(checksum(bytes));
    let words = words_for(bytes.len());
    let mut phrase = Zeroizing::new(String::with_capacity(words.saturating_mul(WORD_MAX + 1)));
    for n in 0..words {
        if n > 0 {
            phrase.push(' ');
        }
        let index = (0..WORD_BITS).fold(0, |index, k| {
            (index << 1) | u16::from(bit(&stream, n.saturating_mul(WORD_BITS).saturating_add(k)))
        });
        phrase.push_str(word(index));
    }
    Ok(phrase)
}

/// Bit `n` of `bytes`, most significant first.
fn bit(bytes: &[u8], n: usize) -> bool {
    bytes
        .get(n / 8)
        .is_some_and(|&byte| byte & (0x80 >> (n % 8)) != 0)
}

/// Set bit `n` of `bytes`, most significant first.
fn set_bit(bytes: &mut [u8], n: usize) {
    if let Some(byte) = bytes.get_mut(n / 8) {
        *byte |= 0x80 >> (n % 8);
    }
}

/// The word at `index`, which is below 2048 since it has eleven bits.
fn word(index: u16) -> &'static str {
    WORDS.get(usize::from(index)).copied().unwrap_or_default()
}

/// The first byte of the entropy's SHA-256 digest.
fn checksum(bytes: &[u8]) -> u8 {
    Sha256::digest(bytes).first().copied().unwrap_or_default()
}

/// The index of a typed word: the word itself in either case, or its
/// first four letters or more.
fn index_of(typed: &str) -> Option<u16> {
    let typed = Zeroizing::new(typed.to_ascii_lowercase());
    let found = match WORDS.binary_search(&typed.as_str()) {
        Ok(i) => Some(i),
        Err(i) if typed.len() >= 4 => WORDS
            .get(i)
            .filter(|w| w.starts_with(typed.as_str()))
            .map(|_| i),
        Err(_) => None,
    };
    found.and_then(|i| u16::try_from(i).ok())
}

/// A phrase read back: the entropy, wiped when dropped.
#[derive(Debug)]
pub struct Decoded {
    /// The entropy.
    pub bytes: Zeroizing<Vec<u8>>,
}

/// Read a phrase back into its entropy. Words are separated by whitespace.
///
/// ```
/// use rite_model::bip39;
///
/// let phrase = bip39::encode(&[0x7F; 16]).unwrap();
/// assert_eq!(*bip39::decode(&phrase.to_uppercase()).unwrap().bytes, [0x7F; 16]);
/// // The first four letters of each word are enough.
/// let short: Vec<String> = phrase.split(' ').map(|w| w.chars().take(4).collect()).collect();
/// assert_eq!(*bip39::decode(&short.join(" ")).unwrap().bytes, [0x7F; 16]);
/// ```
///
/// # Errors
///
/// A word not in the list, a count that is not a phrase, or a checksum
/// that does not match, each named by position.
pub fn decode(text: &str) -> Result<Decoded, Bip39Error> {
    let mut indices = Zeroizing::new(Vec::with_capacity(24));
    for (position, typed) in text.split_whitespace().enumerate() {
        let index = index_of(typed).ok_or(Bip39Error::Word {
            word: position.saturating_add(1),
        })?;
        indices.push(index);
    }
    if indices.is_empty() {
        return Err(Bip39Error::Empty);
    }
    if !is_phrase_len(indices.len()) {
        return Err(Bip39Error::Count {
            words: indices.len(),
        });
    }
    // The entropy, then the checksum's bits at the head of one more byte,
    // as `encode` lays them out.
    let length = bytes_for(indices.len());
    let mut stream = Zeroizing::new(vec![0u8; length.saturating_add(1)]);
    for (n, &index) in indices.iter().enumerate() {
        for k in 0..WORD_BITS {
            if index & (0x400 >> k) != 0 {
                set_bit(&mut stream, n.saturating_mul(WORD_BITS).saturating_add(k));
            }
        }
    }
    // The checksum is the leading `length / 4` bits of the byte after the
    // entropy, compared under a mask of those bits.
    // 24 words have 8 bits of checksum, the whole byte, which `>>` on a u8
    // refuses.
    let bits = u32::try_from(length / 4).unwrap_or(u32::MAX);
    let mask = !u8::MAX.checked_shr(bits).unwrap_or(0);
    let expected = checksum(stream.get(..length).unwrap_or(&[])) & mask;
    if stream
        .get(length)
        .is_none_or(|&byte| byte & mask != expected)
    {
        return Err(Bip39Error::Checksum);
    }
    stream.truncate(length);
    Ok(Decoded { bytes: stream })
}

/// One word as typed, for a frontend that takes a phrase a word at a
/// time: the word it is, in full and lower case. `word` is its position
/// from 1, for the error to name.
///
/// ```
/// use rite_model::bip39;
///
/// assert_eq!(bip39::read_word(" ABAN ", 1).unwrap().as_str(), "abandon");
/// assert!(bip39::read_word("abandonx", 1).is_err());
/// assert!(bip39::read_word("abandon ability", 1).is_err());
/// ```
///
/// # Errors
///
/// Nothing typed, more than one word, or a word not in the list.
pub fn read_word(text: &str, word: usize) -> Result<Zeroizing<String>, Bip39Error> {
    let mut words = text.split_whitespace();
    let (Some(typed), None) = (words.next(), words.next()) else {
        return Err(if text.trim().is_empty() {
            Bip39Error::Empty
        } else {
            Bip39Error::OneWord { word }
        });
    };
    let index = index_of(typed).ok_or(Bip39Error::Word { word })?;
    Ok(Zeroizing::new(self::word(index).to_string()))
}

/// Why a phrase or a word does not read. None of these names a word.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip39Error {
    /// Nothing was typed.
    Empty,
    /// The word at this position, from 1, is not in the English list.
    Word {
        /// Its position.
        word: usize,
    },
    /// A row held more than one word.
    OneWord {
        /// The row's position.
        word: usize,
    },
    /// The phrase has a number of words no phrase has.
    Count {
        /// How many there were.
        words: usize,
    },
    /// The words do not end in the checksum of the ones before.
    Checksum,
    /// Entropy of a length BIP-39 has no phrase for.
    Entropy {
        /// Its length.
        bytes: usize,
    },
}

impl fmt::Display for Bip39Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip39Error::Empty => f.write_str("nothing to read"),
            Bip39Error::Word { word } => {
                write!(f, "word {word} is not in the BIP-39 English list")
            }
            Bip39Error::OneWord { word } => {
                write!(f, "one word per row; row {word} has more")
            }
            Bip39Error::Count { words } => {
                write!(f, "{words} words; a BIP-39 phrase has {PHRASE_LENGTHS}")
            }
            Bip39Error::Checksum => f.write_str(
                "the last word is not the checksum of the others: a word is wrong or out of \
                 order",
            ),
            Bip39Error::Entropy { bytes } => write!(
                f,
                "{bytes} bytes; a BIP-39 phrase holds 16 to 32 bytes, in steps of 4"
            ),
        }
    }
}

impl std::error::Error for Bip39Error {}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        base16ct::lower::decode_vec(s).unwrap()
    }

    /// The English vectors from the BIP-39 reference implementation
    /// (trezor/python-mnemonic, `vectors.json`), entropy and phrase.
    const VECTORS: &[(&str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon agent",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave \
             sausage worth useful legal will",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon art",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave \
             sausage worth useful legal winner thank year wave sausage worth title",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
             zoo zoo zoo vote",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay \
             feature office ecology stable narrow fog",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book \
             happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open \
             amazing screen patrol group space point ten exist slush involve unfold",
        ),
    ];

    #[test]
    fn the_reference_vectors_encode_and_decode() {
        for (entropy, phrase) in VECTORS {
            let bytes = hex(entropy);
            assert_eq!(encode(&bytes).unwrap().as_str(), *phrase, "{entropy}");
            assert_eq!(*decode(phrase).unwrap().bytes, bytes, "{entropy}");
        }
    }

    #[test]
    fn the_list_is_the_published_one() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(
            base16ct::lower::encode_string(&Sha256::digest(ENGLISH.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(WORDS.iter().map(|w| w.len()).max(), Some(WORD_MAX));
    }

    #[test]
    fn case_and_four_letters_read_through() {
        let bytes = hex("9e885d952ad362caeb4efe34a8e91bd2");
        let typed = "OZON Drill\ngrab fibe curt\tgrace pudd thank cruise elder eigh picnic";
        assert_eq!(*decode(typed).unwrap().bytes, bytes);
        // Three letters are not enough, even when only one word starts so.
        assert_eq!(read_word("zoo", 1).unwrap().as_str(), "zoo");
        assert_eq!(read_word("ozo", 1), Err(Bip39Error::Word { word: 1 }));
    }

    #[test]
    fn a_wrong_word_count_or_checksum_is_refused_by_position() {
        let phrase = VECTORS[9].1;
        let mut words: Vec<&str> = phrase.split(' ').collect();
        words[4] = "curtains";
        assert_eq!(
            decode(&words.join(" ")).unwrap_err(),
            Bip39Error::Word { word: 5 }
        );
        words[4] = "curtain";
        words.swap(0, 1);
        assert_eq!(decode(&words.join(" ")).unwrap_err(), Bip39Error::Checksum);
        assert_eq!(
            decode(&words[..11].join(" ")).unwrap_err(),
            Bip39Error::Count { words: 11 }
        );
        assert_eq!(decode("  ").unwrap_err(), Bip39Error::Empty);
        let refused = decode("abandonx").unwrap_err().to_string();
        assert!(!refused.contains("abandon"), "{refused}");
    }

    #[test]
    fn only_phrase_lengths_encode() {
        assert_eq!(
            encode(&[0; 15]).unwrap_err(),
            Bip39Error::Entropy { bytes: 15 }
        );
        assert_eq!(
            encode(&[0; 36]).unwrap_err(),
            Bip39Error::Entropy { bytes: 36 }
        );
        assert_eq!(words_for(32), 24);
        assert_eq!(bytes_for(24), 32);
        assert_eq!(words_for(20), 15);
        assert!(is_phrase_len(18) && !is_phrase_len(13));
    }
}
