//! Shamir secret sharing over GF(2^8), the `rite-sss/v1` format.
//!
//! One polynomial per byte of the secret, over the field AES uses (Rijndael
//! polynomial `0x11b`). A share is the threshold `k`, the `x` the polynomial
//! was evaluated at (from 1) and one `y` byte per byte of the secret. That
//! is the whole specification, and it is written into a ceremony's
//! transcript so that any GF(256) library reconstructs the secret without
//! this code. How a share is laid out in bytes, or on paper, is a container's
//! business and not this module's: see [`super::wire`].
//!
//! The `y` bytes are what draft-mcgrew-tss-03 section 3 and SLIP-0039 produce
//! for the same `x` and coefficients; both share each byte over this field.
//!
//! This module performs no I/O and draws no randomness. [`split`] takes the
//! coefficient bytes it needs from the caller, who gets them from a backend
//! that answers for their quality. Constant time is not a goal: a ceremony
//! splits one secret, once, on a machine nobody else is running code on.
//! Readability is, so the arithmetic is the textbook shift-and-add and the
//! file can be read in full. It is the one cryptographic primitive written in
//! this workspace rather than taken from a provider, because no provider
//! offers it; `docs/development/cryptographic-dependencies.md` says so.
//!
//! Every buffer that holds a secret or a share is wiped when dropped.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

/// The format name, as the transcript and the bag sheet record it.
pub const FORMAT: &str = "rite-sss/v1";

// ── GF(2^8) ─────────────────────────────────────────────────────────────────

/// Multiply in GF(2^8) modulo the Rijndael polynomial.
///
/// Shift-and-add: walk the bits of `b`, accumulating `a` shifted left by each
/// set bit's position and reducing whenever the shift carries past bit 7.
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut product = 0u8;
    let mut shifted = a;
    let mut rest = b;
    while rest != 0 {
        if rest & 1 != 0 {
            product ^= shifted;
        }
        let carry = shifted & 0x80 != 0;
        shifted = shifted.wrapping_shl(1);
        if carry {
            // x^8 = x^4 + x^3 + x + 1, the low byte of 0x11b.
            shifted ^= 0x1b;
        }
        rest >>= 1;
    }
    product
}

/// Multiplicative inverse in GF(2^8), as `a^254`, since `a^255 = 1` for every
/// non-zero `a`.
///
/// Zero has no inverse; the callers never ask for one because share indexes
/// start at 1 and are distinct.
fn gf_inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exponent = 254u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

/// Evaluate a polynomial at `x` by Horner's rule. `coefficients` is lowest
/// degree first, so the first element is the constant term.
fn gf_eval(coefficients: &[u8], x: u8) -> u8 {
    coefficients
        .iter()
        .rev()
        .fold(0u8, |acc, &c| gf_mul(acc, x) ^ c)
}

/// Lagrange interpolation at `x = 0` over points `(x_i, y_i)`. The `x` values
/// must be distinct and non-zero.
fn gf_interpolate_at_zero(points: &[(u8, u8)]) -> u8 {
    let mut secret = 0u8;
    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = gf_mul(numerator, x_j);
            denominator = gf_mul(denominator, x_j ^ x_i);
        }
        let basis = gf_mul(numerator, gf_inv(denominator));
        secret ^= gf_mul(y_i, basis);
    }
    secret
}

// ── shares ──────────────────────────────────────────────────────────────────

/// One share: which split it belongs to, where it was evaluated, and the
/// `y` value for every byte of the secret. Wiped on drop.
///
/// The threshold is carried so that a set short of it, or mixed from two
/// splits, is refused before anything is interpolated. The arithmetic does
/// not need it.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    threshold: u8,
    index: u8,
    y: Zeroizing<Vec<u8>>,
}

impl Share {
    /// A share from its parts, as a container decodes them.
    pub fn new(threshold: u8, index: u8, y: Vec<u8>) -> Result<Self, ShareError> {
        if threshold < 2 {
            return Err(ShareError::ThresholdBelowTwo(threshold));
        }
        if index == 0 {
            return Err(ShareError::IndexZero);
        }
        if y.is_empty() {
            return Err(ShareError::Empty);
        }
        Ok(Self {
            threshold,
            index,
            y: Zeroizing::new(y),
        })
    }

    /// How many shares reconstruct the secret this one belongs to.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The `x` this share was evaluated at, from 1.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The `y` values, one per byte of the secret.
    pub fn y(&self) -> &[u8] {
        &self.y
    }

    /// Length of the secret this share is a part of.
    pub fn secret_len(&self) -> usize {
        self.y.len()
    }

    /// The parts, moved out. What the wrapper wipes on drop is the empty
    /// vector left in its place.
    pub fn into_parts(mut self) -> (u8, u8, Vec<u8>) {
        (self.threshold, self.index, std::mem::take(&mut *self.y))
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Share(index={}, threshold={}, {} bytes)",
            self.index,
            self.threshold,
            self.y.len()
        )
    }
}

/// Every share of one split, in index order.
#[derive(Clone, PartialEq, Eq)]
pub struct ShareSet {
    threshold: u8,
    shares: Vec<Share>,
}

impl ShareSet {
    /// How many shares reconstruct the secret.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// How many shares were made.
    pub fn count(&self) -> u8 {
        u8::try_from(self.shares.len()).unwrap_or(u8::MAX)
    }

    /// The shares, index 1 first.
    pub fn shares(&self) -> &[Share] {
        &self.shares
    }

    /// The shares, moved out, index 1 first.
    pub fn into_shares(self) -> Vec<Share> {
        self.shares
    }

    /// How many subsets of `threshold` shares the set has, or `None` when
    /// the count does not fit in a `u64`.
    pub fn subset_count(&self) -> Option<u64> {
        subset_count(self.shares.len(), usize::from(self.threshold))
    }

    /// Combine every subset of `threshold` shares and check each one gives
    /// `secret`. Returns how many subsets were checked, or the indexes of
    /// the first subset that does not reconstruct.
    ///
    /// This is what a ceremony runs before any share is sealed: a bag that
    /// leaves the room has been shown to work with every other bag. The
    /// cost is one combine per subset, tens of microseconds each for a
    /// 32-byte secret, so [`MAX_VERIFIED_SUBSETS`] is what keeps a large
    /// split from turning the check into a wait nobody planned for; the
    /// caller enforces it.
    pub fn verify_all_subsets(&self, secret: &[u8]) -> Result<u64, Vec<u8>> {
        let k = usize::from(self.threshold);
        let mut checked = 0u64;
        for subset in Combinations::new(self.shares.len(), k) {
            let chosen: Vec<&Share> = subset.iter().filter_map(|&i| self.shares.get(i)).collect();
            let recovered = combine_refs(&chosen);
            if recovered.as_deref().map(Vec::as_slice) != Ok(secret) {
                return Err(chosen.iter().map(|s| s.index()).collect());
            }
            checked = checked.saturating_add(1);
        }
        Ok(checked)
    }
}

/// The most subsets a split may have and still be checked before sealing.
///
/// About two seconds of arithmetic for a 32-byte secret in a release build,
/// and a bound that admits every split a room of people would run: 2-of-n
/// up to the share limit, 3-of-85, 4-of-40, 5-of-26, 6-of-20, 8-of-16. A
/// larger split is refused before it is made.
pub const MAX_VERIFIED_SUBSETS: u64 = 100_000;

/// `n` choose `k`, or `None` past `u64`.
pub fn subset_count(n: usize, k: usize) -> Option<u64> {
    if k > n {
        return Some(0);
    }
    let k = k.min(n.saturating_sub(k));
    let mut count = 1u64;
    for i in 1..=k {
        // Multiply first and divide after, in that order, so each step is an
        // integer: `count * (n - k + i) / i` is `C(n - k + i, i)`.
        let numerator = u64::try_from(n.saturating_sub(k).saturating_add(i)).ok()?;
        count = count.checked_mul(numerator)?;
        count = count.checked_div(u64::try_from(i).ok()?)?;
    }
    Some(count)
}

impl fmt::Debug for ShareSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ShareSet({}-of-{}, {} bytes each)",
            self.threshold,
            self.shares.len(),
            self.shares.first().map_or(0, Share::secret_len)
        )
    }
}

/// Every `k`-subset of `0..n`, in lexicographic order, one at a time.
///
/// Holds one subset and advances it in place: find the rightmost position
/// that can still move right, move it, and reset everything after it to
/// follow. Nothing is materialised beyond the current subset.
struct Combinations {
    n: usize,
    k: usize,
    current: Vec<usize>,
    started: bool,
    done: bool,
}

impl Combinations {
    fn new(n: usize, k: usize) -> Self {
        Self {
            n,
            k,
            current: (0..k).collect(),
            started: false,
            done: k > n,
        }
    }
}

impl Iterator for Combinations {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if !self.started {
            self.started = true;
            return Some(self.current.clone());
        }
        // The rightmost position `i` whose value can grow: its ceiling is
        // `n - k + i`, so the positions after it still fit.
        let movable = (0..self.k).rev().find(|&i| {
            self.current
                .get(i)
                .is_some_and(|&v| v < self.n.saturating_sub(self.k).saturating_add(i))
        });
        let Some(i) = movable else {
            self.done = true;
            return None;
        };
        let base = self
            .current
            .get(i)
            .copied()
            .unwrap_or_default()
            .saturating_add(1);
        for (offset, slot) in self.current.iter_mut().skip(i).enumerate() {
            *slot = base.saturating_add(offset);
        }
        Some(self.current.clone())
    }
}

// ── split ───────────────────────────────────────────────────────────────────

/// How many random bytes [`split`] needs: one coefficient byte per byte of
/// the secret for each of the `threshold - 1` non-constant terms.
pub fn random_len(secret_len: usize, threshold: u8) -> usize {
    secret_len.saturating_mul(usize::from(threshold.saturating_sub(1)))
}

/// Split `secret` into `count` shares of which any `threshold` reconstruct it.
///
/// `random` supplies the polynomial coefficients and must be exactly
/// [`random_len`] bytes from a source the caller answers for. A biased
/// coefficient leaks the secret, so this is not a place for a seeded
/// generator outside a test.
pub fn split(
    secret: &[u8],
    threshold: u8,
    count: u8,
    random: &[u8],
) -> Result<ShareSet, SplitError> {
    if secret.is_empty() {
        return Err(SplitError::EmptySecret);
    }
    if threshold < 2 {
        return Err(SplitError::ThresholdBelowTwo(threshold));
    }
    if count < threshold {
        return Err(SplitError::CountBelowThreshold { threshold, count });
    }
    let needed = random_len(secret.len(), threshold);
    if random.len() != needed {
        return Err(SplitError::RandomLength {
            needed,
            given: random.len(),
        });
    }

    let degree = usize::from(threshold).saturating_sub(1);
    let mut shares: Vec<Share> = (1..=count)
        .map(|index| Share {
            threshold,
            index,
            y: Zeroizing::new(Vec::with_capacity(secret.len())),
        })
        .collect();

    // One polynomial per secret byte. The constant term is the byte itself;
    // coefficient `t` of byte `p` is the random byte at `(t - 1) * len + p`,
    // so the random input is consumed once, in order, with nothing left over.
    let mut coefficients = Zeroizing::new(vec![0u8; usize::from(threshold)]);
    for (position, &byte) in secret.iter().enumerate() {
        if let Some(constant) = coefficients.first_mut() {
            *constant = byte;
        }
        for t in 1..=degree {
            let at = t
                .saturating_sub(1)
                .saturating_mul(secret.len())
                .saturating_add(position);
            if let (Some(slot), Some(&r)) = (coefficients.get_mut(t), random.get(at)) {
                *slot = r;
            }
        }
        for share in &mut shares {
            let x = share.index;
            share.y.push(gf_eval(&coefficients, x));
        }
    }
    coefficients.zeroize();

    Ok(ShareSet { threshold, shares })
}

// ── combine ─────────────────────────────────────────────────────────────────

/// Reconstruct the secret from at least `threshold` shares of one split.
///
/// The shares must agree on threshold and length and carry distinct indexes;
/// a set that does not is rejected with the disagreement spelled out. That
/// is the whole of what can be checked. Nothing here can tell a wrong share
/// from a right one, or a share of another split of the same shape from one
/// of this split: the arithmetic succeeds and the result is a different
/// secret. That is why a ceremony checks every subset before sealing, and
/// checks the recovered secret against something it can observe at the
/// drill. The result is erased from memory when dropped.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>, CombineError> {
    let refs: Vec<&Share> = shares.iter().collect();
    combine_refs(&refs)
}

fn combine_refs(shares: &[&Share]) -> Result<Zeroizing<Vec<u8>>, CombineError> {
    let (&first, rest) = shares.split_first().ok_or(CombineError::NoShares)?;
    let threshold = first.threshold();
    let len = first.secret_len();

    for share in rest {
        if share.threshold() != threshold {
            return Err(CombineError::MixedThreshold {
                first: threshold,
                other: share.threshold(),
            });
        }
        if share.secret_len() != len {
            return Err(CombineError::MixedLength {
                first: len,
                other: share.secret_len(),
            });
        }
    }
    let mut seen = [false; 256];
    for share in shares {
        let slot = seen
            .get_mut(usize::from(share.index()))
            .ok_or(CombineError::NoShares)?;
        if *slot {
            return Err(CombineError::DuplicateIndex(share.index()));
        }
        *slot = true;
    }
    if shares.len() < usize::from(threshold) {
        return Err(CombineError::NotEnough {
            threshold,
            given: shares.len(),
        });
    }

    let mut secret = Zeroizing::new(Vec::with_capacity(len));
    let mut points = Zeroizing::new(Vec::with_capacity(shares.len()));
    for position in 0..len {
        points.clear();
        for share in shares {
            if let Some(&y) = share.y().get(position) {
                points.push((share.index(), y));
            }
        }
        secret.push(gf_interpolate_at_zero(&points));
    }
    Ok(secret)
}

// ── errors ──────────────────────────────────────────────────────────────────

/// What is wrong with the parts offered as a share.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShareError {
    /// No `y` bytes: a share of nothing.
    #[error("a share carries at least one byte of secret")]
    Empty,
    /// A threshold of 0 or 1 is not a split.
    #[error("share threshold {0} is below 2")]
    ThresholdBelowTwo(u8),
    /// Index 0 would evaluate the polynomial at the secret itself.
    #[error("share index 0 is reserved; indexes start at 1")]
    IndexZero,
}

/// Why a split was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SplitError {
    /// Nothing to split.
    #[error("the secret is empty")]
    EmptySecret,
    /// A threshold of 0 or 1 is not a split.
    #[error("threshold {0} is below 2")]
    ThresholdBelowTwo(u8),
    /// Fewer shares than the threshold could never reconstruct.
    #[error("{count} shares cannot meet a threshold of {threshold}")]
    CountBelowThreshold {
        /// Shares needed to reconstruct.
        threshold: u8,
        /// Shares asked for.
        count: u8,
    },
    /// The caller supplied the wrong amount of randomness.
    #[error("{needed} random bytes are needed for this split, {given} were given")]
    RandomLength {
        /// Bytes [`random_len`] asks for.
        needed: usize,
        /// Bytes supplied.
        given: usize,
    },
}

/// Why a set of shares did not combine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CombineError {
    /// No shares at all.
    #[error("no shares to combine")]
    NoShares,
    /// Two shares name different thresholds, so they are from different splits.
    #[error("shares disagree on the threshold ({first} and {other}); they are not from one split")]
    MixedThreshold {
        /// Threshold of the first share.
        first: u8,
        /// Threshold of the share that disagrees.
        other: u8,
    },
    /// Two shares are of different lengths, so they are from different splits.
    #[error(
        "shares disagree on the secret length ({first} and {other} bytes); they are not from one split"
    )]
    MixedLength {
        /// Secret length of the first share.
        first: usize,
        /// Secret length of the share that disagrees.
        other: usize,
    },
    /// One index appears twice: the same share was offered twice.
    #[error("share {0} was given twice")]
    DuplicateIndex(u8),
    /// Not enough shares to meet the threshold they name.
    #[error("{given} shares given, {threshold} needed")]
    NotEnough {
        /// Shares needed to reconstruct.
        threshold: u8,
        /// Shares given.
        given: usize,
    },
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Deterministic coefficients for tests only.
    fn fake_random(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| u8::try_from(i.wrapping_mul(97).wrapping_add(13) & 0xff).unwrap())
            .collect()
    }

    #[test]
    fn field_multiplication_matches_the_aes_test_vector() {
        // FIPS 197, section 4.2: {57} • {83} = {c1}.
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn every_non_zero_element_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse of {a:#x}");
        }
    }

    #[test]
    fn any_threshold_of_shares_recovers_the_secret() {
        let secret = b"a thirty-two byte wallet seed!!!";
        let set = split(secret, 3, 5, &fake_random(random_len(secret.len(), 3))).unwrap();
        assert_eq!(set.count(), 5);
        assert_eq!(set.shares()[0].secret_len(), secret.len());

        for subset in Combinations::new(5, 3) {
            let chosen: Vec<Share> = subset.iter().map(|&i| set.shares()[i].clone()).collect();
            assert_eq!(combine(&chosen).unwrap().as_slice(), secret);
        }
        assert_eq!(set.verify_all_subsets(secret), Ok(10));
    }

    #[test]
    fn combinations_walk_every_subset_once_in_order() {
        let all: Vec<Vec<usize>> = Combinations::new(4, 2).collect();
        assert_eq!(all, [[0, 1], [0, 2], [0, 3], [1, 2], [1, 3], [2, 3]]);
        assert_eq!(Combinations::new(3, 3).count(), 1);
        assert_eq!(Combinations::new(2, 3).count(), 0);
        assert_eq!(Combinations::new(5, 0).count(), 1);
        assert_eq!(Combinations::new(20, 5).count(), 15504);
    }

    #[test]
    fn subset_counts_match_the_closed_form() {
        assert_eq!(subset_count(3, 2), Some(3));
        assert_eq!(subset_count(5, 3), Some(10));
        assert_eq!(subset_count(20, 5), Some(15504));
        assert_eq!(subset_count(2, 3), Some(0));
        assert_eq!(subset_count(253, 2), Some(31878));
        assert_eq!(subset_count(16, 8), Some(12870));
        assert_eq!(subset_count(255, 128), None);
    }

    #[test]
    fn fewer_than_threshold_shares_are_refused() {
        let secret = [0x42u8; 16];
        let set = split(&secret, 2, 3, &fake_random(16)).unwrap();
        let one = [set.shares()[0].clone()];
        assert_eq!(
            combine(&one),
            Err(CombineError::NotEnough {
                threshold: 2,
                given: 1
            })
        );
    }

    #[test]
    fn shares_that_disagree_on_threshold_or_length_are_rejected() {
        let a = split(&[1u8; 8], 2, 2, &fake_random(8)).unwrap();
        let b = split(&[2u8; 8], 3, 3, &fake_random(16)).unwrap();
        let mixed = [a.shares()[0].clone(), b.shares()[1].clone()];
        assert_eq!(
            combine(&mixed),
            Err(CombineError::MixedThreshold { first: 2, other: 3 })
        );

        let c = split(&[3u8; 4], 2, 2, &fake_random(4)).unwrap();
        let mixed = [a.shares()[0].clone(), c.shares()[1].clone()];
        assert_eq!(
            combine(&mixed),
            Err(CombineError::MixedLength { first: 8, other: 4 })
        );

        let twice = [a.shares()[0].clone(), a.shares()[0].clone()];
        assert_eq!(combine(&twice), Err(CombineError::DuplicateIndex(1)));
    }

    #[test]
    fn a_corrupted_share_gives_a_different_secret_and_the_subset_check_says_which() {
        let secret = [7u8; 8];
        let mut set = split(&secret, 2, 3, &fake_random(8)).unwrap();
        let mut y = set.shares()[1].y().to_vec();
        y[5] ^= 0x01;
        set.shares[1] = Share::new(2, 2, y).unwrap();
        assert_eq!(set.verify_all_subsets(&secret), Err(vec![1, 2]));
    }

    #[test]
    fn a_share_checks_its_parts() {
        assert_eq!(Share::new(2, 1, vec![]), Err(ShareError::Empty));
        assert_eq!(
            Share::new(1, 1, vec![0]),
            Err(ShareError::ThresholdBelowTwo(1))
        );
        assert_eq!(Share::new(2, 0, vec![0]), Err(ShareError::IndexZero));
        let share = Share::new(3, 7, vec![1, 2]).unwrap();
        assert_eq!(
            (share.threshold(), share.index(), share.secret_len()),
            (3, 7, 2)
        );
        assert_eq!(share.into_parts(), (3, 7, vec![1, 2]));
    }

    #[test]
    fn split_checks_its_arguments() {
        assert_eq!(split(&[], 2, 3, &[]), Err(SplitError::EmptySecret));
        assert_eq!(
            split(&[1], 1, 3, &[]),
            Err(SplitError::ThresholdBelowTwo(1))
        );
        assert_eq!(
            split(&[1], 3, 2, &[0, 0]),
            Err(SplitError::CountBelowThreshold {
                threshold: 3,
                count: 2
            })
        );
        assert_eq!(
            split(&[1, 2], 3, 3, &[0]),
            Err(SplitError::RandomLength {
                needed: 4,
                given: 1
            })
        );
    }

    /// draft-mcgrew-tss-03, section 9. The draft shares each octet over the
    /// same field with the same index convention, so its shares combine here
    /// as they are. This is the one answer this module did not compute
    /// itself.
    #[test]
    fn combines_the_ietf_tss_draft_test_vector() {
        let secret = [0x74, 0x65, 0x73, 0x74, 0x00];
        let share_1 = Share::new(2, 1, vec![0xB9, 0xFA, 0x07, 0xE1, 0x85]).unwrap();
        let share_2 = Share::new(2, 2, vec![0xF5, 0x40, 0x9B, 0x45, 0x11]).unwrap();
        assert_eq!(combine(&[share_1, share_2]).unwrap().as_slice(), &secret);
    }

    /// A 3-of-5 split computed outside this module: the polynomials
    /// evaluated with the log and exp tables of python-shamir-mnemonic, the
    /// SLIP-0039 reference implementation, over the same field and the
    /// same coefficients `fake_random` yields, and every subset recombined
    /// by its `_interpolate` at `x = 0`. Pins `split` byte for byte, not
    /// only the round trip.
    #[test]
    fn splits_as_the_slip39_reference_arithmetic_does() {
        let secret = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, 0x53, 0xCA];
        let expected: [[u8; 8]; 5] = [
            [0x18, 0x19, 0x67, 0x88, 0xF6, 0xF7, 0x5B, 0xC2],
            [0x4E, 0x1E, 0x8B, 0x00, 0x95, 0xC5, 0x82, 0x7F],
            [0x56, 0x06, 0x93, 0x08, 0x9D, 0xCD, 0x8A, 0x77],
            [0x7F, 0x83, 0xB1, 0xED, 0xDF, 0x23, 0xC3, 0x19],
            [0x67, 0x9B, 0xA9, 0xE5, 0xD7, 0x2B, 0xCB, 0x11],
        ];
        let set = split(&secret, 3, 5, &fake_random(random_len(8, 3))).unwrap();
        for (share, y) in set.shares().iter().zip(expected) {
            assert_eq!(share.y(), y, "share {}", share.index());
        }
        assert_eq!(set.verify_all_subsets(&secret), Ok(10));
    }

    /// Every length a seed or a key comes in, every threshold a room would
    /// name, with coefficients from a small generator seeded per case so a
    /// failure names the case. Catches an indexing slip in the coefficient
    /// layout that one fixed shape would not.
    #[test]
    fn round_trips_every_length_and_threshold() {
        for len in 1..=64usize {
            for threshold in 2..=5u8 {
                let count = threshold.saturating_add(2);
                let mut state = u32::try_from(len).unwrap() * 131 + u32::from(threshold);
                let mut next = || {
                    // xorshift32
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    u8::try_from(state & 0xff).unwrap()
                };
                let secret: Vec<u8> = (0..len).map(|_| next()).collect();
                let random: Vec<u8> = (0..random_len(len, threshold)).map(|_| next()).collect();
                let set = split(&secret, threshold, count, &random).unwrap();
                assert_eq!(
                    set.verify_all_subsets(&secret),
                    Ok(subset_count(usize::from(count), usize::from(threshold)).unwrap()),
                    "{threshold}-of-{count} over {len} bytes"
                );
            }
        }
    }

    #[test]
    fn into_parts_hands_the_bytes_over_intact() {
        let share = Share::new(3, 7, vec![0xDE, 0xAD]).unwrap();
        assert_eq!(share.into_parts(), (3, 7, vec![0xDE, 0xAD]));
    }

    #[test]
    fn more_shares_than_the_threshold_still_agree() {
        let secret = [0x5A; 12];
        let set = split(&secret, 3, 6, &fake_random(random_len(12, 3))).unwrap();
        assert_eq!(combine(&set.shares()[..4]).unwrap().as_slice(), &secret);
        assert_eq!(combine(set.shares()).unwrap().as_slice(), &secret);
    }

    #[test]
    fn the_edges_of_the_index_space_work() {
        // n-of-n, one byte, and the largest count a share index allows.
        let set = split(&[0x01], 2, 2, &fake_random(1)).unwrap();
        assert_eq!(combine(set.shares()).unwrap().as_slice(), &[0x01]);

        let secret = [0xC3; 4];
        let set = split(&secret, 2, 255, &fake_random(4)).unwrap();
        assert_eq!(set.count(), 255);
        assert_eq!(set.shares()[254].index(), 255);
        let last_two = [set.shares()[253].clone(), set.shares()[254].clone()];
        assert_eq!(combine(&last_two).unwrap().as_slice(), &secret);
    }

    #[test]
    fn debug_output_names_no_bytes() {
        let set = split(&[0xAA; 4], 2, 2, &fake_random(4)).unwrap();
        let text = format!("{:?} {:?}", set, set.shares()[0]);
        assert!(!text.contains("aa"), "{text}");
        assert!(!text.contains("170"), "{text}");
    }
}
