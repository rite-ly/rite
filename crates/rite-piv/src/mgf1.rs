//! MGF1 with SHA-256 (RFC 8017, §B.2.1), the mask both host-side RSA
//! encodings use: OAEP decoding after the card decrypts ([`crate::oaep`]) and
//! PSS encoding before it signs ([`crate::pss`]).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// SHA-256 output length, `hLen` in RFC 8017.
pub(crate) const H_LEN: usize = 32;

/// XORs the MGF1 mask of `seed` into `out`, as long as `out`.
///
/// The mask is its own inverse: applying it twice restores `out`.
pub(crate) fn xor(seed: &[u8], out: &mut [u8]) {
    for (counter, chunk) in (0u32..).zip(out.chunks_mut(H_LEN)) {
        let mask = Zeroizing::new(
            Sha256::new()
                .chain_update(seed)
                .chain_update(counter.to_be_bytes())
                .finalize(),
        );
        for (byte, m) in chunk.iter_mut().zip(mask.iter()) {
            *byte ^= m;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mask_is_its_own_inverse() {
        let mut block = [0u8; 223];
        let seed = [9u8; H_LEN];
        xor(&seed, &mut block);
        assert_ne!(block, [0u8; 223]);
        xor(&seed, &mut block);
        assert_eq!(block, [0u8; 223]);
    }
}
