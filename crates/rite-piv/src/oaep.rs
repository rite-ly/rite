//! EME-OAEP decoding (RFC 8017, §7.1.2) with SHA-256 for the label hash and
//! for MGF1, and the empty label.
//!
//! A PIV card runs the raw RSA private-key operation and returns the encoded
//! block, so the host removes the encoding. This is the decryption counterpart
//! of the EMSA-PKCS1-v1_5 encoding [`crate::ops::sign`] applies before the
//! card signs.
//!
//! The decoded message is the content key. The decoder checks the block
//! contents without data-dependent branches or early returns, then makes one
//! decision on validity. It returns the same error for every decoding failure.
//! Distinguishing failures or content-dependent timing can expose an OAEP
//! oracle, as in Manger's attack.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::mgf1::{self, H_LEN};

/// SHA-256 of the empty label.
const EMPTY_LABEL_HASH: [u8; H_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// The encoded block is not an OAEP encoding under SHA-256 and the empty
/// label.
///
/// Carries no detail about which decoding check failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecodingError;

/// Decodes `em`, the block a raw RSA private-key operation returned, and
/// returns the message it carries.
///
/// `em` must be the full modulus length `k`, leading zero included. The
/// length is public, so a block of the wrong length is refused before any
/// check runs over its contents.
pub(crate) fn decode(em: &[u8]) -> Result<Zeroizing<Vec<u8>>, DecodingError> {
    // k >= 2hLen + 2 (RFC 8017, §7.1.2, step 1c).
    if em.len() < 2 * H_LEN + 2 {
        return Err(DecodingError);
    }
    let (&y, rest) = em.split_first().ok_or(DecodingError)?;
    let (masked_seed, masked_db) = rest.split_at_checked(H_LEN).ok_or(DecodingError)?;

    let mut seed = Zeroizing::new([0u8; H_LEN]);
    seed.copy_from_slice(masked_seed);
    mgf1::xor(masked_db, &mut seed[..]);

    let mut db = Zeroizing::new(masked_db.to_vec());
    mgf1::xor(&seed[..], &mut db);

    let (label_hash, padded) = db.split_at_checked(H_LEN).ok_or(DecodingError)?;
    let mut valid = y.ct_eq(&0) & label_hash.ct_eq(&EMPTY_LABEL_HASH[..]);

    // PS is zero bytes up to the first 0x01. Every byte is visited, so the
    // time does not depend on where the separator is.
    let mut in_padding = Choice::from(1);
    let mut message_start = 0u32;
    for (next, &byte) in (1u32..).zip(padded) {
        let is_one = byte.ct_eq(&1);
        let is_zero = byte.ct_eq(&0);
        // A byte other than 0x00 or 0x01 before the separator.
        valid &= !(in_padding & !is_zero & !is_one);
        message_start.conditional_assign(&next, in_padding & is_one);
        in_padding &= !is_one;
    }
    // No separator at all.
    valid &= !in_padding;

    if !bool::from(valid) {
        return Err(DecodingError);
    }
    // The message length is the content key's, which the container's content
    // encryption names publicly.
    usize::try_from(message_start)
        .ok()
        .and_then(|start| padded.get(start..))
        .map(|message| Zeroizing::new(message.to_vec()))
        .ok_or(DecodingError)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use openssl::encrypt::Encrypter;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::{Padding, Rsa};

    use super::*;

    const K: usize = 256;

    pub(crate) fn key() -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    }

    /// One RSA-4096 key for the crate's tests, since generating it takes
    /// seconds.
    pub(crate) fn rsa_4096_key() -> &'static PKey<Private> {
        static KEY: std::sync::OnceLock<PKey<Private>> = std::sync::OnceLock::new();
        KEY.get_or_init(|| PKey::from_rsa(Rsa::generate(4096).unwrap()).unwrap())
    }

    /// RSAES-OAEP-ENCRYPT by OpenSSL, as `openssl pkeyutl -encrypt -pkeyopt
    /// rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt
    /// rsa_mgf1_md:sha256` does it.
    fn oaep_encrypt(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
        let mut encrypter = Encrypter::new(key).unwrap();
        encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        encrypter.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        let mut out = vec![0; encrypter.encrypt_len(message).unwrap()];
        let len = encrypter.encrypt(message, &mut out).unwrap();
        out.truncate(len);
        out
    }

    /// The raw RSA private-key operation a PIV card runs, in software.
    fn raw_decrypt(key: &PKey<Private>, ciphertext: &[u8]) -> Vec<u8> {
        let rsa = key.rsa().unwrap();
        let k = usize::try_from(rsa.size()).unwrap();
        let mut em = vec![0; k];
        let len = rsa
            .private_decrypt(ciphertext, &mut em, Padding::NONE)
            .unwrap();
        assert_eq!(len, k, "OpenSSL returns the full block, leading zero kept");
        em
    }

    pub(crate) fn encoded(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
        raw_decrypt(key, &oaep_encrypt(key, message))
    }

    #[test]
    fn decodes_what_openssl_encrypts() {
        let key = key();
        // Empty, a content key, and the largest message RSA-2048 carries:
        // k - 2hLen - 2 = 190 bytes.
        for len in [0, 1, 16, 32, 189, 190] {
            let message: Vec<u8> = (0u8..=u8::MAX).cycle().take(len).collect();
            for _ in 0..8 {
                let decoded = decode(&encoded(&key, &message)).unwrap();
                assert_eq!(&decoded[..], &message[..], "{len}-byte message");
            }
        }
    }

    /// Under RSA-4096, a content key and the largest message it carries:
    /// k - 2hLen - 2 = 446 bytes.
    #[test]
    fn decodes_what_openssl_encrypts_under_rsa_4096() {
        let key = rsa_4096_key();
        for len in [32, 445, 446] {
            let message: Vec<u8> = (0u8..=u8::MAX).cycle().take(len).collect();
            let decoded = decode(&encoded(key, &message)).unwrap();
            assert_eq!(&decoded[..], &message[..], "{len}-byte message");
        }
    }

    /// Every malformation fails with the same value, so no caller can report
    /// which check it was.
    #[test]
    fn every_malformed_block_fails_alike() {
        let key = key();
        let message = [0x5a; 32];
        let good = encoded(&key, &message);
        assert!(decode(&good).is_ok());

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

        let mut leading = good.clone();
        leading[0] = 1;
        cases.push(("a non-zero leading byte", leading));

        // A flipped bit anywhere in the masked seed or DB unmasks to a wrong
        // label hash, padding, or separator.
        for at in [1, 16, 32, 33, 40, 64, 65, 100, 200, 255] {
            let mut flipped = good.clone();
            flipped[at] ^= 0x01;
            cases.push(("a flipped bit", flipped));
        }

        // A block whose DB is valid except for one field: the good block
        // unmasked, the field changed, and both layers masked again, so the
        // seed still unmasks and only the edited field is wrong.
        let rebuild = |edit: &dyn Fn(&mut [u8])| -> Vec<u8> {
            let mut em = good.clone();
            let (_, rest) = em.split_at_mut(1);
            let (masked_seed, masked_db) = rest.split_at_mut(H_LEN);
            mgf1::xor(masked_db, masked_seed);
            let seed: [u8; H_LEN] = (&*masked_seed).try_into().unwrap();
            mgf1::xor(&seed, masked_db);
            edit(masked_db);
            mgf1::xor(&seed, masked_db);
            masked_seed.copy_from_slice(&seed);
            mgf1::xor(masked_db, masked_seed);
            em
        };
        let unedited = rebuild(&|_| {});
        assert_eq!(&decode(&unedited).unwrap()[..], &message[..]);

        // DB is lHash || PS || 0x01 || M, of k - hLen - 1 bytes.
        let separator = K - H_LEN - 1 - message.len() - 1;
        cases.push(("another label", rebuild(&|db| db[0] ^= 0xff)));
        cases.push((
            "a non-zero padding byte",
            rebuild(&|db| db[H_LEN + 1] = 0x02),
        ));
        cases.push((
            "a non-zero byte just before the separator",
            rebuild(&|db| db[separator - 1] = 0x02),
        ));
        cases.push((
            "a separator other than 0x01",
            rebuild(&|db| db[separator] = 0x02),
        ));
        cases.push(("no separator", rebuild(&|db| db[H_LEN..].fill(0))));

        cases.push(("all zeros", vec![0; K]));
        cases.push(("too short", vec![0; 2 * H_LEN + 1]));

        for (case, em) in cases {
            assert_eq!(decode(&em), Err(DecodingError), "{case}");
        }
    }

    #[test]
    fn empty_label_hash_is_sha256_of_nothing() {
        use sha2::{Digest, Sha256};
        assert_eq!(Sha256::digest([]).as_slice(), &EMPTY_LABEL_HASH[..]);
    }
}
