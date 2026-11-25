//! EMSA-PSS encoding (RFC 8017, §9.1.1) with SHA-256 for the message hash
//! and for MGF1, and a salt as long as the digest.
//!
//! A PIV card runs the raw RSA private-key operation on whatever it receives,
//! so the host builds the encoded block before the card signs, as it does for
//! EMSA-PKCS1-v1_5 in [`crate::ops::sign`].
//!
//! The salt length is the one `rite-openssl` signs with, the length RFC 8017
//! recommends and X.509 tooling expects, so a PSS signature carries the same
//! parameters whichever backend made it. OpenSSL verifies it with the salt
//! length read from the signature or fixed at 32 bytes.

use rand::TryRng;
use rand::rngs::SysRng;
use rite_sdk::BackendError;
use sha2::{Digest, Sha256};

use crate::mgf1::{self, H_LEN};
use crate::ops::RsaSize;

/// The salt length, `sLen` in RFC 8017: the SHA-256 digest length.
pub(crate) const SALT_LEN: usize = H_LEN;

/// A fresh salt from the operating system's random generator.
///
/// The salt is not secret: it is recovered from the signature by anyone
/// holding the public key. It makes each signature of the same message
/// differ, which PSS's security proof relies on. The card offers no random
/// command in standard PIV, and this crate cannot call OpenSSL, so the
/// operating system supplies it.
///
/// # Errors
///
/// Returns [`BackendError::Other`] if the operating system cannot supply
/// random bytes.
pub(crate) fn random_salt() -> Result<[u8; SALT_LEN], BackendError> {
    let mut salt = [0u8; SALT_LEN];
    SysRng.try_fill_bytes(&mut salt).map_err(|error| {
        BackendError::Other(format!(
            "the operating system supplied no salt for an RSA-PSS signature: {error}"
        ))
    })?;
    Ok(salt)
}

/// The EMSA-PSS block for the SHA-256 digest `m_hash` with `salt`, for an
/// RSA key of `size`.
///
/// Both sizes fill their modulus bytes (2048 and 4096 bits), so `emBits`,
/// one less than the modulus bits, is `8k - 1` for a modulus of `k` bytes:
/// the block is the modulus length, and its leftmost bit is cleared so that
/// it is smaller than the modulus. Both are far longer than the
/// `hLen + sLen + 2` bytes the encoding needs.
///
/// `EM = maskedDB || H || 0xbc`, where `H = SHA-256(0x00 * 8 || mHash ||
/// salt)` and `DB = PS || 0x01 || salt`, `PS` being zeros, masked by MGF1
/// over `H`.
pub(crate) fn encode_sha256(m_hash: [u8; H_LEN], salt: &[u8; SALT_LEN], size: RsaSize) -> Vec<u8> {
    let em_len = size.modulus_len();
    let h = Sha256::new()
        .chain_update([0u8; 8])
        .chain_update(m_hash)
        .chain_update(salt)
        .finalize();

    let db_len = em_len.saturating_sub(H_LEN + 1);
    let mut em = Vec::with_capacity(em_len);
    em.resize(db_len.saturating_sub(SALT_LEN + 1), 0x00);
    em.push(0x01);
    em.extend_from_slice(salt);
    mgf1::xor(&h, &mut em);
    if let Some(leftmost) = em.first_mut() {
        *leftmost &= 0x7f;
    }
    em.extend_from_slice(&h);
    em.push(0xbc);
    em
}

#[cfg(test)]
mod tests {
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Padding;
    use openssl::sign::{RsaPssSaltlen, Verifier};

    use super::*;
    use crate::oaep::tests::{key, rsa_4096_key};

    /// The card's part: the raw RSA private-key operation over the block.
    fn raw_sign(key: &PKey<Private>, em: &[u8]) -> Vec<u8> {
        let rsa = key.rsa().unwrap();
        let mut signature = vec![0; rsa.size() as usize];
        let len = rsa
            .private_encrypt(em, &mut signature, Padding::NONE)
            .unwrap();
        signature.truncate(len);
        signature
    }

    /// OpenSSL's PSS verification, as `rite-openssl` and X.509 tooling run
    /// it, with the salt length either fixed at 32 bytes or read from the
    /// signature.
    fn openssl_verifies(
        key: &PKey<Private>,
        message: &[u8],
        signature: &[u8],
        salt_len: RsaPssSaltlen,
    ) -> bool {
        let mut verifier = Verifier::new(MessageDigest::sha256(), key).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        verifier.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        verifier.set_rsa_pss_saltlen(salt_len).unwrap();
        verifier.update(message).unwrap();
        verifier.verify(signature).unwrap()
    }

    #[test]
    fn signs_as_openssl_verifies_with_a_digest_length_salt() {
        let message = b"release manifest";
        for (size, key) in [
            (RsaSize::Rsa2048, &key()),
            (RsaSize::Rsa4096, rsa_4096_key()),
        ] {
            let k = size.modulus_len();
            assert_eq!(key.size(), k);
            let em = encode_sha256(
                Sha256::digest(message).into(),
                &random_salt().unwrap(),
                size,
            );
            assert_eq!(em.len(), k);
            let signature = raw_sign(key, &em);

            for salt_len in [RsaPssSaltlen::DIGEST_LENGTH, RsaPssSaltlen::custom(32)] {
                assert!(openssl_verifies(key, message, &signature, salt_len), "{k}");
            }
            assert!(
                !openssl_verifies(
                    key,
                    b"another manifest",
                    &signature,
                    RsaPssSaltlen::DIGEST_LENGTH
                ),
                "{k}"
            );
        }
    }

    /// A verifier that fixes another salt length refuses the block, so the
    /// verification above checked the 32-byte salt rather than accepting any.
    #[test]
    fn a_verifier_fixing_another_salt_length_refuses_it() {
        let key = key();
        let message = b"release manifest";
        let em = encode_sha256(
            Sha256::digest(message).into(),
            &random_salt().unwrap(),
            RsaSize::Rsa2048,
        );
        let signature = raw_sign(&key, &em);
        assert!(openssl_verifies(
            &key,
            message,
            &signature,
            RsaPssSaltlen::custom(32)
        ));
        assert!(!openssl_verifies(
            &key,
            message,
            &signature,
            RsaPssSaltlen::custom(20)
        ));
    }

    #[test]
    fn each_signature_draws_its_own_salt() {
        assert_ne!(random_salt().unwrap(), random_salt().unwrap());
    }
}
