//! Content encryption under a key the caller already holds.
//!
//! A cipher and nothing else. Which key was used, who may open the result and
//! what container carries it are decided above this module, which is what lets
//! one content pipeline serve every recipient shape.
//!
//! Separate from the backend for the same reason. A backend protects keys, and
//! no key-protection device Rite talks to is fast enough to be handed a file,
//! so content is encrypted here in every design that ships.

use rite_sdk::BackendError;
use zeroize::Zeroizing;

use crate::backend::{aes_256_gcm_open, aes_256_gcm_seal, ossl_err};

/// Content under AES-256-GCM, with the values that have to travel beside it.
///
/// None of the three opens the content alone: the nonce is an input to the
/// decrypt, and the tag is what says the ciphertext was not altered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContent {
    /// The 12-byte AES-GCM nonce, fresh per message.
    pub nonce: Vec<u8>,
    /// The encrypted content.
    pub ciphertext: Vec<u8>,
    /// The authentication tag over that content.
    pub tag: Vec<u8>,
}

/// Encrypt `payload` under `cek` with AES-256-GCM.
///
/// The nonce is drawn here rather than taken as a parameter, because a nonce
/// reused under one key breaks GCM outright and a parameter is a way to reuse
/// one. Ninety-six fresh random bits per message is the random construction of
/// NIST SP 800-38D §8.2.2.
///
/// # Errors
///
/// Returns [`BackendError`] if `cek` is not a 256-bit key or the cipher fails.
pub fn seal_content(cek: &[u8], payload: &[u8]) -> Result<SealedContent, BackendError> {
    let mut nonce = vec![0u8; 12];
    openssl::rand::rand_bytes(&mut nonce).map_err(|e| ossl_err("Generate GCM nonce", &e))?;
    let (ciphertext, tag) = aes_256_gcm_seal(cek, &nonce, payload)?;
    Ok(SealedContent {
        nonce,
        ciphertext,
        tag,
    })
}

/// Undo [`seal_content`].
///
/// # Errors
///
/// Returns [`BackendError`] if the tag does not authenticate the ciphertext,
/// which is also the answer a wrong key gets.
pub fn open_content(
    cek: &[u8],
    sealed: &SealedContent,
) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    aes_256_gcm_open(cek, &sealed.nonce, &sealed.ciphertext, &sealed.tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The primitive carries the published vector and the tampering refusal.
    /// What this layer adds is the nonce, so that is what it pins.
    #[test]
    fn each_seal_draws_its_own_nonce() {
        let cek = [7u8; 32];
        let first = seal_content(&cek, b"same content").expect("seal");
        let second = seal_content(&cek, b"same content").expect("seal");

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_eq!(first.nonce.len(), 12);
    }

    #[test]
    fn content_opens_under_the_key_that_sealed_it() {
        let cek = [7u8; 32];
        let sealed = seal_content(&cek, b"the recovery phrase").expect("seal");

        assert_eq!(
            open_content(&cek, &sealed).expect("open").as_slice(),
            b"the recovery phrase"
        );
        assert!(open_content(&[8u8; 32], &sealed).is_err());
    }
}
