//! Ceremony entropy source: a single, auditable, reproducible origin for
//! every random value a ceremony consumes.
//!
//! # The split: gather vs derive
//!
//! Randomness enters the source once, by *gathering* non-deterministic bytes
//! from the host (the machine seed `m`, and optionally free-form human
//! contributions). Everything after that is *derivation*: a pure, frozen
//! function of the gathered bytes. The gathered bytes are recorded in the
//! transcript, so the derivation, and therefore every value drawn, replays
//! identically from the transcript alone, decades later, in any language.
//!
//! # The `rite-kdf/v1` scheme
//!
//! All steps use HKDF-SHA-256 (RFC 5869).
//!
//! ```text
//! seed_0      = HKDF-Extract(salt = "rite/seed/v1", IKM = m)
//! seed_{k+1}  = HKDF-Extract(salt = seed_k,         IKM = utf8(h_k))
//! path        = "<epoch>/<step>/<purpose>"
//! value(path) = HKDF-Expand(seed_epoch, info = "rite/nonce/v1/" || path, len)
//! ```
//!
//! The seed is an *epoch chain* (a ratchet): each human contribution `h_k`
//! advances the epoch by extracting a new seed with the previous seed as the
//! HMAC salt (key) and the contribution as the IKM (message). This is the
//! TLS 1.3 key-schedule shape. Because the prior high-entropy seed is the key,
//! a weak or empty contribution can never reduce strength below the machine
//! seed; an unpredictable one only adds. A value is drawn from whichever epoch
//! seed is current when the draw happens, so there is no constraint that human
//! steps precede draws.
//!
//! # Why this is reproducible but a PRNG would not be
//!
//! [`CeremonyRandom`] is a deterministic fold over recorded inputs, not opaque
//! generator state. A verifier rebuilds `seed_0` from the recorded `m`, folds
//! each recorded contribution in transcript order, and re-derives any value
//! straight from its recorded path. No draw order, internal buffer, or library
//! version affects the output.

use std::collections::HashSet;

use hkdf::Hkdf;
use rite_model::StepId;
use sha2::Sha256;

/// Frozen-scheme tag recorded with the machine seed. It pins the *entire*
/// construction (Extract/Expand, the ratchet rule, the `info`/path byte
/// encodings), not merely the hash. A verifier treats it as a selector among
/// known-good schemes it already trusts and rejects any value it does not
/// recognise, it is never an instruction to trust an arbitrary algorithm.
pub const DERIVATION_V1: &str = "rite-kdf/v1";

/// Salt for the initial `HKDF-Extract` that turns the machine seed into
/// `seed_0`. Part of the frozen `rite-kdf/v1` scheme.
const SEED_SALT_V1: &[u8] = b"rite/seed/v1";

/// Prefix prepended to every derivation path to form the `HKDF-Expand` info
/// string. Part of the frozen `rite-kdf/v1` scheme.
const VALUE_INFO_PREFIX_V1: &str = "rite/nonce/v1/";

/// Length in bytes of an epoch seed (the HKDF pseudo-random key).
const SEED_LEN: usize = 32;

/// Longest value a single draw can produce: the `HKDF-Expand` output limit of
/// `255 * HashLen` bytes (RFC 5869), with SHA-256's 32-byte output. [`expand`]
/// panics beyond this, so anything replaying a recorded draw must bound the
/// requested length by this value first.
pub const MAX_DRAW_LEN: usize = 255 * SEED_LEN;

/// `HKDF-Extract(salt, ikm)` over SHA-256, returning the 32-byte PRK.
///
/// The `salt` is a fixed domain-separation constant (RFC 5869 permits a
/// non-secret, fixed salt). Uniqueness and unpredictability come from the IKM
/// (the per-ceremony machine entropy), not the salt, so a constant salt here is
/// correct, not the password-KDF static-salt anti-pattern.
fn extract(salt: &[u8], ikm: &[u8]) -> [u8; SEED_LEN] {
    let (prk, _hk) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// `HKDF-Expand(prk, info, len)` over SHA-256.
///
/// # Panics
///
/// Never in practice. `from_prk` only rejects a PRK shorter than the hash
/// output, but every seed here is exactly 32 bytes; `expand` only fails when
/// `len` exceeds [`MAX_DRAW_LEN`], which both untrusted entry points bound
/// before reaching here (`Reporter::draw` on the draw side, `verify_entropy`
/// on the replay side). Both `expect`s therefore guard true invariants and
/// are allowed.
#[allow(clippy::expect_used)]
fn expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("seed is a valid HKDF PRK length");
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("draw length is within HKDF-Expand limits");
    out
}

/// Compute `seed_0` from the machine entropy `m`.
#[must_use]
pub fn initial_seed(m: &[u8]) -> [u8; SEED_LEN] {
    extract(SEED_SALT_V1, m)
}

/// Advance the ratchet by one epoch, folding in a human contribution.
#[must_use]
pub fn fold_seed(current: &[u8; SEED_LEN], contribution: &[u8]) -> [u8; SEED_LEN] {
    extract(current, contribution)
}

/// Derive the value at `path` from the given epoch seed.
///
/// The verifier calls this directly with a recorded path, so it must stay a
/// pure function of `(seed_epoch, path, len)`.
#[must_use]
pub fn derive_value(seed_epoch: &[u8; SEED_LEN], path: &str, len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(VALUE_INFO_PREFIX_V1.len().saturating_add(path.len()));
    info.extend_from_slice(VALUE_INFO_PREFIX_V1.as_bytes());
    info.extend_from_slice(path.as_bytes());
    expand(seed_epoch, &info, len)
}

/// Build a derivation path. The single place the path format lives, so the
/// draw side and the verify side cannot drift. A `purpose` is drawn at most
/// once per step, so `(epoch, step, purpose)` uniquely identifies a value.
#[must_use]
pub fn build_path(epoch: u32, step: &StepId, purpose: &str) -> String {
    format!("{epoch}/{step}/{purpose}", step = step.as_str())
}

/// A value drawn from the source, paired with the path that derives it.
#[derive(Debug, Clone)]
pub struct Draw {
    /// Derivation path: `<epoch>/<step>/<purpose>`.
    pub path: String,
    /// The derived bytes.
    pub value: Vec<u8>,
}

/// The per-ceremony entropy source.
///
/// Owns the running epoch seed, the epoch index, and the set of paths already
/// issued. Held by the [`Reporter`](crate::Reporter), which records a fact for
/// every gather and every draw so the source can be reconstructed from the
/// transcript.
///
/// The issued-paths set is internal runtime state only, never serialized; it
/// exists so a repeated `(step, purpose)` is rejected rather than silently
/// reusing a value.
#[derive(Debug, Clone)]
pub struct CeremonyRandom {
    seed_epoch: [u8; SEED_LEN],
    epoch: u32,
    issued: HashSet<String>,
}

impl CeremonyRandom {
    /// Build a source from gathered machine entropy `m` (epoch 0).
    #[must_use]
    pub fn from_machine_seed(m: &[u8]) -> Self {
        Self {
            seed_epoch: initial_seed(m),
            epoch: 0,
            issued: HashSet::new(),
        }
    }

    /// The current epoch index (0 before any human contribution).
    #[must_use]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Fold a human contribution into the seed, advancing the epoch.
    pub fn fold(&mut self, contribution: &[u8]) {
        self.seed_epoch = fold_seed(&self.seed_epoch, contribution);
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Draw `len` bytes for `(step, purpose)`.
    ///
    /// A `purpose` is drawn at most once per step. Returns `None` if this
    /// `(step, purpose)` was already drawn, since deriving it again would reuse
    /// the value; the caller turns that into a hard error. On success returns
    /// the value together with its derivation path so the caller can record
    /// both in the transcript.
    pub fn draw(&mut self, step: &StepId, purpose: &str, len: usize) -> Option<Draw> {
        let path = build_path(self.epoch, step, purpose);
        if !self.issued.insert(path.clone()) {
            return None;
        }
        let value = derive_value(&self.seed_epoch, &path, len);
        Some(Draw { path, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(id: &str) -> StepId {
        StepId::new(id)
    }

    #[test]
    fn derivation_is_reproducible_from_recorded_inputs() {
        let m = b"machine entropy";
        let seed = initial_seed(m);
        // A verifier with only `m` and the path recomputes the same value.
        let path = build_path(0, &step("issue"), "cert-serial");
        let a = derive_value(&seed, &path, 9);
        let b = derive_value(&initial_seed(m), &path, 9);
        assert_eq!(a, b);
        assert_eq!(a.len(), 9);
    }

    #[test]
    fn different_paths_yield_different_values() {
        let seed = initial_seed(b"m");
        let vp = derive_value(&seed, &build_path(0, &step("s"), "p"), 16);
        let vq = derive_value(&seed, &build_path(0, &step("s"), "q"), 16);
        let vs2 = derive_value(&seed, &build_path(0, &step("s2"), "p"), 16);
        assert_ne!(vp, vq);
        assert_ne!(vp, vs2);
    }

    #[test]
    fn draw_rejects_a_repeated_purpose_in_the_same_step() {
        let mut r = CeremonyRandom::from_machine_seed(b"m");
        let first = r.draw(&step("s"), "tpm-quote", 20).expect("first draw");
        assert_eq!(first.path, "0/s/tpm-quote");
        // The same (step, purpose) again would reuse the value: rejected.
        assert!(r.draw(&step("s"), "tpm-quote", 20).is_none());
        // A different purpose under the same step is fine.
        let other = r
            .draw(&step("s"), "cert-serial", 9)
            .expect("distinct purpose");
        assert_eq!(other.path, "0/s/cert-serial");
        assert_ne!(first.value, other.value);
    }

    #[test]
    fn folding_advances_epoch_and_changes_draws() {
        let mut plain = CeremonyRandom::from_machine_seed(b"m");
        let mut folded = CeremonyRandom::from_machine_seed(b"m");
        folded.fold(b"3 1 6 4 2 5");
        assert_eq!(plain.epoch(), 0);
        assert_eq!(folded.epoch(), 1);

        let p = plain.draw(&step("s"), "p", 16).expect("draw");
        let f = folded.draw(&step("s"), "p", 16).expect("draw");
        // Same step/purpose, different epoch seed: different value and path.
        assert_eq!(p.path, "0/s/p");
        assert_eq!(f.path, "1/s/p");
        assert_ne!(p.value, f.value);
    }

    #[test]
    fn fold_is_a_deterministic_function_of_inputs() {
        // Two sources fed the same machine seed and the same contribution in
        // the same order must derive identically: the verifier's replay.
        let mut a = CeremonyRandom::from_machine_seed(b"seed");
        let mut b = CeremonyRandom::from_machine_seed(b"seed");
        a.fold(b"alice");
        b.fold(b"alice");
        assert_eq!(
            a.draw(&step("s"), "p", 32).expect("draw").value,
            b.draw(&step("s"), "p", 32).expect("draw").value
        );
    }

    #[test]
    fn empty_contribution_still_advances_but_never_panics() {
        // A weak or empty human input is the HMAC message, not the key, so it
        // is always safe to accept.
        let mut r = CeremonyRandom::from_machine_seed(b"m");
        r.fold(b"");
        assert_eq!(r.epoch(), 1);
        assert_eq!(r.draw(&step("s"), "p", 8).expect("draw").value.len(), 8);
    }
}
