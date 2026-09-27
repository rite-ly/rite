//! The commitment chain: how a transcript's lines fold into its fingerprint.
//!
//! ```text
//! node_0      = SHA-256(0x02 ‖ JCS(header))
//! leaf_i      = SHA-256(0x00 ‖ salt_i ‖ JCS(fact_i))
//! node_i      = SHA-256(0x01 ‖ node_{i-1} ‖ len(at_i) ‖ at_i ‖ level_i ‖ leaf_i)
//! fingerprint = node_n
//! ```
//!
//! `JCS` is the RFC 8785 canonical form ([`canonical_json`](crate::canonical_json)).
//! The functions here take it already computed, since the writer puts the same
//! text on the line. A salt is [`SALT_LEN`] bytes from the OS random source,
//! fresh for every fact; it is never drawn from the ceremony entropy source,
//! which is public by design and would let anyone holding a redacted
//! transcript test guesses against a withheld fact. A line writes the salt as 32 lowercase hex digits, and the
//! leaf hashes the 16 decoded bytes, so the commitment does not depend on how
//! the line spells them. `at` is UTF-8, preceded by its length. Lengths and
//! the level are 8-byte big-endian integers.
//!
//! The leaf commits to the fact; the node commits to the leaf, the time and
//! the level, and to everything before it. A line whose fact is withheld keeps
//! its leaf, so it folds to the same node, and a transcript with withheld lines
//! has the same fingerprint as the complete one. The one-byte prefixes keep a
//! leaf, a node and the header from ever hashing the same input.
//!
//! # Example
//!
//! Folding a header and one fact, as a verifier does line by line; the
//! values are the construction's test vectors.
//!
//! ```
//! use rite_model::commitment::{chain_node, fact_leaf, header_node};
//! use rite_model::{Level, Sha256Digest, canonical_json};
//! use serde_json::json;
//!
//! let header = json!({
//!     "rite_transcript": 1,
//!     "vocabulary": 1,
//!     "producer": "rite 0.6.0",
//!     "run_id": "00000000000000000000000000000000",
//!     "dry_run": false,
//!     "levels": { "public": 10, "restricted": 20, "confidential": 30 },
//! });
//! let node_0 = header_node(&canonical_json(&header)?);
//!
//! let fact = json!({ "type": "act_started", "id": "setup", "label": "Setup" });
//! let leaf = fact_leaf(&[0x11; 16], &canonical_json(&fact)?);
//! let node_1 = chain_node(&node_0, "2026-09-22T10:00:00.000000Z", Level::PUBLIC, &leaf);
//!
//! assert_eq!(
//!     Sha256Digest::from_bytes(&node_1).as_str(),
//!     "sha256:e1942a1ab439cad63eb64ed52692d425d898c2c16b0fac24c08e5c04f71a1af5"
//! );
//! # Ok::<(), rite_model::CanonicalJsonError>(())
//! ```

use sha2::{Digest, Sha256};

use crate::transcript::Level;

/// Length of a fact's salt, in bytes.
pub const SALT_LEN: usize = 16;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;
const HEADER_PREFIX: u8 = 0x02;

/// `node_0`: the commitment to the header, given as its canonical JSON.
#[must_use]
pub fn header_node(canonical_header: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([HEADER_PREFIX]);
    hasher.update(canonical_header.as_bytes());
    hasher.finalize().into()
}

/// `leaf_i`: the commitment to one fact, given as its canonical JSON, under
/// its salt.
#[must_use]
pub fn fact_leaf(salt: &[u8; SALT_LEN], canonical_fact: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(salt);
    hasher.update(canonical_fact.as_bytes());
    hasher.finalize().into()
}

/// `node_i`: the chain value after one line.
#[must_use]
pub fn chain_node(previous: &[u8; 32], at: &str, level: Level, leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(previous);
    update_with_length(&mut hasher, at.as_bytes());
    hasher.update(u64::from(level.value()).to_be_bytes());
    hasher.update(leaf);
    hasher.finalize().into()
}

fn update_with_length(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_json;
    use serde_json::{Value, json};

    fn hex(bytes: &[u8; 32]) -> String {
        base16ct::lower::encode_string(bytes)
    }

    fn jcs(value: &Value) -> String {
        canonical_json(value).expect("canonical")
    }

    /// Fixed vectors: a change to the construction shows up here, and a
    /// third-party implementation can check itself against them.
    #[test]
    fn construction_vectors() {
        let header = json!({
            "rite_transcript": 1,
            "vocabulary": 1,
            "producer": "rite 0.6.0",
            "run_id": "00000000000000000000000000000000",
            "dry_run": false,
            "levels": { "public": 10, "restricted": 20, "confidential": 30 },
        });
        let node_0 = header_node(&jcs(&header));
        assert_eq!(
            hex(&node_0),
            "acd329c9b34b4e9443db1b47b4a5908b3f66affd630005935e5c5201c3f123ec"
        );

        let salt = [0x11; SALT_LEN];
        let fact = json!({ "type": "act_started", "id": "setup", "label": "Setup" });
        let leaf = fact_leaf(&salt, &jcs(&fact));
        assert_eq!(
            hex(&leaf),
            "60d495f6e5117daeaa777bcac4b9aa5360c43aff76bdcf5461380864e0c053d0"
        );

        let node_1 = chain_node(&node_0, "2026-09-22T10:00:00.000000Z", Level::PUBLIC, &leaf);
        assert_eq!(
            hex(&node_1),
            "e1942a1ab439cad63eb64ed52692d425d898c2c16b0fac24c08e5c04f71a1af5"
        );
    }

    #[test]
    fn every_committed_input_changes_the_node() {
        let base = chain_node(&[0; 32], "t", Level::PUBLIC, &[1; 32]);
        assert_ne!(base, chain_node(&[9; 32], "t", Level::PUBLIC, &[1; 32]));
        assert_ne!(base, chain_node(&[0; 32], "u", Level::PUBLIC, &[1; 32]));
        assert_ne!(base, chain_node(&[0; 32], "t", Level::RESTRICTED, &[1; 32]));
        assert_ne!(base, chain_node(&[0; 32], "t", Level::PUBLIC, &[2; 32]));
    }

    #[test]
    fn the_salt_and_the_fact_both_change_the_leaf() {
        let fact = jcs(&json!({ "type": "x" }));
        let leaf = fact_leaf(&[0; SALT_LEN], &fact);
        assert_ne!(leaf, fact_leaf(&[1; SALT_LEN], &fact));
        assert_ne!(
            leaf,
            fact_leaf(&[0; SALT_LEN], &jcs(&json!({ "type": "y" })))
        );
    }

    #[test]
    fn member_order_does_not_change_the_leaf() {
        let a: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).expect("parse");
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).expect("parse");
        assert_eq!(
            fact_leaf(&[0; SALT_LEN], &jcs(&a)),
            fact_leaf(&[0; SALT_LEN], &jcs(&b))
        );
    }
}
