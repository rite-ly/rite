//! Fingerprint helpers used across the runtime.

use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Lower-hex SHA-256 of a byte slice, the raw primitive without any prefix.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    base16ct::lower::encode_string(&hasher.finalize())
}

/// SHA-256 fingerprint of an in-memory byte slice.
///
/// Returns `"sha256:{lowercase_hex}"`, the convention used throughout
/// the runtime for artifact and transcript fingerprints.
#[must_use]
pub fn compute_fingerprint(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// SHA-256 fingerprint of a file's contents.
///
/// # Errors
///
/// Returns the underlying I/O error if the file cannot be read.
pub fn compute_file_fingerprint(path: &Path) -> io::Result<String> {
    let data = std::fs::read(path)?;
    Ok(compute_fingerprint(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_of_known_bytes() {
        let fp = compute_fingerprint(b"hello world");
        assert_eq!(
            fp,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
