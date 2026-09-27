//! The `sha256:<hex>` digest used for every hash the transcript records.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PREFIX: &str = "sha256:";

/// A SHA-256 digest written as `sha256:` followed by 64 lowercase hex digits.
///
/// The one hash encoding in the transcript. Parsing rejects any other form,
/// so a recorded digest compares correctly as a string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

#[cfg(test)]
impl schemars::JsonSchema for Sha256Digest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Sha256Digest".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A SHA-256 digest: `sha256:` followed by 64 lowercase hex digits.",
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$",
        })
    }
}

/// A string that is not a `sha256:<64 lowercase hex>` digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestFormatError(String);

impl fmt::Display for DigestFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "'{}' is not a sha256:<64 lowercase hex digits> digest",
            self.0
        )
    }
}

impl std::error::Error for DigestFormatError {}

impl Sha256Digest {
    /// The digest of `data`.
    #[must_use]
    pub fn of(data: &[u8]) -> Self {
        let hash = Sha256::digest(data);
        Self(format!("{PREFIX}{}", base16ct::lower::encode_string(&hash)))
    }

    /// The written form of a raw 32-byte digest.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(format!("{PREFIX}{}", base16ct::lower::encode_string(bytes)))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // `parse` admits only 64 lowercase hex digits, so this decodes.
        let _ = base16ct::lower::decode(&self.0[PREFIX.len()..], &mut out);
        out
    }

    /// Parse a digest in its written form.
    ///
    /// ```
    /// use rite_model::Sha256Digest;
    ///
    /// let digest = Sha256Digest::of(b"ceremony");
    /// assert_eq!(Sha256Digest::parse(digest.as_str()), Ok(digest));
    /// // Any other spelling is refused.
    /// assert!(Sha256Digest::parse("SHA256:00").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`DigestFormatError`] unless `s` is `sha256:` followed by
    /// exactly 64 lowercase hex digits.
    pub fn parse(s: &str) -> Result<Self, DigestFormatError> {
        let valid = s.strip_prefix(PREFIX).is_some_and(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        });
        if valid {
            Ok(Self(s.to_string()))
        } else {
            Err(DigestFormatError(s.to_string()))
        }
    }

    /// The written form, `sha256:<hex>`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = DigestFormatError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<Sha256Digest> for String {
    fn from(d: Sha256Digest) -> Self {
        d.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_known_bytes() {
        assert_eq!(
            Sha256Digest::of(b"hello world").as_str(),
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn bytes_round_trip() {
        let d = Sha256Digest::of(b"x");
        assert_eq!(Sha256Digest::from_bytes(&d.to_bytes()), d);
    }

    #[test]
    fn parse_accepts_the_written_form() {
        let d = Sha256Digest::of(b"x");
        assert_eq!(Sha256Digest::parse(d.as_str()), Ok(d));
    }

    #[test]
    fn parse_rejects_other_forms() {
        let hex = "a".repeat(64);
        for bad in [
            hex.clone(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", &hex[..63]),
            format!("sha512:{hex}"),
            format!("sha256:{hex}0"),
        ] {
            assert!(Sha256Digest::parse(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn deserialize_validates() {
        let err = serde_json::from_str::<Sha256Digest>("\"sha256:zz\"");
        assert!(err.is_err());
    }
}
