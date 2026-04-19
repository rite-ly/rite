//! Serde helpers for marked-yaml compatibility.
//!
//! marked-yaml deserializes all YAML scalars as strings, so numeric fields
//! need custom deserializers that accept both string and integer representations.

use serde::Deserialize;

/// Deserialize `Option<u32>` from either a YAML integer or a string like `"0"`.
pub(crate) fn deserialize_opt_u32<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<serde_json::Value>::deserialize(de)?
        .map(|v| match v {
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| serde::de::Error::custom("expected u32")),
            serde_json::Value::String(s) => s
                .parse::<u32>()
                .map_err(|_| serde::de::Error::custom(format!("invalid u32: {s}"))),
            other => Err(serde::de::Error::custom(format!(
                "expected u32, got {other}"
            ))),
        })
        .transpose()
}
