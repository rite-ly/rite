//! Rules over a step's `with:` values that hold in every build.
//!
//! These sit beside [`ActionType::required_with_fields`] and
//! [`ActionType::reads_contract`]: what an action requires of its block, in
//! one place both the resolver and the runtime can read. Keeping them here lets
//! an editor report them, since the language server links the model and the
//! resolver but no backend.
//!
//! Only rules that travel with the document belong here. `RSA-9999` is not a
//! key algorithm on any machine, so rejecting it is portable. Whether *this*
//! binary can generate an ML-DSA key is a property of the build doing the
//! checking, and that question is answered by the action handler instead, at
//! the point where a backend exists to ask.

use crate::types::{ActionType, CertProfile};
use rite_sdk::{KeyAlgorithm, KeyUsages, SignAlgorithm, WrapScheme};

/// A `with:` value an action cannot accept.
///
/// The message names the field it is about, so a reader with no span still
/// knows where to look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamError {
    /// What is wrong, phrased for the ceremony author.
    pub message: String,
}

/// Check the literal part of a step's `with:` block.
///
/// `with` is the projection produced by
/// [`literal_expr_value`](crate::expression::literal_expr_value), so a field
/// whose value is an expression is *absent* rather than wrong. Nothing here
/// may report a field as missing: required fields are
/// [`ActionType::required_with_fields`]'s job, and a required field is
/// routinely written as `${param.x}`.
#[must_use]
pub fn check(action: ActionType, with: &serde_json::Value) -> Vec<ParamError> {
    match action {
        ActionType::GenerateKeypair => {
            let mut errors = named_value(with, "algorithm", |name| {
                name.parse::<KeyAlgorithm>()
                    .map_err(|_| format!("unknown key algorithm '{name}'"))
            });
            errors.extend(key_usages(with));
            errors
        }
        ActionType::SignData | ActionType::VerifySignature => {
            named_value(with, "algorithm", |name| {
                name.parse::<SignAlgorithm>()
                    .map_err(|_| format!("unknown signature algorithm '{name}'"))
            })
        }
        ActionType::IssueCertificate => named_value(with, "profile", |name| {
            name.parse::<CertProfile>()
                .map_err(|_| format!("unknown certificate profile '{name}'"))
        }),
        ActionType::WrapKey => {
            let mut errors = fingerprint(with, "expect_recipient");
            errors.extend(named_value(with, "scheme", |name| {
                name.parse::<WrapScheme>()
                    .map_err(|_| format!("unknown wrapping scheme '{name}'"))
            }));
            errors
        }
        ActionType::UnwrapKey => fingerprint(with, "expect_key"),

        ActionType::ClockCheck
        | ActionType::Confirm
        | ActionType::CheckValue
        | ActionType::OralReadback
        | ActionType::MachineInfo
        | ActionType::ExportPublic
        | ActionType::Attest
        | ActionType::GatherEntropy
        | ActionType::TpmAttest
        | ActionType::PivReadCertificate
        | ActionType::PivSign
        | ActionType::YubikeyAttestSlot
        | ActionType::GenerateCsr => Vec::new(),
    }
}

/// Apply `parse` to a present string field.
///
/// An absent field is deferred, not missing. A field holding something other
/// than a string is wrong whatever the value would have been.
fn named_value<T>(
    with: &serde_json::Value,
    field: &'static str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Vec<ParamError> {
    let Some(value) = with.get(field) else {
        return Vec::new();
    };
    let Some(name) = value.as_str() else {
        return vec![ParamError {
            message: format!("'{field}' must be a string, found {value}"),
        }];
    };
    parse(name)
        .err()
        .map(|message| ParamError { message })
        .into_iter()
        .collect()
}

/// Check the names under `policy: { usages: [...] }`.
///
/// These are PKCS#11 usages, what the token permits the key to do. The X.509
/// `KeyUsage` extension is a different thing and comes from `profile:` on
/// `issue_certificate`.
fn key_usages(with: &serde_json::Value) -> Vec<ParamError> {
    const FIELD: &str = "policy.usages";
    let Some(usages) = with.get("policy").and_then(|p| p.get("usages")) else {
        return Vec::new();
    };
    let Some(names) = usages.as_array() else {
        return vec![ParamError {
            message: format!("'{FIELD}' must be a list, found {usages}"),
        }];
    };
    names
        .iter()
        .filter_map(|name| {
            let known = name
                .as_str()
                .is_some_and(|name| KeyUsages::usage_named(name).is_some());
            (!known).then(|| ParamError {
                message: format!(
                    "unknown key usage {name} under '{FIELD}'. Supported: {}",
                    KeyUsages::all_names().join(", ")
                ),
            })
        })
        .collect()
}

/// A fingerprint the ceremony declares in advance, `sha256:<64 hex digits>`.
///
/// A value in any other shape can never equal what the runtime computes, so
/// the step would fail in the room, after the keys exist.
fn fingerprint(with: &serde_json::Value, field: &'static str) -> Vec<ParamError> {
    named_value(with, field, |value| {
        let hex = value.strip_prefix("sha256:").unwrap_or_default();
        if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(format!(
                "'{field}' must be a fingerprint of the form 'sha256:<64 hex digits>', \
                 found '{value}'"
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sole(action: ActionType, with: &serde_json::Value) -> String {
        let errors = check(action, with);
        let [error] = errors.as_slice() else {
            panic!("expected exactly one error, got {errors:?}");
        };
        error.message.clone()
    }

    #[test]
    fn rejects_a_value_outside_the_vocabulary() {
        assert!(
            sole(
                ActionType::GenerateKeypair,
                &json!({"algorithm": "RSA-9999"})
            )
            .contains("unknown key algorithm")
        );
        assert!(
            sole(ActionType::SignData, &json!({"algorithm": "RSA-PSS-SHA1"}))
                .contains("unknown signature algorithm")
        );
        assert!(
            sole(
                ActionType::IssueCertificate,
                &json!({"profile": "wildcard"})
            )
            .contains("unknown certificate profile")
        );
        assert!(
            sole(
                ActionType::WrapKey,
                &json!({"expect_recipient": "deadbeef"})
            )
            .contains("sha256:<64 hex digits>")
        );
    }

    /// A scheme name outside the vocabulary would fail in the room, after the
    /// keys exist, so resolution rejects it.
    #[test]
    fn rejects_a_wrapping_scheme_outside_the_vocabulary() {
        let message = sole(ActionType::WrapKey, &json!({"scheme": "CMS-RSA-CBC"}));
        assert!(message.contains("unknown wrapping scheme"), "{message}");

        assert!(
            check(
                ActionType::WrapKey,
                &json!({"scheme": "RSA-AES-KEY-WRAP-SHA256"})
            )
            .is_empty()
        );
        assert!(
            check(ActionType::WrapKey, &json!({})).is_empty(),
            "deferred"
        );
    }

    #[test]
    fn accepts_the_vocabulary() {
        for (action, with) in [
            (
                ActionType::GenerateKeypair,
                json!({"algorithm": "RSA-4096"}),
            ),
            (ActionType::SignData, json!({"algorithm": "RSA-PSS-SHA256"})),
            (ActionType::IssueCertificate, json!({"profile": "root_ca"})),
            (
                ActionType::UnwrapKey,
                json!({"expect_key": format!("sha256:{}", "ab".repeat(32))}),
            ),
        ] {
            assert!(check(action, &with).is_empty(), "{action} rejected {with}");
        }
    }

    #[test]
    fn an_absent_field_is_deferred_not_missing() {
        // The projection drops `algorithm: ${param.algo}`, and a required
        // field written as an expression must not be reported here.
        assert!(check(ActionType::GenerateKeypair, &json!({})).is_empty());
        assert!(check(ActionType::IssueCertificate, &json!({})).is_empty());
    }

    #[test]
    fn rejects_an_unknown_key_usage() {
        let message = sole(
            ActionType::GenerateKeypair,
            &json!({"policy": {"usages": ["sign", "key_cert_sign"]}}),
        );
        assert!(message.contains("unknown key usage"), "{message}");
        assert!(
            message.contains("wrap"),
            "the message should list what is available: {message}"
        );
    }

    #[test]
    fn accepts_the_pkcs11_usages() {
        let with = json!({"policy": {"usages": ["sign", "verify", "wrap", "unwrap", "derive"]}});
        assert!(check(ActionType::GenerateKeypair, &with).is_empty());
    }

    #[test]
    fn a_non_string_value_is_rejected_whatever_it_would_have_meant() {
        assert!(
            sole(ActionType::GenerateKeypair, &json!({"algorithm": 4096}))
                .contains("must be a string")
        );
    }
}
