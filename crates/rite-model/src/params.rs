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

use crate::types::{ActionType, CertProfile, SharingScheme};
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
        ActionType::GenerateKey => {
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
            errors.extend(scheme(with, |_| Ok(())));
            errors
        }
        // Narrower than `wrap_key`'s vocabulary on purpose: the container is
        // the only thing `encrypt_data` writes, and a name it would refuse
        // mid-ceremony belongs in `rite check` rather than in the room.
        ActionType::EncryptData => {
            named_value(with, "scheme", |name| match name.parse::<WrapScheme>() {
                Ok(WrapScheme::CmsAes256Gcm) => Ok(()),
                Ok(other) => Err(format!(
                    "encrypt_data writes {}, not {other}",
                    WrapScheme::CmsAes256Gcm
                )),
                Err(_) => Err(format!("unknown wrapping scheme '{name}'")),
            })
        }
        ActionType::SplitSecret => {
            let mut errors = named_value(with, "scheme", |name| {
                name.parse::<SharingScheme>()
                    .map(|_| ())
                    .map_err(|e| format!("unknown sharing scheme '{name}'; {e}"))
            });
            // The limit is the named scheme's, or the default's when the
            // scheme is absent or not a literal; a scheme that fails to parse
            // is reported above and the counts are still checked against
            // something.
            let scheme = with
                .get("scheme")
                .and_then(serde_json::Value::as_str)
                .and_then(|name| name.parse::<SharingScheme>().ok())
                .unwrap_or(SharingScheme::RiteSssV1);
            let max = u64::from(scheme.max_shares());
            errors.extend(share_count(with, "threshold", max));
            errors.extend(share_count(with, "shares", max));
            if let (Some(threshold), Some(shares)) = (
                with.get("threshold").and_then(serde_json::Value::as_u64),
                with.get("shares").and_then(serde_json::Value::as_u64),
            ) && shares < threshold
            {
                errors.push(ParamError {
                    message: format!(
                        "'shares' is {shares} and 'threshold' is {threshold}; fewer shares than \
                         the threshold could never reconstruct the secret"
                    ),
                });
            }
            errors
        }
        ActionType::UnwrapKey | ActionType::ImportKey => {
            let mut errors = key_identity(with, "expect_key");
            errors.extend(named_value(with, "algorithm", |name| {
                name.parse::<KeyAlgorithm>()
                    .map_err(|_| format!("unknown key algorithm '{name}'"))
            }));
            errors
        }

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
        | ActionType::DecryptData
        | ActionType::CombineShares
        | ActionType::GenerateCsr => Vec::new(),
    }
}

/// A share count or threshold: an integer from 2 to the scheme's limit.
///
/// One is not a split. An absent field is deferred, as everywhere here; a
/// present one that is not an integer is wrong whatever it would have parsed
/// to.
fn share_count(with: &serde_json::Value, field: &'static str, max: u64) -> Vec<ParamError> {
    let Some(value) = with.get(field) else {
        return Vec::new();
    };
    let message = match value.as_u64() {
        Some(n) if (2..=max).contains(&n) => return Vec::new(),
        Some(n) => format!("'{field}' is {n}; it must be from 2 to {max}"),
        None => format!("'{field}' must be an integer from 2 to {max}, found {value}"),
    };
    vec![ParamError { message }]
}

/// The container a step names, checked against the vocabulary rather than left
/// to fail at the backend, and then against what the action itself writes.
///
/// One message for a name outside the vocabulary, whichever action asked, and
/// `accept` for the narrowing an action does on top of that.
fn scheme(
    with: &serde_json::Value,
    accept: impl FnOnce(WrapScheme) -> Result<(), String>,
) -> Vec<ParamError> {
    named_value(with, "scheme", |name| {
        let named = name
            .parse::<WrapScheme>()
            .map_err(|_| format!("unknown wrapping scheme '{name}'"))?;
        accept(named)
    })
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
/// the step would fail in the room, after the keys exist. The runtime renders
/// every fingerprint in lowercase, so uppercase hex is one such shape and is
/// rejected here rather than at the step.
fn fingerprint(with: &serde_json::Value, field: &'static str) -> Vec<ParamError> {
    named_value(with, field, |value| {
        let hex = value.strip_prefix("sha256:").unwrap_or_default();
        if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(())
        } else {
            Err(format!(
                "'{field}' must be a fingerprint of the form \
                 'sha256:<64 lowercase hex digits>', found '{value}'"
            ))
        }
    })
}

/// A key's identity the ceremony declares in advance, in whichever form the
/// key has one: `sha256:<64 hex digits>` over the public half of a keypair, or
/// `cmac-aes:<6 hex digits>` for a symmetric key, which has no public half.
///
/// Same argument as [`fingerprint`]: a value in neither shape can never equal
/// what the runtime computes, so the mismatch is worth reporting before the
/// room rather than during it.
fn key_identity(with: &serde_json::Value, field: &'static str) -> Vec<ParamError> {
    named_value(with, field, |value| {
        let lower_hex = |s: &str, len: usize| {
            s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        let matches_form = match value.split_once(':') {
            Some(("sha256", hex)) => lower_hex(hex, 64),
            Some(("cmac-aes", hex)) => lower_hex(hex, 6),
            _ => false,
        };
        if matches_form {
            Ok(())
        } else {
            Err(format!(
                "'{field}' must name the key either as 'sha256:<64 lowercase hex digits>', \
                 the fingerprint of a public key, or as 'cmac-aes:<6 lowercase hex digits>', \
                 the check value of a symmetric key. Found '{value}'"
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
            sole(ActionType::GenerateKey, &json!({"algorithm": "RSA-9999"}))
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
            .contains("sha256:<64 lowercase hex digits>")
        );
    }

    /// The runtime renders every fingerprint in lowercase, so an uppercase one
    /// would pass resolution and then never match, failing in the room against
    /// the very key it names.
    #[test]
    fn rejects_a_fingerprint_that_is_not_lowercase() {
        let upper = format!("sha256:{}", "AB".repeat(32));
        let message = sole(ActionType::WrapKey, &json!({ "expect_recipient": upper }));
        assert!(message.contains("lowercase"), "{message}");

        let lower = format!("sha256:{}", "ab".repeat(32));
        assert!(
            check(ActionType::WrapKey, &json!({ "expect_recipient": lower })).is_empty(),
            "the shape the runtime produces is the shape that passes"
        );
    }

    /// `encrypt_data` takes a narrower vocabulary than `wrap_key`: a scheme it
    /// would refuse mid-ceremony is refused at check time instead.
    #[test]
    fn rejects_a_scheme_encrypt_data_does_not_write() {
        let message = sole(ActionType::EncryptData, &json!({"scheme": "AES-256-KW"}));
        assert!(
            message.contains("encrypt_data writes CMS-AES-256-GCM"),
            "{message}"
        );

        let message = sole(ActionType::EncryptData, &json!({"scheme": "CMS-RSA-CBC"}));
        assert!(message.contains("unknown wrapping scheme"), "{message}");

        assert!(
            check(
                ActionType::EncryptData,
                &json!({"scheme": "CMS-AES-256-GCM"})
            )
            .is_empty()
        );
        assert!(
            check(ActionType::EncryptData, &json!({})).is_empty(),
            "deferred"
        );

        // The same name is fine on a wrap, which does write it.
        assert!(check(ActionType::WrapKey, &json!({"scheme": "AES-256-KW"})).is_empty());
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
            (ActionType::GenerateKey, json!({"algorithm": "RSA-4096"})),
            (ActionType::SignData, json!({"algorithm": "RSA-PSS-SHA256"})),
            (ActionType::IssueCertificate, json!({"profile": "root_ca"})),
            (
                ActionType::UnwrapKey,
                json!({"expect_key": format!("sha256:{}", "ab".repeat(32))}),
            ),
            (
                ActionType::UnwrapKey,
                json!({"algorithm": "AES-256", "expect_key": "cmac-aes:763cbc"}),
            ),
        ] {
            assert!(check(action, &with).is_empty(), "{action} rejected {with}");
        }
    }

    /// `expect_key` names the recovered key in whichever form it has one, so
    /// both are accepted and anything else is refused before the room.
    #[test]
    fn expect_key_takes_a_fingerprint_or_a_check_value() {
        let message = sole(
            ActionType::UnwrapKey,
            &json!({"expect_key": "cmac-aes:763CBC"}),
        );
        assert!(message.contains("lowercase"), "{message}");

        // A check value is three bytes, so a fingerprint's length under the
        // check value's prefix is not a check value.
        let message = sole(
            ActionType::UnwrapKey,
            &json!({"expect_key": format!("cmac-aes:{}", "ab".repeat(32))}),
        );
        assert!(message.contains("6 lowercase hex digits"), "{message}");

        let message = sole(ActionType::UnwrapKey, &json!({"expect_key": "763cbc"}));
        assert!(
            message.contains("sha256:") && message.contains("cmac-aes:"),
            "{message}"
        );
    }

    /// Nothing travels with a wrapped key saying what it is, so `algorithm:`
    /// declares it, and a name outside the vocabulary fails here rather than
    /// after the blob has been decrypted.
    #[test]
    fn rejects_an_unwrap_algorithm_outside_the_vocabulary() {
        let message = sole(ActionType::UnwrapKey, &json!({"algorithm": "AES-192"}));
        assert!(message.contains("unknown key algorithm"), "{message}");
    }

    #[test]
    fn an_absent_field_is_deferred_not_missing() {
        // The projection drops `algorithm: ${param.algo}`, and a required
        // field written as an expression must not be reported here.
        assert!(check(ActionType::GenerateKey, &json!({})).is_empty());
        assert!(check(ActionType::IssueCertificate, &json!({})).is_empty());
    }

    #[test]
    fn rejects_an_unknown_key_usage() {
        let message = sole(
            ActionType::GenerateKey,
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
        assert!(check(ActionType::GenerateKey, &with).is_empty());
    }

    #[test]
    fn a_non_string_value_is_rejected_whatever_it_would_have_meant() {
        assert!(
            sole(ActionType::GenerateKey, &json!({"algorithm": 4096})).contains("must be a string")
        );
    }

    #[test]
    fn split_secret_counts_are_bounded_by_the_scheme() {
        assert!(
            check(
                ActionType::SplitSecret,
                &json!({"threshold": 2, "shares": 100})
            )
            .is_empty()
        );
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 2, "shares": 101})
            )
            .contains("from 2 to 100")
        );
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 1, "shares": 3})
            )
            .contains("from 2 to 100")
        );
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": 4, "shares": 3})
            )
            .contains("fewer shares than the threshold")
        );
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"threshold": "two", "shares": 3})
            )
            .contains("must be an integer")
        );
        assert!(
            sole(
                ActionType::SplitSecret,
                &json!({"scheme": "sss/v9", "threshold": 2, "shares": 3})
            )
            .contains("unknown sharing scheme")
        );
        // A `${param}` threshold is absent from the literal projection and is
        // deferred, not reported.
        assert!(check(ActionType::SplitSecret, &json!({"shares": 3})).is_empty());
    }
}
