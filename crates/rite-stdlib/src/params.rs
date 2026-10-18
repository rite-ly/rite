//! Runtime helpers over the params types, which live in `rite_model::params`.

/// A key policy as the transcript records it.
///
/// One renderer, because three actions record a policy and an auditor
/// comparing a generate against an import in the same run should be reading a
/// difference in the policy, never a difference in who wrote it out.
#[cfg(feature = "crypto")]
#[must_use]
pub fn policy_json(policy: &rite_sdk::KeyPolicy) -> serde_json::Value {
    serde_json::json!({
        "persistent": policy.persistent,
        "sensitive": policy.sensitive,
        "extractable": policy.extractable,
        "wrap_with_trusted_only": policy.wrap_with_trusted_only,
        "usages": policy.usages.names(),
    })
}

/// The policy a key installed from material the ceremony holds gets when the
/// step declares none. Shared by `unwrap_key` and `import_key`.
///
/// `extractable` is true because this backend has just held the key in the
/// clear, so claiming otherwise would be a claim the run cannot support. The
/// usages are the restrictive default, as they are at generation, and they
/// follow the declared algorithm for the same reason they do there: sign and
/// verify is right for a keypair and impossible for a symmetric key.
///
/// `None` is a ceremony that declared no algorithm, which only a keypair can
/// reach, since a symmetric key cannot be recovered without the declaration.
#[cfg(feature = "crypto")]
#[must_use]
pub fn installed_key_default_policy(
    algorithm: Option<rite_sdk::KeyAlgorithm>,
) -> rite_sdk::KeyPolicy {
    let usages = algorithm.map_or_else(
        || rite_sdk::KeyPolicy::default().usages,
        |algorithm| rite_sdk::KeyPolicy::default_for(algorithm).usages,
    );
    rite_sdk::KeyPolicy {
        extractable: true,
        usages,
        ..rite_sdk::KeyPolicy::default()
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::*;

    /// A recovered key's default usages follow what the ceremony declared it
    /// is, because sign and verify is right for a keypair and impossible for a
    /// symmetric key, which exists only to wrap.
    #[test]
    fn the_default_policy_for_a_recovered_key_follows_its_algorithm() {
        use rite_sdk::{KeyAlgorithm, KeyUsages};

        let keypair = installed_key_default_policy(Some(KeyAlgorithm::Rsa4096));
        assert_eq!(keypair.usages, KeyUsages::SIGN | KeyUsages::VERIFY);

        let secret = installed_key_default_policy(Some(KeyAlgorithm::Aes256));
        assert_eq!(secret.usages, KeyUsages::WRAP | KeyUsages::UNWRAP);

        // Undeclared is a keypair: a symmetric key cannot be recovered at all
        // without the declaration.
        assert_eq!(
            installed_key_default_policy(None).usages,
            installed_key_default_policy(Some(KeyAlgorithm::Rsa4096)).usages
        );

        // The key was held in the clear here whatever it is, so claiming it
        // cannot leave would be a claim the run does not support.
        assert!(secret.extractable && keypair.extractable);
    }
}
