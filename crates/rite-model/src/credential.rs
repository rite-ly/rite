//! What a ceremony declares about a credential a backend has: what it is
//! used for, and where its value comes from when a step needs it.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What a credential is used for in the ceremony.
///
/// Each provider maps it to its own roles. The field is `grants`, not
/// `role`, which names a person everywhere else in the definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialGrant {
    /// Administers the device: a PIV management key, a PKCS#11 security
    /// officer PIN.
    Admin,
    /// Uses the keys on the device: a PIV PIN, a PKCS#11 user PIN.
    User,
    /// Unblocks the user credential: a PIV PUK.
    Unblock,
}

crate::types::vocabulary!(CredentialGrant {
    Admin => "admin",
    User => "user",
    Unblock => "unblock",
});

impl fmt::Display for CredentialGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a credential's value comes from when a step needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// The vendor's well-known value.
    FactoryDefault,
    /// Typed, masked, by the person in the step's role.
    Entered,
    /// Kept outside the device; a step gives it from an artifact.
    Held,
    /// Presented to the device directly, on a PIN pad or a PED. Rite never
    /// sees it.
    OnDevice,
}

crate::types::vocabulary!(CredentialSource {
    FactoryDefault => "factory_default",
    Entered => "entered",
    Held => "held",
    OnDevice => "on_device",
});

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The fields of a credential Rite cannot present yet, as a definition writes
/// them: `'grants: admin' and 'source: held'`. Empty when Rite can.
#[must_use]
pub fn unsupported_fields(
    grants: Option<CredentialGrant>,
    source: Option<CredentialSource>,
) -> String {
    let grants = grants.map(|grants| format!("'grants: {grants}'"));
    let source = source.map(|source| format!("'source: {source}'"));
    match (grants, source) {
        (Some(grants), Some(source)) => format!("{grants} and {source}"),
        (Some(field), None) | (None, Some(field)) => field,
        (None, None) => String::new(),
    }
}
