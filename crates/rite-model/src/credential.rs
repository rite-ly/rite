//! What a ceremony declares about a credential a backend has: what it is
//! used for, and where its value comes from when a step needs it.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Provider;
use crate::ir::CredentialId;

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
//
// `C` is how a protected source names the credential that releases it: the
// `${credential.<id>}` a definition writes, then the credential's ID once
// resolved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource<C = CredentialId> {
    /// The vendor's well-known value.
    FactoryDefault,
    /// Typed, masked, by the person in the step's role.
    Entered,
    /// Kept outside the device; a step gives it from an artifact.
    Held,
    /// Presented to the device directly, on a PIN pad or a PED. Rite never
    /// sees it.
    OnDevice,
    /// Stored on the device and released by another credential of the same
    /// backend, a user credential: a `YubiKey`'s PIN-protected management key.
    ProtectedBy(
        /// The user credential that releases it, as `${credential.<id>}`.
        C,
    ),
}

impl<C> CredentialSource<C> {
    /// The name a definition writes for this kind of source.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialSource::FactoryDefault => "factory_default",
            CredentialSource::Entered => "entered",
            CredentialSource::Held => "held",
            CredentialSource::OnDevice => "on_device",
            CredentialSource::ProtectedBy(_) => "protected_by",
        }
    }

    /// The same source, with the releasing credential named another way.
    pub fn map<D>(self, f: impl FnOnce(C) -> D) -> CredentialSource<D> {
        match self {
            CredentialSource::FactoryDefault => CredentialSource::FactoryDefault,
            CredentialSource::Entered => CredentialSource::Entered,
            CredentialSource::Held => CredentialSource::Held,
            CredentialSource::OnDevice => CredentialSource::OnDevice,
            CredentialSource::ProtectedBy(by) => CredentialSource::ProtectedBy(f(by)),
        }
    }
}

/// `entered`, or `protected_by card_pin`.
impl<C: fmt::Display> fmt::Display for CredentialSource<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialSource::ProtectedBy(by) => write!(f, "protected_by {by}"),
            other => f.write_str(other.as_str()),
        }
    }
}

/// Whether Rite can authenticate, on a backend of `provider`, with a
/// credential that grants `grants` and takes its value from `source`: a
/// user credential its holder types on a PIV card, and on a `YubiKey` also
/// its management key, from the factory default, held, or protected by a
/// user credential. The mock answers what a `YubiKey` does, so a rehearsal
/// walks it.
#[must_use]
pub fn supports_credential<C>(
    provider: Provider,
    grants: CredentialGrant,
    source: &CredentialSource<C>,
) -> bool {
    let user = matches!(
        (grants, source),
        (CredentialGrant::User, CredentialSource::Entered)
    );
    let admin = grants == CredentialGrant::Admin
        && matches!(
            source,
            CredentialSource::FactoryDefault
                | CredentialSource::Held
                | CredentialSource::ProtectedBy(_)
        );
    match provider {
        Provider::Piv => user,
        Provider::Yubikey | Provider::Mock => user || admin,
        Provider::Openssl => false,
    }
}

/// Whether a backend of `provider` generates a key only in an admin
/// session: a PIV card.
#[must_use]
pub fn generates_in_admin_session(provider: Provider) -> bool {
    matches!(provider, Provider::Piv | Provider::Yubikey)
}

/// Whether Rite can open an admin session on a backend of `provider`.
#[must_use]
pub fn opens_admin_session(provider: Provider) -> bool {
    supports_credential(
        provider,
        CredentialGrant::Admin,
        &CredentialSource::<CredentialId>::FactoryDefault,
    )
}
