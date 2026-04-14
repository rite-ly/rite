//! Type-safe identifier newtypes for the ceremony IR.
//!
//! These wrapper types prevent accidentally mixing up different kinds of IDs
//! (e.g., passing a `RoleId` where a `StepId` is expected).
//!
//! Each ID wraps a `String` for easy debugging and display.

use std::fmt;
use std::hash::Hash;

macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Eq, PartialEq, Hash, Debug)]
        pub struct $name(String);

        impl $name {
            /// Create a new ID from any string-like value.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }

            /// Get the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the underlying string.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

define_id!(
    /// Unique identifier for a role in the ceremony.
    RoleId
);

define_id!(
    /// Unique identifier for a step in the ceremony.
    StepId
);

define_id!(
    /// Unique identifier for a section in the ceremony.
    SectionId
);

define_id!(
    /// Unique identifier for an act in the ceremony.
    ActId
);

define_id!(
    /// Unique identifier for a parameter in the ceremony.
    ParamId
);

define_id!(
    /// Unique identifier for a material in the ceremony.
    MaterialId
);

define_id!(
    /// Unique identifier for an artifact produced during the ceremony.
    ///
    /// Artifacts are runtime values produced by step actions and stored in execution state.
    /// They can be referenced by subsequent steps (e.g., `${artifact.keypair.private}`)
    /// or declared as outputs for file/stdout destinations.
    ///
    /// Not all artifacts are outputs — intermediate artifacts may be produced and consumed
    /// without ever being written to disk.
    ///
    /// See also: [`OutputId`] for output declarations.
    ArtifactId
);

define_id!(
    /// Unique identifier for an output declaration in the ceremony.
    ///
    /// Outputs are ceremony declarations that specify the type and format of artifacts
    /// produced during the ceremony. They are resolved at ceremony load time.
    ///
    /// # Relationship to `ArtifactId`
    ///
    /// `OutputId` and `ArtifactId` are **separate types** that **match by name**:
    ///
    /// ```yaml
    /// # Ceremony declares outputs (OutputId)
    /// output:
    ///   public_key:           # OutputId("public_key")
    ///     type: public_key
    ///
    /// # Steps produce artifacts (ArtifactId)
    /// steps:
    ///   - id: export
    ///     produces: ${artifact.public_key}  # ArtifactId("public_key")
    /// ```
    ///
    /// At runtime, the executor looks up: "for this `ArtifactId`, is there a declared `OutputId`?"
    ///
    /// They remain separate types because:
    /// - **Different lifespans**: `OutputId` exists from resolution, `ArtifactId` from execution
    /// - **Different scopes**: Not all artifacts are outputs (intermediate values)
    /// - **Type safety**: Prevents mixing declarations vs runtime values
    ///
    /// See also: [`ArtifactId`] for runtime artifacts.
    OutputId
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn ids_are_type_safe() {
        let role_id = RoleId::new("witness");
        let step_id = StepId::new("witness"); // Same string, different type.

        // These are different types, can't be compared directly.
        assert_eq!(role_id.as_str(), step_id.as_str());
    }

    #[test]
    fn ids_work_as_hash_keys() {
        let mut map: HashMap<RoleId, String> = HashMap::new();
        map.insert(RoleId::new("admin"), "Alice".to_string());
        map.insert(RoleId::new("witness"), "Bob".to_string());

        assert_eq!(map.get(&RoleId::new("admin")), Some(&"Alice".to_string()));
    }

    #[test]
    fn ids_display_nicely() {
        let id = RoleId::new("ceremony_admin");
        assert_eq!(format!("{id}"), "ceremony_admin");
        assert_eq!(format!("{id:?}"), r#"RoleId("ceremony_admin")"#);
    }
}
