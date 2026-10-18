//! The names a ceremony writes for the algorithm enums.

/// Give an enum its names from one list: `ALL`, `as_str`, `Display`,
/// `FromStr`, the `String` conversions serde goes through, and, with the
/// `schemars` feature, a JSON Schema `enum` of the names.
///
/// Expanded in `types`, where `ParseError` is. `as_str` matches every
/// variant, so a variant left out of the list fails to compile, and `ALL` is
/// complete because it is built from the same list.
macro_rules! names {
    ($ty:ident { $($variant:ident => $name:literal,)+ }) => {
        impl $ty {
            /// Every value, in declaration order.
            pub const ALL: &'static [$ty] = &[$($ty::$variant),+];

            /// The name a ceremony writes and a transcript records.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $($ty::$variant => $name,)+
                }
            }
        }

        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl ::std::str::FromStr for $ty {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::ALL
                    .iter()
                    .copied()
                    .find(|value| value.as_str() == s)
                    .ok_or_else(|| ParseError(s.to_owned()))
            }
        }

        impl From<$ty> for String {
            fn from(value: $ty) -> String {
                value.as_str().to_string()
            }
        }

        impl TryFrom<String> for $ty {
            type Error = ParseError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        #[cfg(feature = "schemars")]
        impl schemars::JsonSchema for $ty {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                stringify!($ty).into()
            }

            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    "enum": Self::ALL.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
                })
            }
        }
    };
}

pub(crate) use names;
