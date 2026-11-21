//! Secret sharing: split a secret across custodians and put it back together.
//!
//! The arithmetic is in [`gf256`]; a share's layout as bytes is [`wire`],
//! and as a string a person writes down, [`paper`]. The rest is the
//! ceremony side: which backend supplies the randomness, what the
//! transcript records, and the refusal to let a share become anything but a
//! `reads:` input.

mod combine_shares;
mod enter_share;
pub mod gf256;
pub mod paper;
mod reveal;
mod split_secret;
pub mod wire;

pub use combine_shares::CombineSharesAction;
pub use enter_share::EnterShareAction;
pub use reveal::RevealAction;
pub use split_secret::SplitSecretAction;

use rite_model::{ArtifactRef, SharingScheme};
use rite_runtime::{ArtifactValue, HandlerContext, resolve_artifact_bytes, resolve_share};
use zeroize::Zeroizing;

/// What an input that takes a share or any file's bytes names.
pub(crate) enum ShareOrBytes<'a> {
    /// One share of a set, and the scheme the set was made under.
    Share(SharingScheme, &'a rite_runtime::Share),
    /// Any other artifact's bytes.
    Bytes(&'a [u8]),
}

impl<'a> ShareOrBytes<'a> {
    /// Read `input`, borrowed: a share if it names one, its bytes otherwise.
    ///
    /// # Errors
    ///
    /// Says why the reference names neither.
    pub(crate) fn read(ctx: &'a HandlerContext, input: &ArtifactRef) -> Result<Self, String> {
        let id = input.artifact_id();
        if let Some(ArtifactValue::Shares(_) | ArtifactValue::Share { .. }) = ctx.artifacts.get(&id)
        {
            resolve_share(ctx.artifacts, &id, input.property())
                .map(|(scheme, share)| Self::Share(scheme, share))
                .map_err(|e| e.to_string())
        } else {
            resolve_artifact_bytes(ctx.artifacts, &id, input.property())
                .map(Self::Bytes)
                .map_err(|e| e.to_string())
        }
    }

    /// The share as the arithmetic takes it, its own copy wiped with it: a
    /// held share copied out of its set, which the store keeps, or bytes
    /// read in the share layout, whose version byte names the scheme.
    ///
    /// # Errors
    ///
    /// Says why the parts or the bytes are not a share.
    pub(crate) fn into_share(self) -> Result<wire::Decoded, String> {
        match self {
            Self::Share(scheme, held) => Ok(wire::Decoded {
                scheme,
                share: own_copy(held)?,
            }),
            Self::Bytes(bytes) => {
                wire::decode(bytes).map_err(|e| format!("these bytes are not a share: {e}"))
            }
        }
    }
}

/// A held share's own copy for the arithmetic or a layout, wiped with it.
fn own_copy(held: &rite_runtime::Share) -> Result<gf256::Share, String> {
    gf256::Share::new(held.threshold(), held.index(), held.y().to_vec())
        .map_err(|e| format!("not a share: {e}"))
}

/// One share of a set as the bytes of its scheme's layout, wiped when
/// dropped: what `reveal` shows and `encrypt_data` seals.
///
/// # Errors
///
/// Says why the parts are not a share.
pub(crate) fn share_bytes(
    scheme: SharingScheme,
    share: &rite_runtime::Share,
) -> Result<Zeroizing<Vec<u8>>, String> {
    Ok(Zeroizing::new(wire::encode(scheme, &own_copy(share)?)))
}
