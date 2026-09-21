//! Secret sharing: split a secret across custodians and put it back together.
//!
//! The arithmetic is in [`gf256`]. The rest is the ceremony side: which
//! backend supplies the randomness, what the transcript records, and the
//! refusal to let a share become anything but a `reads:` input.

mod combine_shares;
pub mod gf256;
mod split_secret;
pub mod wire;

pub use combine_shares::CombineSharesAction;
pub use split_secret::SplitSecretAction;
