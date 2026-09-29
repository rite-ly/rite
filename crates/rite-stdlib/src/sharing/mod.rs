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
