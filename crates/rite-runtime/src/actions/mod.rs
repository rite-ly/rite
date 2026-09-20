//! Action support types used by handlers and the executor.
//!
//! The [`Action`](crate::Action) trait itself lives in [`crate::runner`];
//! this module hosts the supporting data types ([`ArtifactValue`]).

mod types;

pub use types::{ArtifactValue, Share, ShareSet};
