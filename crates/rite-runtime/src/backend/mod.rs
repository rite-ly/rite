//! Backend registry for ceremony execution.
//!
//! Backend trait definitions live in `rite-sdk`. This module provides only
//! the registry infrastructure for declaring, lazily initializing, and
//! accessing backends during execution.

pub mod registry;
pub use registry::{BackendFactory, BackendRegistry};
