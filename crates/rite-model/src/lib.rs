//! Core domain model and IR for the Rite ceremony DSL.
//!
//! `rite-model` defines the Intermediate Representation (IR) — the fully resolved
//! ceremony data consumed by the executor. The YAML schema (parser input) lives in
//! `rite-resolver`; this crate contains only the runtime-facing types.
//!
//! # Module structure
//!
//! - [`ir`] — IR types: [`Ceremony`], [`Step`], [`Role`], etc. and typed ID newtypes
//! - [`expression`] — Expression parsing for `${artifact.name | sha256 | hex}` syntax
//! - `types` (private) — Shared semantic enums: [`ActionType`], [`DutyType`], etc.
//!
//! # `BackendConfig`
//!
//! Re-exported from `rite-sdk` for convenience. The canonical definition lives there.

#![warn(missing_docs)]

pub mod expression;
pub mod ir;
mod material;
mod types;

pub use rite_sdk::BackendConfig;

pub use material::MaterialSource;

pub use types::{
    ActionType, DutyType, Metadata, OutputType, ParameterType, derive_role_name, role_type,
};

pub use ir::{
    Act, ActId, ArtifactId, ArtifactRef, Ceremony, Material, MaterialId, MaterialKind, Output,
    OutputId, ParamId, Parameter, PostCeremonyDuty, Role, RoleId, Section, SectionId, Step,
    StepId, StepInputs, SymbolTable,
};
