//! Error types for the ceremony resolver.

use crate::diagnostic::ReferenceContext;
use rite_model::expression::{ExprError, RefType};
use rite_model::{
    ActId, ActionType, ArtifactId, MaterialId, OutputId, ParamId, ParameterType, RoleId, SectionId,
    StepId,
};
use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during ceremony resolution.
#[derive(Debug, Error, Clone)]
pub enum ResolveError {
    /// Schema version is not supported by this resolver.
    #[error("unsupported schema version \"{version}\"; this resolver supports: {supported}")]
    UnsupportedVersion {
        /// The version string found in the ceremony file.
        version: String,
        /// Comma-separated list of supported versions.
        supported: String,
    },

    /// Failed to parse YAML.
    #[error("Failed to parse YAML: {message}")]
    Yaml {
        /// Error message.
        message: String,
        /// Source location `(line, column)` if known.
        location: Option<(usize, usize)>,
    },

    /// Failed to read a file.
    #[error("Failed to read file '{path}': {message}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Error message.
        message: String,
    },

    /// Duplicate role ID.
    #[error("Duplicate role ID: '{0}'")]
    DuplicateRole(RoleId),

    /// Duplicate step ID.
    #[error("Duplicate step ID: '{0}'")]
    DuplicateStep(StepId),

    /// Duplicate section ID.
    #[error("Duplicate section ID: '{0}'")]
    DuplicateSection(SectionId),

    /// Duplicate act ID.
    #[error("Duplicate act ID: '{0}'")]
    DuplicateAct(ActId),

    /// Duplicate parameter ID.
    #[error("Duplicate parameter ID: '{0}'")]
    DuplicateParam(ParamId),

    /// Duplicate material ID.
    #[error("Duplicate material ID: '{0}'")]
    DuplicateMaterial(MaterialId),

    /// Duplicate output ID.
    #[error("Duplicate output ID: '{0}'")]
    DuplicateOutput(OutputId),

    /// Unknown role reference.
    #[error("Unknown role '{role}' in '{context}'")]
    UnknownRole {
        /// The unknown role ID.
        role: RoleId,
        /// Where the reference appears.
        context: ReferenceContext,
    },

    /// Step references an unknown section.
    #[error("Step '{step}' references unknown section '{section}'")]
    UnknownSection {
        /// The unknown section ID.
        section: SectionId,
        /// The step that has the reference.
        step: StepId,
    },

    /// Section references an unknown act.
    #[error("Section '{section}' references unknown act '{act}'")]
    UnknownAct {
        /// The unknown act ID.
        act: ActId,
        /// The section that has the reference.
        section: SectionId,
    },

    /// Reference to an unknown parameter.
    #[error("Reference to unknown parameter '{param}' in '{context}'")]
    UnknownParam {
        /// The unknown parameter ID.
        param: ParamId,
        /// Where the reference appears.
        context: ReferenceContext,
    },

    /// Reference to an unknown material.
    #[error("Reference to unknown material '{material}' in '{context}'")]
    UnknownMaterial {
        /// The unknown material ID.
        material: MaterialId,
        /// Where the reference appears.
        context: ReferenceContext,
    },

    /// Step references an unknown artifact.
    #[error("Step '{step}' references unknown artifact '{artifact}'")]
    UnknownArtifact {
        /// The unknown artifact ID.
        artifact: ArtifactId,
        /// The step that has the reference.
        step: StepId,
    },

    /// Required parameter is missing and has no default.
    #[error("Required parameter '{0}' is missing and has no default")]
    RequiredParamMissing(ParamId),

    /// Required material is missing.
    #[error("Required material '{0}' is missing")]
    RequiredMaterialMissing(MaterialId),

    /// Parameter value has wrong type.
    #[error("Parameter '{param}' has wrong type: expected {expected:?}, got {got}")]
    ParamTypeMismatch {
        /// The parameter ID.
        param: ParamId,
        /// Expected type.
        expected: ParameterType,
        /// Actual type received.
        got: String,
    },

    /// Parameter has invalid date format.
    #[error("Parameter '{param}' has invalid date format: '{value}' (expected YYYY-MM-DD)")]
    InvalidDateFormat {
        /// The parameter ID.
        param: ParamId,
        /// The invalid value.
        value: String,
    },

    /// Material file path not found.
    #[error("Material '{material}' file not found: {path}")]
    MaterialPathNotFound {
        /// The material ID.
        material: MaterialId,
        /// The path that was not found.
        path: PathBuf,
    },

    /// Material input source type doesn't match material type.
    #[error("Material '{material}': input source type doesn't match material type")]
    MaterialSourceMismatch {
        /// The material ID.
        material: MaterialId,
    },

    /// Step references a backend not declared in the ceremony.
    #[error("Step '{step}' references undeclared backend '{backend}'")]
    UndeclaredBackend {
        /// The step ID.
        step: StepId,
        /// The backend name that is not declared.
        backend: String,
    },

    /// Step uses an action that requires a backend but has no `backend:` field.
    #[error("Step '{step}': action '{action}' requires a backend; add a 'backend:' field")]
    MissingRequiredBackend {
        /// The step ID.
        step: StepId,
        /// The action that requires a backend.
        action: ActionType,
    },

    /// Step `with:` block is missing a required field for its action.
    #[error("Step '{step}': action '{action}' requires 'with.{field}'")]
    MissingWithField {
        /// The step ID.
        step: StepId,
        /// The action whose parameter is missing.
        action: ActionType,
        /// The missing `with:` field name.
        field: &'static str,
    },

    /// Step `retry: { attempts: N }` has a zero attempt budget, which can never
    /// run the step. Use `retry: never` to forbid retries instead.
    #[error(
        "Step '{step}': retry attempts must be at least 1 (use 'retry: never' to forbid retries)"
    )]
    InvalidRetryAttempts {
        /// The step ID.
        step: StepId,
    },

    /// Duty references an unknown role.
    #[error("Duty '{duty_id}' references unknown role '{role}'")]
    DutyUnknownRole {
        /// The unknown role ID.
        role: RoleId,
        /// The duty ID.
        duty_id: String,
    },

    /// Custom duty is missing a description.
    #[error("Duty '{duty_id}' with type 'custom' requires a description")]
    CustomDutyMissingDescription {
        /// The duty ID.
        duty_id: String,
    },

    /// Artifact is used before it is produced.
    #[error(
        "Artifact '{artifact}' is used in step '{used_in}' before it is produced in step '{produced_in}'"
    )]
    ArtifactUsedBeforeProduced {
        /// The artifact ID.
        artifact: ArtifactId,
        /// The step that uses the artifact.
        used_in: StepId,
        /// The step that produces the artifact.
        produced_in: StepId,
    },

    /// Artifact is used but never produced.
    #[error("Artifact '{artifact}' is used in step '{step}' but is never produced")]
    ArtifactNeverProduced {
        /// The artifact ID.
        artifact: ArtifactId,
        /// The step that tries to use it.
        step: StepId,
    },

    /// Invalid reference syntax in a field.
    #[error("Invalid reference '{value}' in '{context}' field '{field}': {reason}")]
    InvalidReferenceSyntax {
        /// Where the reference appears.
        context: ReferenceContext,
        /// The field name.
        field: String,
        /// The invalid value, used to look up the expression span.
        value: String,
        /// Why the value is not a usable reference.
        reason: ExprError,
    },

    /// A field that names one thing holds an expression that computes a value.
    #[error("Expected a single reference in '{context}' field '{field}', not '{value}'")]
    ExpectedReference {
        /// Where the value appears.
        context: ReferenceContext,
        /// The field name.
        field: String,
        /// The value, used to look up the expression span.
        value: String,
    },

    /// A named entry under `reads:` holds a value of the wrong YAML type.
    #[error(
        "Expected a string holding an artifact reference in '{context}' field '{field}', \
         found {found}"
    )]
    ReadsInputNotAString {
        /// Where the value appears.
        context: ReferenceContext,
        /// The field name.
        field: String,
        /// The YAML type found instead.
        found: &'static str,
    },

    /// A `reads:` value is neither a reference nor a map of named inputs.
    #[error(
        "Expected an artifact reference or a map of named inputs in '{context}' field \
         'reads', found {found}"
    )]
    ReadsNotAReferenceOrMap {
        /// Where the value appears.
        context: ReferenceContext,
        /// The YAML type found instead.
        found: &'static str,
    },

    /// An artifact id (from a step's `creates:`) is not a safe filename.
    ///
    /// Artifact ids become output filenames, so they must be plain names with no
    /// path separators or `..` traversal.
    #[error("Artifact id '{id}' is not a valid name: {reason}")]
    UnsafeArtifactId {
        /// The offending artifact id.
        id: ArtifactId,
        /// Why it was rejected.
        reason: String,
    },

    /// An output id (an `output:` key) is not a safe filename.
    ///
    /// Output ids become filenames in the run directory, so they must be plain
    /// names with no path separators or `..` traversal.
    #[error("Output id '{id}' is not a valid name: {reason}")]
    UnsafeOutputId {
        /// The offending output id.
        id: OutputId,
        /// Why it was rejected.
        reason: String,
    },

    /// A material's `path:` escapes the ceremony directory.
    ///
    /// Paths embedded in a ceremony file are confined to the directory that
    /// contains the ceremony; absolute paths or `..` traversal are rejected.
    /// Provide out-of-tree files via `--material name=@/path` instead.
    #[error("Material '{material}' path '{path}' is not allowed: {reason}")]
    UnsafeMaterialPath {
        /// The material whose path was rejected.
        material: MaterialId,
        /// The offending path.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },

    /// Reference type mismatch in a field.
    #[error(
        "Reference type mismatch in '{context}' field '{field}': expected {expected}, got {actual}"
    )]
    ReferenceTypeMismatch {
        /// Where the reference appears.
        context: ReferenceContext,
        /// The field name.
        field: String,
        /// The expected reference type.
        expected: RefType,
        /// The actual reference type.
        actual: RefType,
        /// The raw reference string, used to look up the expression span.
        value: String,
    },
}

/// Warnings that don't prevent resolution but may indicate issues.
#[derive(Debug, Clone)]
pub enum ResolveWarning {
    /// Parameter is declared but never referenced.
    UnusedParam(ParamId),
    /// Material is declared but never referenced.
    UnusedMaterial(MaterialId),
    /// Output is declared but no artifact produces it.
    UnusedOutput(OutputId),
    /// Artifact is produced but not written to any output.
    ArtifactNotOutput(ArtifactId),
    /// Inputs reference a role ID not declared in the ceremony.
    UnknownRoleInInputs {
        /// The unknown role ID.
        role: RoleId,
    },
    /// Step has a `backend:` field but its action does not use a backend.
    UnusedBackend {
        /// The step ID.
        step: StepId,
    },
}

impl std::fmt::Display for ResolveWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveWarning::UnusedParam(id) => {
                write!(f, "parameter '{id}' is declared but never used")
            }
            ResolveWarning::UnusedMaterial(id) => {
                write!(f, "material '{id}' is declared but never used")
            }
            ResolveWarning::UnusedOutput(id) => {
                write!(f, "output '{id}' is declared but no artifact produces it")
            }
            ResolveWarning::ArtifactNotOutput(id) => {
                write!(
                    f,
                    "artifact '{id}' is produced but not written to any output"
                )
            }
            ResolveWarning::UnknownRoleInInputs { role } => write!(
                f,
                "inputs reference role '{role}' which is not declared in the ceremony"
            ),
            ResolveWarning::UnusedBackend { step } => write!(
                f,
                "step '{step}' has a 'backend:' field but its action does not use a backend"
            ),
        }
    }
}

/// Result of resolution, containing either a value or accumulated errors.
#[derive(Debug)]
pub struct ResolveResult<T> {
    /// The resolved value, if successful.
    pub value: Option<T>,
    /// All errors encountered during resolution.
    pub errors: Vec<ResolveError>,
    /// Warnings that don't prevent success.
    pub warnings: Vec<ResolveWarning>,
}

impl<T> ResolveResult<T> {
    /// Create a successful result.
    pub fn ok(value: T) -> Self {
        Self {
            value: Some(value),
            errors: vec![],
            warnings: vec![],
        }
    }

    /// Create a failed result with a single error.
    pub fn err(error: ResolveError) -> Self {
        Self {
            value: None,
            errors: vec![error],
            warnings: vec![],
        }
    }

    /// Create a failed result with multiple errors.
    pub fn errors(errors: Vec<ResolveError>) -> Self {
        Self {
            value: None,
            errors,
            warnings: vec![],
        }
    }

    /// Check if resolution succeeded (no errors).
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }

    /// Check if resolution failed.
    pub fn is_err(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Convert to a standard `Result`.
    pub fn into_result(self) -> Result<T, Vec<ResolveError>> {
        match (self.errors.is_empty(), self.value) {
            (true, Some(v)) => Ok(v),
            (_, _) => Err(self.errors),
        }
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: ResolveWarning) {
        self.warnings.push(warning);
    }

    /// Map the success value.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> ResolveResult<U> {
        ResolveResult {
            value: self.value.map(f),
            errors: self.errors,
            warnings: self.warnings,
        }
    }
}

impl<T> From<Result<T, ResolveError>> for ResolveResult<T> {
    fn from(result: Result<T, ResolveError>) -> Self {
        match result {
            Ok(value) => Self::ok(value),
            Err(error) => Self::err(error),
        }
    }
}
