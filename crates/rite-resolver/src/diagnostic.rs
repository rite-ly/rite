//! Diagnostic types for ceremony validation with source location tracking.

use crate::error::{ResolveError, ResolveWarning};
use rite_model::{ActId, MaterialId, ParamId, RoleId, SectionId, StepId};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// A source location within a YAML file (1-indexed line and column).
#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// Line number (1-indexed).
    pub line: usize,
    /// Column number (1-indexed).
    pub column: usize,
}

/// Severity of a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Fatal error that prevents resolution.
    Error,
    /// Non-fatal issue that may indicate a problem.
    Warning,
}

/// A diagnostic message with optional source location.
#[derive(Debug)]
pub struct Diagnostic {
    /// The file this diagnostic refers to (if any).
    pub path: Option<PathBuf>,
    /// The source location within the file (if known).
    pub span: Option<Span>,
    /// Severity of this diagnostic.
    pub severity: Severity,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        match (&self.path, &self.span) {
            (Some(path), Some(span)) => {
                write!(
                    f,
                    "{}:{}:{}: {}: {}",
                    path.display(),
                    span.line,
                    span.column,
                    sev,
                    self.message
                )
            }
            (Some(path), None) => {
                write!(f, "{}: {}: {}", path.display(), sev, self.message)
            }
            (None, _) => {
                write!(f, "{}: {}", sev, self.message)
            }
        }
    }
}

/// The kind of declaration a reference points to.
#[derive(Debug, Clone, PartialEq)]
pub enum ReferenceTarget {
    /// A section declaration.
    Section(SectionId),
    /// A role declaration.
    Role(RoleId),
    /// An act declaration.
    Act(ActId),
    /// A parameter declaration.
    Param(ParamId),
    /// A material declaration.
    Material(MaterialId),
    /// A backend declaration.
    Backend(String),
}

/// A single reference site collected during span walking.
///
/// `span` is the 1-indexed position of the value scalar in the source file.
/// `value_len` is the byte length of the raw value string, used for cursor
/// containment: the reference covers columns `[span.column, span.column + value_len)`.
#[derive(Debug, Clone)]
pub struct ReferenceEntry {
    /// Source location of the reference.
    pub span: Span,
    /// Byte length of the value string.
    pub value_len: usize,
    /// What this reference points to.
    pub target: ReferenceTarget,
}

/// Maps ceremony element IDs to their source positions for diagnostic enrichment.
#[derive(Default)]
pub struct SpanMap {
    /// Step declaration spans.
    pub steps: HashMap<StepId, Span>,
    /// Role declaration spans.
    pub roles: HashMap<RoleId, Span>,
    /// Section declaration spans.
    pub sections: HashMap<SectionId, Span>,
    /// Act declaration spans.
    pub acts: HashMap<ActId, Span>,
    /// Parameter declaration spans.
    pub params: HashMap<ParamId, Span>,
    /// Material declaration spans.
    pub materials: HashMap<MaterialId, Span>,
    /// Declaration spans for `backends:` map keys.
    pub backends: HashMap<String, Span>,
    /// Reference sites collected during parsing: value-scalar span → declaration target.
    /// Used by go-to-definition to map a cursor position to a declaration span.
    pub references: Vec<ReferenceEntry>,
}

impl SpanMap {
    /// Find the reference target whose value scalar contains the given cursor position.
    ///
    /// `line` and `column` are 1-indexed, matching the `Span` convention.
    /// A value scalar at column `c` with length `l` covers `[c, c + l)`.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn find_target_at(&self, line: usize, column: usize) -> Option<&ReferenceTarget> {
        self.references.iter().find_map(|e| {
            if e.span.line == line
                && column >= e.span.column
                && column < e.span.column + e.value_len
            {
                Some(&e.target)
            } else {
                None
            }
        })
    }

    /// Convert a `ResolveError` to a `Diagnostic`, looking up the best available span.
    pub fn to_diagnostic(&self, path: Option<&Path>, err: &ResolveError) -> Diagnostic {
        let span = self.span_for_error(err);
        Diagnostic {
            path: path.map(Path::to_owned),
            span,
            severity: Severity::Error,
            message: err.to_string(),
        }
    }

    /// Convert a `ResolveWarning` to a `Diagnostic`.
    pub fn warning_to_diagnostic(&self, path: Option<&Path>, w: &ResolveWarning) -> Diagnostic {
        let span = self.span_for_warning(w);
        Diagnostic {
            path: path.map(Path::to_owned),
            span,
            severity: Severity::Warning,
            message: w.to_string(),
        }
    }

    fn span_for_error(&self, err: &ResolveError) -> Option<Span> {
        match err {
            ResolveError::Yaml { location, .. } => {
                location.map(|(line, col)| Span { line, column: col })
            }
            ResolveError::Io { .. }
            | ResolveError::DuplicateOutput(_)
            | ResolveError::DutyUnknownRole { .. }
            | ResolveError::CustomDutyMissingDescription { .. } => None,
            ResolveError::DuplicateRole(id) => self.roles.get(id).copied(),
            ResolveError::DuplicateStep(id) => self.steps.get(id).copied(),
            ResolveError::DuplicateSection(id) => self.sections.get(id).copied(),
            ResolveError::DuplicateAct(id) => self.acts.get(id).copied(),
            ResolveError::DuplicateParam(id) => self.params.get(id).copied(),
            ResolveError::DuplicateMaterial(id) => self.materials.get(id).copied(),
            ResolveError::UnknownSection { step, .. }
            | ResolveError::UnknownArtifact { step, .. }
            | ResolveError::MachineInfoWithBackend { step, .. }
            | ResolveError::ArtifactNeverProduced { step, .. } => self.steps.get(step).copied(),
            ResolveError::UnknownRole { context, .. }
            | ResolveError::InvalidReferenceSyntax { context, .. }
            | ResolveError::ReferenceTypeMismatch { context, .. } => self.span_for_context(context),
            ResolveError::ArtifactUsedBeforeProduced { used_in, .. } => {
                self.steps.get(used_in).copied()
            }
            ResolveError::UnknownAct { section, .. } => self.sections.get(section).copied(),
            ResolveError::UnknownParam { param, .. }
            | ResolveError::RequiredParamMissing(param)
            | ResolveError::ParamTypeMismatch { param, .. }
            | ResolveError::InvalidDateFormat { param, .. } => self.params.get(param).copied(),
            ResolveError::UnknownMaterial { material, .. }
            | ResolveError::RequiredMaterialMissing(material)
            | ResolveError::MaterialPathNotFound { material, .. }
            | ResolveError::MaterialSourceMismatch { material, .. } => {
                self.materials.get(material).copied()
            }
        }
    }

    /// Look up a span for a free-form context string (step ID or `"section:<id>"`).
    fn span_for_context(&self, context: &str) -> Option<Span> {
        // Try as a step ID first (most common case).
        let step_id = StepId::new(context);
        if let Some(span) = self.steps.get(&step_id) {
            return Some(*span);
        }
        // Try as "section:<id>" prefix.
        if let Some(section_name) = context.strip_prefix("section:") {
            let section_id = SectionId::new(section_name);
            return self.sections.get(&section_id).copied();
        }
        None
    }

    fn span_for_warning(&self, w: &ResolveWarning) -> Option<Span> {
        match w {
            ResolveWarning::UnusedParam(id) => self.params.get(id).copied(),
            ResolveWarning::UnusedMaterial(id) => self.materials.get(id).copied(),
            ResolveWarning::UnusedOutput(_) | ResolveWarning::ArtifactNotOutput(_) => None,
            ResolveWarning::UnknownRoleInInputs { role } => self.roles.get(role).copied(),
        }
    }
}
