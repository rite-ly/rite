//! Diagnostic types for ceremony validation with source location tracking.

use crate::error::{ResolveError, ResolveWarning};
use rite_model::{ActId, MaterialId, ParamId, RoleId, SectionId, StepId};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// A source location within a YAML file (1-indexed line and column).
///
/// `length` is the byte count of the token when known; `None` signals a point location
/// that editors may extend to a word boundary.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// Line number (1-indexed).
    pub line: usize,
    /// Column number (1-indexed).
    pub column: usize,
    /// Byte length of the token, when known.
    pub length: Option<usize>,
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

/// The container (step or section) that owns a reference site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceContext {
    /// A reference inside a step, identified by its step ID.
    Step(StepId),
    /// A reference at section level, identified by the section ID.
    Section(SectionId),
}

impl fmt::Display for ReferenceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceContext::Step(id) => write!(f, "{id}"),
            ReferenceContext::Section(id) => write!(f, "section:{id}"),
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
/// `span.length` is always set for reference entries; it covers the token byte length
/// used for cursor containment and diagnostic range end: `[span.column, span.column + span.length)`.
#[derive(Debug, Clone)]
pub struct ReferenceEntry {
    /// Source location and token length of the reference.
    pub span: Span,
    /// What this reference points to.
    pub target: ReferenceTarget,
    /// The owning step or section.
    pub context: ReferenceContext,
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
            let len = e.span.length.unwrap_or(0);
            if e.span.line == line && column >= e.span.column && column < e.span.column + len {
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
            ResolveError::Yaml { location, .. } => location.map(|(line, col)| Span {
                line,
                column: col,
                length: None,
            }),
            ResolveError::Io { .. }
            | ResolveError::UnsupportedVersion { .. }
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
            | ResolveError::MissingRequiredBackend { step, .. }
            | ResolveError::MissingWithField { step, .. }
            | ResolveError::ArtifactNeverProduced { step, .. } => self.steps.get(step).copied(),
            ResolveError::UndeclaredBackend { step, backend } => self
                .span_for_reference(
                    &ReferenceTarget::Backend(backend.clone()),
                    &ReferenceContext::Step(step.clone()),
                )
                .or_else(|| self.steps.get(step).copied()),
            ResolveError::UnknownRole { role, context } => self
                .span_for_reference(&ReferenceTarget::Role(role.clone()), context)
                .or_else(|| self.span_for_context(context)),
            ResolveError::UnknownAct { section, act } => self
                .span_for_reference(
                    &ReferenceTarget::Act(act.clone()),
                    &ReferenceContext::Section(section.clone()),
                )
                .or_else(|| self.sections.get(section).copied()),
            ResolveError::InvalidReferenceSyntax { context, .. }
            | ResolveError::ReferenceTypeMismatch { context, .. } => self.span_for_context(context),
            ResolveError::ArtifactUsedBeforeProduced { used_in, .. } => {
                self.steps.get(used_in).copied()
            }
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

    /// Look up the span of a reference value by target and owning context.
    ///
    /// Returns a `Span` with `length` set from the collected token width, so callers
    /// get a proper range rather than a point location.
    fn span_for_reference(
        &self,
        target: &ReferenceTarget,
        context: &ReferenceContext,
    ) -> Option<Span> {
        self.references
            .iter()
            .find(|e| e.target == *target && e.context == *context)
            .map(|e| e.span)
    }

    /// Look up a declaration span for a context (step or section).
    fn span_for_context(&self, context: &ReferenceContext) -> Option<Span> {
        match context {
            ReferenceContext::Step(id) => self.steps.get(id).copied(),
            ReferenceContext::Section(id) => self.sections.get(id).copied(),
        }
    }

    fn span_for_warning(&self, w: &ResolveWarning) -> Option<Span> {
        match w {
            ResolveWarning::UnusedParam(id) => self.params.get(id).copied(),
            ResolveWarning::UnusedMaterial(id) => self.materials.get(id).copied(),
            ResolveWarning::UnusedOutput(_) | ResolveWarning::ArtifactNotOutput(_) => None,
            ResolveWarning::UnknownRoleInInputs { role } => self.roles.get(role).copied(),
            ResolveWarning::UnusedBackend { step } => self.steps.get(step).copied(),
        }
    }
}
