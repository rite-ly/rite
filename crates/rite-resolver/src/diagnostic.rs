//! Diagnostic types for ceremony validation with source location tracking.

use crate::error::{ResolveError, ResolveWarning};
use rite_model::{ActId, ArtifactId, MaterialId, OutputId, ParamId, RoleId, SectionId, StepId};
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
#[non_exhaustive]
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
    /// An artifact reference (resolves to either a `materials:` declaration or
    /// the `creates:` of an upstream step).
    Artifact(ArtifactId),
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
    /// The raw source slice covered by `span` (e.g. `${role.alice}`, `${param.x}`,
    /// or a bare `alice`). Enables span lookup by raw value text without re-reading
    /// the YAML source — see `SpanMap::span_for_value`.
    pub value: String,
}

/// Maps ceremony element IDs to their source positions for diagnostic enrichment
/// and editor navigation.
///
/// The resolver's `Lowerer` populates this in a single pass over the parsed YAML.
/// Declaration spans (one map per kind) record where each ID is defined; the
/// `references` vector records every reference-value scalar — `role:`, `act:`,
/// `backend:`, `creates:`, `reads:`, plus `${param.x}` / `${material.x}` /
/// `${artifact.x}` / `${role.x}` expressions inside `description:` and `with:`
/// blocks. Each reference entry stores its source span, resolved target, owning
/// step or section, and the raw source text.
///
/// Consumers (LSP for navigation, `rite check`/`rite run` for diagnostic spans)
/// should use the `SpanMap` methods rather than the public maps directly when a
/// helper exists — that keeps the lookup rules (e.g. artifact→material fallback)
/// in one place.
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
    /// Output declaration spans (top-level `output:` map keys).
    pub outputs: HashMap<OutputId, Span>,
    /// Spans of the `creates:` value scalars that produce each artifact ID.
    pub artifacts: HashMap<ArtifactId, Span>,
    /// Reference sites collected during parsing: value-scalar span → declaration target.
    /// Used by go-to-definition to map a cursor position to a declaration span.
    pub references: Vec<ReferenceEntry>,
    /// Spans of value scalars for enum-style fields (`action:` on steps,
    /// `provider:` on backends). The values pick from fixed registries
    /// rather than declared identifiers, so they aren't references and
    /// don't fit any of the maps above.
    pub enum_values: Vec<Span>,
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

    /// Look up the declaration span for a resolved [`ReferenceTarget`].
    ///
    /// For artifacts the "declaration" is the producing step's `creates:` site;
    /// when no producer is recorded we fall back to a same-named material entry
    /// (since `${artifact.X}` may resolve to a `materials:` declaration).
    pub fn declaration_span(&self, target: &ReferenceTarget) -> Option<Span> {
        match target {
            ReferenceTarget::Section(id) => self.sections.get(id).copied(),
            ReferenceTarget::Role(id) => self.roles.get(id).copied(),
            ReferenceTarget::Act(id) => self.acts.get(id).copied(),
            ReferenceTarget::Param(id) => self.params.get(id).copied(),
            ReferenceTarget::Material(id) => self.materials.get(id).copied(),
            ReferenceTarget::Backend(name) => self.backends.get(name.as_str()).copied(),
            ReferenceTarget::Artifact(id) => self
                .artifacts
                .get(id)
                .copied()
                .or_else(|| self.materials.get(&MaterialId::new(id.as_str())).copied()),
        }
    }

    /// Identify the [`ReferenceTarget`] kind a free-form `word` declares.
    ///
    /// Used when the cursor is on a declaration key (rather than a reference value)
    /// to pivot from `find-references` back into the same target type. The first
    /// matching map wins.
    pub fn declaration_target_for_word(&self, word: &str) -> Option<ReferenceTarget> {
        let section_id = SectionId::new(word);
        if self.sections.contains_key(&section_id) {
            return Some(ReferenceTarget::Section(section_id));
        }
        let role_id = RoleId::new(word);
        if self.roles.contains_key(&role_id) {
            return Some(ReferenceTarget::Role(role_id));
        }
        let act_id = ActId::new(word);
        if self.acts.contains_key(&act_id) {
            return Some(ReferenceTarget::Act(act_id));
        }
        let param_id = ParamId::new(word);
        if self.params.contains_key(&param_id) {
            return Some(ReferenceTarget::Param(param_id));
        }
        let material_id = MaterialId::new(word);
        if self.materials.contains_key(&material_id) {
            return Some(ReferenceTarget::Material(material_id));
        }
        let artifact_id = ArtifactId::new(word);
        if self.artifacts.contains_key(&artifact_id) {
            return Some(ReferenceTarget::Artifact(artifact_id));
        }
        if self.backends.contains_key(word) {
            return Some(ReferenceTarget::Backend(word.to_string()));
        }
        None
    }

    /// Iterate every reference entry whose target matches `target`.
    ///
    /// Used by find-references to enumerate the use sites of a declaration.
    pub fn references_for_target<'a>(
        &'a self,
        target: &'a ReferenceTarget,
    ) -> impl Iterator<Item = &'a ReferenceEntry> + 'a {
        self.references.iter().filter(move |e| e.target == *target)
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

    // TODO: pair this exhaustive match with a `#[cfg(test)] fn variant_name(&ResolveError)`
    // sentinel + a constructors-list test, so a new variant fails not only here but
    // also in the dispatch test table (`lib.rs`).
    fn span_for_error(&self, err: &ResolveError) -> Option<Span> {
        match err {
            ResolveError::Yaml { location, .. } => location.map(|(line, col)| Span {
                line,
                column: col,
                length: None,
            }),
            ResolveError::Io { .. }
            | ResolveError::UnsupportedVersion { .. }
            | ResolveError::DutyUnknownRole { .. }
            | ResolveError::CustomDutyMissingDescription { .. } => None,
            ResolveError::DuplicateRole(id) => self.roles.get(id).copied(),
            ResolveError::DuplicateStep(id) => self.steps.get(id).copied(),
            ResolveError::DuplicateSection(id) => self.sections.get(id).copied(),
            ResolveError::DuplicateAct(id) => self.acts.get(id).copied(),
            ResolveError::DuplicateParam(id) => self.params.get(id).copied(),
            ResolveError::DuplicateMaterial(id) => self.materials.get(id).copied(),
            ResolveError::DuplicateOutput(id) => self.outputs.get(id).copied(),
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
            ResolveError::InvalidReferenceSyntax { context, value, .. }
            | ResolveError::ReferenceTypeMismatch { context, value, .. } => self
                .span_for_value(context, value)
                .or_else(|| self.span_for_context(context)),
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

    /// Look up the span of a reference by raw source text and owning context.
    ///
    /// Used by `span_for_error` when only the literal value is known (e.g. for
    /// `InvalidReferenceSyntax` and `ReferenceTypeMismatch`, where the value did
    /// not parse as any specific reference kind). Matches whichever entry covers
    /// the same source slice in the same step or section.
    fn span_for_value(&self, context: &ReferenceContext, value: &str) -> Option<Span> {
        self.references
            .iter()
            .find(|e| e.context == *context && e.value == value)
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
            ResolveWarning::UnusedOutput(id) => self.outputs.get(id).copied(),
            ResolveWarning::ArtifactNotOutput(id) => self.artifacts.get(id).copied(),
            ResolveWarning::UnknownRoleInInputs { role } => self.roles.get(role).copied(),
            ResolveWarning::UnusedBackend { step } => self.steps.get(step).copied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point_span(line: usize, column: usize, length: usize) -> Span {
        Span {
            line,
            column,
            length: Some(length),
        }
    }

    #[test]
    fn declaration_span_dispatches_per_target_kind() {
        let mut span_map = SpanMap::default();
        span_map
            .roles
            .insert(RoleId::new("alice"), point_span(3, 5, 5));
        span_map
            .materials
            .insert(MaterialId::new("card"), point_span(7, 5, 4));
        span_map
            .backends
            .insert("ssl".to_string(), point_span(9, 5, 3));

        let role_span = span_map
            .declaration_span(&ReferenceTarget::Role(RoleId::new("alice")))
            .expect("role span");
        assert_eq!(role_span.line, 3);

        let material_span = span_map
            .declaration_span(&ReferenceTarget::Material(MaterialId::new("card")))
            .expect("material span");
        assert_eq!(material_span.line, 7);

        let backend_span = span_map
            .declaration_span(&ReferenceTarget::Backend("ssl".to_string()))
            .expect("backend span");
        assert_eq!(backend_span.line, 9);
    }

    #[test]
    fn declaration_span_for_artifact_falls_back_to_material() {
        // No producing step recorded for the artifact, but a same-named material
        // declaration exists. `${artifact.X}` resolves to that material at IR time;
        // the span lookup must mirror that resolution.
        let mut span_map = SpanMap::default();
        span_map
            .materials
            .insert(MaterialId::new("seed"), point_span(11, 5, 4));

        let span = span_map
            .declaration_span(&ReferenceTarget::Artifact(ArtifactId::new("seed")))
            .expect("should fall back to material span");
        assert_eq!(span.line, 11);
    }

    #[test]
    fn declaration_target_for_word_resolves_each_kind() {
        let mut span_map = SpanMap::default();
        span_map
            .sections
            .insert(SectionId::new("setup"), point_span(2, 3, 5));
        span_map
            .roles
            .insert(RoleId::new("alice"), point_span(4, 3, 5));
        span_map
            .params
            .insert(ParamId::new("threshold"), point_span(6, 3, 9));
        span_map
            .artifacts
            .insert(ArtifactId::new("keypair"), point_span(8, 3, 7));

        assert!(matches!(
            span_map.declaration_target_for_word("setup"),
            Some(ReferenceTarget::Section(_))
        ));
        assert!(matches!(
            span_map.declaration_target_for_word("alice"),
            Some(ReferenceTarget::Role(_))
        ));
        assert!(matches!(
            span_map.declaration_target_for_word("threshold"),
            Some(ReferenceTarget::Param(_))
        ));
        assert!(matches!(
            span_map.declaration_target_for_word("keypair"),
            Some(ReferenceTarget::Artifact(_))
        ));
        assert!(span_map.declaration_target_for_word("nope").is_none());
    }

    #[test]
    fn references_for_target_filters_by_target_only() {
        let mut span_map = SpanMap::default();
        let ctx_a = ReferenceContext::Step(StepId::new("a"));
        let ctx_b = ReferenceContext::Step(StepId::new("b"));
        span_map.references.push(ReferenceEntry {
            span: point_span(10, 3, 4),
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ctx_a.clone(),
            value: "main".to_string(),
        });
        span_map.references.push(ReferenceEntry {
            span: point_span(20, 3, 4),
            target: ReferenceTarget::Section(SectionId::new("main")),
            context: ctx_b,
            value: "main".to_string(),
        });
        span_map.references.push(ReferenceEntry {
            span: point_span(30, 3, 5),
            target: ReferenceTarget::Section(SectionId::new("other")),
            context: ctx_a,
            value: "other".to_string(),
        });

        let main = ReferenceTarget::Section(SectionId::new("main"));
        let lines: Vec<usize> = span_map
            .references_for_target(&main)
            .map(|e| e.span.line)
            .collect();
        assert_eq!(lines, vec![10, 20]);
    }
}
