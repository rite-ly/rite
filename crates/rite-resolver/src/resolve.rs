//! AST to IR resolution.
//!
//! This module transforms a parsed ceremony (`schema::Ceremony`, AST) and optional
//! instance inputs into a resolved ceremony (`rite_model::Ceremony`, IR) ready for execution.

use crate::CeremonyInputs;
use crate::error::{ResolveError, ResolveResult, ResolveWarning};
use crate::schema;
use indexmap::IndexMap;
use rite_model::expression::RefType;
use rite_model::expression::{Expression, Reference, parse_expr_value, parse_expression};
use rite_model::{
    Act, ActId, ArtifactId, ArtifactRef, Ceremony, Material, MaterialId, MaterialKind,
    MaterialSource, Metadata, Output, OutputId, ParamId, Parameter, PostCeremonyDuty, Role, RoleId,
    Section, SectionId, Step, StepId, StepInputs, SymbolTable,
};
use rite_model::{ActionType, DutyType, ParameterType};
use std::collections::{HashMap, HashSet};

/// Schema versions this resolver understands.
///
/// When adding support for a new schema version, add its string here and branch the
/// resolution logic in `resolve_ceremony` as needed. Older versions may need a separate
/// resolution path if they differ structurally.
const SUPPORTED_VERSIONS: &[&str] = &["0.2"];

/// Resolve a ceremony and optional external inputs into IR.
pub(crate) fn resolve_ceremony(
    ceremony: schema::Ceremony,
    inputs: Option<&CeremonyInputs>,
) -> ResolveResult<Ceremony> {
    if !SUPPORTED_VERSIONS.contains(&ceremony.version.as_str()) {
        return ResolveResult::err(ResolveError::UnsupportedVersion {
            version: ceremony.version,
            supported: SUPPORTED_VERSIONS.join(", "),
        });
    }

    let mut ctx = ResolveContext::new();

    // Phase 1: Register all declarations (build symbol tables)
    ctx.register_roles(&ceremony.roles);
    ctx.register_acts(&ceremony.acts);
    ctx.register_sections(&ceremony.sections);
    ctx.register_parameters(&ceremony.parameters);
    ctx.register_materials(&ceremony.materials);
    ctx.register_outputs(&ceremony.output);

    // Phase 2: Resolve external inputs
    if let Some(inputs) = inputs {
        ctx.resolve_input_roles(inputs);
        ctx.resolve_input_parameters(&ceremony.parameters, inputs);
        ctx.resolve_input_materials(&ceremony.materials, inputs);
    } else {
        // No inputs - use defaults for parameters
        ctx.apply_parameter_defaults(&ceremony.parameters);
    }

    // Phase 3: Resolve steps and build execution plan
    let execution_plan = ctx.resolve_steps(&ceremony);

    // Phase 4: Validate artifact ordering
    ctx.validate_artifact_ordering(&execution_plan, &ceremony.materials);

    // Phase 5: Resolve post-ceremony duties
    let after = ctx.resolve_duties(&ceremony.after);

    // Backends come from ceremony YAML only (no instance overrides)
    let backends = ceremony.backends.clone();

    // Check for errors
    if !ctx.errors.is_empty() {
        return ResolveResult::errors(ctx.errors);
    }

    // Build the resolved ceremony IR
    let resolved = Ceremony {
        metadata: Metadata {
            name: ceremony.name,
            description: ceremony.description,
        },
        roles: ctx.roles,
        acts: ctx.acts,
        sections: ctx.sections,
        parameters: ctx.parameters,
        materials: ctx.materials,
        prerequisites: ceremony.prerequisites,
        outputs: ctx.outputs,
        backends,
        execution_plan,
        after,
    };

    let mut result = ResolveResult::ok(resolved);
    result.warnings = ctx.warnings;
    result
}

/// Context for resolution, accumulating symbol tables and errors.
struct ResolveContext {
    // Symbol tables (IR types)
    roles: SymbolTable<RoleId, Role>,
    acts: SymbolTable<ActId, Act>,
    sections: SymbolTable<SectionId, Section>,
    parameters: SymbolTable<ParamId, Parameter>,
    materials: SymbolTable<MaterialId, Material>,
    outputs: SymbolTable<OutputId, Output>,

    // For artifact tracking
    produced_artifacts: HashMap<ArtifactId, StepId>,

    // Error accumulation
    errors: Vec<ResolveError>,
    warnings: Vec<ResolveWarning>,
}

impl ResolveContext {
    fn new() -> Self {
        Self {
            roles: SymbolTable::new(),
            acts: SymbolTable::new(),
            sections: SymbolTable::new(),
            parameters: SymbolTable::new(),
            materials: SymbolTable::new(),
            outputs: SymbolTable::new(),
            produced_artifacts: HashMap::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn add_error(&mut self, error: ResolveError) {
        self.errors.push(error);
    }

    // Phase 1: Registration
    fn register_roles(&mut self, roles: &IndexMap<String, schema::RoleDefinition>) {
        for (id_str, role) in roles {
            let id = RoleId::new(id_str);
            let name = role
                .name
                .clone()
                .unwrap_or_else(|| rite_model::derive_role_name(id_str));
            let resolved = Role {
                id: id.clone(),
                name,
                role_type: rite_model::role_type(id_str).to_string(),
                person: role.person.clone(),
            };
            if self.roles.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateRole(id));
            }
        }
    }

    fn resolve_input_roles(&mut self, inputs: &CeremonyInputs) {
        for (id_str, person) in &inputs.roles {
            let id = RoleId::new(id_str);
            if let Some(role) = self.roles.get_mut(&id) {
                role.person = Some(person.clone());
            } else {
                self.warnings
                    .push(ResolveWarning::UnknownRoleInInputs { role: id });
            }
        }
    }

    fn register_acts(&mut self, acts: &[schema::Act]) {
        for act in acts {
            let id = ActId::new(&act.id);
            let resolved = Act {
                id: id.clone(),
                name: act.name.clone(),
                description: act.description.clone(),
            };
            if self.acts.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateAct(id));
            }
        }
    }

    fn register_sections(&mut self, sections: &IndexMap<String, schema::SectionBody>) {
        for (id_str, section) in sections {
            let id = SectionId::new(id_str);

            // Resolve act reference if present
            let act = section.act.as_ref().map(|a| {
                let act_id = ActId::new(extract_name(a));
                if !self.acts.contains(&act_id) {
                    self.add_error(ResolveError::UnknownAct {
                        act: act_id.clone(),
                        section: id.clone(),
                    });
                }
                act_id
            });

            // Resolve default role if present
            let default_role = section
                .role
                .as_ref()
                .and_then(|r| self.resolve_role_ref(r, &format!("section:{id_str}")));

            let resolved = Section {
                id: id.clone(),
                act,
                name: section.name.clone(),
                description: section.description.clone(),
                default_role,
            };

            if self.sections.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateSection(id));
            }
        }
    }

    fn register_parameters(&mut self, parameters: &HashMap<String, schema::Parameter>) {
        for (name, param) in parameters {
            let id = ParamId::new(name);
            let resolved = Parameter {
                id: id.clone(),
                declared_type: param.param_type.clone(),
                value: serde_json::Value::Null, // Filled in Phase 2
                description: param.description.clone(),
            };
            if self.parameters.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateParam(id));
            }
        }
    }

    fn register_materials(&mut self, materials: &HashMap<String, schema::Material>) {
        for (name, material) in materials {
            let id = MaterialId::new(name);
            let kind = match material {
                schema::Material::Digital { path, .. } => {
                    let source = path
                        .as_ref()
                        .map(|p| MaterialSource::File { file: p.clone() });
                    MaterialKind::Digital { source }
                }
                schema::Material::Physical {
                    quantity,
                    identifier,
                    ..
                } => MaterialKind::Physical {
                    identifier: identifier.clone(),
                    quantity: *quantity,
                },
            };
            let resolved = Material {
                id: id.clone(),
                kind,
                title: material.title().map(String::from),
                description: material.description().map(String::from),
            };
            if self.materials.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateMaterial(id));
            }
        }
    }

    fn register_outputs(&mut self, outputs: &HashMap<String, schema::OutputDeclaration>) {
        for (name, output) in outputs {
            let id = OutputId::new(name);
            let resolved = Output {
                id: id.clone(),
                kind: output.artifact_type,
                description: output.description.clone(),
            };
            if self.outputs.insert(id.clone(), resolved).is_err() {
                self.add_error(ResolveError::DuplicateOutput(id));
            }
        }
    }

    // Phase 2: Input Resolution
    fn resolve_input_parameters(
        &mut self,
        declarations: &HashMap<String, schema::Parameter>,
        inputs: &CeremonyInputs,
    ) {
        for (name, decl) in declarations {
            let id = ParamId::new(name);

            let value = if let Some(v) = inputs.parameters.get(name) {
                let Some(coerced) = self.coerce_input_param_value(&id, &decl.param_type, v) else {
                    continue;
                };
                coerced
            } else if let Some(default) = &decl.default {
                default.clone()
            } else {
                self.add_error(ResolveError::RequiredParamMissing(id.clone()));
                continue;
            };

            if let Some(param) = self.parameters.get_mut(&id) {
                param.value = value;
            }
        }
    }

    fn coerce_input_param_value(
        &mut self,
        id: &ParamId,
        expected: &ParameterType,
        value: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        match expected {
            // CLI/env/prompt inputs are commonly strings. Coerce them to declared scalar types
            // so users can pass --param threshold=5 and --param enabled=true naturally.
            ParameterType::Integer => {
                if value.is_i64() || value.is_u64() {
                    return Some(value.clone());
                }
                if let Some(s) = value.as_str() {
                    if let Ok(i) = s.parse::<i64>() {
                        return Some(serde_json::Value::Number(i.into()));
                    }
                    if let Ok(u) = s.parse::<u64>() {
                        return Some(serde_json::Value::Number(u.into()));
                    }
                }
                self.add_error(ResolveError::ParamTypeMismatch {
                    param: id.clone(),
                    expected: expected.clone(),
                    got: value_type_name(value).to_string(),
                });
                None
            }
            ParameterType::Boolean => {
                if value.is_boolean() {
                    return Some(value.clone());
                }
                if let Some(s) = value.as_str() {
                    if s.eq_ignore_ascii_case("true") {
                        return Some(serde_json::Value::Bool(true));
                    }
                    if s.eq_ignore_ascii_case("false") {
                        return Some(serde_json::Value::Bool(false));
                    }
                }
                self.add_error(ResolveError::ParamTypeMismatch {
                    param: id.clone(),
                    expected: expected.clone(),
                    got: value_type_name(value).to_string(),
                });
                None
            }
            ParameterType::String => {
                if value.is_string() {
                    return Some(value.clone());
                }
                self.add_error(ResolveError::ParamTypeMismatch {
                    param: id.clone(),
                    expected: expected.clone(),
                    got: value_type_name(value).to_string(),
                });
                None
            }
            ParameterType::Date => {
                if let Some(s) = value.as_str() {
                    if is_valid_date(s) {
                        return Some(value.clone());
                    }
                    self.add_error(ResolveError::InvalidDateFormat {
                        param: id.clone(),
                        value: s.to_string(),
                    });
                    return None;
                }
                self.add_error(ResolveError::ParamTypeMismatch {
                    param: id.clone(),
                    expected: expected.clone(),
                    got: value_type_name(value).to_string(),
                });
                None
            }
            // Unknown future variant; accept any value rather than failing.
            _ => Some(value.clone()),
        }
    }

    fn resolve_input_materials(
        &mut self,
        declarations: &HashMap<String, schema::Material>,
        inputs: &CeremonyInputs,
    ) {
        for (name, material) in declarations {
            let id = MaterialId::new(name);

            if let Some(source) = inputs.materials.get(name) {
                if let Some(resolved) = self.materials.get_mut(&id) {
                    match (&mut resolved.kind, source) {
                        (MaterialKind::Digital { source: s }, MaterialSource::File { .. }) => {
                            *s = Some(source.clone());
                        }
                        (
                            MaterialKind::Physical { identifier, .. },
                            MaterialSource::Identifier { identifier: id_str },
                        ) => {
                            *identifier = Some(id_str.clone());
                        }
                        _ => {
                            self.add_error(ResolveError::MaterialSourceMismatch { material: id });
                        }
                    }
                }
            } else if material.is_digital() && material.path().is_none() {
                self.add_error(ResolveError::RequiredMaterialMissing(id));
            }
        }
    }

    fn apply_parameter_defaults(&mut self, declarations: &HashMap<String, schema::Parameter>) {
        for (name, decl) in declarations {
            let id = ParamId::new(name);
            if let Some(default) = &decl.default
                && let Some(param) = self.parameters.get_mut(&id)
            {
                param.value = default.clone();
            }
        }
    }

    // Phase 3: Step Resolution
    fn resolve_steps(&mut self, ceremony: &schema::Ceremony) -> Vec<Step> {
        let mut steps = Vec::new();
        let mut seen_step_ids = HashSet::new();
        let has_multiple_acts = !self.acts.is_empty();

        // Act order for label numbering (computed once, cheap).
        let act_order: Vec<ActId> = ceremony.acts.iter().map(|a| ActId::new(&a.id)).collect();
        let mut act_step_counters: HashMap<Option<ActId>, usize> = HashMap::new();

        for (section_id_str, section) in &ceremony.sections {
            let section_id = SectionId::new(section_id_str);
            let act_id = section.act.as_ref().map(|a| ActId::new(extract_name(a)));

            for (step_id_str, step) in &section.steps {
                let id = StepId::new(step_id_str);

                // Cross-section duplicate step ID check (within-section duplicates are
                // caught by the YAML parser as DuplicateKey errors).
                if !seen_step_ids.insert(step_id_str.clone()) {
                    self.add_error(ResolveError::DuplicateStep(id));
                    continue;
                }

                // Compute step label inline: single pass over sections/steps.
                let step_count = act_step_counters.entry(act_id.clone()).or_insert(0);
                #[allow(clippy::arithmetic_side_effects)]
                {
                    *step_count += 1;
                }
                let act_number = match &act_id {
                    Some(id) => act_order.iter().position(|a| a == id).map_or(1, |i| {
                        #[allow(clippy::arithmetic_side_effects)]
                        {
                            i + 1
                        }
                    }),
                    None => {
                        if act_order.is_empty() {
                            1
                        } else {
                            #[allow(clippy::arithmetic_side_effects)]
                            {
                                act_order.len() + 1
                            }
                        }
                    }
                };
                let step_label = if has_multiple_acts {
                    format!("{act_number}.{step_count}")
                } else {
                    step_count.to_string()
                };

                // Resolve role (from step or section default)
                let role = if let Some(role_ref) = &step.role {
                    self.resolve_role_ref(role_ref, step_id_str)
                } else {
                    self.sections
                        .get(&section_id)
                        .and_then(|s| s.default_role.clone())
                };

                let (reads, reads_resolved) = self.resolve_inputs(step.reads.as_ref(), &id);

                let creates = step.creates.as_ref().map(|p| {
                    let artifact_id = ArtifactId::new(extract_name(p));
                    self.produced_artifacts
                        .insert(artifact_id.clone(), id.clone());
                    artifact_id
                });

                let with_json = step
                    .with
                    .clone()
                    .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
                let with = parse_expr_value(&with_json);

                let description = step
                    .description
                    .as_ref()
                    .map(|desc| parse_expr_value(&serde_json::Value::String(desc.clone())));

                let resolved = Step {
                    id: id.clone(),
                    step_label,
                    section: section_id.clone(),
                    action: step.action,
                    backend: step.backend.clone(),
                    role,
                    preconditions: step.preconditions.clone(),
                    with,
                    reads,
                    reads_resolved,
                    creates,
                    description,
                    silent: step.silent,
                };

                if step.action == ActionType::MachineInfo && step.backend.is_some() {
                    self.add_error(ResolveError::MachineInfoWithBackend { step: id.clone() });
                }

                if let Some(backend_name) = &step.backend
                    && !ceremony.backends.contains_key(backend_name)
                {
                    self.add_error(ResolveError::UndeclaredBackend {
                        step: id,
                        backend: backend_name.clone(),
                    });
                }

                steps.push(resolved);
            }
        }

        steps
    }

    fn resolve_role_ref(&mut self, role_ref: &str, context: &str) -> Option<RoleId> {
        if let Some(reference) = parse_reference(role_ref) {
            if reference.ref_type != RefType::Role {
                self.add_error(ResolveError::ReferenceTypeMismatch {
                    context: context.to_string(),
                    field: "role".to_string(),
                    expected: RefType::Role,
                    actual: reference.ref_type,
                });
                return None;
            }

            let id = RoleId::new(&reference.name);
            if !self.roles.contains(&id) {
                self.add_error(ResolveError::UnknownRole {
                    role: id.clone(),
                    context: context.to_string(),
                });
                return None;
            }
            Some(id)
        } else {
            self.add_error(ResolveError::InvalidReferenceSyntax {
                context: context.to_string(),
                field: "role".to_string(),
                value: role_ref.to_string(),
            });
            None
        }
    }

    /// Resolve input references from step YAML.
    ///
    /// Returns both:
    /// - `Vec<ArtifactRef>` for ordering validation (all referenced artifacts)
    /// - `Option<StepInputs>` for handler access (structured for Single vs Named)
    fn resolve_inputs(
        &mut self,
        reads: Option<&serde_json::Value>,
        step_id: &StepId,
    ) -> (Vec<ArtifactRef>, Option<StepInputs>) {
        let Some(reads) = reads else {
            return (vec![], None);
        };

        match reads {
            serde_json::Value::String(s) => {
                // Single input: reads: "${artifact.keypair}"
                if let Some(artifact_ref) = self.resolve_artifact_ref(s, step_id, "reads") {
                    let typed = StepInputs::Single(artifact_ref.clone());
                    (vec![artifact_ref], Some(typed))
                } else {
                    (vec![], None)
                }
            }
            serde_json::Value::Object(map) => {
                // Named inputs: reads: { key_to_wrap: "...", wrapping_key: "..." }
                let mut refs = Vec::new();
                let mut named = HashMap::new();

                for (key, value) in map {
                    if let Some(s) = value.as_str() {
                        let field = format!("reads.{key}");
                        if let Some(artifact_ref) = self.resolve_artifact_ref(s, step_id, &field) {
                            refs.push(artifact_ref.clone());
                            named.insert(key.clone(), artifact_ref);
                        }
                    }
                }

                let typed = if named.is_empty() {
                    None
                } else {
                    Some(StepInputs::Named(named))
                };

                (refs, typed)
            }
            _ => (vec![], None),
        }
    }

    fn resolve_artifact_ref(
        &mut self,
        ref_str: &str,
        step_id: &StepId,
        field: &str,
    ) -> Option<ArtifactRef> {
        let reference = parse_reference(ref_str)?;

        if reference.ref_type != RefType::Artifact {
            self.add_error(ResolveError::ReferenceTypeMismatch {
                context: step_id.as_str().to_string(),
                field: field.to_string(),
                expected: RefType::Artifact,
                actual: reference.ref_type,
            });
            return None;
        }

        let material_id = MaterialId::new(&reference.name);
        if self.materials.contains(&material_id) {
            return Some(ArtifactRef::Material {
                id: material_id,
                property: reference.property,
            });
        }

        Some(ArtifactRef::Produced {
            id: ArtifactId::new(&reference.name),
            property: reference.property,
        })
    }

    // Phase 4: Artifact Ordering Validation
    fn validate_artifact_ordering(
        &mut self,
        execution_plan: &[Step],
        materials: &HashMap<String, schema::Material>,
    ) {
        let mut available: HashSet<String> = materials.keys().cloned().collect();

        for step in execution_plan {
            for input in &step.reads {
                if let ArtifactRef::Produced { id, .. } = input
                    && !available.contains(id.as_str())
                {
                    if let Some(producing_step) = self.produced_artifacts.get(id) {
                        self.add_error(ResolveError::ArtifactUsedBeforeProduced {
                            artifact: id.clone(),
                            used_in: step.id.clone(),
                            produced_in: producing_step.clone(),
                        });
                    } else {
                        self.add_error(ResolveError::ArtifactNeverProduced {
                            artifact: id.clone(),
                            step: step.id.clone(),
                        });
                    }
                }
            }

            if let Some(artifact_id) = &step.creates {
                available.insert(artifact_id.as_str().to_string());
            }
        }
    }

    // Phase 5: Duty Resolution
    fn resolve_duties(
        &mut self,
        duties: &IndexMap<String, schema::PostCeremonyDutyBody>,
    ) -> Vec<PostCeremonyDuty> {
        let mut resolved = Vec::new();

        for (id, duty) in duties {
            if duty.kind == DutyType::Custom && duty.description.is_none() {
                self.add_error(ResolveError::CustomDutyMissingDescription {
                    duty_id: id.clone(),
                });
            }

            let role = duty
                .role
                .as_ref()
                .and_then(|r| self.resolve_plain_role_ref(r, id));

            resolved.push(PostCeremonyDuty {
                id: id.clone(),
                kind: duty.kind.clone(),
                role,
                description: duty.description.clone(),
                items: duty.items.clone(),
                recipient: duty.recipient.clone(),
                location: duty.location.clone(),
            });
        }

        resolved
    }

    /// Resolve a plain role ID (not `${role.x}` syntax) to a `RoleId`.
    fn resolve_plain_role_ref(&mut self, role_id: &str, duty_id: &str) -> Option<RoleId> {
        let id = RoleId::new(role_id);
        if self.roles.contains(&id) {
            Some(id)
        } else {
            self.add_error(ResolveError::DutyUnknownRole {
                role: id,
                duty_id: duty_id.to_string(),
            });
            None
        }
    }
}

/// Parse a reference string using the expression parser.
fn parse_reference(s: &str) -> Option<Reference> {
    let expr = parse_expression(s)?;
    match expr {
        Expression::Reference(r) => Some(r),
        _ => None,
    }
}

/// Return a short type name for a JSON value (used in type mismatch errors).
fn value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Null => "null",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Validate a YYYY-MM-DD date string.
///
/// Checks structure, numeric ranges, and basic month-length rules (including leap years).
#[allow(clippy::arithmetic_side_effects)]
fn is_valid_date(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 10 || bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (
        s.get(..4).and_then(|v| v.parse::<u32>().ok()),
        s.get(5..7).and_then(|v| v.parse::<u32>().ok()),
        s.get(8..10).and_then(|v| v.parse::<u32>().ok()),
    ) else {
        return false;
    };
    if !(1..=12).contains(&month) || day < 1 {
        return false;
    }
    let max_day = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= max_day
}

/// Extract the plain name from a reference string or return the string as-is.
///
/// Handles `"${artifact.keypair}"` → `"keypair"` and `"keypair"` → `"keypair"`.
fn extract_name(s: &str) -> String {
    if let Some(reference) = parse_reference(s) {
        reference.name
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{PostCeremonyDutyBody, RoleDefinition, SectionBody, StepBody};
    use rite_model::{ActionType, BackendConfig};

    fn minimal_ceremony() -> schema::Ceremony {
        let mut sections = IndexMap::new();
        sections.insert("main".to_string(), empty_section());
        schema::Ceremony {
            version: "0.2".to_string(),
            name: "Test".to_string(),
            description: None,
            backends: HashMap::new(),
            roles: IndexMap::new(),
            acts: vec![],
            sections,
            parameters: HashMap::new(),
            materials: HashMap::new(),
            prerequisites: vec![],
            output: HashMap::new(),
            after: IndexMap::new(),
        }
    }

    fn empty_section() -> SectionBody {
        SectionBody {
            act: None,
            name: None,
            description: None,
            role: None,
            steps: IndexMap::new(),
        }
    }

    fn make_step_body() -> StepBody {
        StepBody {
            action: ActionType::Confirm,
            backend: None,
            with: None,
            role: None,
            preconditions: vec![],
            creates: None,
            reads: None,
            description: None,
            silent: false,
        }
    }

    #[test]
    fn resolves_empty_ceremony() {
        let ceremony = minimal_ceremony();
        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn coerces_string_integer_input_to_json_integer() {
        let mut ceremony = minimal_ceremony();
        ceremony.parameters.insert(
            "threshold".to_string(),
            schema::Parameter {
                param_type: ParameterType::Integer,
                description: None,
                default: None,
            },
        );

        let mut inputs = CeremonyInputs::default();
        inputs
            .parameters
            .insert("threshold".to_string(), serde_json::json!("5"));

        let result = resolve_ceremony(ceremony, Some(&inputs));
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
        let resolved = result.into_result().expect("ceremony resolves");
        let threshold = resolved
            .parameters
            .get(&ParamId::new("threshold"))
            .expect("threshold exists");
        assert_eq!(threshold.value, serde_json::json!(5));
    }

    #[test]
    fn coerces_string_boolean_input_to_json_boolean() {
        let mut ceremony = minimal_ceremony();
        ceremony.parameters.insert(
            "enabled".to_string(),
            schema::Parameter {
                param_type: ParameterType::Boolean,
                description: None,
                default: None,
            },
        );

        let mut inputs = CeremonyInputs::default();
        inputs
            .parameters
            .insert("enabled".to_string(), serde_json::json!("TRUE"));

        let result = resolve_ceremony(ceremony, Some(&inputs));
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
        let resolved = result.into_result().expect("ceremony resolves");
        let enabled = resolved
            .parameters
            .get(&ParamId::new("enabled"))
            .expect("enabled exists");
        assert_eq!(enabled.value, serde_json::json!(true));
    }

    #[test]
    fn detects_duplicate_step_ids() {
        let mut ceremony = minimal_ceremony();
        // Same step ID in two different sections; caught by the resolver.
        ceremony
            .sections
            .insert("other".to_string(), empty_section());
        ceremony
            .sections
            .get_mut("main")
            .unwrap()
            .steps
            .insert("step1".to_string(), make_step_body());
        ceremony
            .sections
            .get_mut("other")
            .unwrap()
            .steps
            .insert("step1".to_string(), make_step_body());

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::DuplicateStep(id) if id.as_str() == "step1"
        )));
    }

    #[test]
    fn resolves_artifact_ordering() {
        let mut ceremony = minimal_ceremony();
        ceremony.sections.clear();

        let mut step_a = make_step_body();
        step_a.creates = Some("${artifact.my_artifact}".to_string());
        let mut section_a = empty_section();
        section_a.steps.insert("step1".to_string(), step_a);

        let mut step_b = make_step_body();
        step_b.reads = Some(serde_json::json!("${artifact.my_artifact}"));
        let mut section_b = empty_section();
        section_b.steps.insert("step2".to_string(), step_b);

        ceremony.sections.insert("section_a".to_string(), section_a);
        ceremony.sections.insert("section_b".to_string(), section_b);

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
    }

    #[test]
    fn detects_artifact_used_before_produced() {
        let mut ceremony = minimal_ceremony();
        ceremony.sections.clear();

        // step in section_a uses artifact (executed first)
        let mut step_a = make_step_body();
        step_a.reads = Some(serde_json::json!("${artifact.my_artifact}"));
        let mut section_a = empty_section();
        section_a.steps.insert("step1".to_string(), step_a);

        // step in section_b produces artifact (executed second)
        let mut step_b = make_step_body();
        step_b.creates = Some("${artifact.my_artifact}".to_string());
        let mut section_b = empty_section();
        section_b.steps.insert("step2".to_string(), step_b);

        ceremony.sections.insert("section_a".to_string(), section_a);
        ceremony.sections.insert("section_b".to_string(), section_b);

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_err());
        assert!(
            result
                .errors
                .iter()
                .any(|e| matches!(e, ResolveError::ArtifactUsedBeforeProduced { .. }))
        );
    }

    #[test]
    fn resolves_duties() {
        let mut ceremony = minimal_ceremony();
        ceremony.after.insert(
            "duty_01".to_string(),
            PostCeremonyDutyBody {
                kind: DutyType::ReturnToVault,
                role: None,
                description: None,
                items: vec![],
                recipient: None,
                location: None,
            },
        );
        ceremony.after.insert(
            "return_media".to_string(),
            PostCeremonyDutyBody {
                kind: DutyType::DistributeMedia,
                role: None,
                description: None,
                items: vec!["USB drive to Alice".to_string()],
                recipient: None,
                location: None,
            },
        );

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
        let resolved = result.into_result().unwrap();
        assert_eq!(resolved.after.len(), 2);
        assert_eq!(
            resolved.after.first().expect("should have first duty").id,
            "duty_01"
        );
        assert_eq!(
            resolved.after.get(1).expect("should have second duty").id,
            "return_media"
        );
    }

    #[test]
    fn errors_on_custom_duty_missing_description() {
        let mut ceremony = minimal_ceremony();
        ceremony.after.insert(
            "my_duty".to_string(),
            PostCeremonyDutyBody {
                kind: DutyType::Custom,
                role: None,
                description: None,
                items: vec![],
                recipient: None,
                location: None,
            },
        );

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::CustomDutyMissingDescription { duty_id } if duty_id == "my_duty"
        )));
    }

    #[test]
    fn errors_on_duty_with_unknown_role() {
        let mut ceremony = minimal_ceremony();
        ceremony.after.insert(
            "my_duty".to_string(),
            PostCeremonyDutyBody {
                kind: DutyType::ReturnToVault,
                role: Some("nonexistent_role".to_string()),
                description: None,
                items: vec![],
                recipient: None,
                location: None,
            },
        );

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::DutyUnknownRole { role, duty_id }
                if role.as_str() == "nonexistent_role" && duty_id == "my_duty"
        )));
    }

    #[test]
    fn resolves_role_type_and_derived_name() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "witness__1".to_string(),
                RoleDefinition {
                    name: None,
                    person: None,
                },
            );
            m.insert(
                "hsm_operator__primary".to_string(),
                RoleDefinition {
                    name: None,
                    person: None,
                },
            );
            m.insert(
                "ceremony_admin".to_string(),
                RoleDefinition {
                    name: None,
                    person: None,
                },
            );
            m
        };

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
        let resolved = result.into_result().unwrap();

        let w1 = resolved.roles.get(&RoleId::new("witness__1")).unwrap();
        assert_eq!(w1.role_type, "witness");
        assert_eq!(w1.name, "Witness");

        let op = resolved
            .roles
            .get(&RoleId::new("hsm_operator__primary"))
            .unwrap();
        assert_eq!(op.role_type, "hsm_operator");
        assert_eq!(op.name, "Hsm Operator");

        let admin = resolved.roles.get(&RoleId::new("ceremony_admin")).unwrap();
        assert_eq!(admin.role_type, "ceremony_admin");
        assert_eq!(admin.name, "Ceremony Admin");
    }

    #[test]
    fn explicit_name_overrides_derived() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "witness__1".to_string(),
                RoleDefinition {
                    name: Some("First Witness".to_string()),
                    person: None,
                },
            );
            m
        };

        let result = resolve_ceremony(ceremony, None);
        let resolved = result.into_result().unwrap();
        let role = resolved.roles.get(&RoleId::new("witness__1")).unwrap();
        assert_eq!(role.name, "First Witness");
        assert_eq!(role.role_type, "witness");
    }

    #[test]
    fn person_from_ceremony_yaml() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "ceremony_admin".to_string(),
                RoleDefinition {
                    name: Some("Ceremony Administrator".to_string()),
                    person: Some("Alice Smith".to_string()),
                },
            );
            m
        };

        let result = resolve_ceremony(ceremony, None);
        let resolved = result.into_result().unwrap();
        let role = resolved.roles.get(&RoleId::new("ceremony_admin")).unwrap();
        assert_eq!(role.person, Some("Alice Smith".to_string()));
    }

    #[test]
    fn inputs_override_person() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "witness__1".to_string(),
                RoleDefinition {
                    name: None,
                    person: Some("Default Witness".to_string()),
                },
            );
            m
        };

        let inputs = CeremonyInputs {
            roles: {
                let mut m = HashMap::new();
                m.insert("witness__1".to_string(), "Jane Doe".to_string());
                m
            },
            ..Default::default()
        };

        let result = resolve_ceremony(ceremony, Some(&inputs));
        let resolved = result.into_result().unwrap();
        let role = resolved.roles.get(&RoleId::new("witness__1")).unwrap();
        assert_eq!(role.person, Some("Jane Doe".to_string()));
    }

    #[test]
    fn inputs_add_person_when_ceremony_has_none() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "operator".to_string(),
                RoleDefinition {
                    name: None,
                    person: None,
                },
            );
            m
        };

        let inputs = CeremonyInputs {
            roles: {
                let mut m = HashMap::new();
                m.insert("operator".to_string(), "Bob Jones".to_string());
                m
            },
            ..Default::default()
        };

        let result = resolve_ceremony(ceremony, Some(&inputs));
        let resolved = result.into_result().unwrap();
        let role = resolved.roles.get(&RoleId::new("operator")).unwrap();
        assert_eq!(role.person, Some("Bob Jones".to_string()));
    }

    #[test]
    fn unknown_input_role_produces_warning() {
        let ceremony = minimal_ceremony();

        let inputs = CeremonyInputs {
            roles: {
                let mut m = HashMap::new();
                m.insert("nonexistent".to_string(), "Ghost".to_string());
                m
            },
            ..Default::default()
        };

        let result = resolve_ceremony(ceremony, Some(&inputs));
        assert!(
            result.is_ok(),
            "Should succeed with a warning, not an error"
        );
        assert!(result.warnings.iter().any(|w| matches!(
            w,
            ResolveWarning::UnknownRoleInInputs { role }
                if role.as_str() == "nonexistent"
        )));
    }

    #[test]
    fn resolves_duty_role_reference() {
        let mut ceremony = minimal_ceremony();
        ceremony.roles = {
            let mut m = IndexMap::new();
            m.insert(
                "admin".to_string(),
                RoleDefinition {
                    name: Some("Administrator".to_string()),
                    person: None,
                },
            );
            m
        };
        ceremony.after.insert(
            "vault_return".to_string(),
            PostCeremonyDutyBody {
                kind: DutyType::ReturnToVault,
                role: Some("admin".to_string()),
                description: None,
                items: vec![],
                recipient: None,
                location: None,
            },
        );

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
        let resolved = result.into_result().unwrap();
        assert_eq!(
            resolved.after.first().expect("should have first duty").role,
            Some(RoleId::new("admin"))
        );
    }

    #[test]
    fn detects_undeclared_backend() {
        let mut ceremony = minimal_ceremony();
        let mut step = make_step_body();
        step.action = ActionType::GenerateKeypair;
        step.backend = Some("nonexistent".to_string());
        ceremony
            .sections
            .get_mut("main")
            .unwrap()
            .steps
            .insert("gen".to_string(), step);

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_err());
        assert!(result.errors.iter().any(|e| matches!(
            e,
            ResolveError::UndeclaredBackend { step, backend }
                if step.as_str() == "gen" && backend == "nonexistent"
        )));
    }

    #[test]
    fn accepts_declared_backend() {
        let mut ceremony = minimal_ceremony();
        ceremony.backends.insert(
            "ssl".to_string(),
            BackendConfig {
                provider: "openssl".to_string(),
                extra: serde_json::json!({}),
            },
        );
        let mut step = make_step_body();
        step.action = ActionType::GenerateKeypair;
        step.backend = Some("ssl".to_string());
        ceremony
            .sections
            .get_mut("main")
            .unwrap()
            .steps
            .insert("gen".to_string(), step);

        let result = resolve_ceremony(ceremony, None);
        assert!(result.is_ok(), "Errors: {:?}", result.errors);
    }
}
