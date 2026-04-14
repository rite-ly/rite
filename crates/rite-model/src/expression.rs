//! Expression parsing for computed values in ceremony DSL.
//!
//! This module provides types and functions for parsing pipeline expressions
//! that compute values at runtime, such as `${artifact.ksr | sha256 | hex}`.
//!
//! ## Syntax
//!
//! Expressions use Unix-style pipes:
//!
//! ```text
//! ${artifact.ksr | sha256 | hex}
//! ${artifact.keypair.public | fingerprint | hex | upper}
//! ${concat(artifact.a | sha256, artifact.b | sha256) | hex}
//! ```
//!
//! ## Design Principles
//!
//! - **Bytes-first**: Hash functions return raw bytes; encoding is explicit
//! - **Left-to-right**: Data flows through transformations naturally
//! - **Safe**: All functions are total and terminate (no user-defined functions)
//!
//! ## Grammar
//!
//! See [docs/dsl/grammar.md](../../../docs/dsl/grammar.md) for the formal grammar.

// The expression parser uses byte-index arithmetic and slice indexing throughout.
// All indices are guarded by length checks and loop bounds — the operations cannot
// overflow or panic in practice. Suppressed here to avoid obscuring the parser logic.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use std::ops::Range;

// ============================================================================
// Reference Types (shared with reference.rs)
// ============================================================================

/// The type/namespace of a reference.
///
/// Used in full-form references like `${param.name}` or `${artifact.ksr}`.
/// This is the canonical definition, re-exported by `reference.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefType {
    /// Parameter reference (runtime configuration from CLI/env/defaults)
    Param,
    /// Role reference (ceremony participant)
    Role,
    /// Artifact reference (materials, outputs, intermediate values)
    Artifact,
}

impl std::str::FromStr for RefType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "param" => Ok(Self::Param),
            "role" => Ok(Self::Role),
            "artifact" => Ok(Self::Artifact),
            _ => Err(format!("unknown reference type: {s}")),
        }
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Param => write!(f, "param"),
            Self::Role => write!(f, "role"),
            Self::Artifact => write!(f, "artifact"),
        }
    }
}

// ============================================================================
// Runtime Values
// ============================================================================

/// A runtime value in the expression system.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Raw binary data (computation core)
    Bytes(Vec<u8>),
    /// UTF-8 text string
    String(String),
    /// Integer value
    Integer(i64),
    /// Boolean value
    Boolean(bool),
    /// Null/missing value
    Null,
}

impl Value {
    /// Try to get this value as bytes.
    /// Strings are converted to UTF-8 bytes.
    pub fn as_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Value::Bytes(b) => Some(b.clone()),
            Value::String(s) => Some(s.as_bytes().to_vec()),
            _ => None,
        }
    }

    /// Try to get this value as a string.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get this value as an integer.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Check if this value is null.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Get a human-readable type name for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Bytes(_) => "bytes",
            Value::String(_) => "string",
            Value::Integer(_) => "integer",
            Value::Boolean(_) => "boolean",
            Value::Null => "null",
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Value::String(s) => write!(f, "{s}"),
            Value::Integer(i) => write!(f, "{i}"),
            Value::Boolean(b) => write!(f, "{b}"),
            Value::Null => write!(f, "null"),
        }
    }
}

// ============================================================================
// Expression Types
// ============================================================================

/// A parsed expression from ceremony YAML.
///
/// Expressions can be:
/// - Simple references: `${artifact.ksr}`
/// - Pipelines: `${artifact.ksr | sha256 | hex}`
/// - Function calls with arguments: `${concat(a | sha256, b | sha256) | hex}`
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// A simple reference to a parameter or artifact
    Reference(Reference),

    /// A literal value
    Literal(Literal),

    /// A pipeline of transformations
    Pipeline {
        /// The starting value (reference or literal)
        source: Box<Expression>,
        /// The transformation stages
        stages: Vec<PipeStage>,
    },
}

/// A reference to a ceremony value: `${type.name}` or `${type.name.property}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// The reference type (param, artifact, role)
    pub ref_type: RefType,
    /// The primary identifier
    pub name: String,
    /// Optional sub-property (e.g., `private` in `artifact.keypair.private`)
    pub property: Option<String>,
}

impl Reference {
    /// Create a new reference.
    pub fn new(ref_type: RefType, name: &str) -> Self {
        Self {
            ref_type,
            name: name.to_string(),
            property: None,
        }
    }

    /// Create a new reference with a property.
    pub fn with_property(ref_type: RefType, name: &str, property: &str) -> Self {
        Self {
            ref_type,
            name: name.to_string(),
            property: Some(property.to_string()),
        }
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(prop) = &self.property {
            write!(f, "{}.{}.{}", self.ref_type, self.name, prop)
        } else {
            write!(f, "{}.{}", self.ref_type, self.name)
        }
    }
}

/// A literal value in an expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    /// String literal (single or double quoted)
    String(String),
    /// Integer literal
    Integer(i64),
    /// Floating-point literal
    Float(f64),
    /// Boolean literal
    Boolean(bool),
    /// Null literal
    Null,
}

#[allow(clippy::cast_possible_truncation)]
impl From<Literal> for Value {
    fn from(lit: Literal) -> Self {
        match lit {
            Literal::String(s) => Value::String(s),
            Literal::Integer(i) => Value::Integer(i),
            Literal::Float(f) => Value::Integer(f as i64), // Truncate float to integer
            Literal::Boolean(b) => Value::Boolean(b),
            Literal::Null => Value::Null,
        }
    }
}

/// A stage in a pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct PipeStage {
    /// The function name
    pub function: String,
    /// Optional arguments to the function
    pub args: Vec<Expression>,
}

impl PipeStage {
    /// Create a new pipe stage with just a function name (no arguments).
    pub fn new(function: &str) -> Self {
        Self {
            function: function.to_string(),
            args: Vec::new(),
        }
    }

    /// Create a new pipe stage with arguments.
    pub fn with_args(function: &str, args: Vec<Expression>) -> Self {
        Self {
            function: function.to_string(),
            args,
        }
    }
}

/// An expression with its location in the source string.
#[derive(Debug, Clone, PartialEq)]
pub struct LocatedExpression {
    /// The parsed expression
    pub expression: Expression,
    /// Byte range in the source string
    pub range: Range<usize>,
}

// ============================================================================
// ExprValue Types (for resolver → runtime)
// ============================================================================

/// A value that may contain deferred expressions (parsed, not yet evaluated).
///
/// This is the bridge between the resolver and runtime: the resolver parses
/// all `${...}` patterns into structured expressions, and the runtime evaluates
/// them without any string parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprValue {
    /// Fully resolved literal (no expressions)
    Literal(Literal),
    /// Single expression (entire value is one expression)
    Expr(Expression),
    /// String with embedded expressions: `"Hash: ${artifact.x | sha256}"`
    Interpolated(Vec<StringPart>),
    /// Structured object with potentially deferred fields
    Object(std::collections::HashMap<String, ExprValue>),
    /// Array of values
    Array(Vec<ExprValue>),
}

impl ExprValue {
    /// Get the value as a literal string, if it is one.
    pub fn as_literal_string(&self) -> Option<&str> {
        match self {
            ExprValue::Literal(Literal::String(s)) => Some(s),
            _ => None,
        }
    }

    /// Get a field from an Object variant.
    pub fn get(&self, key: &str) -> Option<&ExprValue> {
        match self {
            ExprValue::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// Convert to a display string (for script generation, not evaluation).
    ///
    /// For literals, returns the literal value.
    /// For expressions, returns the expression syntax like `"${artifact.ksr | sha256}"`.
    pub fn to_display_string(&self) -> String {
        match self {
            ExprValue::Literal(Literal::String(s)) => s.clone(),
            ExprValue::Literal(Literal::Integer(i)) => i.to_string(),
            ExprValue::Literal(Literal::Float(f)) => f.to_string(),
            ExprValue::Literal(Literal::Boolean(b)) => b.to_string(),
            ExprValue::Literal(Literal::Null) => "null".to_string(),
            ExprValue::Expr(expr) => format!("${{{}}}", expr_to_string(expr)),
            ExprValue::Interpolated(parts) => parts
                .iter()
                .map(|p| match p {
                    StringPart::Literal(s) => s.clone(),
                    StringPart::Expr(expr) => format!("${{{}}}", expr_to_string(expr)),
                })
                .collect(),
            ExprValue::Object(_) => "[object]".to_string(),
            ExprValue::Array(_) => "[array]".to_string(),
        }
    }
}

/// Convert an `Expression` back to a string representation.
fn expr_to_string(expr: &Expression) -> String {
    match expr {
        Expression::Reference(r) => r.to_string(),
        Expression::Literal(Literal::String(s)) => format!("\"{s}\""),
        Expression::Literal(Literal::Integer(i)) => i.to_string(),
        Expression::Literal(Literal::Float(f)) => f.to_string(),
        Expression::Literal(Literal::Boolean(b)) => b.to_string(),
        Expression::Literal(Literal::Null) => "null".to_string(),
        Expression::Pipeline { source, stages } => {
            let mut result = expr_to_string(source);
            for stage in stages {
                result.push_str(" | ");
                result.push_str(&stage.function);
                if !stage.args.is_empty() {
                    result.push('(');
                    let args: Vec<_> = stage.args.iter().map(expr_to_string).collect();
                    result.push_str(&args.join(", "));
                    result.push(')');
                }
            }
            result
        }
    }
}

/// A part of an interpolated string.
#[derive(Debug, Clone, PartialEq)]
pub enum StringPart {
    /// Literal text
    Literal(String),
    /// Embedded expression
    Expr(Expression),
}

/// Parse an expression string.
///
/// The string should be in the form `${...}` containing a pipeline expression.
///
/// # Examples
///
/// ```
/// use rite_model::expression::{parse_expression, Expression, Reference, RefType, PipeStage};
///
/// // Simple reference
/// let expr = parse_expression("${artifact.ksr}").unwrap();
/// assert!(matches!(expr, Expression::Reference(_)));
///
/// // Pipeline
/// let expr = parse_expression("${artifact.ksr | sha256 | hex}").unwrap();
/// if let Expression::Pipeline { stages, .. } = expr {
///     assert_eq!(stages.len(), 2);
///     assert_eq!(stages[0].function, "sha256");
///     assert_eq!(stages[1].function, "hex");
/// }
/// ```
pub fn parse_expression(s: &str) -> Option<Expression> {
    let s = s.trim();

    // Must be wrapped in ${ }
    let inner = s.strip_prefix("${").and_then(|s| s.strip_suffix('}'))?;
    let inner = inner.trim();

    if inner.is_empty() {
        return None;
    }

    parse_pipeline(inner)
}

/// Parse a pipeline expression (without the `${ }` wrapper).
fn parse_pipeline(s: &str) -> Option<Expression> {
    let s = s.trim();

    // Split on pipe operator, being careful about nested parentheses.
    let parts = split_on_pipes(s);

    if parts.is_empty() {
        return None;
    }

    // First part is the source.
    let source = parse_source(parts.first()?.trim())?;

    if parts.len() == 1 {
        // No pipeline, just a source.
        return Some(source);
    }

    // Rest are pipe stages.
    let mut stages = Vec::new();
    for part in parts.iter().skip(1) {
        let stage = parse_pipe_stage(part.trim())?;
        stages.push(stage);
    }

    Some(Expression::Pipeline {
        source: Box::new(source),
        stages,
    })
}

/// Split a string on pipe operators, respecting parentheses.
fn split_on_pipes(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut paren_depth: u32 = 0;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b'|' if paren_depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }

    // Add the last part.
    if start < s.len() {
        parts.push(&s[start..]);
    }

    parts
}

/// Parse a source expression (reference, literal, or function call).
fn parse_source(s: &str) -> Option<Expression> {
    let s = s.trim();

    // Try to parse as a function call (for concat, etc.)
    if let Some(expr) = parse_function_call(s) {
        return Some(expr);
    }

    // Try to parse as a reference (namespace.name.property).
    if let Some(expr_ref) = parse_ref(s) {
        return Some(Expression::Reference(expr_ref));
    }

    // Try to parse as a literal.
    if let Some(lit) = parse_literal(s) {
        return Some(Expression::Literal(lit));
    }

    None
}

/// Parse a reference: `namespace.name` or `namespace.name.property`.
fn parse_ref(s: &str) -> Option<Reference> {
    let parts: Vec<&str> = s.splitn(3, '.').collect();

    if parts.len() < 2 {
        return None;
    }

    let namespace = parts[0];
    if !is_valid_identifier(namespace) {
        return None;
    }

    // Parse and validate namespace.
    let ref_type: RefType = namespace.parse().ok()?;

    let name = parts[1];
    if !is_valid_identifier(name) {
        return None;
    }

    let property = if parts.len() == 3 {
        let prop = parts[2];
        if !is_valid_identifier(prop) {
            return None;
        }
        Some(prop.to_string())
    } else {
        None
    };

    Some(Reference {
        ref_type,
        name: name.to_string(),
        property,
    })
}

/// Parse a literal value.
fn parse_literal(s: &str) -> Option<Literal> {
    let s = s.trim();

    // String literal (double or single quoted).
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        let inner = &s[1..s.len() - 1];
        return Some(Literal::String(inner.to_string()));
    }

    // Integer literal.
    if let Ok(i) = s.parse::<i64>() {
        return Some(Literal::Integer(i));
    }

    None
}

/// Parse a function call: `name(arg1, arg2, ...)`
fn parse_function_call(s: &str) -> Option<Expression> {
    let s = s.trim();

    // Find the opening paren.
    let paren_pos = s.find('(')?;
    let name = &s[..paren_pos];

    if !is_valid_identifier(name) {
        return None;
    }

    // Must end with closing paren.
    if !s.ends_with(')') {
        return None;
    }

    let args_str = &s[paren_pos + 1..s.len() - 1];

    // Parse arguments.
    let args = parse_function_args(args_str)?;

    // For functions like concat, the args ARE the sources, represented as a Pipeline
    // with a placeholder source and the function as the first stage.
    Some(Expression::Pipeline {
        source: Box::new(Expression::Literal(Literal::Integer(0))), // Placeholder
        stages: vec![PipeStage::with_args(name, args)],
    })
}

/// Parse function arguments, handling nested expressions.
fn parse_function_args(s: &str) -> Option<Vec<Expression>> {
    let s = s.trim();

    if s.is_empty() {
        return Some(Vec::new());
    }

    let mut args = Vec::new();
    let mut current_start = 0;
    let mut paren_depth: u32 = 0;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            b',' if paren_depth == 0 => {
                let arg = &s[current_start..i];
                let expr = parse_pipeline(arg.trim())?;
                args.push(expr);
                current_start = i + 1;
            }
            _ => {}
        }
    }

    // Add the last argument.
    if current_start < s.len() {
        let arg = &s[current_start..];
        let expr = parse_pipeline(arg.trim())?;
        args.push(expr);
    }

    Some(args)
}

/// Parse a pipe stage: `function` or `function(args)`.
fn parse_pipe_stage(s: &str) -> Option<PipeStage> {
    let s = s.trim();

    // Check for function with arguments.
    if let Some(paren_pos) = s.find('(') {
        let name = &s[..paren_pos];
        if !is_valid_identifier(name) {
            return None;
        }

        if !s.ends_with(')') {
            return None;
        }

        let args_str = &s[paren_pos + 1..s.len() - 1];
        let args = parse_function_args(args_str)?;

        return Some(PipeStage::with_args(name, args));
    }

    // Simple function name.
    if is_valid_identifier(s) {
        return Some(PipeStage::new(s));
    }

    None
}

/// Check if a string is a valid identifier (ASCII alphanumeric or underscore, not starting
/// with a digit).
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        None => false,
        Some(first) => {
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

/// Find all expressions in a string.
///
/// Returns expressions with their locations for LSP support.
pub fn find_expressions(s: &str) -> Vec<LocatedExpression> {
    let mut results = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Find matching closing brace.
            let mut depth = 1;
            let mut j = i + 2;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }

            if depth == 0 {
                let expr_str = &s[i..j];
                if let Some(expression) = parse_expression(expr_str) {
                    results.push(LocatedExpression {
                        expression,
                        range: i..j,
                    });
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }

    results
}

// ============================================================================
// ExprValue Parsing (JSON → ExprValue)
// ============================================================================

/// Parse a `JSON` value into an `ExprValue`, extracting all `${...}` expressions.
///
/// This function recursively converts `JSON` into `ExprValue`:
/// - Strings containing `${...}` become `Expr` (if entire string) or `Interpolated` (if mixed)
/// - Plain strings become `Literal(String)`
/// - Numbers, bools, null become their `Literal` equivalents
/// - Objects and arrays are recursed into
///
/// # Examples
///
/// ```
/// use rite_model::expression::{parse_expr_value, ExprValue, Literal};
///
/// // Plain string → Literal
/// let json = serde_json::json!("hello");
/// let expr = parse_expr_value(&json);
/// assert!(matches!(expr, ExprValue::Literal(Literal::String(_))));
///
/// // Expression string → Expr
/// let json = serde_json::json!("${artifact.ksr | sha256}");
/// let expr = parse_expr_value(&json);
/// assert!(matches!(expr, ExprValue::Expr(_)));
/// ```
pub fn parse_expr_value(json: &serde_json::Value) -> ExprValue {
    match json {
        serde_json::Value::String(s) => parse_string_to_expr_value(s),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ExprValue::Literal(Literal::Integer(i))
            } else if let Some(f) = n.as_f64() {
                ExprValue::Literal(Literal::Float(f))
            } else {
                // Fallback for very large numbers — truncate to 0.
                ExprValue::Literal(Literal::Integer(0))
            }
        }
        serde_json::Value::Bool(b) => ExprValue::Literal(Literal::Boolean(*b)),
        serde_json::Value::Null => ExprValue::Literal(Literal::Null),
        serde_json::Value::Object(map) => {
            let mut result = std::collections::HashMap::new();
            for (k, v) in map {
                result.insert(k.clone(), parse_expr_value(v));
            }
            ExprValue::Object(result)
        }
        serde_json::Value::Array(arr) => {
            let result: Vec<_> = arr.iter().map(parse_expr_value).collect();
            ExprValue::Array(result)
        }
    }
}

/// Parse a string into an `ExprValue`.
///
/// Handles three cases:
/// 1. Entire string is one expression: `${...}` → `ExprValue::Expr`
/// 2. String contains expressions: `"Hash: ${...}"` → `ExprValue::Interpolated`
/// 3. Plain string: `"hello"` → `ExprValue::Literal`
fn parse_string_to_expr_value(s: &str) -> ExprValue {
    let trimmed = s.trim();

    // Case 1: Entire string is a single expression.
    if trimmed.starts_with("${")
        && trimmed.ends_with('}')
        && !trimmed[2..trimmed.len() - 1].contains("${")
        && let Some(expr) = parse_expression(trimmed)
    {
        return ExprValue::Expr(expr);
    }

    // Case 2: String contains embedded expressions.
    if s.contains("${") {
        let parts = parse_interpolated_string(s);
        if parts.len() == 1 {
            // Single literal part.
            if let StringPart::Literal(lit) = &parts[0] {
                return ExprValue::Literal(Literal::String(lit.clone()));
            }
        }
        return ExprValue::Interpolated(parts);
    }

    // Case 3: Plain string.
    ExprValue::Literal(Literal::String(s.to_string()))
}

/// Parse an interpolated string into parts.
///
/// `"Hello ${param.name}!"` → `[Literal("Hello "), Expr(...), Literal("!")]`
fn parse_interpolated_string(s: &str) -> Vec<StringPart> {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let mut last_end = 0;
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Push literal part before this expression.
            if i > last_end {
                parts.push(StringPart::Literal(s[last_end..i].to_string()));
            }

            // Find matching closing brace.
            let mut depth = 1;
            let mut j = i + 2;
            while j < bytes.len() && depth > 0 {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                j += 1;
            }

            if depth == 0 {
                let expr_str = &s[i..j];
                if let Some(expr) = parse_expression(expr_str) {
                    parts.push(StringPart::Expr(expr));
                } else {
                    // Failed to parse — keep as literal.
                    parts.push(StringPart::Literal(expr_str.to_string()));
                }
                last_end = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }

    // Push remaining literal part.
    if last_end < s.len() {
        parts.push(StringPart::Literal(s[last_end..].to_string()));
    }

    parts
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_reference() {
        let expr = parse_expression("${artifact.ksr}").unwrap();
        match expr {
            Expression::Reference(r) => {
                assert_eq!(r.ref_type, RefType::Artifact);
                assert_eq!(r.name, "ksr");
                assert!(r.property.is_none());
            }
            _ => panic!("Expected Reference"),
        }
    }

    #[test]
    fn parse_reference_with_property() {
        let expr = parse_expression("${artifact.keypair.private}").unwrap();
        match expr {
            Expression::Reference(r) => {
                assert_eq!(r.ref_type, RefType::Artifact);
                assert_eq!(r.name, "keypair");
                assert_eq!(r.property, Some("private".to_string()));
            }
            _ => panic!("Expected Reference"),
        }
    }

    #[test]
    fn parse_param_reference() {
        let expr = parse_expression("${param.key_label}").unwrap();
        match expr {
            Expression::Reference(r) => {
                assert_eq!(r.ref_type, RefType::Param);
                assert_eq!(r.name, "key_label");
            }
            _ => panic!("Expected Reference"),
        }
    }

    #[test]
    fn parse_simple_pipeline() {
        let expr = parse_expression("${artifact.ksr | sha256}").unwrap();
        match expr {
            Expression::Pipeline { source, stages } => {
                assert!(matches!(*source, Expression::Reference(_)));
                assert_eq!(stages.len(), 1);
                assert_eq!(stages[0].function, "sha256");
                assert!(stages[0].args.is_empty());
            }
            _ => panic!("Expected Pipeline"),
        }
    }

    #[test]
    fn parse_multi_stage_pipeline() {
        let expr = parse_expression("${artifact.ksr | sha256 | hex}").unwrap();
        match expr {
            Expression::Pipeline { stages, .. } => {
                assert_eq!(stages.len(), 2);
                assert_eq!(stages[0].function, "sha256");
                assert_eq!(stages[1].function, "hex");
            }
            _ => panic!("Expected Pipeline"),
        }
    }

    #[test]
    fn parse_pipeline_with_function_args() {
        let expr = parse_expression("${artifact.data | substr(0, 16)}").unwrap();
        match expr {
            Expression::Pipeline { stages, .. } => {
                assert_eq!(stages.len(), 1);
                assert_eq!(stages[0].function, "substr");
                assert_eq!(stages[0].args.len(), 2);
            }
            _ => panic!("Expected Pipeline"),
        }
    }

    #[test]
    fn parse_complex_pipeline() {
        let expr =
            parse_expression("${artifact.keypair.public | fingerprint | hex | upper}").unwrap();
        match expr {
            Expression::Pipeline { source, stages } => {
                if let Expression::Reference(r) = *source {
                    assert_eq!(r.name, "keypair");
                    assert_eq!(r.property, Some("public".to_string()));
                }
                assert_eq!(stages.len(), 3);
                assert_eq!(stages[0].function, "fingerprint");
                assert_eq!(stages[1].function, "hex");
                assert_eq!(stages[2].function, "upper");
            }
            _ => panic!("Expected Pipeline"),
        }
    }

    #[test]
    fn parse_invalid_expression() {
        assert!(parse_expression("not an expression").is_none());
        assert!(parse_expression("${").is_none());
        assert!(parse_expression("${}").is_none());
        assert!(parse_expression("${invalid}").is_none()); // No namespace
    }

    #[test]
    fn find_expressions_in_string() {
        let exprs = find_expressions("Hash: ${artifact.ksr | sha256 | hex}");
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].range.start, 6);
    }

    #[test]
    fn find_multiple_expressions() {
        let exprs = find_expressions("${artifact.a | sha256 | hex}-${artifact.b | sha256 | hex}");
        assert_eq!(exprs.len(), 2);
    }

    #[test]
    fn value_type_names() {
        assert_eq!(Value::Bytes(vec![]).type_name(), "bytes");
        assert_eq!(Value::String(String::new()).type_name(), "string");
        assert_eq!(Value::Integer(0).type_name(), "integer");
        assert_eq!(Value::Boolean(true).type_name(), "boolean");
        assert_eq!(Value::Null.type_name(), "null");
    }

    #[test]
    fn value_as_bytes() {
        let v = Value::Bytes(vec![1, 2, 3]);
        assert_eq!(v.as_bytes(), Some(vec![1, 2, 3]));

        let v = Value::String("hello".into());
        assert_eq!(v.as_bytes(), Some(b"hello".to_vec()));

        let v = Value::Integer(42);
        assert!(v.as_bytes().is_none());
    }

    // =========================================================================
    // Tests based on actual ceremony examples
    // =========================================================================

    mod ceremony_examples {
        use super::*;

        // From dnssec_signing/dnssec_signing.rite.yaml
        #[test]
        fn dnssec_hash_verification() {
            // actual: "${artifact.ksr | sha256 | hex | substr(0, 16)}"
            let expr = parse_expression("${artifact.ksr | sha256 | hex | substr(0, 16)}").unwrap();
            match expr {
                Expression::Pipeline { source, stages } => {
                    if let Expression::Reference(r) = *source {
                        assert_eq!(r.ref_type, RefType::Artifact);
                        assert_eq!(r.name, "ksr");
                    } else {
                        panic!("Expected Reference source");
                    }
                    // 3 stages: sha256, hex, substr
                    assert_eq!(stages.len(), 3);
                    assert_eq!(stages[0].function, "sha256");
                    assert_eq!(stages[1].function, "hex");
                    assert_eq!(stages[2].function, "substr");
                    assert_eq!(stages[2].args.len(), 2);
                }
                _ => panic!("Expected Pipeline"),
            }
        }

        #[test]
        fn dnssec_param_reference() {
            // expected: "${param.expected_ksr_hash}"
            let expr = parse_expression("${param.expected_ksr_hash}").unwrap();
            match expr {
                Expression::Reference(r) => {
                    assert_eq!(r.ref_type, RefType::Param);
                    assert_eq!(r.name, "expected_ksr_hash");
                }
                _ => panic!("Expected Reference"),
            }
        }

        #[test]
        fn dnssec_oral_readback() {
            // value: "${artifact.ksr | sha256 | hex}"
            let expr = parse_expression("${artifact.ksr | sha256 | hex}").unwrap();
            match expr {
                Expression::Pipeline { stages, .. } => {
                    assert_eq!(stages.len(), 2);
                    assert_eq!(stages[0].function, "sha256");
                    assert_eq!(stages[1].function, "hex");
                }
                _ => panic!("Expected Pipeline"),
            }
        }

        // From airgapped_hsm/airgapped_hsm.rite.yaml
        #[test]
        fn hsm_artifact_reference() {
            // input: ${artifact.master_keypair}
            let expr = parse_expression("${artifact.master_keypair}").unwrap();
            match expr {
                Expression::Reference(r) => {
                    assert_eq!(r.ref_type, RefType::Artifact);
                    assert_eq!(r.name, "master_keypair");
                    assert!(r.property.is_none());
                }
                _ => panic!("Expected Reference"),
            }
        }

        #[test]
        fn hsm_public_key_fingerprint() {
            // value: "${artifact.master_public_key | sha256 | hex}"
            let expr = parse_expression("${artifact.master_public_key | sha256 | hex}").unwrap();
            match expr {
                Expression::Pipeline { source, stages } => {
                    if let Expression::Reference(r) = *source {
                        assert_eq!(r.name, "master_public_key");
                    }
                    assert_eq!(stages.len(), 2);
                }
                _ => panic!("Expected Pipeline"),
            }
        }

        // From crypto_test/crypto_test.rite.yaml
        #[test]
        fn crypto_artifact_with_property() {
            // key_to_wrap: ${artifact.keypair.private}
            let expr = parse_expression("${artifact.keypair.private}").unwrap();
            match expr {
                Expression::Reference(r) => {
                    assert_eq!(r.ref_type, RefType::Artifact);
                    assert_eq!(r.name, "keypair");
                    assert_eq!(r.property, Some("private".to_string()));
                }
                _ => panic!("Expected Reference"),
            }
        }

        // String interpolation patterns
        #[test]
        fn find_embedded_expressions() {
            // message: "Verify serial number: ${param.hsm_serial}"
            let exprs = find_expressions("Verify serial number: ${param.hsm_serial}");
            assert_eq!(exprs.len(), 1);
            if let Expression::Reference(r) = &exprs[0].expression {
                assert_eq!(r.ref_type, RefType::Param);
                assert_eq!(r.name, "hsm_serial");
            }
        }

        #[test]
        fn find_multiple_embedded_params() {
            // "Key ${param.key_label} for HSM ${param.hsm_serial}"
            let exprs = find_expressions("Key ${param.key_label} for HSM ${param.hsm_serial}");
            assert_eq!(exprs.len(), 2);
        }

        // Role references (namespace = "role" - used in validation, not expressions)
        #[test]
        fn role_reference_parses() {
            let expr = parse_expression("${role.ceremony_admin}").unwrap();
            match expr {
                Expression::Reference(r) => {
                    assert_eq!(r.ref_type, RefType::Role);
                    assert_eq!(r.name, "ceremony_admin");
                }
                _ => panic!("Expected Reference"),
            }
        }
    }

    // =========================================================================
    // Tests for ExprValue parsing
    // =========================================================================

    mod expr_value_tests {
        use super::*;

        #[test]
        fn parse_literal_string() {
            let json = serde_json::json!("hello");
            let expr = parse_expr_value(&json);
            assert!(matches!(expr, ExprValue::Literal(Literal::String(s)) if s == "hello"));
        }

        #[test]
        fn parse_literal_integer() {
            let json = serde_json::json!(42);
            let expr = parse_expr_value(&json);
            assert!(matches!(expr, ExprValue::Literal(Literal::Integer(42))));
        }

        #[test]
        fn parse_literal_float() {
            let json = serde_json::json!(1.5);
            let expr = parse_expr_value(&json);
            assert!(
                matches!(expr, ExprValue::Literal(Literal::Float(f)) if (f - 1.5).abs() < 0.001)
            );
        }

        #[test]
        fn parse_literal_boolean() {
            let json = serde_json::json!(true);
            let expr = parse_expr_value(&json);
            assert!(matches!(expr, ExprValue::Literal(Literal::Boolean(true))));
        }

        #[test]
        fn parse_literal_null() {
            let json = serde_json::Value::Null;
            let expr = parse_expr_value(&json);
            assert!(matches!(expr, ExprValue::Literal(Literal::Null)));
        }

        #[test]
        fn parse_single_expression() {
            let json = serde_json::json!("${artifact.ksr | sha256}");
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Expr(Expression::Pipeline { source, stages }) => {
                    assert!(matches!(*source, Expression::Reference(_)));
                    assert_eq!(stages.len(), 1);
                    assert_eq!(stages[0].function, "sha256");
                }
                _ => panic!("Expected Expr(Pipeline), got {expr:?}"),
            }
        }

        #[test]
        fn parse_simple_reference() {
            let json = serde_json::json!("${param.name}");
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Expr(Expression::Reference(r)) => {
                    assert_eq!(r.ref_type, RefType::Param);
                    assert_eq!(r.name, "name");
                }
                _ => panic!("Expected Expr(Reference), got {expr:?}"),
            }
        }

        #[test]
        fn parse_interpolated_string() {
            let json = serde_json::json!("Hello, ${param.name}!");
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Interpolated(parts) => {
                    assert_eq!(parts.len(), 3);
                    assert!(matches!(&parts[0], StringPart::Literal(s) if s == "Hello, "));
                    assert!(matches!(
                        &parts[1],
                        StringPart::Expr(Expression::Reference(_))
                    ));
                    assert!(matches!(&parts[2], StringPart::Literal(s) if s == "!"));
                }
                _ => panic!("Expected Interpolated, got {expr:?}"),
            }
        }

        #[test]
        fn parse_object_with_expressions() {
            let json = serde_json::json!({
                "actual": "${artifact.ksr | sha256 | hex}",
                "expected": "${param.expected_hash}",
                "static": "hello"
            });
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Object(map) => {
                    assert!(matches!(map.get("actual"), Some(ExprValue::Expr(_))));
                    assert!(matches!(map.get("expected"), Some(ExprValue::Expr(_))));
                    assert!(matches!(
                        map.get("static"),
                        Some(ExprValue::Literal(Literal::String(_)))
                    ));
                }
                _ => panic!("Expected Object, got {expr:?}"),
            }
        }

        #[test]
        fn parse_array_with_expressions() {
            let json = serde_json::json!(["${param.a}", "static", "${param.b}"]);
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Array(arr) => {
                    assert_eq!(arr.len(), 3);
                    assert!(matches!(&arr[0], ExprValue::Expr(_)));
                    assert!(matches!(&arr[1], ExprValue::Literal(Literal::String(_))));
                    assert!(matches!(&arr[2], ExprValue::Expr(_)));
                }
                _ => panic!("Expected Array, got {expr:?}"),
            }
        }

        #[test]
        fn parse_multiple_expressions_in_string() {
            let json = serde_json::json!("${param.a} and ${param.b}");
            let expr = parse_expr_value(&json);
            match expr {
                ExprValue::Interpolated(parts) => {
                    assert_eq!(parts.len(), 3);
                    assert!(matches!(&parts[0], StringPart::Expr(_)));
                    assert!(matches!(&parts[1], StringPart::Literal(s) if s == " and "));
                    assert!(matches!(&parts[2], StringPart::Expr(_)));
                }
                _ => panic!("Expected Interpolated, got {expr:?}"),
            }
        }
    }
}
