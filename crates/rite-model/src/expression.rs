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
//! The formal grammar is documented in `docs/dsl/grammar.md` (not yet published).

// The expression parser uses byte-index arithmetic and slice indexing throughout.
// All indices are guarded by length checks and loop bounds; the operations cannot
// overflow or panic in practice. Suppressed here to avoid obscuring the parser logic.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use std::ops::Range;

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

impl RefType {
    /// Every namespace, in the order messages list them.
    ///
    /// A test matches exhaustively over `RefType` against this list, so a new
    /// variant fails to compile until it is added here.
    pub const ALL: &'static [Self] = &[Self::Param, Self::Role, Self::Artifact];

    /// The namespace as it is written in a ceremony.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Param => "param",
            Self::Role => "role",
            Self::Artifact => "artifact",
        }
    }
}

impl std::str::FromStr for RefType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|ref_type| ref_type.as_str() == s)
            .ok_or_else(|| format!("unknown reference type: {s}"))
    }
}

impl std::fmt::Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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

/// Why a `${...}` occurrence is not a usable expression.
///
/// Each variant names one decision the parser made, so a caller can tell an
/// unknown namespace from a malformed name without reading the message text.
/// [`Display`](std::fmt::Display) renders the sentence a diagnostic shows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExprError {
    /// The text is not wrapped in `${` and `}`.
    NotAnExpression,
    /// Nothing closes the occurrence.
    Unclosed,
    /// The braces hold nothing.
    Empty,
    /// A pipeline has stages but nothing to compute them from.
    MissingSource,
    /// A quoted string never closes.
    UnterminatedString {
        /// The quote character that opened it.
        quote: char,
    },
    /// The text before a `(` is not a function name.
    InvalidFunctionName {
        /// The text as written.
        name: String,
    },
    /// A function call never closes its parentheses.
    UnclosedCall {
        /// The function named.
        function: String,
    },
    /// One argument to a function call is not an expression.
    InvalidArgument {
        /// The function named.
        function: String,
        /// Which argument, counting from one.
        position: usize,
        /// Why that argument is not an expression.
        cause: Box<ExprError>,
    },
    /// A name stands on its own, with no namespace in front of it.
    MissingNamespace {
        /// The text as written.
        text: String,
    },
    /// The text is neither a literal nor the start of a reference.
    NotAReference {
        /// The text as written.
        text: String,
    },
    /// The namespace is not one this DSL has.
    UnknownNamespace {
        /// The namespace as written.
        namespace: String,
    },
    /// A reference names `material`, which is not a namespace.
    MaterialNamespace {
        /// The namespace as written, which may be a misspelling.
        namespace: String,
        /// The name that followed it.
        name: String,
    },
    /// Nothing follows the namespace.
    EmptyName {
        /// The namespace as written.
        namespace: String,
    },
    /// The name is not an identifier.
    InvalidName {
        /// The name as written.
        name: String,
    },
    /// The property is not an identifier.
    InvalidProperty {
        /// The property as written.
        property: String,
    },
    /// A pipe stage is not a function name.
    InvalidPipeStage {
        /// The stage as written.
        stage: String,
    },
}

/// What a name inside a reference may contain, quoted in messages about one
/// that does not qualify.
const IDENTIFIER_RULE: &str =
    "names hold letters, digits, and underscores, and cannot start with a digit";

impl std::fmt::Display for ExprError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnExpression => write!(
                f,
                "write it as an expression, '${{<namespace>.<name>}}', \
                 where <namespace> is one of {}",
                namespace_list()
            ),
            Self::Unclosed => write!(f, "the expression is missing its closing '}}'"),
            Self::Empty => write!(f, "the expression is empty"),
            Self::MissingSource => write!(
                f,
                "nothing comes before the '|': a pipeline starts from a value"
            ),
            Self::UnterminatedString { quote } => {
                write!(f, "the string is missing its closing {quote}")
            }
            Self::InvalidFunctionName { name } => {
                write!(f, "'{name}' is not a usable function name")
            }
            Self::UnclosedCall { function } => {
                write!(f, "the call to '{function}' is missing its closing ')'")
            }
            Self::InvalidArgument {
                function,
                position,
                cause,
            } => write!(
                f,
                "argument {position} to '{function}' is not a usable expression: {cause}"
            ),
            Self::MissingNamespace { text } => write!(
                f,
                "'{text}' names no namespace: write '<namespace>.<name>', \
                 where <namespace> is one of {}",
                namespace_list()
            ),
            Self::NotAReference { text } => write!(
                f,
                "'{text}' is neither a literal nor a reference: a reference starts with \
                 one of {}",
                namespace_list()
            ),
            Self::UnknownNamespace { namespace } => match nearest_namespace(namespace) {
                Some(known) => {
                    write!(
                        f,
                        "unknown namespace '{namespace}': did you mean '{known}'?"
                    )
                }
                None => write!(
                    f,
                    "unknown namespace '{namespace}': expected one of {}",
                    namespace_list()
                ),
            },
            Self::MaterialNamespace { namespace, name } => write!(
                f,
                "there is no '{namespace}' namespace: a material is read as 'artifact.{name}'"
            ),
            Self::EmptyName { namespace } => {
                write!(f, "nothing follows '{namespace}.': expected a name")
            }
            Self::InvalidName { name } => {
                write!(f, "'{name}' is not a usable name: {IDENTIFIER_RULE}")
            }
            Self::InvalidProperty { property } => {
                write!(
                    f,
                    "'{property}' is not a usable property: {IDENTIFIER_RULE}"
                )
            }
            Self::InvalidPipeStage { stage } => write!(
                f,
                "'{stage}' is not a usable pipe stage: expected a function name, \
                 with any arguments in parentheses"
            ),
        }
    }
}

impl ExprError {
    /// The namespace this failure was close enough to have been meant as.
    ///
    /// An editor offers it as a fix. The message says the same thing, so the
    /// two cannot disagree.
    #[must_use]
    pub fn suggestion(&self) -> Option<RefType> {
        match self {
            Self::UnknownNamespace { namespace } => nearest_namespace(namespace),
            // A material is read as an artifact, so the namespace to write is
            // known outright rather than guessed at.
            Self::MaterialNamespace { .. } => Some(RefType::Artifact),
            Self::NotAnExpression
            | Self::Unclosed
            | Self::Empty
            | Self::MissingSource
            | Self::UnterminatedString { .. }
            | Self::InvalidFunctionName { .. }
            | Self::UnclosedCall { .. }
            | Self::InvalidArgument { .. }
            | Self::MissingNamespace { .. }
            | Self::NotAReference { .. }
            | Self::EmptyName { .. }
            | Self::InvalidName { .. }
            | Self::InvalidProperty { .. }
            | Self::InvalidPipeStage { .. } => None,
        }
    }
}

impl std::error::Error for ExprError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidArgument { cause, .. } => Some(cause.as_ref()),
            Self::NotAnExpression
            | Self::Unclosed
            | Self::Empty
            | Self::MissingSource
            | Self::UnterminatedString { .. }
            | Self::InvalidFunctionName { .. }
            | Self::UnclosedCall { .. }
            | Self::MissingNamespace { .. }
            | Self::NotAReference { .. }
            | Self::UnknownNamespace { .. }
            | Self::MaterialNamespace { .. }
            | Self::EmptyName { .. }
            | Self::InvalidName { .. }
            | Self::InvalidProperty { .. }
            | Self::InvalidPipeStage { .. } => None,
        }
    }
}

/// The namespaces a reference can name, formatted for a message.
fn namespace_list() -> String {
    RefType::ALL
        .iter()
        .map(|ref_type| ref_type.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse an expression string.
///
/// The string should be in the form `${...}` containing a pipeline expression.
/// Returns `None` for anything else; [`parse_expression_detailed`] returns the
/// reason instead.
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
    parse_expression_detailed(s).ok()
}

/// Parse an expression string, reporting why it is not one.
///
/// The counterpart to [`parse_expression`], for callers that put the failure in
/// front of an author. Accepts exactly the same strings.
///
/// # Examples
///
/// ```
/// use rite_model::expression::{parse_expression_detailed, ExprError, RefType};
///
/// let err = parse_expression_detailed("${nonsense.x}").unwrap_err();
/// assert!(matches!(err, ExprError::UnknownNamespace { .. }));
///
/// let err = parse_expression_detailed("${paramm.region}").unwrap_err();
/// assert_eq!(err.to_string(), "unknown namespace 'paramm': did you mean 'param'?");
/// ```
///
/// # Errors
///
/// Returns the [`ExprError`] naming the first thing that did not parse.
pub fn parse_expression_detailed(s: &str) -> Result<Expression, ExprError> {
    // Text that never opened an expression is a different mistake from text
    // that opened one and did not close it, and only the wrapper knows which.
    let Some(rest) = s.trim().strip_prefix("${") else {
        return Err(ExprError::NotAnExpression);
    };
    let Some(inner) = rest.strip_suffix('}') else {
        return Err(ExprError::Unclosed);
    };

    parse_pipeline(inner)
}

/// Parse a pipeline expression (without the `${ }` wrapper).
fn parse_pipeline(s: &str) -> Result<Expression, ExprError> {
    let s = s.trim();

    // Split on pipe operator, being careful about nested parentheses.
    let parts = split_top_level(s, b'|');
    let first = parts.first().copied().unwrap_or("").trim();

    // An empty source with stages after it is a pipeline that starts from
    // nothing, which is a different mistake from an empty `${}`.
    if first.is_empty() && parts.len() > 1 {
        return Err(ExprError::MissingSource);
    }

    let source = parse_source(first)?;
    if parts.len() == 1 {
        // No pipeline, just a source.
        return Ok(source);
    }

    let mut stages = Vec::with_capacity(parts.len().saturating_sub(1));
    for part in parts.iter().skip(1) {
        stages.push(parse_pipe_stage(part.trim())?);
    }

    Ok(Expression::Pipeline {
        source: Box::new(source),
        stages,
    })
}

/// Split a string on `delimiter`, ignoring any inside parentheses.
///
/// Serves both delimiters the grammar has: `|` between pipeline stages and `,`
/// between call arguments. An empty string splits into nothing.
fn split_top_level(s: &str, delimiter: u8) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut paren_depth: u32 = 0;
    let bytes = s.as_bytes();

    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => paren_depth += 1,
            b')' => paren_depth = paren_depth.saturating_sub(1),
            _ if b == delimiter && paren_depth == 0 => {
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

/// Parse the part of a pipeline before the first `|`.
///
/// A source is a quoted string, an integer, a function call, or a reference.
/// Which one is decided from the text before any of them is parsed: a quote
/// opens a string, a name followed by `(` opens a call, and a dot separates a
/// namespace from a name. A failure then reports the shape the author reached
/// for.
fn parse_source(s: &str) -> Result<Expression, ExprError> {
    let s = s.trim();

    if s.is_empty() {
        return Err(ExprError::Empty);
    }

    if let Some(quote) = s.chars().next().filter(|c| *c == '"' || *c == '\'') {
        return parse_string_literal(s, quote).map(Expression::Literal);
    }

    if let Some(paren) = s.find('(')
        && is_valid_identifier(&s[..paren])
    {
        // The arguments are the sources, so the source slot holds a placeholder.
        return parse_call(s, paren).map(|stage| Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::Integer(0))),
            stages: vec![stage],
        });
    }

    if let Some((namespace, rest)) = s.split_once('.') {
        return parse_ref(namespace, rest).map(Expression::Reference);
    }

    if let Ok(value) = s.parse::<i64>() {
        return Ok(Expression::Literal(Literal::Integer(value)));
    }

    // A bare name is a reference that lost its namespace, which is a different
    // mistake from text that was never going to be one.
    if is_valid_identifier(s) {
        return Err(ExprError::MissingNamespace {
            text: s.to_string(),
        });
    }

    Err(ExprError::NotAReference {
        text: s.to_string(),
    })
}

/// Parse a reference split at its first dot: `name` or `name.property`.
fn parse_ref(namespace: &str, rest: &str) -> Result<Reference, ExprError> {
    // Not a name at all, so it was never a reference. Says so rather than
    // reporting an unknown namespace, which would send the author looking for
    // the wrong mistake.
    if !is_valid_identifier(namespace) {
        return Err(ExprError::NotAReference {
            text: format!("{namespace}.{rest}"),
        });
    }

    let (name, property) = match rest.split_once('.') {
        Some((name, property)) => (name, Some(property)),
        None => (rest, None),
    };

    let Ok(ref_type) = namespace.parse::<RefType>() else {
        return Err(unknown_namespace(namespace, name));
    };

    if name.is_empty() {
        return Err(ExprError::EmptyName {
            namespace: namespace.to_string(),
        });
    }
    if !is_valid_identifier(name) {
        return Err(ExprError::InvalidName {
            name: name.to_string(),
        });
    }

    if let Some(property) = property
        && !is_valid_identifier(property)
    {
        return Err(ExprError::InvalidProperty {
            property: property.to_string(),
        });
    }

    Ok(Reference {
        ref_type,
        name: name.to_string(),
        property: property.map(ToString::to_string),
    })
}

/// Classify a namespace that is not one this DSL has.
fn unknown_namespace(namespace: &str, name: &str) -> ExprError {
    // `material` is the namespace an author reaches for that does not exist:
    // materials are declared under `materials:` and read as artifacts, so the
    // mistake is worth naming rather than guessing at. Matched within one edit
    // so that the plural, which is what the declaring key is called, lands on
    // the same explanation.
    if edit_distance(namespace, "material") <= 1 {
        return ExprError::MaterialNamespace {
            namespace: namespace.to_string(),
            name: name.to_string(),
        };
    }

    ExprError::UnknownNamespace {
        namespace: namespace.to_string(),
    }
}

/// The namespace `s` was close enough to have been meant as, if any.
///
/// Close enough is an edit distance of one or two, which covers a doubled or
/// dropped letter and a plural. Anything further is reported as unknown rather
/// than guessed at.
fn nearest_namespace(s: &str) -> Option<RefType> {
    RefType::ALL
        .iter()
        .map(|known| (*known, edit_distance(s, known.as_str())))
        .filter(|(_, distance)| *distance <= 2)
        .min_by_key(|(_, distance)| *distance)
        .map(|(known, _)| known)
}

/// Levenshtein distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b_chars.len()).collect();
    let mut current = vec![0; b_chars.len() + 1];

    for (i, a_char) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b_chars.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != *b_char);
            let deletion = previous[j + 1] + 1;
            let insertion = current[j] + 1;
            current[j + 1] = substitution.min(deletion).min(insertion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b_chars.len()]
}

/// Parse a quoted string literal, given the quote character that opened it.
fn parse_string_literal(s: &str, quote: char) -> Result<Literal, ExprError> {
    // Both quote characters are one byte, so the closing one cannot be the
    // opening one read twice: a lone quote is unterminated.
    if s.len() < 2 || !s.ends_with(quote) {
        return Err(ExprError::UnterminatedString { quote });
    }

    Ok(Literal::String(s[1..s.len() - 1].to_string()))
}

/// Parse a call `name(arg, ...)`, given the position of its `(`.
///
/// Serves both positions a call appears in: as a pipeline source, where the
/// arguments are the sources, and as a pipe stage.
fn parse_call(s: &str, paren: usize) -> Result<PipeStage, ExprError> {
    let name = &s[..paren];

    if !is_valid_identifier(name) {
        return Err(ExprError::InvalidFunctionName {
            name: name.to_string(),
        });
    }
    if !s.ends_with(')') {
        return Err(ExprError::UnclosedCall {
            function: name.to_string(),
        });
    }

    // Trimmed first so that `f(  )` splits into no arguments rather than one
    // blank one.
    let args = split_top_level(s[paren + 1..s.len() - 1].trim(), b',')
        .into_iter()
        .enumerate()
        .map(|(index, arg)| {
            parse_pipeline(arg.trim()).map_err(|cause| ExprError::InvalidArgument {
                function: name.to_string(),
                position: index + 1,
                cause: Box::new(cause),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PipeStage::with_args(name, args))
}

/// Parse a pipe stage: `function` or `function(args)`.
fn parse_pipe_stage(s: &str) -> Result<PipeStage, ExprError> {
    let s = s.trim();

    if let Some(paren) = s.find('(') {
        return parse_call(s, paren);
    }

    // Simple function name.
    if is_valid_identifier(s) {
        return Ok(PipeStage::new(s));
    }

    Err(ExprError::InvalidPipeStage {
        stage: s.to_string(),
    })
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

/// A `${...}` occurrence located in a scalar, with the result of parsing it.
struct Occurrence<'a> {
    range: Range<usize>,
    text: &'a str,
    parsed: Result<Expression, ExprError>,
}

/// Find every `${...}` occurrence in `s`, parsed or not.
///
/// The one place that decides where an occurrence starts and ends. Braces are
/// balanced rather than stopping at the first `}`, so a `}` inside the
/// expression does not cut it short. An occurrence nothing closes runs to the
/// end of the string and parses as nothing.
fn scan_occurrences(s: &str) -> Vec<Occurrence<'_>> {
    let mut found = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
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

            // An unbalanced `${a{b}` is not closed even though its text ends in
            // a brace, and has no closing brace to parse against.
            let closed = depth == 0;
            let end = if closed { j } else { s.len() };
            let text = &s[i..end];
            found.push(Occurrence {
                range: i..end,
                text,
                parsed: if closed {
                    parse_expression_detailed(text)
                } else {
                    Err(ExprError::Unclosed)
                },
            });
            i = end;
            continue;
        }
        i += 1;
    }

    found
}

/// Find all expressions in a string.
///
/// Returns expressions with their locations for LSP support.
pub fn find_expressions(s: &str) -> Vec<LocatedExpression> {
    scan_occurrences(s)
        .into_iter()
        .filter_map(|occurrence| {
            Some(LocatedExpression {
                expression: occurrence.parsed.ok()?,
                range: occurrence.range,
            })
        })
        .collect()
}

/// A `${...}` occurrence that does not parse as an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidExpression {
    /// Byte range of the occurrence within the scanned string.
    pub range: Range<usize>,
    /// The occurrence as written, including the `${` and the `}`.
    pub text: String,
    /// Why it is not a usable expression.
    pub reason: ExprError,
}

/// Find every `${...}` in `s` that does not parse as an expression.
///
/// The counterpart to [`find_expressions`], which keeps the occurrences that do
/// parse. `${` always opens an expression, so an occurrence that fails to parse
/// is a mistake rather than prose, and a caller reports each one it gets back.
///
/// # Examples
///
/// ```
/// use rite_model::expression::find_invalid_expressions;
///
/// assert!(find_invalid_expressions("${artifact.ksr | sha256}").is_empty());
///
/// let found = find_invalid_expressions("sign ${nonsense.x} now");
/// assert_eq!(found.len(), 1);
/// assert_eq!(found[0].text, "${nonsense.x}");
/// ```
pub fn find_invalid_expressions(s: &str) -> Vec<InvalidExpression> {
    scan_occurrences(s)
        .into_iter()
        .filter_map(|occurrence| {
            Some(InvalidExpression {
                reason: occurrence.parsed.err()?,
                range: occurrence.range,
                text: occurrence.text.to_string(),
            })
        })
        .collect()
}

/// Parse a JSON value into an `ExprValue`, extracting all `${...}` expressions.
///
/// This function recursively converts JSON into `ExprValue`:
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
    parse_expr_value_at(json, 0)
}

/// Maximum nesting depth [`parse_expr_value`] recurses into.
///
/// Matches the depth cap the resolver enforces on ceremony YAML, so values
/// that went through resolution never reach this limit.
const MAX_VALUE_DEPTH: usize = 64;

/// Depth-tracking worker for [`parse_expr_value`].
///
/// Values nested deeper than [`MAX_VALUE_DEPTH`] are truncated to
/// `Literal(Null)`: the function returns a value rather than a `Result`, so
/// truncation is the least invasive way to stay total on adversarial input
/// without overflowing the stack. The resolver rejects ceremony files nested
/// past the same cap before values reach this function, so the truncation is
/// a defensive backstop, not user-visible behavior.
fn parse_expr_value_at(json: &serde_json::Value, depth: usize) -> ExprValue {
    if depth >= MAX_VALUE_DEPTH {
        return ExprValue::Literal(Literal::Null);
    }
    let child_depth = depth.saturating_add(1);
    match json {
        serde_json::Value::String(s) => parse_string_to_expr_value(s),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                ExprValue::Literal(Literal::Integer(i))
            } else if let Some(f) = n.as_f64() {
                ExprValue::Literal(Literal::Float(f))
            } else {
                // Fallback for very large numbers: truncate to 0.
                ExprValue::Literal(Literal::Integer(0))
            }
        }
        serde_json::Value::Bool(b) => ExprValue::Literal(Literal::Boolean(*b)),
        serde_json::Value::Null => ExprValue::Literal(Literal::Null),
        serde_json::Value::Object(map) => {
            let mut result = std::collections::HashMap::new();
            for (k, v) in map {
                result.insert(k.clone(), parse_expr_value_at(v, child_depth));
            }
            ExprValue::Object(result)
        }
        serde_json::Value::Array(arr) => {
            let result: Vec<_> = arr
                .iter()
                .map(|v| parse_expr_value_at(v, child_depth))
                .collect();
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
                    // Failed to parse: keep as literal.
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
        fn parse_deeply_nested_value_is_truncated_not_crashed() {
            // 200 levels of nesting: far past the cap. The function must
            // return (no stack overflow), truncating everything below
            // MAX_VALUE_DEPTH to Literal(Null).
            let mut json = serde_json::json!("leaf");
            for _ in 0..200 {
                json = serde_json::Value::Array(vec![json]);
            }
            let mut expr = parse_expr_value(&json);
            let mut levels = 0;
            loop {
                match expr {
                    ExprValue::Array(mut arr) => {
                        assert_eq!(arr.len(), 1);
                        expr = arr.remove(0);
                        levels += 1;
                    }
                    other => {
                        assert!(
                            matches!(other, ExprValue::Literal(Literal::Null)),
                            "truncated tail must be Literal(Null), got {other:?}"
                        );
                        break;
                    }
                }
            }
            assert_eq!(levels, MAX_VALUE_DEPTH, "recursion must stop at the cap");
        }

        #[test]
        fn parse_moderately_nested_value_is_preserved() {
            let mut json = serde_json::json!("leaf");
            for _ in 0..10 {
                json = serde_json::Value::Array(vec![json]);
            }
            let mut expr = parse_expr_value(&json);
            for _ in 0..10 {
                match expr {
                    ExprValue::Array(mut arr) => {
                        assert_eq!(arr.len(), 1);
                        expr = arr.remove(0);
                    }
                    other => panic!("expected Array, got {other:?}"),
                }
            }
            assert!(matches!(expr, ExprValue::Literal(Literal::String(s)) if s == "leaf"));
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

    mod invalid_expressions {
        use super::*;

        /// `RefType::ALL` is written by hand; this match makes a new variant a
        /// compile error until it is listed there.
        #[test]
        fn all_lists_every_namespace() {
            for ref_type in RefType::ALL {
                match ref_type {
                    RefType::Param | RefType::Role | RefType::Artifact => {}
                }
            }
            assert_eq!(RefType::ALL.len(), 3);
            assert_eq!(namespace_list(), "param, role, artifact");
        }

        #[test]
        fn a_valid_expression_yields_nothing() {
            for s in [
                "${artifact.ksr}",
                "${artifact.keypair.public | sha256 | hex}",
                "${param.name}",
                "plain text with no expression",
                "Hash: ${artifact.a | sha256 | hex} done",
                "${concat(artifact.a | sha256, artifact.b) | hex}",
            ] {
                assert!(
                    find_invalid_expressions(s).is_empty(),
                    "{s} should be accepted"
                );
            }
        }

        #[test]
        fn an_unknown_namespace_is_reported_with_its_range() {
            let found = find_invalid_expressions("sign ${nonsense.x} now");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].range, 5..18);
            assert_eq!(found[0].text, "${nonsense.x}");
            assert_eq!(
                found[0].reason,
                ExprError::UnknownNamespace {
                    namespace: "nonsense".to_string(),
                }
            );
            assert_eq!(
                found[0].reason.to_string(),
                "unknown namespace 'nonsense': expected one of param, role, artifact"
            );
        }

        #[test]
        fn every_occurrence_in_one_string_is_reported() {
            let found = find_invalid_expressions("${a.b} ${param.ok} ${c.d}");
            assert_eq!(found.len(), 2);
            assert_eq!(found[0].text, "${a.b}");
            assert_eq!(found[1].text, "${c.d}");
        }

        #[test]
        fn the_material_namespace_names_the_artifact_form() {
            // The plural is what the declaring key is called, so it lands on
            // the same explanation rather than the generic unknown-namespace one.
            for namespace in ["material", "materials"] {
                let found = find_invalid_expressions(&format!("${{{namespace}.manifest}}"));
                assert_eq!(found.len(), 1, "for {namespace}");
                assert_eq!(
                    found[0].reason,
                    ExprError::MaterialNamespace {
                        namespace: namespace.to_string(),
                        name: "manifest".to_string(),
                    }
                );
                assert_eq!(
                    found[0].reason.to_string(),
                    format!(
                        "there is no '{namespace}' namespace: \
                         a material is read as 'artifact.manifest'"
                    )
                );
                assert_eq!(
                    found[0].reason.suggestion(),
                    Some(RefType::Artifact),
                    "an editor fix points at the artifact namespace"
                );
            }
        }

        #[test]
        fn a_pipeline_with_nothing_before_the_pipe_is_not_an_empty_expression() {
            assert_eq!(
                parse_expression_detailed("${ | sha256 }").unwrap_err(),
                ExprError::MissingSource
            );
            assert_eq!(
                parse_expression_detailed("${}").unwrap_err(),
                ExprError::Empty
            );
        }

        #[test]
        fn an_unclosed_expression_is_reported_to_the_end_of_the_string() {
            let found = find_invalid_expressions("see ${artifact.k");
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].text, "${artifact.k");
            assert_eq!(found[0].reason, ExprError::Unclosed);
            assert_eq!(
                found[0].reason.to_string(),
                "the expression is missing its closing '}'"
            );
        }

        #[test]
        fn each_shape_of_mistake_gets_its_own_reason() {
            for (input, expected) in [
                ("${}", "the expression is empty"),
                (
                    "${artifact}",
                    "'artifact' names no namespace: write '<namespace>.<name>', \
                     where <namespace> is one of param, role, artifact",
                ),
                (
                    "${artifact.}",
                    "nothing follows 'artifact.': expected a name",
                ),
                (
                    "${artifact.9k}",
                    "'9k' is not a usable name: names hold letters, digits, and underscores, \
                     and cannot start with a digit",
                ),
                (
                    "${artifact.k.9p}",
                    "'9p' is not a usable property: names hold letters, digits, and underscores, \
                     and cannot start with a digit",
                ),
                (
                    "${artifact.k | 9hex}",
                    "'9hex' is not a usable pipe stage: expected a function name, \
                     with any arguments in parentheses",
                ),
                (
                    "${concat(artifact.a}",
                    "the call to 'concat' is missing its closing ')'",
                ),
            ] {
                let found = find_invalid_expressions(input);
                assert_eq!(found.len(), 1, "{input} should be rejected");
                assert_eq!(found[0].reason.to_string(), expected, "for {input}");
            }
        }

        #[test]
        fn a_bare_name_is_told_to_use_the_wrapper() {
            let error = parse_expression_detailed("keypair").unwrap_err();
            assert_eq!(error, ExprError::NotAnExpression);
            assert_eq!(
                error.to_string(),
                "write it as an expression, '${<namespace>.<name>}', \
                 where <namespace> is one of param, role, artifact"
            );
        }

        #[test]
        fn a_namespace_one_or_two_edits_away_is_suggested() {
            for (input, expected) in [
                ("${paramm.region}", RefType::Param),
                ("${params.region}", RefType::Param),
                ("${roles.officer}", RefType::Role),
                ("${artifacts.ksr}", RefType::Artifact),
            ] {
                let error = parse_expression_detailed(input).unwrap_err();
                assert_eq!(error.suggestion(), Some(expected), "for {input}");
                assert!(
                    error
                        .to_string()
                        .contains(&format!("did you mean '{expected}'")),
                    "for {input}: {error}"
                );
            }
        }

        #[test]
        fn a_namespace_nothing_like_a_known_one_gets_no_suggestion() {
            for input in ["${nonsense.x}", "${env.HOME}", "${secret.pin}"] {
                let error = parse_expression_detailed(input).unwrap_err();
                assert!(
                    matches!(error, ExprError::UnknownNamespace { .. }),
                    "{input} should be an unknown namespace, got {error:?}"
                );
                assert_eq!(error.suggestion(), None, "{input} should not be guessed at");
            }
        }

        #[test]
        fn a_failing_argument_names_its_position_and_its_own_cause() {
            let error = parse_expression_detailed("${concat(artifact.a, nonsense.b)}").unwrap_err();
            assert_eq!(
                error,
                ExprError::InvalidArgument {
                    function: "concat".to_string(),
                    position: 2,
                    cause: Box::new(ExprError::UnknownNamespace {
                        namespace: "nonsense".to_string(),
                    }),
                }
            );
            assert_eq!(
                error.to_string(),
                "argument 2 to 'concat' is not a usable expression: \
                 unknown namespace 'nonsense': expected one of param, role, artifact"
            );
        }

        #[test]
        fn a_lone_quote_is_an_unterminated_string() {
            // The source is dispatched on its first character, so a quote that
            // opens a string is never also read as the one that closes it.
            for (input, quote) in [("${\"}", '"'), ("${'}", '\''), ("${\"abc}", '"')] {
                assert_eq!(
                    parse_expression_detailed(input).unwrap_err(),
                    ExprError::UnterminatedString { quote },
                    "for {input}"
                );
            }
        }

        #[test]
        fn a_quote_opens_a_string_even_when_it_holds_a_parenthesis() {
            let parsed = parse_expression_detailed("${\"a(b\"}");
            assert!(
                matches!(parsed, Ok(Expression::Literal(Literal::String(ref s))) if s == "a(b"),
                "the parenthesis belongs to the string, got {parsed:?}"
            );
        }

        #[test]
        fn the_shape_a_source_is_read_as_comes_from_its_first_characters() {
            // A dot means a reference, so a name with a parenthesis in it is a
            // broken name rather than a broken call.
            for (input, expected) in [
                (
                    "${param.x(1)}",
                    ExprError::InvalidName {
                        name: "x(1)".to_string(),
                    },
                ),
                (
                    "${42abc}",
                    ExprError::NotAReference {
                        text: "42abc".to_string(),
                    },
                ),
                (
                    "${1.5}",
                    ExprError::NotAReference {
                        text: "1.5".to_string(),
                    },
                ),
            ] {
                assert_eq!(
                    parse_expression_detailed(input).unwrap_err(),
                    expected,
                    "for {input}"
                );
            }
        }

        #[test]
        fn parses_every_accepted_form() {
            for input in [
                "${artifact.ksr}",
                "${artifact.keypair.public}",
                "${param.region | sha256 | hex}",
                "${\"literal\"}",
                "${'literal'}",
                "${42}",
                "${-42}",
                "${\"\"}",
                "${concat(artifact.a, artifact.b) | hex}",
                "${pad(artifact.a, 4)}",
            ] {
                assert!(
                    parse_expression_detailed(input).is_ok(),
                    "{input} should parse, got {:?}",
                    parse_expression_detailed(input)
                );
            }
        }
    }
}
