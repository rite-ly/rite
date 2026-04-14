//! Expression evaluation for computed values.
//!
//! Evaluates pipeline expressions like `${artifact.ksr | sha256 | hex}` at runtime,
//! resolving artifact references and applying transformations.

use crate::actions::ArtifactValue;
use crate::artifact_resolver::resolve_artifact_bytes;
use crate::executor::ExecutionError;
use crate::state::HandlerContext;
use base16ct::lower::encode_string as hex_encode_string;
use base32ct::{Base32Unpadded, Encoding as Base32Encoding};
use base64ct::{Base64, Encoding as Base64Encoding};
use rite_model::expression::{
    ExprValue, Expression, Literal, PipeStage, RefType, Reference, StringPart, Value,
};
use rite_model::{ArtifactId, ParamId};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Evaluate an expression in the given context.
///
/// # Examples
///
/// ```ignore
/// let expr = rite_model::expression::parse_expression("${artifact.ksr | sha256 | hex}").unwrap();
/// let result = evaluate(&expr, &context)?;
/// assert!(matches!(result, Value::String(_)));
/// ```
pub fn evaluate(expr: &Expression, ctx: &HandlerContext) -> Result<Value, ExecutionError> {
    match expr {
        Expression::Reference(ref_) => evaluate_reference(ref_, ctx),
        Expression::Literal(lit) => Ok(evaluate_literal(lit)),
        Expression::Pipeline { source, stages } => {
            let mut value = evaluate(source, ctx)?;
            for stage in stages {
                value = apply_pipe_stage(&value, stage, ctx)?;
            }
            Ok(value)
        }
    }
}

/// Evaluate a reference to get its value.
fn evaluate_reference(ref_: &Reference, ctx: &HandlerContext) -> Result<Value, ExecutionError> {
    match ref_.ref_type {
        RefType::Param => evaluate_param_ref(ref_, ctx),
        RefType::Artifact => evaluate_artifact_ref(ref_, ctx),
        // Role references evaluate to their ID as a string
        // This allows ${role.name} to be used in role-related fields
        RefType::Role => Ok(Value::String(ref_.name.clone())),
    }
}

/// Evaluate a parameter reference.
fn evaluate_param_ref(ref_: &Reference, ctx: &HandlerContext) -> Result<Value, ExecutionError> {
    let param_id = ParamId::new(&ref_.name);
    let value = ctx.params.get(&param_id).ok_or_else(|| {
        ExecutionError::InvalidParams(format!("Unknown parameter: {}", ref_.name))
    })?;

    json_to_value(value)
}

/// Convert a JSON value to our Value type.
fn json_to_value(json: &serde_json::Value) -> Result<Value, ExecutionError> {
    match json {
        serde_json::Value::String(s) => Ok(Value::String(s.clone())),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Integer(i))
            } else if let Some(f) = n.as_f64() {
                #[allow(clippy::cast_possible_truncation)]
                Ok(Value::Integer(f as i64))
            } else {
                Err(ExecutionError::InvalidParams(
                    "Number too large".to_string(),
                ))
            }
        }
        serde_json::Value::Bool(b) => Ok(Value::Boolean(*b)),
        serde_json::Value::Null => Ok(Value::Null),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            Err(ExecutionError::InvalidParams(
                "Cannot use array or object as expression value".to_string(),
            ))
        }
    }
}

/// Evaluate an artifact reference.
fn evaluate_artifact_ref(ref_: &Reference, ctx: &HandlerContext) -> Result<Value, ExecutionError> {
    let artifact_id = ArtifactId::new(&ref_.name);
    let artifact = ctx.get_artifact(&artifact_id).ok_or_else(|| {
        ExecutionError::InvalidParams(format!("Artifact '{}' not found", ref_.name))
    })?;

    match artifact {
        // Text references (physical items) - return as string for display
        ArtifactValue::Text(text) => {
            if let Some(property) = &ref_.property {
                return Err(ExecutionError::InvalidParams(format!(
                    "Property access '.{property}' not supported for text artifacts"
                )));
            }
            Ok(Value::String(text.clone()))
        }

        // Binary content (documents, crypto materials) - return as bytes
        ArtifactValue::Bytes(bytes) => {
            // Property access not supported for raw byte artifacts
            if let Some(property) = &ref_.property {
                return Err(ExecutionError::InvalidParams(format!(
                    "Property access '.{property}' not supported for binary artifacts"
                )));
            }
            Ok(Value::Bytes(bytes.clone()))
        }

        // Other artifact types - delegate to resolve_artifact_bytes
        _ => {
            let bytes =
                resolve_artifact_bytes(ctx.artifacts, &artifact_id, ref_.property.as_deref())?;
            Ok(Value::Bytes(bytes))
        }
    }
}

/// Evaluate a literal to a Value.
fn evaluate_literal(lit: &Literal) -> Value {
    match lit {
        Literal::String(s) => Value::String(s.clone()),
        Literal::Integer(i) => Value::Integer(*i),
        #[allow(clippy::cast_possible_truncation)]
        Literal::Float(f) => Value::Integer(*f as i64), //TODO Handle float better
        Literal::Boolean(b) => Value::Boolean(*b),
        Literal::Null => Value::Null,
    }
}

/// Apply a pipe stage to a value.
fn apply_pipe_stage(
    input: &Value,
    stage: &PipeStage,
    ctx: &HandlerContext,
) -> Result<Value, ExecutionError> {
    match stage.function.as_str() {
        // Hash functions: Bytes -> Bytes
        "sha256" => apply_sha256(input),
        "sha384" => apply_sha384(input),
        "sha512" => apply_sha512(input),

        // Encoding functions: Bytes -> String
        "hex" => apply_hex(input),
        "base32" => apply_base32(input),
        "base64" => apply_base64(input),

        // String functions: String -> String
        "upper" => apply_upper(input),
        "lower" => apply_lower(input),
        "substr" => apply_substr(input, &stage.args, ctx),

        // Bytes concatenation
        "concat" => apply_concat(&stage.args, ctx),

        unknown => Err(ExecutionError::InvalidParams(format!(
            "Unknown function: {unknown}"
        ))),
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

fn apply_sha256(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "sha256 expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();

    Ok(Value::Bytes(result.to_vec()))
}

fn apply_sha384(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "sha384 expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    let mut hasher = Sha384::new();
    hasher.update(&bytes);
    let result = hasher.finalize();

    Ok(Value::Bytes(result.to_vec()))
}

fn apply_sha512(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "sha512 expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    let mut hasher = Sha512::new();
    hasher.update(&bytes);
    let result = hasher.finalize();

    Ok(Value::Bytes(result.to_vec()))
}

// ============================================================================
// Encoding Functions
// ============================================================================

fn apply_hex(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "hex expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    let hex_string = hex_encode(&bytes);
    Ok(Value::String(hex_string))
}

fn apply_base32(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "base32 expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    // base32ct returns lowercase, but RFC 4648 specifies uppercase
    let encoded = Base32Unpadded::encode_string(&bytes).to_uppercase();
    Ok(Value::String(encoded))
}

fn apply_base64(input: &Value) -> Result<Value, ExecutionError> {
    let bytes = input.as_bytes().ok_or_else(|| {
        ExecutionError::InvalidParams(format!(
            "base64 expects bytes or string, got {}",
            input.type_name()
        ))
    })?;

    let encoded = Base64::encode_string(&bytes);
    Ok(Value::String(encoded))
}

/// Encode bytes as lowercase hex string using constant-time encoding.
fn hex_encode(bytes: &[u8]) -> String {
    hex_encode_string(bytes)
}

// ============================================================================
// String Functions
// ============================================================================

fn apply_upper(input: &Value) -> Result<Value, ExecutionError> {
    let s = input.as_string().ok_or_else(|| {
        ExecutionError::InvalidParams(format!("upper expects string, got {}", input.type_name()))
    })?;

    Ok(Value::String(s.to_uppercase()))
}

fn apply_lower(input: &Value) -> Result<Value, ExecutionError> {
    let s = input.as_string().ok_or_else(|| {
        ExecutionError::InvalidParams(format!("lower expects string, got {}", input.type_name()))
    })?;

    Ok(Value::String(s.to_lowercase()))
}

fn apply_substr(
    input: &Value,
    args: &[Expression],
    ctx: &HandlerContext,
) -> Result<Value, ExecutionError> {
    let s = input.as_string().ok_or_else(|| {
        ExecutionError::InvalidParams(format!("substr expects string, got {}", input.type_name()))
    })?;

    let [start_arg, len_arg] = args else {
        return Err(ExecutionError::InvalidParams(
            "substr requires 2 arguments: start and length".to_string(),
        ));
    };

    let start_i64 = evaluate(start_arg, ctx)?
        .as_integer()
        .ok_or_else(|| ExecutionError::InvalidParams("substr start must be integer".to_string()))?;

    let len_i64 = evaluate(len_arg, ctx)?.as_integer().ok_or_else(|| {
        ExecutionError::InvalidParams("substr length must be integer".to_string())
    })?;

    // Clamp negative values to 0, then convert to usize
    let start = usize::try_from(start_i64.max(0)).unwrap_or(0).min(s.len());
    let len = usize::try_from(len_i64.max(0)).unwrap_or(0);
    let end = start.saturating_add(len).min(s.len());

    Ok(Value::String(
        s.get(start..end).unwrap_or_default().to_string(),
    ))
}

// ============================================================================
// Bytes Concatenation
// ============================================================================

fn apply_concat(args: &[Expression], ctx: &HandlerContext) -> Result<Value, ExecutionError> {
    let mut result = Vec::new();

    for arg in args {
        let value = evaluate(arg, ctx)?;
        let bytes = value.as_bytes().ok_or_else(|| {
            ExecutionError::InvalidParams(format!(
                "concat expects bytes arguments, got {}",
                value.type_name()
            ))
        })?;
        result.extend(bytes);
    }

    Ok(Value::Bytes(result))
}

// ============================================================================
// ExprValue Evaluation (new: no runtime parsing)
// ============================================================================

/// Evaluate an `ExprValue` to a JSON value.
///
/// This is the new entry point for expression evaluation. Unlike `evaluate_json_value`,
/// this function receives pre-parsed expressions and performs NO string parsing.
/// All `${...}` patterns have already been parsed by the resolver.
///
/// # Examples
///
/// ```ignore
/// let expr_value = parse_expr_value(&json!({"message": "${param.name}"}));
/// let result = evaluate_expr_value(&expr_value, &ctx)?;
/// // result is a serde_json::Value with expressions evaluated
/// ```
pub fn evaluate_expr_value(
    value: &ExprValue,
    ctx: &HandlerContext,
) -> Result<serde_json::Value, ExecutionError> {
    match value {
        ExprValue::Literal(lit) => Ok(literal_to_json(lit)),
        ExprValue::Expr(expr) => {
            let result = evaluate(expr, ctx)?;
            Ok(value_to_json(&result))
        }
        ExprValue::Interpolated(parts) => {
            let mut result = String::new();
            for part in parts {
                match part {
                    StringPart::Literal(s) => result.push_str(s),
                    StringPart::Expr(expr) => {
                        let val = evaluate(expr, ctx)?;
                        result.push_str(&val.to_string());
                    }
                }
            }
            Ok(serde_json::Value::String(result))
        }
        ExprValue::Object(map) => {
            let mut result = serde_json::Map::new();
            for (k, v) in map {
                result.insert(k.clone(), evaluate_expr_value(v, ctx)?);
            }
            Ok(serde_json::Value::Object(result))
        }
        ExprValue::Array(arr) => {
            let result: Result<Vec<_>, _> =
                arr.iter().map(|v| evaluate_expr_value(v, ctx)).collect();
            Ok(serde_json::Value::Array(result?))
        }
    }
}

/// Convert a Literal to a JSON value.
fn literal_to_json(lit: &Literal) -> serde_json::Value {
    match lit {
        Literal::String(s) => serde_json::Value::String(s.clone()),
        Literal::Integer(i) => serde_json::Value::Number((*i).into()),
        Literal::Float(f) => serde_json::Number::from_f64(*f)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Literal::Boolean(b) => serde_json::Value::Bool(*b),
        Literal::Null => serde_json::Value::Null,
    }
}

/// Evaluate an `ExprValue` to a string.
///
/// Useful for description fields that should always produce a string.
pub fn evaluate_expr_value_to_string(
    value: &ExprValue,
    ctx: &HandlerContext,
) -> Result<String, ExecutionError> {
    match value {
        ExprValue::Literal(Literal::String(s)) => Ok(s.clone()),
        ExprValue::Literal(lit) => {
            // Convert other literals to string representation
            let json = literal_to_json(lit);
            Ok(match json {
                serde_json::Value::String(s) => s,
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => "null".to_string(),
                _ => json.to_string(),
            })
        }
        ExprValue::Expr(expr) => {
            let result = evaluate(expr, ctx)?;
            Ok(result.to_string())
        }
        ExprValue::Interpolated(parts) => {
            let mut result = String::new();
            for part in parts {
                match part {
                    StringPart::Literal(s) => result.push_str(s),
                    StringPart::Expr(expr) => {
                        let val = evaluate(expr, ctx)?;
                        result.push_str(&val.to_string());
                    }
                }
            }
            Ok(result)
        }
        ExprValue::Object(_) | ExprValue::Array(_) => {
            // For complex types, return JSON string representation
            let json = evaluate_expr_value(value, ctx)?;
            Ok(json.to_string())
        }
    }
}

/// Convert a Value to a JSON value for action parameters.
pub fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Bytes(b) => {
            // Bytes are encoded as base64 for JSON
            serde_json::Value::String(Base64::encode_string(b))
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Integer(i) => serde_json::Value::Number((*i).into()),
        Value::Boolean(b) => serde_json::Value::Bool(*b),
        Value::Null => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::ArtifactValue;
    use rite_model::{MaterialId, RoleId};
    use std::collections::HashMap;

    fn empty_context() -> HandlerContext<'static> {
        static EMPTY_PARAMS: std::sync::LazyLock<HashMap<ParamId, serde_json::Value>> =
            std::sync::LazyLock::new(HashMap::new);
        static EMPTY_ARTIFACTS: std::sync::LazyLock<HashMap<ArtifactId, ArtifactValue>> =
            std::sync::LazyLock::new(HashMap::new);
        static EMPTY_ROLES: std::sync::LazyLock<HashMap<RoleId, String>> =
            std::sync::LazyLock::new(HashMap::new);
        static EMPTY_MATERIALS: std::sync::LazyLock<HashMap<MaterialId, String>> =
            std::sync::LazyLock::new(HashMap::new);
        HandlerContext {
            dry_run: false,
            params: &EMPTY_PARAMS,
            artifacts: &EMPTY_ARTIFACTS,
            roles: &EMPTY_ROLES,
            materials: &EMPTY_MATERIALS,
        }
    }

    /// Create a HandlerContext from params and artifacts for tests.
    /// Note: This leaks memory, only use in tests.
    fn make_context(
        params: HashMap<ParamId, serde_json::Value>,
        artifacts: HashMap<ArtifactId, ArtifactValue>,
    ) -> HandlerContext<'static> {
        static EMPTY_ROLES: std::sync::LazyLock<HashMap<RoleId, String>> =
            std::sync::LazyLock::new(HashMap::new);
        static EMPTY_MATERIALS: std::sync::LazyLock<HashMap<MaterialId, String>> =
            std::sync::LazyLock::new(HashMap::new);
        let params_box = Box::leak(Box::new(params));
        let artifacts_box = Box::leak(Box::new(artifacts));
        HandlerContext {
            dry_run: false,
            params: params_box,
            artifacts: artifacts_box,
            roles: &EMPTY_ROLES,
            materials: &EMPTY_MATERIALS,
        }
    }

    #[test]
    fn test_sha256_of_string() {
        let input = Value::String("hello".to_string());
        let result = apply_sha256(&input).unwrap();

        if let Value::Bytes(bytes) = result {
            assert_eq!(bytes.len(), 32); // SHA-256 produces 32 bytes
            let hex = hex_encode(&bytes);
            assert_eq!(
                hex,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            );
        } else {
            panic!("Expected Bytes");
        }
    }

    #[test]
    fn test_sha256_of_bytes() {
        let input = Value::Bytes(b"hello".to_vec());
        let result = apply_sha256(&input).unwrap();

        if let Value::Bytes(bytes) = result {
            assert_eq!(bytes.len(), 32);
        } else {
            panic!("Expected Bytes");
        }
    }

    #[test]
    fn test_hex_encoding() {
        let input = Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let result = apply_hex(&input).unwrap();

        assert_eq!(result, Value::String("deadbeef".to_string()));
    }

    #[test]
    fn test_base32_encoding() {
        let input = Value::Bytes(b"hello".to_vec());
        let result = apply_base32(&input).unwrap();

        // Base32 unpadded encoding of "hello" (RFC 4648 uppercase)
        assert_eq!(result, Value::String("NBSWY3DP".to_string()));
    }

    #[test]
    fn test_base64_encoding() {
        let input = Value::Bytes(b"hello".to_vec());
        let result = apply_base64(&input).unwrap();

        assert_eq!(result, Value::String("aGVsbG8=".to_string()));
    }

    #[test]
    fn test_upper() {
        let input = Value::String("hello".to_string());
        let result = apply_upper(&input).unwrap();

        assert_eq!(result, Value::String("HELLO".to_string()));
    }

    #[test]
    fn test_lower() {
        let input = Value::String("HELLO".to_string());
        let result = apply_lower(&input).unwrap();

        assert_eq!(result, Value::String("hello".to_string()));
    }

    #[test]
    fn test_pipeline_sha256_hex() {
        let ctx = empty_context();

        // Simulate: "hello" | sha256 | hex
        let expr = Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::String("hello".to_string()))),
            stages: vec![PipeStage::new("sha256"), PipeStage::new("hex")],
        };

        let result = evaluate(&expr, &ctx).unwrap();

        if let Value::String(s) = result {
            assert_eq!(
                s,
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            );
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_pipeline_sha256_hex_upper() {
        let ctx = empty_context();

        // Simulate: "hello" | sha256 | hex | upper
        let expr = Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::String("hello".to_string()))),
            stages: vec![
                PipeStage::new("sha256"),
                PipeStage::new("hex"),
                PipeStage::new("upper"),
            ],
        };

        let result = evaluate(&expr, &ctx).unwrap();

        if let Value::String(s) = result {
            assert_eq!(
                s,
                "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"
            );
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_type_error_sha256_on_integer() {
        let input = Value::Integer(42);
        let result = apply_sha256(&input);

        assert!(result.is_err());
    }

    #[test]
    fn test_type_error_upper_on_bytes() {
        let input = Value::Bytes(vec![1, 2, 3]);
        let result = apply_upper(&input);

        assert!(result.is_err());
    }

    #[test]
    fn test_substr_via_pipeline() {
        let ctx = empty_context();

        // Test: "abcdefgh" | substr(0, 4)
        let expr = Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::String("abcdefgh".to_string()))),
            stages: vec![PipeStage {
                function: "substr".to_string(),
                args: vec![
                    Expression::Literal(Literal::Integer(0)),
                    Expression::Literal(Literal::Integer(4)),
                ],
            }],
        };

        let result = evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("abcd".to_string()));
    }

    #[test]
    fn test_substr_from_middle_via_pipeline() {
        let ctx = empty_context();

        // Test: "abcdefgh" | substr(2, 4)
        let expr = Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::String("abcdefgh".to_string()))),
            stages: vec![PipeStage {
                function: "substr".to_string(),
                args: vec![
                    Expression::Literal(Literal::Integer(2)),
                    Expression::Literal(Literal::Integer(4)),
                ],
            }],
        };

        let result = evaluate(&expr, &ctx).unwrap();
        assert_eq!(result, Value::String("cdef".to_string()));
    }

    #[test]
    fn test_artifact_evaluation() {
        let mut params = HashMap::new();
        params.insert(ParamId::new("name"), serde_json::json!("test"));

        let mut artifacts = HashMap::new();
        // Use Bytes which stores binary content
        artifacts.insert(
            ArtifactId::new("ksr"),
            ArtifactValue::Bytes(b"KSR content".to_vec()),
        );

        let ctx = make_context(params, artifacts);

        // Parse and evaluate: ${artifact.ksr | sha256 | hex}
        let expr =
            rite_model::expression::parse_expression("${artifact.ksr | sha256 | hex}").unwrap();
        let result = evaluate(&expr, &ctx).unwrap();

        if let Value::String(s) = result {
            assert_eq!(s.len(), 64); // SHA-256 hex is 64 chars
        } else {
            panic!("Expected String");
        }
    }

    #[test]
    fn test_param_evaluation() {
        let mut params = HashMap::new();
        params.insert(ParamId::new("expected_hash"), serde_json::json!("abc123"));

        let artifacts = HashMap::new();
        let ctx = make_context(params, artifacts);

        let expr = rite_model::expression::parse_expression("${param.expected_hash}").unwrap();
        let result = evaluate(&expr, &ctx).unwrap();

        assert_eq!(result, Value::String("abc123".to_string()));
    }

    #[test]
    fn test_sha384() {
        let input = Value::String("hello".to_string());
        let result = apply_sha384(&input).unwrap();

        if let Value::Bytes(bytes) = result {
            assert_eq!(bytes.len(), 48); // SHA-384 produces 48 bytes
        } else {
            panic!("Expected Bytes");
        }
    }

    #[test]
    fn test_sha512() {
        let input = Value::String("hello".to_string());
        let result = apply_sha512(&input).unwrap();

        if let Value::Bytes(bytes) = result {
            assert_eq!(bytes.len(), 64); // SHA-512 produces 64 bytes
        } else {
            panic!("Expected Bytes");
        }
    }

    #[test]
    fn test_concat_through_pipeline() {
        let ctx = empty_context();

        // Test concat via expression: concat("hello", " ", "world")
        // concat takes all strings as args, ignores pipeline input
        let expr = Expression::Pipeline {
            source: Box::new(Expression::Literal(Literal::String("ignored".to_string()))),
            stages: vec![PipeStage {
                function: "concat".to_string(),
                args: vec![
                    Expression::Literal(Literal::String("hello".to_string())),
                    Expression::Literal(Literal::String(" ".to_string())),
                    Expression::Literal(Literal::String("world".to_string())),
                ],
            }],
        };

        let result = evaluate(&expr, &ctx).unwrap();

        // concat returns bytes
        if let Value::Bytes(b) = result {
            assert_eq!(b, b"hello world".to_vec());
        } else {
            panic!("Expected Bytes, got {:?}", result);
        }
    }

    #[test]
    fn test_parse_and_evaluate_pipeline() {
        let ctx = empty_context();

        // Test parsing a real expression string
        let expr = rite_model::expression::parse_expression("${\"test\" | sha256 | hex}").unwrap();
        let result = evaluate(&expr, &ctx).unwrap();

        if let Value::String(s) = result {
            // SHA-256 of "test" in hex
            assert_eq!(
                s,
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            );
        } else {
            panic!("Expected String");
        }
    }

    // =========================================================================
    // Tests based on actual ceremony examples
    // =========================================================================

    mod ceremony_examples {
        use super::*;

        fn ceremony_context() -> HandlerContext<'static> {
            let params: HashMap<ParamId, serde_json::Value> = [
                ("ceremony_id", serde_json::json!("KC-2024-Q4")),
                ("hsm_serial", serde_json::json!("HSM-001")),
                ("key_label", serde_json::json!("MASTER-KEY")),
                ("expected_ksr_hash", serde_json::json!("a3b8f4e91c2d6078")),
                ("zone_name", serde_json::json!(".")),
                ("signing_validity_days", serde_json::json!(21)),
            ]
            .into_iter()
            .map(|(k, v)| (ParamId::new(k), v))
            .collect();

            let mut artifacts: HashMap<ArtifactId, ArtifactValue> = HashMap::new();
            artifacts.insert(
                ArtifactId::new("ksr"),
                ArtifactValue::Bytes(b"KSR test content".to_vec()),
            );
            artifacts.insert(
                ArtifactId::new("master_public_key"),
                ArtifactValue::Bytes(b"PUBLIC KEY DATA".to_vec()),
            );

            make_context(params, artifacts)
        }

        // From dnssec_signing/dnssec_signing.rite.yaml
        #[test]
        fn dnssec_hash_verification_full_pipeline() {
            let ctx = ceremony_context();

            // actual: "${artifact.ksr | sha256 | hex | substr(0, 16)}"
            let expr = rite_model::expression::parse_expression(
                "${artifact.ksr | sha256 | hex | substr(0, 16)}",
            )
            .unwrap();
            let result = evaluate(&expr, &ctx).unwrap();

            if let Value::String(s) = result {
                assert_eq!(s.len(), 16); // First 16 hex chars
                assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
            } else {
                panic!("Expected String");
            }
        }

        #[test]
        fn dnssec_param_comparison() {
            let ctx = ceremony_context();

            // expected: "${param.expected_ksr_hash}"
            let expr =
                rite_model::expression::parse_expression("${param.expected_ksr_hash}").unwrap();
            let result = evaluate(&expr, &ctx).unwrap();

            assert_eq!(result, Value::String("a3b8f4e91c2d6078".to_string()));
        }

        #[test]
        fn hsm_fingerprint_computation() {
            let ctx = ceremony_context();

            // value: "${artifact.master_public_key | sha256 | hex}"
            let expr = rite_model::expression::parse_expression(
                "${artifact.master_public_key | sha256 | hex}",
            )
            .unwrap();
            let result = evaluate(&expr, &ctx).unwrap();

            if let Value::String(s) = result {
                assert_eq!(s.len(), 64); // Full SHA-256 hex
            } else {
                panic!("Expected String");
            }
        }
    }
}
