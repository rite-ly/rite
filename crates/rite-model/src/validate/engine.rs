//! A JSON Schema validator for the keywords generated schemas use.
//!
//! Draft 2020-12 semantics, for [`params::KEYWORDS`](crate::params::KEYWORDS)
//! alone. A schema is compiled into a tree first, so a keyword outside that
//! set, a value of the wrong shape, a pattern that does not compile or a
//! reference to nothing is a [`SchemaError`] before any value is checked.
//!
//! References are local, to a definition under the root's `$defs`. A keyword
//! is located where it is written, so one inside a definition is located
//! there, not where it was referenced from. A definition that reaches itself
//! again without going into the value is refused, since checking it would
//! never end.
//!
//! One difference with the standard: an integer is a number serde reads as
//! one, so `2.0` is not, where the standard counts it.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use regex_lite::Regex;
use serde_json::{Map, Number, Value};

use super::{Keyword, Matched, Pointer, SchemaError, Violation};

/// A compiled schema: the root and the definitions it refers to.
pub(super) struct Engine {
    root: Node,
    definitions: Vec<Node>,
}

/// One schema: `true`, `false`, or an object of keywords.
enum Node {
    Bool { value: bool, at: Pointer },
    Object(Box<Keywords>),
}

/// The keywords of one schema object that check a value. Annotations are
/// read and dropped.
#[derive(Default)]
struct Keywords {
    /// Where this object is in the schema document.
    at: Pointer,
    reference: Option<usize>,
    types: Option<Vec<String>>,
    options: Option<Vec<Value>>,
    constant: Option<Value>,
    pattern: Option<(String, Regex)>,
    minimum: Option<Number>,
    maximum: Option<Number>,
    min_items: Option<u64>,
    items: Option<Node>,
    properties: BTreeMap<String, Node>,
    required: Vec<String>,
    additional: Option<Node>,
    all_of: Vec<Node>,
    one_of: Vec<Node>,
    condition: Option<(Node, Node)>,
    not: Option<Node>,
}

/// The JSON types `type` may name.
const TYPES: &[&str] = &[
    "null", "boolean", "object", "array", "number", "string", "integer",
];

impl Engine {
    pub(super) fn new(schema: &Value) -> Result<Self, SchemaError> {
        let empty = Map::new();
        let at = Pointer::root().join("$defs");
        let definitions = match schema.get("$defs") {
            None => &empty,
            Some(Value::Object(definitions)) => definitions,
            Some(_) => return Err(error(&at, "is not an object")),
        };
        let names: Vec<&String> = definitions.keys().collect();
        let compiler = Compiler { names: &names };
        let definitions: Vec<Node> = definitions
            .iter()
            .map(|(name, definition)| compiler.node(definition, &at.join(name)))
            .collect::<Result<_, _>>()?;
        if let Some(index) = first_cycle(&definitions) {
            let name = names.get(index).map_or("", |name| name.as_str());
            return Err(error(
                &at.join(name),
                "refers back to itself without going into the value",
            ));
        }
        Ok(Engine {
            root: compiler.node(schema, &Pointer::root())?,
            definitions,
        })
    }

    pub(super) fn validate(&self, instance: &Value) -> Vec<Violation> {
        let mut found = Vec::new();
        self.check(&self.root, instance, &Pointer::root(), &mut found);
        found
    }

    fn is_valid(&self, node: &Node, instance: &Value) -> bool {
        let mut found = Vec::new();
        self.check(node, instance, &Pointer::root(), &mut found);
        found.is_empty()
    }

    fn check(&self, node: &Node, instance: &Value, path: &Pointer, found: &mut Vec<Violation>) {
        let schema = match node {
            Node::Bool { value: true, .. } => return,
            Node::Bool { value: false, at } => {
                found.push(violation(path, at.clone(), Keyword::False));
                return;
            }
            Node::Object(schema) => schema,
        };
        let at = |keyword: &str| schema.at.join(keyword);

        if let Some(index) = schema.reference
            && let Some(definition) = self.definitions.get(index)
        {
            self.check(definition, instance, path, found);
        }
        schema.check_value(instance, path, found);
        if let Value::Array(elements) = instance {
            if let Some(limit) = schema.min_items
                && (elements.len() as u64) < limit
            {
                found.push(violation(path, at("minItems"), Keyword::MinItems { limit }));
            }
            if let Some(items) = &schema.items {
                for (index, element) in elements.iter().enumerate() {
                    self.check(items, element, &path.join(&index.to_string()), found);
                }
            }
        }
        if let Value::Object(object) = instance {
            for property in &schema.required {
                if !object.contains_key(property) {
                    let property = property.clone();
                    found.push(violation(
                        path,
                        at("required"),
                        Keyword::Required { property },
                    ));
                }
            }
            for (key, value) in object {
                if let Some(property) = schema.properties.get(key) {
                    self.check(property, value, &path.join(key), found);
                }
            }
            if let Some(additional) = &schema.additional {
                self.check_additional(&schema.properties, additional, object, path, found);
            }
        }
        for rule in &schema.all_of {
            self.check(rule, instance, path, found);
        }
        if !schema.one_of.is_empty() {
            let valid = schema
                .one_of
                .iter()
                .filter(|alternative| self.is_valid(alternative, instance))
                .count();
            let matched = match valid {
                0 => Some(Matched::None),
                1 => None,
                _ => Some(Matched::Several),
            };
            if let Some(matched) = matched {
                found.push(violation(path, at("oneOf"), Keyword::OneOf { matched }));
            }
        }
        if let Some((condition, then)) = &schema.condition
            && self.is_valid(condition, instance)
        {
            self.check(then, instance, path, found);
        }
        if let Some(not) = &schema.not
            && self.is_valid(not, instance)
        {
            found.push(violation(path, at("not"), Keyword::Not));
        }
    }

    /// The keys `properties` does not name. Under `false` they are one
    /// violation of the object, otherwise each is checked against the schema.
    fn check_additional(
        &self,
        properties: &BTreeMap<String, Node>,
        additional: &Node,
        object: &Map<String, Value>,
        path: &Pointer,
        found: &mut Vec<Violation>,
    ) {
        let extra = object
            .iter()
            .filter(|(key, _)| !properties.contains_key(*key));
        if let Node::Bool { value: false, at } = additional {
            let unexpected: Vec<String> = extra.map(|(key, _)| key.clone()).collect();
            if !unexpected.is_empty() {
                let keyword = Keyword::AdditionalProperties { unexpected };
                found.push(violation(path, at.clone(), keyword));
            }
            return;
        }
        for (key, value) in extra {
            self.check(additional, value, &path.join(key), found);
        }
    }
}

impl Keywords {
    /// The keywords about the value itself, not what it holds.
    fn check_value(&self, instance: &Value, path: &Pointer, found: &mut Vec<Violation>) {
        let at = |keyword: &str| self.at.join(keyword);
        if let Some(types) = &self.types
            && !types.iter().any(|name| has_type(instance, name))
        {
            let expected = types.clone();
            found.push(violation(path, at("type"), Keyword::Type { expected }));
        }
        if let Some(options) = &self.options
            && !options.iter().any(|option| equal(option, instance))
        {
            let options = options.clone();
            found.push(violation(path, at("enum"), Keyword::Enum { options }));
        }
        if let Some(expected) = &self.constant
            && !equal(expected, instance)
        {
            let expected = expected.clone();
            found.push(violation(path, at("const"), Keyword::Const { expected }));
        }
        if let (Some((pattern, regex)), Value::String(text)) = (&self.pattern, instance)
            && !regex.is_match(text)
        {
            let pattern = pattern.clone();
            found.push(violation(path, at("pattern"), Keyword::Pattern { pattern }));
        }
        if let Value::Number(number) = instance {
            if let Some(limit) = &self.minimum
                && compare(number, limit) == Some(Ordering::Less)
            {
                let limit = Value::Number(limit.clone());
                found.push(violation(path, at("minimum"), Keyword::Minimum { limit }));
            }
            if let Some(limit) = &self.maximum
                && compare(number, limit) == Some(Ordering::Greater)
            {
                let limit = Value::Number(limit.clone());
                found.push(violation(path, at("maximum"), Keyword::Maximum { limit }));
            }
        }
    }
}

/// Compiles schema objects, with the names of the definitions a reference
/// may point to.
struct Compiler<'a> {
    names: &'a [&'a String],
}

impl Compiler<'_> {
    fn node(&self, schema: &Value, at: &Pointer) -> Result<Node, SchemaError> {
        let object = match schema {
            Value::Bool(value) => {
                return Ok(Node::Bool {
                    value: *value,
                    at: at.clone(),
                });
            }
            Value::Object(object) => object,
            _ => return Err(error(at, "is not a schema")),
        };
        let mut keywords = Keywords {
            at: at.clone(),
            ..Keywords::default()
        };
        let mut condition = None;
        let mut then = None;
        for (keyword, value) in object {
            let here = at.join(keyword);
            match keyword.as_str() {
                "$ref" => keywords.reference = Some(self.reference(value, &here)?),
                "type" => keywords.types = Some(types(value, &here)?),
                "enum" => keywords.options = Some(array(value, &here)?.clone()),
                "const" => keywords.constant = Some(value.clone()),
                "pattern" => keywords.pattern = Some(pattern(value, &here)?),
                "minimum" => keywords.minimum = Some(number(value, &here)?),
                "maximum" => keywords.maximum = Some(number(value, &here)?),
                "minItems" => {
                    let limit = value
                        .as_u64()
                        .ok_or_else(|| error(&here, "is not a count"))?;
                    keywords.min_items = Some(limit);
                }
                "items" => keywords.items = Some(self.node(value, &here)?),
                "properties" => {
                    let Value::Object(properties) = value else {
                        return Err(error(&here, "is not an object"));
                    };
                    for (name, property) in properties {
                        let property = self.node(property, &here.join(name))?;
                        keywords.properties.insert(name.clone(), property);
                    }
                }
                "required" => {
                    for name in array(value, &here)? {
                        let name = name.as_str().ok_or_else(|| error(&here, "is not names"))?;
                        keywords.required.push(name.to_string());
                    }
                }
                "additionalProperties" => keywords.additional = Some(self.node(value, &here)?),
                "allOf" => keywords.all_of = self.nodes(value, &here)?,
                "oneOf" => keywords.one_of = self.nodes(value, &here)?,
                "if" => condition = Some(self.node(value, &here)?),
                "then" => then = Some(self.node(value, &here)?),
                "not" => keywords.not = Some(self.node(value, &here)?),
                // The root's definitions are compiled on their own, and a
                // definition anywhere else could not be referred to.
                "$defs" if at.segments().is_empty() => {}
                "description" | "default" | "title" | "x-message" => {}
                _ => return Err(error(&here, "is not a keyword this validator checks")),
            }
        }
        // `if` alone checks nothing, and `then` alone is never applied.
        keywords.condition = match (condition, then) {
            (Some(condition), Some(then)) => Some((condition, then)),
            (Some(_) | None, None) => None,
            (None, Some(_)) => return Err(error(&at.join("then"), "has no 'if'")),
        };
        Ok(Node::Object(Box::new(keywords)))
    }

    fn nodes(&self, value: &Value, at: &Pointer) -> Result<Vec<Node>, SchemaError> {
        let list = array(value, at)?;
        if list.is_empty() {
            return Err(error(at, "is empty"));
        }
        list.iter()
            .enumerate()
            .map(|(index, schema)| self.node(schema, &at.join(&index.to_string())))
            .collect()
    }

    fn reference(&self, value: &Value, at: &Pointer) -> Result<usize, SchemaError> {
        let target = value.as_str().ok_or_else(|| error(at, "is not a string"))?;
        let pointer = target
            .strip_prefix('#')
            .map(Pointer::parse)
            .unwrap_or_default();
        let name = match pointer.segments() {
            [defs, name] if defs == "$defs" => name,
            _ => {
                return Err(error(
                    at,
                    "does not name a definition under the root's $defs",
                ));
            }
        };
        self.names
            .iter()
            .position(|known| *known == name)
            .ok_or_else(|| error(at, "names no definition"))
    }
}

/// A definition on a cycle of references through the keywords that check
/// the same value, if there is one.
fn first_cycle(definitions: &[Node]) -> Option<usize> {
    /// Where a walk from a definition is: not reached, on the current path,
    /// or done and free of cycles.
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        New,
        OnPath,
        Done,
    }
    /// The definition the walk from `index` finds on a cycle: the one it
    /// reaches while still on the path to it.
    fn visit(index: usize, definitions: &[Node], states: &mut [State]) -> Option<usize> {
        match states.get(index) {
            Some(State::OnPath) => return Some(index),
            Some(State::Done) | None => return None,
            Some(State::New) => {}
        }
        if let Some(state) = states.get_mut(index) {
            *state = State::OnPath;
        }
        let mut next = Vec::new();
        if let Some(definition) = definitions.get(index) {
            same_value_references(definition, &mut next);
        }
        if let Some(on_cycle) = next.iter().find_map(|&n| visit(n, definitions, states)) {
            return Some(on_cycle);
        }
        if let Some(state) = states.get_mut(index) {
            *state = State::Done;
        }
        None
    }
    let mut states = vec![State::New; definitions.len()];
    (0..definitions.len()).find_map(|index| visit(index, definitions, &mut states))
}

/// The definitions `node` refers to while checking the value it is given,
/// not one inside it.
fn same_value_references(node: &Node, out: &mut Vec<usize>) {
    let Node::Object(schema) = node else {
        return;
    };
    out.extend(schema.reference);
    let applied = schema
        .all_of
        .iter()
        .chain(&schema.one_of)
        .chain(
            schema
                .condition
                .iter()
                .flat_map(|(condition, then)| [condition, then]),
        )
        .chain(&schema.not);
    for node in applied {
        same_value_references(node, out);
    }
}

/// A schema error at `at`, written as a URI fragment so the root is `#`.
fn error(at: &Pointer, what: &str) -> SchemaError {
    SchemaError(format!("#{at} {what}"))
}

fn array<'a>(value: &'a Value, at: &Pointer) -> Result<&'a Vec<Value>, SchemaError> {
    value.as_array().ok_or_else(|| error(at, "is not an array"))
}

fn number(value: &Value, at: &Pointer) -> Result<Number, SchemaError> {
    match value {
        Value::Number(number) => Ok(number.clone()),
        _ => Err(error(at, "is not a number")),
    }
}

fn types(value: &Value, at: &Pointer) -> Result<Vec<String>, SchemaError> {
    let names: Vec<&Value> = match value {
        Value::Array(names) if !names.is_empty() => names.iter().collect(),
        Value::String(_) => vec![value],
        _ => return Err(error(at, "is not a type or a list of types")),
    };
    names
        .into_iter()
        .map(|name| match name.as_str() {
            Some(name) if TYPES.contains(&name) => Ok(name.to_string()),
            _ => Err(error(at, "names a type JSON does not have")),
        })
        .collect()
}

fn pattern(value: &Value, at: &Pointer) -> Result<(String, Regex), SchemaError> {
    let pattern = value.as_str().ok_or_else(|| error(at, "is not a string"))?;
    let regex = Regex::new(pattern).map_err(|e| error(at, &format!("does not compile: {e}")))?;
    Ok((pattern.to_string(), regex))
}

fn violation(path: &Pointer, schema_path: Pointer, keyword: Keyword) -> Violation {
    Violation {
        instance_path: path.clone(),
        schema_path,
        keyword,
    }
}

/// Whether `value` is of the JSON Schema type `name`. An integer is a number
/// serde reads into an integer field, so `2.0` is not one.
fn has_type(value: &Value, name: &str) -> bool {
    match (name, value) {
        ("null", Value::Null)
        | ("boolean", Value::Bool(_))
        | ("object", Value::Object(_))
        | ("array", Value::Array(_))
        | ("number", Value::Number(_))
        | ("string", Value::String(_)) => true,
        ("integer", Value::Number(number)) => number.is_i64() || number.is_u64(),
        _ => false,
    }
}

/// JSON Schema equality: numbers are equal by value, so `1` is `1.0`, and
/// arrays and objects are equal element by element.
fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => compare(a, b) == Some(Ordering::Equal),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| equal(a, b)))
        }
        _ => a == b,
    }
}

/// Order two numbers by value. Integers compare exactly, a float against
/// anything compares as floats.
fn compare(a: &Number, b: &Number) -> Option<Ordering> {
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => Some(a.cmp(&b)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ActionType;
    use crate::params::with_schema;
    use serde_json::json;

    fn compile(schema: &Value) -> Engine {
        Engine::new(schema).unwrap_or_else(|e| panic!("{e}"))
    }

    fn found(schema: &Value, instance: &Value) -> Vec<(String, String, String)> {
        compile(schema)
            .validate(instance)
            .into_iter()
            .map(|v| {
                (
                    v.instance_path.to_string(),
                    v.schema_path.to_string(),
                    v.keyword.name().to_string(),
                )
            })
            .collect()
    }

    /// Every constant an `enum` or `const` in the schema names.
    fn constants(value: &Value, out: &mut Vec<Value>) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    match (key.as_str(), child) {
                        ("enum", Value::Array(options)) => out.extend(options.iter().cloned()),
                        ("const", constant) => out.push(constant.clone()),
                        _ => constants(child, out),
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    constants(item, out);
                }
            }
            _ => {}
        }
    }

    /// The path in a value of every property `schema` names, at any depth,
    /// through references, applicators and `items` (as the first element).
    fn property_paths(root: &Value, schema: &Value, prefix: &[String], out: &mut Vec<Vec<String>>) {
        // Deep enough for every generated schema, and an end for one that
        // refers to itself inside the value.
        if prefix.len() > 4 {
            return;
        }
        let Value::Object(object) = schema else {
            return;
        };
        for (key, child) in object {
            match (key.as_str(), child) {
                ("$ref", Value::String(target)) => {
                    if let Some(definition) = target.strip_prefix('#').and_then(|p| root.pointer(p))
                    {
                        property_paths(root, definition, prefix, out);
                    }
                }
                ("properties", Value::Object(properties)) => {
                    for (name, property) in properties {
                        let mut path = prefix.to_vec();
                        path.push(name.clone());
                        out.push(path.clone());
                        property_paths(root, property, &path, out);
                    }
                }
                ("items", items) => {
                    let mut path = prefix.to_vec();
                    path.push("0".to_string());
                    property_paths(root, items, &path, out);
                }
                ("allOf" | "oneOf", Value::Array(rules)) => {
                    for rule in rules {
                        property_paths(root, rule, prefix, out);
                    }
                }
                ("if" | "then" | "not" | "additionalProperties", rule) => {
                    property_paths(root, rule, prefix, out);
                }
                _ => {}
            }
        }
    }

    /// `value` placed at `path` in `instance`, building the objects and the
    /// one-element lists on the way. `None` when `instance` already holds
    /// something else there.
    fn place(instance: &mut Value, path: &[String], value: &Value) -> Option<()> {
        let Some((first, rest)) = path.split_first() else {
            *instance = value.clone();
            return Some(());
        };
        if first == "0" {
            if instance.is_null() {
                *instance = json!([null]);
            }
            return place(instance.as_array_mut()?.first_mut()?, rest, value);
        }
        if instance.is_null() {
            *instance = json!({});
        }
        let child = instance
            .as_object_mut()?
            .entry(first.clone())
            .or_insert(Value::Null);
        if rest.is_empty() && !child.is_null() {
            return None;
        }
        place(child, rest, value)
    }

    /// A violation as both engines can say it: where, which keyword at which
    /// place in the schema, and what the messages read from it.
    type Said = (String, String, String);

    fn ours_said(violation: &Violation) -> Said {
        let detail = match &violation.keyword {
            Keyword::Type { expected } => {
                let mut expected = expected.clone();
                expected.sort();
                format!("type {expected:?}")
            }
            Keyword::AdditionalProperties { unexpected } => format!("unexpected {unexpected:?}"),
            Keyword::OneOf { matched } => format!("oneOf {matched:?}"),
            other => other.name().to_string(),
        };
        (
            violation.instance_path.to_string(),
            violation.schema_path.to_string(),
            detail,
        )
    }

    fn theirs_said(error: &jsonschema::ValidationError<'_>) -> Said {
        use jsonschema::error::{TypeKind, ValidationErrorKind as Kind};
        let detail = match error.kind() {
            Kind::Type { kind } => {
                let mut expected: Vec<String> = match kind {
                    TypeKind::Single(single) => vec![single.to_string()],
                    TypeKind::Multiple(set) => set.into_iter().map(|t| t.to_string()).collect(),
                };
                expected.sort();
                format!("type {expected:?}")
            }
            Kind::AdditionalProperties { unexpected } => format!("unexpected {unexpected:?}"),
            Kind::OneOfNotValid { .. } => format!("oneOf {:?}", Matched::None),
            Kind::OneOfMultipleValid { .. } => format!("oneOf {:?}", Matched::Several),
            Kind::FalseSchema => "false".to_string(),
            Kind::Constant { .. } => "const".to_string(),
            other => other.keyword().to_string(),
        };
        (
            error.instance_path().as_str().to_string(),
            error.schema_path().as_str().to_string(),
            detail,
        )
    }

    /// One of each JSON type, and the edges of the bounds the schemas use.
    fn values() -> Vec<Value> {
        vec![
            json!(null),
            json!(true),
            json!(""),
            json!("x"),
            json!("0x9a"),
            json!("9a"),
            json!("sha256:00"),
            json!(0),
            json!(-1),
            json!(1),
            json!(2.5),
            json!(3),
            json!(100),
            json!(101),
            json!(300),
            json!([]),
            json!(["x"]),
            json!([1]),
            json!({}),
            json!({"pattern": "[a-z]+"}),
            json!({"pattern": 1}),
            json!({"unexpected": 1}),
        ]
    }

    /// Each action's schema, against those values and every constant it
    /// names at the path of each property it has, at any depth, one property
    /// and two sibling properties at a time, gives the same violations as a
    /// complete implementation of the standard. A whole float is left out,
    /// being the one difference.
    #[test]
    fn every_action_schema_agrees_with_a_complete_validator() {
        let mut deepest = 0;
        for &action in ActionType::ALL {
            let schema = with_schema(action).to_value();
            let reference = jsonschema::draft202012::options()
                .should_validate_formats(false)
                .build(&schema)
                .unwrap();
            let ours = compile(&schema);
            let mut values = values();
            constants(&schema, &mut values);
            values.retain(|value| {
                !value
                    .as_f64()
                    .is_some_and(|f| value.is_f64() && f.fract() == 0.0)
            });
            let mut paths = Vec::new();
            property_paths(&schema, &schema, &[], &mut paths);
            paths.sort();
            paths.dedup();
            let mut instances = vec![json!(null), json!([]), json!({}), json!({"wibble": 1})];
            for path in &paths {
                for value in &values {
                    let mut one = Value::Null;
                    if place(&mut one, path, value).is_some() {
                        instances.push(one.clone());
                    }
                    let parent =
                        |path: &[String]| path.split_last().map(|(_, parent)| parent.to_vec());
                    let siblings = paths
                        .iter()
                        .filter(|other| *other != path && parent(other) == parent(path));
                    for other in siblings {
                        for second in values.iter().step_by(5) {
                            let mut two = one.clone();
                            if place(&mut two, other, second).is_some() {
                                instances.push(two);
                            }
                        }
                    }
                }
            }
            deepest = deepest.max(paths.iter().map(Vec::len).max().unwrap_or(0));
            for instance in &instances {
                let mut theirs: Vec<Said> = reference
                    .iter_errors(instance)
                    .map(|e| theirs_said(&e))
                    .collect();
                let mut mine: Vec<Said> = ours.validate(instance).iter().map(ours_said).collect();
                theirs.sort();
                mine.sort();
                assert_eq!(mine, theirs, "{action}: {instance}");
            }
        }
        // Some properties are inside others, such as a format's pattern.
        assert!(deepest >= 2, "no nested property was tried");
    }

    /// A float is not an integer, as serde reads it, but a number equals
    /// another of the same value.
    #[test]
    fn an_integer_is_what_serde_reads_as_one() {
        let schema = json!({"type": "integer"});
        assert!(found(&schema, &json!(2)).is_empty());
        assert!(found(&schema, &json!(-2)).is_empty());
        assert_eq!(
            found(&schema, &json!(2.0)),
            [(String::new(), "/type".to_string(), "type".to_string())]
        );
        assert!(found(&json!({"enum": [1, 2]}), &json!(2.0)).is_empty());
        assert!(found(&json!({"const": 2.0}), &json!(2)).is_empty());
        let bounded = json!({"minimum": 1, "maximum": u64::MAX});
        assert!(found(&bounded, &json!(u64::MAX)).is_empty());
        assert_eq!(found(&bounded, &json!(0.5)).len(), 1);
    }

    #[test]
    fn the_applicators_combine_as_the_standard_says() {
        let one_of = compile(&json!({"oneOf": [{"type": "integer"}, {"type": "number"}]}));
        assert!(matches!(
            one_of.validate(&json!(1)).as_slice(),
            [Violation {
                keyword: Keyword::OneOf {
                    matched: Matched::Several
                },
                ..
            }]
        ));
        assert!(one_of.validate(&json!(1.5)).is_empty());
        assert!(matches!(
            one_of.validate(&json!("x")).as_slice(),
            [Violation {
                keyword: Keyword::OneOf {
                    matched: Matched::None
                },
                ..
            }]
        ));

        let rule = json!({
            "if": {"required": ["a"]},
            "then": {"required": ["b"]},
        });
        assert!(found(&rule, &json!({})).is_empty());
        assert_eq!(
            found(&rule, &json!({"a": 1})),
            [(
                String::new(),
                "/then/required".to_string(),
                "required".to_string()
            )]
        );

        let items = json!({"items": {"type": "string"}, "minItems": 2});
        assert_eq!(
            found(&items, &json!(["x", 1])),
            [(
                "/1".to_string(),
                "/items/type".to_string(),
                "type".to_string()
            )]
        );

        let open = json!({"properties": {"a": true}, "additionalProperties": {"type": "string"}});
        assert_eq!(
            found(&open, &json!({"a": 1, "b": 2})),
            [(
                "/b".to_string(),
                "/additionalProperties/type".to_string(),
                "type".to_string()
            )]
        );
    }

    #[test]
    fn a_schema_outside_the_keywords_does_not_compile() {
        let refused = [
            json!({"format": "date"}),
            json!({"$ref": "#/$defs/Missing"}),
            json!({"$ref": "https://example.com/schema"}),
            json!({"pattern": "[0-9"}),
            json!({"type": "float"}),
            json!({"then": {}}),
            json!({"allOf": []}),
            json!({"properties": {"a": {"$defs": {}}}}),
            json!(1),
            json!({"$defs": {"A": {"$ref": "#/$defs/A"}}, "$ref": "#/$defs/A"}),
            json!({"$defs": {
                "A": {"allOf": [{"$ref": "#/$defs/B"}]},
                "B": {"not": {"$ref": "#/$defs/A"}},
            }}),
        ];
        for schema in refused {
            assert!(Engine::new(&schema).is_err(), "{schema}");
        }
    }

    /// The error names a definition on the cycle, not one that only leads
    /// into it, and the root's location is `#`.
    #[test]
    fn a_schema_error_says_where_it_is() {
        let schema = json!({"$defs": {
            "A": {"allOf": [{"$ref": "#/$defs/B"}]},
            "B": {"allOf": [{"$ref": "#/$defs/B"}]},
        }});
        let Err(error) = Engine::new(&schema) else {
            panic!("a cycle compiles");
        };
        assert!(error.to_string().contains("#/$defs/B "), "{error}");
        let Err(error) = Engine::new(&json!(1)) else {
            panic!("a number compiles");
        };
        assert_eq!(error.to_string(), "invalid schema: # is not a schema");
    }

    /// A definition that refers to itself inside the value checks a smaller
    /// value each time, so it ends.
    #[test]
    fn a_definition_may_refer_to_itself_inside_the_value() {
        let tree = json!({
            "$defs": {"Tree": {
                "type": "object",
                "properties": {"children": {"items": {"$ref": "#/$defs/Tree"}}},
                "additionalProperties": false,
            }},
            "$ref": "#/$defs/Tree",
        });
        assert!(found(&tree, &json!({"children": [{"children": []}]})).is_empty());
        assert_eq!(
            found(&tree, &json!({"children": [{"leaf": 1}]})),
            [(
                "/children/0".to_string(),
                "/$defs/Tree/additionalProperties".to_string(),
                "additionalProperties".to_string()
            )]
        );
    }
}
