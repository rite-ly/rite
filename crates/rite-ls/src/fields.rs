//! What the ceremony schema says at a place in a document: the fields a map
//! takes, the values a field takes, and what each of them means.
//!
//! The schema is the one published for editors, so completion and hover
//! offer what `rite check` accepts, described as the schema describes it.
//! The place is read from the lines above the cursor by their indentation,
//! not from a parse, since a document being typed is often not valid YAML.

use std::sync::OnceLock;

use serde_json::Value;
use tower_lsp_server::ls_types::{
    CompletionItem, CompletionItemKind, Documentation, MarkupContent, MarkupKind, Position,
};

/// The editor schema, generated on first use.
fn schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| rite_resolver::editor_schema().to_value())
}

/// One step down from a map or a list.
#[derive(Debug, Clone, PartialEq)]
enum Segment {
    /// The value of a key.
    Key(String),
    /// An item of a list.
    Item,
}

/// The keys of a map in the document, with the scalar each one holds, empty
/// for a key whose value is on the lines below.
type Members = Vec<(String, String)>;

/// A place in the document: the path from the top to a map, and the members
/// of each map along it, the top's first.
#[derive(Debug)]
struct Place {
    path: Vec<Segment>,
    maps: Vec<Members>,
}

/// One line of the document, as the outline reads it.
#[derive(Debug, Clone, Copy)]
struct Line<'a> {
    /// The column of the line's first character, a list item's `-`.
    start: usize,
    /// The column of the key, after a list item's `- `.
    indent: usize,
    /// Whether the line starts a list item.
    item: bool,
    /// The key the line writes.
    key: Option<&'a str>,
    /// What follows the key's colon, or the whole line when it has no key.
    value: &'a str,
}

/// Read `text` as one line of the outline, or nothing for a blank line or
/// a comment.
fn read_line(text: &str) -> Option<Line<'_>> {
    let rest = text.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        return None;
    }
    let start = text.len() - rest.len();
    let (item, body) = match rest.strip_prefix('-') {
        Some(after) if after.is_empty() || after.starts_with(' ') => (true, after.trim_start()),
        _ => (false, rest),
    };
    let indent = text.len() - body.len();
    let body = without_comment(body);
    let (key, value) = match body.split_once(':') {
        Some((key, value)) if is_key(key) && (value.is_empty() || value.starts_with(' ')) => {
            (Some(key), value.trim())
        }
        _ => (None, body.trim()),
    };
    Some(Line {
        start,
        indent,
        item,
        key,
        value,
    })
}

/// `text` without a trailing comment: a `#` after a space, outside quotes.
fn without_comment(text: &str) -> &str {
    let mut quote = None;
    let mut previous = ' ';
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(open), _) if c == open => quote = None,
            (None, '#') if previous == ' ' => return text.get(..at).unwrap_or(text),
            _ => {}
        }
        previous = c;
    }
    text
}

fn is_key(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The members of the map whose keys sit at column `indent`, from line
/// `from` on, until a line further left.
fn members(lines: &[Option<Line<'_>>], from: usize, indent: usize) -> Members {
    lines
        .iter()
        .skip(from)
        .flatten()
        .take_while(|line| line.start >= indent)
        .filter(|line| line.start == indent && !line.item)
        .filter_map(|line| Some((line.key?.to_string(), line.value.to_string())))
        .collect()
}

/// The place of a map whose keys start at column `indent`, above line
/// `below`. An `item` place is the map a list item starts on line `below`
/// itself.
fn place(lines: &[Option<Line<'_>>], below: usize, indent: usize, item: bool) -> Place {
    // From the innermost: each segment, the line its map's keys start after,
    // and their column. An item's map also holds the key on its own line.
    let mut chain: Vec<(Segment, usize, usize)> = Vec::new();
    let mut limit = indent;
    // Whether the last segment is a list item, whose list's key may be in
    // the column of its `-`.
    let mut in_item = item;
    if item {
        let key_indent = lines
            .get(below)
            .copied()
            .flatten()
            .map_or(indent + 2, |line| line.indent);
        chain.push((Segment::Item, below, key_indent));
    }
    for (index, line) in lines.iter().enumerate().take(below).rev() {
        if limit == 0 && !in_item {
            break;
        }
        let Some(line) = line else { continue };
        let list_key = in_item && line.start == limit && !line.item && line.key.is_some();
        if line.start > limit || (line.start == limit && !list_key) {
            continue;
        }
        in_item = line.item;
        if line.item {
            if let Some(key) = line.key
                && line.indent < limit
            {
                chain.push((Segment::Key(key.to_string()), index, limit));
            }
            chain.push((Segment::Item, index, line.indent));
        } else if let Some(key) = line.key {
            chain.push((Segment::Key(key.to_string()), index, limit));
        }
        limit = line.start;
    }
    chain.reverse();
    let mut maps = vec![members(lines, 0, 0)];
    let mut path = Vec::new();
    for (segment, after, indent) in chain {
        let mut map = members(lines, after + 1, indent);
        if segment == Segment::Item
            && let Some(Some(line)) = lines.get(after)
            && let Some(key) = line.key
        {
            map.insert(0, (key.to_string(), line.value.to_string()));
        }
        path.push(segment);
        maps.push(map);
    }
    Place { path, maps }
}

/// `node`, after any reference and with an expression's alternative set
/// aside.
fn resolve(mut node: &Value) -> &Value {
    for _ in 0..16 {
        if let Some(target) = node.get("$ref").and_then(Value::as_str) {
            match target.strip_prefix('#').and_then(|at| schema().pointer(at)) {
                Some(found) => node = found,
                None => break,
            }
        } else if let Some(Value::Array(alternatives)) = node.get("anyOf")
            && let [value, expression] = alternatives.as_slice()
            && expression.get("$ref").and_then(Value::as_str) == Some("#/$defs/Expression")
        {
            node = value;
        } else {
            break;
        }
    }
    node
}

/// Whether the members of a map meet the condition `rule`, as JSON Schema
/// reads it: each key it requires is written, and each key written meets
/// what the condition says of it.
///
/// Only `const` and `type` are read, the keywords the schema's conditions
/// use on a value; a key whose value is on the lines below is taken as a map
/// or a list.
fn holds(rule: &Value, map: &Members) -> bool {
    let written = |key: &str| map.iter().find(|(name, _)| name == key).map(|(_, v)| v);
    let required = rule
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .all(|key| written(key).is_some());
    let properties = rule
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .all(|(key, condition)| written(key).is_none_or(|value| meets(value, condition)));
    required && properties
}

/// Whether a value written as `value` meets `condition`.
fn meets(value: &str, condition: &Value) -> bool {
    let value = unquoted(value);
    let nested = value.is_empty() || value.starts_with('{') || value.starts_with('[');
    let constant = condition
        .get("const")
        .is_none_or(|constant| constant.as_str() == Some(value));
    let kind = match condition.get("type").and_then(Value::as_str) {
        Some("object" | "array") => nested,
        Some(_) => !nested,
        None => true,
    };
    constant && kind
}

fn unquoted(value: &str) -> &str {
    value.trim_matches(|c| c == '"' || c == '\'')
}

/// The schemas a map at `node` is held to, given what it holds: `node`, and
/// each rule it combines whose condition the map meets.
fn branches<'a>(node: &'a Value, map: &Members, out: &mut Vec<&'a Value>) {
    let node = resolve(node);
    out.push(node);
    let rules = node.get("allOf").and_then(Value::as_array);
    for rule in rules.into_iter().flatten() {
        match rule.get("if") {
            Some(condition) => {
                if holds(condition, map)
                    && let Some(then) = rule.get("then")
                {
                    branches(then, map, out);
                }
            }
            None => branches(rule, map, out),
        }
    }
}

/// The schemas a value is held to: a key can be named by several rules,
/// as a step's `with` is by the step and by its action.
type Node = Vec<&'static Value>;

/// The fields a map held to `node` takes, each with its schemas, in the
/// order the schema names them.
fn fields(node: &[&'static Value], map: &Members) -> Vec<(&'static str, Node)> {
    let mut found = Vec::new();
    for schema in node {
        branches(schema, map, &mut found);
    }
    let mut fields: Vec<(&str, Node)> = Vec::new();
    for branch in found {
        let properties = branch.get("properties").and_then(Value::as_object);
        for (name, property) in properties.into_iter().flatten() {
            match fields.iter_mut().find(|(known, _)| known == name) {
                Some((_, schemas)) => schemas.push(property),
                None => fields.push((name, vec![property])),
            }
        }
    }
    fields
}

/// The schemas of `key` in a map held to `node`: the field it names, or
/// what each entry is in a map keyed by ids.
fn field(node: &[&'static Value], key: &str, map: &Members) -> Node {
    if let Some((_, schemas)) = fields(node, map).into_iter().find(|(name, _)| *name == key) {
        return schemas;
    }
    let mut found = Vec::new();
    for schema in node {
        branches(schema, map, &mut found);
    }
    found
        .into_iter()
        .filter_map(|branch| branch.get("additionalProperties").filter(|a| a.is_object()))
        .collect()
}

/// The schemas at `place`, empty where the schema does not reach.
fn node_at(place: &Place) -> Node {
    let mut node = vec![schema()];
    for (segment, map) in place.path.iter().zip(&place.maps) {
        node = match segment {
            Segment::Key(key) => field(&node, key, map),
            Segment::Item => node
                .iter()
                .filter_map(|schema| resolve(schema).get("items"))
                .collect(),
        };
        if node.is_empty() {
            break;
        }
    }
    node
}

fn description(node: &[&'static Value]) -> Option<&'static str> {
    node.iter().find_map(|schema| {
        schema
            .get("description")
            .or_else(|| resolve(schema).get("description"))
            .and_then(Value::as_str)
    })
}

/// The values a field takes from a fixed list, each with its description.
fn values(node: &[&'static Value]) -> Vec<(String, Option<&'static str>)> {
    let mut values: Vec<(String, Option<&str>)> = Vec::new();
    let mut add = |name: &str, text: Option<&'static str>| match values
        .iter_mut()
        .find(|(known, _)| known == name)
    {
        Some(value) => value.1 = value.1.or(text),
        None => values.push((name.to_string(), text)),
    };
    for schema in node {
        let schema = resolve(schema);
        let names = schema.get("enum").and_then(Value::as_array);
        for name in names.into_iter().flatten().filter_map(Value::as_str) {
            add(name, None);
        }
        let alternatives = schema
            .get("oneOf")
            .or_else(|| schema.get("anyOf"))
            .and_then(Value::as_array);
        for alternative in alternatives.into_iter().flatten() {
            let alternative = resolve(alternative);
            if let Some(name) = alternative.get("const").and_then(Value::as_str) {
                add(name, description(&[alternative]));
            }
        }
        if schema.get("type").and_then(Value::as_str) == Some("boolean") {
            add("true", None);
            add("false", None);
        }
    }
    values
}

/// The first sentence of `text`, for a one-line summary.
fn first_sentence(text: &str) -> &str {
    let paragraph = text.split("\n\n").next().unwrap_or(text);
    paragraph
        .find(". ")
        .and_then(|end| paragraph.get(..=end))
        .unwrap_or(paragraph)
}

fn completion(label: &str, text: Option<&str>, kind: CompletionItemKind) -> CompletionItem {
    CompletionItem {
        label: label.to_string(),
        kind: Some(kind),
        detail: text.map(|text| first_sentence(text).to_string()),
        documentation: text.map(|text| {
            Documentation::MarkupContent(MarkupContent {
                kind: MarkupKind::Markdown,
                value: text.to_string(),
            })
        }),
        ..Default::default()
    }
}

/// The document's lines, read for the outline.
fn outline(text: &str) -> Vec<Option<Line<'_>>> {
    text.lines().map(read_line).collect()
}

/// Completions from the schema at `pos`: the fields the map there takes and
/// it does not hold yet, while a key is typed; the values a field takes,
/// after its key.
pub fn completions(text: &str, pos: Position) -> Vec<CompletionItem> {
    let lines = outline(text);
    let row = pos.line as usize;
    let current = text.lines().nth(row).unwrap_or("");
    let before = current
        .char_indices()
        .nth(pos.character as usize)
        .map_or(current, |(end, _)| current.get(..end).unwrap_or(current));
    let typed = before.trim_start();
    let start = before.len() - typed.len();
    let (item, typed) = match typed.strip_prefix("- ") {
        Some(rest) => (true, rest),
        None => (false, typed),
    };

    if let Some((key, value)) = typed.split_once(':') {
        let value = value.trim_start();
        if !is_key(key) || value.contains("${") {
            return Vec::new();
        }
        let place = place(&lines, row, start, item);
        let map = place.maps.last().cloned().unwrap_or_default();
        return values(&field(&node_at(&place), key, &map))
            .into_iter()
            .filter(|(name, _)| name.starts_with(unquoted(value)))
            .map(|(name, text)| completion(&name, text, CompletionItemKind::ENUM_MEMBER))
            .collect();
    }

    if !typed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Vec::new();
    }
    let place = place(&lines, row, start, item);
    let map = place.maps.last().cloned().unwrap_or_default();
    fields(&node_at(&place), &map)
        .into_iter()
        .filter(|(name, _)| !map.iter().any(|(written, _)| written == name))
        .map(|(name, node)| {
            let mut item = completion(name, description(&node), CompletionItemKind::FIELD);
            item.insert_text = Some(format!("{name}: "));
            item
        })
        .collect()
}

/// What the schema says of the key or the value at `pos`, in Markdown.
pub fn hover(text: &str, pos: Position) -> Option<String> {
    let lines = outline(text);
    let row = pos.line as usize;
    let line = lines.get(row).copied().flatten()?;
    let key = line.key?;
    let column = pos.character as usize;
    let place = place(&lines, row, line.start, line.item);
    let map = place.maps.last().cloned().unwrap_or_default();
    let node = field(&node_at(&place), key, &map);

    let on_key = (line.indent..=line.indent + key.len()).contains(&column);
    let markdown = if on_key {
        format!("**`{key}`**\n\n{}", description(&node)?)
    } else {
        let value = unquoted(line.value);
        let (_, text) = values(&node).into_iter().find(|(name, _)| name == value)?;
        format!("**`{value}`**\n\n{}", text?)
    };
    Some(markdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = "\
version: \"0.3\"
name: Example
roles:
  operator: {}
backends:
  ssl:
    provider: openssl
sections:
  keys:
    role: ${role.operator}
    steps:
      generate:
        action: generate_key
        backend: ssl
        with:
          algorithm: ECDSA-P256
          policy:
            extractable: true
        creates: root
acts:
  - id: opening
    name: Opening
";

    fn at(text: &str, line: u32, character: u32) -> Position {
        let _ = text;
        Position { line, character }
    }

    fn with_line(line: u32, text: &str) -> String {
        let mut lines: Vec<&str> = DOCUMENT.lines().collect();
        lines.insert(line as usize, text);
        lines.join("\n")
    }

    fn labels(items: &[CompletionItem]) -> Vec<String> {
        items.iter().map(|item| item.label.clone()).collect()
    }

    fn hover_text(text: &str, pos: Position) -> String {
        hover(text, pos).unwrap_or_default()
    }

    /// Inside `with:`, the fields offered are the action's, without those
    /// already written, and each carries its description.
    #[test]
    fn a_with_block_offers_its_action_s_fields() {
        let text = with_line(18, "          sl");
        let items = completions(&text, at(&text, 18, 12));
        let offered = labels(&items);
        assert!(offered.iter().any(|name| name == "slot"), "{offered:?}");
        assert!(
            !offered.iter().any(|name| name == "algorithm"),
            "{offered:?}"
        );
        let slot = items.iter().find(|item| item.label == "slot").unwrap();
        assert!(
            slot.detail
                .as_deref()
                .unwrap()
                .starts_with("A backend-specific location")
        );
        assert_eq!(slot.insert_text.as_deref(), Some("slot: "));
    }

    /// A step offers its own fields, the ones its action asks for among them.
    #[test]
    fn a_step_offers_the_step_fields() {
        let text = with_line(19, "        re");
        let offered = labels(&completions(&text, at(&text, 19, 10))).join(" ");
        for field in ["reads", "retry", "description", "silent"] {
            assert!(
                offered.split(' ').any(|name| name == field),
                "{field} missing from {offered}"
            );
        }
        assert!(
            !offered.split(' ').any(|name| name == "action"),
            "{offered}"
        );
    }

    /// The top of the document offers the definition's fields.
    #[test]
    fn the_top_offers_the_definition_fields() {
        let text = with_line(2, "");
        let offered = labels(&completions(&text, at(&text, 2, 0))).join(" ");
        assert!(
            offered.split(' ').any(|name| name == "materials"),
            "{offered}"
        );
        assert!(
            !offered.split(' ').any(|name| name == "version"),
            "{offered}"
        );
    }

    /// A comment after a value is not part of it.
    #[test]
    fn a_comment_does_not_hide_the_action() {
        let text = with_line(18, "          sl").replace(
            "action: generate_key",
            "action: generate_key  # the root key",
        );
        let offered = labels(&completions(&text, at(&text, 18, 12)));
        assert!(offered.iter().any(|name| name == "slot"), "{offered:?}");
        assert!(without_comment("'a # b' # c").trim() == "'a # b'");
    }

    /// A list written in its key's column is still that key's list.
    #[test]
    fn a_list_in_its_key_s_column_is_found() {
        let text = DOCUMENT.replace("  - id: opening\n    name:", "- id: opening\n  name:");
        let text = format!("{text}  desc");
        let offered = labels(&completions(&text, at(&text, 22, 6)));
        assert_eq!(offered, ["description"]);
    }

    /// A condition on a key the map does not write holds, as in JSON Schema.
    #[test]
    fn a_condition_on_an_absent_key_holds() {
        let rule = serde_json::json!({ "properties": { "scheme": { "const": "rite-sss/v1" } } });
        assert!(holds(&rule, &Vec::new()));
        let written = vec![("scheme".to_string(), "other".to_string())];
        assert!(!holds(&rule, &written));
        let object = serde_json::json!({ "properties": { "format": { "type": "object" } } });
        let hex = vec![("format".to_string(), "hex".to_string())];
        assert!(!holds(&object, &hex));
    }

    /// A list item's map offers its fields.
    #[test]
    fn a_list_item_offers_its_fields() {
        let text = format!("{DOCUMENT}    desc");
        let offered = labels(&completions(&text, at(&text, 22, 8)));
        assert_eq!(offered, ["description"]);
    }

    /// After a key, the values its field takes, filtered by what is typed.
    #[test]
    fn a_field_offers_its_values() {
        let text = DOCUMENT.replace("algorithm: ECDSA-P256", "algorithm: ML-");
        let offered = labels(&completions(&text, at(&text, 15, 24)));
        assert!(!offered.is_empty());
        assert!(
            offered.iter().all(|name| name.starts_with("ML-")),
            "{offered:?}"
        );

        let text = DOCUMENT.replace("extractable: true", "extractable: ");
        let offered = labels(&completions(&text, at(&text, 17, 25)));
        assert_eq!(offered, ["true", "false"]);
    }

    /// `action:` offers every action, each with its summary.
    #[test]
    fn an_action_is_offered_with_its_summary() {
        let text = DOCUMENT.replace("action: generate_key", "action: ");
        let items = completions(&text, at(&text, 12, 16));
        assert_eq!(items.len(), rite_model::ActionType::ALL.len());
        let wrap = items.iter().find(|item| item.label == "wrap_key").unwrap();
        assert_eq!(
            wrap.detail.as_deref(),
            Some(rite_model::ActionType::WrapKey.summary())
        );
    }

    /// Hovering a key shows its field's description; hovering a value from a
    /// list shows the value's.
    #[test]
    fn hover_describes_keys_and_values() {
        let on_key = hover_text(DOCUMENT, at(DOCUMENT, 17, 14));
        assert!(on_key.starts_with("**`extractable`**"), "{on_key}");
        assert!(on_key.contains("exported from the backend"), "{on_key}");

        let on_action = hover_text(DOCUMENT, at(DOCUMENT, 12, 20));
        assert_eq!(
            on_action,
            format!(
                "**`generate_key`**\n\n{}",
                rite_model::ActionType::GenerateKey.description()
            )
        );

        let on_role = hover_text(DOCUMENT, at(DOCUMENT, 9, 5));
        assert!(on_role.starts_with("**`role`**"), "{on_role}");
    }

    /// A value with no description of its own, and a key the schema does
    /// not name, have no hover.
    #[test]
    fn hover_says_nothing_it_does_not_know() {
        assert!(hover(DOCUMENT, at(DOCUMENT, 15, 24)).is_none());
        let text = DOCUMENT.replace("algorithm:", "algorithmm:");
        assert!(hover(&text, at(&text, 15, 12)).is_none());
    }
}
