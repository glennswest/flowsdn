//! Ordered documents written as the reference's encoders write them: JSON
//! with two-space indentation (Go `json.MarshalIndent`) and YAML with
//! four-space indentation (go-yaml v3). Field order is the struct's.
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Doc {
    Map(Vec<(String, Doc)>),
    Seq(Vec<Doc>),
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
}

impl Doc {
    pub fn map(fields: impl IntoIterator<Item = (impl Into<String>, Doc)>) -> Self {
        Self::Map(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
    pub fn str(text: impl Into<String>) -> Self {
        Self::Str(text.into())
    }
}

/// A number as Go's `strconv.FormatFloat(v, 'g'-ish, -1)` writes the values
/// the corpus holds: integers without a fraction, the shortest round trip.
fn number(value: f64) -> String {
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        format!("{value}")
    }
}

/// `json.MarshalIndent(v, "", "  ")` plus the encoder's newline.
pub fn json(doc: &Doc) -> String {
    let mut out = String::new();
    json_into(&mut out, doc, 0);
    out.push('\n');
    out
}
fn json_into(out: &mut String, doc: &Doc, indent: usize) {
    let pad = |out: &mut String, n: usize| out.extend(std::iter::repeat_n(' ', n));
    let inner = indent.saturating_add(2);
    match doc {
        Doc::Map(fields) if fields.is_empty() => out.push_str("{}"),
        Doc::Seq(items) if items.is_empty() => out.push_str("[]"),
        Doc::Map(fields) => {
            out.push_str("{\n");
            for (index, (key, value)) in fields.iter().enumerate() {
                pad(out, inner);
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push_str(": ");
                json_into(out, value, inner);
                if index.saturating_add(1) < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(out, indent);
            out.push('}');
        }
        Doc::Seq(items) => {
            out.push_str("[\n");
            for (index, value) in items.iter().enumerate() {
                pad(out, inner);
                json_into(out, value, inner);
                if index.saturating_add(1) < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            pad(out, indent);
            out.push(']');
        }
        Doc::Num(value) => out.push_str(&number(*value)),
        Doc::Str(text) => out.push_str(&serde_json::Value::String(text.clone()).to_string()),
        Doc::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Doc::Null => out.push_str("null"),
    }
}

/// go-yaml v3 (indent 4): a mapping's children four columns in from the
/// mapping; a sequence under a key four columns in; a mapping that is a
/// sequence item starts after `- ` but indents its children from the dash.
pub fn yaml(doc: &Doc) -> String {
    let mut out = String::new();
    match doc {
        Doc::Map(fields) if !fields.is_empty() => map_into(&mut out, fields, 0, 0),
        Doc::Seq(items) if !items.is_empty() => seq_into(&mut out, items, 0),
        _ => {
            out.push_str(&scalar(doc));
            out.push('\n');
        }
    }
    out
}
fn scalar(doc: &Doc) -> String {
    match doc {
        Doc::Map(_) => "{}".into(),
        Doc::Seq(_) => "[]".into(),
        Doc::Num(value) => number(*value),
        Doc::Str(text) => {
            if crate::k8s::go_plain(text) {
                text.clone()
            } else {
                serde_json::Value::String(text.clone()).to_string()
            }
        }
        Doc::Bool(value) => value.to_string(),
        Doc::Null => "null".into(),
    }
}
fn nested(doc: &Doc) -> bool {
    match doc {
        Doc::Map(fields) => !fields.is_empty(),
        Doc::Seq(items) => !items.is_empty(),
        _ => false,
    }
}
/// Keys at column `column`; children indented from `base`.
fn map_into(out: &mut String, fields: &[(String, Doc)], column: usize, base: usize) {
    for (index, (key, value)) in fields.iter().enumerate() {
        // The first key of a sequence item follows its `- ` on the same line.
        if index > 0 || column == base {
            out.extend(std::iter::repeat_n(' ', column));
        }
        out.push_str(&scalar(&Doc::Str(key.clone())));
        out.push(':');
        let child = base.saturating_add(4);
        match value {
            Doc::Map(inner) if nested(value) => {
                out.push('\n');
                map_into(out, inner, child, child);
            }
            Doc::Seq(items) if nested(value) => {
                out.push('\n');
                seq_into(out, items, child);
            }
            _ => {
                let _ = write!(out, " {}", scalar(value));
                out.push('\n');
            }
        }
    }
}
fn seq_into(out: &mut String, items: &[Doc], dash: usize) {
    for item in items {
        out.extend(std::iter::repeat_n(' ', dash));
        out.push_str("- ");
        match item {
            Doc::Map(fields) if nested(item) => {
                map_into(out, fields, dash.saturating_add(2), dash);
            }
            Doc::Seq(inner) if nested(item) => {
                out.push('\n');
                seq_into(out, inner, dash.saturating_add(4));
            }
            _ => {
                out.push_str(&scalar(item));
                out.push('\n');
            }
        }
    }
}
