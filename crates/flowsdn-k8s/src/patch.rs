//! Guarded JSON-patch fallback for core/v1 Node /status. Send only after an
//! explicit capability probe. On conflict reread and rebuild; never replay.
use crate::Error;
use serde_json::{Value, json};
use std::collections::BTreeMap;
pub const CONTENT_TYPE: &str = "application/json-patch+json";
fn escaped(key: &str) -> String { key.replace('~', "~0").replace('/', "~1") }
/// None annotation values are ignored, matching the strategic-merge writer.
/// Existing foreign annotations and condition types are preserved. Both object
/// identity and revision are tested before any mutation, including absent maps.
pub fn node_status_patch(node: &Value, annotations: &BTreeMap<String, Option<String>>, condition: Option<&Value>) -> Result<Vec<Value>, Error> {
    let metadata = node.get("metadata").and_then(Value::as_object).ok_or_else(|| Error("missing node metadata".into()))?;
    let mut ops = Vec::new();
    for field in ["uid", "resourceVersion"] {
        let value = metadata.get(field).and_then(Value::as_str).filter(|v| !v.is_empty()).ok_or_else(|| Error(format!("missing node {field}")))?;
        ops.push(json!({"op":"test", "path":format!("/metadata/{field}"), "value":value}));
    }
    let updates: serde_json::Map<String, Value> = annotations.iter().filter_map(|(key, value)| value.as_ref().map(|value| (key.clone(), json!(value)))).collect();
    if !updates.is_empty() {
        match metadata.get("annotations") {
            None | Some(Value::Null) => ops.push(json!({"op":"add", "path":"/metadata/annotations", "value":updates})),
            Some(Value::Object(_)) => for (key, value) in updates { ops.push(json!({"op":"add", "path":format!("/metadata/annotations/{}", escaped(&key)), "value":value})); },
            _ => return Err(Error("node annotations is not an object".into())),
        }
    }
    if let Some(condition) = condition {
        let kind = condition.get("type").and_then(Value::as_str).filter(|v| !v.is_empty()).ok_or_else(|| Error("condition requires a type".into()))?;
        match node.get("status") {
            None | Some(Value::Null) => ops.push(json!({"op":"add", "path":"/status", "value":{"conditions":[condition]}})),
            Some(Value::Object(status)) => match status.get("conditions") {
                None | Some(Value::Null) => ops.push(json!({"op":"add", "path":"/status/conditions", "value":[condition]})),
                Some(Value::Array(conditions)) => {
                    let mut seen = std::collections::BTreeSet::new();
                    let mut index = None;
                    for (position, existing) in conditions.iter().enumerate() {
                        let existing_kind = existing.get("type").and_then(Value::as_str).filter(|v| !v.is_empty()).ok_or_else(|| Error("existing condition requires a type".into()))?;
                        if !seen.insert(existing_kind) { return Err(Error("duplicate condition type".into())); }
                        if existing_kind == kind { index = Some(position); }
                    }
                    match index {
                        Some(index) => {
                            let mut merged = conditions.get(index).and_then(Value::as_object).cloned().ok_or_else(|| Error("invalid condition object".into()))?;
                            for (key, value) in condition.as_object().ok_or_else(|| Error("invalid condition update".into()))? {
                                if value.is_null() { merged.remove(key); } else { merged.insert(key.clone(), value.clone()); }
                            }
                            ops.push(json!({"op":"replace", "path":format!("/status/conditions/{index}"), "value":merged}));
                        },
                        None => ops.push(json!({"op":"add", "path":"/status/conditions/-", "value":condition})),
                    }
                }
                _ => return Err(Error("node conditions is not an array".into())),
            },
            _ => return Err(Error("node status is not an object".into())),
        }
    }
    Ok(ops)
}
