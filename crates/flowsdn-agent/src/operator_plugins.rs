//! FlowsdnDatapathPlugin objects are not applied (#566, spec 01's datapath
//! plugin decision): flowsdn loads no third-party BPF into its datapath. The
//! kind stays registered, so the CRD set is complete, but an object of it
//! must not look as if it does something. While leading, the operator lists
//! them every minute and posts one `Warning` `NotApplied` Event on each object
//! (by uid) it has not reported in this leader term.
use crate::operator_gc::Send;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const PLUGINS: &str = "/apis/flowsdn.io/v1alpha1/flowsdndatapathplugins";
const EVENTS: &str = "/api/v1/namespaces/default/events";
pub const REASON: &str = "NotApplied";
pub const MESSAGE: &str =
    "flowsdn loads no datapath plugins: this object is registered but not applied (spec 01, flowsdn#566)";

/// The Events to post for `plugins` (a list's items), skipping uids already
/// reported; `now` is RFC 3339. Each Event's name is `<object>.<uid prefix>`,
/// so an operator that restarts posts the same name (409: already reported).
pub fn plan(plugins: &[Value], reported: &BTreeSet<String>, now: &str) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for plugin in plugins {
        let name = plugin.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("");
        let uid = plugin.pointer("/metadata/uid").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || uid.is_empty() || reported.contains(uid) {
            continue;
        }
        let event_name = format!("{name}.{}", uid.chars().take(8).collect::<String>());
        out.push((
            uid.to_owned(),
            json!({
                "apiVersion": "v1",
                "kind": "Event",
                "metadata": {"name": event_name, "namespace": "default"},
                "involvedObject": {
                    "apiVersion": "flowsdn.io/v1alpha1",
                    "kind": "FlowsdnDatapathPlugin",
                    "name": name,
                    "uid": uid,
                },
                "reason": REASON,
                "message": MESSAGE,
                "type": "Warning",
                "count": 1,
                "firstTimestamp": now,
                "lastTimestamp": now,
                "source": {"component": "flowsdn-operator"},
                "reportingComponent": "flowsdn-operator",
            }),
        ));
    }
    out
}

/// One pass: list, post an Event on each object not yet reported (a 409 is
/// one already posted). Returns the names reported this pass.
pub fn report(reported: &mut BTreeSet<String>, now: &str, send: &mut Send<'_>) -> Result<Vec<String>, String> {
    let list = match send(http::Method::GET, PLUGINS, None).map_err(|e| format!("{PLUGINS}: {e}"))? {
        (200, body) => body,
        // The CRD not registered yet: nothing to report.
        (404, _) => return Ok(Vec::new()),
        (status, body) => {
            return Err(format!(
                "{PLUGINS}: HTTP {status} {}",
                body.get("message").and_then(Value::as_str).unwrap_or("")
            ));
        }
    };
    let items = list.get("items").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    // Forget objects that are gone, so the set stays bounded.
    let present: BTreeSet<&str> = items
        .iter()
        .filter_map(|p| p.pointer("/metadata/uid").and_then(Value::as_str))
        .collect();
    reported.retain(|uid| present.contains(uid.as_str()));
    let mut names = Vec::new();
    for (uid, event) in plan(items, reported, now) {
        match send(http::Method::POST, EVENTS, Some(&event)).map_err(|e| format!("{EVENTS}: {e}"))? {
            (200..=299 | 409, _) => {
                reported.insert(uid);
                if let Some(name) = event.pointer("/involvedObject/name").and_then(Value::as_str) {
                    names.push(name.to_owned());
                }
            }
            (status, body) => {
                return Err(format!(
                    "{EVENTS}: HTTP {status} {}",
                    body.get("message").and_then(Value::as_str).unwrap_or("")
                ));
            }
        }
    }
    Ok(names)
}

#[cfg(test)]
#[path = "operator_plugins_tests.rs"]
mod tests;
