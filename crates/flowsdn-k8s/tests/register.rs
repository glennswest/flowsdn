//! CRD registration (#337, spec 13 §3.2): the embedded payloads are the
//! projection, the update rule, and the algorithm against a scripted server.
use flowsdn_k8s::crd::owned_crds;
use flowsdn_k8s::register::{
    CRDS_PATH, POLLS, Registered, established, listed_names, needs_update, register, shipped_crds,
    update_body,
};
use flowsdn_k8s::{Error, SCHEMA_VERSION, SCHEMA_VERSION_LABEL};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::time::Duration;

#[test]
fn shipped_payloads_are_the_projection() {
    let shipped = shipped_crds().expect("shipped CRDs parse");
    let owned = owned_crds().expect("projection");
    assert_eq!(shipped.len(), owned.len());
    for crd in owned {
        let name = crd
            .document
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .expect("name");
        let (_, payload) = shipped
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name} is not embedded"));
        assert_eq!(payload, &crd.document, "{name}");
        assert_eq!(
            payload.pointer(&format!(
                "/metadata/labels/{}",
                SCHEMA_VERSION_LABEL.replace('/', "~1")
            )),
            Some(&json!(SCHEMA_VERSION))
        );
    }
}

fn crd(label: Option<&str>, schema: bool) -> Value {
    let mut labels = serde_json::Map::new();
    if let Some(label) = label {
        labels.insert(SCHEMA_VERSION_LABEL.into(), json!(label));
    }
    let version = if schema {
        json!({"name": "v1alpha1", "schema": {"openAPIV3Schema": {"type": "object"}}})
    } else {
        json!({"name": "v1alpha1"})
    };
    json!({"metadata": {"name": "flowsdnnodes.flowsdn.io", "resourceVersion": "7", "labels": labels},
        "spec": {"versions": [version], "preserveUnknownFields": true},
        "status": {"conditions": [{"type": "Established", "status": "True"}]}})
}

#[test]
fn update_only_when_missing_or_older() {
    assert!(needs_update(&crd(Some("1.33.11"), false)), "no schema");
    assert!(needs_update(&crd(None, true)), "no label");
    assert!(needs_update(&crd(Some("not-a-version"), true)));
    assert!(needs_update(&crd(Some("1.33.10"), true)));
    assert!(needs_update(&crd(Some("1.9.99"), true)));
    assert!(!needs_update(&crd(Some(SCHEMA_VERSION), true)));
    assert!(
        !needs_update(&crd(Some("1.34.0"), true)),
        "a newer schema is left alone"
    );
    assert!(!needs_update(&crd(Some("2.0.0"), true)));

    let payload = json!({"metadata": {"labels": {SCHEMA_VERSION_LABEL: SCHEMA_VERSION}},
        "spec": {"group": "flowsdn.io"}});
    let body = update_body(&crd(Some("1.0.0"), true), &payload);
    assert_eq!(body.pointer("/metadata/resourceVersion"), Some(&json!("7")));
    assert_eq!(
        body.pointer("/metadata/labels"),
        payload.pointer("/metadata/labels")
    );
    assert_eq!(
        body.get("spec"),
        Some(&json!({"group": "flowsdn.io", "preserveUnknownFields": false}))
    );
    assert!(body.get("status").is_none());
}

#[test]
fn names_not_accepted_is_fatal() {
    let mut conflict = crd(Some(SCHEMA_VERSION), true);
    if let Some(object) = conflict.as_object_mut() {
        object.insert(
            "status".into(),
            json!({"conditions": [{"type": "NamesAccepted", "status": "False",
                "message": "\"fsn\" is already in use"}]}),
        );
    }
    let error = established(&conflict).expect_err("fatal");
    assert!(
        error.0.contains("flowsdnnodes.flowsdn.io") && error.0.contains("already in use"),
        "{error}"
    );
    assert_eq!(established(&crd(Some(SCHEMA_VERSION), true)), Ok(true));
    assert_eq!(
        established(&json!({"status": {"conditions": []}})),
        Ok(false)
    );
}

/// A scripted API: answers in order; every call is recorded.
struct Script {
    answers: VecDeque<(u16, Value)>,
    calls: Vec<(String, String, Option<Value>)>,
}
fn run(answers: Vec<(u16, Value)>, payload: &Value) -> (Result<Registered, Error>, Script, u32) {
    let mut script = Script {
        answers: answers.into(),
        calls: Vec::new(),
    };
    let mut waits = 0u32;
    let result = {
        let mut send =
            |m: http::Method, p: &str, b: Option<&Value>| -> Result<(u16, Value), Error> {
                script.calls.push((m.to_string(), p.to_owned(), b.cloned()));
                Ok(script.answers.pop_front().unwrap_or((404, Value::Null)))
            };
        let mut wait = |_: Duration| waits = waits.saturating_add(1);
        register("flowsdnnodes.flowsdn.io", payload, &mut send, &mut wait)
    };
    (result, script, waits)
}
fn methods(script: &Script) -> Vec<&str> {
    script.calls.iter().map(|c| c.0.as_str()).collect()
}

#[test]
fn absent_is_created_then_established() {
    let payload = json!({"metadata": {"name": "flowsdnnodes.flowsdn.io"}});
    let pending = json!({"status": {"conditions": [{"type": "Established", "status": "False"}]}});
    let (result, script, waits) = run(
        vec![
            (404, Value::Null),
            (201, Value::Null),
            (200, pending),
            (200, crd(Some(SCHEMA_VERSION), true)),
        ],
        &payload,
    );
    assert_eq!(result, Ok(Registered::Created));
    assert_eq!(methods(&script), ["GET", "POST", "GET", "GET"]);
    assert_eq!(script.calls.get(1).map(|c| c.1.as_str()), Some(CRDS_PATH));
    assert_eq!(script.calls.get(1).and_then(|c| c.2.clone()), Some(payload));
    assert_eq!(waits, 1);
}

#[test]
fn a_raced_create_is_success() {
    let (result, script, _) = run(
        vec![
            (404, Value::Null),
            (409, Value::Null),
            (200, crd(Some(SCHEMA_VERSION), true)),
        ],
        &json!({}),
    );
    assert_eq!(result, Ok(Registered::Created));
    assert_eq!(methods(&script), ["GET", "POST", "GET"]);
}

#[test]
fn current_is_left_alone_and_older_is_updated_through_conflicts() {
    let (result, script, _) = run(
        vec![
            (200, crd(Some(SCHEMA_VERSION), true)),
            (200, crd(Some(SCHEMA_VERSION), true)),
        ],
        &json!({}),
    );
    assert_eq!(result, Ok(Registered::Current));
    assert_eq!(methods(&script), ["GET", "GET"]);

    let payload = json!({"metadata": {"labels": {SCHEMA_VERSION_LABEL: SCHEMA_VERSION}},
        "spec": {"group": "flowsdn.io"}});
    let (result, script, _) = run(
        vec![
            (200, crd(Some("1.30.0"), true)),
            (409, Value::Null),
            (200, crd(Some("1.30.0"), true)),
            (200, Value::Null),
            (200, crd(Some(SCHEMA_VERSION), true)),
        ],
        &payload,
    );
    assert_eq!(result, Ok(Registered::Updated));
    assert_eq!(methods(&script), ["GET", "PUT", "GET", "PUT", "GET"]);
    let put = script.calls.get(3).and_then(|c| c.2.clone()).expect("PUT");
    assert_eq!(
        put.pointer("/spec/preserveUnknownFields"),
        Some(&json!(false))
    );
    assert_eq!(put.pointer("/metadata/resourceVersion"), Some(&json!("7")));
}

#[test]
fn never_established_gives_up_after_sixty_seconds() {
    let pending = json!({"status": {"conditions": []}});
    let mut answers = vec![(200, crd(Some(SCHEMA_VERSION), true))];
    answers.extend((0..POLLS).map(|_| (200, pending.clone())));
    let (result, _, waits) = run(answers, &json!({}));
    assert!(result.is_err());
    assert_eq!(waits, POLLS, "120 polls of 500 ms");
}

#[test]
fn a_refusal_is_an_error() {
    let (result, _, _) = run(
        vec![(404, Value::Null), (403, json!({"message": "forbidden"}))],
        &json!({}),
    );
    assert_eq!(
        result,
        Err(Error(
            "create flowsdnnodes.flowsdn.io: HTTP 403 forbidden".into()
        ))
    );
}

#[test]
fn names_come_from_a_metadata_list() {
    let list = json!({"kind": "PartialObjectMetadataList", "items": [
        {"metadata": {"name": "flowsdnnodes.flowsdn.io"}},
        {"metadata": {"name": "flowsdnidentities.flowsdn.io"}}]});
    let names = listed_names(&list);
    assert!(names.contains("flowsdnnodes.flowsdn.io") && names.len() == 2);
}
