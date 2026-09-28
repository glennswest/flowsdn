use flowsdn_k8s::{SCHEMA_VERSION, SCHEMA_VERSION_LABEL, schemas::registration_payloads};
use flowsdn_operator::registration::{Action, MANAGED_BY, MANAGED_BY_LABEL, plan};
use serde_json::{Value, json};
use std::sync::OnceLock;

fn desired() -> &'static [Value] {
    static DESIRED: OnceLock<Vec<Value>> = OnceLock::new();
    DESIRED.get_or_init(|| registration_payloads().expect("verified bundle"))
}
fn first() -> &'static Value { desired().first().expect("CRD") }
fn installed(desired: &Value) -> Value {
    let Action::Create(mut value) = plan(desired, None, false).expect("create plan").action else { panic!("create") };
    let metadata = value.get_mut("metadata").and_then(Value::as_object_mut).expect("metadata");
    metadata.insert("uid".into(), json!("uid-a"));
    metadata.insert("resourceVersion".into(), json!("opaque/rv-1"));
    value.as_object_mut().expect("object").insert("status".into(), json!({"conditions":[{"type":"Established","status":"True"},{"type":"NamesAccepted","status":"True"}]}));
    value
}
fn version(value: &mut Value, version: Value) {
    value.pointer_mut("/metadata/labels").and_then(Value::as_object_mut).expect("labels").insert(SCHEMA_VERSION_LABEL.into(), version);
}

#[test]
fn real_bundle_creates_owned_objects_and_requires_fresh_established_observation() {
    assert_eq!(desired().len(), 22);
    for desired in desired() {
        let creation = plan(desired, None, false).expect("creation");
        assert!(!creation.established);
        let Action::Create(value) = creation.action else { panic!("create") };
        assert_eq!(value.pointer("/metadata/labels").and_then(|v| v.get(MANAGED_BY_LABEL)), Some(&json!(MANAGED_BY)));
        assert!(value.get("status").is_none());
        let live = installed(desired);
        let observed = plan(desired, Some(&live), false).expect("observation");
        assert_eq!(observed.action, Action::Observe);
        assert!(observed.established);
        let mut pending = live;
        pending.as_object_mut().expect("object").remove("status");
        assert!(!plan(desired, Some(&pending), false).expect("pending admission").established);
    }
}

#[test]
fn replacement_preserves_metadata_and_carries_exact_uid_and_resource_version() {
    let mut live = installed(first());
    version(&mut live, json!("1.32.0"));
    let meta = live.get_mut("metadata").and_then(Value::as_object_mut).expect("meta");
    meta.insert("annotations".into(), json!({"external.example/note":"retain"}));
    meta.insert("finalizers".into(), json!(["external.example/protect"]));
    meta.insert("ownerReferences".into(), json!([{"uid":"other-owner","name":"other"}]));
    meta.insert("managedFields".into(), json!([{"manager":"gitops","operation":"Update"}]));
    meta.get_mut("labels").and_then(Value::as_object_mut).expect("labels").insert("external.example/label".into(), json!("retain"));
    live.pointer_mut("/spec").and_then(Value::as_object_mut).expect("spec").insert("preserveUnknownFields".into(), json!(true));
    let result = plan(first(), Some(&live), false).expect("replace");
    assert!(!result.established);
    let Action::Replace { object, uid, resource_version } = result.action else { panic!("replace") };
    assert_eq!(uid, "uid-a");
    assert_eq!(resource_version, "opaque/rv-1");
    assert_eq!(object.pointer("/metadata/uid"), live.pointer("/metadata/uid"));
    assert_eq!(object.pointer("/metadata/resourceVersion"), live.pointer("/metadata/resourceVersion"));
    for field in ["annotations", "finalizers", "ownerReferences", "managedFields"] {
        assert_eq!(object.pointer(&format!("/metadata/{field}")), live.pointer(&format!("/metadata/{field}")));
    }
    assert_eq!(object.pointer("/metadata/labels").and_then(|v| v.get("external.example/label")), Some(&json!("retain")));
    assert_eq!(object.pointer("/spec"), first().pointer("/spec"));
    assert!(object.get("status").is_none());
    assert_eq!(live.pointer("/spec/preserveUnknownFields"), Some(&json!(true)), "input remains immutable");
}

#[test]
fn foreign_objects_are_never_adopted_but_skip_mode_observes_gitops() {
    for marker in [None, Some(json!("gitops")), Some(json!("cilium-operator"))] {
        let mut live = installed(first());
        let labels = live.pointer_mut("/metadata/labels").and_then(Value::as_object_mut).expect("labels");
        labels.remove(MANAGED_BY_LABEL);
        if let Some(marker) = marker { labels.insert(MANAGED_BY_LABEL.into(), marker); }
        assert!(plan(first(), Some(&live), false).is_err());
        let skip = plan(first(), Some(&live), true).expect("read-only GitOps observation");
        assert_eq!(skip.action, Action::Observe);
        assert!(skip.established);
    }
    let missing = plan(first(), None, true).expect("missing external CRD");
    assert_eq!(missing.action, Action::Observe);
    assert!(!missing.established);
}

#[test]
fn mismatched_identity_and_missing_concurrency_tokens_fail_closed() {
    for (path, value) in [
        ("/metadata/name", json!("ciliumnodes.cilium.io")),
        ("/spec/group", json!("cilium.io")),
        ("/spec/scope", json!("Namespaced")),
        ("/spec/names/kind", json!("CiliumNode")),
        ("/spec/names/plural", json!("flowsdnnodes")),
        ("/metadata/uid", json!("")),
        ("/metadata/resourceVersion", Value::Null),
    ] {
        let mut live = installed(first());
        *live.pointer_mut(path).expect("field") = value;
        assert!(plan(first(), Some(&live), false).is_err(), "normal mode accepted {path}");
        assert!(plan(first(), Some(&live), true).is_err(), "skip mode accepted {path}");
    }
    let mut upstream = first().clone();
    *upstream.pointer_mut("/spec/group").expect("group") = json!("cilium.io");
    assert!(plan(&upstream, None, false).is_err());
}

#[test]
fn malformed_older_and_prerelease_labels_repair_without_downgrading_newer_schemas() {
    for label in ["", "invalid", "01.33.11", "1.33", "v1.33.11", "1.33.11-alpha.01", "1.33.11+", "1.32.99", "1.33.10", "1.33.11-rc.1"] {
        let mut live = installed(first());
        version(&mut live, json!(label));
        assert!(matches!(plan(first(), Some(&live), false).expect("repair").action, Action::Replace { .. }), "did not repair {label}");
    }
    for label in [SCHEMA_VERSION, "1.33.11+build.01", "1.33.12", "1.34.0-alpha.1", "999999999999999999999999999999.0.0"] {
        let mut live = installed(first());
        version(&mut live, json!(label));
        assert_eq!(plan(first(), Some(&live), false).expect("preserve equal or newer").action, Action::Observe, "changed {label}");
    }
    let mut newer = installed(first());
    version(&mut newer, json!("1.34.0"));
    newer.pointer_mut("/spec/versions/0").and_then(Value::as_object_mut).expect("version").remove("schema");
    let result = plan(first(), Some(&newer), false).expect("do not downgrade missing newer schema");
    assert_eq!(result.action, Action::Observe);
    assert!(!result.established);
    version(&mut newer, json!(SCHEMA_VERSION));
    assert!(matches!(plan(first(), Some(&newer), false).expect("repair equal missing schema").action, Action::Replace { .. }));
    let mut missing = installed(first());
    missing.pointer_mut("/metadata/labels").and_then(Value::as_object_mut).expect("labels").remove(SCHEMA_VERSION_LABEL);
    assert!(matches!(plan(first(), Some(&missing), false).expect("repair missing label").action, Action::Replace { .. }));
}

#[test]
fn termination_conflicts_and_duplicate_status_never_report_ready() {
    for conditions in [
        json!([{"type":"Established","status":"False"}]),
        json!([{"type":"Established","status":"True"},{"type":"Terminating","status":"True"}]),
        json!([]),
    ] {
        let mut live = installed(first());
        *live.pointer_mut("/status/conditions").expect("conditions") = conditions;
        assert!(!plan(first(), Some(&live), false).expect("unready").established);
    }
    let mut live = installed(first());
    version(&mut live, json!("1.0.0"));
    live.get_mut("metadata").and_then(Value::as_object_mut).expect("metadata").insert("deletionTimestamp".into(), json!("2026-09-27T00:00:00Z"));
    let result = plan(first(), Some(&live), false).expect("terminating object");
    assert_eq!(result.action, Action::Observe);
    assert!(!result.established);
    for conditions in [
        json!([{"type":"Established","status":"True"},{"type":"NamesAccepted","status":"False"}]),
        json!([{"type":"Established","status":"True"},{"type":"Established","status":"False"}]),
    ] {
        let mut live = installed(first());
        *live.pointer_mut("/status/conditions").expect("conditions") = conditions;
        assert!(plan(first(), Some(&live), false).is_err());
    }
}

#[test]
fn readiness_requires_one_usable_served_supported_version_even_for_newer_schema() {
    for (path, invalid) in [
        ("/spec/versions/0/name", json!("v2")),
        ("/spec/versions/0/served", json!(false)),
        ("/spec/versions/0/served", Value::Null),
        ("/spec/versions/0/schema/openAPIV3Schema", json!({})),
    ] {
        let mut live = installed(first());
        version(&mut live, json!("1.34.0"));
        *live.pointer_mut(path).expect("field") = invalid;
        let newer = plan(first(), Some(&live), false).expect("preserve newer");
        assert_eq!(newer.action, Action::Observe);
        assert!(!newer.established, "ready with unsupported {path}");
        version(&mut live, json!(SCHEMA_VERSION));
        let equal = plan(first(), Some(&live), false).expect("repair equal version");
        assert!(matches!(equal.action, Action::Replace { .. }));
        assert!(!equal.established);
    }
    let mut live = installed(first());
    version(&mut live, json!("1.34.0"));
    let duplicate = live.pointer("/spec/versions/0").expect("version").clone();
    live.pointer_mut("/spec/versions").and_then(Value::as_array_mut).expect("versions").push(duplicate);
    assert!(!plan(first(), Some(&live), false).expect("duplicate supported versions").established);
    let versions = live.pointer_mut("/spec/versions").and_then(Value::as_array_mut).expect("versions");
    let storage = versions.first_mut().and_then(Value::as_object_mut).expect("storage version");
    storage.insert("name".into(), json!("v2"));
    versions.last_mut().and_then(Value::as_object_mut).expect("old supported version").insert("storage".into(), json!(false));
    assert!(plan(first(), Some(&live), false).expect("new storage still serves supported API").established);
}
