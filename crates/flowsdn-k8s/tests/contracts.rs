use flowsdn_k8s::{patch::node_status_patch, plan::*, version::*};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[test]
fn version_floor_fallback_and_capabilities_are_independent() {
    for (version, expected) in [
        ("v1.26.0", Band::OlderUntested),
        ("v1.33.4+vendor.2", Band::ReferenceRange),
        ("1.36.0-alpha.1", Band::ReferenceRange),
        ("v1.37.0", Band::NewerUntested),
        ("2.0.0", Band::NewerUntested),
    ] {
        assert_eq!(
            Version::detect(version, "", "")
                .expect("version")
                .classify(),
            Ok(expected)
        );
    }
    assert!(
        Version::detect("1.25.99", "", "")
            .expect("version")
            .classify()
            .is_err()
    );
    assert_eq!(Version::detect("invalid", "1", "26+"), Ok(MINIMUM));
    for invalid in [
        "1.2", "1.26.0.1", "1.026.0", "1.26.0-", "1.26.0+", "garbage",
    ] {
        assert!(Version::detect(invalid, "", "").is_err());
    }
    assert!(crd_prerequisites(Probe::Unsupported, Probe::Supported).is_err());
    assert!(crd_prerequisites(Probe::Supported, Probe::Unknown).is_err());
    assert!(crd_prerequisites(Probe::Supported, Probe::Supported).is_ok());
    assert_eq!(
        node_patch_mode(Probe::Supported, Probe::Unknown),
        Ok(NodePatchMode::StrategicMerge)
    );
    assert_eq!(
        node_patch_mode(Probe::Unsupported, Probe::Supported),
        Ok(NodePatchMode::GuardedJson)
    );
    assert!(node_patch_mode(Probe::Unknown, Probe::Supported).is_err());
}
fn document(plural: &str) -> Value {
    json!({"metadata":{"annotations":{"discard":"me"}}, "spec":{"group":"cilium.io", "scope":"Cluster", "names":{"kind":"Example", "plural":plural, "singular":"example", "listKind":"ExampleList", "categories":["cilium"]}, "versions":[{"name":"v2", "served":true, "storage":true, "schema":{"openAPIV3Schema":{"type":"object", "x-kubernetes-validations":[{"rule":"self == oldSelf"}]}}}, {"name":"v2alpha1", "served":true, "storage":false, "deprecated":true}]}})
}
#[test]
fn registration_retains_all_versions_and_whitelisted_metadata() {
    assert_eq!(
        REGISTRATION_PLURALS
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        22
    );
    assert!(REGISTRATION_PLURALS.contains(&"ciliumgatewayclassconfigs"));
    let spec = include_str!("../../../docs/spec/13-crds-k8s-client.md");
    for plural in REGISTRATION_PLURALS {
        assert!(spec.contains(&format!("| {plural} |")));
    }
    for plural in DUAL_VERSION_PLURALS {
        let source = document(plural);
        let payload = registration_payload(&source).expect("projection");
        assert_eq!(
            payload.pointer("/spec/versions"),
            source.pointer("/spec/versions")
        );
        assert!(payload.pointer("/spec/names/listKind").is_none());
        assert!(payload.pointer("/metadata/annotations").is_none());
        assert_eq!(
            payload.pointer("/metadata/labels"),
            Some(&json!({"io.cilium.k8s.crd.schema.version":"1.33.11"}))
        );
        let mut stripped = source.clone();
        stripped
            .pointer_mut("/spec/versions")
            .and_then(Value::as_array_mut)
            .expect("versions")
            .pop();
        assert!(registration_payload(&stripped).is_err());
        let mut multiple_storage = source;
        *multiple_storage
            .pointer_mut("/spec/versions/1/storage")
            .expect("flag") = json!(true);
        assert!(registration_payload(&multiple_storage).is_err());
    }
}
#[test]
fn endpoint_defaults_and_namespace_plans() {
    assert_eq!(
        EndpointOptions::default().plan().expect("default"),
        EndpointPlan {
            write_cep: true,
            watch_ces: false,
            slim: false
        }
    );
    assert!(
        EndpointOptions {
            enable_ces: true,
            ..Default::default()
        }
        .plan()
        .expect("ces")
        .write_cep
    );
    let slim = EndpointOptions {
        enable_ces: true,
        slim: true,
        disable_endpoint_crd: true,
        operator_managed_identities: true,
        mixed_reference_agents: false,
    };
    assert!(!slim.plan().expect("slim").write_cep);
    assert!(
        EndpointOptions {
            mixed_reference_agents: true,
            ..slim
        }
        .plan()
        .is_err()
    );
    assert!(
        EndpointOptions {
            operator_managed_identities: false,
            ..slim
        }
        .plan()
        .is_err()
    );
    assert!(
        EndpointOptions {
            enable_ces: false,
            ..slim
        }
        .plan()
        .is_err()
    );
    assert!(
        EndpointOptions {
            disable_endpoint_crd: false,
            ..slim
        }
        .plan()
        .is_err()
    );
    assert!(
        EndpointOptions {
            disable_endpoint_crd: true,
            ..Default::default()
        }
        .plan()
        .is_err()
    );
    for plural in ["ciliumnodeconfigs", "ciliumgatewayclassconfigs"] {
        assert_eq!(operator_config_scope(plural), Ok(ListScope::AllNamespaces));
    }
}
// Small atomic RFC6902 subset interpreter exercises generated operations against
// independently modified objects. Production HTTP transport is not implemented.
fn apply(source: &Value, ops: &[Value]) -> Result<Value, String> {
    let mut candidate = source.clone();
    for op in ops {
        let path = op.get("path").and_then(Value::as_str).ok_or("path")?;
        let value = op.get("value").ok_or("value")?;
        match op.get("op").and_then(Value::as_str).ok_or("op")? {
            "test" => {
                if candidate.pointer(path) != Some(value) {
                    return Err("precondition".into());
                }
            }
            "add" | "replace" => {
                let (parent, key) = path.rsplit_once('/').ok_or("pointer")?;
                let target = candidate.pointer_mut(parent).ok_or("parent")?;
                match target {
                    Value::Object(map) => {
                        map.insert(key.replace("~1", "/").replace("~0", "~"), value.clone());
                    }
                    Value::Array(array) if key == "-" => array.push(value.clone()),
                    Value::Array(array) => {
                        *array
                            .get_mut(key.parse::<usize>().map_err(|_| "index")?)
                            .ok_or("index")? = value.clone();
                    }
                    _ => return Err("container".into()),
                }
            }
            _ => return Err("unsupported op".into()),
        }
    }
    Ok(candidate)
}
#[test]
fn patches_preserve_foreign_fields_and_reject_stale_objects() {
    let node = json!({"metadata":{"uid":"u1", "resourceVersion":"opaque/rv", "annotations":{"other":"keep"}}, "status":{"capacity":{"cpu":"4"}, "conditions":[{"type":"Ready","status":"True"},{"type":"NetworkUnavailable","status":"True","reason":"keep","message":"remove"}]}});
    let annotations = BTreeMap::from([
        ("example.io/a~b".into(), Some("new".into())),
        ("other".into(), None),
    ]);
    let condition = json!({"type":"NetworkUnavailable", "status":"False", "message":null});
    let ops = node_status_patch(&node, &annotations, Some(&condition)).expect("patch");
    let patched = apply(&node, &ops).expect("apply");
    assert_eq!(
        patched.pointer("/metadata/annotations/other"),
        Some(&json!("keep"))
    );
    assert_eq!(
        patched.pointer("/metadata/annotations/example.io~1a~0b"),
        Some(&json!("new"))
    );
    assert_eq!(
        patched.pointer("/status/conditions/0"),
        node.pointer("/status/conditions/0")
    );
    assert_eq!(
        patched.pointer("/status/conditions/1"),
        Some(&json!({"type":"NetworkUnavailable", "status":"False", "reason":"keep"}))
    );
    assert_eq!(
        patched.pointer("/status/capacity"),
        node.pointer("/status/capacity")
    );
    for field in ["uid", "resourceVersion"] {
        let mut concurrent = node.clone();
        *concurrent
            .pointer_mut(&format!("/metadata/{field}"))
            .expect("field") = json!("changed");
        assert!(apply(&concurrent, &ops).is_err());
        assert_eq!(
            concurrent.pointer("/metadata/annotations/example.io~1a~0b"),
            None
        );
    }
}
#[test]
fn patch_missing_parents_append_and_invalid_snapshots() {
    for status in [None, Some(json!({})), Some(json!({"conditions":[]}))] {
        let mut node = json!({"metadata":{"uid":"u", "resourceVersion":"1"}});
        if let Some(status) = status {
            node.as_object_mut()
                .expect("object")
                .insert("status".into(), status);
        }
        let condition = json!({"type":"Ready","status":"True"});
        let ops = node_status_patch(
            &node,
            &BTreeMap::from([("a/b".into(), Some("v".into()))]),
            Some(&condition),
        )
        .expect("patch");
        let result = apply(&node, &ops).expect("apply");
        assert_eq!(result.pointer("/status/conditions/0"), Some(&condition));
        assert_eq!(
            result.pointer("/metadata/annotations/a~1b"),
            Some(&json!("v"))
        );
    }
    assert!(
        node_status_patch(
            &json!({"metadata":{"resourceVersion":"1"}}),
            &BTreeMap::new(),
            None
        )
        .is_err()
    );
    let duplicate = json!({"metadata":{"uid":"u","resourceVersion":"1"},"status":{"conditions":[{"type":"Ready"},{"type":"Ready"}]}});
    assert!(
        node_status_patch(&duplicate, &BTreeMap::new(), Some(&json!({"type":"Ready"}))).is_err()
    );
}
