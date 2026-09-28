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
const CASES: [(&str, &str, &str, &str); 22] = [
    ("NetworkPolicy", "networkpolicies", "Namespaced", "v2"),
    ("ClusterwideNetworkPolicy", "clusterwidenetworkpolicies", "Cluster", "v2"),
    ("CIDRGroup", "cidrgroups", "Cluster", "v2"),
    ("Endpoint", "endpoints", "Namespaced", "v2"),
    ("EndpointSlice", "endpointslices", "Cluster", "v2alpha1"),
    ("Identity", "identities", "Cluster", "v2"),
    ("Node", "nodes", "Cluster", "v2"),
    ("NodeConfig", "nodeconfigs", "Namespaced", "v2"),
    ("LocalRedirectPolicy", "localredirectpolicies", "Namespaced", "v2"),
    ("EgressGatewayPolicy", "egressgatewaypolicies", "Cluster", "v2"),
    ("EnvoyConfig", "envoyconfigs", "Namespaced", "v2"),
    ("ClusterwideEnvoyConfig", "clusterwideenvoyconfigs", "Cluster", "v2"),
    ("LoadBalancerIPPool", "loadbalancerippools", "Cluster", "v2"),
    ("L2AnnouncementPolicy", "l2announcementpolicies", "Cluster", "v2alpha1"),
    ("PodIPPool", "podippools", "Cluster", "v2alpha1"),
    ("BGPClusterConfig", "bgpclusterconfigs", "Cluster", "v2"),
    ("BGPPeerConfig", "bgppeerconfigs", "Cluster", "v2"),
    ("BGPAdvertisement", "bgpadvertisements", "Cluster", "v2"),
    ("BGPNodeConfig", "bgpnodeconfigs", "Cluster", "v2"),
    ("BGPNodeConfigOverride", "bgpnodeconfigoverrides", "Cluster", "v2"),
    ("GatewayClassConfig", "gatewayclassconfigs", "Namespaced", "v2alpha1"),
    ("DatapathPlugin", "datapathplugins", "Cluster", "v2alpha1"),
];
fn document(case: (&str, &str, &str, &str)) -> Value {
    let (kind, plural, scope, version) = case;
    let plural = format!("cilium{plural}");
    let mut versions = vec![json!({"name":version,"served":true,"storage":true,"deprecated":true,"deprecationWarning":"upstream warning","schema":{"openAPIV3Schema":{"type":"object","x-kubernetes-validations":[{"rule":"self == oldSelf"}]}},"subresources":{"status":{}},"additionalPrinterColumns":[{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}]})];
    if DUAL_VERSION_PLURALS.contains(&plural.as_str()) {
        versions.push(json!({"name":"v2alpha1","served":true,"storage":false,"deprecated":true,"schema":{"openAPIV3Schema":{"type":"object","description":"non-storage schema must not win"}}}));
    }
    json!({"metadata":{"name":format!("{plural}.cilium.io"),"annotations":{"discard":"me"}},"spec":{"group":"cilium.io","scope":scope,"names":{"kind":format!("Cilium{kind}"),"plural":plural,"singular":format!("cilium{}",kind.to_lowercase()),"listKind":format!("Cilium{kind}List"),"categories":["cilium"],"shortNames":["upstreamalias"]},"versions":versions}})
}
#[test]
fn all_resources_migrate_to_owned_identity_and_project_idempotently() {
    assert_eq!(REGISTRATION_PLURALS.iter().collect::<std::collections::BTreeSet<_>>().len(), 22);
    for case in CASES {
        let source = document(case);
        assert!(registration_payload(&source).is_err(), "upstream needs explicit migration");
        let payload = migration_registration_payload(&source).expect("migration projection");
        let (kind, plural, scope, _) = case;
        let owned_plural = format!("flowsdn{plural}");
        assert!(REGISTRATION_PLURALS.contains(&owned_plural.as_str()));
        assert_eq!(payload.pointer("/metadata/name"), Some(&json!(format!("{owned_plural}.flowsdn.io"))));
        assert_eq!(payload.pointer("/spec/group"), Some(&json!("flowsdn.io")));
        assert_eq!(payload.pointer("/spec/scope"), Some(&json!(scope)));
        assert_eq!(payload.pointer("/spec/names"), Some(&json!({"kind":format!("Flowsdn{kind}"),"plural":owned_plural,"singular":format!("flowsdn{}",kind.to_lowercase()),"listKind":format!("Flowsdn{kind}List"),"categories":["flowsdn"]})));
        assert_eq!(payload.pointer("/spec/versions").and_then(Value::as_array).expect("versions").len(), 1);
        assert_eq!(payload.pointer("/spec/versions/0/name"), Some(&json!("v1alpha1")));
        assert_eq!(payload.pointer("/spec/versions/0/served"), Some(&json!(true)));
        assert_eq!(payload.pointer("/spec/versions/0/storage"), Some(&json!(true)));
        for field in ["schema", "subresources", "additionalPrinterColumns"] {
            assert_eq!(payload.pointer(&format!("/spec/versions/0/{field}")), source.pointer(&format!("/spec/versions/0/{field}")));
        }
        for field in ["deprecated", "deprecationWarning"] { assert!(payload.pointer(&format!("/spec/versions/0/{field}")).is_none()); }
        assert!(payload.pointer("/metadata/annotations").is_none());
        assert_eq!(payload.pointer("/metadata/labels"), Some(&json!({"io.flowsdn.k8s.crd.schema.version":"1.33.11"})));
        assert_eq!(registration_payload(&payload).expect("idempotent"), payload);
        assert!(migration_registration_payload(&payload).is_err());
    }
}
#[test]
fn registration_rejects_spoofed_identity_and_invalid_version_contracts() {
    let source = document(("BGPNodeConfig", "bgpnodeconfigs", "Cluster", "v2"));
    for (path, replacement) in [
        ("/spec/group", json!("other.io")),
        ("/spec/names/kind", json!("FlowsdnBGPNodeConfig")),
        ("/spec/names/plural", json!("ciliumnodes")),
        ("/spec/names/singular", json!("ciliumnode")),
        ("/spec/names/listKind", json!("CiliumNodeList")),
        ("/metadata/name", json!("ciliumnodes.cilium.io")),
        ("/spec/scope", json!("Namespaced")),
        ("/spec/versions/0/storage", json!(false)),
        ("/spec/versions/0/served", json!(false)),
        ("/spec/versions/0/schema", json!({})),
        ("/spec/versions/1/storage", json!(true)),
        ("/spec/versions/1/name", json!("v2")),
        ("/spec/versions/1/served", json!(false)),
        ("/spec/versions/1/deprecated", json!(false)),
    ] {
        let mut bad = source.clone();
        *bad.pointer_mut(path).expect("test path") = replacement;
        assert!(migration_registration_payload(&bad).is_err(), "accepted {path}");
    }
    let mut truncated = source.clone();
    truncated.pointer_mut("/spec/versions").and_then(Value::as_array_mut).expect("versions").pop();
    assert!(migration_registration_payload(&truncated).is_err());
    let mut conversion = source.clone();
    conversion.get_mut("spec").and_then(Value::as_object_mut).expect("spec").insert("conversion".into(), json!({"strategy":"Webhook"}));
    assert!(migration_registration_payload(&conversion).is_err());
    conversion.get_mut("spec").and_then(Value::as_object_mut).expect("spec").insert("conversion".into(), json!({"strategy":"None"}));
    let owned = migration_registration_payload(&conversion).expect("None conversion");
    assert_eq!(registration_payload(&owned).expect("idempotent None conversion"), owned);
    for (path, replacement) in [
        ("/spec/versions/0/name", json!("v2")),
        ("/spec/names/kind", json!("CiliumBGPNodeConfig")),
        ("/spec/names/plural", json!("flowsdnnodes")),
        ("/spec/scope", json!("Namespaced")),
    ] {
        let mut bad = owned.clone();
        *bad.pointer_mut(path).expect("path") = replacement;
        assert!(registration_payload(&bad).is_err(), "accepted owned {path}");
    }
}
#[test]
fn migration_adapts_embedded_identity_constraints_but_preserves_other_values() {
    let mut source = document(("BGPNodeConfig", "bgpnodeconfigs", "Cluster", "v2"));
    let schema = source.pointer_mut("/spec/versions/0/schema/openAPIV3Schema").expect("schema");
    *schema = json!({"type":"object","properties":{
        "apiVersion":{"type":"string","const":"cilium.io/v2"},
        "spec":{"type":"object","properties":{
            "peers":{"type":"array","items":{"type":"object","properties":{
                "peerConfigRef":{"type":"object","properties":{
                    "group":{"default":"cilium.io","description":"reference cilium.io"},
                    "kind":{"default":"CiliumBGPPeerConfig"}
                }}
            }}},
            "envoyConfig":{"type":"object","properties":{
                "kind":{"enum":["CiliumEnvoyConfig","CiliumClusterwideEnvoyConfig","OtherExternalKind"]}
            }},
            "arbitraryValue":{"default":"cilium.io"},
            "arbitraryObject":{"default":{"properties":{"kind":{"default":"CiliumNode"}}}}
        }}
    }});
    let payload = migration_registration_payload(&source).expect("projection");
    let schema = payload.pointer("/spec/versions/0/schema/openAPIV3Schema").expect("schema");
    assert_eq!(schema.pointer("/properties/apiVersion/const"), Some(&json!("flowsdn.io/v1alpha1")));
    let peer = schema.pointer("/properties/spec/properties/peers/items/properties/peerConfigRef/properties").expect("peer reference");
    assert_eq!(peer.pointer("/group/default"), Some(&json!("flowsdn.io")));
    assert_eq!(peer.pointer("/kind/default"), Some(&json!("FlowsdnBGPPeerConfig")));
    assert_eq!(peer.pointer("/group/description"), Some(&json!("reference cilium.io")));
    assert_eq!(schema.pointer("/properties/spec/properties/envoyConfig/properties/kind/enum"), Some(&json!(["FlowsdnEnvoyConfig","FlowsdnClusterwideEnvoyConfig","OtherExternalKind"])));
    assert_eq!(schema.pointer("/properties/spec/properties/arbitraryValue/default"), Some(&json!("cilium.io")));
    assert_eq!(schema.pointer("/properties/spec/properties/arbitraryObject/default/properties/kind/default"), Some(&json!("CiliumNode")));
    assert_eq!(registration_payload(&payload).expect("idempotent"), payload);
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
    for plural in ["flowsdnnodeconfigs", "flowsdngatewayclassconfigs"] {
        assert_eq!(operator_config_scope(plural), Ok(ListScope::AllNamespaces));
    }
}
#[test]
fn upstream_configuration_plurals_are_not_owned() {
    assert!(operator_config_scope("ciliumnodeconfigs").is_err());
    assert!(operator_config_scope("ciliumgatewayclassconfigs").is_err());
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
