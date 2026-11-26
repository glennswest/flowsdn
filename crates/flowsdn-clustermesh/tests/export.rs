#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
//! The apiserver's export converters (spec 20 §3.8.2, §4.2–4.6, §5.1) and
//! the `flowsdn/` key space (ADR-0023). The FlowsdnNode, FlowsdnEndpoint and
//! FlowsdnIdentity objects are `crates/flowsdn-k8s/testdata/crs/*/` examples
//! as JSON.
use flowsdn_clustermesh::{
    export::*,
    ownership::{InstanceUuid, plan_claim},
    prefixes::{FrontPolicy, Role, Rpc},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

/// flowsdnnodes/realistic.yaml
fn realistic_node() -> Value {
    json!({
        "apiVersion": "flowsdn.io/v1alpha1",
        "kind": "FlowsdnNode",
        "metadata": {
            "name": "pvetest1",
            "labels": {"kubernetes.io/hostname": "pvetest1", "kubernetes.io/os": "linux"},
            "ownerReferences": [{"apiVersion": "v1", "kind": "Node", "name": "pvetest1",
                "uid": "9c3e5a7b-1d2f-4e6a-8b0c-3d5e7f9a1b2c"}]
        },
        "spec": {
            "addresses": [
                {"type": "InternalIP", "ip": "192.168.8.21"},
                {"type": "InternalIP", "ip": "fd00:8::21"},
                {"type": "FlowsdnInternalIP", "ip": "10.21.0.1"}
            ],
            "bootid": "4f6a2c1e-8b3d-4e5f-9a7c-1b2d3e4f5a6b",
            "encryption": {"key": 0},
            "health": {"ipv4": "10.21.0.12", "ipv6": "fd00:10:21::c"},
            "ingress": {"ipv4": "10.21.0.200"},
            "ipam": {
                "podCIDRs": ["10.21.0.0/16", "fd00:10:21::/64"],
                "pools": {
                    "requested": [{"pool": "default", "needed": {"ipv4-addrs": 16, "ipv6-addrs": 16}}],
                    "allocated": [{"pool": "default", "cidrs": ["10.21.0.0/24", "fd00:10:21::/112"]}]
                }
            }
        },
        "status": {"ipam": {"pod-cidrs": {"10.21.0.0/16": {"status": "in-use"},
            "fd00:10:21::/64": {"status": "in-use"}}, "operator-status": {}}}
    })
}

/// flowsdnendpoints/realistic.yaml (policy, controllers and log trimmed:
/// the converter does not read them).
fn realistic_endpoint() -> Value {
    json!({
        "apiVersion": "flowsdn.io/v1alpha1",
        "kind": "FlowsdnEndpoint",
        "metadata": {"name": "web-7d4b9c8f6d-x2kqp", "namespace": "prod", "labels": {"app": "web"}},
        "status": {
            "id": 1832,
            "state": "ready",
            "service-account": "web",
            "identity": {"id": 48213, "labels": ["k8s:app=web",
                "k8s:io.flowsdn.k8s.policy.serviceaccount=web", "k8s:io.kubernetes.pod.namespace=prod"]},
            "networking": {"node": "192.168.8.21",
                "addressing": [{"ipv4": "10.21.0.47", "ipv6": "fd00:10:21::2f"}]},
            "named-ports": [
                {"name": "http", "port": 8080, "protocol": "TCP"},
                {"name": "metrics", "port": 9090, "protocol": "TCP"}
            ],
            "encryption": {"key": 0},
            "external-identifiers": {"k8s-namespace": "prod", "k8s-pod-name": "web-7d4b9c8f6d-x2kqp",
                "pod-name": "prod/web-7d4b9c8f6d-x2kqp"},
            "policy": {"ingress": {"enforcing": true, "state": "enforcing"},
                "egress": {"enforcing": false, "state": "non-enforcing"}}
        }
    })
}

/// flowsdnidentities/realistic.yaml
fn realistic_identity() -> Value {
    json!({
        "apiVersion": "flowsdn.io/v1alpha1",
        "kind": "FlowsdnIdentity",
        "metadata": {"name": "48213", "labels": {"app": "web", "io.kubernetes.pod.namespace": "prod",
            "io.flowsdn.k8s.policy.serviceaccount": "web"}},
        "security-labels": {
            "k8s:app": "web",
            "k8s:io.flowsdn.k8s.namespace.labels.kubernetes.io/metadata.name": "prod",
            "k8s:io.flowsdn.k8s.policy.cluster": "default",
            "k8s:io.flowsdn.k8s.policy.serviceaccount": "web",
            "k8s:io.kubernetes.pod.namespace": "prod"
        }
    })
}

#[test]
fn keys_are_flowsdn_names_with_canary_overrides() {
    assert_eq!(NODES, "flowsdn/state/nodes/v1");
    assert_eq!(IDENTITIES, "flowsdn/state/identities/v1");
    assert_eq!(IP, "flowsdn/state/ip/v1");
    assert_eq!(SERVICES, "flowsdn/state/services/v1");
    assert_eq!(
        canary("east", NODES),
        "flowsdn/synced/east/flowsdn/state/nodes/v1"
    );
    assert_eq!(
        canary("east", SERVICES),
        "flowsdn/synced/east/flowsdn/state/services/v1"
    );
    for (data, registered) in [(IDENTITIES_ID, IDENTITIES), (IDENTITIES, IDENTITIES)] {
        assert_eq!(
            canary("east", data),
            format!("flowsdn/synced/east/{registered}")
        );
    }
    assert_eq!(
        canary("east", IP_DEFAULT),
        "flowsdn/synced/east/flowsdn/state/ip/v1"
    );
    assert_eq!(cluster_config_key("east"), "flowsdn/cluster-config/east");
    assert_eq!(
        join(&["flowsdn/state/", "/east/", "", "a/"]),
        "flowsdn/state/east/a"
    );
    assert_eq!(join(&["a", "..", ".", "b"]), "a/.././b");
    assert_eq!(
        join(&[IDENTITIES_ID, "48213"]),
        "flowsdn/state/identities/v1/id/48213"
    );
}

#[test]
fn grants_and_claims_use_flowsdn_prefixes() {
    let remote = FrontPolicy::for_role(Role::Remote, "east").unwrap();
    assert!(remote.permits(Rpc::Range, b"flowsdn/state/nodes/v1/east/n", None));
    assert!(remote.permits(Rpc::Range, b"flowsdn/cluster-config/east", None));
    assert!(remote.permits(
        Rpc::Range,
        b"flowsdn/synced/east/flowsdn/state/nodes/v1",
        None
    ));
    assert!(remote.permits(Rpc::Watch, b"flowsdn/.heartbeat", None));
    for old in [
        "cilium/state/nodes/v1/east/n",
        "cilium/cluster-config/east",
        "cilium/synced/east/x",
        "cilium/.heartbeat",
    ] {
        assert!(!remote.permits(Rpc::Range, old.as_bytes(), None));
    }
    let local = FrontPolicy::for_role(Role::Local, "east").unwrap();
    assert!(local.permits(Rpc::Range, b"flowsdn/cache/nodes/v1/west/n", None));
    assert!(!local.permits(Rpc::Range, b"cilium/cache/nodes/v1/west/n", None));

    let instance = InstanceUuid::parse("7beea67f-6435-4f2a-9d80-c6c9c18e0f01").unwrap();
    let plan = plan_claim("east", &instance, None, None, &cluster_config(3, 255), 1).unwrap();
    let keys: Vec<&str> = plan.puts.iter().map(|put| put.key.as_str()).collect();
    assert_eq!(
        keys,
        ["flowsdn/cluster-owners/east", "flowsdn/cluster-config/east"]
    );
    assert_eq!(
        parse(&plan.puts[1].value),
        json!({"id": 3, "capabilities": {"syncedCanaries": true, "maxConnectedClusters": 255,
            "flowsdnInstanceUUID": "7beea67f-6435-4f2a-9d80-c6c9c18e0f01"}})
    );
}

#[test]
fn cluster_config_omits_empty_fields() {
    assert_eq!(
        cluster_config(3, 255),
        json!({"id": 3, "capabilities": {"syncedCanaries": true, "maxConnectedClusters": 255}})
    );
    assert_eq!(
        cluster_config(3, 0),
        json!({"id": 3, "capabilities": {"syncedCanaries": true}})
    );
}

#[test]
fn node_record_from_the_realistic_flowsdnnode() {
    let (key, bytes) = node_record(&realistic_node(), "east", 3).unwrap().unwrap();
    assert_eq!(key, "east/pvetest1");
    assert_eq!(
        parse(&bytes),
        json!({
            "Name": "pvetest1",
            "Cluster": "east",
            "IPAddresses": [
                {"Type": "InternalIP", "IP": "192.168.8.21"},
                {"Type": "InternalIP", "IP": "fd00:8::21"},
                {"Type": "CiliumInternalIP", "IP": "10.21.0.1"}
            ],
            "IPv4AllocCIDR": "10.21.0.0/16",
            "IPv4SecondaryAllocCIDRs": null,
            "IPv6AllocCIDR": "fd00:10:21::/64",
            "IPv6SecondaryAllocCIDRs": null,
            "IPv4HealthIP": "10.21.0.12",
            "IPv6HealthIP": "fd00:10:21::c",
            "IPv4IngressIP": "10.21.0.200",
            "IPv6IngressIP": "",
            "ClusterID": 3,
            "Source": "custom-resource",
            "EncryptionKey": 0,
            "Labels": {"kubernetes.io/hostname": "pvetest1", "kubernetes.io/os": "linux"},
            "Annotations": null,
            "WireguardPubKey": "",
            "BootID": "4f6a2c1e-8b3d-4e5f-9a7c-1b2d3e4f5a6b"
        })
    );
    let again = node_record(&realistic_node(), "east", 3).unwrap().unwrap();
    assert_eq!(again.1, bytes);
}

#[test]
fn node_record_writes_every_go_field_for_the_minimal_flowsdnnode() {
    let minimal = json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnNode",
        "metadata": {"name": "pvetest1"}, "spec": {}});
    let (key, bytes) = node_record(&minimal, "east", 3).unwrap().unwrap();
    assert_eq!(key, "east/pvetest1");
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        concat!(
            r#"{"Annotations":null,"BootID":"","Cluster":"east","ClusterID":3,"EncryptionKey":0,"#,
            r#""IPAddresses":null,"IPv4AllocCIDR":null,"IPv4HealthIP":"","IPv4IngressIP":"","#,
            r#""IPv4SecondaryAllocCIDRs":null,"IPv6AllocCIDR":null,"IPv6HealthIP":"","#,
            r#""IPv6IngressIP":"","IPv6SecondaryAllocCIDRs":null,"Labels":null,"Name":"pvetest1","#,
            r#""Source":"custom-resource","WireguardPubKey":""}"#
        )
    );
}

#[test]
fn node_record_cidrs_cluster_override_and_errors() {
    let node = json!({
        "metadata": {"name": "n1", "annotations": {"a": "b", "n": 1}},
        "spec": {
            "addresses": [{"type": "ExternalIP", "ip": "203.0.113.9"}, {"type": "InternalIP", "ip": "bad"},
                {"type": "InternalIP"}],
            "encryption": {"key": 300},
            "ipam": {"podCIDRs": ["10.1.0.5/16", "10.2.0.0/24", "bad", "10.3.0.0/33",
                "fd00::1/64", "fd00:1::/64", "10.4.0.0/+8"]}
        }
    });
    let (key, bytes) = node_record(&node, "west", 7).unwrap().unwrap();
    assert_eq!(key, "west/n1");
    let record = parse(&bytes);
    assert_eq!(
        record["IPAddresses"],
        json!([{"Type": "ExternalIP", "IP": "203.0.113.9"}])
    );
    assert_eq!(record["IPv4AllocCIDR"], json!("10.1.0.0/16"));
    assert_eq!(record["IPv4SecondaryAllocCIDRs"], json!(["10.2.0.0/24"]));
    assert_eq!(record["IPv6AllocCIDR"], json!("fd00::/64"));
    assert_eq!(record["IPv6SecondaryAllocCIDRs"], json!(["fd00:1::/64"]));
    assert_eq!(record["EncryptionKey"], json!(0));
    assert_eq!(record["Annotations"], json!({"a": "b"}));
    assert_eq!(record["Cluster"], json!("west"));
    assert_eq!(record["ClusterID"], json!(7));

    assert!(node_record(&node, "West", 7).is_err());
    assert!(node_record(&json!([]), "west", 7).is_err());
    assert!(node_record(&json!({"metadata": {"name": "a/b"}}), "west", 7).is_err());
    assert_eq!(node_record(&json!({"metadata": {}}), "west", 7), Ok(None));
}

#[test]
fn identity_value_is_the_canonical_label_string() {
    let (key, value) = identity_record(&realistic_identity()).unwrap();
    assert_eq!(key, "id/48213");
    assert_eq!(
        String::from_utf8(value).unwrap(),
        concat!(
            "k8s:app=web;",
            "k8s:io.flowsdn.k8s.namespace.labels.kubernetes.io/metadata.name=prod;",
            "k8s:io.flowsdn.k8s.policy.cluster=default;",
            "k8s:io.flowsdn.k8s.policy.serviceaccount=web;",
            "k8s:io.kubernetes.pod.namespace=prod;"
        )
    );
    let labels: BTreeMap<String, String> = [
        ("k8s:io.kubernetes.pod.namespace", "default"),
        ("k8s:app", "foo"),
    ]
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .into();
    let (key, value) = identity_value("7", &labels).unwrap();
    assert_eq!(key, "id/7");
    assert_eq!(
        value,
        b"k8s:app=foo;k8s:io.kubernetes.pod.namespace=default;"
    );
    assert_eq!(identity_namespace(&labels), Some("default"));
    // Sorted by key, not by `source:key`.
    let mixed: BTreeMap<String, String> = [("k8s:zeta", "1"), ("reserved:alpha", "")]
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .into();
    assert_eq!(
        identity_value("8", &mixed).unwrap().1,
        b"reserved:alpha=;k8s:zeta=1;"
    );
    // flowsdnidentities/minimal.yaml: no security labels, skipped.
    let minimal = json!({"metadata": {"name": "48213"}, "security-labels": {}});
    assert_eq!(identity_record(&minimal), None);
    for name in ["0", "048213", "+5", "x", "4294967296"] {
        assert_eq!(identity_value(name, &labels), None, "{name}");
    }
}

#[test]
fn ip_pairs_of_the_realistic_flowsdnendpoint() {
    let pairs = ip_pairs(&realistic_endpoint());
    let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, ["default/10.21.0.47", "default/fd00:10:21::2f"]);
    assert_eq!(
        String::from_utf8(pairs[0].1.clone()).unwrap(),
        concat!(
            r#"{"HostIP":"192.168.8.21","ID":48213,"IP":"10.21.0.47","K8sNamespace":"prod","#,
            r#""K8sPodName":"web-7d4b9c8f6d-x2kqp","K8sServiceAccount":"web","Key":0,"Mask":null,"#,
            r#""Metadata":"","NamedPorts":[{"Name":"http","Port":8080,"Protocol":"TCP"},"#,
            r#"{"Name":"metrics","Port":9090,"Protocol":"TCP"}]}"#
        )
    );
    assert_eq!(parse(&pairs[1].1)["IP"], json!("fd00:10:21::2f"));
    assert_eq!(ip_pairs(&realistic_endpoint()), pairs);
}

#[test]
fn ip_pairs_omit_empty_fields_and_need_an_identity() {
    // flowsdnendpoints/minimal.yaml has no status.
    let minimal = json!({"metadata": {"name": "web-7d4b9c8f6d-x2kqp", "namespace": "default"}});
    assert!(ip_pairs(&minimal).is_empty());
    let endpoint = json!({
        "metadata": {"name": "p", "namespace": "ns"},
        "status": {
            "identity": {"id": 5},
            "encryption": {"key": 2},
            "named-ports": [{"name": "x", "port": 0}],
            "networking": {"addressing": [{"ipv4": "10.0.0.1"}, {"ipv4": "10.0.0.1"}, {"ipv6": "bad"}]}
        }
    });
    let pairs = ip_pairs(&endpoint);
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, "default/10.0.0.1");
    assert_eq!(
        parse(&pairs[0].1),
        json!({"IP": "10.0.0.1", "Mask": null, "HostIP": "", "ID": 5, "Key": 2, "Metadata": "",
            "K8sNamespace": "ns", "K8sPodName": "p"})
    );
    let mut no_identity = endpoint.clone();
    no_identity["status"]["identity"] = json!({"id": 0});
    assert!(ip_pairs(&no_identity).is_empty());
}

#[test]
fn ip_owner_arbitration() {
    let mut owners = IpOwners::new();
    let ip = "default/10.0.0.1";
    assert_eq!(
        owners.upsert(ip, "ns/old", b"a".to_vec()),
        Some(Write::Put(ip.into(), b"a".to_vec()))
    );
    assert_eq!(owners.upsert(ip, "ns/old", b"a".to_vec()), None);
    // A second owner of the same IP waits; its updates write nothing.
    assert_eq!(owners.upsert(ip, "ns/new", b"b".to_vec()), None);
    assert_eq!(owners.upsert(ip, "ns/new", b"b2".to_vec()), None);
    assert_eq!(owners.upsert(ip, "ns/third", b"c".to_vec()), None);
    assert_eq!(owners.primary(ip), Some(("ns/old", &b"a"[..])));
    assert_eq!(
        owners.upsert(ip, "ns/old", b"a2".to_vec()),
        Some(Write::Put(ip.into(), b"a2".to_vec()))
    );
    // The primary leaves: the first pending owner's latest value is written.
    assert_eq!(
        owners.remove(ip, "ns/old"),
        Some(Write::Put(ip.into(), b"b2".to_vec()))
    );
    assert_eq!(owners.remove(ip, "ns/old"), None);
    assert_eq!(owners.remove(ip, "ns/unknown"), None);
    // A pending owner leaving writes nothing.
    assert_eq!(owners.remove(ip, "ns/third"), None);
    assert_eq!(owners.primary(ip), Some(("ns/new", &b"b2"[..])));
    // The last owner leaves: delete.
    assert_eq!(owners.remove(ip, "ns/new"), Some(Write::Delete(ip.into())));
    assert!(owners.is_empty());
    assert_eq!(owners.remove(ip, "ns/new"), None);
}

fn service(annotations: Value) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "svc", "namespace": "ns", "labels": {"app": "svc"},
            "annotations": annotations},
        "spec": {
            "clusterIP": "10.96.0.10",
            "clusterIPs": ["10.96.0.10", "fd00:96::a"],
            "selector": {"app": "web"},
            "ports": [
                {"name": "http", "port": 80, "protocol": "TCP", "targetPort": 8080},
                {"name": "dns", "port": 53, "protocol": "UDP"}
            ]
        }
    })
}

fn slice(name: &str, service: &str, address_type: &str, endpoints: Value) -> Value {
    json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {"name": name, "namespace": "ns",
            "labels": {"kubernetes.io/service-name": service}},
        "addressType": address_type,
        "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
        "endpoints": endpoints
    })
}

#[test]
fn cluster_service_from_service_and_slices() {
    let svc = service(json!({"service.flowsdn.io/global": "True"}));
    let main = slice(
        "svc-a",
        "svc",
        "IPv4",
        json!([
            {"addresses": ["10.0.1.5"], "conditions": {"ready": true}, "hostname": "pod-1",
                "zone": "a", "hints": {"forZones": [{"name": "a"}]}},
            {"addresses": ["10.0.1.6"], "conditions": {"ready": false, "serving": true,
                "terminating": true}, "zone": "b"},
            {"addresses": ["10.0.1.7"], "conditions": {"ready": false, "serving": false}},
            {"addresses": ["10.0.1.8"], "conditions": {"ready": false}},
            {"addresses": ["10.0.1.9"], "conditions": {}}
        ]),
    );
    let other = slice(
        "other-a",
        "other",
        "IPv4",
        json!([{"addresses": ["10.0.2.1"]}]),
    );
    let fqdn = slice(
        "svc-f",
        "svc",
        "FQDN",
        json!([{"addresses": ["example.com"]}]),
    );
    let (key, bytes) = cluster_service(&svc, &[&main, &other, &fqdn], "east", 3).unwrap();
    assert_eq!(key, "east/ns/svc");
    let ports =
        json!({"http": {"Protocol": "TCP", "Port": 80}, "dns": {"Protocol": "UDP", "Port": 53}});
    let target = json!({"http": {"Protocol": "TCP", "Port": 8080}});
    assert_eq!(
        parse(&bytes),
        json!({
            "cluster": "east", "namespace": "ns", "name": "svc",
            "frontends": {"10.96.0.10": ports, "fd00:96::a": ports},
            "backends": {"10.0.1.5": target, "10.0.1.6": target, "10.0.1.9": target},
            "hostnames": {"10.0.1.5": "pod-1"},
            "zones": {"10.0.1.5": {"zone": "a", "forZones": [{"name": "a"}]},
                "10.0.1.6": {"zone": "b"}},
            "labels": {"app": "svc"}, "selector": {"app": "web"},
            "includeExternal": true, "shared": true, "clusterID": 3
        })
    );
    let again = cluster_service(&svc, &[&main, &other, &fqdn], "east", 3).unwrap();
    assert_eq!(again.1, bytes);
}

#[test]
fn cluster_service_headless_and_unexported() {
    let mut headless = service(json!({"service.flowsdn.io/global": "true"}));
    headless["spec"]["clusterIP"] = json!("None");
    headless["spec"]["clusterIPs"] = json!(["None"]);
    headless["metadata"]["labels"] = Value::Null;
    let (_, bytes) = cluster_service(&headless, &[], "east", 3).unwrap();
    assert_eq!(
        parse(&bytes),
        json!({"cluster": "east", "namespace": "ns", "name": "svc", "frontends": {},
            "backends": {}, "labels": {}, "selector": {"app": "web"},
            "includeExternal": true, "shared": true, "clusterID": 3})
    );
    for annotations in [
        json!({}),
        json!({"service.flowsdn.io/global": "false"}),
        json!({"service.cilium.io/global": "true"}),
        json!({"service.flowsdn.io/global": "true", "service.flowsdn.io/shared": "false"}),
        json!({"service.flowsdn.io/shared": "true"}),
    ] {
        assert_eq!(
            cluster_service(&service(annotations.clone()), &[], "east", 3),
            None,
            "{annotations}"
        );
    }
    assert!(
        cluster_service(
            &service(
                json!({"service.flowsdn.io/global": "true", "service.flowsdn.io/shared": "TRUE"})
            ),
            &[],
            "east",
            3
        )
        .is_some()
    );
    let global = service(json!({"service.flowsdn.io/global": "true"}));
    assert!(service_global(&global) && service_shared(&global));
    assert_eq!(cluster_service(&global, &[], "East", 3), None);
}

#[test]
fn namespace_global_default_and_override() {
    let namespace = |value: &str| json!({"metadata": {"name": "ns", "annotations": {"clustermesh.flowsdn.io/global": value}}});
    assert!(namespace_global(None, DEFAULT_GLOBAL_NAMESPACE));
    assert!(!namespace_global(None, false));
    let plain = json!({"metadata": {"name": "ns"}});
    assert!(namespace_global(Some(&plain), true));
    assert!(!namespace_global(Some(&plain), false));
    assert!(!namespace_global(Some(&namespace("false")), true));
    assert!(!namespace_global(Some(&namespace("FALSE")), true));
    assert!(namespace_global(Some(&namespace("true")), false));
    assert!(!namespace_global(Some(&namespace("maybe")), false));
    let cilium = json!({"metadata": {"annotations": {"clustermesh.cilium.io/global": "false"}}});
    assert!(namespace_global(Some(&cilium), true));
}
