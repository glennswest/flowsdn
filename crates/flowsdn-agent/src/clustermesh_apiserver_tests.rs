#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;
use flowsdn_k8s::watch::Metadata;
use flowsdn_kvstore::memory::{MemoryBackend, MemoryStore};
use serde_json::json;

const UUID: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

fn meta(name: &str) -> Metadata {
    Metadata {
        name: name.into(),
        namespace: String::new(),
        uid: format!("uid-{name}"),
        resource_version: "1".into(),
    }
}

fn node(name: &str, ip: &str) -> Value {
    json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnNode",
           "metadata": {"name": name, "uid": format!("u-{name}"), "resourceVersion": "1"},
           "spec": {"addresses": [{"type": "InternalIP", "ip": ip}],
                    "ipam": {"podCIDRs": ["10.21.0.0/24"]}}})
}

fn endpoint(namespace: &str, name: &str, ip: &str, id: u32) -> Value {
    json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnEndpoint",
           "metadata": {"name": name, "namespace": namespace, "uid": format!("u-{name}"), "resourceVersion": "1"},
           "status": {"identity": {"id": id},
                      "networking": {"addressing": [{"ipv4": ip}], "node": "192.168.1.10"}}})
}

fn identity(id: &str, namespace: &str) -> Identity {
    Identity {
        metadata: meta(id),
        id: id.parse().unwrap(),
        security_labels: BTreeMap::from([
            ("k8s:app".to_owned(), "web".to_owned()),
            (
                "k8s:io.kubernetes.pod.namespace".to_owned(),
                namespace.to_owned(),
            ),
        ]),
        created: "2026-11-25T00:00:00Z".into(),
        heartbeat: false,
    }
}

fn namespace(name: &str, global: Option<&str>) -> Value {
    let mut object = json!({"apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": name, "uid": format!("u-{name}"), "resourceVersion": "1"}});
    if let Some(global) = global {
        object["metadata"]["annotations"] = json!({"clustermesh.flowsdn.io/global": global});
    }
    object
}

fn service(namespace: &str, name: &str, global: bool) -> Value {
    let mut object = json!({"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": name, "namespace": namespace, "uid": format!("u-{name}"), "resourceVersion": "1"},
        "spec": {"clusterIP": "10.96.0.10", "clusterIPs": ["10.96.0.10"],
                 "ports": [{"name": "http", "protocol": "TCP", "port": 80, "targetPort": 8080}]}});
    if global {
        object["metadata"]["annotations"] = json!({"service.flowsdn.io/global": "true"});
    }
    object
}

fn slice(namespace: &str, service: &str, ip: &str) -> Value {
    json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {"name": format!("{service}-abc"), "namespace": namespace, "uid": "u-s", "resourceVersion": "1",
                     "labels": {"kubernetes.io/service-name": service}},
        "addressType": "IPv4",
        "endpoints": [{"addresses": [ip], "conditions": {"ready": true}}],
        "ports": [{"name": "http", "protocol": "TCP", "port": 8080}]})
}

fn cluster() -> Cluster {
    Cluster {
        name: "c1".into(),
        id: 7,
        default_global: true,
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn keys(store: &MemoryStore) -> Vec<String> {
    store.dump().into_keys().collect()
}

#[tokio::test(start_paused = true)]
async fn the_four_stores_are_exported_with_their_canaries() {
    let kv = Arc::new(MemoryBackend::new());
    let mut exporter = Exporter::new(&kv, cluster());
    for store in exporter.stores() {
        tokio::spawn(async move { store.run().await });
    }
    exporter.update(Source::Nodes, vec![node("w1", "192.168.1.10")], true);
    exporter.update(
        Source::Namespaces,
        vec![
            namespace("default", None),
            namespace("private", Some("false")),
        ],
        true,
    );
    exporter.update_identities(
        vec![identity("65538", "default"), identity("65539", "private")],
        true,
    );
    exporter.update(
        Source::Endpoints,
        vec![
            endpoint("default", "web-1", "10.21.0.5", 65538),
            endpoint("private", "db-1", "10.21.0.6", 65539),
        ],
        true,
    );
    exporter.update(
        Source::Services,
        vec![
            service("default", "web", true),
            service("default", "local", false),
        ],
        true,
    );
    settle().await;
    assert!(
        !exporter.ready(),
        "the services canary waits for the slices list"
    );
    exporter.update(
        Source::Slices,
        vec![slice("default", "web", "10.21.0.5")],
        true,
    );
    settle().await;
    assert!(exporter.ready());
    let store = kv.store();
    assert_eq!(
        keys(&store),
        [
            "flowsdn/state/identities/v1/id/65538",
            "flowsdn/state/ip/v1/default/10.21.0.5",
            "flowsdn/state/nodes/v1/c1/w1",
            "flowsdn/state/services/v1/c1/default/web",
            "flowsdn/synced/c1/flowsdn/state/identities/v1",
            "flowsdn/synced/c1/flowsdn/state/ip/v1",
            "flowsdn/synced/c1/flowsdn/state/nodes/v1",
            "flowsdn/synced/c1/flowsdn/state/services/v1",
        ]
    );
    let dump = store.dump();
    assert_eq!(
        dump["flowsdn/state/identities/v1/id/65538"].lease_id, 0,
        "identities unleased"
    );
    assert_ne!(dump["flowsdn/state/nodes/v1/c1/w1"].lease_id, 0);
    assert_eq!(
        String::from_utf8(dump["flowsdn/state/identities/v1/id/65538"].data.clone()).unwrap(),
        "k8s:app=web;k8s:io.kubernetes.pod.namespace=default;"
    );
    let node: Value = serde_json::from_slice(&dump["flowsdn/state/nodes/v1/c1/w1"].data).unwrap();
    assert_eq!(
        (node["Cluster"].clone(), node["ClusterID"].clone()),
        (json!("c1"), json!(7))
    );
    let service: Value =
        serde_json::from_slice(&dump["flowsdn/state/services/v1/c1/default/web"].data).unwrap();
    assert_eq!(service["clusterID"], json!(7));
    assert!(service["backends"].get("10.21.0.5").is_some(), "{service}");

    // Flipping a namespace to local deletes what it had published.
    exporter.update(
        Source::Namespaces,
        vec![
            namespace("default", Some("false")),
            namespace("private", Some("false")),
        ],
        true,
    );
    settle().await;
    let left = keys(&store);
    assert!(
        left.iter()
            .all(|k| !k.starts_with("flowsdn/state/") || k.starts_with("flowsdn/state/nodes/")),
        "{left:?}"
    );
    // A deleted node goes too.
    exporter.update(Source::Nodes, vec![], true);
    settle().await;
    assert!(!keys(&store).contains(&"flowsdn/state/nodes/v1/c1/w1".to_owned()));
}

#[tokio::test(start_paused = true)]
async fn one_ip_two_endpoints_is_written_from_the_primary() {
    let kv = Arc::new(MemoryBackend::new());
    let mut exporter = Exporter::new(&kv, cluster());
    for store in exporter.stores() {
        tokio::spawn(async move { store.run().await });
    }
    exporter.update(Source::Namespaces, vec![namespace("default", None)], true);
    exporter.update(
        Source::Endpoints,
        vec![endpoint("default", "old", "10.21.0.9", 100)],
        true,
    );
    exporter.update(
        Source::Endpoints,
        vec![
            endpoint("default", "old", "10.21.0.9", 100),
            endpoint("default", "new", "10.21.0.9", 200),
        ],
        true,
    );
    settle().await;
    let id = |kv: &MemoryBackend| -> Option<Value> {
        kv.store()
            .dump()
            .get("flowsdn/state/ip/v1/default/10.21.0.9")
            .map(|v| serde_json::from_slice::<Value>(&v.data).unwrap()["ID"].clone())
    };
    assert_eq!(id(&kv), Some(json!(100)), "the first owner is primary");
    // The old pod goes: the new one's value is written, not a delete.
    exporter.update(
        Source::Endpoints,
        vec![endpoint("default", "new", "10.21.0.9", 200)],
        true,
    );
    settle().await;
    assert_eq!(id(&kv), Some(json!(200)));
    exporter.update(Source::Endpoints, vec![], true);
    settle().await;
    assert_eq!(id(&kv), None);
}

#[tokio::test]
async fn the_cluster_config_is_claimed_rebound_and_foreign_ones_refused() {
    let instance = InstanceUuid::parse(UUID).unwrap();
    let store = MemoryStore::new();
    let kv = store.client();
    let desired = export::cluster_config(7, 255);
    assert!(
        publish_config(&kv, "c1", &instance, &desired)
            .await
            .unwrap()
    );
    let dump = store.dump();
    assert_eq!(dump["flowsdn/cluster-owners/c1"].data, UUID.as_bytes());
    assert_eq!(
        dump["flowsdn/cluster-owners/c1"].lease_id, 0,
        "the owner key is unleased"
    );
    let config: Value = serde_json::from_slice(&dump["flowsdn/cluster-config/c1"].data).unwrap();
    assert_eq!(config["id"], json!(7));
    assert_eq!(config["capabilities"]["syncedCanaries"], json!(true));
    assert_eq!(config["capabilities"]["flowsdnInstanceUUID"], json!(UUID));
    assert_ne!(dump["flowsdn/cluster-config/c1"].lease_id, 0);
    // Unchanged: nothing written.
    assert!(
        !publish_config(&kv, "c1", &instance, &desired)
            .await
            .unwrap()
    );
    // A new session (its lease gone, config with it) re-claims onto its lease.
    let lease = dump["flowsdn/cluster-config/c1"].lease_id;
    kv.lose_lease(lease);
    assert!(!store.dump().contains_key("flowsdn/cluster-config/c1"));
    assert!(
        publish_config(&kv, "c1", &instance, &desired)
            .await
            .unwrap()
    );
    assert_ne!(store.dump()["flowsdn/cluster-config/c1"].lease_id, lease);
    // Another instance UUID may not take the name.
    let other = InstanceUuid::parse("2b4e28ba-2fa1-41d2-883f-0016d3cca427").unwrap();
    let error = publish_config(&store.client(), "c1", &other, &desired)
        .await
        .unwrap_err();
    assert!(error.contains("different instance"), "{error}");
    // A config someone else wrote, without a stamp, is not adopted.
    let fresh = MemoryStore::new();
    fresh.put_raw("flowsdn/cluster-config/c2", br#"{"id":9}"#);
    let error = publish_config(&fresh.client(), "c2", &instance, &desired)
        .await
        .unwrap_err();
    assert!(error.contains("unstamped"), "{error}");
}

#[tokio::test(start_paused = true)]
async fn a_foreign_modification_is_repaired() {
    let instance = InstanceUuid::parse(UUID).unwrap();
    let store = MemoryStore::new();
    let kv = Arc::new(store.client());
    let task = tokio::spawn(enforce_config(
        Arc::clone(&kv),
        "c1".into(),
        instance,
        export::cluster_config(7, 255),
    ));
    tokio::time::sleep(Duration::from_secs(6)).await;
    let written = store.dump()["flowsdn/cluster-config/c1"].data.clone();
    // Same owner UUID, changed content: repaired.
    let mut changed: Value = serde_json::from_slice(&written).unwrap();
    changed["id"] = json!(8);
    store.put_raw(
        "flowsdn/cluster-config/c1",
        &serde_json::to_vec(&changed).unwrap(),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(store.dump()["flowsdn/cluster-config/c1"].data, written);
    task.abort();
}

#[test]
fn arguments() {
    let args = |list: &[&str]| -> Vec<std::ffi::OsString> {
        list.iter().map(std::ffi::OsString::from).collect()
    };
    let base = [
        "--cluster-name",
        "c1",
        "--cluster-id",
        "7",
        "--cluster-instance-uuid",
        UUID,
        "--kvstore-address",
        "https://127.0.0.1:2379",
    ];
    let options = parse(&args(&base)).unwrap();
    assert_eq!((options.cluster.as_str(), options.cluster_id), ("c1", 7));
    assert_eq!(options.health_port, 9880);
    assert!(options.default_global && options.heartbeat);
    let mut more = base.to_vec();
    more.extend([
        "--clustermesh-default-global-namespace",
        "false",
        "--enable-heartbeat",
        "false",
        "--kvstore-lease-ttl",
        "60",
        "--health-port",
        "9999",
    ]);
    let options = parse(&args(&more)).unwrap();
    assert!(!options.default_global && !options.heartbeat);
    assert_eq!(options.lease_ttl, Duration::from_secs(60));
    assert!(parse(&args(&base[..6])).is_err(), "a kvstore is required");
    let mut both = base.to_vec();
    both.extend(["--kvstore-config", "/x"]);
    assert!(parse(&args(&both)).is_err());
    let mut bad = base.to_vec();
    bad[3] = "0";
    assert!(parse(&args(&bad)).is_err());
    let mut bad = base.to_vec();
    bad[5] = "not-a-uuid";
    assert!(parse(&args(&bad)).is_err());
    let mut bad = base.to_vec();
    bad[1] = "Bad_Name";
    assert!(parse(&args(&bad)).is_err());
}
