//! The ClusterMesh apiserver's sync against a live fastetcd (#567, spec 20
//! §3.8): the four stores and their canaries, the cluster config claim, and
//! what a peer reading the store sees, including when the apiserver goes.
//! Runs only when `FASTETCD_BIN` names a fastetcd binary (`SC_TOOLS=fastetcd`);
//! otherwise it prints `skipped: FASTETCD_BIN unset` and passes.
#![cfg(feature = "kubernetes")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use flowsdn_agent::clustermesh_apiserver::{Cluster, Exporter, Source, publish_config};
use flowsdn_clustermesh::export;
use flowsdn_clustermesh::ownership::InstanceUuid;
use flowsdn_k8s::watch::{Identity, Metadata};
use flowsdn_kvstore::etcd::{EtcdBackend, EtcdConfig};
use flowsdn_kvstore::{EventKind, Kvstore};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(bin: &str) -> (tokio::process::Child, u16, std::path::PathBuf) {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("clustermesh-fastetcd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let child = tokio::process::Command::new(bin)
        .arg("--data-dir")
        .arg(dir.join("data"))
        .arg("--listen-client-urls")
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("--listen-peer-urls")
        .arg(format!("http://127.0.0.1:{}", free_port()))
        .arg("--listen-metrics-url")
        .arg(format!("127.0.0.1:{}", free_port()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    (child, port, dir)
}

async fn connect(port: u16, ttl: Duration) -> EtcdBackend {
    let config = EtcdConfig {
        endpoints: vec![format!("http://127.0.0.1:{port}")],
        key_lease_ttl: ttl,
        ..EtcdConfig::default()
    };
    for _ in 0..150 {
        if let Ok(backend) = EtcdBackend::connect(config.clone()).await {
            return backend;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("fastetcd on {port} did not accept a client within 30 s");
}

fn objects() -> (Vec<Value>, Vec<Value>, Vec<Value>, Vec<Value>, Vec<Value>) {
    let node = json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnNode",
        "metadata": {"name": "w1", "uid": "n", "resourceVersion": "1"},
        "spec": {"addresses": [{"type": "InternalIP", "ip": "192.168.1.10"}],
                 "ipam": {"podCIDRs": ["10.21.0.0/24"]}}});
    let endpoint = json!({"apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnEndpoint",
        "metadata": {"name": "web-1", "namespace": "default", "uid": "e", "resourceVersion": "1"},
        "status": {"identity": {"id": 65538},
                   "networking": {"addressing": [{"ipv4": "10.21.0.5"}], "node": "192.168.1.10"}}});
    let service = json!({"apiVersion": "v1", "kind": "Service",
        "metadata": {"name": "web", "namespace": "default", "uid": "s", "resourceVersion": "1",
                     "annotations": {"service.flowsdn.io/global": "true"}},
        "spec": {"clusterIP": "10.96.0.10", "clusterIPs": ["10.96.0.10"],
                 "ports": [{"name": "http", "protocol": "TCP", "port": 80}]}});
    let slice = json!({"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
        "metadata": {"name": "web-abc", "namespace": "default", "uid": "l", "resourceVersion": "1",
                     "labels": {"kubernetes.io/service-name": "web"}},
        "addressType": "IPv4",
        "endpoints": [{"addresses": ["10.21.0.5"], "conditions": {"ready": true}}],
        "ports": [{"name": "http", "protocol": "TCP", "port": 8080}]});
    let namespace = json!({"apiVersion": "v1", "kind": "Namespace",
        "metadata": {"name": "default", "uid": "d", "resourceVersion": "1"}});
    (vec![node], vec![endpoint], vec![service], vec![slice], vec![namespace])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sync_publishes_into_fastetcd_and_goes_with_its_leases() {
    let Some(bin) = std::env::var("FASTETCD_BIN").ok().filter(|b| !b.is_empty()) else {
        println!("skipped: FASTETCD_BIN unset");
        return;
    };
    let (_child, port, dir) = start(&bin).await;
    let kv = Arc::new(connect(port, Duration::from_secs(30)).await);
    let peer = connect(port, Duration::from_secs(30)).await;
    let mut nodes_watch = peer.watch("flowsdn/state/nodes/v1/c1/").await.unwrap();
    let mut exporter = Exporter::new(
        &kv,
        Cluster {
            name: "c1".into(),
            id: 7,
            default_global: true,
        },
    );
    for store in exporter.stores() {
        tokio::spawn(async move { store.run().await });
    }
    let (nodes, endpoints, services, slices, namespaces) = objects();
    exporter.update(Source::Namespaces, namespaces, true);
    exporter.update(Source::Nodes, nodes, true);
    exporter.update(Source::Endpoints, endpoints, true);
    exporter.update(Source::Services, services, true);
    exporter.update(Source::Slices, slices, true);
    exporter.update_identities(
        vec![Identity {
            metadata: Metadata {
                name: "65538".into(),
                namespace: String::new(),
                uid: "i".into(),
                resource_version: "1".into(),
            },
            id: 65538,
            security_labels: BTreeMap::from([
                ("k8s:app".to_owned(), "web".to_owned()),
                ("k8s:io.kubernetes.pod.namespace".to_owned(), "default".to_owned()),
            ]),
            created: "2026-11-25T00:00:00Z".into(),
            heartbeat: false,
        }],
        true,
    );
    for _ in 0..300 {
        if exporter.ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(exporter.ready(), "every canary within 30 s");
    let instance = InstanceUuid::parse("1b4e28ba-2fa1-41d2-883f-0016d3cca427").unwrap();
    assert!(publish_config(&*kv, "c1", &instance, &export::cluster_config(7, 255)).await.unwrap());
    assert!(!publish_config(&*kv, "c1", &instance, &export::cluster_config(7, 255)).await.unwrap(), "unchanged");

    // What a peer reads.
    let seen = peer.list_prefix("flowsdn/", None).await.unwrap();
    let keys: Vec<&str> = seen.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "flowsdn/cluster-config/c1",
            "flowsdn/cluster-owners/c1",
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
    let pair: Value = serde_json::from_slice(&seen["flowsdn/state/ip/v1/default/10.21.0.5"].data).unwrap();
    assert_eq!((pair["ID"].clone(), pair["HostIP"].clone()), (json!(65538), json!("192.168.1.10")));
    let config: Value = serde_json::from_slice(&seen["flowsdn/cluster-config/c1"].data).unwrap();
    assert_eq!(config["capabilities"]["syncedCanaries"], json!(true));
    assert_eq!(seen["flowsdn/state/identities/v1/id/65538"].lease_id, 0);
    assert_ne!(seen["flowsdn/state/nodes/v1/c1/w1"].lease_id, 0);

    // The peer's watch saw the node arrive; a node removal reaches it as a delete.
    let mut created = false;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(5), nodes_watch.recv()).await {
        if event.kind == EventKind::Create && event.key.ends_with("/w1") {
            created = true;
            break;
        }
    }
    assert!(created, "the peer watch saw the node");
    exporter.update(Source::Nodes, vec![], true);
    let mut deleted = false;
    while let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(10), nodes_watch.recv()).await {
        if event.kind == EventKind::Delete && event.key.ends_with("/w1") {
            deleted = true;
            break;
        }
    }
    assert!(deleted, "the peer watch saw the node go");

    // The apiserver goes: its leases with it. Leased state and canaries
    // disappear for peers; unleased identities and the owner record stay.
    kv.close().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let left: Vec<String> = peer.list_prefix("flowsdn/", None).await.unwrap().into_keys().collect();
    assert_eq!(left, ["flowsdn/cluster-owners/c1", "flowsdn/state/identities/v1/id/65538"]);
    peer.close().await;
    let _ = std::fs::remove_dir_all(dir);
}
