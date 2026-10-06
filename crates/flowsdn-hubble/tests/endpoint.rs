use flowsdn_hubble::endpoint::{EndpointInfo, Resolver, Workload, describe, workload};
use serde_json::json;
use std::{collections::BTreeMap, net::IpAddr};

#[test]
fn workload_follows_the_controller_and_collapses_deployment_replicasets() {
    let rs = [("ReplicaSet", "web-7d4b9c", true)];
    assert_eq!(
        workload(rs, Some("7d4b9c")),
        Some(Workload {
            kind: "Deployment".into(),
            name: "web".into()
        })
    );
    // A bare ReplicaSet, or a hash that is not the name's suffix, stays itself.
    assert_eq!(
        workload(rs, None).map(|w| w.kind),
        Some("ReplicaSet".into())
    );
    assert_eq!(
        workload(rs, Some("ffff")).map(|w| w.name),
        Some("web-7d4b9c".into())
    );
    assert_eq!(
        workload([("ReplicaSet", "-7d4b9c", true)], Some("7d4b9c")).map(|w| w.kind),
        Some("ReplicaSet".into())
    );
    let owners = [("Node", "n1", false), ("StatefulSet", "db", true)];
    assert_eq!(
        workload(owners, None),
        Some(Workload {
            kind: "StatefulSet".into(),
            name: "db".into()
        })
    );
    assert_eq!(workload([("Node", "n1", false)], None), None);
}

#[test]
fn endpoint_json_is_hubbles_shape_without_empty_fields() {
    let info = EndpointInfo {
        id: 7,
        identity: None,
        namespace: "ns".into(),
        pod_name: "web-1".into(),
        pod_uid: "uid".into(),
        container_id: "0123456789abcdef".into(),
        node: "n1".into(),
        labels: vec!["k8s:app=web".into()],
        workloads: vec![Workload {
            kind: "Deployment".into(),
            name: "web".into(),
        }],
    };
    assert_eq!(
        info.to_json(),
        json!({"ID":7,"namespace":"ns","pod_name":"web-1","pod_uid":"uid","container_id":"0123456789abcdef",
            "node_name":"n1","labels":["k8s:app=web"],"workloads":[{"name":"web","kind":"Deployment"}]})
    );
    assert_eq!(EndpointInfo::default().to_json(), json!({}));
    assert_eq!(
        EndpointInfo {
            identity: Some(12345),
            ..EndpointInfo::default()
        }
        .to_json(),
        json!({"identity":12345})
    );
}

struct Table(BTreeMap<IpAddr, EndpointInfo>);
impl Resolver for Table {
    fn endpoint(&self, address: IpAddr) -> Option<EndpointInfo> {
        self.0.get(&address).cloned()
    }
}

#[test]
fn describe_names_pods_and_containers_and_falls_back_to_addresses() {
    let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
    let table = Table(BTreeMap::from([
        (
            ip("10.1.0.5"),
            EndpointInfo {
                namespace: "ns".into(),
                pod_name: "client".into(),
                container_id: "containerd://0123456789abcdef".into(),
                ..EndpointInfo::default()
            },
        ),
        (
            ip("10.2.0.9"),
            EndpointInfo {
                namespace: "kube-system".into(),
                pod_name: "coredns".into(),
                ..EndpointInfo::default()
            },
        ),
    ]));
    assert_eq!(
        describe(&table, ip("10.1.0.5"), ip("10.2.0.9"), 53),
        "ns/client (0123456789ab) → kube-system/coredns:53"
    );
    assert_eq!(
        describe(&table, ip("10.2.0.9"), ip("192.0.2.1"), 0),
        "kube-system/coredns → 192.0.2.1"
    );
    assert_eq!(
        describe(&table, ip("fd00::1"), ip("fd00::2"), 443),
        "fd00::1 → [fd00::2]:443"
    );
}
