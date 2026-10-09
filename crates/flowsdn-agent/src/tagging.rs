//! Pod and container tagging (#328): the `flowsdn.io/pod-networks` value the
//! agent writes onto each local Pod (the shape of OVN-Kubernetes's
//! `k8s.ovn.org/pod-networks`, keyed by network name), built from the
//! persisted endpoint, the Multus/NPWG `network-status` entry for the same
//! interface (#371), and the endpoint's Pod identity for the API.
use crate::kubernetes::{EndpointInfo, View};
use serde_json::{Map, Value, json};
use std::net::IpAddr;

pub const POD_NETWORKS: &str = "flowsdn.io/pod-networks";
/// The Kubernetes Network Plumbing WG annotation Multus writes (stormcos#249).
pub const NETWORK_STATUS: &str = "k8s.v1.cni.cncf.io/network-status";
/// The one network flowsdn attaches today: the primary pod network.
pub const DEFAULT_NETWORK: &str = "default";

fn text<'a>(document: &'a Value, key: &str) -> &'a str {
    document.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `{"default":{…}}` for endpoint `id`: what the CNI configured inside the
/// Pod (host-scope addresses, a host route to each gateway and a default
/// route through it, the Pod's MAC and interface), the host side, the
/// sandbox and `node` when known. The identity is not part of it (it can
/// change while the network does not); the endpoint model and `pod` carry it.
pub fn pod_networks(id: u16, document: &Value, node: &str) -> Value {
    let mut addresses = Vec::new();
    let mut gateways = Vec::new();
    let mut routes = Vec::new();
    for family in ["IPv4", "IPv6"] {
        let Ok(ip) = text(document, family).parse::<IpAddr>() else {
            continue;
        };
        let host = if ip.is_ipv4() { 32 } else { 128 };
        addresses.push(format!("{ip}/{host}"));
        let gateway = document
            .pointer(&format!("/CNIHostAddressing/{}/ip", family.to_lowercase()))
            .and_then(Value::as_str)
            .and_then(|g| g.parse::<IpAddr>().ok())
            .filter(|g| g.is_ipv4() == ip.is_ipv4());
        if let Some(gateway) = gateway {
            gateways.push(gateway.to_string());
            routes.push(json!({"dest":format!("{gateway}/{host}")}));
            let default = if ip.is_ipv4() { "0.0.0.0/0" } else { "::/0" };
            routes.push(json!({"dest":default,"nextHop":gateway.to_string()}));
        }
    }
    let mut network = Map::new();
    network.insert("role".into(), json!("primary"));
    network.insert("interface".into(), json!(text(document, "ContainerIfName")));
    network.insert("mac_address".into(), json!(text(document, "LXCMAC")));
    network.insert("ip_addresses".into(), json!(addresses));
    network.insert("gateway_ips".into(), json!(gateways));
    network.insert("routes".into(), json!(routes));
    network.insert("host_interface".into(), json!(text(document, "IfName")));
    network.insert("endpoint_id".into(), json!(id));
    network.insert("sandbox".into(), json!(text(document, "dockerID")));
    if !node.is_empty() {
        network.insert("node".into(), json!(node));
    }
    json!({ DEFAULT_NETWORK: network })
}

/// The NPWG `network-status` entry for flowsdn's interface, from the
/// `pod-networks` value (so the two annotations always agree): the conflist's
/// network name, the interface, its addresses without prefix, its MAC, and
/// `default` (flowsdn attaches only the primary network today).
pub fn network_status_entry(pod_networks: &Value) -> Value {
    let network = pod_networks.get(DEFAULT_NETWORK);
    let field = |key: &str| network.and_then(|n| n.get(key));
    let ips: Vec<&str> = field("ip_addresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|cidr| cidr.split_once('/').map_or(cidr, |(ip, _)| ip))
        .collect();
    let mut entry = Map::new();
    entry.insert("name".into(), json!(flowsdn_cni::install::NETWORK_NAME));
    entry.insert(
        "interface".into(),
        field("interface").cloned().unwrap_or(json!("")),
    );
    entry.insert("ips".into(), json!(ips));
    if let Some(mac) = field("mac_address")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
    {
        entry.insert("mac".into(), json!(mac));
    }
    entry.insert(
        "default".into(),
        json!(field("role").and_then(Value::as_str) == Some("primary")),
    );
    Value::Object(entry)
}

/// The Pod's `network-status` with flowsdn's `entry` in it: every other
/// plugin's entry kept as it is (Multus writes the secondary attachments),
/// flowsdn's earlier entry (same name or same interface) replaced, and the
/// default network's entry first, as Multus orders it. A current value that
/// is not a JSON array is not anyone's list and is replaced.
pub fn network_status(current: Option<&Value>, entry: &Value) -> Value {
    let interface = entry.get("interface");
    let ours = |other: &Value| {
        other.get("name") == entry.get("name")
            || (interface.and_then(Value::as_str).is_some_and(|i| !i.is_empty()) && other.get("interface") == interface)
    };
    let others = current
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|other| !ours(other))
        .cloned();
    let list: Vec<Value> = if entry.get("default") == Some(&json!(true)) {
        std::iter::once(entry.clone()).chain(others).collect()
    } else {
        others.chain(std::iter::once(entry.clone())).collect()
    };
    Value::Array(list)
}

/// The endpoint's Pod as a flow names it (#328): Hubble's flow `Endpoint`
/// from the persisted endpoint, filled in from the Pod view when it has the
/// Pod (labels, workload, node), with the Pod's containers.
pub fn pod(id: u16, document: &Value, view: Option<&View>) -> Value {
    let (namespace, name, uid) = (
        text(document, "K8sNamespace"),
        text(document, "K8sPodName"),
        text(document, "K8sUID"),
    );
    let found = view.and_then(|view| view.local_pod(namespace, name, uid));
    let mut info = found
        .map(|pod| pod.endpoint_info())
        .unwrap_or(EndpointInfo {
            namespace: namespace.into(),
            pod_name: name.into(),
            pod_uid: uid.into(),
            node: view.map(|v| v.local_node.clone()).unwrap_or_default(),
            ..EndpointInfo::default()
        });
    info.id = id;
    info.identity = found
        .and(view)
        .and_then(|view| view.pod_identity(namespace, name));
    info.container_id = text(document, "dockerID").into();
    let mut value = info.to_json();
    if let (Some(pod), Some(object)) = (found, value.as_object_mut()) {
        object.insert("containers".into(), pod.containers_json());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kubernetes::{Container, LocalEndpoint, PodInfo, Workload};

    fn document() -> Value {
        json!({"dockerID":"sandbox1","ContainerIfName":"eth0","IfName":"lxc1234","LXCMAC":"02:00:00:00:00:07",
            "IPv4":"10.5.0.7","IPv6":"f00d::a05:0:0:7","K8sNamespace":"ns","K8sPodName":"web-1","K8sUID":"uid-1",
            "CNIHostAddressing":{"ipv4":{"enabled":true,"ip":"10.5.0.1","alloc-range":"10.5.0.0/16"},
                "ipv6":{"enabled":true,"ip":"f00d::a05:0:0:1","alloc-range":"f00d::a05:0:0:0/96"}}})
    }

    #[test]
    fn pod_networks_is_the_ovn_shape_of_what_the_cni_configured() {
        assert_eq!(
            pod_networks(7, &document(), "n1"),
            json!({"default":{"role":"primary","interface":"eth0","mac_address":"02:00:00:00:00:07",
                "ip_addresses":["10.5.0.7/32","f00d::a05:0:0:7/128"],"gateway_ips":["10.5.0.1","f00d::a05:0:0:1"],
                "routes":[{"dest":"10.5.0.1/32"},{"dest":"0.0.0.0/0","nextHop":"10.5.0.1"},
                    {"dest":"f00d::a05:0:0:1/128"},{"dest":"::/0","nextHop":"f00d::a05:0:0:1"}],
                "host_interface":"lxc1234","endpoint_id":7,"sandbox":"sandbox1","node":"n1"}})
        );
        let mut v4 = document();
        let object = v4.as_object_mut().expect("object");
        object.insert("IPv6".into(), json!(""));
        object.insert("CNIHostAddressing".into(), json!({}));
        let value = pod_networks(3, &v4, "");
        assert_eq!(
            value.pointer("/default/ip_addresses"),
            Some(&json!(["10.5.0.7/32"]))
        );
        assert_eq!(value.pointer("/default/routes"), Some(&json!([])));
        assert_eq!(value.pointer("/default/node"), None);
    }

    #[test]
    fn network_status_entry_agrees_with_pod_networks() {
        let value = pod_networks(7, &document(), "n1");
        assert_eq!(
            network_status_entry(&value),
            json!({"name":"flowsdn","interface":"eth0","ips":["10.5.0.7","f00d::a05:0:0:7"],
                "mac":"02:00:00:00:00:07","default":true})
        );
        let mut bare = document();
        let object = bare.as_object_mut().expect("object");
        object.insert("LXCMAC".into(), json!(""));
        object.insert("IPv6".into(), json!(""));
        assert_eq!(
            network_status_entry(&pod_networks(7, &bare, "")),
            json!({"name":"flowsdn","interface":"eth0","ips":["10.5.0.7"],"default":true})
        );
    }

    #[test]
    fn network_status_merges_into_other_plugins_entries() {
        let entry = network_status_entry(&pod_networks(7, &document(), "n1"));
        assert_eq!(network_status(None, &entry), json!([entry]));
        assert_eq!(network_status(Some(&json!({"not":"a list"})), &entry), json!([entry]));
        let secondary = json!({"name":"ns/vlan10","interface":"net1","ips":["192.0.2.5"],"mac":"02:aa:00:00:00:01"});
        // Multus's own entry for flowsdn (same name, its own extra keys) and an
        // old one on the same interface are replaced; the default goes first.
        let multus = json!({"name":"flowsdn","interface":"eth0","ips":["10.5.0.6"],"default":true,"dns":{}});
        let stale = json!({"name":"old","interface":"eth0","ips":["10.9.0.1"]});
        assert_eq!(
            network_status(Some(&json!([secondary, multus, stale])), &entry),
            json!([entry, secondary])
        );
        // A non-default entry goes after the others.
        let mut extra = entry.clone();
        extra
            .as_object_mut()
            .expect("entry")
            .insert("default".into(), json!(false));
        assert_eq!(
            network_status(Some(&json!([secondary])), &extra),
            json!([secondary, extra])
        );
    }

    fn view() -> View {
        View {
            local_node: "n1".into(),
            pods: vec![PodInfo {
                namespace: "ns".into(),
                name: "web-1".into(),
                node: "n1".into(),
                uid: "uid-1".into(),
                labels: [("app".to_owned(), "web".to_owned())].into_iter().collect(),
                workload: Some(Workload {
                    kind: "Deployment".into(),
                    name: "web".into(),
                }),
                containers: vec![Container {
                    name: "app".into(),
                    id: "containerd://abc".into(),
                    init: false,
                }],
                ..PodInfo::default()
            }],
            ..View::default()
        }
    }

    fn first<T>(items: &mut [T]) -> &mut T {
        items.first_mut().expect("one item")
    }

    #[test]
    fn pod_joins_the_endpoint_with_the_pod_view() {
        assert_eq!(
            pod(7, &document(), Some(&view())),
            json!({"ID":7,"namespace":"ns","pod_name":"web-1","pod_uid":"uid-1","container_id":"sandbox1",
                "node_name":"n1","labels":["k8s:app=web","k8s:io.kubernetes.pod.namespace=ns"],
                "workloads":[{"name":"web","kind":"Deployment"}],
                "containers":[{"name":"app","container-id":"containerd://abc","init":false}]})
        );
        // Without Kubernetes (or before the Pod is seen) only the endpoint's facts.
        assert_eq!(
            pod(7, &document(), None),
            json!({"ID":7,"namespace":"ns","pod_name":"web-1","pod_uid":"uid-1","container_id":"sandbox1"})
        );
        // With an identity (spec 03 §3.3) the flow endpoint carries it.
        let mut with = view();
        with.pod_identities
            .insert(("ns".into(), "web-1".into()), 300);
        assert_eq!(
            pod(7, &document(), Some(&with)).get("identity"),
            Some(&json!(300))
        );
        // A recreated Pod (another UID) is not this endpoint's Pod.
        let mut other = with;
        first(&mut other.pods).uid = "uid-2".into();
        assert_eq!(pod(7, &document(), Some(&other)).get("workloads"), None);
        assert_eq!(pod(7, &document(), Some(&other)).get("identity"), None);
    }

    #[test]
    fn annotation_patches_only_what_differs_once_both_lists_are_known() {
        let value = pod_networks(7, &document(), "n1");
        let mut view = view();
        view.endpoints = vec![LocalEndpoint {
            id: 7,
            namespace: "ns".into(),
            name: "web-1".into(),
            uid: "uid-1".into(),
            value: value.clone(),
        }];
        assert!(view.annotation_patches().is_empty(), "pods not synced");
        view.pods_synced = true;
        assert!(
            view.annotation_patches().is_empty(),
            "endpoints not published"
        );
        view.endpoints_published = true;
        let patches = view.annotation_patches();
        assert_eq!(patches.len(), 1);
        assert_eq!(
            patches.first().expect("patch").path(),
            "/api/v1/namespaces/ns/pods/web-1"
        );
        let status = network_status(None, &network_status_entry(&value));
        first(&mut view.pods).resource_version = "41".into();
        assert_eq!(
            view.annotation_patches().first().expect("patch").body(),
            json!({"metadata":{"uid":"uid-1","resourceVersion":"41","annotations":{
                POD_NETWORKS:value.to_string(),NETWORK_STATUS:status.to_string()}}})
        );
        // Current (in any key order): nothing to write.
        let mut reordered = Map::new();
        reordered.insert(
            "default".into(),
            value.get("default").cloned().expect("default"),
        );
        first(&mut view.pods).pod_networks = Some(Value::Object(reordered).to_string());
        first(&mut view.pods).network_status = Some(status.to_string());
        assert!(view.annotation_patches().is_empty());
        // Removed or edited by someone else: written back, only that one;
        // pod-networks alone needs no resourceVersion precondition.
        first(&mut view.pods).pod_networks = Some("{\"default\":{}}".into());
        let patches = view.annotation_patches();
        assert_eq!(
            patches.first().expect("patch").body(),
            json!({"metadata":{"uid":"uid-1","annotations":{POD_NETWORKS:value.to_string()}}})
        );
        first(&mut view.pods).pod_networks = Some(value.to_string());
        // Multus added a secondary attachment: flowsdn's entry is current.
        let secondary = json!({"name":"ns/vlan10","interface":"net1","ips":["192.0.2.5"],"default":false});
        first(&mut view.pods).network_status =
            Some(json!([status.get(0).cloned().expect("entry"), secondary]).to_string());
        assert!(view.annotation_patches().is_empty());
        // flowsdn's entry removed beside it: written back, the secondary kept.
        first(&mut view.pods).network_status = Some(json!([secondary]).to_string());
        let patches = view.annotation_patches();
        let written: Value = serde_json::from_str(
            patches
                .first()
                .and_then(|p| p.network_status.as_deref())
                .expect("network-status"),
        )
        .expect("json");
        assert_eq!(
            written,
            json!([status.get(0).cloned().expect("entry"), secondary])
        );
        assert_eq!(patches.first().expect("patch").pod_networks, None);
        // Too large to have been kept: never merged into.
        first(&mut view.pods).network_status = None;
        first(&mut view.pods).network_status_oversized = true;
        assert!(view.annotation_patches().is_empty());
        first(&mut view.pods).network_status_oversized = false;
        first(&mut view.pods).network_status = Some(status.to_string());
        first(&mut view.pods).pod_networks = Some("{\"default\":{}}".into());
        assert_eq!(view.annotation_patches().len(), 1);
        // A Pod on another node, another UID, or a name that is no DNS name: never.
        first(&mut view.pods).node = "n2".into();
        assert!(view.annotation_patches().is_empty());
        first(&mut view.pods).node = "n1".into();
        first(&mut view.pods).uid = "uid-2".into();
        assert!(view.annotation_patches().is_empty());
        first(&mut view.pods).uid = "uid-1".into();
        first(&mut view.endpoints).name = "Web/../x".into();
        assert!(view.annotation_patches().is_empty());
        // Two endpoints for one Pod: the newest ID's value.
        first(&mut view.endpoints).name = "web-1".into();
        let mut newer = first(&mut view.endpoints).clone();
        newer.id = 9;
        newer.value = pod_networks(9, &document(), "n1");
        view.endpoints.push(newer);
        let patches = view.annotation_patches();
        assert_eq!(patches.len(), 1);
        assert!(
            patches
                .first()
                .and_then(|p| p.pod_networks.as_deref())
                .expect("pod-networks")
                .contains("\"endpoint_id\":9")
        );
    }
}
