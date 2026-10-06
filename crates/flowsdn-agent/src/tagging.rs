//! Pod and container tagging (#328): the `flowsdn.io/pod-networks` value the
//! agent writes onto each local Pod (the shape of OVN-Kubernetes's
//! `k8s.ovn.org/pod-networks`, keyed by network name), built from the
//! persisted endpoint, and the endpoint's Pod identity for the API.
use crate::kubernetes::{EndpointInfo, View};
use serde_json::{Map, Value, json};
use std::net::IpAddr;

pub const POD_NETWORKS: &str = "flowsdn.io/pod-networks";
/// The one network flowsdn attaches today: the primary pod network.
pub const DEFAULT_NETWORK: &str = "default";

fn text<'a>(document: &'a Value, key: &str) -> &'a str {
    document.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `{"default":{…}}` for endpoint `id`: what the CNI configured inside the
/// Pod (host-scope addresses, a host route to each gateway and a default
/// route through it, the Pod's MAC and interface), the host side, the
/// sandbox and `node` when known. `identity` is added once identities are
/// allocated; there is none today.
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
        // A recreated Pod (another UID) is not this endpoint's Pod.
        let mut other = view();
        first(&mut other.pods).uid = "uid-2".into();
        assert_eq!(pod(7, &document(), Some(&other)).get("workloads"), None);
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
        assert_eq!(patches.first().expect("patch").path(), "/api/v1/namespaces/ns/pods/web-1");
        assert_eq!(
            patches.first().expect("patch").body(),
            json!({"metadata":{"uid":"uid-1","annotations":{POD_NETWORKS:value.to_string()}}})
        );
        // Current (in any key order): nothing to write.
        let mut reordered = Map::new();
        reordered.insert("default".into(), value.get("default").cloned().expect("default"));
        first(&mut view.pods).pod_networks = Some(Value::Object(reordered).to_string());
        assert!(view.annotation_patches().is_empty());
        // Removed or edited by someone else: written back.
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
        assert!(patches.first().expect("patch").value.contains("\"endpoint_id\":9"));
    }
}
