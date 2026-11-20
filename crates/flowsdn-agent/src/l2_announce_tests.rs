use super::*;
use crate::services::Endpoint;
use serde_json::json;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("IP")
}
fn node(name: &str, ready: bool) -> NodeInfo {
    NodeInfo {
        name: name.into(),
        ready,
        ..NodeInfo::default()
    }
}
fn uplink(name: &str, cidr: (&str, u8), up: bool) -> Uplink {
    Uplink {
        name: name.into(),
        up,
        addresses: vec![(ip(cidr.0), cidr.1)],
        ..Uplink::default()
    }
}
fn edge_lb(local: bool) -> ServiceInfo {
    ServiceInfo {
        namespace: "storefront".into(),
        name: "edge-lb".into(),
        service_type: "LoadBalancer".into(),
        load_balancer_ips: vec![ip("192.168.30.240")],
        external_local: local,
        ..ServiceInfo::default()
    }
}
fn edge_slice(nodes: &[(&str, bool)]) -> SliceInfo {
    SliceInfo {
        namespace: "storefront".into(),
        name: "edge-lb-x".into(),
        service: "edge-lb".into(),
        address_type: "IPv4".into(),
        endpoints: nodes
            .iter()
            .enumerate()
            .map(|(i, (n, ready))| Endpoint {
                addresses: vec![ip(&format!("10.1.0.{}", i.saturating_add(10)))],
                ready: *ready,
                serving: *ready,
                terminating: false,
                node_name: (*n).into(),
            })
            .collect(),
        ports: Vec::new(),
    }
}
fn all_lb() -> Policy {
    Policy::parse(&json!({"metadata": {"name": "lan"}, "spec": {"loadBalancerIPs": true}}))
}
fn winners(
    policies: &[Policy],
    service: &ServiceInfo,
    slices: &[SliceInfo],
    nodes: &[NodeInfo],
) -> Vec<String> {
    let uplinks = [uplink("eth0", ("192.168.16.10", 20), true)];
    nodes
        .iter()
        .filter(|n| {
            !plan(
                policies,
                std::slice::from_ref(service),
                slices,
                nodes,
                &n.name,
                &uplinks,
                &[],
            )
            .is_empty()
        })
        .map(|n| n.name.clone())
        .collect()
}

#[test]
fn etp_local_is_answered_by_one_node_with_an_endpoint() {
    let nodes = [
        node("pvetest1", true),
        node("pvetest2", true),
        node("pvetest3", true),
    ];
    let service = edge_lb(true);
    // Both edge pods on pvetest2: only it answers.
    let both = [edge_slice(&[("pvetest2", true), ("pvetest2", true)])];
    assert_eq!(winners(&[all_lb()], &service, &both, &nodes), ["pvetest2"]);
    // Spread over two nodes: exactly one of them answers.
    let spread = [edge_slice(&[("pvetest1", true), ("pvetest3", true)])];
    let won = winners(&[all_lb()], &service, &spread, &nodes);
    assert_eq!(won.len(), 1);
    let first = won.first().expect("winner");
    assert!(first == "pvetest1" || first == "pvetest3", "{won:?}");
    // No ready endpoint: nobody answers.
    let none = [edge_slice(&[("pvetest1", false)])];
    assert!(winners(&[all_lb()], &service, &none, &nodes).is_empty());
    // The address goes on the uplink whose subnet holds it.
    let uplinks = [
        uplink("eth0", ("10.9.0.1", 24), true),
        uplink("eth1", ("192.168.16.10", 20), true),
        uplink("eth2", ("192.168.16.11", 20), false),
    ];
    let out = plan(
        &[all_lb()],
        &[service],
        &both,
        &nodes,
        "pvetest2",
        &uplinks,
        &[],
    );
    assert_eq!(
        out,
        [Announcement {
            ip: ip("192.168.30.240"),
            namespace: "storefront".into(),
            name: "edge-lb".into(),
            interfaces: vec!["eth1".into()],
        }]
    );
}

#[test]
fn etp_cluster_picks_one_ready_selected_node_and_moves_when_it_goes() {
    let service = edge_lb(false);
    let nodes = [node("a", true), node("b", true), node("c", true)];
    let won = winners(&[all_lb()], &service, &[], &nodes);
    assert_eq!(won.len(), 1);
    let first = won.first().expect("winner").clone();
    // The winner stops being Ready: another node takes over.
    let down: Vec<NodeInfo> = nodes
        .iter()
        .map(|n| NodeInfo {
            ready: n.name != first,
            ..n.clone()
        })
        .collect();
    let next = winners(&[all_lb()], &service, &[], &down);
    assert_eq!(next.len(), 1);
    assert_ne!(next.first(), Some(&first));
    // nodeSelector limits the candidates.
    let only_b = Policy::parse(&json!({"metadata": {"name": "b"}, "spec": {
        "loadBalancerIPs": true,
        "nodeSelector": {"matchLabels": {"edge": "yes"}}}}));
    let labelled: Vec<NodeInfo> = nodes
        .iter()
        .map(|n| NodeInfo {
            labels: if n.name == "b" {
                [("edge".to_owned(), "yes".to_owned())].into()
            } else {
                BTreeMap::new()
            },
            ..n.clone()
        })
        .collect();
    assert_eq!(winners(&[only_b], &service, &[], &labelled), ["b"]);
}

#[test]
fn nothing_is_announced_without_a_selecting_policy_or_flag() {
    let nodes = [node("a", true)];
    let service = edge_lb(false);
    assert!(winners(&[], &service, &[], &nodes).is_empty());
    let off = Policy::parse(&json!({"metadata": {"name": "off"}, "spec": {}}));
    assert!(winners(&[off], &service, &[], &nodes).is_empty());
    let other_ns = Policy::parse(&json!({"metadata": {"name": "x"}, "spec": {
        "loadBalancerIPs": true,
        "serviceSelector": {"matchLabels": {"io.kubernetes.service.namespace": "other"}}}}));
    assert!(winners(&[other_ns], &service, &[], &nodes).is_empty());
    let classed = ServiceInfo {
        load_balancer_class: Some("example.com/bgp".into()),
        ..service.clone()
    };
    assert!(winners(&[all_lb()], &classed, &[], &nodes).is_empty());
    let bad = Policy::parse(&json!({"metadata": {"name": "bad"}, "spec": {
        "loadBalancerIPs": true, "interfaces": ["("]}}));
    assert!(
        bad.invalid
            .as_deref()
            .is_some_and(|e| e.starts_with("interfaces:"))
    );
    assert!(winners(&[bad], &service, &[], &nodes).is_empty());
}

#[test]
fn interfaces_and_external_ips() {
    let nodes = [node("a", true)];
    let service = ServiceInfo {
        external_ips: vec![ip("203.0.113.5")],
        ..edge_lb(false)
    };
    let policy = Policy::parse(&json!({"metadata": {"name": "p"}, "spec": {
        "externalIPs": true, "interfaces": ["^ens", "bond"]}}));
    let names = ["ens18".to_owned(), "lo".to_owned(), "bond0".to_owned()];
    let out = plan(&[policy], &[service], &[], &nodes, "a", &[], &names);
    assert_eq!(out.len(), 1);
    let only = out.first().expect("announcement");
    assert_eq!(only.ip, ip("203.0.113.5"));
    assert_eq!(only.interfaces, ["bond0", "ens18"]);
    let status = status_json(&out, &[], &[]);
    assert_eq!(
        status.pointer("/announcing/0/service"),
        Some(&json!("storefront/edge-lb"))
    );
    assert_eq!(
        status.pointer("/announcing/0/interfaces/1"),
        Some(&json!("ens18"))
    );
}
