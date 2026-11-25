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
                zone_hints: Vec::new(),
                node_hints: Vec::new(),
            })
            .collect(),
        ports: Vec::new(),
    }
}
fn all_lb() -> Policy {
    Policy::parse(&json!({"metadata": {"name": "lan"}, "spec": {"loadBalancerIPs": true}}))
}
/// The nodes that contend for the Service's Lease.
fn contenders(
    policies: &[Policy],
    service: &ServiceInfo,
    slices: &[SliceInfo],
    nodes: &[NodeInfo],
) -> Vec<String> {
    let uplinks = [uplink("eth0", ("192.168.16.10", 20), true)];
    nodes
        .iter()
        .filter(|n| {
            !eligible(
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
    // Both edge pods on pvetest2: only it contends.
    let both = [edge_slice(&[("pvetest2", true), ("pvetest2", true)])];
    assert_eq!(
        contenders(&[all_lb()], &service, &both, &nodes),
        ["pvetest2"]
    );
    // Spread over two nodes: those two contend (the Lease picks one).
    let spread = [edge_slice(&[("pvetest1", true), ("pvetest3", true)])];
    assert_eq!(
        contenders(&[all_lb()], &service, &spread, &nodes),
        ["pvetest1", "pvetest3"]
    );
    // No ready endpoint: nobody contends.
    let none = [edge_slice(&[("pvetest1", false)])];
    assert!(contenders(&[all_lb()], &service, &none, &nodes).is_empty());
    // The address goes on the uplink whose subnet holds it.
    let uplinks = [
        uplink("eth0", ("10.9.0.1", 24), true),
        uplink("eth1", ("192.168.16.10", 20), true),
        uplink("eth2", ("192.168.16.11", 20), false),
    ];
    let out = eligible(
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
fn etp_cluster_ready_selected_nodes_contend() {
    let service = edge_lb(false);
    let nodes = [node("a", true), node("b", true), node("c", true)];
    assert_eq!(
        contenders(&[all_lb()], &service, &[], &nodes),
        ["a", "b", "c"]
    );
    // A node that is not Ready stops contending (and releases the Lease).
    let down: Vec<NodeInfo> = nodes
        .iter()
        .map(|n| NodeInfo {
            ready: n.name != "a",
            ..n.clone()
        })
        .collect();
    assert_eq!(contenders(&[all_lb()], &service, &[], &down), ["b", "c"]);
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
    assert_eq!(contenders(&[only_b], &service, &[], &labelled), ["b"]);
}

#[test]
fn nothing_is_announced_without_a_selecting_policy_or_flag() {
    let nodes = [node("a", true)];
    let service = edge_lb(false);
    assert!(contenders(&[], &service, &[], &nodes).is_empty());
    let off = Policy::parse(&json!({"metadata": {"name": "off"}, "spec": {}}));
    assert!(contenders(&[off], &service, &[], &nodes).is_empty());
    let other_ns = Policy::parse(&json!({"metadata": {"name": "x"}, "spec": {
        "loadBalancerIPs": true,
        "serviceSelector": {"matchLabels": {"io.kubernetes.service.namespace": "other"}}}}));
    assert!(contenders(&[other_ns], &service, &[], &nodes).is_empty());
    let classed = ServiceInfo {
        load_balancer_class: Some("example.com/bgp".into()),
        ..service.clone()
    };
    assert!(contenders(&[all_lb()], &classed, &[], &nodes).is_empty());
    let bad = Policy::parse(&json!({"metadata": {"name": "bad"}, "spec": {
        "loadBalancerIPs": true, "interfaces": ["("]}}));
    assert!(
        bad.invalid
            .as_deref()
            .is_some_and(|e| e.starts_with("interfaces:"))
    );
    assert!(contenders(&[bad], &service, &[], &nodes).is_empty());
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
    let out = eligible(&[policy], &[service], &[], &nodes, "a", &[], &names);
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

/// #549 (finding 27c1663186dc): with two Ready selected nodes whose device
/// names differ and an `interfaces` expression matching only one, only the
/// node with a matching interface contends, so the address always has an
/// owner; a node without one never takes the Lease and leaves it unanswered.
#[test]
fn only_nodes_with_a_matching_interface_contend() {
    let nodes = [node("a", true), node("b", true)];
    let service = edge_lb(false);
    let policy = Policy::parse(&json!({"metadata": {"name": "p"}, "spec": {
        "loadBalancerIPs": true, "interfaces": ["^ens"]}}));
    let on = |local: &str, names: &[&str]| {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        eligible(
            std::slice::from_ref(&policy),
            std::slice::from_ref(&service),
            &[],
            &nodes,
            local,
            &[],
            &names,
        )
    };
    // Whichever node a hash of the names would favour, "a" has only eth0.
    assert!(on("a", &["eth0", "lo"]).is_empty());
    let b = on("b", &["ens18", "lo"]);
    assert_eq!(b.len(), 1);
    assert_eq!(
        b.first().map(|a| a.interfaces.clone()),
        Some(vec!["ens18".to_owned()])
    );
    let key = ("storefront".to_owned(), "edge-lb".to_owned());
    assert_eq!(services(&b), [key.clone()].into());
    assert_eq!(
        lease_name(&key.0, &key.1),
        "flowsdn-l2announce-storefront-edge-lb"
    );
    // b answers once it holds the Lease, and not before.
    assert!(held(&b, &BTreeSet::new()).is_empty());
    assert_eq!(held(&b, &[key].into()), b);
}

/// #549: Lease collection deletes announcement Leases without a holder and
/// those no node renewed over a whole period, and nothing else.
#[test]
fn stale_announcement_leases_are_collected() {
    let lease = |name: &str, holder: &str, renew: &str| {
        json!({"metadata": {"name": name, "resourceVersion": format!("rv-{name}")},
               "spec": {"holderIdentity": holder, "renewTime": renew}})
    };
    let list = |renew: &str| {
        json!({"items": [
            lease("flowsdn-l2announce-a-x", "", ""),
            lease("flowsdn-l2announce-a-y", "n1", renew),
            lease("flowsdn-lb-ipam", "", ""),
        ]})
    };
    let (stale, seen) = stale_leases(&list("t1"), &BTreeMap::new());
    assert_eq!(
        stale,
        [(
            "flowsdn-l2announce-a-x".to_owned(),
            "rv-flowsdn-l2announce-a-x".to_owned()
        )]
    );
    assert_eq!(seen.len(), 1);
    // Renewed since: kept.
    let (stale, seen) = stale_leases(&list("t2"), &seen);
    assert_eq!(stale.len(), 1);
    // Not renewed for a period: collected too.
    let (stale, seen) = stale_leases(&list("t2"), &seen);
    let names: Vec<&str> = stale.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["flowsdn-l2announce-a-x", "flowsdn-l2announce-a-y"]);
    assert!(seen.is_empty());
}
