#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
use super::*;

fn node(name: &str, ip: &str, labels: &[(&str, &str)]) -> NodeInfo {
    NodeInfo {
        name: name.into(),
        internal_ips: vec![ip.parse().unwrap()],
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        ..NodeInfo::default()
    }
}
fn pod(name: &str, node: &str, ip: &str, labels: &[(&str, &str)]) -> PodInfo {
    PodInfo {
        namespace: "shop".into(),
        name: name.into(),
        node: node.into(),
        uid: format!("uid-{name}"),
        ips: vec![ip.parse().unwrap()],
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        ..PodInfo::default()
    }
}
fn nodes() -> Vec<NodeInfo> {
    vec![
        node("n2", "192.0.2.2", &[("egress", "yes")]),
        node("n1", "192.0.2.1", &[]),
        node("n3", "192.0.2.3", &[("egress", "yes")]),
    ]
}
fn namespaces() -> BTreeMap<String, BTreeMap<String, String>> {
    BTreeMap::from([(
        "shop".to_owned(),
        BTreeMap::from([("team".to_owned(), "a".to_owned())]),
    )])
}
fn interfaces() -> Vec<Interface> {
    vec![
        Interface {
            name: "eth0".into(),
            index: 2,
            addresses: vec!["192.0.2.2".parse().unwrap()],
            addresses6: vec!["2001:db8:2::2".parse().unwrap()],
        },
        Interface {
            name: "eth1".into(),
            index: 3,
            addresses: vec!["198.51.100.7".parse().unwrap()],
            addresses6: vec!["2001:db8:64::7".parse().unwrap()],
        },
    ]
}
fn policy(gateway: Value) -> Value {
    json!({"metadata": {"name": "web-out"},
           "spec": {"selectors": [{"podSelector": {"matchLabels": {"app": "web"}}}],
                    "destinationCIDRs": ["203.0.113.0/24"],
                    "excludedCIDRs": ["203.0.113.128/25"],
                    "egressGateway": gateway}})
}
fn value(entries: &Entries, src: [u8; 4], dst: [u8; 4], len: u32) -> EgressGw4Value {
    let [a, b, c, d] = src;
    let [e, f, g, h] = dst;
    EgressGw4Value::from_bytes(*entries.get(&(32 + len, [a, b, c, d, e, f, g, h])).unwrap())
}

/// spec 14 §3.4.3–3.4.5 (#564): the first selected node in name order is the
/// gateway; on it the entry carries the egress address of the uplink holding
/// the node's address; elsewhere only the gateway address; the excluded CIDR
/// is the 0.0.0.1 sentinel; unselected Pods get nothing.
#[test]
fn single_gateway_entries_on_the_gateway_and_elsewhere() {
    let pods = vec![
        pod("web", "n1", "10.1.1.5", &[("app", "web")]),
        pod("db", "n1", "10.1.1.6", &[("app", "db")]),
    ];
    let objects = [policy(
        json!({"nodeSelector": {"matchLabels": {"egress": "yes"}}}),
    )];
    let ifs = interfaces();
    let gateway = Local {
        node: "n2",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let (Maps { v4: entries, .. }, report) =
        plan(&objects, &pods, &namespaces(), &nodes(), &gateway);
    assert_eq!(report.problems.get("web-out"), Some(&None));
    assert_eq!(
        report.gateways["web-out"],
        vec![("192.0.2.2".parse().unwrap(), "n2".to_owned())]
    );
    assert_eq!(
        entries.len(),
        2,
        "one destination and one exclusion for the one web Pod"
    );
    let entry = value(&entries, [10, 1, 1, 5], [203, 0, 113, 0], 24);
    assert_eq!(entry.gateway_ip, [192, 0, 2, 2]);
    assert_eq!(entry.egress_ip, [192, 0, 2, 2]);
    assert_eq!(entry.egress_ifindex, 2);
    assert_eq!(
        value(&entries, [10, 1, 1, 5], [203, 0, 113, 128], 25).gateway_ip,
        GATEWAY_EXCLUDED
    );
    let other = Local {
        node: "n1",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let (Maps { v4: entries, .. }, _) = plan(&objects, &pods, &namespaces(), &nodes(), &other);
    let entry = value(&entries, [10, 1, 1, 5], [203, 0, 113, 0], 24);
    assert_eq!(
        (entry.gateway_ip, entry.egress_ip, entry.egress_ifindex),
        ([192, 0, 2, 2], [0; 4], 0)
    );
}

/// `interface` gives its address and index; `egressIP` gives the address
/// with index 0 (the FIB chooses); a missing interface leaves 0.0.0.0 (drop).
#[test]
fn egress_address_from_interface_or_egress_ip() {
    let pods = vec![pod("web", "n1", "10.1.1.5", &[("app", "web")])];
    let ifs = interfaces();
    let here = Local {
        node: "n2",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    for (gateway, want) in [
        (
            json!({"nodeSelector": {"matchLabels": {"egress": "yes"}}, "interface": "eth1"}),
            ([198, 51, 100, 7], 3),
        ),
        (
            json!({"nodeSelector": {"matchLabels": {"egress": "yes"}}, "egressIP": "198.51.100.7"}),
            ([198, 51, 100, 7], 0),
        ),
        (
            json!({"nodeSelector": {"matchLabels": {"egress": "yes"}}, "interface": "eth9"}),
            ([0, 0, 0, 0], 0),
        ),
    ] {
        let (Maps { v4: entries, .. }, report) =
            plan(&[policy(gateway)], &pods, &namespaces(), &nodes(), &here);
        let entry = value(&entries, [10, 1, 1, 5], [203, 0, 113, 0], 24);
        assert_eq!((entry.egress_ip, entry.egress_ifindex), want);
        assert_eq!(report.local.len(), 1);
    }
}

/// No node selected: the gateway is 0.0.0.0 so the traffic is dropped, never
/// sent from the node's own address.
#[test]
fn no_gateway_is_the_drop_sentinel() {
    let pods = vec![pod("web", "n1", "10.1.1.5", &[("app", "web")])];
    let ifs = interfaces();
    let local = Local {
        node: "n1",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let objects = [policy(
        json!({"nodeSelector": {"matchLabels": {"egress": "nowhere"}}}),
    )];
    let (Maps { v4: entries, .. }, report) = plan(&objects, &pods, &namespaces(), &nodes(), &local);
    assert!(report.gateways["web-out"].is_empty());
    assert_eq!(
        value(&entries, [10, 1, 1, 5], [203, 0, 113, 0], 24).gateway_ip,
        GATEWAY_NONE
    );
}

/// Several gateways: each Pod gets FNV-1a(UID) mod n of the gateways in
/// address order, as `flowsdn_encryption::gateway::choose` computes.
#[test]
fn multiple_gateways_split_by_uid() {
    let pods: Vec<PodInfo> = (0..16)
        .map(|i| {
            pod(
                &format!("web-{i}"),
                "n1",
                &format!("10.1.1.{}", i + 10),
                &[("app", "web")],
            )
        })
        .collect();
    let mut object = policy(json!(null));
    object["spec"]["egressGateways"] = json!([
        {"nodeSelector": {"matchLabels": {"kubernetes.io/hostname": "n3"}}},
        {"nodeSelector": {"matchLabels": {"kubernetes.io/hostname": "n2"}}},
    ]);
    let mut all = nodes();
    for node in &mut all {
        node.labels
            .insert("kubernetes.io/hostname".into(), node.name.clone());
    }
    let ifs = interfaces();
    let local = Local {
        node: "n1",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let (Maps { v4: entries, .. }, _) = plan(&[object], &pods, &namespaces(), &all, &local);
    let mut seen = std::collections::BTreeSet::new();
    for (i, pod) in pods.iter().enumerate() {
        let gateway = value(
            &entries,
            [10, 1, 1, u8::try_from(i + 10).unwrap()],
            [203, 0, 113, 0],
            24,
        )
        .gateway_ip;
        let want = flowsdn_encryption::gateway::choose(
            pod.uid.as_bytes(),
            &["192.0.2.2".parse().unwrap(), "192.0.2.3".parse().unwrap()],
            flowsdn_encryption::gateway::Selection::Modulo,
        )
        .unwrap()
        .unwrap();
        assert_eq!(gateway, want.octets());
        seen.insert(gateway);
    }
    assert_eq!(seen.len(), 2, "16 Pods use both gateways");
}

/// Namespace selectors read the Namespace's labels; node selectors are one
/// flat list; validation drops the whole policy.
#[test]
fn selection_and_validation() {
    let pods = vec![
        pod("web", "n1", "10.1.1.5", &[("app", "web")]),
        pod("web2", "n2", "10.1.2.5", &[("app", "web")]),
    ];
    let ifs = interfaces();
    let local = Local {
        node: "n1",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let mut object = policy(json!({"nodeSelector": {"matchLabels": {"egress": "yes"}}}));
    object["spec"]["selectors"] = json!([{"namespaceSelector": {"matchLabels": {"team": "a"}},
                                          "nodeSelector": {"matchLabels": {"egress": "yes"}}}]);
    let (Maps { v4: entries, .. }, report) =
        plan(&[object], &pods, &namespaces(), &nodes(), &local);
    assert_eq!(
        report.sources["web-out"], 1,
        "only the Pod on a selected node"
    );
    assert!(entries.keys().all(|(_, data)| data[..4] == [10, 1, 2, 5]));
    for (spec, want) in [
        (
            json!({"selectors": [{"podSelector": {}}], "egressGateway": {"nodeSelector": {}}}),
            "destination CIDRs",
        ),
        (
            json!({"selectors": [{}], "destinationCIDRs": [], "egressGateway": {"nodeSelector": {}}}),
            "nil namespace selector",
        ),
        (
            json!({"selectors": [], "destinationCIDRs": ["10.0.0.0/33"], "egressGateway": {"nodeSelector": {}}}),
            "failed to parse destination",
        ),
        (
            json!({"selectors": [], "destinationCIDRs": [], "egressGateway": {"nodeSelector": {}, "interface": "eth0", "egressIP": "1.2.3.4"}}),
            "cannot specify both",
        ),
        (
            json!({"selectors": [], "destinationCIDRs": [], "egressGateway": {"nodeSelector": {}, "egressIP": "nope"}}),
            "egress IP",
        ),
    ] {
        let (Maps { v4: entries, .. }, report) = plan(
            &[json!({"metadata": {"name": "bad"}, "spec": spec})],
            &pods,
            &namespaces(),
            &nodes(),
            &local,
        );
        let problem = report.problems["bad"].clone().unwrap();
        assert!(problem.contains(want), "{want}: {problem}");
        assert!(entries.is_empty());
    }
}

fn value6(entries: &Entries6, src: &str, dst: &str, len: u32) -> EgressGw6Value {
    let src: Ipv6Addr = src.parse().unwrap();
    let dst: Ipv6Addr = dst.parse().unwrap();
    let mut data = [0u8; 32];
    data[..16].copy_from_slice(&src.octets());
    data[16..].copy_from_slice(&dst.octets());
    EgressGw6Value::from_bytes(*entries.get(&(128 + len, data)).unwrap())
}

/// #580: an IPv6 Pod and an IPv6 destination get an IPv6 entry with the same
/// gateway IPv4; the gateway's IPv6 InternalIP is its next hop; on the gateway
/// the entry carries the uplink's IPv6; mixed families match nothing; a
/// gateway with no IPv6 InternalIP has no next hop.
#[test]
fn ipv6_entries_and_next_hops() {
    let mut dual = pod("web", "n1", "10.1.1.5", &[("app", "web")]);
    dual.ips.push("fd00:1:1::5".parse().unwrap());
    let pods = vec![dual];
    let mut all = nodes();
    for node in &mut all {
        if node.name == "n2" {
            node.internal_ips.push("2001:db8:2::2".parse().unwrap());
            node.internal_ips.push("fe80::2".parse().unwrap());
        }
    }
    let object = json!({"metadata": {"name": "web-out"},
        "spec": {"selectors": [{"podSelector": {"matchLabels": {"app": "web"}}}],
                 "destinationCIDRs": ["203.0.113.0/24", "2001:db8:64::/48"],
                 "excludedCIDRs": ["2001:db8:64:1::/64"],
                 "egressGateway": {"nodeSelector": {"matchLabels": {"egress": "yes"}}}}});
    let ifs = interfaces();
    let gateway = Local {
        node: "n2",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let (maps, report) = plan(std::slice::from_ref(&object), &pods, &namespaces(), &all, &gateway);
    assert_eq!(
        maps.v4.len(),
        1,
        "the IPv4 source and IPv4 destination only"
    );
    assert_eq!(
        maps.v6.len(),
        2,
        "an IPv6 destination and an IPv6 exclusion"
    );
    let entry = value6(&maps.v6, "fd00:1:1::5", "2001:db8:64::", 48);
    assert_eq!(entry.gateway_ip, [192, 0, 2, 2]);
    assert_eq!(
        entry.egress_ip,
        "2001:db8:2::2".parse::<Ipv6Addr>().unwrap().octets()
    );
    assert_eq!(entry.egress_ifindex, 2);
    assert_eq!(
        value6(&maps.v6, "fd00:1:1::5", "2001:db8:64:1::", 64).gateway_ip,
        GATEWAY_EXCLUDED
    );
    assert_eq!(
        maps.nexthop6,
        Nexthops6::from([(
            [192, 0, 2, 2],
            "2001:db8:2::2".parse::<Ipv6Addr>().unwrap().octets()
        )]),
        "the global InternalIP, not the link-local one"
    );
    let json = report.json(true, maps.v4.len(), maps.v6.len());
    assert_eq!(json["entries6"], 2);
    assert_eq!(json["policies"][0]["gateways"][0]["ip6"], "2001:db8:2::2");
    assert_eq!(
        json["policies"][0]["this-node"][1]["egress-ip"],
        "2001:db8:2::2"
    );
    // Elsewhere: no egress address, the same gateway.
    let other = Local {
        node: "n1",
        interfaces: &ifs,
        primary: Some("eth0"),
    };
    let (maps, _) = plan(std::slice::from_ref(&object), &pods, &namespaces(), &all, &other);
    let entry = value6(&maps.v6, "fd00:1:1::5", "2001:db8:64::", 48);
    assert_eq!(
        (entry.gateway_ip, entry.egress_ip),
        ([192, 0, 2, 2], [0; 16])
    );
    // An egressIP that is IPv4: the IPv6 address of the interface holding it,
    // index 0; an IPv6 egressIP this node does not hold is an error.
    let mut by_ip = object.clone();
    by_ip["spec"]["egressGateway"]["egressIP"] = json!("198.51.100.7");
    let (maps, _) = plan(&[by_ip], &pods, &namespaces(), &all, &gateway);
    let entry = value6(&maps.v6, "fd00:1:1::5", "2001:db8:64::", 48);
    assert_eq!(
        (entry.egress_ip, entry.egress_ifindex),
        ("2001:db8:64::7".parse::<Ipv6Addr>().unwrap().octets(), 0)
    );
    let mut missing = object.clone();
    missing["spec"]["egressGateway"]["egressIP"] = json!("2001:db8:99::1");
    let (maps, report) = plan(&[missing], &pods, &namespaces(), &all, &gateway);
    assert_eq!(
        value6(&maps.v6, "fd00:1:1::5", "2001:db8:64::", 48).egress_ip,
        [0; 16]
    );
    assert!(
        report.local6[0]
            .1
            .as_ref()
            .unwrap_err()
            .contains("no interface holds")
    );
    // No IPv6 InternalIP on the gateway: no next hop.
    let (maps, _) = plan(&[object], &pods, &namespaces(), &nodes(), &other);
    assert!(maps.nexthop6.is_empty());
    assert_eq!(maps.v6.len(), 2);
}
