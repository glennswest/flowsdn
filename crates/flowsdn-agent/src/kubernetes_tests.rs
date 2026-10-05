use super::*;

fn env(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
    pairs
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect()
}
fn ip(text: &str) -> IpAddr {
    text.parse().expect("IP")
}
fn node(name: &str, cidrs: &[(&str, u8)], ips: &[&str]) -> NodeInfo {
    NodeInfo {
        name: name.into(),
        pod_cidrs: cidrs.iter().map(|(a, p)| (ip(a), *p)).collect(),
        internal_ips: ips.iter().map(|a| ip(a)).collect(),
    }
}

#[test]
fn settings_default_and_take_the_node_name_from_the_environment() {
    assert_eq!(Settings::parse(None, &env(&[])).expect("absent"), None);
    assert_eq!(
        Settings::parse(Some(&Value::Null), &env(&[])).expect("null"),
        None
    );
    let parsed = Settings::parse(
        Some(&json!({})),
        &env(&[("NODE_NAME", "b"), ("K8S_NODE_NAME", "a")]),
    )
    .expect("env")
    .expect("enabled");
    assert_eq!(parsed.node_name, "a");
    assert_eq!(parsed.kubeconfig, None);
    assert!(parsed.auto_direct_node_routes);
    let parsed = Settings::parse(
        Some(
            &json!({"node-name":"n1","kubeconfig":"/k","auto-direct-node-routes":false,
            "direct-routing-skip-unreachable":true}),
        ),
        &env(&[("K8S_NODE_NAME", "a")]),
    )
    .expect("explicit")
    .expect("enabled");
    assert_eq!(parsed.node_name, "n1");
    assert_eq!(parsed.kubeconfig, Some(PathBuf::from("/k")));
    assert!(!parsed.auto_direct_node_routes && parsed.skip_unreachable);
    assert!(Settings::parse(Some(&json!({})), &env(&[])).is_err());
    assert!(Settings::parse(Some(&json!({"node-name":"bad name"})), &env(&[])).is_err());
}

#[test]
fn alloc_cidr_prefers_pod_cidrs_then_derives_the_reference_default() {
    let explicit = node("a", &[("fd02::", 64), ("10.2.0.0", 24)], &["192.0.2.2"]);
    assert_eq!(alloc_cidr(&explicit, false), Some((ip("10.2.0.0"), 24)));
    assert_eq!(alloc_cidr(&explicit, true), Some((ip("fd02::"), 64)));
    let derived = node("b", &[], &["2001:db8::9", "192.168.31.172"]);
    assert_eq!(alloc_cidr(&derived, false), Some((ip("10.172.0.0"), 16)));
    // f00d:: + the IPv4 alloc CIDR's bytes 0a.ac.00.00 (f00d:0:0:0:aac::), /96.
    assert_eq!(
        alloc_cidr(&derived, true),
        Some((ip("f00d::aac:0:0:0"), 96))
    );
    let v6_only = node("c", &[], &["2001:db8::1:2"]);
    assert_eq!(alloc_cidr(&v6_only, false), None);
    assert_eq!(alloc_cidr(&v6_only, true), Some((ip("f00d::1:2:0:0"), 96)));
    assert_eq!(alloc_cidr(&node("d", &[], &[]), true), None);
}

#[test]
fn router_ip_is_the_first_host_address() {
    assert_eq!(
        router_ip((ip("10.172.0.0"), 16)).expect("v4"),
        ip("10.172.0.1")
    );
    assert_eq!(
        router_ip((ip("10.172.3.7"), 24)).expect("v4"),
        ip("10.172.3.1")
    );
    assert_eq!(
        router_ip((ip("f00d::aac:0:0:0"), 96)).expect("v6"),
        ip("f00d::aac:0:0:1")
    );
    assert!(router_ip((ip("10.0.0.0"), 31)).is_err());
    assert!(router_ip((ip("fd00::"), 127)).is_err());
}

#[test]
fn desired_routes_cover_other_nodes_by_family() {
    let nodes = [
        node("local", &[("10.172.0.0", 16)], &["192.168.31.172"]),
        node(
            "peer",
            &[("10.173.0.0", 16), ("f00d::aad:0:0:0", 96)],
            &["192.168.31.173", "2001:db8::173"],
        ),
        node(
            "v4-only",
            &[("10.174.0.0", 16), ("fd09::", 64)],
            &["192.168.31.174"],
        ),
    ];
    let routes = desired_routes("local", &nodes);
    let text: Vec<_> = routes
        .iter()
        .map(|r| {
            format!(
                "{} via {} ({})",
                cidr_text(r.destination, r.prefix),
                r.gateway,
                r.node
            )
        })
        .collect();
    assert_eq!(
        text,
        [
            "10.173.0.0/16 via 192.168.31.173 (peer)",
            "10.174.0.0/16 via 192.168.31.174 (v4-only)",
            "f00d::aad:0:0:0/96 via 2001:db8::173 (peer)",
        ]
    );
}

#[test]
fn ip_list_has_node_identities_pod_labels_and_host_ips() {
    let mut view = View {
        local_node: "local".into(),
        nodes: vec![
            node("local", &[], &["192.168.31.172"]),
            node("peer", &[], &["192.168.31.173"]),
        ],
        ..View::default()
    };
    view.pods = vec![
        PodInfo {
            namespace: "ns".into(),
            name: "web".into(),
            node: "peer".into(),
            host_network: false,
            ips: vec![ip("10.173.0.5"), ip("f00d::5")],
            labels: [("app".to_owned(), "web".to_owned())].into_iter().collect(),
        },
        PodInfo {
            namespace: "kube-system".into(),
            name: "flowsdn".into(),
            node: "local".into(),
            host_network: true,
            ips: vec![ip("192.168.31.172")],
            labels: BTreeMap::new(),
        },
    ];
    let list = view.ip_list();
    let rows = list.as_array().expect("array");
    assert_eq!(rows.len(), 4);
    let find = |cidr: &str| {
        rows.iter()
            .find(|r| r.get("cidr") == Some(&json!(cidr)))
            .expect("row")
            .clone()
    };
    assert_eq!(
        find("192.168.31.172/32").get("identity"),
        Some(&json!(IDENTITY_HOST))
    );
    assert_eq!(
        find("192.168.31.173/32").get("identity"),
        Some(&json!(IDENTITY_REMOTE_NODE))
    );
    let pod = find("10.173.0.5/32");
    assert_eq!(pod.get("identity"), None);
    assert_eq!(pod.get("hostIP"), Some(&json!("192.168.31.173")));
    assert_eq!(
        pod.get("labels"),
        Some(&json!([
            "k8s:app=web",
            "k8s:io.kubernetes.pod.namespace=ns"
        ]))
    );
    assert_eq!(find("f00d::5/128").get("hostIP"), None);
    assert_eq!(view.health().get("state"), Some(&json!("Warning")));
    view.nodes_synced = true;
    view.pods_synced = true;
    assert_eq!(view.health().get("state"), Some(&json!("Ok")));
    view.errors.insert("routes".into(), "boom".into());
    assert_eq!(view.health().get("msg"), Some(&json!("routes: boom")));
}
