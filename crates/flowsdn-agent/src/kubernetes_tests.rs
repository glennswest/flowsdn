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
    assert!(parsed.service_lb);
    assert!(parsed.node_port);
    assert_eq!(parsed.cgroup_root, PathBuf::from(DEFAULT_CGROUP_ROOT));
    let parsed = Settings::parse(
        Some(
            &json!({"node-name":"n1","kubeconfig":"/k","auto-direct-node-routes":false,
            "direct-routing-skip-unreachable":true,"service-lb":false,"node-port":false,
            "cgroup-root":"/run/flowsdn/cgroupv2"}),
        ),
        &env(&[("K8S_NODE_NAME", "a")]),
    )
    .expect("explicit")
    .expect("enabled");
    assert_eq!(parsed.node_name, "n1");
    assert_eq!(parsed.kubeconfig, Some(PathBuf::from("/k")));
    assert!(!parsed.auto_direct_node_routes && parsed.skip_unreachable);
    assert!(!parsed.service_lb);
    assert!(!parsed.node_port);
    assert_eq!(parsed.cgroup_root, PathBuf::from("/run/flowsdn/cgroupv2"));
    assert!(
        Settings::parse(
            Some(&json!({"node-name":"n1","cgroup-root":"relative"})),
            &env(&[])
        )
        .is_err()
    );
    assert!(Settings::parse(Some(&json!({})), &env(&[])).is_err());
    assert!(Settings::parse(Some(&json!({"node-name":"bad name"})), &env(&[])).is_err());
}

#[test]
fn identity_settings_default_on_with_the_default_cluster() {
    let parsed = Settings::parse(Some(&json!({"node-name":"n1"})), &env(&[]))
        .expect("defaults")
        .expect("enabled");
    assert!(parsed.identity_allocation);
    assert_eq!(parsed.cluster_name, "default");
    let parsed = Settings::parse(
        Some(&json!({"node-name":"n1","identity-allocation":false,"cluster-name":"lab-2"})),
        &env(&[]),
    )
    .expect("explicit")
    .expect("enabled");
    assert!(!parsed.identity_allocation);
    assert_eq!(parsed.cluster_name, "lab-2");
    for bad in [
        "-a",
        "a-",
        "Upper",
        "a.b",
        "abcdefghijabcdefghijabcdefghijabc",
    ] {
        assert!(
            Settings::parse(
                Some(&json!({"node-name":"n1","cluster-name":bad})),
                &env(&[])
            )
            .is_err(),
            "{bad}"
        );
    }
}

#[test]
fn pod_identities_reach_the_ip_list_and_identity_list() {
    let filter = flowsdn_identity::filter::LabelFilter::identity(&[]).expect("filter");
    let mut view = View {
        local_node: "local".into(),
        identity: true,
        cluster_name: "default".into(),
        pods: vec![
            PodInfo {
                namespace: "ns".into(),
                name: "web".into(),
                node: "local".into(),
                ips: vec![ip("10.172.0.5")],
                labels: [("app".to_owned(), "web".to_owned())].into_iter().collect(),
                service_account: "default".into(),
                ..PodInfo::default()
            },
            PodInfo {
                namespace: "ns".into(),
                name: "db".into(),
                node: "peer".into(),
                ips: vec![ip("10.173.0.9")],
                ..PodInfo::default()
            },
            PodInfo {
                namespace: "kube-system".into(),
                name: "flowsdn".into(),
                node: "local".into(),
                host_network: true,
                ..PodInfo::default()
            },
        ],
        ..View::default()
    };
    view.pods_synced = true;
    assert!(
        view.pod_label_sets(&filter).is_empty(),
        "namespaces not listed"
    );
    view.namespaces_synced = true;
    view.namespaces.insert(
        "ns".into(),
        [("team".to_owned(), "a".to_owned())].into_iter().collect(),
    );
    let sets = view.pod_label_sets(&filter);
    assert_eq!(sets.len(), 2, "host-network Pods have no identity");
    let (key, local, labels) = sets.first().expect("web");
    assert_eq!(key, &("ns".to_owned(), "web".to_owned()));
    assert!(*local);
    assert_eq!(
        crate::identity::label_strings(labels),
        [
            "k8s:app=web",
            "k8s:io.flowsdn.k8s.namespace.labels.team=a",
            "k8s:io.flowsdn.k8s.policy.cluster=default",
            "k8s:io.flowsdn.k8s.policy.serviceaccount=default",
            "k8s:io.kubernetes.pod.namespace=ns",
        ]
    );
    assert!(!sets.get(1).expect("db").1);

    view.pod_identities.insert(("ns".into(), "web".into()), 300);
    view.identities
        .insert(300, crate::identity::label_strings(labels));
    let list = view.ip_list();
    let row = list
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r.get("cidr") == Some(&json!("10.172.0.5/32")))
        })
        .expect("web row");
    assert_eq!(row.get("identity"), Some(&json!(300)));
    let identities = view.identity_list();
    assert_eq!(identities.pointer("/0/id"), Some(&json!(300)));
    assert_eq!(
        identities.pointer("/0/labels/0"),
        Some(&json!("k8s:app=web"))
    );
    view.nodes_synced = true;
    assert_eq!(view.health().get("state"), Some(&json!("Warning")));
    view.identities_synced = true;
    assert_eq!(view.health().get("state"), Some(&json!("Ok")));
    assert_eq!(
        view.health().get("msg"),
        Some(&json!(
            "0 nodes, 3 pods, 0 service frontends (0 programmed), 1 identities (0 local label sets waiting)"
        ))
    );
    assert_eq!(view.health().get("identity-allocation"), Some(&json!(true)));
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
    let plan = desired_routes("local", &nodes, Derive::default());
    assert!(plan.collisions.is_empty());
    let text: Vec<_> = plan
        .routes
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

fn route_text(plan: &RoutePlan) -> Vec<String> {
    plan.routes
        .iter()
        .map(|r| format!("{} via {}", cidr_text(r.destination, r.prefix), r.gateway))
        .collect()
}

#[test]
fn nodes_without_pod_cidrs_get_derived_routes_for_auto_families() {
    // pvetest1 + pvetest2 (#296, option C): stormcos sets no podCIDRs.
    let nodes = [
        node("pvetest1", &[], &["192.168.31.172"]),
        node("pvetest2", &[], &["192.168.31.173", "2001:db8::173"]),
        node("explicit", &[("10.9.0.0", 24)], &["192.168.31.9"]),
    ];
    assert!(
        desired_routes("pvetest1", &nodes, Derive::default())
            .routes
            .iter()
            .all(|r| r.node == "explicit"),
        "nothing is derived unless the local pool is auto"
    );
    let plan = desired_routes("pvetest1", &nodes, Derive { v4: true, v6: true });
    assert!(plan.collisions.is_empty(), "{:?}", plan.collisions);
    assert_eq!(
        route_text(&plan),
        [
            "10.9.0.0/24 via 192.168.31.9",
            "10.173.0.0/16 via 192.168.31.173",
            "f00d::aad:0:0:0/96 via 2001:db8::173",
        ]
    );
    // The other side sees pvetest1's derived pool.
    let back = desired_routes(
        "pvetest2",
        &nodes,
        Derive {
            v4: true,
            v6: false,
        },
    );
    assert!(route_text(&back).contains(&"10.172.0.0/16 via 192.168.31.172".to_owned()));
}

#[test]
fn colliding_pod_cidrs_get_no_route_and_are_reported() {
    // Same last IPv4 byte on two subnets: both derive 10.5.0.0/16.
    let nodes = [
        node("local", &[], &["192.168.31.4"]),
        node("a", &[], &["192.168.31.5"]),
        node("b", &[], &["192.168.40.5"]),
        node("c", &[("10.5.3.0", 24)], &["192.168.31.6"]),
        node("d", &[], &["192.168.31.7"]),
    ];
    let plan = desired_routes(
        "local",
        &nodes,
        Derive {
            v4: true,
            v6: false,
        },
    );
    assert_eq!(route_text(&plan), ["10.7.0.0/16 via 192.168.31.7"]);
    assert_eq!(plan.collisions.len(), 3, "{:?}", plan.collisions);
    assert!(
        plan.collisions
            .iter()
            .any(|c| c == "nodes a (10.5.0.0/16) and b (10.5.0.0/16) have overlapping pod CIDRs")
    );
    // A remote node that collides with this one gets no route either.
    let mine = [
        node("local", &[], &["192.168.31.5"]),
        node("twin", &[], &["192.168.40.5"]),
    ];
    let plan = desired_routes(
        "local",
        &mine,
        Derive {
            v4: true,
            v6: false,
        },
    );
    assert!(plan.routes.is_empty());
    assert_eq!(plan.collisions.len(), 1);
}

#[test]
fn overlap_compares_under_the_shorter_prefix() {
    assert!(overlaps((ip("10.5.0.0"), 16), (ip("10.5.3.0"), 24)));
    assert!(!overlaps((ip("10.5.0.0"), 16), (ip("10.6.0.0"), 16)));
    assert!(overlaps(
        (ip("f00d::aac:0:0:0"), 96),
        (ip("f00d::aac:0:0:0"), 96)
    ));
    assert!(!overlaps((ip("10.5.0.0"), 16), (ip("f00d::"), 96)));
    assert!(overlaps((ip("10.0.0.0"), 0), (ip("192.0.2.0"), 24)));
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
            uid: "uid-web".into(),
            workload: Some(Workload {
                kind: "StatefulSet".into(),
                name: "web".into(),
            }),
            containers: vec![Container {
                name: "app".into(),
                id: "containerd://abc".into(),
                init: false,
            }],
            ..PodInfo::default()
        },
        PodInfo {
            namespace: "kube-system".into(),
            name: "flowsdn".into(),
            node: "local".into(),
            host_network: true,
            ips: vec![ip("192.168.31.172")],
            ..PodInfo::default()
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
    assert_eq!(
        pod.get("metadata"),
        Some(
            &json!({"source":"kube-apiserver","namespace":"ns","name":"web","uid":"uid-web",
            "containers":[{"name":"app","container-id":"containerd://abc","init":false}],
            "workloads":[{"name":"web","kind":"StatefulSet"}]})
        )
    );
    assert_eq!(find("f00d::5/128").get("hostIP"), None);
    assert_eq!(view.health().get("state"), Some(&json!("Warning")));
    view.nodes_synced = true;
    view.pods_synced = true;
    assert_eq!(view.health().get("state"), Some(&json!("Ok")));
    view.service_lb = true;
    assert_eq!(view.health().get("state"), Some(&json!("Warning")));
    assert!(
        view.refresh_frontends().is_none(),
        "no frontends before both lists"
    );
    view.services_synced = true;
    view.slices_synced = true;
    assert_eq!(view.refresh_frontends(), Some(vec![]));
    assert_eq!(view.health().get("state"), Some(&json!("Ok")));
    view.errors.insert("routes".into(), "boom".into());
    assert_eq!(view.health().get("msg"), Some(&json!("routes: boom")));
}
