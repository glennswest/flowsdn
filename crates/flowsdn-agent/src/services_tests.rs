use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}
fn port(name: &str, protocol: &str, port: u16) -> ServicePort {
    ServicePort {
        name: name.into(),
        protocol: protocol.into(),
        port,
        node_port: None,
    }
}
fn slice_port(name: &str, protocol: &str, port: u16) -> SlicePort {
    SlicePort {
        name: name.into(),
        protocol: protocol.into(),
        port: Some(port),
    }
}
fn endpoint(address: &str, ready: bool, serving: bool, terminating: bool) -> Endpoint {
    Endpoint {
        addresses: vec![ip(address)],
        ready,
        serving,
        terminating,
        node_name: String::new(),
        zone_hints: Vec::new(),
        node_hints: Vec::new(),
    }
}
fn kube_dns() -> ServiceInfo {
    ServiceInfo {
        namespace: "kube-system".into(),
        name: "kube-dns".into(),
        service_type: "ClusterIP".into(),
        cluster_ips: vec![ip("10.96.0.10")],
        ports: vec![
            port("dns", "UDP", 53),
            port("dns-tcp", "TCP", 53),
            port("metrics", "TCP", 9153),
        ],
        ..ServiceInfo::default()
    }
}
fn dns_slice(endpoints: Vec<Endpoint>) -> SliceInfo {
    SliceInfo {
        namespace: "kube-system".into(),
        name: "kube-dns-x".into(),
        service: "kube-dns".into(),
        address_type: "IPv4".into(),
        endpoints,
        ports: vec![
            slice_port("dns", "UDP", 53),
            slice_port("dns-tcp", "TCP", 53),
            slice_port("metrics", "TCP", 9153),
        ],
    }
}
fn backends(frontends: &[Frontend], port: u16, proto: u8) -> Vec<String> {
    frontends
        .iter()
        .find(|f| f.service.frontend.port == port && f.service.frontend.proto == proto)
        .expect("frontend")
        .service
        .backends
        .iter()
        .map(|b| format!("{}:{}", b.ip, b.port))
        .collect()
}

#[test]
fn dsr_applies_to_node_local_frontends_of_the_port_protocol() {
    let service = ServiceInfo {
        namespace: "default".into(),
        name: "web".into(),
        service_type: "NodePort".into(),
        cluster_ips: vec![ip("10.96.5.6")],
        ports: vec![
            ServicePort {
                node_port: Some(30080),
                ..port("http", "TCP", 80)
            },
            ServicePort {
                node_port: Some(30053),
                ..port("dns", "UDP", 53)
            },
        ],
        dsr_tcp: true,
        ..ServiceInfo::default()
    };
    let nodes = [NodeAddresses {
        name: "n1".into(),
        ips: vec![ip("192.0.2.1")],
        zone: String::new(),
    }];
    let out = frontends(&[service], &[], "n1", &nodes);
    assert!(!out.is_empty());
    for f in &out {
        let tcp = f.service.frontend.proto == PROTO_TCP;
        assert_eq!(f.service.dsr, tcp && f.service.scope == SCOPE_NODE_LOCAL);
    }
}

#[test]
fn nat46x64_translates_a_node_local_frontend_with_no_backend_of_its_family() {
    let service = ServiceInfo {
        namespace: "default".into(),
        name: "web".into(),
        service_type: "NodePort".into(),
        cluster_ips: vec![ip("fd00:96::5")],
        ports: vec![ServicePort {
            node_port: Some(30080),
            ..port("http", "TCP", 80)
        }],
        dsr_tcp: true,
        nat46x64: true,
        ..ServiceInfo::default()
    };
    let endpoint = |address: &str, node: &str| Endpoint {
        addresses: vec![ip(address)],
        ready: true,
        serving: true,
        terminating: false,
        node_name: node.into(),
        zone_hints: Vec::new(),
        node_hints: Vec::new(),
    };
    let slices = [SliceInfo {
        namespace: "default".into(),
        name: "web-v6".into(),
        service: "web".into(),
        address_type: "IPv6".into(),
        endpoints: vec![endpoint("fd00:1::5", "n1"), endpoint("fd00:2::5", "n2")],
        ports: vec![SlicePort {
            name: "http".into(),
            protocol: "TCP".into(),
            port: Some(8080),
        }],
    }];
    let nodes = [NodeAddresses {
        name: "n1".into(),
        ips: vec![ip("192.0.2.1"), ip("2001:db8::1")],
        zone: String::new(),
    }];
    let find = |out: &[Frontend], at: &str, scope: u8| {
        out.iter()
            .find(|f| f.service.frontend.ip == ip(at) && f.service.scope == scope)
            .expect("frontend")
            .service
            .clone()
    };
    let out = frontends(std::slice::from_ref(&service), &slices, "n1", &nodes);
    // IPv4 on the uplink: the IPv6 backends, this node's too (#450), never
    // DSR.
    let v4 = find(&out, "192.0.2.1", SCOPE_NODE_LOCAL);
    assert!(v4.nat46x64 && !v4.dsr);
    assert_eq!(
        v4.backends.iter().map(|b| b.ip).collect::<Vec<_>>(),
        [ip("fd00:1::5"), ip("fd00:2::5")]
    );
    // Its own family has backends, or it is not the uplink's: not translated.
    let v6 = find(&out, "2001:db8::1", SCOPE_NODE_LOCAL);
    assert!(!v6.nat46x64 && v6.dsr);
    assert_eq!(v6.backends.len(), 2);
    // The socket LB's copy is translated too (#542).
    let socket = find(&out, "192.0.2.1", SCOPE_CLUSTER);
    assert!(socket.nat46x64);
    assert_eq!(socket.backends.len(), 2);
    // The API says so.
    let list = service_list(&out, &BTreeMap::new());
    let rows = list.as_array().expect("rows");
    let policies: Vec<_> = rows
        .iter()
        .filter_map(|r| r.pointer("/spec/flags/nat-policy")?.as_str())
        .collect();
    // The uplink's frontend and the socket LB's (#542).
    assert!(
        !policies.is_empty() && policies.iter().all(|p| *p == "Nat46"),
        "{policies:?}"
    );

    // Only local backends: translated too (#450). The setting off, or a
    // Local policy: not translated.
    let local_only = [SliceInfo {
        endpoints: vec![endpoint("fd00:1::5", "n1")],
        ..slices[0].clone()
    }];
    let out = frontends(std::slice::from_ref(&service), &local_only, "n1", &nodes);
    let local = find(&out, "192.0.2.1", SCOPE_NODE_LOCAL);
    assert!(local.nat46x64);
    assert_eq!(
        local.backends.iter().map(|b| b.ip).collect::<Vec<_>>(),
        [ip("fd00:1::5")]
    );
    let off = ServiceInfo {
        nat46x64: false,
        ..service.clone()
    };
    let out = frontends(&[off], &slices, "n1", &nodes);
    assert!(!find(&out, "192.0.2.1", SCOPE_NODE_LOCAL).nat46x64);
    let etp_local = ServiceInfo {
        external_local: true,
        ..service
    };
    let out = frontends(&[etp_local], &slices, "n1", &nodes);
    assert!(!find(&out, "192.0.2.1", SCOPE_NODE_LOCAL).nat46x64);
}

#[test]
fn kube_dns_and_kubernetes_services() {
    let kubernetes = ServiceInfo {
        namespace: "default".into(),
        name: "kubernetes".into(),
        service_type: "ClusterIP".into(),
        cluster_ips: vec![ip("10.96.0.1")],
        ports: vec![port("https", "TCP", 443)],
        ..ServiceInfo::default()
    };
    let apiserver = SliceInfo {
        namespace: "default".into(),
        name: "kubernetes".into(),
        service: "kubernetes".into(),
        address_type: "IPv4".into(),
        endpoints: vec![endpoint("192.168.31.172", true, true, false)],
        ports: vec![slice_port("https", "TCP", 6443)],
    };
    let slices = vec![
        dns_slice(vec![
            endpoint("10.172.0.5", true, true, false),
            endpoint("10.172.0.6", false, false, false),
        ]),
        apiserver,
    ];
    let out = frontends(&[kube_dns(), kubernetes], &slices, "n1", &[]);
    assert_eq!(out.len(), 4);
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.5:53"]);
    assert_eq!(backends(&out, 53, PROTO_TCP), vec!["10.172.0.5:53"]);
    assert_eq!(backends(&out, 443, PROTO_TCP), vec!["192.168.31.172:6443"]);
    let list = service_list(&out, &BTreeMap::new());
    let first = list.get(0).expect("row");
    assert_eq!(first.pointer("/spec/id"), Some(&json!(0)));
    assert!(first.get("status").is_none());
    let ids = out
        .iter()
        .map(|f| ((f.service.frontend, f.service.scope), 7))
        .collect::<BTreeMap<_, _>>();
    let list = service_list(&out, &ids);
    let row = list
        .as_array()
        .expect("array")
        .iter()
        .find(|r| r.pointer("/spec/frontend-address/port") == Some(&json!(443)))
        .expect("kubernetes row");
    assert_eq!(
        row.pointer("/status/realized/backend-addresses/0/ip"),
        Some(&json!("192.168.31.172"))
    );
    assert_eq!(row.pointer("/spec/flags/name"), Some(&json!("kubernetes")));
}

#[test]
fn terminating_endpoints_serve_only_when_none_is_ready() {
    let terminating = endpoint("10.172.0.8", false, true, true);
    let out = frontends(
        &[kube_dns()],
        &[dns_slice(vec![terminating.clone()])],
        "n1",
        &[],
    );
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.8:53"]);
    let out = frontends(
        &[kube_dns()],
        &[dns_slice(vec![
            terminating,
            endpoint("10.172.0.9", true, true, false),
        ])],
        "n1",
        &[],
    );
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.9:53"]);
    // No slices: frontends exist without backends (connect fails).
    let out = frontends(&[kube_dns()], &[], "n1", &[]);
    assert!(backends(&out, 53, PROTO_UDP).is_empty());
}

#[test]
fn families_ports_and_protocols_must_match() {
    let mut service = kube_dns();
    service.cluster_ips.push(ip("fd00:10:96::a"));
    service.ports.push(port("sctp", "SCTP", 9));
    let mut v6 = dns_slice(vec![endpoint("fd00:172::5", true, true, false)]);
    v6.address_type = "IPv6".into();
    v6.name = "kube-dns-y".into();
    let mut renamed = dns_slice(vec![endpoint("10.172.0.20", true, true, false)]);
    renamed.ports = vec![slice_port("other", "UDP", 5353)];
    let mut foreign = dns_slice(vec![endpoint("10.172.0.30", true, true, false)]);
    foreign.namespace = "default".into();
    let out = frontends(
        &[service],
        &[
            dns_slice(vec![endpoint("10.172.0.5", true, true, false)]),
            v6,
            renamed,
            foreign,
        ],
        "n1",
        &[],
    );
    // 2 IPs x 3 TCP/UDP ports; SCTP is skipped.
    assert_eq!(out.len(), 6);
    let v6_dns = out
        .iter()
        .find(|f| {
            f.service.frontend.ip == ip("fd00:10:96::a") && f.service.frontend.proto == PROTO_UDP
        })
        .expect("v6 frontend");
    assert_eq!(v6_dns.service.backends.len(), 1);
    assert_eq!(
        v6_dns.service.backends.first().map(|b| b.ip),
        Some(ip("fd00:172::5"))
    );
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.5:53"]);
}

#[test]
fn node_ports_external_and_load_balancer_addresses_and_traffic_policies() {
    let web = ServiceInfo {
        namespace: "ns".into(),
        name: "web".into(),
        service_type: "LoadBalancer".into(),
        cluster_ips: vec![ip("10.96.5.5")],
        ports: vec![ServicePort {
            node_port: Some(30080),
            ..port("http", "TCP", 80)
        }],
        external_ips: vec![ip("192.0.2.10")],
        load_balancer_ips: vec![ip("198.51.100.7")],
        ..ServiceInfo::default()
    };
    let on = |address: &str, node: &str| Endpoint {
        node_name: node.into(),
        ..endpoint(address, true, true, false)
    };
    let slice = SliceInfo {
        namespace: "ns".into(),
        name: "web-x".into(),
        service: "web".into(),
        address_type: "IPv4".into(),
        endpoints: vec![on("10.1.0.5", "n1"), on("10.2.0.5", "n2")],
        ports: vec![slice_port("http", "TCP", 8080)],
    };
    let nodes = [
        NodeAddresses {
            name: "n1".into(),
            ips: vec![ip("192.168.0.1")],
            zone: String::new(),
        },
        NodeAddresses {
            name: "n2".into(),
            ips: vec![ip("192.168.0.2"), ip("fd00::2")],
            zone: String::new(),
        },
    ];
    let find = |out: &[Frontend], address: &str, port: u16| -> (&'static str, Vec<String>) {
        let f = out
            .iter()
            .find(|f| f.service.frontend.ip == ip(address) && f.service.frontend.port == port)
            .expect("frontend");
        let backends = f
            .service
            .backends
            .iter()
            .map(|b| format!("{}:{}", b.ip, b.port))
            .collect();
        (f.kind, backends)
    };
    let both = vec!["10.1.0.5:8080".to_owned(), "10.2.0.5:8080".to_owned()];
    let out = frontends(
        std::slice::from_ref(&web),
        std::slice::from_ref(&slice),
        "n1",
        &nodes,
    );
    // ClusterIP, external IP, LB IP, and a NodePort on each node address;
    // all but the cluster IP also get a node-local copy for the uplink.
    assert_eq!(out.len(), 11);
    let local = |address: &str, port: u16| {
        out.iter()
            .find(|f| {
                f.service.scope == SCOPE_NODE_LOCAL
                    && f.service.frontend.ip == ip(address)
                    && f.service.frontend.port == port
            })
            .map(|f| f.service.backends.iter().map(|b| b.ip).collect::<Vec<_>>())
    };
    // externalTrafficPolicy Cluster: the uplink copy has every backend
    // (other nodes' are reached through SNAT).
    let every = Some(vec![ip("10.1.0.5"), ip("10.2.0.5")]);
    assert_eq!(local("192.168.0.2", 30080), every);
    assert_eq!(local("198.51.100.7", 80), every);
    assert_eq!(local("192.0.2.10", 80), every);
    assert_eq!(
        local("10.96.5.5", 80),
        None,
        "cluster IPs have no uplink copy"
    );
    assert_eq!(find(&out, "10.96.5.5", 80), ("ClusterIP", both.clone()));
    assert_eq!(find(&out, "192.0.2.10", 80), ("ExternalIPs", both.clone()));
    assert_eq!(
        find(&out, "198.51.100.7", 80),
        ("LoadBalancer", both.clone())
    );
    assert_eq!(find(&out, "192.168.0.2", 30080), ("NodePort", both.clone()));
    // An IPv6 node address has no IPv4 backends.
    assert_eq!(find(&out, "fd00::2", 30080), ("NodePort", vec![]));
    // Traffic policies: Local cluster IP -> this node's; Local NodePort ->
    // the backends on the node whose address it is.
    let local = ServiceInfo {
        internal_local: true,
        external_local: true,
        ..web.clone()
    };
    let out = frontends(&[local], std::slice::from_ref(&slice), "n1", &nodes);
    // externalTrafficPolicy Local: the uplink copy has this node's only.
    for (address, port) in [
        ("192.168.0.2", 30080),
        ("198.51.100.7", 80),
        ("192.0.2.10", 80),
    ] {
        let uplink = out
            .iter()
            .find(|f| {
                f.service.scope == SCOPE_NODE_LOCAL
                    && f.service.frontend.ip == ip(address)
                    && f.service.frontend.port == port
            })
            .map(|f| f.service.backends.iter().map(|b| b.ip).collect::<Vec<_>>());
        assert_eq!(uplink, Some(vec![ip("10.1.0.5")]), "{address}:{port}");
    }
    assert_eq!(find(&out, "10.96.5.5", 80).1, vec!["10.1.0.5:8080"]);
    assert_eq!(find(&out, "192.168.0.2", 30080).1, vec!["10.2.0.5:8080"]);
    assert_eq!(find(&out, "192.0.2.10", 80).1, both);
    // A ClusterIP Service has no NodePort or LB frontends even with values set.
    let plain = ServiceInfo {
        service_type: "ClusterIP".into(),
        ..web
    };
    let out = frontends(&[plain], &[slice], "n1", &nodes);
    assert_eq!(
        out.len(),
        3,
        "cluster IP, external IP and its node-local copy"
    );
    let row = service_list(&out, &BTreeMap::new());
    assert_eq!(
        row.pointer("/1/spec/flags/type"),
        Some(&json!("ExternalIPs"))
    );
}

#[test]
fn client_ip_affinity_reaches_every_frontend_and_the_api() {
    let sticky = ServiceInfo {
        affinity: Some(600),
        ..kube_dns()
    };
    let out = frontends(&[sticky], &[], "n1", &[]);
    assert!(out.iter().all(|f| f.service.affinity == Some(600)));
    let rows = service_list(&out, &BTreeMap::new());
    assert_eq!(
        rows.pointer("/0/spec/flags/session-affinity-timeout"),
        Some(&json!(600))
    );
    let plain = frontends(&[kube_dns()], &[], "n1", &[]);
    assert!(plain.iter().all(|f| f.service.affinity.is_none()));
    assert_eq!(
        service_list(&plain, &BTreeMap::new()).pointer("/0/spec/flags/session-affinity-timeout"),
        None
    );
}

#[test]
fn maglev_applies_to_the_node_local_copies_only() {
    let web = ServiceInfo {
        namespace: "ns".into(),
        name: "web".into(),
        service_type: "NodePort".into(),
        cluster_ips: vec![ip("10.96.5.5")],
        ports: vec![ServicePort {
            node_port: Some(30080),
            ..port("http", "TCP", 80)
        }],
        maglev: true,
        ..ServiceInfo::default()
    };
    let nodes = [NodeAddresses {
        name: "n1".into(),
        ips: vec![ip("192.168.0.1")],
        zone: String::new(),
    }];
    let out = frontends(std::slice::from_ref(&web), &[], "n1", &nodes);
    assert_eq!(out.len(), 3, "cluster IP, NodePort and its node-local copy");
    for f in &out {
        assert_eq!(f.service.maglev, f.service.scope == SCOPE_NODE_LOCAL);
    }
    let rows = service_list(&out, &BTreeMap::new());
    let algorithms: Vec<_> = rows
        .as_array()
        .expect("rows")
        .iter()
        .map(|r| r.pointer("/spec/flags/lb-algorithm").cloned())
        .collect();
    assert_eq!(
        algorithms.iter().filter(|a| a.is_some()).count(),
        1,
        "{algorithms:?}"
    );
    let random = ServiceInfo {
        maglev: false,
        ..web
    };
    let out = frontends(&[random], &[], "n1", &nodes);
    assert!(out.iter().all(|f| !f.service.maglev));
}

#[test]
fn termination_passes_are_at_most_every_50_ms() {
    use std::time::{Duration, Instant};
    let ip: IpAddr = "10.2.0.9".parse().expect("IP");
    let start = Instant::now();
    let at = |ms| start.checked_add(Duration::from_millis(ms)).expect("time");
    let mut batch = TerminationBatch::default();
    assert_eq!(batch.wait(start), None);
    assert_eq!(batch.take(start), None, "nothing pending");
    batch.add([(PROTO_UDP, ip, 53)]);
    assert_eq!(
        batch.wait(start),
        Some(Duration::ZERO),
        "the first is due at once"
    );
    assert_eq!(batch.take(start).map(|g| g.len()), Some(1));
    // Two more within 50 ms: held, then ended in one pass.
    batch.add([(PROTO_UDP, ip, 54)]);
    assert_eq!(batch.take(at(10)), None);
    batch.add([(PROTO_TCP, ip, 80)]);
    assert_eq!(batch.wait(at(30)), Some(Duration::from_millis(20)));
    assert_eq!(batch.take(at(49)), None);
    let pass = batch.take(at(50)).expect("due");
    assert_eq!(pass.len(), 2);
    assert_eq!(batch.wait(at(50)), None);
}

#[test]
fn terminable_and_stale_backends() {
    let ip = |s: &str| -> IpAddr { s.parse().expect("IP") };
    let service = Service {
        frontend: Address {
            ip: ip("10.96.0.10"),
            port: 53,
            proto: PROTO_UDP,
        },
        backends: vec![
            Address {
                ip: ip("::ffff:10.2.0.9"),
                port: 53,
                proto: PROTO_UDP,
            },
            Address {
                ip: ip("10.2.0.9"),
                port: 53,
                proto: PROTO_TCP,
            },
        ],
        affinity: None,
        scope: SCOPE_CLUSTER,
        maglev: false,
        dsr: false,
        nat46x64: false,
        local_redirect: false,
        skip: Vec::new(),
    };
    let udp_only = terminable_backends(std::slice::from_ref(&service), false);
    assert_eq!(udp_only, [(PROTO_UDP, ip("10.2.0.9"), 53)].into());
    let all = terminable_backends(std::slice::from_ref(&service), true);
    assert_eq!(all.len(), 2);
    // At start: _reverse_sk remembers 10.2.0.9:53 (still a backend) and
    // 10.2.0.8:53 (gone while the agent was down).
    let reverse = vec![
        (1, ip("10.2.0.9"), 53),
        (2, ip("10.2.0.8"), 53),
        (3, ip("10.2.0.8"), 53),
    ];
    assert_eq!(
        stale_udp_backends(&reverse, &udp_only),
        [(PROTO_UDP, ip("10.2.0.8"), 53)].into()
    );
}

/// #465: with `lb-external-clusterip` a cluster IP gets a node-local copy
/// (the uplink path) under internalTrafficPolicy, with Maglev as the
/// Service asks; without it, none.
#[test]
fn external_clusterip_adds_node_local_cluster_ip_copies() {
    let on = |address: &str, node: &str| Endpoint {
        node_name: node.into(),
        ..endpoint(address, true, true, false)
    };
    let slice = SliceInfo {
        namespace: "default".into(),
        name: "web-x".into(),
        service: "web".into(),
        address_type: "IPv4".into(),
        endpoints: vec![on("10.9.0.5", "n1"), on("10.9.1.5", "n2")],
        ports: vec![slice_port("http", "TCP", 8080)],
    };
    let web = ServiceInfo {
        namespace: "default".into(),
        name: "web".into(),
        service_type: "NodePort".into(),
        cluster_ips: vec![ip("10.96.5.7")],
        ports: vec![ServicePort {
            node_port: Some(30080),
            ..port("http", "TCP", 80)
        }],
        maglev: true,
        // externalTrafficPolicy: Local applies to the NodePort, not the
        // cluster IP.
        external_local: true,
        ..ServiceInfo::default()
    };
    let nodes = [NodeAddresses {
        name: "n1".into(),
        ips: vec![ip("192.0.2.1")],
        zone: String::new(),
    }];
    let copy = |out: &[Frontend], kind: &str| -> Option<(Vec<String>, bool)> {
        out.iter()
            .find(|f| f.kind == kind && f.service.scope == SCOPE_NODE_LOCAL)
            .map(|f| {
                (
                    f.service
                        .backends
                        .iter()
                        .map(|b| format!("{}:{}", b.ip, b.port))
                        .collect(),
                    f.service.maglev,
                )
            })
    };
    let slices = [slice];
    let off = frontends(std::slice::from_ref(&web), &slices, "n1", &nodes);
    assert_eq!(copy(&off, "ClusterIP"), None, "off by default");
    assert!(copy(&off, "NodePort").is_some());

    let external = ServiceInfo {
        external_clusterip: true,
        ..web.clone()
    };
    let out = frontends(std::slice::from_ref(&external), &slices, "n1", &nodes);
    assert_eq!(
        copy(&out, "ClusterIP"),
        Some((vec!["10.9.0.5:8080".into(), "10.9.1.5:8080".into()], true)),
        "every backend (internalTrafficPolicy Cluster), Maglev"
    );
    assert_eq!(
        copy(&out, "NodePort"),
        Some((vec!["10.9.0.5:8080".into()], true)),
        "the NodePort keeps externalTrafficPolicy Local"
    );
    let cluster = out
        .iter()
        .find(|f| f.kind == "ClusterIP" && f.service.scope == SCOPE_CLUSTER)
        .expect("cluster-scope copy");
    assert!(
        !cluster.service.maglev,
        "the socket LB copy never uses Maglev"
    );

    let internal = ServiceInfo {
        internal_local: true,
        maglev: false,
        ..external
    };
    let out = frontends(&[internal], &slices, "n1", &nodes);
    assert_eq!(
        copy(&out, "ClusterIP"),
        Some((vec!["10.9.0.5:8080".into()], false)),
        "internalTrafficPolicy Local: this node's backends"
    );
}

/// #459: topology-aware routing as kube-proxy does it. With traffic policy
/// Cluster, ready endpoints are chosen by node hints when all have them and
/// one names this node, else by zone hints the same way, else all; Local
/// policies and the serving-terminating fallback ignore hints.
#[test]
fn topology_hints_choose_ready_backends_for_cluster_policy() {
    let hinted = |address: &str, zones: &[&str], nodes: &[&str]| Endpoint {
        zone_hints: zones.iter().map(|z| (*z).to_owned()).collect(),
        node_hints: nodes.iter().map(|n| (*n).to_owned()).collect(),
        node_name: "elsewhere".into(),
        ..endpoint(address, true, true, false)
    };
    let service = ServiceInfo {
        namespace: "ns".into(),
        name: "web".into(),
        service_type: "ClusterIP".into(),
        cluster_ips: vec![ip("10.96.0.20")],
        ports: vec![port("http", "TCP", 80)],
        ..ServiceInfo::default()
    };
    let slice = |endpoints: Vec<Endpoint>| SliceInfo {
        namespace: "ns".into(),
        name: "web-x".into(),
        service: "web".into(),
        address_type: "IPv4".into(),
        endpoints,
        ports: vec![slice_port("http", "TCP", 8080)],
    };
    let nodes = |zone: &str| {
        [NodeAddresses {
            name: "n1".into(),
            ips: vec![ip("192.0.2.1")],
            zone: zone.into(),
        }]
    };
    let run = |service: &ServiceInfo, endpoints: Vec<Endpoint>, zone: &str| {
        let out = frontends(
            std::slice::from_ref(service),
            &[slice(endpoints)],
            "n1",
            &nodes(zone),
        );
        backends(&out, 80, PROTO_TCP)
    };
    let zoned = || {
        vec![
            hinted("10.1.0.1", &["z1"], &[]),
            hinted("10.1.0.2", &["z2"], &[]),
            hinted("10.1.0.3", &["z1"], &[]),
        ]
    };
    // Zone hints, this node in z1: the z1 endpoints.
    assert_eq!(
        run(&service, zoned(), "z1"),
        ["10.1.0.1:8080", "10.1.0.3:8080"]
    );
    // No endpoint for this zone, or the node has no zone: all of them.
    assert_eq!(run(&service, zoned(), "z9").len(), 3);
    assert_eq!(run(&service, zoned(), "").len(), 3);
    // One ready endpoint without hints: hints are not used.
    let mut partial = zoned();
    partial.push(hinted("10.1.0.4", &[], &[]));
    assert_eq!(run(&service, partial, "z1").len(), 4);
    // A not-ready endpoint without hints does not count.
    let mut with_unready = zoned();
    with_unready.push(endpoint("10.1.0.5", false, false, false));
    assert_eq!(run(&service, with_unready, "z1").len(), 2);
    // Node hints (PreferSameNode) win over zone hints.
    let by_node = vec![
        hinted("10.1.0.1", &["z1"], &["n1"]),
        hinted("10.1.0.3", &["z1"], &["n2"]),
    ];
    assert_eq!(run(&service, by_node, "z1"), ["10.1.0.1:8080"]);
    // Node hints naming other nodes only: zone hints decide.
    let other_nodes = vec![
        hinted("10.1.0.1", &["z1"], &["n2"]),
        hinted("10.1.0.2", &["z2"], &["n3"]),
    ];
    assert_eq!(run(&service, other_nodes, "z1"), ["10.1.0.1:8080"]);
    // internalTrafficPolicy: Local ignores hints (this node's endpoints).
    let local = ServiceInfo {
        internal_local: true,
        ..service.clone()
    };
    let mut on_n1 = zoned();
    if let Some(e) = on_n1.get_mut(1) {
        e.node_name = "n1".into();
    }
    assert_eq!(run(&local, on_n1, "z1"), ["10.1.0.2:8080"]);
    // No ready endpoint: the serving-terminating fallback, hints ignored.
    let terminating = vec![
        Endpoint {
            zone_hints: vec!["z2".into()],
            ..endpoint("10.1.0.6", false, true, true)
        },
        endpoint("10.1.0.7", false, true, true),
    ];
    assert_eq!(run(&service, terminating, "z1").len(), 2);
}
