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
        },
        NodeAddresses {
            name: "n2".into(),
            ips: vec![ip("192.168.0.2"), ip("fd00::2")],
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
    for (address, port) in [("192.168.0.2", 30080), ("198.51.100.7", 80), ("192.0.2.10", 80)] {
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
