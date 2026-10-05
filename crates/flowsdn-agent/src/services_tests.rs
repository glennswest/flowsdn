use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}
fn port(name: &str, protocol: &str, port: u16) -> ServicePort {
    ServicePort {
        name: name.into(),
        protocol: protocol.into(),
        port,
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
    let out = frontends(&[kube_dns(), kubernetes], &slices);
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
        .map(|f| (f.service.frontend, 7))
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
    let out = frontends(&[kube_dns()], &[dns_slice(vec![terminating.clone()])]);
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.8:53"]);
    let out = frontends(
        &[kube_dns()],
        &[dns_slice(vec![
            terminating,
            endpoint("10.172.0.9", true, true, false),
        ])],
    );
    assert_eq!(backends(&out, 53, PROTO_UDP), vec!["10.172.0.9:53"]);
    // No slices: frontends exist without backends (connect fails).
    let out = frontends(&[kube_dns()], &[]);
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
