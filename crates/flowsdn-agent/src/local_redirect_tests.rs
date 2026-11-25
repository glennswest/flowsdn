#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use super::*;

fn addr(text: &str) -> Address {
    let (ip, rest) = text.rsplit_once(':').unwrap();
    let (port, proto) = rest.split_once('/').unwrap();
    Address {
        ip: ip.parse().unwrap(),
        port: port.parse().unwrap(),
        proto: if proto == "UDP" { PROTO_UDP } else { PROTO_TCP },
    }
}
/// kube-system/kube-dns ClusterIP 10.96.0.10 on 53/UDP (dns) and 53/TCP
/// (dns-tcp), with two cluster backends.
fn dns() -> Vec<Frontend> {
    ["10.96.0.10:53/UDP", "10.96.0.10:53/TCP"]
        .iter()
        .map(|front| {
            let frontend = addr(front);
            let suffix = if frontend.proto == PROTO_UDP { "UDP" } else { "TCP" };
            Frontend {
                namespace: "kube-system".into(),
                name: "kube-dns".into(),
                port_name: if frontend.proto == PROTO_UDP { "dns" } else { "dns-tcp" }.into(),
                service_type: "ClusterIP".into(),
                kind: "ClusterIP",
                service: Service {
                    frontend,
                    backends: vec![
                        addr(&format!("10.1.1.5:53/{suffix}")),
                        addr(&format!("10.1.2.5:53/{suffix}")),
                    ],
                    affinity: None,
                    scope: SCOPE_CLUSTER,
                    maglev: false,
                    dsr: false,
                    nat46x64: false,
                    local_redirect: false,
                    skip: Vec::new(),
                },
            }
        })
        .collect()
}
/// The node-local DNS Pod on `node`.
fn cache(node: &str, ready: bool) -> PodInfo {
    PodInfo {
        namespace: "kube-system".into(),
        name: "node-local-dns-x".into(),
        node: node.into(),
        ips: vec!["10.1.9.9".parse().unwrap()],
        labels: [("k8s-app".to_owned(), "node-local-dns".to_owned())].into_iter().collect(),
        ports: vec![(17, "dns".into(), 53), (6, "dns-tcp".into(), 53)],
        ready,
        ..PodInfo::default()
    }
}
fn endpoint() -> LocalEndpoint {
    LocalEndpoint {
        namespace: "kube-system".into(),
        name: "node-local-dns-x".into(),
        netns_cookie: 4242,
        ..LocalEndpoint::default()
    }
}
fn service_policy(skip: bool) -> Value {
    json!({
        "apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnLocalRedirectPolicy",
        "metadata": {"namespace": "kube-system", "name": "nodelocaldns"},
        "spec": {
            "redirectFrontend": {"serviceMatcher": {"serviceName": "kube-dns", "namespace": "kube-system"}},
            "redirectBackend": {
                "localEndpointSelector": {"matchLabels": {"k8s-app": "node-local-dns"}},
                "toPorts": [{"port": "53", "name": "dns", "protocol": "UDP"},
                            {"port": "53", "name": "dns-tcp", "protocol": "TCP"}]
            },
            "skipRedirectFromBackend": skip
        }
    })
}

/// spec 05 §3.9 (#565): a serviceMatcher redirects every ClusterIP port to
/// the local Pod, pairing ports by name; skip-LB keeps the Service's own
/// backends at scope 2 and lists the backend's netns cookie.
#[test]
fn service_matcher_redirects_to_the_local_pod_and_skips_its_backend() {
    let mut frontends = dns();
    let report = apply(&mut frontends, &[service_policy(true)], &[cache("n1", true)], "n1", &[endpoint()]);
    assert_eq!(report.problems.get(&("kube-system".into(), "nodelocaldns".into())), Some(&None));
    let redirected: Vec<&Frontend> = frontends.iter().filter(|f| f.service.scope == SCOPE_CLUSTER).collect();
    assert_eq!(redirected.len(), 2);
    for f in &redirected {
        assert!(f.service.local_redirect);
        assert_eq!(f.service.skip, vec![4242]);
        assert_eq!(f.service.backends, vec![Address { ip: "10.1.9.9".parse().unwrap(), ..f.service.frontend }]);
    }
    let own: Vec<&Frontend> = frontends.iter().filter(|f| f.service.scope == SCOPE_REDIRECT_SKIPPED).collect();
    assert_eq!(own.len(), 2, "the Service's own backends for skipped sockets");
    assert!(own.iter().all(|f| f.service.backends.len() == 2 && !f.service.local_redirect));
    assert_eq!(report.redirected.len(), 2);
    let listed = report.json(true);
    assert_eq!(listed["policies"][0]["ok"], true);
    assert_eq!(listed["policies"][0]["frontends"].as_array().unwrap().len(), 2);
}

/// Without a Ready local Pod (another node's, or not Ready) the Service keeps
/// its backends; without skip there is no scope-2 copy.
#[test]
fn no_local_ready_backend_leaves_the_service_alone() {
    for (pods, node) in [(vec![cache("n2", true)], "n1"), (vec![cache("n1", false)], "n1")] {
        let mut frontends = dns();
        let before = frontends.clone();
        let report = apply(&mut frontends, &[service_policy(false)], &pods, node, &[]);
        assert_eq!(frontends, before);
        assert!(report.redirected.is_empty());
        assert_eq!(report.problems.values().next(), Some(&None));
    }
    let mut frontends = dns();
    apply(&mut frontends, &[service_policy(false)], &[cache("n1", true)], "n1", &[endpoint()]);
    assert_eq!(frontends.len(), 2);
    assert!(frontends.iter().all(|f| f.service.local_redirect && f.service.skip.is_empty()));
}

/// An addressMatcher adds a LOCAL_REDIRECT frontend; one already served by
/// a Service is refused (spec 05 §3.9, `address-matcher-conflict`).
#[test]
fn address_matcher_adds_a_frontend_and_refuses_a_taken_address() {
    let policy = |ip: &str| {
        json!({
            "metadata": {"namespace": "kube-system", "name": "linklocal"},
            "spec": {
                "redirectFrontend": {"addressMatcher": {"ip": ip, "toPorts": [{"port": "53", "protocol": "UDP"}]}},
                "redirectBackend": {
                    "localEndpointSelector": {"matchLabels": {"k8s-app": "node-local-dns"}},
                    "toPorts": [{"port": "53", "protocol": "UDP"}]
                },
                "skipRedirectFromBackend": true
            }
        })
    };
    let mut frontends = dns();
    let report = apply(&mut frontends, &[policy("169.254.20.10")], &[cache("n1", true)], "n1", &[endpoint()]);
    assert_eq!(report.problems.values().next(), Some(&None));
    let added = frontends.iter().find(|f| f.kind == "LocalRedirect").unwrap();
    assert_eq!(added.service.frontend, addr("169.254.20.10:53/UDP"));
    assert_eq!(added.service.backends, vec![addr("10.1.9.9:53/UDP")]);
    assert!(added.service.local_redirect);
    assert_eq!(added.service.skip, vec![4242]);
    let mut frontends = dns();
    let report = apply(&mut frontends, &[policy("10.96.0.10")], &[cache("n1", true)], "n1", &[]);
    let problem = report.problems.values().next().unwrap().clone().unwrap();
    assert!(problem.contains("kube-system/kube-dns"), "{problem}");
    assert_eq!(frontends, dns());
}

/// Validation (spec 05 §3.9): each refusal says why and changes nothing.
#[test]
fn invalid_policies_are_reported_and_do_nothing() {
    let base = service_policy(false);
    let cases: [(&str, Value, &str); 5] = [
        ("both", json!({"addressMatcher": {"ip": "1.2.3.4", "toPorts": [{"port": "53", "protocol": "UDP"}]},
                         "serviceMatcher": {"serviceName": "kube-dns", "namespace": "kube-system"}}), "exactly one"),
        ("namespace", json!({"serviceMatcher": {"serviceName": "kube-dns", "namespace": "other"}}), "namespace"),
        ("ip", json!({"addressMatcher": {"ip": "nope", "toPorts": [{"port": "53", "protocol": "UDP"}]}}), "not an address"),
        ("port", json!({"addressMatcher": {"ip": "1.2.3.4", "toPorts": [{"port": "0", "protocol": "UDP"}]}}), "port"),
        ("names", json!({"addressMatcher": {"ip": "1.2.3.4", "toPorts": [{"port": "53", "protocol": "UDP"},
                                                                      {"port": "54", "protocol": "UDP"}]}}), "name"),
    ];
    for (label, frontend, want) in cases {
        let mut object = base.clone();
        object["spec"]["redirectFrontend"] = frontend;
        let mut frontends = dns();
        let report = apply(&mut frontends, &[object], &[cache("n1", true)], "n1", &[]);
        let problem = report.problems.values().next().unwrap().clone().unwrap_or_default();
        assert!(problem.contains(want), "{label}: {problem}");
        assert_eq!(frontends, dns(), "{label}");
    }
}
