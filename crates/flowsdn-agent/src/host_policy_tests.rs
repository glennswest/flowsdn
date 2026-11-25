use super::*;
use serde_json::json;

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}
fn policy(name: &str, spec: Value) -> Value {
    json!({"metadata":{"name":name},"spec":spec})
}

#[test]
fn node_selector_picks_the_policies_of_this_node() {
    let node = labels(&[("kubernetes.io/hostname", "n1"), ("role", "worker")]);
    let objects = [
        policy(
            "workers",
            json!({"nodeSelector":{"matchLabels":{"role":"worker"}},
                "ingress":[{"fromEntities":["cluster"],"toPorts":[{"ports":[{"port":"9090","protocol":"TCP"}]}]}]}),
        ),
        policy(
            "masters",
            json!({"nodeSelector":{"matchLabels":{"role":"master"}},
                "ingress":[{"fromEntities":["world"]}]}),
        ),
        policy(
            "sourced",
            json!({"nodeSelector":{"matchLabels":{"k8s:kubernetes.io/hostname":"n1"}},
                "ingress":[{}]}),
        ),
        policy(
            "pods",
            json!({"endpointSelector":{},"ingress":[{"fromEntities":["world"]}]}),
        ),
    ];
    let got = select(&objects, &node, false);
    assert_eq!(
        got.names,
        vec!["/workers".to_owned(), "/sourced".to_owned()]
    );
    assert!(got.enforce_ingress);
    assert!(!got.audit);
    // workers' rule and sourced's empty rule (default deny, allows nothing).
    assert_eq!(got.rules.len(), 2);
    let workers = got.rules.first().expect("rule");
    assert_eq!(
        workers.peers,
        entity("cluster").map(|ids| vec![Peer::Identities(ids)])
    );
    assert_eq!(
        workers.ports,
        vec![(6, PortRange::from_api(9090, None).expect("range"))]
    );
    assert_eq!(got.rules.get(1).and_then(|r| r.peers.clone()), Some(vec![]));
    assert!(
        got.problems
            .iter()
            .any(|p| p.contains("/pods: endpointSelector"))
    );
}

#[test]
fn peers_ports_and_denies() {
    let node = labels(&[("role", "worker")]);
    let objects = [
        json!({"metadata":{"name":"fw","annotations":{"policy.flowsdn.io/audit":"true"}},
        "specs":[{"nodeSelector":{},
            "ingress":[
                {"fromCIDR":["192.168.31.0/24"],"fromCIDRSet":[{"cidr":"10.0.0.0/8","except":["10.9.0.0/16"]}],
                 "toPorts":[{"ports":[{"port":22,"protocol":"TCP"},{"port":"5100","endPort":5110}]}]},
                {"toPorts":[{"ports":[{"port":"53","protocol":"UDP"}]}]},
                {"fromEndpoints":[{"matchLabels":{"app":"prom","k8s:io.kubernetes.pod.namespace":"mon"}}]}
            ],
            "ingressDeny":[{"fromEntities":["world"],"toPorts":[{"ports":[{"port":"22","protocol":"TCP"}]}]}],
            "egress":[{"toEntities":["world"]}]}]}),
    ];
    let got = select(&objects, &node, false);
    assert!(got.audit && got.enforce_ingress);
    assert_eq!(got.rules.len(), 4);
    let cidr = got.rules.first().expect("cidr rule");
    assert_eq!(cidr.peers.as_ref().map(Vec::len), Some(2));
    // TCP 22, then ANY 5100-5110 as TCP, UDP and SCTP.
    assert_eq!(cidr.ports.len(), 4);
    let l4_only = got.rules.get(1).expect("l4 rule");
    assert_eq!(l4_only.peers, None);
    let pods = got.rules.get(2).expect("endpoints rule");
    let Some(Some(Peer::Endpoints(selector))) = pods.peers.as_ref().map(|p| p.first()) else {
        panic!("endpoints peer");
    };
    assert!(selector.matches(&labels(&[
        ("k8s:app", "prom"),
        ("k8s:io.kubernetes.pod.namespace", "mon")
    ])));
    let deny = got.rules.get(3).expect("deny");
    assert!(deny.deny);
    // Egress rules are host egress rules (#477), not a problem.
    assert!(got.enforce_egress);
    assert_eq!(got.egress_rules.len(), 1);
    assert!(got.problems.is_empty(), "{:?}", got.problems);
}

#[test]
fn host_egress_rules_and_their_default_deny() {
    let node = labels(&[]);
    let objects = [policy(
        "out",
        json!({"nodeSelector":{},
            "egress":[
                {"toCIDR":["203.0.113.0/24"],"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]},
                {"toEntities":["kube-apiserver","remote-node"]},
                {"toEndpoints":[{"matchLabels":{"app":"db"}}],"toPorts":[{"ports":[{"port":"5432"}]}]},
                {"toFQDNs":[{"matchName":"example.com"}]},
                {"toServices":[{"k8sService":{"serviceName":"x","namespace":"y"}}]}
            ],
            "egressDeny":[{"toEntities":["world"],"toPorts":[{"ports":[{"port":"25","protocol":"TCP"}]}]}]}),
    )];
    let got = select(&objects, &node, false);
    assert!(got.enforce_egress);
    assert!(!got.enforce_ingress, "no ingress rules: ingress untouched");
    assert!(got.rules.is_empty());
    // CIDR + 443, entities, endpoints + 5432 (TCP, UDP, SCTP), the deny.
    assert_eq!(got.egress_rules.len(), 4, "{:?}", got.egress_rules);
    let cidr = got.egress_rules.first().expect("cidr");
    assert_eq!(
        cidr.peers,
        Some(vec![Peer::Cidr {
            cidr: "203.0.113.0/24".into(),
            except: Vec::new()
        }])
    );
    assert_eq!(cidr.ports.len(), 1);
    assert_eq!(
        got.egress_rules.get(1).and_then(|r| r.peers.clone()),
        Some(vec![
            Peer::Identities(vec![KUBE_APISERVER]),
            Peer::Identities(vec![REMOTE_NODE, AGGREGATE_REMOTE_NODE])
        ])
    );
    assert!(got.egress_rules.last().is_some_and(|r| r.deny));
    for field in ["toFQDNs", "toServices"] {
        assert!(
            got.problems.iter().any(|p| p.contains(field)),
            "{field}: {:?}",
            got.problems
        );
    }

    let open = [policy(
        "open",
        json!({"nodeSelector":{},"enableDefaultDeny":{"egress":false},
            "egress":[{"toEntities":["world"]}]}),
    )];
    let got = select(&open, &node, false);
    assert!(
        !got.enforce_egress,
        "default deny off: the rules add nothing"
    );
    assert_eq!(got.egress_rules.len(), 1);
}

#[test]
fn unsupported_rules_are_skipped_and_reported() {
    let node = labels(&[]);
    let objects = [policy(
        "odd",
        json!({"nodeSelector":{},"enableDefaultDeny":{"ingress":false},
        "ingress":[
            {"fromEntities":["world"],"toPorts":[{"ports":[{"port":"80"}],"rules":{"http":[{}]}}]},
            {"fromGroups":[{"aws":{"securityGroupsIds":["sg-1"]}}]},
            {"fromEntities":["nonsense"],"toPorts":[{"ports":[{"port":"ssh"}]}]}
        ]}),
    )];
    let got = select(&objects, &node, false);
    assert!(!got.enforce_ingress, "enableDefaultDeny.ingress false");
    assert!(got.rules.is_empty());
    for needle in [
        "L7 rules",
        "fromGroups",
        "unknown entity nonsense",
        "named port ssh",
    ] {
        assert!(
            got.problems.iter().any(|p| p.contains(needle)),
            "{needle}: {:?}",
            got.problems
        );
    }
}

/// #472 and #530: rules with `authentication` (mutual authentication) or a
/// `toGroups`/`fromGroups` peer (cloud security groups) are not built and stay
/// refused: skipped and reported, so with default deny on they allow nothing
/// (fail closed), and the rules beside them still apply.
#[test]
fn authentication_and_to_groups_are_refused() {
    let node = labels(&[]);
    let objects = [policy(
        "mesh",
        json!({"nodeSelector":{},
        "ingress":[
            {"fromEntities":["world"],"authentication":{"mode":"required"}},
            {"fromEntities":["world"],"authentication":{"mode":"test-always-fail"}},
            {"fromEntities":["cluster"],"toPorts":[{"ports":[{"port":"22","protocol":"TCP"}]}]}
        ],
        "egress":[
            {"toGroups":[{"aws":{"securityGroupsIds":["sg-1"]}}]}
        ]}),
    )];
    let got = select(&objects, &node, false);
    assert!(got.enforce_ingress && got.enforce_egress, "default deny stays on");
    assert_eq!(got.rules.len(), 1, "only the plain rule: {:?}", got.rules);
    assert!(got.egress_rules.is_empty(), "nothing allowed by toGroups");
    for needle in [
        "mesh: authentication is not enforced; the rule is skipped",
        "mesh: toGroups is not enforced; the rule is skipped",
    ] {
        assert!(
            got.problems.iter().any(|p| p == needle),
            "{needle}: {:?}",
            got.problems
        );
    }
}

#[test]
fn scope_is_every_interface_holding_a_global_address() {
    use std::net::IpAddr;
    let ip = |s: &str| s.parse::<IpAddr>().expect("address");
    let link = |name: &str, index, has_master| Link {
        name: name.to_owned(),
        index,
        has_master,
    };
    let links = [
        link("lo", 1, false),
        link("eth0", 2, false),
        link("admin0", 3, false),
        link("br0", 4, false),
        link("eth1", 5, true),
        link("veth1", 6, false),
    ];
    let addresses = [
        (1, ip("127.0.0.1"), 8),
        (1, ip("::1"), 128),
        (2, ip("192.168.16.10"), 20),
        (2, ip("2001:db8::10"), 64),
        (2, ip("fe80::1"), 64),
        (3, ip("10.0.0.10"), 24),
        (4, ip("172.20.0.1"), 16),
        // A bridge port and a veth with only a link-local address.
        (5, ip("192.0.2.9"), 24),
        (6, ip("fe80::2"), 64),
        (6, ip("169.254.0.1"), 32),
    ];
    let (interfaces, held) = scope(&links, &addresses);
    assert_eq!(
        interfaces.into_iter().collect::<Vec<_>>(),
        vec![
            ("admin0".to_owned(), 3),
            ("br0".to_owned(), 4),
            ("eth0".to_owned(), 2)
        ]
    );
    assert_eq!(
        held,
        vec![
            ip("10.0.0.10"),
            ip("172.20.0.1"),
            ip("192.168.16.10"),
            ip("2001:db8::10")
        ]
    );
}

/// #496 (finding 5c9e6d072bfa): one invalid spec fails the whole resource,
/// so neither its host rules nor its Pod rules are published.
#[test]
fn an_invalid_spec_fails_host_and_pod_rules_together() {
    let node = labels(&[("role", "worker")]);
    let host = json!({"nodeSelector":{"matchLabels":{"role":"worker"}},
        "ingress":[{"fromEntities":["cluster"]}]});
    let pods = json!({"endpointSelector":{},"ingress":[{"fromEntities":["world"]}]});
    let bad_pods = json!({"endpointSelector":{},
        "ingress":[{"fromEndpoints":[{}],"fromCIDR":["10.0.0.0/8"]}]});
    let bad_host = json!({"nodeSelector":{"matchExpressions":[{"key":"role","operator":"Bogus"}]},
        "ingress":[{"fromEntities":["world"]}]});
    let mixed = |name: &str, specs: Vec<Value>| json!({"metadata":{"name":name},"specs":specs});
    let objects = [
        mixed("bad-pod-spec", vec![host.clone(), bad_pods]),
        mixed("bad-host-spec", vec![bad_host, pods.clone()]),
        mixed("good", vec![host, pods]),
    ];
    for pod_rules in [true, false] {
        let got = select(&objects, &node, pod_rules);
        assert_eq!(got.names, ["/good"], "pod_rules {pod_rules}");
        assert_eq!(got.rules.len(), 1, "only the valid resource's host rule");
        assert!(got.enforce_ingress);
        let reported = |needle: &str| got.problems.iter().any(|p| p.contains(needle));
        // With Pod rules on, pod_policies reports the resource (once).
        assert_eq!(
            reported("/bad-pod-spec: not enforced, combining fromEndpoints and fromCIDR"),
            !pod_rules,
            "{:?}",
            got.problems
        );
        assert_eq!(
            reported("/bad-host-spec: not enforced, nodeSelector"),
            !pod_rules,
            "{:?}",
            got.problems
        );
    }
    let (policies, problems) = pod_policies(&[], &objects, "default");
    assert_eq!(
        policies.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        ["/good"]
    );
    for needle in [
        "/bad-pod-spec: not enforced, combining fromEndpoints and fromCIDR",
        "/bad-host-spec: not enforced, nodeSelector",
    ] {
        assert!(
            problems.iter().any(|p| p.contains(needle)),
            "{needle}: {problems:?}"
        );
    }
}
