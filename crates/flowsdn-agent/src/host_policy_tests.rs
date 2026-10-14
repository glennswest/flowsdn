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
    let got = select(&objects, &node);
    assert_eq!(got.names, vec!["/workers".to_owned(), "/sourced".to_owned()]);
    assert!(got.enforce_ingress);
    assert!(!got.audit);
    // workers' rule and sourced's empty rule (default deny, allows nothing).
    assert_eq!(got.rules.len(), 2);
    let workers = got.rules.first().expect("rule");
    assert_eq!(workers.peers, entity("cluster").map(|ids| vec![Peer::Identities(ids)]));
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
    let objects = [json!({"metadata":{"name":"fw","annotations":{"policy.flowsdn.io/audit":"true"}},
        "specs":[{"nodeSelector":{},
            "ingress":[
                {"fromCIDR":["192.168.31.0/24"],"fromCIDRSet":[{"cidr":"10.0.0.0/8","except":["10.9.0.0/16"]}],
                 "toPorts":[{"ports":[{"port":22,"protocol":"TCP"},{"port":"5100","endPort":5110}]}]},
                {"toPorts":[{"ports":[{"port":"53","protocol":"UDP"}]}]},
                {"fromEndpoints":[{"matchLabels":{"app":"prom","k8s:io.kubernetes.pod.namespace":"mon"}}]}
            ],
            "ingressDeny":[{"fromEntities":["world"],"toPorts":[{"ports":[{"port":"22","protocol":"TCP"}]}]}],
            "egress":[{"toEntities":["world"]}]}]})];
    let got = select(&objects, &node);
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
    assert!(
        got.problems
            .iter()
            .any(|p| p.contains("host egress rules are not enforced"))
    );
}

#[test]
fn unsupported_rules_are_skipped_and_reported() {
    let node = labels(&[]);
    let objects = [policy(
        "odd",
        json!({"nodeSelector":{},"enableDefaultDeny":{"ingress":false},
            "ingress":[
                {"fromEntities":["world"],"toPorts":[{"ports":[{"port":"80"}],"rules":{"http":[{}]}}]},
                {"fromNodes":[{}]},
                {"fromEntities":["nonsense"],"toPorts":[{"ports":[{"port":"ssh"}]}]}
            ]}),
    )];
    let got = select(&objects, &node);
    assert!(!got.enforce_ingress, "enableDefaultDeny.ingress false");
    assert!(got.rules.is_empty());
    for needle in [
        "L7 rules",
        "fromNodes",
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
