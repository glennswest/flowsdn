use super::*;
use serde_json::json;

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}
fn policy(spec: Value) -> Value {
    json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
        "metadata":{"name":"web","namespace":"shop","uid":"u-1"},"spec":spec})
}
fn selector(peer: &Peer) -> &LabelSelector {
    match peer {
        Peer::Selector(s) => s,
        Peer::Cidr { .. } => panic!("selector peer expected"),
    }
}

#[test]
fn deny_all_ingress_is_a_marker_that_allows_nothing() {
    // TestParseNetworkPolicyDenyAll: podSelector {} and no ingress rules.
    let entries = network_policy(&policy(json!({"podSelector":{}})), None).expect("parse");
    assert_eq!(entries.len(), 1);
    let only = entries.first().expect("entry");
    assert!(only.ingress && only.is_marker() && only.default_deny);
    assert_eq!(only.l3, Some(vec![]));
    assert_eq!(only.l4, None);
    assert_eq!(only.subject.key(), "k8s:io.kubernetes.pod.namespace=shop");
    // Explicit policyTypes with an empty list: still the marker.
    let entries = network_policy(
        &policy(json!({"podSelector":{},"policyTypes":["Ingress"],"ingress":[]})),
        None,
    )
    .expect("parse");
    assert!(entries.iter().all(Entry::is_marker));
}

#[test]
fn egress_only_policy_types_ignore_ingress_and_mark_egress() {
    // TestParseNetworkPolicyNoIngress: Egress only, nothing allowed out.
    let entries = network_policy(
        &policy(
            json!({"podSelector":{"matchLabels":{"app":"web"}},"policyTypes":["Egress"],
            "ingress":[{}]}),
        ),
        None,
    )
    .expect("parse");
    assert_eq!(entries.len(), 1);
    let only = entries.first().expect("entry");
    assert!(!only.ingress && only.is_marker());
    assert_eq!(
        only.subject.key(),
        "k8s:app=web,k8s:io.kubernetes.pod.namespace=shop"
    );
}

#[test]
fn allow_all_ingress_is_the_wildcard_peer() {
    let entries =
        network_policy(&policy(json!({"podSelector":{},"ingress":[{}]})), None).expect("parse");
    let only = entries.first().expect("entry");
    assert_eq!((only.l3.clone(), only.l4.clone()), (None, None));
    assert!(!only.is_marker());
}

#[test]
fn peers_ports_and_selectors() {
    let entries = network_policy(
        &policy(json!({
            "podSelector":{"matchLabels":{"app":"web"}},
            "ingress":[{
                "from":[
                    {"podSelector":{"matchLabels":{"role":"client"}}},
                    {"namespaceSelector":{"matchLabels":{"team":"a"}},
                     "podSelector":{"matchExpressions":[{"key":"tier","operator":"In","values":["fe","be"]}]}},
                    {"namespaceSelector":{}},
                    {"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}
                ],
                "ports":[{"port":80},{"protocol":"UDP","port":"dns"},{"port":8000,"endPort":8080},{}]
            }],
            "egress":[{"to":[{"podSelector":{}}]}]
        })),
        Some("c1"),
    )
    .expect("parse");
    // 4 ingress peers + 1 egress peer; Egress is effective because egress is set.
    assert_eq!(entries.len(), 5);
    let ingress: Vec<&Entry> = entries.iter().filter(|e| e.ingress).collect();
    let peers: Vec<&Peer> = ingress
        .iter()
        .map(|e| e.l3.as_ref().and_then(|l| l.first()).expect("peer"))
        .collect();
    // Same namespace, same cluster.
    assert_eq!(
        selector(peers.first().expect("peer")).key(),
        "k8s:io.flowsdn.k8s.policy.cluster=c1,k8s:io.kubernetes.pod.namespace=shop,k8s:role=client"
    );
    // Namespace labels rewritten and ANDed with the pod selector.
    assert_eq!(
        selector(peers.get(1).expect("peer")).key(),
        "k8s:io.flowsdn.k8s.namespace.labels.team=a,k8s:io.flowsdn.k8s.policy.cluster=c1,k8s:tier in (be,fe)"
    );
    // An empty namespace selector is every namespace.
    assert_eq!(
        selector(peers.get(2).expect("peer")).key(),
        "k8s:io.flowsdn.k8s.policy.cluster=c1,k8s:io.kubernetes.pod.namespace"
    );
    assert_eq!(
        peers.get(3).copied(),
        Some(&Peer::Cidr {
            cidr: "10.0.0.0/8".into(),
            except: vec!["10.1.0.0/16".into()]
        })
    );
    let ports = ingress.first().and_then(|e| e.l4.clone()).expect("ports");
    assert_eq!(
        ports,
        vec![
            PortRule {
                protocol: Protocol::Tcp,
                port: "80".into(),
                end_port: None
            },
            PortRule {
                protocol: Protocol::Udp,
                port: "dns".into(),
                end_port: None
            },
            PortRule {
                protocol: Protocol::Tcp,
                port: "8000".into(),
                end_port: Some(8080)
            },
            PortRule {
                protocol: Protocol::Tcp,
                port: "0".into(),
                end_port: None
            },
        ]
    );
    // Every entry carries the same labels.
    let first = entries.first().expect("entry");
    assert_eq!(
        first.labels,
        vec![
            "k8s:io.flowsdn.k8s.policy.derived-from=NetworkPolicy",
            "k8s:io.flowsdn.k8s.policy.name=web",
            "k8s:io.flowsdn.k8s.policy.namespace=shop",
            "k8s:io.flowsdn.k8s.policy.uid=u-1",
        ]
    );
    assert!(
        entries
            .iter()
            .all(|e| e.tier == Tier::Normal && e.verdict == Verdict::Allow && e.priority == 0.0)
    );
}

#[test]
fn selectors_match_like_kubernetes() {
    let parsed = LabelSelector::parse(Some(
        &json!({"matchLabels":{"app":"web"},"matchExpressions":[
        {"key":"tier","operator":"NotIn","values":["db"]},
        {"key":"zone","operator":"Exists"},
        {"key":"debug","operator":"DoesNotExist"}]}),
    ))
    .expect("selector");
    assert!(parsed.matches(&labels(&[("app", "web"), ("zone", "a")])));
    assert!(parsed.matches(&labels(&[("app", "web"), ("zone", "a"), ("tier", "fe")])));
    assert!(!parsed.matches(&labels(&[("app", "web"), ("zone", "a"), ("tier", "db")])));
    assert!(!parsed.matches(&labels(&[("app", "web")])));
    assert!(!parsed.matches(&labels(&[("app", "web"), ("zone", "a"), ("debug", "1")])));
    assert_eq!(parsed.key(), "app=web,!debug,tier notin (db),zone");
    assert!(LabelSelector::default().matches(&labels(&[])));
    assert_eq!(LabelSelector::default().key(), "{}");
    // Conflicting fixed values: the conjunction matches nothing.
    let a = LabelSelector::parse(Some(&json!({"matchLabels":{"app":"a"}}))).expect("a");
    let b = LabelSelector::parse(Some(&json!({"matchLabels":{"app":"b"}}))).expect("b");
    let both = a.and(b);
    assert!(!both.matches(&labels(&[("app", "a")])));
    assert!(!both.matches(&labels(&[("app", "b")])));
}

#[test]
fn name_annotation_default_namespace_and_rejections() {
    let mut object = policy(json!({"podSelector":{},"ingress":[{}]}));
    if let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("namespace");
        metadata.insert(
            "annotations".into(),
            json!({"flowsdn.io/policy-name":"renamed"}),
        );
    }
    let entries = network_policy(&object, None).expect("parse");
    let first = entries.first().expect("entry");
    assert!(
        first
            .labels
            .contains(&"k8s:io.flowsdn.k8s.policy.name=renamed".to_owned())
    );
    assert_eq!(
        first.subject.key(),
        "k8s:io.kubernetes.pod.namespace=default"
    );
    for bad in [
        json!({"podSelector":{},"ingress":[{"ports":[{"protocol":"ICMP"}]}]}),
        json!({"podSelector":{},"ingress":[{"ports":[{"port":70000}]}]}),
        json!({"podSelector":{},"ingress":[{"from":[{"ipBlock":{}}]}]}),
        json!({"podSelector":{"matchExpressions":[{"key":"a","operator":"In"}]}}),
        json!({"podSelector":{"matchExpressions":[{"key":"a","operator":"Exists","values":["x"]}]}}),
        json!({"podSelector":{"matchExpressions":[{"key":"a","operator":"Like"}]}}),
        json!({"podSelector":{},"policyTypes":["Both"]}),
    ] {
        assert!(network_policy(&policy(bad.clone()), None).is_err(), "{bad}");
    }
    // A peer selector already naming the cluster keeps its own.
    let entries = network_policy(
        &policy(json!({"podSelector":{},"ingress":[{"from":[
            {"podSelector":{"matchLabels":{"io.flowsdn.k8s.policy.cluster":"other"}}}]}]})),
        Some("c1"),
    )
    .expect("parse");
    let peer = entries
        .first()
        .and_then(|e| e.l3.as_ref())
        .and_then(|l| l.first())
        .expect("peer");
    assert!(selector(peer).key().contains("cluster=other"));
    assert!(!selector(peer).key().contains("cluster=c1"));
}
