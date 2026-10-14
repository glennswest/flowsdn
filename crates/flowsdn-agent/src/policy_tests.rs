use super::*;
use crate::kubernetes::{NodeInfo, PodInfo};
use flowsdn_bpf_abi::policy::EndpointPolicyKey;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("IP")
}
fn pod(name: &str, node: &str, address: &str, labels: &[(&str, &str)]) -> PodInfo {
    PodInfo {
        namespace: "shop".into(),
        name: name.into(),
        node: node.into(),
        ips: vec![ip(address)],
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        service_account: "default".into(),
        ..PodInfo::default()
    }
}
/// web (local endpoint 7 on ifindex 40), client (remote) and db (remote);
/// every Pod has an identity whose labels are what the allocator writes.
fn view(policies: Vec<Value>) -> View {
    let mut web = pod("web", "n1", "10.1.0.5", &[("app", "web")]);
    web.named_ports = vec![(6, "http".into(), 8080)];
    let mut db = pod("db", "n2", "10.2.0.9", &[("app", "db")]);
    db.named_ports = vec![(6, "sql".into(), 5432)];
    let mut view = View {
        local_node: "n1".into(),
        cluster_name: "default".into(),
        identity: true,
        network_policy: true,
        nodes: vec![
            NodeInfo {
                name: "n1".into(),
                internal_ips: vec![ip("192.0.2.1")],
                ..NodeInfo::default()
            },
            NodeInfo {
                name: "n2".into(),
                internal_ips: vec![ip("192.0.2.2")],
                ..NodeInfo::default()
            },
        ],
        pods: vec![
            web,
            pod("client", "n2", "10.2.0.7", &[("app", "client")]),
            db,
        ],
        pods_synced: true,
        namespaces: [("shop".to_owned(), BTreeMap::new())].into_iter().collect(),
        namespaces_synced: true,
        endpoints: vec![LocalEndpoint {
            id: 7,
            namespace: "shop".into(),
            name: "web".into(),
            interface: "lxc7".into(),
            ifindex: 40,
            ..LocalEndpoint::default()
        }],
        endpoints_published: true,
        network_policies: policies,
        policies_synced: true,
        ..View::default()
    };
    let filter = LabelFilter::identity(&[]).expect("filter");
    for ((pod, _, labels), id) in view.pod_label_sets(&filter).into_iter().zip(300u32..) {
        view.identities
            .insert(id, crate::identity::label_strings(&labels));
        view.pod_identities.insert(pod, id);
    }
    view
}
fn identity_of(view: &View, name: &str) -> u32 {
    view.pod_identity("shop", name).expect("identity")
}
fn policy(spec: Value) -> Value {
    json!({"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
        "metadata":{"name":"p","namespace":"shop","uid":"u-1"},"spec":spec})
}
/// (identity, egress, protocol, port, port prefix) of every entry for endpoint 7.
fn keys_of(desired: &Desired) -> BTreeSet<(u32, bool, u8, u16, u32)> {
    desired
        .entries
        .keys()
        .map(|k| EndpointPolicyKey::from_bytes(*k))
        .inspect(|k| assert_eq!(k.endpoint, 7))
        .map(|k| {
            (
                k.sec_label,
                k.egress == 1,
                k.protocol,
                k.dport.get(),
                k.prefixlen.saturating_sub(80),
            )
        })
        .collect()
}

#[test]
fn without_policies_nothing_is_enforced_and_the_ipcache_has_pods_and_host() {
    let view = view(Vec::new());
    let desired = compile(&view, &[ip("10.1.0.1")]);
    assert!(desired.endpoints.is_empty());
    assert!(desired.entries.is_empty());
    let ipcache: BTreeMap<u32, usize> =
        desired
            .ipcache
            .values()
            .fold(BTreeMap::new(), |mut counts, info| {
                *counts.entry(info.sec_identity).or_default() += 1;
                counts
            });
    // Three Pods, the host's InternalIP and gateway, and n2 (remote node).
    assert_eq!(ipcache.get(&HOST), Some(&2));
    assert_eq!(ipcache.get(&REMOTE_NODE), Some(&1));
    assert_eq!(desired.ipcache.len(), 6);
    assert!(desired.host.is_null());
    assert!(desired.problems.is_empty());
}

#[test]
fn ingress_from_a_selected_peer_on_one_port() {
    let view = view(vec![policy(json!({
        "podSelector":{"matchLabels":{"app":"web"}},
        "ingress":[{"from":[{"podSelector":{"matchLabels":{"app":"client"}}}],
                    "ports":[{"protocol":"TCP","port":80}]}]
    }))]);
    let desired = compile(&view, &[]);
    assert_eq!(
        desired.endpoints.get(&40),
        Some(&PolicyEndpoint {
            endpoint: 7,
            flags: enforce::INGRESS
        })
    );
    let client = identity_of(&view, "client");
    assert_eq!(
        keys_of(&desired),
        BTreeSet::from([(client, false, 6, 80, 16)])
    );
    let entry = desired.entries.values().next().expect("entry");
    assert_eq!(entry.lpm_prefix_length(), 24);
    assert_eq!(entry.precedence, ALLOW_PRECEDENCE);
    assert!(!entry.denies());
}

#[test]
fn default_deny_both_directions_has_no_entries() {
    let view = view(vec![policy(json!({
        "podSelector":{}, "policyTypes":["Ingress","Egress"]
    }))]);
    let desired = compile(&view, &[]);
    assert_eq!(
        desired.endpoints.get(&40).map(|e| e.flags),
        Some(enforce::INGRESS | enforce::EGRESS)
    );
    assert!(desired.entries.is_empty());
    assert_eq!(
        desired.enforced,
        vec![(7, "shop/web".into(), true, true, 0)]
    );
}

#[test]
fn a_policy_for_other_pods_does_not_enforce_this_one() {
    let view = view(vec![policy(json!({
        "podSelector":{"matchLabels":{"app":"db"}}, "policyTypes":["Ingress"]
    }))]);
    assert!(compile(&view, &[]).endpoints.is_empty());
}

#[test]
fn egress_ip_block_with_except_gets_cidr_identities() {
    let view = view(vec![policy(json!({
        "podSelector":{"matchLabels":{"app":"web"}}, "policyTypes":["Egress"],
        "egress":[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.9.0.0/16"]}}]}]
    }))]);
    let desired = compile(&view, &[]);
    let cidr = |text: &str, bits: u8| {
        desired
            .ipcache
            .get(&ip_key(ip(text), bits).expect("key"))
            .map(|i| i.sec_identity)
            .expect("CIDR in the ipcache")
    };
    let allowed = cidr("10.0.0.0", 8);
    let excepted = cidr("10.9.0.0", 16);
    assert!(allowed > CIDR_IDENTITY_BASE && excepted > CIDR_IDENTITY_BASE);
    assert_ne!(allowed, excepted);
    assert_eq!(
        keys_of(&desired),
        BTreeSet::from([(allowed, true, 0, 0, 0)])
    );
}

#[test]
fn ip_block_holding_the_node_selects_the_host() {
    let view = view(vec![policy(json!({
        "podSelector":{}, "policyTypes":["Egress"],
        "egress":[{"to":[{"ipBlock":{"cidr":"192.0.2.0/24"}}],"ports":[{"port":6443}]}]
    }))]);
    let keys = keys_of(&compile(&view, &[]));
    assert!(keys.contains(&(HOST, true, 6, 6443, 16)), "{keys:?}");
}

#[test]
fn named_ports_resolve_on_the_destination_and_ranges_are_masked() {
    let view = view(vec![policy(json!({
        "podSelector":{"matchLabels":{"app":"web"}},
        "ingress":[{"ports":[{"port":"http"}]}],
        "egress":[{"to":[{"podSelector":{"matchLabels":{"app":"db"}}}],
                   "ports":[{"port":"sql"},{"port":9000,"endPort":9003}]}]
    }))]);
    let desired = compile(&view, &[]);
    let db = identity_of(&view, "db");
    assert_eq!(
        keys_of(&desired),
        BTreeSet::from([
            (0, false, 6, 8080, 16),
            (db, true, 6, 5432, 16),
            (db, true, 6, 9000, 14),
        ])
    );
}

#[test]
fn a_policy_that_cannot_be_read_is_reported() {
    let view = view(vec![
        json!({"kind":"NetworkPolicy","metadata":{"name":"bad","namespace":"shop"},
        "spec":{"podSelector":{"matchExpressions":[{"key":"a","operator":"Bogus"}]}}}),
    ]);
    let desired = compile(&view, &[]);
    assert!(desired.endpoints.is_empty());
    assert!(
        desired.problems.iter().any(|p| p.starts_with("shop/bad:")),
        "{:?}",
        desired.problems
    );
}

#[test]
fn an_ip_block_still_selects_remote_nodes() {
    let view = view(vec![policy(json!({
        "podSelector":{"matchLabels":{"app":"web"}},
        "ingress":[{"from":[{"ipBlock":{"cidr":"192.0.2.0/24"}}]}]
    }))]);
    let desired = compile(&view, &[]);
    let identities: BTreeSet<u32> = keys_of(&desired).iter().map(|k| k.0).collect();
    assert!(identities.contains(&REMOTE_NODE), "{identities:?}");
    assert!(identities.contains(&HOST));
}

fn host_view(mode: HostFirewall, learning: bool) -> View {
    let mut view = view(Vec::new());
    view.host_firewall = mode;
    if let Some(n1) = view.nodes.iter_mut().find(|n| n.name == "n1") {
        n1.labels.insert("role".into(), "worker".into());
    }
    view.clusterwide_policies = vec![json!({"metadata":{"name":"fw"},"spec":{
        "nodeSelector":{"matchLabels":{"role":"worker"}},
        "ingress":[
            {"fromEntities":["remote-node"]},
            {"fromCIDR":["198.51.100.0/24"],"toPorts":[{"ports":[{"port":"22","protocol":"TCP"}]}]},
            {"fromEndpoints":[{"matchLabels":{"app":"client"}}],"toPorts":[{"ports":[{"port":"9090","protocol":"TCP"}]}]}
        ],
        "ingressDeny":[{"fromEntities":["all"],"toPorts":[{"ports":[{"port":"9100","protocol":"TCP"}]}]}]
    }})];
    view.clusterwide_synced = true;
    view.host_interfaces = [("eth0".to_owned(), 5u32)].into_iter().collect();
    if learning {
        view.host_learning.insert(5);
    }
    view
}
/// (identity, protocol, port, port prefix, deny) of every host entry.
fn host_keys(desired: &Desired) -> BTreeSet<(u32, u8, u16, u32, bool)> {
    desired
        .entries
        .iter()
        .map(|(k, v)| (EndpointPolicyKey::from_bytes(*k), *v))
        .filter(|(k, _)| k.endpoint == HOST_ENDPOINT)
        .map(|(k, v)| {
            assert_eq!(k.egress, 0, "host rules are ingress");
            (
                k.sec_label,
                k.protocol,
                k.dport.get(),
                k.prefixlen.saturating_sub(80),
                v.denies(),
            )
        })
        .collect()
}

#[test]
fn host_firewall_rules_enforcement_and_audit() {
    let view = host_view(HostFirewall::Enforce, false);
    let desired = compile(&view, &[]);
    assert_eq!(
        desired.endpoints.get(&5),
        Some(&PolicyEndpoint {
            endpoint: HOST_ENDPOINT,
            flags: enforce::INGRESS
        })
    );
    let keys = host_keys(&desired);
    let cidr = desired
        .ipcache
        .iter()
        .map(|(k, v)| (IpCacheKey::from_bytes(*k), v.sec_identity))
        .find(|(k, _)| k.prefixlen == 64 - 8)
        .map(|(_, id)| id)
        .expect("198.51.100.0/24 has a CIDR identity");
    let client = identity_of(&view, "client");
    let tcp = |port| (6u8, port, 16u32);
    for want in [
        // remote-node: every L4, with the wildcard deny repeated at it.
        (REMOTE_NODE, 0, 0, 0, false),
        (REMOTE_NODE, tcp(9100).0, 9100, 16, true),
        (cidr, tcp(22).0, 22, 16, false),
        (client, tcp(9090).0, 9090, 16, false),
        (0, 6, 9100, 16, true),
    ] {
        assert!(keys.contains(&want), "{want:?} not in {keys:?}");
    }
    assert_eq!(keys.len(), 5, "{keys:?}");
    assert_eq!(
        desired.host.pointer("/enforcing-on/0"),
        Some(&json!("eth0"))
    );
    assert_eq!(desired.host.pointer("/policies/0"), Some(&json!("/fw")));
    assert!(desired.problems.is_empty(), "{:?}", desired.problems);

    let audit = compile(&host_view(HostFirewall::Audit, false), &[]);
    assert_eq!(
        audit.endpoints.get(&5).map(|e| e.flags),
        Some(enforce::INGRESS | enforce::AUDIT)
    );
    let learning = compile(&host_view(HostFirewall::Enforce, true), &[]);
    assert_eq!(learning.endpoints.get(&5).map(|e| e.flags), Some(0));
    assert_eq!(learning.host.pointer("/learning/0"), Some(&json!("eth0")));
    // Off: nothing of the host, whatever the policies say.
    let off = compile(&host_view(HostFirewall::Off, false), &[]);
    assert!(off.endpoints.is_empty() && host_keys(&off).is_empty());
    // Not selected: tracked only.
    let mut other = host_view(HostFirewall::Enforce, false);
    for node in &mut other.nodes {
        node.labels.clear();
    }
    let other = compile(&other, &[]);
    assert_eq!(other.endpoints.get(&5).map(|e| e.flags), Some(0));
    assert!(host_keys(&other).is_empty());
}

#[test]
fn denies_win_over_the_allows_they_cover() {
    let allows: BTreeSet<_> = [
        (300, 0, 0, 0),    // everything from 300
        (301, 6, 22, 16),  // TCP 22 from 301
        (302, 6, 0, 0),    // all TCP from 302
        (303, 17, 53, 16), // UDP 53 from 303
    ]
    .into_iter()
    .collect();
    let denies: BTreeSet<_> = [
        (0, 6, 22, 16),  // TCP 22 from everyone
        (302, 6, 8, 13), // TCP 8-15 from 302
    ]
    .into_iter()
    .collect();
    let (kept, denies) = deny_over_allow(&allows, &denies);
    // 301's allow is inside the wildcard deny: gone.
    assert!(!kept.contains(&(301, 6, 22, 16)));
    assert!(kept.contains(&(300, 0, 0, 0)) && kept.contains(&(302, 6, 0, 0)));
    assert!(kept.contains(&(303, 17, 53, 16)));
    // The wildcard deny is repeated at 300 and 302, whose allows hold it.
    assert!(denies.contains(&(300, 6, 22, 16)));
    assert!(denies.contains(&(302, 6, 22, 16)));
    assert!(denies.contains(&(302, 6, 8, 13)));
    assert!(!denies.contains(&(303, 6, 22, 16)));
}
