#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
use super::*;
use serde_json::json;

const NOW: &str = "2026-11-25T12:00:00Z";
const EARLIER: &str = "2026-11-01T00:00:00Z";

fn cluster(name: &str, uid: &str, spec: Value) -> FlowsdnBGPClusterConfig {
    serde_json::from_value(json!({
        "metadata": {"name": name, "uid": uid, "generation": 2, "resourceVersion": "7"},
        "spec": spec,
    }))
    .expect("cluster config")
}

fn rack(selector: Value) -> Value {
    json!({
        "nodeSelector": selector,
        "bgpInstances": [{
            "name": "i65001",
            "localASN": 65001,
            "localPort": 179,
            "peers": [
                {"name": "tor-a", "peerASN": 65000, "peerAddress": "10.0.0.1", "peerConfigRef": {"name": "tor"}},
                {"name": "tor-b", "peerASN": 65000, "peerAddress": "10.0.0.2"}
            ]
        }]
    })
}

fn node_config(name: &str, owner: Option<(&str, &str)>, spec: Value) -> FlowsdnBGPNodeConfig {
    let owners: Vec<Value> = owner
        .into_iter()
        .map(|(n, u)| {
            json!({"apiVersion": API_VERSION, "kind": "FlowsdnBGPClusterConfig", "name": n,
                   "uid": u, "controller": true})
        })
        .collect();
    serde_json::from_value(json!({
        "metadata": {"name": name, "uid": format!("nc-{name}"), "resourceVersion": "3",
                     "ownerReferences": owners},
        "spec": spec,
    }))
    .expect("node config")
}

fn nodes(list: &[(&str, &[(&str, &str)])]) -> BTreeMap<String, BTreeMap<String, String>> {
    list.iter()
        .map(|(name, labels)| {
            (
                (*name).to_owned(),
                labels
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            )
        })
        .collect()
}

fn peer(name: &str, secret: Option<&str>) -> FlowsdnBGPPeerConfig {
    let mut spec = json!({});
    if let Some(secret) = secret {
        spec = json!({"authSecretRef": secret});
    }
    serde_json::from_value(json!({"metadata": {"name": name, "generation": 1}, "spec": spec}))
        .expect("peer config")
}

fn enabled() -> BgpSettings {
    BgpSettings {
        enabled: true,
        ..BgpSettings::default()
    }
}

fn creates(plan: &Plan) -> Vec<&FlowsdnBGPNodeConfig> {
    plan.writes
        .iter()
        .filter_map(|w| match w {
            Write::Create(c) => Some(c),
            _ => None,
        })
        .collect()
}

fn cluster_conditions(plan: &Plan, name: &str) -> Vec<(String, String, String)> {
    plan.writes
        .iter()
        .find_map(|w| match w {
            Write::ClusterStatus(c) if c.metadata.name.as_deref() == Some(name) => Some(c),
            _ => None,
        })
        .and_then(|c| c.status.as_ref())
        .and_then(|s| s.conditions.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|c| (c.type_, c.status, c.message))
        .collect()
}

#[test]
fn disabled_writes_nothing() {
    let inputs = Inputs {
        clusters: vec![cluster("rack-a", "u1", rack(Value::Null))],
        nodes: nodes(&[("w1", &[])]),
        ..Inputs::default()
    };
    let plan = plan(&inputs, &BgpSettings::default(), &mut RouterIds::default(), NOW);
    assert_eq!(plan, Plan::default());
}

#[test]
fn selected_nodes_get_a_node_config_owned_by_the_cluster_config() {
    let inputs = Inputs {
        clusters: vec![cluster(
            "rack-a",
            "u1",
            rack(json!({"matchLabels": {"rack": "a"}})),
        )],
        peers: vec![peer("tor", None)],
        nodes: nodes(&[("w1", &[("rack", "a")]), ("w2", &[("rack", "b")])]),
        ..Inputs::default()
    };
    let plan = plan(&inputs, &enabled(), &mut RouterIds::default(), NOW);
    assert!(plan.errors.is_empty(), "{:?}", plan.errors);
    let created = creates(&plan);
    assert_eq!(created.len(), 1);
    let config = serde_json::to_value(created[0]).expect("serialize");
    assert_eq!(
        config,
        json!({
            "apiVersion": "flowsdn.io/v1alpha1",
            "kind": "FlowsdnBGPNodeConfig",
            "metadata": {"name": "w1", "ownerReferences": [{
                "apiVersion": "flowsdn.io/v1alpha1", "kind": "FlowsdnBGPClusterConfig",
                "name": "rack-a", "uid": "u1", "controller": true}]},
            "spec": {"bgpInstances": [{
                "name": "i65001", "localASN": 65001, "localPort": 179,
                "peers": [
                    {"name": "tor-a", "peerASN": 65000, "peerAddress": "10.0.0.1", "peerConfigRef": {"name": "tor"}},
                    {"name": "tor-b", "peerASN": 65000, "peerAddress": "10.0.0.2"}
                ]
            }]}
        })
    );
    // An absent selector selects every node.
    let all = Inputs {
        clusters: vec![cluster("rack-a", "u1", rack(Value::Null))],
        ..inputs
    };
    let plan = super::plan(&all, &enabled(), &mut RouterIds::default(), NOW);
    assert_eq!(creates(&plan).len(), 2);
}

#[test]
fn the_override_is_merged_by_name() {
    let override_: FlowsdnBGPNodeConfigOverride = serde_json::from_value(json!({
        "metadata": {"name": "w1"},
        "spec": {"bgpInstances": [
            {"name": "i65001", "routerID": "192.0.2.11", "localASN": 65011, "localPort": 1790,
             "peers": [{"name": "tor-b", "localAddress": "10.0.0.11", "localPort": 1}, {"name": "nope", "localAddress": "10.9.9.9"}]},
            {"name": "unknown-instance", "localASN": 1}
        ]}
    }))
    .expect("override");
    let inputs = Inputs {
        clusters: vec![cluster("rack-a", "u1", rack(Value::Null))],
        overrides: vec![override_],
        nodes: nodes(&[("w1", &[])]),
        ..Inputs::default()
    };
    let plan = plan(&inputs, &enabled(), &mut RouterIds::default(), NOW);
    let spec = &creates(&plan)[0].spec;
    assert_eq!(spec.bgp_instances.len(), 1, "unmatched instances are ignored");
    let instance = &spec.bgp_instances[0];
    assert_eq!(instance.router_id.as_deref(), Some("192.0.2.11"));
    assert_eq!(instance.local_asn, Some(65011));
    assert_eq!(instance.local_port, Some(1790));
    let peers = instance.peers.as_ref().expect("peers");
    assert_eq!(peers[0].local_address, None);
    assert_eq!(peers[1].local_address.as_deref(), Some("10.0.0.11"));
    assert_eq!(peers.len(), 2, "unmatched peers are ignored");
}

#[test]
fn update_only_when_the_spec_differs_and_delete_when_no_longer_selected() {
    let clusters = vec![cluster(
        "rack-a",
        "u1",
        rack(json!({"matchLabels": {"rack": "a"}})),
    )];
    let first = Inputs {
        clusters: clusters.clone(),
        nodes: nodes(&[("w1", &[("rack", "a")])]),
        ..Inputs::default()
    };
    let rendered = creates(&plan(&first, &enabled(), &mut RouterIds::default(), NOW))[0].clone();
    let stored = node_config(
        "w1",
        Some(("rack-a", "u1")),
        serde_json::to_value(&rendered.spec).expect("spec"),
    );
    // Unchanged: no node config write.
    let same = Inputs {
        node_configs: vec![stored.clone()],
        ..first.clone()
    };
    let plan1 = plan(&same, &enabled(), &mut RouterIds::default(), NOW);
    assert!(
        plan1
            .writes
            .iter()
            .all(|w| matches!(w, Write::ClusterStatus(_))),
        "{:?}",
        plan1.writes
    );
    // Changed: an update of the stored object.
    let mut edited = stored.clone();
    edited.spec.bgp_instances[0].local_asn = Some(1);
    let changed = Inputs {
        node_configs: vec![edited],
        ..first.clone()
    };
    let plan2 = plan(&changed, &enabled(), &mut RouterIds::default(), NOW);
    let update = plan2
        .writes
        .iter()
        .find_map(|w| match w {
            Write::Update(c) => Some(c),
            _ => None,
        })
        .expect("update");
    assert_eq!(update.metadata.resource_version.as_deref(), Some("3"));
    assert_eq!(update.spec, rendered.spec);
    // No longer selected: deleted, by uid.
    let gone = Inputs {
        node_configs: vec![stored],
        nodes: nodes(&[("w1", &[("rack", "b")])]),
        ..first
    };
    let plan3 = plan(&gone, &enabled(), &mut RouterIds::default(), NOW);
    assert!(plan3.writes.contains(&Write::Delete {
        name: "w1".into(),
        uid: "nc-w1".into()
    }));
}

#[test]
fn the_first_owner_wins_and_the_loser_reports_the_conflict() {
    let inputs = Inputs {
        clusters: vec![
            cluster("a-first", "u1", rack(Value::Null)),
            cluster("b-second", "u2", rack(Value::Null)),
        ],
        node_configs: vec![node_config(
            "w1",
            Some(("z-existing", "u0")),
            json!({"bgpInstances": [{"name": "x"}]}),
        )],
        nodes: nodes(&[("w1", &[]), ("w2", &[])]),
        ..Inputs::default()
    };
    let plan = plan(&inputs, &enabled(), &mut RouterIds::default(), NOW);
    // w1 belongs to z-existing: neither touches it. w2 goes to a-first.
    let created = creates(&plan);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].metadata.name.as_deref(), Some("w2"));
    assert!(!plan.writes.iter().any(|w| matches!(w, Write::Update(_) | Write::Delete { .. })));
    let conflict = |name: &str| {
        cluster_conditions(&plan, name)
            .into_iter()
            .find(|(t, _, _)| t == CONDITION_CONFLICTING_CLUSTER_CONFIG)
            .expect("condition")
    };
    assert_eq!(conflict("a-first").1, "True");
    assert!(conflict("a-first").2.ends_with("z-existing"));
    let second = conflict("b-second");
    assert_eq!(second.1, "True");
    assert!(
        second.2.ends_with("a-first, z-existing"),
        "sorted: {}",
        second.2
    );
}

#[test]
fn cluster_conditions_are_sorted_kept_and_written_only_on_change() {
    let mut config = cluster("rack-a", "u1", rack(json!({"matchLabels": {"rack": "none"}})));
    let inputs = Inputs {
        clusters: vec![config.clone()],
        peers: vec![],
        nodes: nodes(&[("w1", &[])]),
        ..Inputs::default()
    };
    let plan1 = plan(&inputs, &enabled(), &mut RouterIds::default(), NOW);
    let conditions = cluster_conditions(&plan1, "rack-a");
    assert_eq!(
        conditions,
        vec![
            (
                CONDITION_CONFLICTING_CLUSTER_CONFIG.into(),
                "False".into(),
                String::new()
            ),
            (
                CONDITION_MISSING_PEER_CONFIGS.into(),
                "True".into(),
                "Referenced peer configs missing: tor".into()
            ),
            (
                CONDITION_NO_MATCHING_NODE.into(),
                "True".into(),
                "No node matches spec.nodeSelector".into()
            ),
        ]
    );
    let written = plan1
        .writes
        .iter()
        .find_map(|w| match w {
            Write::ClusterStatus(c) => Some(c.clone()),
            _ => None,
        })
        .expect("status");
    let first = written.status.clone().and_then(|s| s.conditions).expect("conditions");
    assert!(first.iter().all(|c| c.observed_generation == Some(2) && c.last_transition_time == NOW));
    // Stored as written: the next pass writes nothing.
    config.status = written.status.clone();
    let again = Inputs {
        clusters: vec![config.clone()],
        ..inputs.clone()
    };
    let plan2 = plan(&again, &enabled(), &mut RouterIds::default(), "2026-11-25T12:00:10Z");
    assert!(plan2.writes.is_empty(), "{:?}", plan2.writes);
    // A foreign condition is kept; a status that holds keeps its time.
    let mut status = written.status.clone().expect("status");
    if let Some(list) = status.conditions.as_mut() {
        for c in list.iter_mut() {
            c.last_transition_time = EARLIER.into();
        }
        list.push(Condition {
            last_transition_time: EARLIER.into(),
            message: String::new(),
            observed_generation: None,
            reason: "Other".into(),
            status: "True".into(),
            type_: "example.com/Other".into(),
        });
    }
    config.status = Some(status);
    let resolved = Inputs {
        clusters: vec![config.clone()],
        peers: vec![peer("tor", None)],
        ..inputs.clone()
    };
    let plan3 = plan(&resolved, &enabled(), &mut RouterIds::default(), NOW);
    let status = plan3
        .writes
        .iter()
        .find_map(|w| match w {
            Write::ClusterStatus(c) => c.status.clone(),
            _ => None,
        })
        .and_then(|s| s.conditions)
        .expect("conditions");
    let by_type: BTreeMap<&str, &Condition> = status.iter().map(|c| (c.type_.as_str(), c)).collect();
    assert_eq!(by_type["example.com/Other"].reason, "Other");
    assert_eq!(by_type[CONDITION_MISSING_PEER_CONFIGS].status, "False");
    assert_eq!(by_type[CONDITION_MISSING_PEER_CONFIGS].last_transition_time, NOW);
    assert_eq!(by_type[CONDITION_NO_MATCHING_NODE].last_transition_time, EARLIER);
    // Status reporting off: flowsdn's conditions go, the foreign one stays.
    let off = BgpSettings {
        status_report: false,
        ..enabled()
    };
    let plan4 = plan(&resolved, &off, &mut RouterIds::default(), NOW);
    assert_eq!(
        cluster_conditions(&plan4, "rack-a"),
        vec![("example.com/Other".into(), "True".into(), String::new())]
    );
}

#[test]
fn peer_config_auth_secret_condition() {
    let settings = BgpSettings {
        secrets_namespace: Some("bgp-secrets".into()),
        ..enabled()
    };
    let inputs = Inputs {
        peers: vec![peer("has", Some("present")), peer("lacks", Some("absent")), peer("none", None)],
        secrets: Some(["present".to_owned()].into()),
        ..Inputs::default()
    };
    let plan1 = plan(&inputs, &settings, &mut RouterIds::default(), NOW);
    let statuses: BTreeMap<String, Vec<Condition>> = plan1
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::PeerStatus(p) => Some((
                p.metadata.name.clone().unwrap_or_default(),
                p.status.clone().and_then(|s| s.conditions).unwrap_or_default(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(statuses.len(), 2, "no write for the one without a ref: {statuses:?}");
    assert_eq!(statuses["has"][0].status, "False");
    assert_eq!(statuses["lacks"][0].status, "True");
    assert_eq!(statuses["lacks"][0].type_, CONDITION_MISSING_AUTH_SECRET);
    assert!(statuses["lacks"][0].message.contains("bgp-secrets"));
    // No secrets namespace: the condition is not evaluated.
    let unset = Inputs {
        secrets: None,
        ..inputs.clone()
    };
    assert!(plan(&unset, &enabled(), &mut RouterIds::default(), NOW).writes.is_empty());
    // Status reporting off: an existing condition is removed.
    let mut reported = peer("lacks", Some("absent"));
    reported.status = Some(ConditionsStatus {
        conditions: Some(statuses["lacks"].clone()),
    });
    let off = BgpSettings {
        status_report: false,
        ..settings
    };
    let cleared = Inputs {
        peers: vec![reported],
        ..inputs
    };
    let plan2 = plan(&cleared, &off, &mut RouterIds::default(), NOW);
    match plan2.writes.as_slice() {
        [Write::PeerStatus(p)] => assert_eq!(p.status.as_ref().and_then(|s| s.conditions.clone()), None),
        other => panic!("{other:?}"),
    }
}

fn pool_settings(pool: &str) -> BgpSettings {
    BgpSettings {
        router_ids: RouterIdMode::Pool(Pool::parse(pool).expect("pool")),
        ..enabled()
    }
}

fn router_ids(plan: &Plan) -> BTreeMap<String, String> {
    plan.writes
        .iter()
        .filter_map(|w| match w {
            Write::Create(c) | Write::Update(c) => Some((
                c.metadata.name.clone().unwrap_or_default(),
                c.spec.bgp_instances[0].router_id.clone().unwrap_or_default(),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn pools_parse() {
    assert_eq!(
        Pool::parse("10.1.2.0/30").map(|p| (p.size(), Ipv4Addr::from(p.first))),
        Ok((4, Ipv4Addr::new(10, 1, 2, 0)))
    );
    assert_eq!(Pool::parse("10.0.0.5-10.0.0.9").map(|p| p.size()), Ok(5));
    assert!(Pool::parse("10.0.0.9-10.0.0.5").is_err());
    assert!(Pool::parse("10.0.0.0/33").is_err());
    assert!(Pool::parse("fd00::/64").is_err());
}

#[test]
fn ip_pool_router_ids_allocate_restore_and_free() {
    let settings = pool_settings("10.255.0.0/30");
    let inputs = Inputs {
        clusters: vec![cluster("rack-a", "u1", rack(Value::Null))],
        nodes: nodes(&[("w1", &[]), ("w2", &[]), ("w3", &[])]),
        ..Inputs::default()
    };
    let mut ids = RouterIds::default();
    let first = router_ids(&plan(&inputs, &settings, &mut ids, NOW));
    assert_eq!(first.len(), 3);
    let distinct: BTreeSet<&String> = first.values().collect();
    assert_eq!(distinct.len(), 3, "{first:?}");
    // The same allocator gives the same answer.
    assert_eq!(router_ids(&plan(&inputs, &settings, &mut ids, NOW)), first);
    // A new term restores from the node configs, whatever the hash says.
    let stored: Vec<FlowsdnBGPNodeConfig> = ["w1", "w2", "w3"]
        .iter()
        .map(|n| {
            node_config(
                n,
                Some(("rack-a", "u1")),
                json!({"bgpInstances": [{"name": "i65001", "routerID": format!("10.255.0.{}", 3 - (n.as_bytes()[1] - b'1'))}]}),
            )
        })
        .collect();
    let restored = Inputs {
        node_configs: stored.clone(),
        ..inputs.clone()
    };
    let mut term = RouterIds::default();
    let plan2 = plan(&restored, &settings, &mut term, NOW);
    assert_eq!(
        router_ids(&plan2),
        BTreeMap::from([
            ("w1".into(), "10.255.0.3".into()),
            ("w2".into(), "10.255.0.2".into()),
            ("w3".into(), "10.255.0.1".into())
        ])
    );
    // A fourth node takes the one address left, a fifth finds none.
    let more = Inputs {
        nodes: nodes(&[("w1", &[]), ("w2", &[]), ("w3", &[]), ("w4", &[]), ("w5", &[])]),
        ..restored.clone()
    };
    let plan3 = plan(&more, &settings, &mut term, NOW);
    let ids3 = router_ids(&plan3);
    let w4 = ids3.get("w4").or(ids3.get("w5")).expect("one allocated");
    assert_eq!(w4, "10.255.0.0");
    assert_eq!(plan3.errors.len(), 1, "{:?}", plan3.errors);
    assert!(plan3.errors[0].contains("exhausted"));
    // w3 leaves: its node config is deleted and its address freed.
    let fewer = Inputs {
        nodes: nodes(&[("w1", &[]), ("w2", &[])]),
        ..restored
    };
    let plan4 = plan(&fewer, &settings, &mut term, NOW);
    assert!(plan4.writes.contains(&Write::Delete {
        name: "w3".into(),
        uid: "nc-w3".into()
    }));
    assert!(!term.holders.contains_key(&Ipv4Addr::new(10, 255, 0, 1)));
    // No cluster config at all: the allocator is cleared.
    let none = Inputs::default();
    let _ = plan(&none, &settings, &mut term, NOW);
    assert!(term.by_key.is_empty() && term.holders.is_empty());
}

#[test]
fn override_router_ids_inside_and_outside_the_pool() {
    let settings = pool_settings("10.255.0.0/30");
    let over = |node: &str, ip: &str| -> FlowsdnBGPNodeConfigOverride {
        serde_json::from_value(json!({"metadata": {"name": node},
            "spec": {"bgpInstances": [{"name": "i65001", "routerID": ip}]}}))
        .expect("override")
    };
    let base = Inputs {
        clusters: vec![cluster("rack-a", "u1", rack(Value::Null))],
        nodes: nodes(&[("w1", &[]), ("w2", &[])]),
        ..Inputs::default()
    };
    // Outside: used verbatim, holding nothing in the pool.
    let mut ids = RouterIds::default();
    let outside = Inputs {
        overrides: vec![over("w1", "192.0.2.1")],
        ..base.clone()
    };
    let got = router_ids(&plan(&outside, &settings, &mut ids, NOW));
    assert_eq!(got["w1"], "192.0.2.1");
    assert!(!ids.by_key.contains_key(&("w1".into(), "i65001".into())));
    // Inside and free: taken.
    let mut ids = RouterIds::default();
    let inside = Inputs {
        overrides: vec![over("w1", "10.255.0.2")],
        ..base.clone()
    };
    let plan1 = plan(&inside, &settings, &mut ids, NOW);
    assert!(plan1.errors.is_empty(), "{:?}", plan1.errors);
    assert_eq!(router_ids(&plan1)["w1"], "10.255.0.2");
    assert_ne!(router_ids(&plan1)["w2"], "10.255.0.2");
    // Inside and held by another key: that node errors, naming the holder;
    // the other node is still written.
    let mut ids = RouterIds::default();
    ids.hold(("w2".into(), "i65001".into()), Ipv4Addr::new(10, 255, 0, 2));
    ids.restored = true;
    let plan2 = plan(&inside, &settings, &mut ids, NOW);
    assert_eq!(plan2.errors.len(), 1);
    assert!(plan2.errors[0].contains("held by node w2"), "{}", plan2.errors[0]);
    assert_eq!(router_ids(&plan2).keys().collect::<Vec<_>>(), vec!["w2"]);
    // Not IPv4 at all.
    let mut ids = RouterIds::default();
    let bad = Inputs {
        overrides: vec![over("w1", "not-an-ip")],
        ..base
    };
    assert!(plan(&bad, &settings, &mut ids, NOW).errors[0].contains("not IPv4"));
}

#[test]
fn a_pass_reads_writes_and_tolerates_conflicts() {
    let settings = BgpSettings {
        secrets_namespace: Some("bgp".into()),
        ..enabled()
    };
    let mut calls: Vec<(String, String)> = Vec::new();
    type Reply = Result<(u16, Value), flowsdn_k8s::Error>;
    let mut send = |method: http::Method, path: &str, body: Option<&Value>| -> Reply {
        calls.push((method.to_string(), path.to_owned()));
        let list = |items: Value| -> Reply { Ok((200, json!({"items": items}))) };
        match (method.as_str(), path) {
            ("GET", "/apis/flowsdn.io/v1alpha1/flowsdnbgpclusterconfigs") => list(json!([
                serde_json::to_value(cluster("rack-a", "u1", rack(Value::Null))).expect("c")
            ])),
            ("GET", "/apis/flowsdn.io/v1alpha1/flowsdnbgppeerconfigs") => list(json!([
                {"metadata": {"name": "tor"}, "spec": {"authSecretRef": "tor-md5"}}
            ])),
            ("GET", "/apis/flowsdn.io/v1alpha1/flowsdnbgpnodeconfigoverrides") => list(json!([])),
            ("GET", "/apis/flowsdn.io/v1alpha1/flowsdnbgpnodeconfigs") => list(json!([])),
            ("GET", "/apis/flowsdn.io/v1alpha1/flowsdnnodes") => list(json!([
                {"metadata": {"name": "w1", "labels": {"rack": "a"}}},
                {"metadata": {"name": "w2"}}
            ])),
            ("GET", "/api/v1/namespaces/bgp/secrets") => list(json!([
                {"metadata": {"name": "tor-md5"}, "data": {"password": "c2VjcmV0"}}
            ])),
            ("POST", "/apis/flowsdn.io/v1alpha1/flowsdnbgpnodeconfigs") => {
                let name = body
                    .and_then(|b| b.pointer("/metadata/name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // w2 was created meanwhile by someone else.
                Ok((if name == "w2" { 409 } else { 201 }, json!({})))
            }
            ("PUT", _) if path.ends_with("/status") => Ok((200, json!({}))),
            _ => Ok((500, json!({"message": format!("unexpected {method} {path}")}))),
        }
    };
    let (summary, errors) =
        run(&settings, &mut RouterIds::default(), NOW, &mut send).expect("pass");
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(
        summary,
        Summary {
            created: 1,
            updated: 0,
            deleted: 0,
            statuses: 2,
            skipped: 1
        }
    );
    assert!(calls.contains(&(
        "PUT".into(),
        "/apis/flowsdn.io/v1alpha1/flowsdnbgpclusterconfigs/rack-a/status".into()
    )));
    assert!(calls.contains(&(
        "PUT".into(),
        "/apis/flowsdn.io/v1alpha1/flowsdnbgppeerconfigs/tor/status".into()
    )));
    // A list failure aborts the pass before any write.
    let mut failing = |method: http::Method, path: &str, _: Option<&Value>| -> Reply {
        assert_eq!(method, http::Method::GET, "no write after a failed list");
        Ok((if path.ends_with("flowsdnbgppeerconfigs") { 403 } else { 200 }, json!({"items": []})))
    };
    assert!(run(&settings, &mut RouterIds::default(), NOW, &mut failing).is_err());
}
