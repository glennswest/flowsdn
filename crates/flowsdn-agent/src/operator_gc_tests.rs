use super::*;
use std::cell::RefCell;

fn identity(name: &str, version: &str, heartbeat: bool) -> Value {
    let annotations = if heartbeat {
        json!({HEARTBEAT_ANNOTATION: "2026-11-20T10:00:00Z"})
    } else {
        json!({})
    };
    json!({
        "apiVersion": "flowsdn.io/v1alpha1",
        "kind": "FlowsdnIdentity",
        "metadata": {"name": name, "uid": format!("uid-{name}"),
            "resourceVersion": version, "annotations": annotations},
        "security-labels": {"k8s:app": name},
    })
}
fn settings() -> Settings {
    Settings {
        identity_interval: Duration::from_secs(900),
        heartbeat_timeout: Duration::from_secs(1800),
        rate_limit: 2,
        rate_interval: Duration::from_secs(60),
        nodes_interval: Duration::from_secs(300),
    }
}
fn used(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}
fn mins(n: u64) -> Duration {
    Duration::from_secs(n.saturating_mul(60))
}

#[test]
fn a_new_leader_waits_a_timeout_then_marks_then_deletes_a_timeout_later() {
    let start = Instant::now();
    let mut gc = IdentityGc::new(&settings(), start);
    let at = |m| start.checked_add(mins(m)).expect("time");
    let list = [identity("300", "1", false), identity("301", "1", false)];
    // 301 is used by an endpoint throughout; 300 by nothing.
    let (actions, alive) = gc.plan(at(0), "w0", &list, &used(&["301"]));
    assert!(actions.is_empty());
    assert_eq!(alive, 1);
    let (actions, _) = gc.plan(at(30), "w30", &list, &used(&["301"]));
    assert!(actions.is_empty(), "not older than the timeout yet");
    let (actions, _) = gc.plan(at(31), "w31", &list, &used(&["301"]));
    let [IdentityAction::Mark { name, object }] = actions.as_slice() else {
        panic!("one mark expected: {actions:?}");
    };
    assert_eq!(name, "300");
    assert_eq!(
        object
            .pointer("/metadata/annotations")
            .and_then(|a| a.get(HEARTBEAT_ANNOTATION)),
        Some(&json!("w31"))
    );
    assert_eq!(
        object.get("security-labels"),
        Some(&json!({"k8s:app": "300"}))
    );
    // The mark's own write is a new resourceVersion: life again.
    let marked = [identity("300", "2", true), identity("301", "1", false)];
    let (actions, _) = gc.plan(at(32), "w32", &marked, &used(&["301"]));
    assert!(actions.is_empty(), "{actions:?}");
    let (actions, _) = gc.plan(at(62), "w62", &marked, &used(&["301"]));
    assert!(actions.is_empty(), "exactly one timeout is not expired");
    let (actions, _) = gc.plan(at(63), "w63", &marked, &used(&["301"]));
    assert_eq!(
        actions,
        vec![IdentityAction::Delete {
            name: "300".into(),
            uid: "uid-300".into(),
            resource_version: "2".into(),
        }]
    );
}

#[test]
fn an_identity_used_again_or_acquired_is_not_collected() {
    let start = Instant::now();
    let mut gc = IdentityGc::new(&settings(), start);
    let at = |m| start.checked_add(mins(m)).expect("time");
    let marked = [identity("400", "5", true)];
    gc.plan(at(0), "w", &marked, &used(&[]));
    // An endpoint uses it before the timeout: alive, never deleted.
    let (actions, alive) = gc.plan(at(40), "w", &marked, &used(&["400"]));
    assert!(actions.is_empty());
    assert_eq!(alive, 1);
    let (actions, _) = gc.plan(at(60), "w", &marked, &used(&[]));
    assert!(actions.is_empty(), "lifesign renewed at 40");
    // An agent removed the annotation (a new resourceVersion) at 80.
    let acquired = [identity("400", "6", false)];
    let (actions, _) = gc.plan(at(80), "w", &acquired, &used(&[]));
    assert!(actions.is_empty());
    let (actions, _) = gc.plan(at(105), "w", &acquired, &used(&[]));
    assert!(actions.is_empty(), "lifesign renewed at 80");
}

#[test]
fn an_identity_created_after_the_first_list_counts_from_when_it_is_seen() {
    let start = Instant::now();
    let mut gc = IdentityGc::new(&settings(), start);
    let at = |m| start.checked_add(mins(m)).expect("time");
    gc.plan(at(0), "w", &[], &used(&[]));
    let (actions, _) = gc.plan(at(20), "w", &[identity("500", "1", false)], &used(&[]));
    assert!(actions.is_empty());
    let (actions, _) = gc.plan(at(45), "w", &[identity("500", "1", false)], &used(&[]));
    assert!(actions.is_empty(), "seen at 20, not 0");
    let (actions, _) = gc.plan(at(51), "w", &[identity("500", "1", false)], &used(&[]));
    assert_eq!(actions.len(), 1);
}

#[test]
fn used_ids_come_from_endpoints_and_slices() {
    let endpoints = json!({"items": [
        {"status": {"identity": {"id": 300}}},
        {"status": {"identity": {}}},
        {"status": {}},
    ]});
    let slices = json!({"items": [{"endpoints": [{"id": 301}, {"name": "x"}]}]});
    assert_eq!(
        used_identities(&endpoints, Some(&slices)),
        used(&["300", "301"])
    );
    assert_eq!(used_identities(&endpoints, None), used(&["300"]));
}

#[test]
fn the_limiter_admits_its_limit_per_window() {
    let start = Instant::now();
    let mut limiter = Limiter::new(2, Duration::from_secs(60));
    assert!(limiter.admit(start));
    assert!(limiter.admit(start));
    assert!(!limiter.admit(start.checked_add(Duration::from_secs(59)).expect("t")));
    assert!(limiter.admit(start.checked_add(Duration::from_secs(60)).expect("t")));
}

/// A fake API: lists from `lists`, records writes, answers each write
/// with `status`.
fn fake<'a>(
    lists: &'a BTreeMap<&'static str, (u16, Value)>,
    writes: &'a RefCell<Vec<(String, String, Option<Value>)>>,
    status: u16,
) -> impl FnMut(http::Method, &str, Option<&Value>) -> Result<(u16, Value), flowsdn_k8s::Error> + 'a
{
    move |method, path, body| {
        if method == http::Method::GET {
            return Ok(lists.get(path).cloned().unwrap_or((404, Value::Null)));
        }
        writes
            .borrow_mut()
            .push((method.to_string(), path.to_owned(), body.cloned()));
        Ok((status, Value::Null))
    }
}

#[test]
fn identity_gc_run_marks_deletes_with_preconditions_and_respects_the_rate_limit() {
    let start = Instant::now();
    let mut gc = IdentityGc::new(&settings(), start);
    let later = start.checked_add(mins(31)).expect("time");
    let lists = BTreeMap::from([
        (
            IDENTITIES,
            (
                200,
                json!({"items": [
                    identity("300", "1", true),
                    identity("301", "1", true),
                    identity("302", "1", true),
                    identity("303", "1", false),
                    identity("304", "1", true),
                ]}),
            ),
        ),
        (
            ENDPOINTS,
            (200, json!({"items": [{"status": {"identity": {"id": 304}}}]})),
        ),
    ]);
    let writes = RefCell::new(Vec::new());
    gc.plan(start, "w", &[], &BTreeSet::new());
    // First listed at `later`: not the term's first list, so counts from now.
    let mut send = fake(&lists, &writes, 200);
    let summary = identity_gc(&mut gc, later, "w", &mut send).expect("run");
    assert_eq!(summary, IdentitySummary { alive: 1, ..Default::default() });
    let much_later = later.checked_add(mins(31)).expect("time");
    let summary = identity_gc(&mut gc, much_later, "w", &mut send).expect("run");
    assert_eq!(
        summary,
        IdentitySummary {
            alive: 1,
            marked: 1,
            deleted: 2,
            skipped: 0,
            deferred: 1,
        }
    );
    let writes = writes.into_inner();
    assert_eq!(writes.len(), 3);
    let (method, path, body) = writes.first().expect("delete");
    assert_eq!(method, "DELETE");
    assert_eq!(path, &format!("{IDENTITIES}/300"));
    assert_eq!(
        body.as_ref().and_then(|b| b.get("preconditions")),
        Some(&json!({"uid": "uid-300", "resourceVersion": "1"}))
    );
    let mark = writes.iter().find(|(m, _, _)| m == "PUT").expect("mark");
    assert_eq!(mark.1, format!("{IDENTITIES}/303"));
    assert!(
        writes.iter().all(|(_, p, _)| !p.ends_with("/304")),
        "a used identity is never written"
    );
}

#[test]
fn identity_gc_conflicts_are_skipped_and_a_failed_list_writes_nothing() {
    let start = Instant::now();
    let mut gc = IdentityGc::new(&settings(), start);
    let lists = BTreeMap::from([
        (IDENTITIES, (200, json!({"items": [identity("300", "1", true)]}))),
        (ENDPOINTS, (200, json!({"items": []}))),
    ]);
    let writes = RefCell::new(Vec::new());
    let mut send = fake(&lists, &writes, 409);
    identity_gc(&mut gc, start, "w", &mut send).expect("first");
    let later = start.checked_add(mins(31)).expect("time");
    let summary = identity_gc(&mut gc, later, "w", &mut send).expect("run");
    assert_eq!(summary.skipped, 1);
    assert_eq!(summary.deleted, 0);

    let broken = BTreeMap::from([
        (IDENTITIES, (200, json!({"items": [identity("300", "1", true)]}))),
        (ENDPOINTS, (403, json!({"message": "forbidden"}))),
    ]);
    let none = RefCell::new(Vec::new());
    let mut send = fake(&broken, &none, 200);
    let error = identity_gc(&mut gc, later, "w", &mut send).expect_err("list failed");
    assert!(error.contains("403 forbidden"), "{error}");
    assert!(none.into_inner().is_empty());
}

fn flowsdn_node(name: &str, owned: bool, do_not_gc: Option<&str>) -> Value {
    let owners = if owned {
        json!([{"apiVersion": "v1", "kind": "Node", "name": name, "uid": "u"}])
    } else {
        json!([])
    };
    let annotations = do_not_gc.map_or_else(|| json!({}), |value| json!({DO_NOT_GC: value}));
    json!({"metadata": {"name": name, "ownerReferences": owners, "annotations": annotations}})
}

#[test]
fn node_gc_deletes_an_orphan_after_one_interval_as_a_candidate() {
    let start = Instant::now();
    let mut gc = NodeGc::new(&settings());
    let at = |m| start.checked_add(mins(m)).expect("time");
    let list = [
        flowsdn_node("gone", false, None),
        flowsdn_node("owned", true, None),
        flowsdn_node("kept", false, Some("TRUE")),
        flowsdn_node("other", false, Some("false")),
        flowsdn_node("live", false, None),
    ];
    let nodes = used(&["live"]);
    assert!(gc.plan(at(0), &list, &nodes).is_empty(), "candidates first");
    assert!(gc.plan(at(4), &list, &nodes).is_empty());
    assert_eq!(gc.plan(at(5), &list, &nodes), vec!["gone", "other"]);
    // A Node that comes back ends the candidacy.
    let back = [flowsdn_node("node9", false, None)];
    gc.plan(at(10), &back, &used(&[]));
    gc.plan(at(12), &back, &used(&["node9"]));
    assert!(gc.plan(at(16), &back, &used(&[])).is_empty(), "candidate again from 16");
    assert_eq!(gc.plan(at(21), &back, &used(&[])), vec!["node9"]);
}

#[test]
fn node_gc_run_deletes_and_treats_not_found_as_done() {
    let start = Instant::now();
    let mut gc = NodeGc::new(&settings());
    let lists = BTreeMap::from([
        (
            FLOWSDN_NODES,
            (200, json!({"items": [flowsdn_node("gone", false, None)]})),
        ),
        (NODES, (200, json!({"items": [{"metadata": {"name": "live"}}]}))),
    ]);
    let writes = RefCell::new(Vec::new());
    let mut send = fake(&lists, &writes, 404);
    assert!(node_gc(&mut gc, start, &mut send).expect("run").is_empty());
    let later = start.checked_add(mins(5)).expect("time");
    assert_eq!(node_gc(&mut gc, later, &mut send).expect("run"), vec!["gone"]);
    let writes = writes.into_inner();
    assert_eq!(
        writes,
        vec![("DELETE".to_owned(), format!("{FLOWSDN_NODES}/gone"), None)]
    );
}
