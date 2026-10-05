use flowsdn_k8s::watch::{Limits, PageResult, Resource, Scope, WatchState};
use serde_json::{Value, json};

fn run(future: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(future);
}
fn pod(name: &str, uid: &str, rv: &str) -> Value {
    json!({"metadata":{"name":name,"namespace":"ns","uid":uid,"resourceVersion":rv,"labels":{"app":"demo"}}, "spec":{"nodeName":"node-a","hostNetwork":false}, "status":{"podIPs":[{"ip":"10.0.0.2"},{"ip":"fd00::2"}]}})
}
fn list(items: Vec<Value>, rv: &str, token: &str) -> Value {
    json!({"metadata":{"resourceVersion":rv,"continue":token},"items":items})
}
fn state(limits: Limits) -> WatchState {
    WatchState::new(
        Scope::LocalPods {
            node_name: "node-a".into(),
        },
        limits,
    )
    .expect("state")
}
fn event(kind: &str, object: Value) -> Value {
    json!({"type":kind,"object":object})
}

#[test]
fn relist_is_atomic_and_failed_pages_preserve_last_snapshot() {
    run(async {
        let mut watch = state(Limits::default());
        watch.begin_list();
        watch
            .list_page(&list(vec![pod("old", "u1", "1")], "2", ""))
            .await
            .expect("initial list");
        let old = watch.snapshot();
        watch.begin_list();
        assert_eq!(
            watch
                .list_page(&list(vec![pod("new", "u2", "3")], "4", "next"))
                .await
                .expect("first page"),
            PageResult::Continue("next".into())
        );
        assert!(
            watch
                .snapshot()
                .get("primary", b"ns/old")
                .expect("lookup")
                .is_some()
        );
        assert!(watch.list_page(&list(vec![], "5", "")).await.is_err());
        assert!(watch.needs_relist());
        assert_eq!(watch.resource_version(), Some("2"));
        assert_eq!(watch.snapshot().revision(), old.revision());
        assert!(
            watch
                .event(&event("ADDED", pod("late", "u3", "6")))
                .await
                .is_err()
        );
        watch.begin_list();
        watch
            .list_page(&list(vec![pod("new", "u2", "7")], "8", "next"))
            .await
            .expect("page");
        watch
            .list_page(&list(vec![pod("last", "u4", "7")], "8", ""))
            .await
            .expect("commit");
        assert_eq!(watch.snapshot().len(), 2);
        assert!(
            watch
                .snapshot()
                .get("primary", b"ns/old")
                .expect("lookup")
                .is_none()
        );
        assert_eq!(old.len(), 1); // previously retained snapshot is immutable
        assert!(!watch.needs_relist());
        assert!(watch.initialized());
    });
}

#[test]
fn stale_uid_delete_cannot_remove_recreated_pod_and_bookmarks_do_not_write() {
    run(async {
        let mut watch = state(Limits::default());
        watch.begin_list();
        watch
            .list_page(&list(vec![pod("same", "old", "1")], "2", ""))
            .await
            .expect("list");
        watch
            .event(&event("ADDED", pod("same", "new", "3")))
            .await
            .expect("recreation");
        let revision = watch.snapshot().revision();
        watch.event(&event("DELETED", json!({"metadata":{"name":"same","namespace":"ns","uid":"old","resourceVersion":"4"}}))).await.expect("stale tombstone");
        assert_eq!(watch.snapshot().revision(), revision);
        assert_eq!(
            watch
                .snapshot()
                .get("primary", b"ns/same")
                .expect("lookup")
                .expect("new pod")
                .0
                .metadata()
                .uid,
            "new"
        );
        watch
            .event(&event(
                "BOOKMARK",
                json!({"metadata":{"resourceVersion":"opaque-rv"}}),
            ))
            .await
            .expect("bookmark");
        assert_eq!(watch.resource_version(), Some("opaque-rv"));
        assert_eq!(watch.snapshot().revision(), revision);
        watch.event(&event("DELETED", json!({"metadata":{"name":"same","namespace":"ns","uid":"new","resourceVersion":"5"}}))).await.expect("current tombstone");
        assert!(watch.snapshot().is_empty());
    });
}

#[test]
fn errors_and_transport_disconnect_require_relist_without_pruning() {
    run(async {
        let mut watch = state(Limits::default());
        watch.begin_list();
        watch
            .list_page(&list(vec![pod("kept", "u1", "1")], "2", ""))
            .await
            .expect("list");
        let revision = watch.snapshot().revision();
        assert!(
            watch
                .event(&event("ERROR", json!({"code":410,"reason":"Expired"})))
                .await
                .is_err()
        );
        assert!(watch.needs_relist());
        assert_eq!(watch.snapshot().revision(), revision);
        watch.begin_list();
        watch
            .list_page(&list(vec![], "3", "more"))
            .await
            .expect("empty page");
        watch.failed();
        assert!(watch.list_page(&list(vec![], "3", "")).await.is_err());
        assert_eq!(watch.snapshot().revision(), revision);
        watch.begin_list();
        watch
            .list_page(&list(vec![], "4", ""))
            .await
            .expect("successful empty relist");
        assert!(watch.snapshot().is_empty());
    });
}

#[test]
fn local_selector_and_slim_parsing_validate_dual_stack() {
    let scope = Scope::LocalPods {
        node_name: "node-a".into(),
    };
    assert_eq!(
        scope.field_selector().as_deref(),
        Some("spec.nodeName=node-a")
    );
    let mut value = pod("pod", "uid", "rv");
    value
        .as_object_mut()
        .expect("pod object")
        .insert("unknown".into(), json!({"ignored":true}));
    let Resource::Pod(parsed) = scope.parse(&value).expect("slim pod") else {
        panic!("pod")
    };
    assert_eq!(parsed.pod_ips.len(), 2);
    assert_eq!(parsed.labels.get("app").map(String::as_str), Some("demo"));
    *value.pointer_mut("/spec/nodeName").expect("node name") = json!("other");
    assert!(scope.parse(&value).is_err());
    let node = json!({"metadata":{"name":"node-b","uid":"uid","resourceVersion":"rv"},"spec":{"podCIDRs":["10.2.0.0/24","fd02::/64"]},"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.2"},{"type":"InternalIP","address":"2001:db8::2"},{"type":"Hostname","address":"node-b"}]}});
    let Resource::Node(parsed) = Scope::Nodes.parse(&node).expect("slim node") else {
        panic!("node")
    };
    assert_eq!(parsed.pod_cidrs.len(), 2);
    assert_eq!(parsed.internal_ips.len(), 2);
}

#[test]
fn bounded_staging_rejects_duplicates_cycles_and_object_overflow() {
    run(async {
        let mut watch = state(Limits {
            max_objects: 2,
            max_pages: 2,
            max_bytes: 4096,
        });
        watch.begin_list();
        assert!(
            watch
                .list_page(&list(
                    vec![pod("same", "a", "1"), pod("same", "b", "1")],
                    "2",
                    ""
                ))
                .await
                .is_err()
        );
        assert!(!watch.initialized());
        watch.begin_list();
        watch
            .list_page(&list(vec![], "2", "repeat"))
            .await
            .expect("page");
        assert!(watch.list_page(&list(vec![], "2", "repeat")).await.is_err());
        watch.begin_list();
        watch
            .list_page(&list(
                vec![pod("a", "a", "1"), pod("b", "b", "1")],
                "2",
                "more",
            ))
            .await
            .expect("two objects");
        assert!(
            watch
                .list_page(&list(vec![pod("c", "c", "1")], "2", ""))
                .await
                .is_err()
        );
        assert!(watch.snapshot().is_empty());
        let mut tiny = state(Limits {
            max_objects: 1,
            max_pages: 1,
            max_bytes: 10,
        });
        tiny.begin_list();
        assert!(tiny.list_page(&list(vec![], "1", "")).await.is_err());
    });
}

#[test]
fn ignored_selector_on_watch_invalidates_stream_without_overwriting_pod() {
    run(async {
        let mut watch = state(Limits::default());
        watch.begin_list();
        watch
            .list_page(&list(vec![pod("a", "u", "1")], "2", ""))
            .await
            .expect("list");
        let revision = watch.snapshot().revision();
        let mut invalid = pod("a", "u", "3");
        *invalid.pointer_mut("/spec/nodeName").expect("node name") = json!("other-node");
        assert!(watch.event(&event("MODIFIED", invalid)).await.is_err());
        assert_eq!(watch.snapshot().revision(), revision);
        assert!(watch.needs_relist());
    });
}

#[test]
fn sparse_and_nullable_optional_fields_remain_empty() {
    let scope = Scope::LocalPods {
        node_name: "node-a".into(),
    };
    for nullable in [false, true] {
        let mut value = json!({"metadata":{"name":"pod","namespace":"ns","uid":"u","resourceVersion":"1"},"spec":{"nodeName":"node-a"}});
        let mut node = json!({"metadata":{"name":"node","uid":"u","resourceVersion":"1"}});
        if nullable {
            value
                .get_mut("metadata")
                .and_then(Value::as_object_mut)
                .expect("pod metadata")
                .insert("labels".into(), Value::Null);
            value
                .get_mut("spec")
                .and_then(Value::as_object_mut)
                .expect("pod spec")
                .insert("hostNetwork".into(), Value::Null);
            value
                .as_object_mut()
                .expect("pod object")
                .insert("status".into(), json!({"podIPs":null,"podIP":null}));
            node.as_object_mut()
                .expect("node object")
                .insert("spec".into(), json!({"podCIDRs":null,"podCIDR":null}));
            node.as_object_mut()
                .expect("node object")
                .insert("status".into(), json!({"addresses":null}));
        }
        let Resource::Pod(parsed) = scope.parse(&value).expect("sparse pod") else {
            panic!("pod")
        };
        assert!(parsed.pod_ips.is_empty() && parsed.labels.is_empty() && !parsed.host_network);
        let Resource::Node(parsed) = Scope::Nodes.parse(&node).expect("sparse node") else {
            panic!("node")
        };
        assert!(parsed.pod_cidrs.is_empty() && parsed.internal_ips.is_empty());
    }
}

#[test]
fn cluster_pod_scope_accepts_every_node_and_unscheduled_pods() {
    assert_eq!(Scope::Pods.field_selector(), None);
    assert!(Scope::Pods.namespaced());
    assert!(!Scope::Nodes.namespaced());
    let mut value = pod("pod", "uid", "rv");
    *value.pointer_mut("/spec/nodeName").expect("node name") = json!("node-b");
    let Resource::Pod(parsed) = Scope::Pods.parse(&value).expect("remote pod") else {
        panic!("pod")
    };
    assert_eq!(parsed.node_name, "node-b");
    value
        .pointer_mut("/spec")
        .and_then(Value::as_object_mut)
        .expect("spec")
        .remove("nodeName");
    let Resource::Pod(parsed) = Scope::Pods.parse(&value).expect("pending pod") else {
        panic!("pod")
    };
    assert_eq!(parsed.node_name, "");
    run(async {
        let mut watch = WatchState::new(Scope::Pods, Limits::default()).expect("state");
        watch.begin_list();
        watch
            .list_page(&list(vec![value.clone()], "1", ""))
            .await
            .expect("list");
        watch.event(&event("DELETED", value)).await.expect("delete");
        assert_eq!(watch.snapshot().len(), 0);
    });
}
