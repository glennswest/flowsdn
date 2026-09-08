#![allow(clippy::unwrap_used)]
use flowsdn_health::{Level, Readiness, Registry, State, metrics, readiness};

#[tokio::test]
async fn unknown_scopes_and_component_validation() {
    let registry = Registry::new();
    let root = registry.reporter("agent").unwrap();
    assert_eq!(
        root.new_scope("lb")
            .unwrap()
            .new_scope("reconciler")
            .unwrap()
            .id(),
        "agent.lb.reconciler"
    );
    assert_eq!(registry.snapshot().all().count(), 0);
    for invalid in ["", "a.b", "a b", "../other", "λ"] {
        assert!(root.new_scope(invalid).is_err());
    }
    root.stopped("never started").await.unwrap();
    let snapshot = registry.snapshot();
    let (row, _) = snapshot.all().next().unwrap();
    assert_eq!(row.level, Level::Stopped);
    assert_eq!(row.last_ok, None);
    assert_eq!(row.count, 1);
}

#[tokio::test]
async fn transitions_preserve_last_ok_and_stop_reason() {
    let registry = Registry::new();
    let reporter = registry.reporter("agent").unwrap();
    reporter.ok("ready").await.unwrap();
    let first = registry.snapshot();
    let (old, _) = first.all().next().unwrap();
    reporter
        .degraded("retrying", "failed target")
        .await
        .unwrap();
    reporter.stopped("shutdown").await.unwrap();
    let snapshot = registry.snapshot();
    let (row, _) = snapshot.all().next().unwrap();
    assert_eq!(row.level, Level::Degraded);
    assert_eq!(row.last_ok, old.last_ok);
    assert_eq!(row.count, 3);
    assert_eq!(row.error, "failed target");
    assert_eq!(row.final_message, "shutdown");
    assert!(row.stopped.is_some());
    assert_eq!(old.level, Level::Ok);
    assert_eq!(old.count, 1);
    reporter.ok("resumed").await.unwrap();
    let snapshot = registry.snapshot();
    let (row, _) = snapshot.all().next().unwrap();
    assert_eq!(row.count, 4);
    assert!(row.stopped.is_none());
    assert!(row.final_message.is_empty());
    assert!(row.error.is_empty());
}

#[tokio::test]
async fn close_publishes_deletion_without_closing_children() {
    let registry = Registry::new();
    let root = registry.reporter("agent").unwrap();
    let child = root.new_scope("child").unwrap();
    root.ok("root").await.unwrap();
    child.ok("child").await.unwrap();
    let mut changes = registry.table().watch(registry.snapshot().revision());
    root.close().await.unwrap();
    assert!(
        matches!(changes.drain(1).first(),Some(flowsdn_table::Change::Delete {key,..}) if key == b"agent")
    );
    assert_eq!(registry.snapshot().all().count(), 1);
    drop(child);
    assert_eq!(registry.snapshot().all().count(), 1);
    root.ok("new report").await.unwrap();
    assert_eq!(
        registry
            .snapshot()
            .get("primary", b"agent")
            .unwrap()
            .unwrap()
            .0
            .count,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_reports_do_not_lose_updates() {
    let registry = Registry::new();
    let reporter = registry.reporter("agent").unwrap();
    let mut tasks = Vec::new();
    for n in 0..100 {
        let reporter = reporter.clone();
        tasks.push(tokio::spawn(async move {
            reporter.ok(n.to_string()).await.unwrap();
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(
        registry
            .snapshot()
            .get("primary", b"agent")
            .unwrap()
            .unwrap()
            .0
            .count,
        100
    );
}

#[tokio::test]
async fn metrics_preserve_levels_and_group_top_level_modules() {
    let registry = Registry::new();
    let root = registry.reporter("agent").unwrap();
    root.ok("ready").await.unwrap();
    root.new_scope("a")
        .unwrap()
        .degraded("a", "failure")
        .await
        .unwrap();
    let nested = root.new_scope("b").unwrap().new_scope("c").unwrap();
    nested.degraded("b", "failure").await.unwrap();
    nested.stopped("done").await.unwrap();
    registry
        .reporter("operator")
        .unwrap()
        .stopped("not started")
        .await
        .unwrap();
    let values = metrics(&registry.snapshot());
    assert_eq!(values.levels.get(&Level::Ok), Some(&1));
    assert_eq!(values.levels.get(&Level::Degraded), Some(&2));
    assert_eq!(values.levels.get(&Level::Stopped), Some(&1));
    assert_eq!(values.degraded_modules.get("agent"), Some(&2));
}

#[tokio::test]
async fn readiness_priorities_and_optional_dependencies() {
    let registry = Registry::new();
    let reporter = registry.reporter("agent").unwrap();
    reporter.degraded("retry", "target").await.unwrap();
    let snapshot = registry.snapshot();
    let mut input = Readiness {
        pending_fence: Some("agent-ready".into()),
        kvstore_configured: true,
        kvstore_failure: Some("unavailable".into()),
        kubernetes_failure: Some("disconnected".into()),
        ..Readiness::default()
    };
    let v = readiness(&snapshot, &input);
    assert_eq!(v.state, State::Failure);
    assert_eq!(v.message, "Not all probes executed at least once");
    input.probes_complete = true;
    let v = readiness(&snapshot, &input);
    assert_eq!((v.http_status, v.state), (500, State::Warning));
    assert!(v.message.contains("agent-ready"));
    input.pending_fence = None;
    assert!(readiness(&snapshot, &input).message.starts_with("kvstore:"));
    input.kvstore_configured = false;
    assert!(
        readiness(&snapshot, &input)
            .message
            .starts_with("kubernetes:")
    );
    input.require_kubernetes = false;
    let v = readiness(&snapshot, &input);
    assert_eq!((v.http_status, v.state), (200, State::Warning));
    assert!(v.message.contains("agent: retry"));
    input.brief = true;
    assert!(readiness(&snapshot, &input).message.is_empty());
    reporter.ok("recovered").await.unwrap();
    assert_eq!(readiness(&registry.snapshot(), &input).state, State::Ok);
}

#[tokio::test]
async fn healthy_empty_registry_requires_probes_but_not_a_synthetic_row() {
    let registry = Registry::new();
    let input = Readiness {
        probes_complete: true,
        ..Readiness::default()
    };
    let v = readiness(&registry.snapshot(), &input);
    assert_eq!((v.http_status, v.state), (200, State::Ok));
}
