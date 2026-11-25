//! One builder per corpus area (spec 17 §3.5.1): its fixture, wired by hand,
//! and the command table, merged with the generic and `k8s/*` commands.
use crate::{
    fixture::{self, Fixture, lock},
    k8s::{self, FakeClient},
};
use flowsdn_scripttest::Engine;
use serde_json::json;
use std::sync::{Arc, Mutex};

/// The areas with a builder: the harvested scripts the runner executes.
pub const AREAS: [&str; 9] = [
    "dynamicconfig",
    "hive-health",
    "ipam-migration",
    "ipam-multipool",
    "k8s-tables",
    "k8sclient",
    "metrics",
    "podippool",
    "policy",
];

/// The engine for one script of `area`, with the script's `#!` flags.
pub fn build(area: &str, flags: &[String]) -> Result<Engine, String> {
    match area {
        // The fake API and the agent lifecycle only: flowsdn has none of the
        // reference tables these areas compare (their DIVERGENCES.toml).
        "dynamicconfig" | "k8s-tables" => kubernetes_only(FakeClient::default(), flags),
        "ipam-migration" | "ipam-multipool" | "podippool" => ipam(flags),
        "hive-health" => hive_health(),
        "k8sclient" => k8sclient(flags),
        "metrics" => metrics(flags),
        "policy" => policy(flags),
        other => Err(format!("no fixture for area {other}")),
    }
}

/// `k8sclient` (#516): the fake client alone, with the CiliumNode `test` the
/// reference's test runner adds before every script (`fake.txtar` reads it).
fn k8sclient(flags: &[String]) -> Result<Engine, String> {
    let mut client = FakeClient::default();
    client.add(json!({"apiVersion": "cilium.io/v2", "kind": "CiliumNode",
        "metadata": {"name": "test"}}))?;
    kubernetes_only(client, flags)
}

/// The fake client, `hive/*` and `k8s/*`, with no components.
fn kubernetes_only(client: FakeClient, flags: &[String]) -> Result<Engine, String> {
    let fixture = Fixture::new(client, flags, Box::new(|_| Ok(Vec::new())))?;
    let shared = Arc::new(Mutex::new(fixture));
    let k8s = Arc::clone(&lock(&shared).k8s);
    let mut engine = Engine::new();
    fixture::register_hive(&mut engine, &shared)?;
    k8s::register(&mut engine, &k8s)?;
    Ok(engine)
}

/// Complete a future that never waits (an uncontended table write), without
/// a runtime: the area builders run outside one.
fn ready<F: std::future::Future>(future: F) -> Result<F::Output, String> {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(output) => Ok(output),
        std::task::Poll::Pending => Err("a fixture setup step would block".into()),
    }
}

/// `hive-health` (#516): the health registry, at the reference test's fixed
/// clock (one second past the epoch), holding the state its runner reports
/// before the script: an OK, a degraded, a stopped and two closed scopes.
fn hive_health() -> Result<Engine, String> {
    fn one_second() -> std::time::SystemTime {
        std::time::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(1))
            .unwrap_or(std::time::UNIX_EPOCH)
    }
    let registry = flowsdn_health::Registry::with_clock(one_second);
    let scope = |path: &[&str]| -> Result<flowsdn_health::Reporter, String> {
        let (first, rest) = path.split_first().ok_or("empty scope")?;
        let mut reporter = registry.reporter(first).map_err(|e| e.to_string())?;
        for part in rest {
            reporter = reporter.new_scope(part).map_err(|e| e.to_string())?;
        }
        Ok(reporter)
    };
    let error = |e: flowsdn_table::TableError| e.to_string();
    let c0 = scope(&["agent", "m0", "c0"])?;
    ready(c0.ok("ok"))?.map_err(error)?;
    let closed = scope(&["agent", "m2", "degraded-closed"])?;
    ready(closed.degraded("broken", "err2"))?.map_err(error)?;
    ready(closed.close())?.map_err(error)?;
    let degraded = scope(&["agent", "m2", "degraded"])?;
    ready(degraded.degraded("broken", "err2"))?.map_err(error)?;
    let done = scope(&["agent", "m3", "done"])?;
    ready(done.ok("finished"))?.map_err(error)?;
    ready(done.close())?.map_err(error)?;
    let stopped = scope(&["agent", "m4", "stopped"])?;
    ready(stopped.ok("ok"))?.map_err(error)?;
    ready(stopped.stopped("now stopped"))?.map_err(error)?;
    let mut engine = Engine::new();
    crate::health::register(&mut engine, &registry)?;
    Ok(engine)
}

/// `metrics` (#516): a fixture-owned registry and its sampler, holding the
/// series the reference's test registers (reconstructed from the expected
/// output; its Go setup is not harvested): `test_A` = 1, `test_B` = 2 (a
/// disabled metric: sampled, not listed), and the histogram
/// `test_C_seconds{lbl=a}` with four observations whose percentiles are
/// 10ms, 800ms and 980ms. The sampler takes its first sample on `hive start`.
fn metrics(flags: &[String]) -> Result<Engine, String> {
    use crate::metrics::{DEFAULT_BUCKETS, Metrics, Sampler, Series, Value};
    use std::collections::BTreeMap;
    let mut registry = Metrics::default();
    for (name, value, enabled) in [("test_A", 1.0, true), ("test_B", 2.0, false)] {
        registry.add(Series {
            name: name.into(),
            labels: BTreeMap::new(),
            value: Value::Scalar(value),
            enabled,
        });
    }
    let labels = BTreeMap::from([("lbl".to_owned(), "a".to_owned())]);
    registry.add(Series {
        name: "test_C_seconds".into(),
        labels: labels.clone(),
        value: Value::Histogram {
            bounds: DEFAULT_BUCKETS.to_vec(),
            counts: vec![0; DEFAULT_BUCKETS.len()],
            overflow: 0,
        },
        enabled: true,
    });
    for observation in [0.01, 0.01, 0.1, 1.0] {
        registry.observe("test_C_seconds", &labels, observation);
    }
    let shared = Arc::new(Mutex::new(registry));
    let sampler = Arc::clone(&shared);
    let fixture = Fixture::new(
        FakeClient::default(),
        flags,
        Box::new(move |_| {
            Ok(vec![
                Box::new(Sampler(Arc::clone(&sampler))) as Box<dyn crate::fixture::Component>
            ])
        }),
    )?;
    let fixture = Arc::new(Mutex::new(fixture));
    let mut engine = Engine::new();
    fixture::register_hive(&mut engine, &fixture)?;
    crate::metrics::register(&mut engine, &shared)?;
    Ok(engine)
}

/// `policy` (#518): the fake API, the health table, and the identity,
/// endpoint and policy commands over flowsdn's allocator and watch parser.
fn policy(flags: &[String]) -> Result<Engine, String> {
    let fixture = Fixture::new(FakeClient::default(), flags, Box::new(|_| Ok(Vec::new())))?;
    let shared = Arc::new(Mutex::new(fixture));
    let k8s = Arc::clone(&lock(&shared).k8s);
    let mut engine = Engine::new();
    fixture::register_hive(&mut engine, &shared)?;
    k8s::register(&mut engine, &k8s)?;
    crate::health::register(&mut engine, &flowsdn_health::Registry::new())?;
    crate::policy::register(
        &mut engine,
        &Arc::new(Mutex::new(crate::policy::Policies::default())),
    )?;
    Ok(engine)
}

/// The IPAM areas (#517): the fake API, `hive/*`, `k8s/*` and `ipam/start`.
fn ipam(flags: &[String]) -> Result<Engine, String> {
    let fixture = Fixture::new(FakeClient::default(), flags, Box::new(|_| Ok(Vec::new())))?;
    let shared = Arc::new(Mutex::new(fixture));
    let k8s = Arc::clone(&lock(&shared).k8s);
    let mut engine = Engine::new();
    fixture::register_hive(&mut engine, &shared)?;
    k8s::register(&mut engine, &k8s)?;
    crate::ipam::register(&mut engine, &k8s)?;
    Ok(engine)
}
