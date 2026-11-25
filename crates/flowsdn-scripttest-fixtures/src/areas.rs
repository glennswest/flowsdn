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
pub const AREAS: [&str; 2] = ["hive-health", "k8sclient"];

/// The engine for one script of `area`, with the script's `#!` flags.
pub fn build(area: &str, flags: &[String]) -> Result<Engine, String> {
    match area {
        "hive-health" => hive_health(),
        "k8sclient" => k8sclient(flags),
        other => Err(format!("no fixture for area {other}")),
    }
}

/// `k8sclient` (#516): the fake client alone, with the CiliumNode `test` the
/// reference's test runner adds before every script (`fake.txtar` reads it).
fn k8sclient(flags: &[String]) -> Result<Engine, String> {
    let mut client = FakeClient::default();
    client.add(json!({"apiVersion": "cilium.io/v2", "kind": "CiliumNode",
        "metadata": {"name": "test"}}))?;
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
