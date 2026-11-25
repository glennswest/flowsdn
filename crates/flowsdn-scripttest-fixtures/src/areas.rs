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
pub const AREAS: [&str; 1] = ["k8sclient"];

/// The engine for one script of `area`, with the script's `#!` flags.
pub fn build(area: &str, flags: &[String]) -> Result<Engine, String> {
    match area {
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
