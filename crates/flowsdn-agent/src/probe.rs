//! Bounded agent API liveness probe; this is not pod-network readiness.
use flowsdn_api_client::{Client, Limits, Method};
use std::{path::Path, time::Duration};

/// Includes Unix connect (even a saturated backlog), writes, reads and decoding.
pub const DEADLINE: Duration = Duration::from_secs(2);
pub const HEADER_BYTES: usize = 4096;
pub const BODY_BYTES: usize = 4096;

/// Probe only the already-running daemon; never load configuration, restore
/// endpoint state or initialize the datapath in the probing process.
pub fn health(socket: &Path) -> crate::state::Result<()> {
    let response = Client::new(socket, DEADLINE)
        .with_limits(Limits { header_bytes: HEADER_BYTES, body_bytes: BODY_BYTES, wire_bytes: 16_384 })
        .request(Method::Get, "/v1/healthz", None)?;
    if response.status != 200 {
        return Err(format!("agent health returned HTTP {}", response.status).into());
    }
    if response.json.as_ref().and_then(|body| body.pointer("/cilium/state")).and_then(serde_json::Value::as_str) != Some("Ok") {
        return Err("agent health response does not report cilium.state=Ok".into());
    }
    Ok(())
}
