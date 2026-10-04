//! The node's own flowsdn, read-only through the host mounts the suite
//! declares (`/opt/cni/bin`, `/run`). flowsdn is a flavor: a node without its
//! CNI does not run it, and that is a skip, never a pass. A Cilium node has a
//! `cilium.sock` too, so the agent is only probed where flowsdn's CNI is
//! installed.
use crate::{env::Env, report::Report};
use flowsdn_api_client::Client;
use std::time::{Duration, Instant};

pub fn probe(report: &mut Report, env: &Env) {
    let cni_dir = env.host("/opt/cni/bin");
    if !cni_dir.is_dir() {
        report.skip(
            "node-cni",
            "host /opt/cni/bin not mounted (test/requires.toml host_paths_read_only)",
        );
        report.skip("node-agent", "host CNI directory not visible");
        return;
    }
    let start = Instant::now();
    if !cni_dir.join("flowsdn").is_file() {
        report.skip(
            "node-cni",
            "requires: flavor flowsdn; no /opt/cni/bin/flowsdn on this node",
        );
        report.skip("node-agent", "requires: flavor flowsdn");
        return;
    }
    report.pass("node-cni", start.elapsed(), "/opt/cni/bin/flowsdn present");
    let Some(socket) = ["/run/cilium/cilium.sock", "/var/run/cilium/cilium.sock"]
        .iter()
        .map(|p| env.host(p))
        .find(|p| p.exists())
    else {
        report.fail(
            "node-agent",
            start.elapsed(),
            "flowsdn CNI installed but no agent socket at /run/cilium/cilium.sock",
        );
        return;
    };
    report.check("node-agent", || {
        let client = Client::new(&socket, Duration::from_secs(2));
        let health = client
            .request(flowsdn_api_client::Method::Get, "/v1/healthz", None)
            .map_err(|e| format!("GET /v1/healthz: {e}"))?;
        if health.status != 200 {
            return Err(format!("GET /v1/healthz returned {}", health.status));
        }
        let config = client
            .config()
            .map_err(|e| format!("GET /v1/config: {e}"))?;
        if config.status != 200 {
            return Err(format!("GET /v1/config returned {}", config.status));
        }
        let endpoints = client
            .request(flowsdn_api_client::Method::Get, "/v1/endpoint", None)
            .map_err(|e| format!("GET /v1/endpoint: {e}"))?;
        let count = endpoints
            .json
            .as_ref()
            .and_then(|v| v.as_array())
            .map(Vec::len)
            .ok_or_else(|| format!("GET /v1/endpoint returned {}", endpoints.status))?;
        Ok(((), format!("agent healthy; {count} endpoints")))
    });
}
