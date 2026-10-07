//! The node's own flowsdn, read-only through the host mounts the suite
//! declares (`/opt/cni/bin`, `/run`). flowsdn is a flavor: a node without its
//! CNI does not run it, and that is a skip, never a pass. The agent is only
//! probed where flowsdn's CNI is installed, and then its ClusterIP Services
//! (`services`, #292) from this pod's network.
use crate::{env::Env, report::Report};
use flowsdn_api_client::Client;
use std::time::{Duration, Instant};

/// What the pod sees of the host's run directories, for a missing socket:
/// whether each mount is there, and the entries of its flowsdn directory.
fn seen(env: &Env) -> String {
    ["/var/run", "/run"]
        .iter()
        .map(|dir| {
            let root = env.host(dir);
            let entries = |path: &std::path::Path| -> String {
                std::fs::read_dir(path).map_or_else(
                    |e| e.to_string(),
                    |list| {
                        let mut names: Vec<String> = list
                            .filter_map(|e| e.ok())
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect();
                        names.sort();
                        names.truncate(12);
                        names.join(",")
                    },
                )
            };
            format!(
                "{dir}: [{}] flowsdn: [{}]",
                entries(&root),
                entries(&root.join("flowsdn"))
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

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
    // The manifests' hostPath is /var/run/flowsdn; /run is where a host
    // with /var/run -> /run shows it.
    let Some(socket) = ["/var/run/flowsdn/flowsdn.sock", "/run/flowsdn/flowsdn.sock"]
        .iter()
        .map(|p| env.host(p))
        .find(|p| p.exists())
    else {
        report.fail(
            "node-agent",
            start.elapsed(),
            &format!(
                "flowsdn CNI installed but no agent socket at /var/run/flowsdn/flowsdn.sock or /run/flowsdn/flowsdn.sock; seen: {}",
                seen(env)
            ),
        );
        return;
    };
    let healthy = report.check("node-agent", || {
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
    if healthy.is_some() {
        crate::services::probe(report, &socket);
    }
}
