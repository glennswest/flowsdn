//! The node's own flowsdn, read-only through the host mounts the suite
//! declares (`/opt/cni/bin`, `/run`). flowsdn is a flavor: a node without its
//! CNI does not run it, and that is a skip, never a pass. The agent is only
//! probed where flowsdn's CNI is installed, and then its ClusterIP Services
//! (`services`, #292) from this pod's network.
use crate::{env::Env, report::Report};
use flowsdn_api_client::Client;
use std::time::{Duration, Instant};

/// Sockets one directory below the host's run directories, `flowsdn/`
/// first; the first that answers `GET /v1/healthz` with 200.
fn find_agent(env: &Env) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    let mut sockets = Vec::new();
    for dir in ["/var/run", "/run"] {
        let Ok(list) = std::fs::read_dir(env.host(dir)) else {
            continue;
        };
        for entry in list.filter_map(|e| e.ok()) {
            let Ok(inner) = std::fs::read_dir(entry.path()) else {
                continue;
            };
            for file in inner.filter_map(|e| e.ok()) {
                if file.file_type().is_ok_and(|t| t.is_socket()) {
                    sockets.push(file.path());
                }
            }
        }
    }
    sockets.sort_by_key(|p| !p.to_string_lossy().contains("/flowsdn/"));
    sockets.into_iter().find(|socket| {
        Client::new(socket, Duration::from_secs(2))
            .request(flowsdn_api_client::Method::Get, "/v1/healthz", None)
            .is_ok_and(|reply| reply.status == 200)
    })
}

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
    // The agent's socket is wherever the node's release put it (the current
    // manifests use /var/run/flowsdn; earlier releases another directory):
    // the first socket under the host's run directories that answers
    // GET /v1/healthz is the agent.
    let Some(socket) = find_agent(env) else {
        report.fail(
            "node-agent",
            start.elapsed(),
            &format!(
                "flowsdn CNI installed but no socket under /var/run/*/ or /run/*/ answers GET /v1/healthz; seen: {}",
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
        Ok((
            (),
            format!("agent healthy at {}; {count} endpoints", socket.display()),
        ))
    });
    if healthy.is_some() {
        crate::services::probe(report, &socket);
    }
}
