//! The node's own flowsdn, read-only through the host mounts the suite
//! declares (`/opt/cni/bin`, `/run`). flowsdn is a flavor: a node without its
//! CNI does not run it, and that is a skip, never a pass. The agent is only
//! probed where flowsdn's CNI is installed, then the flowsdn operator
//! (`node-operator`, #446, through the apiserver), and then its ClusterIP
//! Services (`services`, #292) from this pod's network.
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
    operator(report, env);
    if healthy.is_some() {
        host_firewall(report, &socket);
        crate::services::probe(report, &socket);
    }
}

/// The host firewall on the node's uplinks (#478): `kubernetes.policy.host-firewall`
/// of `/v1/healthz` and the host's rows of `/v1/policy/verdicts`, GETs only.
/// Off on this node (`null`) is a skip. On, it passes once every interface it
/// is on has left its 60 s learning window and it judges on at least one; the
/// detail says the mode, the interfaces, the local Pods' path, the node's
/// addresses and what the host's verdict rows counted.
fn host_firewall(report: &mut Report, socket: &std::path::Path) {
    const LIMIT: Duration = Duration::from_secs(120);
    let client = Client::new(socket, Duration::from_secs(2));
    let get = |path: &str| -> Result<serde_json::Value, String> {
        let reply = client
            .request(flowsdn_api_client::Method::Get, path, None)
            .map_err(|e| format!("GET {path}: {e}"))?;
        if reply.status != 200 {
            return Err(format!("GET {path} returned {}", reply.status));
        }
        reply.json.ok_or_else(|| format!("GET {path}: not JSON"))
    };
    let start = Instant::now();
    let firewall = loop {
        let health = match get("/v1/healthz") {
            Ok(health) => health,
            Err(error) => return report.fail("node-host-firewall", start.elapsed(), &error),
        };
        let Some(policy) = health.pointer("/kubernetes/policy").filter(|p| !p.is_null()) else {
            if start.elapsed() > LIMIT {
                return report.fail(
                    "node-host-firewall",
                    start.elapsed(),
                    "kubernetes.policy is still null (no policy pass)",
                );
            }
            std::thread::sleep(Duration::from_secs(2));
            continue;
        };
        let firewall = policy.get("host-firewall").cloned().unwrap_or_default();
        if firewall.is_null() {
            return report.skip("node-host-firewall", "kubernetes.host-firewall is off on this node");
        }
        let learning = firewall.get("learning").and_then(|l| l.as_array()).map_or(0, Vec::len);
        if learning == 0 || start.elapsed() > LIMIT {
            break firewall;
        }
        std::thread::sleep(Duration::from_secs(2));
    };
    report.check("node-host-firewall", || {
        let list = |key: &str| -> Vec<String> {
            firewall
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mode = firewall.get("mode").and_then(|m| m.as_str()).unwrap_or("?").to_owned();
        let interfaces = list("interfaces");
        let learning = list("learning");
        let judging = list("enforcing-on");
        let addresses = list("addresses");
        let pods = firewall
            .get("pods")
            .map_or_else(String::new, |p| p.as_str().map_or_else(|| p.to_string(), str::to_owned));
        let policies = list("policies");
        let verdicts = get("/v1/policy/verdicts")?;
        let rows = verdicts
            .as_array()
            .or_else(|| verdicts.get("verdicts").and_then(|v| v.as_array()))
            .cloned()
            .unwrap_or_default();
        let mut counted = std::collections::BTreeMap::<String, u64>::new();
        for row in rows.iter().filter(|r| r.get("endpoint").and_then(|e| e.as_str()) == Some("host")) {
            let verdict = row.get("verdict").and_then(|v| v.as_str()).unwrap_or("?").to_owned();
            let packets = row.get("packets").and_then(serde_json::Value::as_u64).unwrap_or(0);
            *counted.entry(verdict).or_default() += packets;
        }
        let counted = counted
            .iter()
            .map(|(verdict, packets)| format!("{verdict} {packets}"))
            .collect::<Vec<_>>()
            .join(", ");
        let detail = format!(
            "mode {mode}; on [{}]; learning [{}]; judging [{}]; local Pods {pods}; addresses [{}]; policies [{}]; host verdicts: {}",
            interfaces.join(" "),
            learning.join(" "),
            judging.join(" "),
            addresses.join(" "),
            policies.join(" "),
            if counted.is_empty() { "none".to_owned() } else { counted },
        );
        if interfaces.is_empty() {
            return Err(format!("on no interface: {detail}"));
        }
        if !learning.is_empty() {
            return Err(format!("still learning after {}s: {detail}", LIMIT.as_secs()));
        }
        if judging.is_empty() {
            return Err(format!("judging on no interface: {detail}"));
        }
        Ok(((), detail))
    });
}

/// The flowsdn operator (#446) on a flowsdn-flavor node: `flowsdn-perf
/// operator` (the image's GNU binary, which has the API client) reads the
/// Lease `kube-system/flowsdn-operator` and the CRD it registers, with the
/// suite's declared cluster reads. Without an apiserver (kernel-check's VM)
/// it is a skip.
fn operator(report: &mut Report, env: &Env) {
    const LIMIT: Duration = Duration::from_secs(60);
    if std::env::var_os("STORM_API").is_none()
        && std::env::var_os("KUBERNETES_SERVICE_HOST").is_none()
    {
        report.skip(
            "node-operator",
            "requires: an apiserver (STORM_API); none in this environment",
        );
        return;
    }
    let perf = env.root.join("bin/flowsdn-perf");
    report.check("node-operator", || {
        let mut child = std::process::Command::new(&perf)
            .arg("operator")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start {}: {e}", perf.display()))?;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                break status;
            }
            if start.elapsed() > LIMIT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "flowsdn-perf operator: no answer in {}s",
                    LIMIT.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let mut line = String::new();
        if let Some(mut out) = child.stdout.take() {
            use std::io::Read;
            let _ = out.read_to_string(&mut line);
        }
        let line = line.trim().to_owned();
        if status.success() {
            Ok(((), line))
        } else {
            Err(if line.is_empty() {
                format!("flowsdn-perf operator: {status}")
            } else {
                line
            })
        }
    });
}
