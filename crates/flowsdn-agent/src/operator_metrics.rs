//! The operator's `GET /metrics` (#420): what the leader did, for the node's
//! scraper (stormcos#64), Prometheus text format 0.0.4, names under
//! `flowsdn_operator_`. `--metrics-listen` (loopback only; the edition
//! manifests use `127.0.0.1:9967`) serves it from a thread of its own, so a
//! scrape never waits on the operator's loop. Counters count since the
//! process started; gauges are the latest pass.
use crate::api::metrics::family;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// What the operator has done.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub leading: bool,
    /// CRDs established at the last registration.
    pub crds_established: Option<usize>,
    pub crd_registration_failures: u64,
    pub identity_gc_runs: u64,
    pub identity_gc_failures: u64,
    /// Identities in use at the last identity GC run.
    pub identities_alive: Option<usize>,
    pub identities_marked: u64,
    pub identities_deleted: u64,
    pub identities_skipped: u64,
    pub identities_deferred: u64,
    pub node_gc_runs: u64,
    pub node_gc_failures: u64,
    pub nodes_deleted: u64,
    pub bgp_enabled: bool,
    pub bgp_passes: u64,
    pub bgp_pass_failures: u64,
    /// The last BGP pass's errors (it went on past them).
    pub bgp_errors: usize,
    pub bgp_created: u64,
    pub bgp_updated: u64,
    pub bgp_deleted: u64,
    pub bgp_statuses: u64,
}

/// Stats shared between the operator's loop and the metrics thread.
#[derive(Clone, Debug, Default)]
pub struct Shared(Arc<Mutex<Stats>>);
impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, Stats> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The exposition of `stats`.
pub fn render(stats: &Stats) -> String {
    let mut out = String::new();
    let gauge = |out: &mut String, name: &str, help: &str, value: u64| {
        family(out, name, "gauge", help).sample(name, &[], value);
    };
    family(
        &mut out,
        "flowsdn_operator_build_info",
        "gauge",
        "The running operator's version (always 1).",
    )
    .sample(
        "flowsdn_operator_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );
    gauge(
        &mut out,
        "flowsdn_operator_leader",
        "1 while this operator holds the kube-system/flowsdn-operator Lease.",
        u64::from(stats.leading),
    );
    if let Some(n) = stats.crds_established {
        gauge(
            &mut out,
            "flowsdn_operator_crds_established",
            "flowsdn.io CRDs established at the last registration.",
            u64::try_from(n).unwrap_or(u64::MAX),
        );
    }
    if let Some(n) = stats.identities_alive {
        gauge(
            &mut out,
            "flowsdn_operator_identities_alive",
            "FlowsdnIdentities in use at the last identity GC run.",
            u64::try_from(n).unwrap_or(u64::MAX),
        );
    }
    if stats.bgp_enabled {
        gauge(
            &mut out,
            "flowsdn_operator_bgp_errors",
            "Errors of the last BGP pass (node configs or statuses it could not write).",
            u64::try_from(stats.bgp_errors).unwrap_or(u64::MAX),
        );
    }
    let counters: [(&str, &str, u64); 16] = [
        (
            "flowsdn_operator_crd_registration_failures_total",
            "CRD registrations that failed and were retried.",
            stats.crd_registration_failures,
        ),
        (
            "flowsdn_operator_identity_gc_runs_total",
            "Identity GC runs that completed.",
            stats.identity_gc_runs,
        ),
        (
            "flowsdn_operator_identity_gc_failures_total",
            "Identity GC runs that failed (retried after 30 s).",
            stats.identity_gc_failures,
        ),
        (
            "flowsdn_operator_identities_marked_total",
            "FlowsdnIdentities marked unused.",
            stats.identities_marked,
        ),
        (
            "flowsdn_operator_identities_deleted_total",
            "FlowsdnIdentities deleted.",
            stats.identities_deleted,
        ),
        (
            "flowsdn_operator_identities_skipped_total",
            "Identity deletes refused because the object changed or went.",
            stats.identities_skipped,
        ),
        (
            "flowsdn_operator_identities_deferred_total",
            "Identity deletes left for a later run by the rate limit.",
            stats.identities_deferred,
        ),
        (
            "flowsdn_operator_node_gc_runs_total",
            "FlowsdnNode GC runs that completed.",
            stats.node_gc_runs,
        ),
        (
            "flowsdn_operator_node_gc_failures_total",
            "FlowsdnNode GC runs that failed.",
            stats.node_gc_failures,
        ),
        (
            "flowsdn_operator_nodes_deleted_total",
            "FlowsdnNodes deleted (no Node, no owner).",
            stats.nodes_deleted,
        ),
        (
            "flowsdn_operator_bgp_passes_total",
            "BGP passes that completed.",
            stats.bgp_passes,
        ),
        (
            "flowsdn_operator_bgp_pass_failures_total",
            "BGP passes that could not read their inputs.",
            stats.bgp_pass_failures,
        ),
        (
            "flowsdn_operator_bgp_node_configs_created_total",
            "FlowsdnBGPNodeConfigs created.",
            stats.bgp_created,
        ),
        (
            "flowsdn_operator_bgp_node_configs_updated_total",
            "FlowsdnBGPNodeConfigs updated.",
            stats.bgp_updated,
        ),
        (
            "flowsdn_operator_bgp_node_configs_deleted_total",
            "FlowsdnBGPNodeConfigs deleted.",
            stats.bgp_deleted,
        ),
        (
            "flowsdn_operator_bgp_statuses_written_total",
            "BGP cluster and peer config statuses written.",
            stats.bgp_statuses,
        ),
    ];
    for (name, help, value) in counters {
        family(&mut out, name, "counter", help).sample(name, &[], value);
    }
    out
}

/// The answer to one request: `GET /metrics` (HTTP/1.0 or 1.1) is the
/// exposition, another path 404, another method 405.
pub fn answer(request: &[u8], stats: &Stats) -> Vec<u8> {
    let line = request
        .split(|b| *b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim_end().to_owned())
        .unwrap_or_default();
    let mut parts = line.split(' ');
    let (method, path, version) = (parts.next(), parts.next(), parts.next());
    let (status, body, kind) = match (method, path, version) {
        (_, _, Some(v)) if v != "HTTP/1.1" && v != "HTTP/1.0" => {
            ("400 Bad Request", "bad request\n".to_owned(), "text/plain")
        }
        (Some("GET"), Some("/metrics"), _) => (
            "200 OK",
            render(stats),
            "text/plain; version=0.0.4; charset=utf-8",
        ),
        (Some("GET"), Some(_), _) => ("404 Not Found", "only /metrics\n".to_owned(), "text/plain"),
        (Some(_), Some(_), _) => (
            "405 Method Not Allowed",
            "only GET\n".to_owned(),
            "text/plain",
        ),
        _ => ("400 Bad Request", "bad request\n".to_owned(), "text/plain"),
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn serve_one(mut stream: TcpStream, shared: &Shared) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buffer = [0u8; 4096];
    let mut used = 0usize;
    // Read until the end of the headers, or the buffer is full.
    while used < buffer.len() {
        match stream.read(buffer.get_mut(used..).unwrap_or(&mut [])) {
            Ok(0) | Err(_) => break,
            Ok(n) => used = used.saturating_add(n),
        }
        if buffer.get(..used).is_some_and(|b| b.windows(4).any(|w| w == b"\r\n\r\n")) {
            break;
        }
    }
    let stats = shared.lock().clone();
    let _ = stream.write_all(&answer(buffer.get(..used).unwrap_or(&[]), &stats));
}

/// Parse `--metrics-listen`: a loopback `IP:port` with a nonzero port.
pub fn parse_listen(text: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = text
        .parse()
        .map_err(|_| format!("--metrics-listen needs IP:port, got {text:?}"))?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(format!(
            "--metrics-listen {address}: a loopback address with a nonzero port"
        ));
    }
    Ok(address)
}

/// Serve `GET /metrics` on `address` from a thread of its own.
pub fn spawn(address: SocketAddr, shared: Shared) -> Result<(), String> {
    let listener = TcpListener::bind(address).map_err(|e| format!("{address}: {e}"))?;
    // Also to the kernel log, where a node's syslog sees it (#420, #484).
    crate::log::noticeln!("operator metrics listening on http://{address}/metrics");
    std::thread::Builder::new()
        .name("operator-metrics".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => serve_one(stream, &shared),
                    Err(error) => crate::log::logln!("operator metrics: accept: {error}"),
                }
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
#[path = "operator_metrics_tests.rs"]
mod tests;
