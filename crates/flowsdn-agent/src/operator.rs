//! `flowsdn-agent operator` (#337, #446): the flowsdn operator. It holds the
//! Lease `kube-system/flowsdn-operator` (one operator acts at a time, spec
//! 12) and, while leading, registers flowsdn's CRDs (spec 13 §3.2,
//! [`flowsdn_k8s::register`]) at once and every five minutes, so a deleted
//! or downgraded CRD comes back. `--skip-crd-creation` leaves the CRDs to an
//! administrator. A CRD whose names the server refuses (`NamesAccepted=False`)
//! is fatal: the process exits naming it. Any other failure is logged and
//! retried after 30 s.
//!
//! While leading it also runs the garbage collectors (#479,
//! [`crate::operator_gc`]): FlowsdnIdentity GC (spec 03 §3.6) every
//! `--identity-gc-interval` and FlowsdnNode GC (spec 12 §3.9) every
//! `--nodes-gc-interval`; their state lasts one leader term.
//!
//! With `--enable-bgp-control-plane` the leader also compiles the BGP
//! cluster configs into per-node FlowsdnBGPNodeConfigs and writes the
//! cluster and peer config conditions every `--bgp-interval` (#334,
//! [`crate::operator_bgp`], spec 15 §3.2).
//!
//! It runs in the same binary as the agent so the flowsdn golden carries it
//! with the agent's runtime; the edition manifests run it as a host-network
//! Deployment (`64-flowsdn-operator.yaml`), since agents wait for the CRDs it
//! registers before their flowsdn.io watchers start.
use crate::lease::{Elector, Step, micro_time};
use crate::operator_bgp::{self, BgpSettings, Pool, RouterIdMode, RouterIds};
use crate::operator_gc::{self, IdentityGc, NodeGc, Settings};
use flowsdn_k8s::client::{JsonClient, TransportLimits};
use flowsdn_k8s::register::{Registered, register, shipped_crds};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

pub const LEASE_NAMESPACE: &str = "kube-system";
pub const LEASE_NAME: &str = "flowsdn-operator";
const LEASE_DURATION: Duration = Duration::from_secs(30);
const TICK: Duration = Duration::from_secs(2);
const REREGISTER: Duration = Duration::from_secs(300);
const RETRY: Duration = Duration::from_secs(30);

pub const HELP: &str = "flowsdn-agent operator — register flowsdn's CRDs under leader election

Usage: flowsdn-agent operator [OPTIONS]

Options:
  --skip-crd-creation                Do not create or update CRDs (an administrator applies them)
  --kubeconfig PATH                  Explicit kubeconfig (default: the in-cluster service account)
  --identity-gc-interval SECONDS     FlowsdnIdentity GC period (default 900; 0: off)
  --identity-heartbeat-timeout SECONDS
                                     Unused this long: marked, then deleted one timeout later (default 1800)
  --identity-gc-rate-limit N         Identity deletes per rate interval (default 2500)
  --identity-gc-rate-interval SECONDS
                                     The rate limit's window (default 60)
  --nodes-gc-interval SECONDS        FlowsdnNode GC period (default 300; 0: off)
  --enable-bgp-control-plane         Compile FlowsdnBGPClusterConfigs into FlowsdnBGPNodeConfigs
  --bgp-secrets-namespace NAMESPACE  Where peer configs' auth Secrets are (default: unset, not checked)
  --enable-bgp-control-plane-status-report true|false
                                     Write the BGP cluster and peer config conditions (default true;
                                     false removes them)
  --bgp-router-id-allocation-mode default|ip-pool
                                     ip-pool: the operator gives router IDs (default: the agent derives them)
  --bgp-router-id-allocation-ip-pool CIDR|FIRST-LAST
                                     The IPv4 pool of ip-pool mode
  --bgp-interval SECONDS             Time between BGP passes (default 10)

The Lease kube-system/flowsdn-operator elects one operator; its holder is
POD_NAME (else the host name and process ID). The leader registers the 22
flowsdn.io CRDs at once and every five minutes, deletes FlowsdnIdentities no
FlowsdnEndpoint has used for two heartbeat timeouts (marked
io.flowsdn.heartbeat after the first), and deletes FlowsdnNodes with no owner
and no Node of their name once they have been so for one GC interval.
With the BGP control plane on, it renders one FlowsdnBGPNodeConfig per node a
FlowsdnBGPClusterConfig selects.
";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Options {
    pub skip_crd_creation: bool,
    pub kubeconfig: Option<PathBuf>,
    pub gc: Settings,
    pub bgp: BgpSettings,
}

/// The whole number after a flag, at most `max`.
fn number(
    rest: &mut std::slice::Iter<'_, std::ffi::OsString>,
    name: &str,
    max: u64,
) -> Result<u64, String> {
    rest.next()
        .and_then(|v| v.to_str())
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v <= max)
        .ok_or(format!("{name} needs a whole number, 0 to {max}"))
}

/// Parse the arguments after `operator`.
pub fn parse(args: &[std::ffi::OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut rest = args.iter();
    let (mut mode, mut pool) = (None, None);
    while let Some(arg) = rest.next() {
        let seconds = Duration::from_secs;
        match arg.to_str() {
            Some("--skip-crd-creation") => options.skip_crd_creation = true,
            Some("--kubeconfig") => {
                let path = rest.next().ok_or("--kubeconfig needs a path")?;
                options.kubeconfig = Some(PathBuf::from(path));
            }
            Some(name @ "--identity-gc-interval") => {
                options.gc.identity_interval = seconds(number(&mut rest, name, 604_800)?);
            }
            Some(name @ "--identity-heartbeat-timeout") => {
                options.gc.heartbeat_timeout = seconds(number(&mut rest, name, 604_800)?);
            }
            Some(name @ "--identity-gc-rate-interval") => {
                let value = number(&mut rest, name, 86_400)?;
                if value == 0 {
                    return Err(format!("{name} must be at least 1"));
                }
                options.gc.rate_interval = seconds(value);
            }
            Some(name @ "--identity-gc-rate-limit") => {
                options.gc.rate_limit = u32::try_from(number(&mut rest, name, 1_000_000)?)
                    .map_err(|e| e.to_string())?;
            }
            Some(name @ "--nodes-gc-interval") => {
                options.gc.nodes_interval = seconds(number(&mut rest, name, 604_800)?);
            }
            Some("--enable-bgp-control-plane") => options.bgp.enabled = true,
            Some(name @ "--bgp-secrets-namespace") => {
                let value = rest
                    .next()
                    .and_then(|v| v.to_str())
                    .filter(|v| !v.is_empty())
                    .ok_or(format!("{name} needs a namespace"))?;
                options.bgp.secrets_namespace = Some(value.to_owned());
            }
            Some(name @ "--enable-bgp-control-plane-status-report") => {
                options.bgp.status_report = match rest.next().and_then(|v| v.to_str()) {
                    Some("true") => true,
                    Some("false") => false,
                    _ => return Err(format!("{name} needs true or false")),
                };
            }
            Some(name @ "--bgp-router-id-allocation-mode") => {
                mode = match rest.next().and_then(|v| v.to_str()) {
                    Some("default") => Some(false),
                    Some("ip-pool") => Some(true),
                    _ => return Err(format!("{name} needs default or ip-pool")),
                };
            }
            Some(name @ "--bgp-router-id-allocation-ip-pool") => {
                let value = rest
                    .next()
                    .and_then(|v| v.to_str())
                    .ok_or(format!("{name} needs a CIDR or range"))?;
                pool = Some(Pool::parse(value)?);
            }
            Some(name @ "--bgp-interval") => {
                let value = number(&mut rest, name, 3600)?;
                if value == 0 {
                    return Err(format!("{name} must be at least 1"));
                }
                options.bgp.interval = seconds(value);
            }
            _ => return Err(format!("unknown operator argument {arg:?}")),
        }
    }
    if mode == Some(true) {
        let pool = pool.ok_or(
            "--bgp-router-id-allocation-mode ip-pool needs --bgp-router-id-allocation-ip-pool",
        )?;
        options.bgp.router_ids = RouterIdMode::Pool(pool);
    }
    Ok(options)
}

/// This operator's Lease holder identity.
pub fn identity(env: Option<String>, hostname: &str, pid: u32) -> String {
    env.filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("{}-{pid}", hostname.trim()))
}

/// Register every shipped CRD once; the first fatal error stops it.
pub fn register_all(
    send: &mut flowsdn_k8s::register::Send<'_>,
    wait: &mut dyn FnMut(Duration),
) -> Result<Vec<(String, Registered)>, flowsdn_k8s::Error> {
    let mut done = Vec::new();
    for (name, payload) in shipped_crds()? {
        let result = register(&name, &payload, send, wait)?;
        done.push((name, result));
    }
    Ok(done)
}

fn message(body: &Value) -> &str {
    body.get("message").and_then(Value::as_str).unwrap_or("")
}

/// Run until a fatal error.
pub fn run(options: &Options) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let client = runtime
        .block_on(JsonClient::load(
            options.kubeconfig.as_deref(),
            TransportLimits::default(),
        ))
        .map_err(|e| e.to_string())?;
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let me = identity(
        std::env::var("POD_NAME").ok(),
        &hostname,
        std::process::id(),
    );
    if options.bgp.enabled {
        crate::log::logln!(
            "operator: BGP control plane on (status report {}, router IDs {}, secrets {})",
            options.bgp.status_report,
            match options.bgp.router_ids {
                RouterIdMode::Default => "from the agents",
                RouterIdMode::Pool(_) => "from the ip-pool",
            },
            options
                .bgp
                .secrets_namespace
                .as_deref()
                .unwrap_or("not checked")
        );
    }
    crate::log::logln!(
        "operator {me}: lease {LEASE_NAMESPACE}/{LEASE_NAME}{}",
        if options.skip_crd_creation {
            ", CRD creation skipped (--skip-crd-creation)"
        } else {
            ""
        }
    );
    let mut elector = Elector::new(LEASE_NAMESPACE, LEASE_NAME, &me, LEASE_DURATION);
    let mut was_leading = false;
    let mut next_registration: Option<Instant> = None;
    let mut collectors = Collectors::new(&options.gc, Instant::now());
    loop {
        let now = Instant::now();
        let wall = micro_time(SystemTime::now());
        let step =
            match runtime.block_on(client.send_json(http::Method::GET, &elector.path(), None)) {
                Ok((200, lease)) => Some(elector.step(now, &wall, Some(&lease))),
                Ok((404, _)) => Some(elector.step(now, &wall, None)),
                Ok((status, body)) => {
                    crate::log::logln!("operator lease: HTTP {status} {}", message(&body));
                    None
                }
                Err(error) => {
                    crate::log::logln!("operator lease: {error}");
                    None
                }
            };
        let write = match step {
            Some(Step::Create(body)) => Some((http::Method::POST, elector.collection(), body)),
            Some(Step::Update(body)) => Some((http::Method::PUT, elector.path(), body)),
            Some(Step::Wait) | None => None,
        };
        if let Some((method, path, body)) = write {
            match runtime.block_on(client.send_json(method, &path, Some(&body))) {
                Ok((200..=299, _)) => elector.wrote(now, true),
                Ok((409, _)) => elector.wrote(now, false),
                Ok((status, body)) => {
                    elector.wrote(now, false);
                    crate::log::logln!("operator lease: HTTP {status} {}", message(&body));
                }
                Err(error) => {
                    elector.wrote(now, false);
                    crate::log::logln!("operator lease: {error}");
                }
            }
        }
        let leading = elector.leading(Instant::now());
        if leading != was_leading {
            crate::log::logln!(
                "operator {me}: {}",
                if leading { "leading" } else { "following" }
            );
            was_leading = leading;
            next_registration = None;
            // A new term starts its collectors' memory afresh (spec 12 §4.7).
            collectors = Collectors::new(&options.gc, Instant::now());
        }
        if leading
            && !options.skip_crd_creation
            && next_registration.is_none_or(|at| Instant::now() >= at)
        {
            let mut send = |method: http::Method, path: &str, body: Option<&Value>| {
                runtime.block_on(client.send_json(method, path, body))
            };
            let mut wait = |pause: Duration| std::thread::sleep(pause);
            let delay = match register_all(&mut send, &mut wait) {
                Ok(done) => {
                    let changed: Vec<String> = done
                        .iter()
                        .filter(|(_, r)| *r != Registered::Current)
                        .map(|(name, r)| format!("{name} {r:?}"))
                        .collect();
                    crate::log::logln!(
                        "operator: {} CRDs established{}",
                        done.len(),
                        if changed.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", changed.join(", ").to_lowercase())
                        }
                    );
                    REREGISTER
                }
                Err(error) if error.0.contains("names not accepted") => {
                    return Err(format!("{error}: another CRD holds these names"));
                }
                Err(error) => {
                    crate::log::logln!("operator: CRD registration: {error}; retrying in 30s");
                    RETRY
                }
            };
            next_registration = Instant::now().checked_add(delay);
        }
        if leading {
            let mut send = |method: http::Method, path: &str, body: Option<&Value>| {
                runtime.block_on(client.send_json(method, path, body))
            };
            collectors.tick(
                &options.gc,
                &options.bgp,
                Instant::now(),
                &micro_time(SystemTime::now()),
                &mut send,
            );
        }
        std::thread::sleep(TICK);
    }
}

/// The garbage collectors of one leader term and when each runs next.
struct Collectors {
    identity: IdentityGc,
    nodes: NodeGc,
    next_identity: Instant,
    next_nodes: Instant,
    /// The BGP pass's router-ID allocator, restored at its first pass.
    router_ids: RouterIds,
    next_bgp: Instant,
    /// The last BGP pass's errors, logged when they change.
    bgp_errors: Vec<String>,
}
impl Collectors {
    fn new(settings: &Settings, now: Instant) -> Self {
        Self {
            identity: IdentityGc::new(settings, now),
            nodes: NodeGc::new(settings),
            next_identity: now,
            next_nodes: now,
            router_ids: RouterIds::default(),
            next_bgp: now,
            bgp_errors: Vec::new(),
        }
    }
    /// Run whichever collector is due; a failed run is logged and retried
    /// after [`RETRY`].
    fn tick(
        &mut self,
        settings: &Settings,
        bgp: &BgpSettings,
        now: Instant,
        wall: &str,
        send: &mut operator_gc::Send<'_>,
    ) {
        if !settings.identity_interval.is_zero() && now >= self.next_identity {
            let delay = match operator_gc::identity_gc(&mut self.identity, now, wall, send) {
                Ok(done) => {
                    if done.marked != 0 || done.deleted != 0 || done.deferred != 0 {
                        crate::log::logln!(
                            "operator: identity GC: {} alive, {} marked, {} deleted, {} skipped, {} left for the next run (rate limit)",
                            done.alive,
                            done.marked,
                            done.deleted,
                            done.skipped,
                            done.deferred
                        );
                    }
                    settings.identity_interval
                }
                Err(error) => {
                    crate::log::logln!("operator: identity GC: {error}; retrying in 30s");
                    RETRY
                }
            };
            self.next_identity = now.checked_add(delay).unwrap_or(now);
        }
        if !settings.nodes_interval.is_zero() && now >= self.next_nodes {
            let delay = match operator_gc::node_gc(&mut self.nodes, now, send) {
                Ok(deleted) => {
                    if !deleted.is_empty() {
                        crate::log::logln!(
                            "operator: FlowsdnNode GC: deleted {} (no Node)",
                            deleted.join(", ")
                        );
                    }
                    settings.nodes_interval
                }
                Err(error) => {
                    crate::log::logln!("operator: FlowsdnNode GC: {error}; retrying in 30s");
                    RETRY
                }
            };
            self.next_nodes = now.checked_add(delay).unwrap_or(now);
        }
        if bgp.enabled && now >= self.next_bgp {
            let condition_time = crate::events::rfc3339(SystemTime::now());
            let delay = match operator_bgp::run(bgp, &mut self.router_ids, &condition_time, send) {
                Ok((done, errors)) => {
                    if done != operator_bgp::Summary::default() {
                        crate::log::logln!(
                            "operator: BGP: {} node configs created, {} updated, {} deleted, {} statuses written, {} skipped (changed meanwhile)",
                            done.created,
                            done.updated,
                            done.deleted,
                            done.statuses,
                            done.skipped
                        );
                    }
                    if errors != self.bgp_errors {
                        for error in &errors {
                            crate::log::logln!("operator: BGP: {error}");
                        }
                        self.bgp_errors = errors;
                    }
                    bgp.interval
                }
                Err(error) => {
                    crate::log::logln!("operator: BGP: {error}; retrying in 30s");
                    RETRY
                }
            };
            self.next_bgp = now.checked_add(delay).unwrap_or(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments() {
        let args = |list: &[&str]| -> Vec<std::ffi::OsString> {
            list.iter().map(std::ffi::OsString::from).collect()
        };
        assert_eq!(parse(&args(&[])), Ok(Options::default()));
        assert_eq!(Options::default().gc, Settings::default());
        assert_eq!(
            parse(&args(&["--skip-crd-creation", "--kubeconfig", "/k"])),
            Ok(Options {
                skip_crd_creation: true,
                kubeconfig: Some(PathBuf::from("/k")),
                gc: Settings::default(),
                bgp: BgpSettings::default(),
            })
        );
        let bgp = parse(&args(&[
            "--enable-bgp-control-plane",
            "--bgp-secrets-namespace",
            "bgp-secrets",
            "--enable-bgp-control-plane-status-report",
            "false",
            "--bgp-router-id-allocation-mode",
            "ip-pool",
            "--bgp-router-id-allocation-ip-pool",
            "10.255.0.0/24",
            "--bgp-interval",
            "3",
        ]))
        .map(|o| o.bgp);
        assert_eq!(
            bgp,
            Ok(BgpSettings {
                enabled: true,
                secrets_namespace: Some("bgp-secrets".into()),
                status_report: false,
                router_ids: RouterIdMode::Pool(Pool::parse("10.255.0.0/24").expect("pool")),
                interval: Duration::from_secs(3),
            })
        );
        assert!(!BgpSettings::default().enabled && BgpSettings::default().status_report);
        assert!(parse(&args(&["--bgp-router-id-allocation-mode", "ip-pool"])).is_err());
        assert!(parse(&args(&["--bgp-router-id-allocation-ip-pool", "fd00::/64"])).is_err());
        assert!(parse(&args(&["--enable-bgp-control-plane-status-report", "yes"])).is_err());
        assert!(parse(&args(&["--bgp-interval", "0"])).is_err());
        assert_eq!(
            parse(&args(&[
                "--identity-gc-interval",
                "0",
                "--identity-heartbeat-timeout",
                "60",
                "--identity-gc-rate-limit",
                "5",
                "--identity-gc-rate-interval",
                "10",
                "--nodes-gc-interval",
                "0",
            ]))
            .map(|o| o.gc),
            Ok(Settings {
                identity_interval: Duration::ZERO,
                heartbeat_timeout: Duration::from_secs(60),
                rate_limit: 5,
                rate_interval: Duration::from_secs(10),
                nodes_interval: Duration::ZERO,
            })
        );
        assert!(parse(&args(&["--kubeconfig"])).is_err());
        assert!(parse(&args(&["--bogus"])).is_err());
        assert!(parse(&args(&["--nodes-gc-interval", "5m"])).is_err());
        assert!(parse(&args(&["--identity-gc-rate-interval", "0"])).is_err());
        assert!(parse(&args(&["--identity-gc-interval"])).is_err());
    }

    #[test]
    fn identity_is_the_pod_name_else_host_and_pid() {
        assert_eq!(identity(Some("op-1".into()), "h", 9), "op-1");
        assert_eq!(identity(Some(String::new()), "node1\n", 9), "node1-9");
        assert_eq!(identity(None, "node1", 9), "node1-9");
    }

    #[test]
    fn every_shipped_crd_is_registered_and_a_conflict_stops_it() {
        let mut calls: Vec<(String, String)> = Vec::new();
        let established = serde_json::json!({"metadata": {"labels": {
            flowsdn_k8s::SCHEMA_VERSION_LABEL: flowsdn_k8s::SCHEMA_VERSION}},
            "spec": {"versions": [{"schema": {}}]},
            "status": {"conditions": [{"type": "Established", "status": "True"}]}});
        let done = {
            let mut send = |m: http::Method,
                            p: &str,
                            _: Option<&Value>|
             -> Result<(u16, Value), flowsdn_k8s::Error> {
                calls.push((m.to_string(), p.to_owned()));
                Ok((200, established.clone()))
            };
            register_all(&mut send, &mut |_| {}).expect("registered")
        };
        assert_eq!(done.len(), 22);
        assert!(done.iter().all(|(_, r)| *r == Registered::Current));
        assert!(calls.iter().all(|(m, _)| m == "GET"), "nothing written");

        let conflict = serde_json::json!({"metadata": {"name": "x"},
            "status": {"conditions": [{"type": "NamesAccepted", "status": "False"}]}});
        let mut sent = 0usize;
        let result = {
            let mut send = |m: http::Method,
                            _: &str,
                            _: Option<&Value>|
             -> Result<(u16, Value), flowsdn_k8s::Error> {
                sent = sent.saturating_add(1);
                Ok(if m == http::Method::GET && sent == 1 {
                    (404, Value::Null)
                } else if m == http::Method::POST {
                    (201, Value::Null)
                } else {
                    (200, conflict.clone())
                })
            };
            register_all(&mut send, &mut |_| {})
        };
        let error = result.expect_err("fatal");
        assert!(error.0.contains("names not accepted"), "{error}");
        assert_eq!(sent, 3, "stopped at the first CRD");
    }
}
