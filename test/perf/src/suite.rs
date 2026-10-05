//! The `perf` suite (#321). It measures the cluster's pod network as any pod
//! sees it, the same way on every CNI flavor, so a Cilium and a flowsdn run
//! on the same machines compare metric by metric.
//!
//! This pod is the client. Server pods (this image, `flowsdn-perf server`)
//! are pinned with `nodeName` to this pod's node (`same-node`) and to
//! another ready node (`cross-node`, skipped on a one-node cluster).
use crate::{
    dns,
    host::{self, Agent, Usage},
    kube::{self, Image, Kube, Placed},
    report::Report,
    stats::{Samples, gbps},
    wire::{self, ACCEPT_PORT, RR_PORT, RrResult, STREAM_PORT},
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

/// Pods for the network-readiness measurement.
const READINESS_PODS: usize = 10;
/// Most pods the scale step creates; it also stays under half the node's
/// allocatable pods.
const SCALE_PODS: u64 = 100;
const POLICY_TIMEOUT: Duration = Duration::from_secs(60);
const DNS_LOOKUPS: usize = 200;
/// Pods added per `perf-scale` step (owner, 2026-10-05: "100 unit").
const RAMP_STEP: u64 = 100;
/// How long one step's pods may take to get pod IPs.
const RAMP_STEP_TIMEOUT: Duration = Duration::from_secs(600);

struct Suite {
    kube: Kube,
    report: Report,
    node: String,
    other: Option<String>,
    image: Image,
    own_ip: Option<IpAddr>,
    seconds: Duration,
    proc_root: PathBuf,
    agent: Option<Agent>,
    /// API paths of everything created, deleted at the end.
    created: Vec<String>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// `ramp`: the `perf-scale` suite (steps of [`RAMP_STEP`] pods until one
/// fails); otherwise the `perf` suite.
pub fn run(ramp: bool) -> ExitCode {
    let proc_root = PathBuf::from("/proc");
    let agent = host::find_agent(&proc_root);
    let flavor = agent
        .as_ref()
        .map(|a| a.flavor.to_owned())
        .or_else(|| env("STORM_FLAVOR"))
        .unwrap_or_else(|| "unknown".into());
    let (Some(namespace), Some(run_id)) = (env("STORM_NAMESPACE"), env("STORM_RUN_ID")) else {
        let mut report = Report::new(&flavor, "");
        report.infrastructure(
            "perf-setup",
            "STORM_NAMESPACE and STORM_RUN_ID are required (run by stormcentral)",
        );
        return report.finish();
    };
    let kube = match Kube::connect(namespace, run_id) {
        Ok(kube) => kube,
        Err(e) => {
            let mut report = Report::new(&flavor, "");
            report.infrastructure("perf-setup", &format!("Kubernetes API: {e}"));
            return report.finish();
        }
    };
    let (node, image, own_ip) = match kube::own_pod(&kube) {
        Ok(own) => own,
        Err(e) => {
            let mut report = Report::new(&flavor, "");
            report.infrastructure("perf-setup", &format!("own pod: {e}"));
            return report.finish();
        }
    };
    let mut report = Report::new(&flavor, &node);
    let nodes = match kube::nodes(&kube) {
        Ok(nodes) => nodes,
        Err(e) => {
            report.infrastructure("perf-setup", &format!("nodes (cluster_read): {e}"));
            return report.finish();
        }
    };
    let other = nodes.iter().map(|(n, _)| n.clone()).find(|n| *n != node);
    let allocatable = nodes
        .iter()
        .find(|(n, _)| *n == node)
        .map_or(110, |(_, p)| *p);
    let seconds = env("STORM_PERF_SECONDS")
        .and_then(|s| s.parse().ok())
        .map_or(Duration::from_secs(10), Duration::from_secs);
    report.pass(
        "perf-setup",
        Duration::ZERO,
        &format!(
            "flavor {flavor} (agent {}), {} ready nodes, client on {node}, cross-node peer {}",
            agent
                .as_ref()
                .map_or("not found".into(), |a| format!("pid {}", a.pid)),
            nodes.len(),
            other.as_deref().unwrap_or("none")
        ),
        json!({"nodes": nodes.len(), "other_node": other, "image": image.name,
            "seconds_per_measurement": seconds.as_secs()}),
    );
    let mut suite = Suite {
        kube,
        report,
        node,
        other,
        image,
        own_ip,
        seconds,
        proc_root,
        agent,
        created: Vec::new(),
    };
    if ramp {
        suite.ramp(&nodes);
    } else {
        suite.all(allocatable);
    }
    suite.cleanup();
    suite.report.finish()
}

fn rr_metrics(kind: &str, mut result: RrResult) -> (String, Value) {
    let mut metrics = result.samples.summary();
    let per_second = result.per_second();
    if let Some(object) = metrics.as_object_mut() {
        object.insert("transactions_per_second".into(), json!(per_second));
        object.insert("lost".into(), json!(result.lost));
    }
    let p50 = result.samples.percentile_us(0.5).unwrap_or(0.0);
    let p99 = result.samples.percentile_us(0.99).unwrap_or(0.0);
    (
        format!(
            "{kind}: p50 {p50:.1} us, p99 {p99:.1} us, {per_second} tx/s, {} lost",
            result.lost
        ),
        metrics,
    )
}
fn ms_summary(samples: &mut Samples) -> Value {
    let ms = |v: Option<f64>| v.map(|us| (us / 100.0).round() / 10.0);
    json!({"p50_ms": ms(samples.percentile_us(0.5)), "p99_ms": ms(samples.percentile_us(0.99)),
        "max_ms": ms(samples.percentile_us(1.0)), "count": samples.len()})
}

impl Suite {
    fn all(&mut self, allocatable: u64) {
        self.cost("agent-cost-idle", |s| thread::sleep(s.seconds));
        self.readiness();
        self.report.skip(
            "cni-ready-after-boot",
            "node boot to CNI ready is the network phase of stormcentral's boot breakdown (stormcentral#365), not measurable from a pod",
        );
        let node = self.node.clone();
        let same = self.server("perf-server-same", &node);
        let cross = match self.other.clone() {
            Some(other) => self.server("perf-server-cross", &other),
            None => {
                self.report
                    .skip("cross-node", "one ready node: no cross-node peer");
                None
            }
        };
        if let Some(server) = &same {
            self.pod_to_pod("same-node", server, true);
        }
        if let Some(server) = &cross {
            self.pod_to_pod("cross-node", server, false);
        }
        let target = cross.as_ref().or(same.as_ref()).cloned();
        if let Some(server) = target {
            self.service(&server);
        } else {
            self.report.skip("service", "no server pod");
        }
        self.dns();
        if let Some(server) = &same {
            self.policy(server);
        }
        self.scale(allocatable);
    }

    fn track(&mut self, path: String) {
        self.created.push(path);
    }
    fn cleanup(&mut self) {
        for path in self.created.drain(..).rev() {
            if let Err(e) = self.kube.delete(&path) {
                eprintln!("cleanup: {e}");
            }
        }
    }

    /// Agent CPU (percent of one core) and RSS around `work`.
    fn cost(&mut self, test: &str, work: impl FnOnce(&mut Self)) {
        let Some(agent) = self.agent.clone() else {
            work(self);
            self.report.skip(
                test,
                "no flowsdn-agent or cilium-agent process in the host PID namespace",
            );
            return;
        };
        let started = Instant::now();
        let usage = Usage::start(&self.proc_root, agent.pid);
        work(self);
        match usage.and_then(|u| u.finish()) {
            Some((cpu, rss)) => self.report.pass(
                test,
                started.elapsed(),
                &format!("{} agent: {cpu}% of a core, {rss} MiB RSS", agent.flavor),
                json!({"cpu_percent": cpu, "rss_mib": rss, "pid": agent.pid}),
            ),
            None => self
                .report
                .fail(test, started.elapsed(), "agent process vanished"),
        }
    }

    /// Pod create to pod IP (network set up) for READINESS_PODS pods created
    /// together on this node.
    fn readiness(&mut self) {
        let node = self.node.clone();
        let image = self.image.clone();
        let names: Vec<String> = (0..READINESS_PODS)
            .map(|i| format!("perf-ready-{i}"))
            .collect();
        let started = Instant::now();
        let mut created = Vec::new();
        for name in &names {
            let body = self.kube.pod(name, "perf-ready", &node, &image, &["sleep"]);
            let at = Instant::now();
            match self.kube.create(&self.kube.pods_path(), &body) {
                Ok(_) => {
                    self.track(format!("{}/{name}", self.kube.pods_path()));
                    created.push((name.clone(), at));
                }
                Err(e) => {
                    self.report.fail("pod-network-ready", started.elapsed(), &e);
                    return;
                }
            }
        }
        let mut samples = Samples::default();
        for (name, at) in &created {
            match self.kube.wait_ip(name, *at, Duration::from_secs(180)) {
                Ok((_, after)) => samples.push(after),
                Err(e) => {
                    self.report.fail("pod-network-ready", started.elapsed(), &e);
                    return;
                }
            }
        }
        let metrics = ms_summary(&mut samples);
        self.report.pass(
            "pod-network-ready",
            started.elapsed(),
            &format!(
                "{READINESS_PODS} pods created together on {node}: create -> Running with pod IP"
            ),
            metrics,
        );
        for (name, _) in created {
            let path = format!("{}/{name}", self.kube.pods_path());
            let _ = self.kube.delete(&path);
            self.created.retain(|p| *p != path);
        }
    }

    fn server(&mut self, name: &str, node: &str) -> Option<Placed> {
        let image = self.image.clone();
        let started = Instant::now();
        match self.kube.place_server(name, name, node, &image) {
            Ok(placed) => {
                self.track(format!("{}/{name}", self.kube.pods_path()));
                let address = SocketAddr::new(placed.ip, RR_PORT);
                if !wait_reachable(address, Duration::from_secs(60)) {
                    self.report
                        .fail(name, started.elapsed(), &format!("{address} not reachable"));
                    return None;
                }
                self.report.pass(
                    name,
                    started.elapsed(),
                    &format!("server on {node} at {}", placed.ip),
                    json!({"pod_ip_ms": placed.ip_after.as_millis()}),
                );
                Some(placed)
            }
            Err(e) => {
                self.track(format!("{}/{name}", self.kube.pods_path()));
                self.report.fail(name, started.elapsed(), &e);
                None
            }
        }
    }

    /// RR latency, 1 and 8 stream throughput (and connect rate) to `ip`.
    fn traffic(&mut self, prefix: &str, where_: &str, ip: IpAddr, with_cost: bool) {
        let seconds = self.seconds;
        self.report
            .measure(&format!("{prefix}-tcp-rr-{where_}"), || {
                wire::tcp_rr(SocketAddr::new(ip, RR_PORT), seconds)
                    .map(|r| rr_metrics("TCP_RR", r))
                    .map_err(|e| e.to_string())
            });
        self.report
            .measure(&format!("{prefix}-udp-rr-{where_}"), || {
                wire::udp_rr(SocketAddr::new(ip, RR_PORT), seconds)
                    .map(|r| rr_metrics("UDP_RR", r))
                    .map_err(|e| e.to_string())
            });
        for streams in [1usize, 8] {
            let test = format!("{prefix}-tcp-stream-{streams}-{where_}");
            let run = |s: &mut Self| {
                s.report.measure(&test, || {
                    wire::tcp_stream(SocketAddr::new(ip, STREAM_PORT), streams, seconds)
                        .map(|(bytes, elapsed)| {
                            let rate = gbps(bytes, elapsed);
                            (
                                format!("{streams} stream(s): {rate} Gbit/s"),
                                json!({"gbps": rate, "bytes": bytes, "streams": streams}),
                            )
                        })
                        .map_err(|e| e.to_string())
                });
            };
            if with_cost && streams == 8 {
                self.cost("agent-cost-load", run);
            } else {
                run(self);
            }
        }
        self.report
            .measure(&format!("{prefix}-connect-rate-{where_}"), || {
                let (mut result, failed) =
                    wire::connect_rate(SocketAddr::new(ip, ACCEPT_PORT), seconds);
                let per_second = result.per_second();
                let mut metrics = result.samples.summary();
                if let Some(object) = metrics.as_object_mut() {
                    object.insert("connections_per_second".into(), json!(per_second));
                    object.insert("failed".into(), json!(failed));
                }
                if failed > 0 && result.samples.is_empty() {
                    return Err(format!("{failed} connects failed, none succeeded"));
                }
                let p50 = result.samples.percentile_us(0.5).unwrap_or(0.0);
                Ok((
                    format!("{per_second} connections/s, connect p50 {p50:.1} us, {failed} failed"),
                    metrics,
                ))
            });
    }

    fn pod_to_pod(&mut self, where_: &str, server: &Placed, with_cost: bool) {
        self.traffic("pod", where_, server.ip, with_cost);
    }

    /// The same measurements through a ClusterIP Service in front of `server`.
    fn service(&mut self, server: &Placed) {
        let started = Instant::now();
        let body = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "perf-svc", "labels": self.kube.labels("perf-svc")},
            "spec": {"selector": {"app": server.name}, "ports": [
                {"name": "rr", "protocol": "TCP", "port": RR_PORT, "targetPort": RR_PORT},
                {"name": "rr-udp", "protocol": "UDP", "port": RR_PORT, "targetPort": RR_PORT},
                {"name": "stream", "protocol": "TCP", "port": STREAM_PORT, "targetPort": STREAM_PORT},
                {"name": "accept", "protocol": "TCP", "port": ACCEPT_PORT, "targetPort": ACCEPT_PORT},
            ]},
        });
        let created = match self.kube.create(&self.kube.services_path(), &body) {
            Ok(value) => value,
            Err(e) => {
                self.report.fail("svc-ready", started.elapsed(), &e);
                return;
            }
        };
        self.track(format!("{}/perf-svc", self.kube.services_path()));
        let Some(ip) = created
            .pointer("/spec/clusterIP")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        else {
            self.report
                .fail("svc-ready", started.elapsed(), "Service has no clusterIP");
            return;
        };
        if !wait_reachable(SocketAddr::new(ip, RR_PORT), Duration::from_secs(60)) {
            self.report.fail(
                "svc-ready",
                started.elapsed(),
                &format!("ClusterIP {ip}:{RR_PORT} not reachable within 60 s"),
            );
            return;
        }
        let ready_ms = started.elapsed().as_millis();
        self.report.pass(
            "svc-ready",
            started.elapsed(),
            &format!("ClusterIP {ip} -> {} on {}: create to first connect", server.ip, server.node),
            json!({"create_to_connect_ms": ready_ms, "cluster_ip": ip.to_string(), "backend_node": server.node}),
        );
        self.traffic("svc", "clusterip", ip, false);
    }

    fn dns(&mut self) {
        let namespace = self.kube.namespace.clone();
        self.report.measure("dns-lookup", || {
            let conf = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| e.to_string())?;
            let (server, domain) =
                dns::resolver(&conf, &namespace).ok_or("no nameserver in /etc/resolv.conf")?;
            let kind = if server.is_ipv4() { dns::TYPE_A } else { dns::TYPE_AAAA };
            let mut service = dns::lookups(server, &format!("perf-svc.{namespace}.svc.{domain}"), kind, DNS_LOOKUPS)
                .map_err(|e| format!("perf-svc via {server}: {e}"))?;
            let mut kubernetes = dns::lookups(server, &format!("kubernetes.default.svc.{domain}"), kind, DNS_LOOKUPS)
                .map_err(|e| format!("kubernetes.default via {server}: {e}"))?;
            let p50 = service.percentile_us(0.5).unwrap_or(0.0);
            let p99 = service.percentile_us(0.99).unwrap_or(0.0);
            Ok((
                format!("{DNS_LOOKUPS} lookups each via {server}: perf-svc p50 {p50:.1} us, p99 {p99:.1} us"),
                json!({"nameserver": server.to_string(), "service": service.summary(),
                    "kubernetes_default": kubernetes.summary()}),
            ))
        });
    }

    /// NetworkPolicy change to enforcement, and throughput under 100 and
    /// 1,000 rules, on the same-node server.
    fn policy(&mut self, server: &Placed) {
        let target = SocketAddr::new(server.ip, RR_PORT);
        let path = format!("{}/perf-deny", self.kube.policies_path());
        let deny = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "perf-deny", "labels": self.kube.labels("perf-policy")},
            "spec": {"podSelector": {"matchLabels": {"app": server.name}}, "policyTypes": ["Ingress"]},
        });
        let started = Instant::now();
        if let Err(e) = self.kube.create(&self.kube.policies_path(), &deny) {
            self.report
                .fail("policy-deny-enforced", started.elapsed(), &e);
            return;
        }
        self.track(path.clone());
        match until(POLICY_TIMEOUT, || !connects(target), started) {
            Some(after) => self.report.pass(
                "policy-deny-enforced",
                started.elapsed(),
                &format!("deny-all ingress enforced {} ms after create", after.as_millis()),
                json!({"enforce_ms": after.as_millis()}),
            ),
            None => self.report.fail(
                "policy-deny-enforced",
                started.elapsed(),
                &format!("{target} still accepts connections {POLICY_TIMEOUT:?} after a deny-all ingress policy"),
            ),
        }
        let removed = Instant::now();
        let _ = self.kube.delete(&path);
        self.created.retain(|p| *p != path);
        match until(POLICY_TIMEOUT, || connects(target), removed) {
            Some(after) => self.report.pass(
                "policy-remove-restored",
                removed.elapsed(),
                &format!(
                    "traffic back {} ms after the policy was deleted",
                    after.as_millis()
                ),
                json!({"restore_ms": after.as_millis()}),
            ),
            None => self.report.fail(
                "policy-remove-restored",
                removed.elapsed(),
                &format!("{target} unreachable {POLICY_TIMEOUT:?} after the policy was deleted"),
            ),
        }
        let Some(own) = self.own_ip else {
            self.report
                .skip("policy-rules", "this pod has no pod IP in its status");
            return;
        };
        for rules in [100usize, 1000] {
            self.rules_throughput(server, own, rules);
        }
    }

    fn rules_throughput(&mut self, server: &Placed, own: IpAddr, rules: usize) {
        let test = format!("policy-rules-{rules}-tcp-stream-1");
        let name = format!("perf-rules-{rules}");
        let path = format!("{}/{name}", self.kube.policies_path());
        let mut ingress: Vec<Value> = (1..rules)
            .map(|i| {
                let [hi, lo] = u16::try_from(i).unwrap_or(u16::MAX).to_be_bytes();
                json!({"from": [{"ipBlock": {"cidr": format!("198.18.{hi}.{lo}/32")}}],
                    "ports": [{"protocol": "TCP", "port": STREAM_PORT}]})
            })
            .collect();
        let own_cidr = if own.is_ipv4() {
            format!("{own}/32")
        } else {
            format!("{own}/128")
        };
        ingress.push(json!({"from": [{"ipBlock": {"cidr": own_cidr}}]}));
        let body = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "labels": self.kube.labels("perf-policy")},
            "spec": {"podSelector": {"matchLabels": {"app": server.name}}, "policyTypes": ["Ingress"],
                "ingress": ingress},
        });
        let started = Instant::now();
        if let Err(e) = self.kube.create(&self.kube.policies_path(), &body) {
            self.report.fail(&test, started.elapsed(), &e);
            return;
        }
        self.track(path.clone());
        // Let the policy reach the datapath; the allowed client must still connect.
        thread::sleep(Duration::from_secs(3));
        let seconds = self.seconds;
        self.report.measure(&test, || {
            let (bytes, elapsed) =
                wire::tcp_stream(SocketAddr::new(server.ip, STREAM_PORT), 1, seconds).map_err(
                    |e| format!("allowed client blocked or stream failed under {rules} rules: {e}"),
                )?;
            let rate = gbps(bytes, elapsed);
            Ok((
                format!("{rules} ingress rules selecting the server: {rate} Gbit/s"),
                json!({"gbps": rate, "rules": rules}),
            ))
        });
        let _ = self.kube.delete(&path);
        self.created.retain(|p| *p != path);
    }

    /// Pods per node with networking ready, endpoints per Service, conntrack.
    fn scale(&mut self, allocatable: u64) {
        let count = SCALE_PODS.min(allocatable / 2).max(1);
        let node = self.node.clone();
        let image = self.image.clone();
        let started = Instant::now();
        let mut names = Vec::new();
        for i in 0..count {
            let name = format!("perf-scale-{i}");
            let body = self
                .kube
                .pod(&name, "perf-scale", &node, &image, &["server"]);
            match self.kube.create(&self.kube.pods_path(), &body) {
                Ok(_) => {
                    self.track(format!("{}/{name}", self.kube.pods_path()));
                    names.push(name);
                }
                Err(e) => {
                    self.report.fail("scale-pods-ready", started.elapsed(), &e);
                    break;
                }
            }
        }
        let mut ready = 0usize;
        let mut last = Duration::ZERO;
        let mut errors = Vec::new();
        for name in &names {
            match self.kube.wait_ip(name, started, Duration::from_secs(300)) {
                Ok((_, after)) => {
                    ready = ready.saturating_add(1);
                    last = last.max(after);
                }
                Err(e) => errors.push(e),
            }
        }
        let rate = if last.is_zero() {
            0.0
        } else {
            (ready as f64 / last.as_secs_f64() * 10.0).round() / 10.0
        };
        let metrics = json!({"requested": count, "ready": ready, "all_ready_ms": last.as_millis(),
            "pods_per_second": rate, "allocatable_pods": allocatable});
        if errors.is_empty() {
            self.report.pass(
                "scale-pods-ready",
                started.elapsed(),
                &format!(
                    "{ready}/{count} pods on {node} with pod IPs in {} ms",
                    last.as_millis()
                ),
                metrics,
            );
        } else {
            self.report.fail(
                "scale-pods-ready",
                started.elapsed(),
                &format!(
                    "{ready}/{count} ready; first error: {}",
                    errors.first().map_or("", String::as_str)
                ),
            );
        }
        if ready > 0 {
            self.scale_service(ready);
        }
        for name in names {
            let path = format!("{}/{name}", self.kube.pods_path());
            let _ = self.kube.delete(&path);
            self.created.retain(|p| *p != path);
        }
    }

    fn scale_service(&mut self, ready: usize) {
        let started = Instant::now();
        let body = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "perf-scale-svc", "labels": self.kube.labels("perf-scale-svc")},
            "spec": {"selector": {"app": "perf-scale"}, "ports": [
                {"name": "accept", "protocol": "TCP", "port": ACCEPT_PORT, "targetPort": ACCEPT_PORT}]},
        });
        let created = match self.kube.create(&self.kube.services_path(), &body) {
            Ok(value) => value,
            Err(e) => {
                self.report.fail("scale-endpoints", started.elapsed(), &e);
                return;
            }
        };
        self.track(format!("{}/perf-scale-svc", self.kube.services_path()));
        let slices = self.kube.slices_path("perf-scale-svc");
        let mut endpoints = 0;
        let deadline = Duration::from_secs(120);
        while started.elapsed() < deadline {
            endpoints = self
                .kube
                .get(&slices)
                .map(|v| kube::ready_endpoints(&v))
                .unwrap_or(0);
            if endpoints >= ready {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if endpoints < ready {
            self.report.fail(
                "scale-endpoints",
                started.elapsed(),
                &format!("{endpoints}/{ready} ready endpoints after {deadline:?}"),
            );
            return;
        }
        self.report.pass(
            "scale-endpoints",
            started.elapsed(),
            &format!("{endpoints} endpoints in one Service's EndpointSlices"),
            json!({"endpoints": endpoints, "ready_ms": started.elapsed().as_millis()}),
        );
        let Some(ip) = created
            .pointer("/spec/clusterIP")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
        else {
            return;
        };
        let address = SocketAddr::new(ip, ACCEPT_PORT);
        if !wait_reachable(address, Duration::from_secs(60)) {
            self.report.fail(
                "scale-svc-connect",
                started.elapsed(),
                &format!("{address} not reachable"),
            );
            return;
        }
        let before = host::conntrack_entries(&self.proc_root);
        let seconds = self.seconds;
        self.report.measure("scale-svc-connect", || {
            let (mut result, failed) = wire::connect_rate(address, seconds);
            let per_second = result.per_second();
            if failed > 0 {
                return Err(format!(
                    "{failed} of {} connects through the Service failed",
                    result
                        .samples
                        .len()
                        .saturating_add(usize::try_from(failed).unwrap_or(usize::MAX))
                ));
            }
            let mut metrics = result.samples.summary();
            if let Some(object) = metrics.as_object_mut() {
                object.insert("connections_per_second".into(), json!(per_second));
                object.insert("endpoints".into(), json!(endpoints));
            }
            Ok((
                format!("{per_second} connections/s across {endpoints} endpoints"),
                metrics,
            ))
        });
        match (before, host::conntrack_entries(&self.proc_root)) {
            (Some(before), Some(after)) => self.report.pass(
                "conntrack-entries",
                Duration::ZERO,
                &format!(
                    "host netfilter conntrack: {before} before, {after} after the connect run"
                ),
                json!({"before": before, "after": after}),
            ),
            _ => self.report.skip(
                "conntrack-entries",
                "no /proc/1/net/stat/nf_conntrack (nf_conntrack not loaded in the host namespace)",
            ),
        }
    }
}

impl Suite {
    /// `perf-scale`: add RAMP_STEP server pods at a time, round-robin over
    /// the ready nodes, behind one Service. A step passes when every new pod
    /// gets a pod IP within RAMP_STEP_TIMEOUT, the Service's EndpointSlices
    /// hold every pod, connects through the ClusterIP all succeed and the
    /// newest pod answers TCP_RR. Stops at the first failing step or at the
    /// cluster's allocatable pods (less what the node already runs is not
    /// known, so a capacity stop shows as a step whose pods stay Pending).
    /// `scale-max` reports the most pods with working networking.
    fn ramp(&mut self, nodes: &[(String, u64)]) {
        let capacity: u64 = nodes.iter().map(|(_, p)| *p).sum();
        let limit = env("STORM_SCALE_MAX")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(capacity)
            .min(capacity);
        let service = match self.ramp_service() {
            Ok(ip) => ip,
            Err(e) => {
                self.report.fail("scale-ramp", Duration::ZERO, &e);
                return;
            }
        };
        let image = self.image.clone();
        let mut total: u64 = 0;
        let mut best: u64 = 0;
        let mut stop = String::from("reached the cluster's allocatable pods");
        let started = Instant::now();
        let mut step: u64 = 0;
        while total < limit {
            step = step.saturating_add(1);
            let size = RAMP_STEP.min(limit.saturating_sub(total));
            let test = format!("scale-step-{step}");
            let step_started = Instant::now();
            let usage = self
                .agent
                .clone()
                .and_then(|a| Usage::start(&self.proc_root, a.pid));
            let mut created = Vec::new();
            for i in 0..size {
                let index = total.saturating_add(i);
                let node = nodes
                    .get(
                        usize::try_from(index)
                            .unwrap_or(0)
                            .checked_rem(nodes.len())
                            .unwrap_or(0),
                    )
                    .map_or(self.node.clone(), |(n, _)| n.clone());
                let name = format!("perf-ramp-{index}");
                let body = self
                    .kube
                    .pod(&name, "perf-ramp", &node, &image, &["server"]);
                let at = Instant::now();
                match self.kube.create(&self.kube.pods_path(), &body) {
                    Ok(_) => {
                        self.track(format!("{}/{name}", self.kube.pods_path()));
                        created.push((name, at));
                    }
                    Err(e) => {
                        stop = format!("step {step}: create failed: {e}");
                        break;
                    }
                }
            }
            let mut samples = Samples::default();
            let mut newest = None;
            let mut failure = None;
            for (name, at) in &created {
                let remaining = RAMP_STEP_TIMEOUT.saturating_sub(step_started.elapsed());
                match self
                    .kube
                    .wait_ip(name, *at, remaining.max(Duration::from_secs(1)))
                {
                    Ok((ip, after)) => {
                        samples.push(after);
                        newest = Some(ip);
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            let ready = u64::try_from(samples.len()).unwrap_or(0);
            let now = total.saturating_add(ready);
            if failure.is_none() && ready == size {
                failure =
                    self.ramp_check(&service, usize::try_from(now).unwrap_or(usize::MAX), newest);
            }
            let cost = usage.and_then(|u| u.finish());
            let mut metrics = ms_summary(&mut samples);
            if let Some(object) = metrics.as_object_mut() {
                object.insert("pods_total".into(), json!(now));
                object.insert("step_pods".into(), json!(size));
                object.insert("step_ms".into(), json!(step_started.elapsed().as_millis()));
                if let Some((cpu, rss)) = cost {
                    object.insert("agent_cpu_percent".into(), json!(cpu));
                    object.insert("agent_rss_mib".into(), json!(rss));
                }
            }
            match failure {
                None if ready == size => {
                    total = now;
                    best = now;
                    let p99 = metrics.get("p99_ms").cloned().unwrap_or(Value::Null);
                    self.report.pass(
                        &test,
                        step_started.elapsed(),
                        &format!(
                            "{now} pods with working networking (step p99 to pod IP {p99} ms)"
                        ),
                        metrics,
                    );
                }
                other => {
                    let why = other.unwrap_or_else(|| format!("{ready}/{size} pods created"));
                    stop = format!("step {step} ({now} pods): {why}");
                    self.report.fail(&test, step_started.elapsed(), &why);
                    break;
                }
            }
        }
        let rss = self
            .agent
            .clone()
            .and_then(|a| Usage::start(&self.proc_root, a.pid))
            .and_then(|u| u.finish())
            .map(|(_, rss)| rss);
        self.report.pass(
            "scale-max",
            started.elapsed(),
            &format!("{best} pods with working networking; stopped: {stop}"),
            json!({"max_pods": best, "nodes": nodes.len(), "allocatable_pods": capacity,
                "limit": limit, "agent_rss_mib": rss, "stopped": stop}),
        );
        // Drain: delete every ramp pod, then the time for the Service to empty.
        let drained = Instant::now();
        let pods: Vec<String> = self
            .created
            .iter()
            .filter(|p| p.contains("/pods/perf-ramp-"))
            .cloned()
            .collect();
        for path in &pods {
            let _ = self.kube.delete(path);
        }
        self.created.retain(|p| !pods.contains(p));
        let slices = self.kube.slices_path("perf-ramp-svc");
        let mut left = usize::MAX;
        while drained.elapsed() < Duration::from_secs(600) {
            left = self
                .kube
                .get(&slices)
                .map(|v| kube::ready_endpoints(&v))
                .unwrap_or(usize::MAX);
            if left == 0 {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
        let rss_after = self
            .agent
            .clone()
            .and_then(|a| Usage::start(&self.proc_root, a.pid))
            .and_then(|u| u.finish())
            .map(|(_, rss)| rss);
        if left == 0 {
            self.report.pass(
                "scale-drain",
                drained.elapsed(),
                &format!(
                    "{best} pods deleted; Service empty after {} ms",
                    drained.elapsed().as_millis()
                ),
                json!({"drain_ms": drained.elapsed().as_millis(), "agent_rss_mib": rss_after}),
            );
        } else {
            self.report.fail(
                "scale-drain",
                drained.elapsed(),
                &format!("{left} endpoints still ready 600 s after deleting the pods"),
            );
        }
    }

    /// The Service in front of every ramp pod; its ClusterIP.
    fn ramp_service(&mut self) -> Result<IpAddr, String> {
        let body = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "perf-ramp-svc", "labels": self.kube.labels("perf-ramp-svc")},
            "spec": {"selector": {"app": "perf-ramp"}, "ports": [
                {"name": "accept", "protocol": "TCP", "port": ACCEPT_PORT, "targetPort": ACCEPT_PORT}]},
        });
        let created = self.kube.create(&self.kube.services_path(), &body)?;
        self.track(format!("{}/perf-ramp-svc", self.kube.services_path()));
        created
            .pointer("/spec/clusterIP")
            .and_then(Value::as_str)
            .and_then(|ip| ip.parse::<IpAddr>().ok())
            .ok_or_else(|| "perf-ramp-svc has no clusterIP".to_string())
    }

    /// After a step: endpoints for every pod, clean connects through the
    /// ClusterIP, and TCP_RR to the newest pod. None when all hold.
    fn ramp_check(
        &mut self,
        service: &IpAddr,
        pods: usize,
        newest: Option<IpAddr>,
    ) -> Option<String> {
        let slices = self.kube.slices_path("perf-ramp-svc");
        let waited = Instant::now();
        let mut endpoints = 0;
        while waited.elapsed() < Duration::from_secs(120) {
            endpoints = self
                .kube
                .get(&slices)
                .map(|v| kube::ready_endpoints(&v))
                .unwrap_or(0);
            if endpoints >= pods {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
        if endpoints < pods {
            return Some(format!(
                "{endpoints}/{pods} endpoints in the Service after 120 s"
            ));
        }
        let address = SocketAddr::new(*service, ACCEPT_PORT);
        if !wait_reachable(address, Duration::from_secs(60)) {
            return Some(format!("ClusterIP {address} not reachable"));
        }
        let (result, failed) = wire::connect_rate(address, Duration::from_secs(3));
        if failed > 0 {
            return Some(format!(
                "{failed} of {} connects through the ClusterIP failed",
                result
                    .samples
                    .len()
                    .saturating_add(usize::try_from(failed).unwrap_or(0))
            ));
        }
        if let Some(ip) = newest {
            let target = SocketAddr::new(ip, RR_PORT);
            if !wait_reachable(target, Duration::from_secs(60)) {
                return Some(format!("newest pod {target} not reachable"));
            }
            if let Err(e) = wire::tcp_rr(target, Duration::from_secs(1)) {
                return Some(format!("TCP_RR to newest pod {target}: {e}"));
            }
        }
        None
    }
}

/// One TCP connect with a short timeout.
fn connects(address: SocketAddr) -> bool {
    wire::reachable(address, Duration::from_millis(300))
}
fn wait_reachable(address: SocketAddr, timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if wire::reachable(address, Duration::from_millis(500)) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}
/// Time from `since` until `condition` holds three probes in a row (the
/// first of them counts), or None after `timeout`.
fn until(
    timeout: Duration,
    mut condition: impl FnMut() -> bool,
    since: Instant,
) -> Option<Duration> {
    let mut first: Option<Duration> = None;
    let mut streak = 0u8;
    while since.elapsed() < timeout {
        if condition() {
            first.get_or_insert_with(|| since.elapsed());
            streak = streak.saturating_add(1);
            if streak >= 3 {
                return first;
            }
        } else {
            first = None;
            streak = 0;
        }
        thread::sleep(Duration::from_millis(100));
    }
    None
}
