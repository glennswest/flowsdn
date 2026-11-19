//! `GET /metrics` (#420): the agent's network-level series for the node's
//! scraper (stormcos#64), Prometheus text format 0.0.4, every name under
//! `flowsdn_` (#330). Built from live state on each scrape; a source that
//! cannot be read is reported by `flowsdn_metrics_source_failing`, never
//! by a made-up value.
use super::*;
use flowsdn_bpf_abi::policy::{PolicyStatsValue, PolicyVerdictKey, verdict};
use std::fmt::Write as _;

/// What one scrape reports, read from the agent (see [`Facts::of`]).
pub(super) struct Facts {
    pub endpoints: usize,
    pub deleting: usize,
    /// Controller part -> its current failure.
    pub failing: BTreeMap<String, String>,
    pub kubernetes: Option<Kubernetes>,
    pub verdicts: std::result::Result<Vec<(PolicyVerdictKey, PolicyStatsValue)>, String>,
    pub pressure: std::result::Result<Vec<(&'static str, u64, u32)>, String>,
}
impl Default for Facts {
    fn default() -> Self {
        Self {
            endpoints: 0,
            deleting: 0,
            failing: BTreeMap::new(),
            kubernetes: None,
            verdicts: Ok(Vec::new()),
            pressure: Ok(Vec::new()),
        }
    }
}
/// The Kubernetes controller's part of a scrape.
#[derive(Default)]
pub(super) struct Kubernetes {
    pub synced: bool,
    pub nodes: usize,
    pub pods: usize,
    /// Nodes with a direct route that is not installed (skipped or failed).
    pub unreachable_nodes: BTreeSet<String>,
    /// (identities, local label sets waiting) when allocation is on.
    pub identities: Option<(usize, usize)>,
    pub frontends: usize,
    pub programmed: usize,
    /// (uplink, carrier).
    pub uplinks: Vec<(String, bool)>,
}

impl Facts {
    pub(super) fn of(api: &mut Api) -> Self {
        let mut failing = BTreeMap::new();
        if let Some(error) = &api.policy_maps_error {
            failing.insert("policy-maps".to_owned(), error.clone());
        }
        let kubernetes = api.kubernetes.as_ref().map(|view| {
            let view = crate::kubernetes::lock(view);
            for (part, error) in &view.errors {
                failing.insert(part.clone(), error.clone());
            }
            Kubernetes {
                synced: view.synced(),
                nodes: view.nodes.len(),
                pods: view.pods.len(),
                unreachable_nodes: view
                    .routes
                    .values()
                    .filter(|(_, state)| !state.starts_with("installed"))
                    .map(|(route, _)| route.node.clone())
                    .collect(),
                identities: view
                    .identity
                    .then(|| (view.identities.len(), view.identities_waiting)),
                frontends: view.frontends.len(),
                programmed: view.service_ids.len(),
                uplinks: view
                    .uplinks
                    .uplinks
                    .iter()
                    .map(|uplink| (uplink.name.clone(), uplink.up))
                    .collect(),
            }
        });
        Self {
            endpoints: api.manager.len(),
            deleting: api.manager.deleting(),
            failing,
            kubernetes,
            verdicts: api.manager.policy_verdicts().map_err(|e| e.to_string()),
            pressure: api.manager.policy_map_pressure().map_err(|e| e.to_string()),
        }
    }
}

/// One metric family in the text format.
struct Family<'a> {
    out: &'a mut String,
}
fn family<'a>(out: &'a mut String, name: &str, kind: &str, help: &str) -> Family<'a> {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    Family { out }
}
impl Family<'_> {
    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl fmt::Display) {
        self.out.push_str(name);
        if !labels.is_empty() {
            self.out.push('{');
            for (index, (key, text)) in labels.iter().enumerate() {
                if index > 0 {
                    self.out.push(',');
                }
                let _ = write!(self.out, "{key}=\"{}\"", escape(text));
            }
            self.out.push('}');
        }
        let _ = writeln!(self.out, " {value}");
    }
}
/// Label value escaping of the text format: backslash, quote, newline.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
fn direction(key: &PolicyVerdictKey) -> &'static str {
    if key.egress != 0 { "egress" } else { "ingress" }
}

/// The exposition for `facts`.
pub(super) fn render(facts: &Facts) -> String {
    let mut out = String::new();
    family(
        &mut out,
        "flowsdn_build_info",
        "gauge",
        "The running agent's version (always 1).",
    )
    .sample(
        "flowsdn_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
    );

    let mut f = family(
        &mut out,
        "flowsdn_endpoint_state",
        "gauge",
        "Endpoints the agent holds, by state.",
    );
    f.sample(
        "flowsdn_endpoint_state",
        &[("endpoint_state", "ready")],
        facts.endpoints.saturating_sub(facts.deleting),
    );
    f.sample(
        "flowsdn_endpoint_state",
        &[("endpoint_state", "disconnecting")],
        facts.deleting,
    );

    family(
        &mut out,
        "flowsdn_controllers_failing",
        "gauge",
        "Controller parts whose last reconcile failed.",
    )
    .sample("flowsdn_controllers_failing", &[], facts.failing.len());
    let mut f = family(
        &mut out,
        "flowsdn_controller_failing",
        "gauge",
        "1 for each controller part whose last reconcile failed (its error is in /v1/healthz).",
    );
    for part in facts.failing.keys() {
        f.sample("flowsdn_controller_failing", &[("controller", part)], 1);
    }

    let mut failing_sources = Vec::new();
    match &facts.verdicts {
        Ok(rows) => {
            // (direction, verdict) -> (packets, bytes); endpoints and ports
            // are summed so the series stay few.
            let mut sums: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
            for direction in ["ingress", "egress"] {
                for kind in ["allowed", "denied", "audit"] {
                    sums.insert((direction, kind), (0, 0));
                }
            }
            for (key, value) in rows {
                let kind = match key.verdict {
                    verdict::ALLOWED => "allowed",
                    verdict::DENIED => "denied",
                    verdict::AUDIT => "audit",
                    _ => continue,
                };
                let sum = sums.entry((direction(key), kind)).or_default();
                sum.0 = sum.0.saturating_add(value.packets);
                sum.1 = sum.1.saturating_add(value.bytes);
            }
            let mut f = family(
                &mut out,
                "flowsdn_policy_verdict_total",
                "counter",
                "Packets judged by policy (new flows only; packets of a remembered flow are not counted).",
            );
            for ((direction, kind), (packets, _)) in &sums {
                f.sample(
                    "flowsdn_policy_verdict_total",
                    &[("direction", direction), ("action", kind)],
                    packets,
                );
            }
            let mut f = family(
                &mut out,
                "flowsdn_drop_count_total",
                "counter",
                "Packets the datapath dropped, by reason (policy denials are the only reason counted).",
            );
            for ((direction, kind), (packets, _)) in &sums {
                if *kind == "denied" {
                    f.sample(
                        "flowsdn_drop_count_total",
                        &[("reason", "policy_denied"), ("direction", direction)],
                        packets,
                    );
                }
            }
            let mut f = family(
                &mut out,
                "flowsdn_drop_bytes_total",
                "counter",
                "Bytes the datapath dropped, by reason.",
            );
            for ((direction, kind), (_, bytes)) in &sums {
                if *kind == "denied" {
                    f.sample(
                        "flowsdn_drop_bytes_total",
                        &[("reason", "policy_denied"), ("direction", direction)],
                        bytes,
                    );
                }
            }
        }
        Err(_) => failing_sources.push("policy-verdicts"),
    }
    match &facts.pressure {
        Ok(maps) => {
            let mut f = family(
                &mut out,
                "flowsdn_bpf_map_pressure",
                "gauge",
                "Entries in a BPF map over its max_entries.",
            );
            for (name, entries, max) in maps {
                let ratio = if *max == 0 {
                    0.0
                } else {
                    *entries as f64 / f64::from(*max)
                };
                f.sample("flowsdn_bpf_map_pressure", &[("map_name", name)], ratio);
            }
        }
        Err(_) => failing_sources.push("bpf-map-pressure"),
    }

    if let Some(k) = &facts.kubernetes {
        family(
            &mut out,
            "flowsdn_kubernetes_synced",
            "gauge",
            "1 once every list the enabled features need has been received.",
        )
        .sample("flowsdn_kubernetes_synced", &[], u8::from(k.synced));
        family(&mut out, "flowsdn_nodes", "gauge", "Nodes in the cluster.").sample(
            "flowsdn_nodes",
            &[],
            k.nodes,
        );
        family(&mut out, "flowsdn_pods", "gauge", "Pods the agent watches.").sample(
            "flowsdn_pods",
            &[],
            k.pods,
        );
        family(
            &mut out,
            "flowsdn_unreachable_nodes",
            "gauge",
            "Nodes whose direct pod-CIDR route is not installed (skipped or failed).",
        )
        .sample("flowsdn_unreachable_nodes", &[], k.unreachable_nodes.len());
        if let Some((identities, waiting)) = k.identities {
            family(
                &mut out,
                "flowsdn_identity",
                "gauge",
                "Security identities the agent knows.",
            )
            .sample("flowsdn_identity", &[("type", "cluster")], identities);
            family(
                &mut out,
                "flowsdn_identity_waiting",
                "gauge",
                "Local Pod label sets still without an identity.",
            )
            .sample("flowsdn_identity_waiting", &[], waiting);
        }
        let mut f = family(
            &mut out,
            "flowsdn_services",
            "gauge",
            "Service frontends, and those programmed in the socket LB.",
        );
        f.sample("flowsdn_services", &[("state", "desired")], k.frontends);
        f.sample("flowsdn_services", &[("state", "programmed")], k.programmed);
        let mut f = family(
            &mut out,
            "flowsdn_uplink_up",
            "gauge",
            "1 while an uplink port has carrier.",
        );
        for (name, up) in &k.uplinks {
            f.sample("flowsdn_uplink_up", &[("uplink", name)], u8::from(*up));
        }
    }

    let mut f = family(
        &mut out,
        "flowsdn_metrics_source_failing",
        "gauge",
        "1 for each source this scrape could not read (its series are absent).",
    );
    for source in failing_sources {
        f.sample("flowsdn_metrics_source_failing", &[("source", source)], 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowsdn_bpf_abi::Be16;

    fn row(egress: u8, kind: u8, packets: u64, bytes: u64) -> (PolicyVerdictKey, PolicyStatsValue) {
        (
            PolicyVerdictKey {
                endpoint: 7,
                dport: Be16::default(),
                protocol: 6,
                egress,
                verdict: kind,
                pad: [0; 3],
            },
            PolicyStatsValue { packets, bytes },
        )
    }

    /// Every sample line is `name{labels} value` of a family declared by
    /// `# TYPE` before it, and every value parses as a number.
    fn well_formed(text: &str) {
        let mut declared = BTreeSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let name = rest.split(' ').next().unwrap_or_default();
                assert!(declared.insert(name.to_owned()), "{name} declared twice");
                continue;
            }
            if line.starts_with("# HELP ") {
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect("sample line");
            let name = series.split('{').next().unwrap_or_default();
            assert!(declared.contains(name), "{name} has no TYPE");
            assert!(name.starts_with("flowsdn_"), "{name}");
            value.parse::<f64>().expect("numeric value");
        }
    }

    #[test]
    fn policy_verdicts_become_verdict_and_drop_counters() {
        let facts = Facts {
            endpoints: 3,
            deleting: 1,
            verdicts: Ok(vec![
                row(0, verdict::ALLOWED, 10, 1000),
                row(0, verdict::ALLOWED, 5, 500),
                row(0, verdict::DENIED, 4, 240),
                row(1, verdict::AUDIT, 2, 120),
            ]),
            pressure: Ok(vec![("flowsdn_policy", 16384, 65536)]),
            ..Facts::default()
        };
        let text = render(&facts);
        well_formed(&text);
        for line in [
            "flowsdn_endpoint_state{endpoint_state=\"ready\"} 2",
            "flowsdn_endpoint_state{endpoint_state=\"disconnecting\"} 1",
            "flowsdn_policy_verdict_total{direction=\"ingress\",action=\"allowed\"} 15",
            "flowsdn_policy_verdict_total{direction=\"ingress\",action=\"denied\"} 4",
            "flowsdn_policy_verdict_total{direction=\"egress\",action=\"audit\"} 2",
            "flowsdn_policy_verdict_total{direction=\"egress\",action=\"denied\"} 0",
            "flowsdn_drop_count_total{reason=\"policy_denied\",direction=\"ingress\"} 4",
            "flowsdn_drop_bytes_total{reason=\"policy_denied\",direction=\"ingress\"} 240",
            "flowsdn_bpf_map_pressure{map_name=\"flowsdn_policy\"} 0.25",
            "flowsdn_controllers_failing 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}:\n{text}");
        }
        assert!(!text.contains("flowsdn_metrics_source_failing{"));
        assert!(!text.contains("flowsdn_nodes"), "no Kubernetes series without it");
    }

    #[test]
    fn failures_are_reported_not_invented() {
        let mut failing = BTreeMap::new();
        failing.insert("routes".to_owned(), "route conflict".to_owned());
        failing.insert("policy-maps".to_owned(), "no map".to_owned());
        let facts = Facts {
            failing,
            verdicts: Err("EPERM".into()),
            pressure: Err("EPERM".into()),
            kubernetes: Some(Kubernetes {
                synced: true,
                nodes: 2,
                unreachable_nodes: ["b".to_owned()].into_iter().collect(),
                identities: Some((5, 1)),
                uplinks: vec![("eth0".into(), true), ("eth1".into(), false)],
                ..Kubernetes::default()
            }),
            ..Facts::default()
        };
        let text = render(&facts);
        well_formed(&text);
        for line in [
            "flowsdn_controllers_failing 2",
            "flowsdn_controller_failing{controller=\"policy-maps\"} 1",
            "flowsdn_controller_failing{controller=\"routes\"} 1",
            "flowsdn_metrics_source_failing{source=\"policy-verdicts\"} 1",
            "flowsdn_metrics_source_failing{source=\"bpf-map-pressure\"} 1",
            "flowsdn_unreachable_nodes 1",
            "flowsdn_kubernetes_synced 1",
            "flowsdn_identity{type=\"cluster\"} 5",
            "flowsdn_uplink_up{uplink=\"eth1\"} 0",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}:\n{text}");
        }
        assert!(!text.contains("flowsdn_drop_count_total{"), "no drops without the map");
        assert!(!text.contains("flowsdn_bpf_map_pressure{"));
    }

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }
}
