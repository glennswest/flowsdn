//! FlowsdnNodeConfig as an agent configuration source (#480, spec 00 §3.3
//! source 5, as flowsdn decided it): on the nodes a FlowsdnNodeConfig's
//! `spec.nodeSelector` picks, each `spec.defaults` key is one of flowsdn's
//! own agent settings ([`ALLOWED`], dotted for `kubernetes.*`) and its value
//! replaces the configuration file's.
//!
//! Read once at agent start, from the agent's namespace (`POD_NAMESPACE`,
//! else `kube-system`): a change takes effect at the next start, as the
//! reference's do. Selected configs apply in name order, a later one
//! overriding an earlier one's key. A value is JSON when it parses as JSON
//! (`true`, `1400`, an object) and a string otherwise. A config's keys are
//! kept together when the whole configuration parses with all of them (a
//! pool and its gateway are only valid as a pair); otherwise each is kept
//! only if the configuration still parses with it, so a bad value is
//! refused with the reason rather than stopping the agent. A key flowsdn does
//! not read per node (a path the manifest mounts, the node name, the
//! kubeconfig, the cluster name, anything unknown) is refused too: nothing
//! accepted does nothing. Refusals are Warning Events on the Node, and
//! `/v1/healthz` shows `kubernetes.node-config`.
use flowsdn_policy::k8s::LabelSelector;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The settings a FlowsdnNodeConfig may set: node-scoped ones the agent
/// reads. Paths that depend on the manifest's mounts, the node's identity,
/// the API credentials and the cluster-wide name are not among them.
pub const ALLOWED: [&str; 25] = [
    "egress",
    "device-mtu",
    "route-mtu",
    "ipv4-pool",
    "ipv6-pool",
    "ipv4-gateway",
    "ipv6-gateway",
    "kubernetes.auto-direct-node-routes",
    "kubernetes.direct-routing-skip-unreachable",
    "kubernetes.service-lb",
    "kubernetes.node-port",
    "kubernetes.lb-algorithm",
    "kubernetes.lb-mode",
    "kubernetes.nat46x64",
    "kubernetes.lb-external-clusterip",
    "kubernetes.lb-ipam",
    "kubernetes.l2-announcements",
    "kubernetes.identity-allocation",
    "kubernetes.network-policy",
    "kubernetes.flowsdn-policy",
    "kubernetes.host-firewall",
    "kubernetes.uplinks",
    "kubernetes.endpoint-crd",
    "kubernetes.node-crd",
    "kubernetes.crd-wait-timeout",
    "kubernetes.lb-sock-terminate-all-protos",
];

/// One refused key: the FlowsdnNodeConfig, the key and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Refused {
    pub config: String,
    pub key: String,
    pub reason: String,
}

/// What the FlowsdnNodeConfigs did to this agent's configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// The configs whose selector picked this node, in the order applied.
    pub selected: Vec<String>,
    /// Each applied key and the config its value came from.
    pub applied: BTreeMap<String, String>,
    pub refused: Vec<Refused>,
}
impl Report {
    pub fn json(&self) -> Value {
        json!({
            "selected": self.selected,
            "applied": self.applied,
            "refused": self.refused.iter().map(|r| json!({
                "config": r.config, "key": r.key, "reason": r.reason,
            })).collect::<Vec<_>>(),
        })
    }
}

fn name(config: &Value) -> String {
    config
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// A `defaults` value as configuration: JSON when it parses, else the text.
fn setting(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
}

/// `config` with dotted `key` set to `value`; None when `kubernetes` is
/// not an object (the agent is not in Kubernetes mode).
fn with(config: &Value, key: &str, value: Value) -> Option<Value> {
    let mut out = config.clone();
    let object = out.as_object_mut()?;
    match key.split_once('.') {
        Some((section, field)) => {
            object
                .get_mut(section)?
                .as_object_mut()?
                .insert(field.to_owned(), value);
        }
        None => {
            object.insert(key.to_owned(), value);
        }
    }
    Some(out)
}

/// Apply the FlowsdnNodeConfigs that select a node with `labels` to the
/// configuration `base`; `valid` parses a candidate configuration.
pub fn apply(
    base: &Value,
    configs: &[Value],
    labels: &BTreeMap<String, String>,
    valid: &dyn Fn(&Value) -> Result<(), String>,
) -> (Value, Report) {
    let mut report = Report::default();
    let mut sorted: Vec<&Value> = configs.iter().collect();
    sorted.sort_by_key(|c| name(c));
    let mut current = base.clone();
    for config in sorted {
        let config_name = name(config);
        let selector = match LabelSelector::parse(config.pointer("/spec/nodeSelector")) {
            Ok(selector) => selector,
            Err(error) => {
                report.refused.push(Refused {
                    config: config_name,
                    key: "nodeSelector".into(),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        if !selector.matches(labels) {
            continue;
        }
        report.selected.push(config_name.clone());
        let defaults = config
            .pointer("/spec/defaults")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(Map::new);
        let mut pending: Vec<(String, Value)> = Vec::new();
        for (key, value) in defaults {
            let refuse = |reason: String| Refused {
                config: config_name.clone(),
                key: key.clone(),
                reason,
            };
            if !ALLOWED.contains(&key.as_str()) {
                report.refused.push(refuse(
                    "not a setting a FlowsdnNodeConfig can set on a node".into(),
                ));
                continue;
            }
            let Some(text) = value.as_str() else {
                report
                    .refused
                    .push(refuse("the value must be a string".into()));
                continue;
            };
            pending.push((key, setting(text)));
        }
        // All of this config's keys at once, when that parses.
        let together = pending
            .iter()
            .try_fold(current.clone(), |doc, (key, value)| {
                with(&doc, key, value.clone())
            });
        if let Some(candidate) = together.filter(|c| valid(c).is_ok()) {
            current = candidate;
            for (key, _) in pending {
                report.applied.insert(key, config_name.clone());
            }
            continue;
        }
        for (key, value) in pending {
            let refuse = |reason: String| Refused {
                config: config_name.clone(),
                key: key.clone(),
                reason,
            };
            let Some(candidate) = with(&current, &key, value) else {
                report
                    .refused
                    .push(refuse("the agent is not in Kubernetes mode".into()));
                continue;
            };
            match valid(&candidate) {
                Ok(()) => {
                    current = candidate;
                    report.applied.insert(key, config_name.clone());
                }
                Err(reason) => report.refused.push(refuse(reason)),
            }
        }
    }
    (current, report)
}

/// The agent's namespace, where its FlowsdnNodeConfigs live.
pub fn namespace() -> String {
    std::env::var("POD_NAMESPACE")
        .ok()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "kube-system".into())
}

/// How long start-up keeps trying to read the Node and the configs.
pub const FETCH_FOR: Duration = Duration::from_secs(60);

/// Read this node's labels and the FlowsdnNodeConfigs of `namespace` (none
/// while the kind is not served), retrying for [`FETCH_FOR`].
pub fn fetch(
    settings: &crate::kubernetes::Settings,
    namespace: &str,
) -> Result<(BTreeMap<String, String>, Vec<Value>), String> {
    use flowsdn_k8s::client::{JsonClient, TransportLimits};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let client = runtime
        .block_on(JsonClient::load(
            settings.kubeconfig.as_deref(),
            TransportLimits::default(),
        ))
        .map_err(|e| e.to_string())?;
    let node_path = format!("/api/v1/nodes/{}", settings.node_name);
    let configs_path =
        format!("/apis/flowsdn.io/v1alpha1/namespaces/{namespace}/flowsdnnodeconfigs");
    let started = Instant::now();
    loop {
        let attempt = || -> Result<(BTreeMap<String, String>, Vec<Value>), String> {
            let get = |path: &str| {
                runtime
                    .block_on(client.send_json(http::Method::GET, path, None))
                    .map_err(|e| e.to_string())
            };
            let labels = match get(&node_path)? {
                (200, node) => node
                    .pointer("/metadata/labels")
                    .and_then(Value::as_object)
                    .map(|l| {
                        l.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default(),
                (status, _) => return Err(format!("Node {}: HTTP {status}", settings.node_name)),
            };
            let configs = match get(&configs_path)? {
                (200, list) => list
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
                // The kind is not served: no FlowsdnNodeConfig can exist.
                (404, _) => Vec::new(),
                (status, _) => return Err(format!("FlowsdnNodeConfigs: HTTP {status}")),
            };
            Ok((labels, configs))
        };
        match attempt() {
            Ok(found) => return Ok(found),
            Err(error) if started.elapsed() < FETCH_FOR => {
                crate::log::logln!("node configuration: {error}; retrying");
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(error) => return Err(format!("node configuration: {error}")),
        }
    }
}

#[cfg(test)]
#[path = "node_config_tests.rs"]
mod tests;
