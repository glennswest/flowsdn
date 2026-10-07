//! Kubernetes `networking.k8s.io/v1` NetworkPolicy to policy entries (spec 06
//! §3.3, IR §4.1), with flowsdn's label keys (ADR-0020). Pure translation:
//! identities, selector resolution and the map state are later stages.
//!
//! Two deliberate differences from the reference text:
//! - The default-deny markers of §3.3 step 5 carry an empty peer list
//!   (`l3: Some(vec![])`, selects nothing), so no later stage can read them as
//!   the wildcard and allow everything (§3.3 requires that they allow nothing).
//! - A direction left out of `policyTypes` is not translated, as Kubernetes
//!   defines (`policyTypes: [Egress]` ignores `spec.ingress`). Without
//!   `policyTypes` the effective types are Ingress, plus Egress when
//!   `spec.egress` is present.
use crate::oracle::{Tier, Verdict};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Source prefix of Kubernetes labels in selectors and identities.
pub const SOURCE: &str = "k8s";
pub const POD_NAMESPACE: &str = "io.kubernetes.pod.namespace";
/// The cluster a peer selector is limited to.
pub const POLICY_CLUSTER: &str = "io.flowsdn.k8s.policy.cluster";
/// Prefix of a namespace's labels on its pods' identities.
pub const NAMESPACE_LABELS: &str = "io.flowsdn.k8s.namespace.labels";
pub const DERIVED_FROM: &str = "io.flowsdn.k8s.policy.derived-from";
pub const POLICY_NAME: &str = "io.flowsdn.k8s.policy.name";
pub const POLICY_NAMESPACE: &str = "io.flowsdn.k8s.policy.namespace";
pub const POLICY_UID: &str = "io.flowsdn.k8s.policy.uid";
/// Annotation that overrides the policy name in the rule labels.
pub const NAME_ANNOTATION: &str = "flowsdn.io/policy-name";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportError(pub String);
impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ImportError {}
fn invalid(message: impl Into<String>) -> ImportError {
    ImportError(message.into())
}
type Result<T> = std::result::Result<T, ImportError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Requirement {
    pub key: String,
    pub operator: Operator,
    pub values: BTreeSet<String>,
}

/// A Kubernetes label selector: every label and every requirement must hold.
/// The empty selector selects everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<Requirement>,
}
impl LabelSelector {
    /// Parse `matchLabels`/`matchExpressions`; absent or null is `{}`.
    pub fn parse(value: Option<&Value>) -> Result<Self> {
        let mut selector = Self::default();
        let Some(value) = value.filter(|v| !v.is_null()) else {
            return Ok(selector);
        };
        let object = value
            .as_object()
            .ok_or_else(|| invalid("label selector must be an object"))?;
        if let Some(labels) = object.get("matchLabels").filter(|v| !v.is_null()) {
            for (key, value) in labels
                .as_object()
                .ok_or_else(|| invalid("matchLabels must be an object"))?
            {
                let value = value
                    .as_str()
                    .ok_or_else(|| invalid(format!("matchLabels.{key} must be a string")))?;
                selector.match_labels.insert(key.clone(), value.into());
            }
        }
        if let Some(expressions) = object.get("matchExpressions").filter(|v| !v.is_null()) {
            for expression in expressions
                .as_array()
                .ok_or_else(|| invalid("matchExpressions must be a list"))?
            {
                let key = expression
                    .get("key")
                    .and_then(Value::as_str)
                    .filter(|k| !k.is_empty())
                    .ok_or_else(|| invalid("matchExpressions entry without key"))?;
                let operator = match expression.get("operator").and_then(Value::as_str) {
                    Some("In") => Operator::In,
                    Some("NotIn") => Operator::NotIn,
                    Some("Exists") => Operator::Exists,
                    Some("DoesNotExist") => Operator::DoesNotExist,
                    other => return Err(invalid(format!("unknown selector operator {other:?}"))),
                };
                let mut values = BTreeSet::new();
                if let Some(list) = expression.get("values").filter(|v| !v.is_null()) {
                    for item in list
                        .as_array()
                        .ok_or_else(|| invalid("matchExpressions values must be a list"))?
                    {
                        values.insert(
                            item.as_str()
                                .ok_or_else(|| invalid("selector values must be strings"))?
                                .to_owned(),
                        );
                    }
                }
                let needs_values = matches!(operator, Operator::In | Operator::NotIn);
                if needs_values == values.is_empty() {
                    return Err(invalid(format!(
                        "{key}: In/NotIn need values, Exists/DoesNotExist take none"
                    )));
                }
                selector.match_expressions.push(Requirement {
                    key: key.into(),
                    operator,
                    values,
                });
            }
        }
        Ok(selector)
    }
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }
    /// Whether any label or requirement is on `key`.
    pub fn constrains(&self, key: &str) -> bool {
        self.match_labels.contains_key(key) || self.match_expressions.iter().any(|r| r.key == key)
    }
    /// Every key rewritten by `rename`.
    fn rekey(self, rename: impl Fn(&str) -> String) -> Self {
        Self {
            match_labels: self
                .match_labels
                .into_iter()
                .map(|(k, v)| (rename(&k), v))
                .collect(),
            match_expressions: self
                .match_expressions
                .into_iter()
                .map(|r| Requirement {
                    key: rename(&r.key),
                    ..r
                })
                .collect(),
        }
    }
    /// Keys with the label source prefix (`k8s:app`).
    pub fn sourced(self) -> Self {
        self.rekey(|k| format!("{SOURCE}:{k}"))
    }
    /// Both selectors must hold. When both fix one label to different
    /// values, the second becomes an `In` requirement, so the conjunction
    /// (which nothing can satisfy) is kept rather than overwritten.
    pub fn and(mut self, other: Self) -> Self {
        for (key, value) in other.match_labels {
            match self.match_labels.get(&key) {
                Some(existing) if *existing != value => {
                    self.match_expressions.push(Requirement {
                        key,
                        operator: Operator::In,
                        values: BTreeSet::from([value]),
                    });
                }
                _ => {
                    self.match_labels.insert(key, value);
                }
            }
        }
        self.match_expressions.extend(other.match_expressions);
        self
    }
    /// Whether `labels` (keys as the selector spells them) satisfy it.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
            && self.match_expressions.iter().all(|r| {
                let value = labels.get(&r.key);
                match r.operator {
                    Operator::In => value.is_some_and(|v| r.values.contains(v)),
                    Operator::NotIn => value.is_none_or(|v| !r.values.contains(v)),
                    Operator::Exists => value.is_some(),
                    Operator::DoesNotExist => value.is_none(),
                }
            })
    }
    /// The selector cache key (spec 06 §4.2): Kubernetes' selector string,
    /// requirements sorted by key, `{}` for the wildcard.
    pub fn key(&self) -> String {
        if self.is_empty() {
            return "{}".into();
        }
        let mut parts: Vec<(String, String)> = self
            .match_labels
            .iter()
            .map(|(k, v)| (k.clone(), format!("{k}={v}")))
            .collect();
        for r in &self.match_expressions {
            let values = r.values.iter().cloned().collect::<Vec<_>>().join(",");
            let text = match r.operator {
                Operator::In => format!("{} in ({values})", r.key),
                Operator::NotIn => format!("{} notin ({values})", r.key),
                Operator::Exists => r.key.clone(),
                Operator::DoesNotExist => format!("!{}", r.key),
            };
            parts.push((r.key.clone(), text));
        }
        parts.sort();
        parts
            .into_iter()
            .map(|(_, t)| t)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// One peer of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    Selector(LabelSelector),
    /// `ipBlock`: the CIDR minus the excepted ones (spec 06 §3.2.4).
    Cidr {
        cidr: String,
        except: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}
impl Protocol {
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
        }
    }
}
/// A port: a number (`"0"` for every port) or a named container port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortRule {
    pub protocol: Protocol,
    pub port: String,
    pub end_port: Option<u16>,
}

/// A policy entry (spec 06 §4.1).
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub tier: Tier,
    pub priority: f64,
    pub verdict: Verdict,
    pub ingress: bool,
    pub subject: LabelSelector,
    /// None: every peer. `Some(vec![])`: no peer (a default-deny marker).
    pub l3: Option<Vec<Peer>>,
    /// None: all traffic to the peers.
    pub l4: Option<Vec<PortRule>>,
    pub labels: Vec<String>,
    pub default_deny: bool,
}
impl Entry {
    /// A default-deny marker: selects the subject, allows nothing.
    pub fn is_marker(&self) -> bool {
        self.l3.as_ref().is_some_and(Vec::is_empty)
    }
}

fn list<'a>(value: Option<&'a Value>, what: &str) -> Result<&'a [Value]> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(v) => v
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| invalid(format!("{what} must be a list"))),
    }
}

fn peer(value: &Value, namespace: &str, cluster: Option<&str>) -> Result<Peer> {
    if let Some(block) = value.get("ipBlock").filter(|v| !v.is_null()) {
        let cidr = block
            .get("cidr")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| invalid("ipBlock without cidr"))?;
        let mut except = Vec::new();
        for item in list(block.get("except"), "ipBlock.except")? {
            except.push(
                item.as_str()
                    .ok_or_else(|| invalid("ipBlock.except entries must be strings"))?
                    .to_owned(),
            );
        }
        return Ok(Peer::Cidr {
            cidr: cidr.into(),
            except,
        });
    }
    let mut pods = LabelSelector::parse(value.get("podSelector"))?;
    if let Some(cluster) = cluster
        && !pods.constrains(POLICY_CLUSTER)
    {
        pods.match_labels
            .insert(POLICY_CLUSTER.into(), cluster.into());
    }
    let selector = match value.get("namespaceSelector").filter(|v| !v.is_null()) {
        Some(namespaces) => {
            let namespaces = LabelSelector::parse(Some(namespaces))?;
            let namespaces = if namespaces.is_empty() {
                LabelSelector {
                    match_expressions: vec![Requirement {
                        key: POD_NAMESPACE.into(),
                        operator: Operator::Exists,
                        values: BTreeSet::new(),
                    }],
                    ..LabelSelector::default()
                }
            } else {
                namespaces.rekey(|k| format!("{NAMESPACE_LABELS}.{k}"))
            };
            namespaces.and(pods)
        }
        None => {
            pods.match_labels
                .insert(POD_NAMESPACE.into(), namespace.into());
            pods
        }
    };
    Ok(Peer::Selector(selector.sourced()))
}

fn port(value: &Value) -> Result<PortRule> {
    let protocol = match value.get("protocol").and_then(Value::as_str) {
        None | Some("TCP") => Protocol::Tcp,
        Some("UDP") => Protocol::Udp,
        Some("SCTP") => Protocol::Sctp,
        Some(other) => return Err(invalid(format!("unsupported protocol {other}"))),
    };
    let port = match value.get("port") {
        None | Some(Value::Null) => "0".to_owned(),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| invalid(format!("invalid port {n}")))?
            .to_string(),
        Some(Value::String(name)) if !name.is_empty() => name.clone(),
        Some(other) => return Err(invalid(format!("invalid port {other}"))),
    };
    let end_port = match value.get("endPort") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| invalid(format!("invalid endPort {v}")))?,
        ),
    };
    Ok(PortRule {
        protocol,
        port,
        end_port,
    })
}

/// Translate one NetworkPolicy object. `cluster` limits same-cluster peer
/// selectors to that cluster; None is "any cluster".
pub fn network_policy(object: &Value, cluster: Option<&str>) -> Result<Vec<Entry>> {
    let metadata = object
        .get("metadata")
        .ok_or_else(|| invalid("NetworkPolicy without metadata"))?;
    let text = |key: &str| metadata.get(key).and_then(Value::as_str).unwrap_or("");
    let namespace = match text("namespace") {
        "" => "default",
        ns => ns,
    };
    let name = metadata
        .pointer(&format!(
            "/annotations/{}",
            NAME_ANNOTATION.replace('/', "~1")
        ))
        .and_then(Value::as_str)
        .unwrap_or(text("name"));
    let spec = object
        .get("spec")
        .ok_or_else(|| invalid("NetworkPolicy without spec"))?;
    let mut subject = LabelSelector::parse(spec.get("podSelector"))?;
    subject
        .match_labels
        .insert(POD_NAMESPACE.into(), namespace.into());
    let subject = subject.sourced();
    let mut labels = vec![
        format!("{SOURCE}:{DERIVED_FROM}=NetworkPolicy"),
        format!("{SOURCE}:{POLICY_NAME}={name}"),
        format!("{SOURCE}:{POLICY_NAMESPACE}={namespace}"),
        format!("{SOURCE}:{POLICY_UID}={}", text("uid")),
    ];
    labels.sort();

    let mut types = BTreeSet::new();
    for item in list(spec.get("policyTypes"), "policyTypes")? {
        match item.as_str() {
            Some(kind @ ("Ingress" | "Egress")) => {
                types.insert(kind);
            }
            other => return Err(invalid(format!("unknown policyType {other:?}"))),
        }
    }
    if types.is_empty() {
        types.insert("Ingress");
        if spec.get("egress").is_some_and(|v| !v.is_null()) {
            types.insert("Egress");
        }
    }

    let entry = |ingress: bool, l3: Option<Vec<Peer>>, l4: Option<Vec<PortRule>>| Entry {
        tier: Tier::Normal,
        priority: 0.0,
        verdict: Verdict::Allow,
        ingress,
        subject: subject.clone(),
        l3,
        l4,
        labels: labels.clone(),
        default_deny: true,
    };
    let mut entries = Vec::new();
    for (ingress, kind, rules_key, peers_key) in [
        (true, "Ingress", "ingress", "from"),
        (false, "Egress", "egress", "to"),
    ] {
        if !types.contains(kind) {
            continue;
        }
        let before = entries.len();
        for rule in list(spec.get(rules_key), rules_key)? {
            let mut ports = Vec::new();
            for item in list(rule.get("ports"), "ports")? {
                ports.push(port(item)?);
            }
            let l4 = (!ports.is_empty()).then_some(ports);
            let peers = list(rule.get(peers_key), peers_key)?;
            if peers.is_empty() {
                entries.push(entry(ingress, None, l4));
            } else {
                for item in peers {
                    let peer = peer(item, namespace, cluster)?;
                    entries.push(entry(ingress, Some(vec![peer]), l4.clone()));
                }
            }
        }
        if entries.len() == before {
            entries.push(entry(ingress, Some(Vec::new()), None));
        }
    }
    Ok(entries)
}

/// A peer the lowering cannot express yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsupported {
    pub labels: Vec<String>,
    pub peer: Peer,
    pub why: &'static str,
}

/// Lower entries to the simulator's (one per entry x peer x port), for
/// direct evaluation and compilation over endpoint identities. A default-deny
/// marker becomes an entry whose peers select nothing. `ipBlock` peers need
/// CIDR identities, which do not exist yet: they are returned as unsupported
/// and allow nothing, so a policy is never made more permissive than written.
pub fn lower(
    entries: &[Entry],
) -> std::result::Result<(Vec<crate::simulator::Entry>, Vec<Unsupported>), crate::Error> {
    use crate::{
        oracle::{Peer as OraclePeer, Rule},
        ports::PortRange,
        simulator::{Entry as SimEntry, Port, Selector},
    };
    let mut out = Vec::new();
    let mut unsupported = Vec::new();
    for entry in entries {
        let mut peers = Vec::new();
        match &entry.l3 {
            None => peers.push(Selector::Any),
            Some(list) if list.is_empty() => peers.push(Selector::None),
            Some(list) => {
                for peer in list {
                    match peer {
                        Peer::Selector(selector) => {
                            peers.push(Selector::Kubernetes(selector.clone()));
                        }
                        Peer::Cidr { .. } => unsupported.push(Unsupported {
                            labels: entry.labels.clone(),
                            peer: peer.clone(),
                            why: "ipBlock peers need CIDR identities",
                        }),
                    }
                }
            }
        }
        // (protocol, port); None for every protocol and port.
        let mut ports: Vec<(u8, Port)> = Vec::new();
        match &entry.l4 {
            None => ports.push((0, Port::Numeric(PortRange::any()))),
            Some(list) => {
                for rule in list {
                    let protocol = rule.protocol.number();
                    let port = match rule.port.parse::<u16>() {
                        Ok(0) if rule.end_port.is_none() => Port::Numeric(PortRange::any()),
                        Ok(number) => Port::Numeric(PortRange::from_api(number, rule.end_port)?),
                        Err(_) => Port::Named(rule.port.clone()),
                    };
                    ports.push((protocol, port));
                }
            }
        }
        for selector in &peers {
            for (protocol, port) in &ports {
                out.push(SimEntry {
                    subject: Selector::Kubernetes(entry.subject.clone()),
                    peers: selector.clone(),
                    default_deny: entry.default_deny,
                    rule: Rule {
                        tier: entry.tier,
                        priority: entry.priority,
                        verdict: entry.verdict,
                        egress: !entry.ingress,
                        peer: OraclePeer::Any,
                        protocol: *protocol,
                        ports: PortRange::any(),
                        authentication: None,
                        proxy_port: 0,
                        listener_priority: 0,
                    },
                    port: port.clone(),
                });
            }
        }
    }
    Ok((out, unsupported))
}

#[cfg(test)]
#[path = "k8s_tests.rs"]
mod tests;
