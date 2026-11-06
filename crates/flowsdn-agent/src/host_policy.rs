//! The host firewall's rules (#379): the host-policy parts of
//! `FlowsdnClusterwideNetworkPolicy` objects, the rule model of the
//! reference's host firewall (a `CiliumClusterwideNetworkPolicy` with a
//! `nodeSelector`), so one policy works on both flavours (stormcos#558: the
//! stormfw controller translates its `HostFirewallPolicy` into one).
//!
//! A spec selects this node when it has a `nodeSelector` that matches the
//! Node's labels. Supported: `ingress` and `ingressDeny` rules with
//! `fromEntities`, `fromCIDR`, `fromCIDRSet` (`cidr`, `except`),
//! `fromEndpoints` and `toPorts` (`port`, `endPort`, `protocol`), and
//! `enableDefaultDeny.ingress`. Everything else is reported and not
//! enforced: egress rules, L7 rules, ICMP rules, `fromRequires`,
//! `fromNodes`, `fromGroups`, `cidrGroupRef`, authentication and named
//! ports. The annotation [`AUDIT_ANNOTATION`] `"true"` puts the host in audit
//! mode.
//!
//! The same rule model selects Pods (#292, [`pod_policies`]):
//! `endpointSelector` specs of FlowsdnClusterwideNetworkPolicy and
//! FlowsdnNetworkPolicy, in both directions, with named ports and the
//! namespace and cluster of spec 06 §3.2.9.
//!
//! Pure data: `policy::compile` resolves peers to identities.
use flowsdn_policy::{
    k8s::{LabelSelector, NAMESPACE_LABELS, Operator, POD_NAMESPACE, POLICY_CLUSTER, Requirement},
    ports::PortRange,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A selecting policy with this annotation set to `"true"` puts the host
/// endpoint in audit mode: would-be drops are counted and passed.
pub const AUDIT_ANNOTATION: &str = "policy.flowsdn.io/audit";

/// Reserved identities (spec 03 §4.4).
pub const HOST: u32 = 1;
pub const WORLD: u32 = 2;
pub const UNMANAGED: u32 = 3;
pub const HEALTH: u32 = 4;
pub const INIT: u32 = 5;
pub const REMOTE_NODE: u32 = 6;
pub const KUBE_APISERVER: u32 = 7;
pub const INGRESS: u32 = 8;
/// Aggregate identities the datapath derives (spec 03 `aggregate_for`).
pub const AGGREGATE_CLUSTER: u32 = 11;
pub const AGGREGATE_WORLD: u32 = 13;

/// Where a rule allows (or denies) traffic from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Peer {
    /// Fixed identities (entities).
    Identities(Vec<u32>),
    Cidr {
        cidr: String,
        except: Vec<String>,
    },
    /// Pods whose identity labels match.
    Endpoints(LabelSelector),
}

/// One ingress rule of a host policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// `namespace/name` of the policy (cluster-scoped: `/name`).
    pub policy: String,
    pub deny: bool,
    /// `None`: every source (an L4-only rule). `Some(empty)`: nothing.
    pub peers: Option<Vec<Peer>>,
    /// (protocol, ports). With `named` also empty: every protocol and port.
    pub ports: Vec<(u8, PortRange)>,
    /// (protocol, port name): the destination's container ports name them
    /// (Pod rules only).
    pub named: Vec<(u8, String)>,
}

/// The policies that select this node, merged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostPolicies {
    /// Names of the selecting policies.
    pub names: Vec<String>,
    /// Some selecting spec turns on ingress default deny.
    pub enforce_ingress: bool,
    pub audit: bool,
    pub rules: Vec<Rule>,
    pub problems: BTreeSet<String>,
}

/// The node selector's keys may carry a label source (`k8s:`, `any:`).
fn plain_key(key: &str) -> String {
    key.strip_prefix("k8s:")
        .or_else(|| key.strip_prefix("any:"))
        .unwrap_or(key)
        .to_owned()
}
/// An endpoint selector's keys as identity labels spell them (`k8s:app`):
/// no source and `any:` mean any source, and Pod identities have `k8s:`.
fn sourced_key(key: &str) -> String {
    match key.split_once(':') {
        Some(("any", rest)) => format!("k8s:{rest}"),
        Some((source, _)) if !source.contains('/') && !source.contains('.') => key.to_owned(),
        _ => format!("k8s:{key}"),
    }
}
fn rekey(selector: LabelSelector, rename: impl Fn(&str) -> String) -> LabelSelector {
    LabelSelector {
        match_labels: selector
            .match_labels
            .into_iter()
            .map(|(k, v)| (rename(&k), v))
            .collect(),
        match_expressions: selector
            .match_expressions
            .into_iter()
            .map(|mut r| {
                r.key = rename(&r.key);
                r
            })
            .collect(),
    }
}

/// The identities an entity names; `None` for an unknown entity.
pub fn entity(name: &str) -> Option<Vec<u32>> {
    Some(match name {
        "all" => vec![0],
        "world" | "world-ipv4" | "world-ipv6" => vec![WORLD, AGGREGATE_WORLD],
        "cluster" => vec![
            HOST,
            UNMANAGED,
            HEALTH,
            INIT,
            REMOTE_NODE,
            KUBE_APISERVER,
            INGRESS,
            AGGREGATE_CLUSTER,
        ],
        "host" => vec![HOST],
        "remote-node" => vec![REMOTE_NODE],
        "health" => vec![HEALTH],
        "init" => vec![INIT],
        "kube-apiserver" => vec![KUBE_APISERVER],
        "ingress" => vec![INGRESS],
        "unmanaged" => vec![UNMANAGED],
        "none" => vec![],
        _ => return None,
    })
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// The `toPorts` of a rule.
#[derive(Default)]
struct Ports {
    ranges: Vec<(u8, PortRange)>,
    named: Vec<(u8, String)>,
}

/// (protocol number, range) pairs of `toPorts`; `ANY` is TCP, UDP and SCTP.
fn ports(
    rule: &Value,
    policy: &str,
    problems: &mut BTreeSet<String>,
    allow_named: bool,
) -> Option<Ports> {
    let mut out = Ports::default();
    let Some(list) = rule.get("toPorts").filter(|v| !v.is_null()) else {
        return Some(out);
    };
    for item in list.as_array()? {
        if item.get("rules").is_some_and(|v| !v.is_null())
            || item.get("listener").is_some_and(|v| !v.is_null())
        {
            problems.insert(format!(
                "{policy}: L7 rules are not enforced; the rule is skipped"
            ));
            return None;
        }
        let Some(entries) = item.get("ports").and_then(Value::as_array) else {
            continue;
        };
        for port in entries {
            let protocols: &[u8] = match port.get("protocol").and_then(Value::as_str) {
                None | Some("ANY") => &[6, 17, 132],
                Some("TCP") => &[6],
                Some("UDP") => &[17],
                Some("SCTP") => &[132],
                Some(other) => {
                    problems.insert(format!("{policy}: protocol {other} is not enforced"));
                    return None;
                }
            };
            let text = match port.get("port") {
                None | Some(Value::Null) => "0".to_owned(),
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                Some(_) => return None,
            };
            let Ok(number) = text.parse::<u16>() else {
                if allow_named {
                    out.named
                        .extend(protocols.iter().map(|p| (*p, text.to_lowercase())));
                    continue;
                }
                problems.insert(format!(
                    "{policy}: named port {text} has no meaning on the host; the rule is skipped"
                ));
                return None;
            };
            let end = port
                .get("endPort")
                .and_then(Value::as_u64)
                .and_then(|e| u16::try_from(e).ok())
                .filter(|e| *e != 0);
            let Ok(range) = PortRange::from_api(number, end) else {
                problems.insert(format!("{policy}: port {text}-{end:?} is not a range"));
                return None;
            };
            out.ranges.extend(protocols.iter().map(|p| (*p, range)));
        }
    }
    Some(out)
}

/// Which rule a parse reads: the peer fields' prefix (`from`, or `to` for
/// egress) and, for Pod rules, the namespace and cluster peers get.
struct Side<'a> {
    prefix: &'static str,
    /// `None`: the host firewall. `Some((namespace, cluster))`: a Pod rule of
    /// that namespace (`None` for the clusterwide kind).
    pods: Option<(Option<&'a str>, &'a str)>,
}

/// Whether a selector has a `reserved:` key; identities of Pods have none.
fn has_reserved(selector: &LabelSelector) -> bool {
    selector
        .match_labels
        .keys()
        .chain(selector.match_expressions.iter().map(|r| &r.key))
        .any(|k| k.starts_with("reserved:"))
}

/// Spec 06 §3.2.9 step 2 on a peer selector whose keys carry their source.
fn inject(mut selector: LabelSelector, namespace: Option<&str>, cluster: &str) -> LabelSelector {
    if has_reserved(&selector) {
        return selector;
    }
    let namespace_key = format!("k8s:{POD_NAMESPACE}");
    let labels_prefix = format!("k8s:{NAMESPACE_LABELS}.");
    let names_namespace_labels = selector
        .match_labels
        .keys()
        .chain(selector.match_expressions.iter().map(|r| &r.key))
        .any(|k| k.starts_with(&labels_prefix));
    if !selector.constrains(&namespace_key) {
        match namespace {
            None => selector.match_expressions.push(Requirement {
                key: namespace_key,
                operator: Operator::Exists,
                values: BTreeSet::new(),
            }),
            Some(namespace) if !names_namespace_labels => {
                selector
                    .match_labels
                    .insert(namespace_key, namespace.to_owned());
            }
            Some(_) => {}
        }
    }
    let cluster_key = format!("k8s:{POLICY_CLUSTER}");
    if !selector.constrains(&cluster_key) {
        selector
            .match_labels
            .insert(cluster_key, cluster.to_owned());
    }
    selector
}

/// The reference's combination matrix (spec 06 §3.2.1): the first pair of a
/// rule's L3 members that may not be combined.
fn bad_combination(value: &Value, prefix: &str) -> Option<String> {
    const MEMBERS: [&str; 6] = [
        "Endpoints",
        "CIDR",
        "CIDRSet",
        "Entities",
        "Nodes",
        "Groups",
    ];
    let present: Vec<&str> = MEMBERS
        .iter()
        .copied()
        .filter(|m| {
            value
                .get(format!("{prefix}{m}"))
                .and_then(Value::as_array)
                .is_some_and(|list| !list.is_empty())
        })
        .collect();
    for (at, first) in present.iter().enumerate() {
        for second in present.iter().skip(at.saturating_add(1)) {
            if !matches!(
                (*first, *second),
                ("Endpoints", "Entities") | ("CIDR", "CIDRSet")
            ) {
                return Some(format!(
                    "combining {prefix}{first} and {prefix}{second} is not supported"
                ));
            }
        }
    }
    None
}

/// One rule of a direction.
fn rule(
    value: &Value,
    deny: bool,
    policy: &str,
    problems: &mut BTreeSet<String>,
    side: &Side<'_>,
) -> Option<Rule> {
    let prefix = side.prefix;
    let mut unsupported = vec![
        format!("{prefix}Requires"),
        format!("{prefix}Nodes"),
        format!("{prefix}Groups"),
        "icmps".to_owned(),
        "authentication".to_owned(),
    ];
    if prefix == "to" {
        unsupported.extend(["toServices".to_owned(), "toFQDNs".to_owned()]);
    }
    for field in &unsupported {
        if value.get(field).is_some_and(|v| !v.is_null()) {
            problems.insert(format!(
                "{policy}: {field} is not enforced; the rule is skipped"
            ));
            return None;
        }
    }
    let mut peers = Vec::new();
    let mut any_l3 = false;
    if let Some(list) = value
        .get(format!("{prefix}Entities"))
        .filter(|v| !v.is_null())
    {
        any_l3 = true;
        for name in strings(Some(list))? {
            match entity(&name) {
                Some(ids) => peers.push(Peer::Identities(ids)),
                None => {
                    problems.insert(format!(
                        "{policy}: unknown entity {name}; it allows nothing"
                    ));
                }
            }
        }
    }
    if let Some(list) = value.get(format!("{prefix}CIDR")).filter(|v| !v.is_null()) {
        any_l3 = true;
        for cidr in strings(Some(list))? {
            peers.push(Peer::Cidr {
                cidr,
                except: Vec::new(),
            });
        }
    }
    if let Some(list) = value
        .get(format!("{prefix}CIDRSet"))
        .filter(|v| !v.is_null())
    {
        any_l3 = true;
        for item in list.as_array()? {
            match item.get("cidr").and_then(Value::as_str) {
                Some(cidr) => peers.push(Peer::Cidr {
                    cidr: cidr.to_owned(),
                    except: strings(item.get("except")).unwrap_or_default(),
                }),
                None => {
                    problems.insert(format!(
                        "{policy}: {prefix}CIDRSet without cidr (cidrGroupRef) is not enforced"
                    ));
                }
            }
        }
    }
    if let Some(list) = value
        .get(format!("{prefix}Endpoints"))
        .filter(|v| !v.is_null())
    {
        any_l3 = true;
        for item in list.as_array()? {
            match LabelSelector::parse(Some(item)) {
                Ok(selector) => {
                    let selector = rekey(selector, sourced_key);
                    if side.pods.is_some() && has_reserved(&selector) {
                        problems.insert(format!(
                            "{policy}: {prefix}Endpoints with a reserved: label selects no \
                             identity; use {prefix}Entities"
                        ));
                        continue;
                    }
                    peers.push(Peer::Endpoints(match side.pods {
                        Some((namespace, cluster)) => inject(selector, namespace, cluster),
                        None => selector,
                    }));
                }
                Err(error) => {
                    problems.insert(format!(
                        "{policy}: {prefix}Endpoints {error}; it allows nothing"
                    ));
                }
            }
        }
    }
    let ports = ports(value, policy, problems, side.pods.is_some())?;
    let no_ports = ports.ranges.is_empty() && ports.named.is_empty();
    Some(Rule {
        policy: policy.to_owned(),
        deny,
        peers: if any_l3 || no_ports { Some(peers) } else { None },
        ports: ports.ranges,
        named: ports.named,
    })
}

/// One direction of a Pod policy spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PodDirection {
    /// The spec has rules of this direction, or turns its default deny on:
    /// the direction is enforced on the Pods it selects (spec 06 §3.6).
    pub selects: bool,
    /// `enableDefaultDeny`: true unless the spec says otherwise, when it has
    /// rules of this direction (§3.2.8). Without it the rules only add to a
    /// wildcard allow.
    pub default_deny: bool,
    pub rules: Vec<Rule>,
}
/// One `endpointSelector` spec of a policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PodPolicy {
    /// `namespace/name` (cluster-scoped: `/name`).
    pub name: String,
    pub subject: LabelSelector,
    pub ingress: PodDirection,
    pub egress: PodDirection,
}

fn pod_direction(
    spec: &Value,
    egress: bool,
    name: &str,
    problems: &mut BTreeSet<String>,
    namespace: Option<&str>,
    cluster: &str,
) -> PodDirection {
    let (allow, deny, prefix, switch) = if egress {
        ("egress", "egressDeny", "to", "/enableDefaultDeny/egress")
    } else {
        (
            "ingress",
            "ingressDeny",
            "from",
            "/enableDefaultDeny/ingress",
        )
    };
    let side = Side {
        prefix,
        pods: Some((namespace, cluster)),
    };
    let mut out = PodDirection::default();
    let mut has_rules = false;
    for (field, is_deny) in [(allow, false), (deny, true)] {
        for item in spec
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            has_rules = true;
            if let Some(rule) = rule(item, is_deny, name, problems, &side) {
                out.rules.push(rule);
            }
        }
    }
    out.default_deny = spec
        .pointer(switch)
        .and_then(Value::as_bool)
        .unwrap_or(has_rules);
    out.selects = has_rules || out.default_deny;
    out
}

/// A spec that fails the reference's validation fails its whole resource
/// (spec 06 §3.2.9 step 6).
fn pod_spec(
    spec: &Value,
    name: &str,
    namespace: Option<&str>,
    cluster: &str,
    problems: &mut BTreeSet<String>,
) -> Result<Option<PodPolicy>, String> {
    let has = |field: &str| spec.get(field).is_some_and(|v| !v.is_null());
    match (has("endpointSelector"), has("nodeSelector")) {
        // A host rule: the host firewall reads it.
        (false, true) if namespace.is_none() => return Ok(None),
        (false, true) => return Err("nodeSelector is cluster-scoped".into()),
        (true, true) => return Err("both endpointSelector and nodeSelector".into()),
        (false, false) => return Err("neither endpointSelector nor nodeSelector".into()),
        (true, false) => {}
    }
    for (fields, prefix) in [
        (["ingress", "ingressDeny"], "from"),
        (["egress", "egressDeny"], "to"),
    ] {
        for field in fields {
            for item in spec
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(error) = bad_combination(item, prefix) {
                    return Err(error);
                }
            }
        }
    }
    let subject = LabelSelector::parse(spec.get("endpointSelector"))
        .map_err(|error| format!("endpointSelector {error}"))?;
    let mut subject = rekey(subject, sourced_key);
    if has_reserved(&subject) {
        problems.insert(format!(
            "{name}: an endpointSelector with a reserved: label selects no Pod"
        ));
        return Ok(None);
    }
    if let Some(namespace) = namespace {
        subject
            .match_labels
            .insert(format!("k8s:{POD_NAMESPACE}"), namespace.to_owned());
    }
    Ok(Some(PodPolicy {
        name: name.to_owned(),
        subject,
        ingress: pod_direction(spec, false, name, problems, namespace, cluster),
        egress: pod_direction(spec, true, name, problems, namespace, cluster),
    }))
}

/// The Pod policies of FlowsdnNetworkPolicy (`namespaced`) and
/// FlowsdnClusterwideNetworkPolicy (`clusterwide`) objects.
pub fn pod_policies(
    namespaced: &[Value],
    clusterwide: &[Value],
    cluster: &str,
) -> (Vec<PodPolicy>, BTreeSet<String>) {
    let mut out = Vec::new();
    let mut problems = BTreeSet::new();
    for (objects, scoped) in [(namespaced, true), (clusterwide, false)] {
        for object in objects {
            let text = |p: &str| object.pointer(p).and_then(Value::as_str).unwrap_or("");
            let namespace = scoped.then(|| text("/metadata/namespace"));
            let name = format!("{}/{}", namespace.unwrap_or(""), text("/metadata/name"));
            let mut specs: Vec<&Value> = Vec::new();
            if let Some(spec) = object.get("spec").filter(|v| !v.is_null()) {
                specs.push(spec);
            }
            if let Some(list) = object.get("specs").and_then(Value::as_array) {
                specs.extend(list);
            }
            let mut found = Vec::new();
            let mut failed = None;
            for spec in specs {
                match pod_spec(spec, &name, namespace, cluster, &mut problems) {
                    Ok(policy) => found.extend(policy),
                    Err(error) => {
                        failed = Some(error);
                        break;
                    }
                }
            }
            match failed {
                Some(error) => {
                    problems.insert(format!("{name}: not enforced, {error}"));
                }
                None => out.extend(found),
            }
        }
    }
    (out, problems)
}

/// The host policies among `objects` that select a node with `labels`.
/// `pod_rules`: another pass reads the `endpointSelector` specs
/// ([`pod_policies`]), so they are no problem here.
pub fn select(
    objects: &[Value],
    labels: &BTreeMap<String, String>,
    pod_rules: bool,
) -> HostPolicies {
    let mut out = HostPolicies::default();
    let side = Side {
        prefix: "from",
        pods: None,
    };
    for object in objects {
        let name = format!(
            "/{}",
            object
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
        );
        let mut specs: Vec<&Value> = Vec::new();
        if let Some(spec) = object.get("spec").filter(|v| !v.is_null()) {
            specs.push(spec);
        }
        if let Some(list) = object.get("specs").and_then(Value::as_array) {
            specs.extend(list);
        }
        let mut selected = false;
        for spec in specs {
            let Some(node_selector) = spec.get("nodeSelector").filter(|v| !v.is_null()) else {
                if !pod_rules && spec.get("endpointSelector").is_some_and(|v| !v.is_null()) {
                    out.problems.insert(format!(
                        "{name}: endpointSelector rules (Pod policy) are not enforced"
                    ));
                }
                continue;
            };
            let selector = match LabelSelector::parse(Some(node_selector)) {
                Ok(selector) => rekey(selector, plain_key),
                Err(error) => {
                    out.problems
                        .insert(format!("{name}: nodeSelector {error}; not enforced"));
                    continue;
                }
            };
            if !selector.matches(labels) {
                continue;
            }
            selected = true;
            for field in ["egress", "egressDeny"] {
                if spec.get(field).is_some_and(|v| !v.is_null()) {
                    out.problems
                        .insert(format!("{name}: host {field} rules are not enforced"));
                }
            }
            let mut has_ingress = false;
            for (field, deny) in [("ingress", false), ("ingressDeny", true)] {
                let Some(list) = spec.get(field).and_then(Value::as_array) else {
                    continue;
                };
                has_ingress = true;
                for item in list {
                    if let Some(rule) = rule(item, deny, &name, &mut out.problems, &side) {
                        out.rules.push(rule);
                    }
                }
            }
            let default_deny = spec
                .pointer("/enableDefaultDeny/ingress")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if has_ingress && default_deny {
                out.enforce_ingress = true;
            }
        }
        if selected {
            out.names.push(name);
            if object
                .pointer("/metadata/annotations")
                .and_then(|a| a.get(AUDIT_ANNOTATION))
                .and_then(Value::as_str)
                == Some("true")
            {
                out.audit = true;
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "host_policy_tests.rs"]
mod tests;
