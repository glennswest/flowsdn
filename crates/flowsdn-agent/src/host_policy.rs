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
//! `fromNodes`, `fromGroups`, `cidrGroupRef`, authentication, named ports,
//! and `endpointSelector` specs (Pod policies of this kind). The annotation
//! [`AUDIT_ANNOTATION`] `"true"` puts the host in audit mode.
//!
//! Pure data: `policy::compile` resolves peers to identities.
use flowsdn_policy::{k8s::LabelSelector, ports::PortRange};
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
    Cidr { cidr: String, except: Vec<String> },
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
    /// (protocol, ports); empty: every protocol and port.
    pub ports: Vec<(u8, PortRange)>,
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

/// (protocol number, range) pairs of `toPorts`; `ANY` is TCP, UDP and SCTP.
fn ports(rule: &Value, policy: &str, problems: &mut BTreeSet<String>) -> Option<Vec<(u8, PortRange)>> {
    let mut out = Vec::new();
    let Some(list) = rule.get("toPorts").filter(|v| !v.is_null()) else {
        return Some(out);
    };
    for item in list.as_array()? {
        if item.get("rules").is_some_and(|v| !v.is_null())
            || item.get("listener").is_some_and(|v| !v.is_null())
        {
            problems.insert(format!("{policy}: L7 rules are not enforced; the rule is skipped"));
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
            out.extend(protocols.iter().map(|p| (*p, range)));
        }
    }
    Some(out)
}

/// One `ingress`/`ingressDeny` rule.
fn rule(
    value: &Value,
    deny: bool,
    policy: &str,
    problems: &mut BTreeSet<String>,
) -> Option<Rule> {
    for field in [
        "fromRequires",
        "fromNodes",
        "fromGroups",
        "icmps",
        "authentication",
    ] {
        if value.get(field).is_some_and(|v| !v.is_null()) {
            problems.insert(format!(
                "{policy}: {field} is not enforced; the rule is skipped"
            ));
            return None;
        }
    }
    let mut peers = Vec::new();
    let mut any_l3 = false;
    if let Some(list) = value.get("fromEntities").filter(|v| !v.is_null()) {
        any_l3 = true;
        for name in strings(Some(list))? {
            match entity(&name) {
                Some(ids) => peers.push(Peer::Identities(ids)),
                None => {
                    problems.insert(format!("{policy}: unknown entity {name}; it allows nothing"));
                }
            }
        }
    }
    if let Some(list) = value.get("fromCIDR").filter(|v| !v.is_null()) {
        any_l3 = true;
        for cidr in strings(Some(list))? {
            peers.push(Peer::Cidr {
                cidr,
                except: Vec::new(),
            });
        }
    }
    if let Some(list) = value.get("fromCIDRSet").filter(|v| !v.is_null()) {
        any_l3 = true;
        for item in list.as_array()? {
            match item.get("cidr").and_then(Value::as_str) {
                Some(cidr) => peers.push(Peer::Cidr {
                    cidr: cidr.to_owned(),
                    except: strings(item.get("except")).unwrap_or_default(),
                }),
                None => {
                    problems.insert(format!(
                        "{policy}: fromCIDRSet without cidr (cidrGroupRef) is not enforced"
                    ));
                }
            }
        }
    }
    if let Some(list) = value.get("fromEndpoints").filter(|v| !v.is_null()) {
        any_l3 = true;
        for item in list.as_array()? {
            match LabelSelector::parse(Some(item)) {
                Ok(selector) => peers.push(Peer::Endpoints(rekey(selector, sourced_key))),
                Err(error) => {
                    problems.insert(format!("{policy}: fromEndpoints {error}; it allows nothing"));
                }
            }
        }
    }
    let ports = ports(value, policy, problems)?;
    Some(Rule {
        policy: policy.to_owned(),
        deny,
        peers: if !any_l3 && !ports.is_empty() {
            None
        } else {
            Some(peers)
        },
        ports,
    })
}

/// The host policies among `objects` that select a node with `labels`.
pub fn select(objects: &[Value], labels: &BTreeMap<String, String>) -> HostPolicies {
    let mut out = HostPolicies::default();
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
                if spec.get("endpointSelector").is_some_and(|v| !v.is_null()) {
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
                    if let Some(rule) = rule(item, deny, &name, &mut out.problems) {
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
