//! L2 announcements (#475): which node answers ARP and NDP for a Service's
//! load-balancer and external addresses, and on which interfaces.
//!
//! Pure data; the Kubernetes controller's announcer thread feeds it the
//! FlowsdnL2AnnouncementPolicies, Services, EndpointSlices, Nodes and this
//! node's interfaces, and answers for what it returns
//! (`flowsdn_connector::announce`).
//!
//! - A policy selects Services by `serviceSelector` (with
//!   `io.kubernetes.service.namespace` and `io.kubernetes.service.name`) and
//!   nodes by `nodeSelector` (absent: all), and announces the Services'
//!   ingress addresses when `loadBalancerIPs` is true and `spec.externalIPs`
//!   when `externalIPs` is true (both default false, as in the reference).
//!   Ingress addresses are announced for `type: LoadBalancer` Services with
//!   no `loadBalancerClass` or `io.flowsdn/l2-announcer`.
//! - One node answers for a Service, so a client's traffic reaches one
//!   node: the candidate with the highest rendezvous hash of (node, Service).
//!   Candidates are Ready nodes some selecting policy selects; with
//!   `externalTrafficPolicy: Local`, only those with a ready endpoint of the
//!   Service (the uplink programs send Local traffic to this node's
//!   endpoints only). Every agent computes the same winner from the same
//!   lists; a change moves the address, and the new node announces it with
//!   gratuitous ARP / unsolicited NA.
//! - The interfaces are those of this node a policy's `interfaces` regular
//!   expressions match (any of them, unanchored); without `interfaces`,
//!   the uplinks with carrier that are on the address's subnet, else every
//!   uplink with carrier.
use crate::kubernetes::NodeInfo;
use crate::lb_ipam::{LB_CLASS_L2, service_labels};
use crate::services::{ServiceInfo, SliceInfo};
use crate::uplinks::Uplink;
use flowsdn_policy::k8s::LabelSelector;
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub name: String,
    pub service_selector: LabelSelector,
    pub node_selector: LabelSelector,
    /// `None`: no `interfaces` (the uplinks).
    pub interfaces: Option<Vec<Regex>>,
    pub load_balancer_ips: bool,
    pub external_ips: bool,
    /// Why the policy is not used (a bad selector or expression).
    pub invalid: Option<String>,
}
impl Policy {
    /// A FlowsdnL2AnnouncementPolicy object.
    pub fn parse(object: &Value) -> Policy {
        let spec = object.get("spec").unwrap_or(&Value::Null);
        let mut policy = Policy {
            name: object
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            load_balancer_ips: spec.get("loadBalancerIPs").and_then(Value::as_bool) == Some(true),
            external_ips: spec.get("externalIPs").and_then(Value::as_bool) == Some(true),
            ..Policy::default()
        };
        let mut problems = Vec::new();
        match LabelSelector::parse(spec.get("serviceSelector")) {
            Ok(s) => policy.service_selector = s,
            Err(e) => problems.push(format!("serviceSelector: {e}")),
        }
        match LabelSelector::parse(spec.get("nodeSelector")) {
            Ok(s) => policy.node_selector = s,
            Err(e) => problems.push(format!("nodeSelector: {e}")),
        }
        if let Some(list) = spec.get("interfaces").and_then(Value::as_array) {
            let mut compiled = Vec::new();
            for item in list {
                match item.as_str().map(Regex::new) {
                    Some(Ok(re)) => compiled.push(re),
                    Some(Err(e)) => problems.push(format!("interfaces: {e}")),
                    None => problems.push("interfaces: not a string".into()),
                }
            }
            policy.interfaces = Some(compiled);
        }
        if !problems.is_empty() {
            policy.invalid = Some(problems.join("; "));
        }
        policy
    }
}

/// One address this node answers for.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Announcement {
    pub ip: IpAddr,
    pub namespace: String,
    pub name: String,
    /// Interface names, sorted.
    pub interfaces: Vec<String>,
}

/// FNV-1a 64 of `node`, a NUL and `service`: the rendezvous weight.
fn weight(node: &str, service: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in node.bytes().chain([0u8]).chain(service.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The nodes with a ready endpoint of `service`.
fn endpoint_nodes<'a>(service: &ServiceInfo, slices: &'a [SliceInfo]) -> BTreeSet<&'a str> {
    slices
        .iter()
        .filter(|s| s.namespace == service.namespace && s.service == service.name)
        .flat_map(|s| s.endpoints.iter())
        .filter(|e| e.ready && !e.node_name.is_empty())
        .map(|e| e.node_name.as_str())
        .collect()
}

/// The node that answers for `service` among `candidates`.
pub fn elect<'a>(service: &ServiceInfo, candidates: &[&'a str]) -> Option<&'a str> {
    let key = format!("{}/{}", service.namespace, service.name);
    candidates
        .iter()
        .copied()
        .max_by_key(|node| (weight(node, &key), *node))
}

/// This node's interfaces for `ip`, given the policies that announce it here.
fn interfaces_for(
    ip: IpAddr,
    policies: &[&Policy],
    uplinks: &[Uplink],
    interfaces: &[String],
) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut default = false;
    for policy in policies {
        match &policy.interfaces {
            Some(expressions) => {
                for name in interfaces {
                    if expressions.iter().any(|re| re.is_match(name)) {
                        out.insert(name.clone());
                    }
                }
            }
            None => default = true,
        }
    }
    if default {
        let live: Vec<&Uplink> = uplinks.iter().filter(|u| u.up).collect();
        let on_subnet: Vec<&&Uplink> = live.iter().filter(|u| u.reaches(ip)).collect();
        if on_subnet.is_empty() {
            out.extend(live.iter().map(|u| u.name.clone()));
        } else {
            out.extend(on_subnet.iter().map(|u| u.name.clone()));
        }
    }
    out.into_iter().collect()
}

/// What this node (`local`) answers for.
pub fn plan(
    policies: &[Policy],
    services: &[ServiceInfo],
    slices: &[SliceInfo],
    nodes: &[NodeInfo],
    local: &str,
    uplinks: &[Uplink],
    interfaces: &[String],
) -> Vec<Announcement> {
    let valid: Vec<&Policy> = policies.iter().filter(|p| p.invalid.is_none()).collect();
    let mut out = BTreeMap::new();
    for service in services {
        let labels = service_labels(service);
        let selecting: Vec<&Policy> = valid
            .iter()
            .copied()
            .filter(|p| p.service_selector.matches(&labels))
            .collect();
        if selecting.is_empty() {
            continue;
        }
        let lb_class = service
            .load_balancer_class
            .as_deref()
            .is_none_or(|c| c == LB_CLASS_L2);
        let mut addresses: Vec<(IpAddr, Vec<&Policy>)> = Vec::new();
        if service.service_type == "LoadBalancer" && lb_class {
            let by: Vec<&Policy> = selecting
                .iter()
                .copied()
                .filter(|p| p.load_balancer_ips)
                .collect();
            if !by.is_empty() {
                addresses.extend(service.load_balancer_ips.iter().map(|ip| (*ip, by.clone())));
            }
        }
        let by: Vec<&Policy> = selecting
            .iter()
            .copied()
            .filter(|p| p.external_ips)
            .collect();
        if !by.is_empty() {
            addresses.extend(service.external_ips.iter().map(|ip| (*ip, by.clone())));
        }
        if addresses.is_empty() {
            continue;
        }
        let with_endpoints = endpoint_nodes(service, slices);
        for (ip, by) in addresses {
            let candidates: Vec<&str> = nodes
                .iter()
                .filter(|n| n.ready)
                .filter(|n| by.iter().any(|p| p.node_selector.matches(&n.labels)))
                .filter(|n| !service.external_local || with_endpoints.contains(n.name.as_str()))
                .map(|n| n.name.as_str())
                .collect();
            if elect(service, &candidates) != Some(local) {
                continue;
            }
            let here: Vec<&Policy> = by
                .iter()
                .copied()
                .filter(|p| {
                    nodes
                        .iter()
                        .any(|n| n.name == local && p.node_selector.matches(&n.labels))
                })
                .collect();
            let names = interfaces_for(ip, &here, uplinks, interfaces);
            if names.is_empty() {
                continue;
            }
            out.entry(ip).or_insert(Announcement {
                ip,
                namespace: service.namespace.clone(),
                name: service.name.clone(),
                interfaces: names,
            });
        }
    }
    out.into_values().collect()
}

/// `GET /v1/l2-announcements`.
pub fn status_json(announcements: &[Announcement], policies: &[Policy], errors: &[String]) -> Value {
    json!({
        "policies": policies.iter().map(|p| json!({
            "name": p.name,
            "invalid": p.invalid,
        })).collect::<Vec<_>>(),
        "announcing": announcements.iter().map(|a| json!({
            "ip": a.ip.to_string(),
            "service": format!("{}/{}", a.namespace, a.name),
            "interfaces": a.interfaces,
        })).collect::<Vec<_>>(),
        "errors": errors,
    })
}

#[cfg(test)]
#[path = "l2_announce_tests.rs"]
mod tests;
