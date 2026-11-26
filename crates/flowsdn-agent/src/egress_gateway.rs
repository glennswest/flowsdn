//! Egress gateway (#564, spec 14 §3.4, flowsdn's native-routing amendment):
//! FlowsdnEgressGatewayPolicy objects to `flowsdn_egress_gw_policy_v4`.
//!
//! - **Validation** (§3.4.2): a policy needs a name and `destinationCIDRs`
//!   (an empty list passes); each gateway names a `nodeSelector` and at most
//!   one of `interface` and `egressIP`; every selector entry needs a namespace
//!   or a Pod selector; every address and CIDR must parse. One failure drops
//!   the whole policy.
//! - **Sources:** Pods with an IPv4 address and a UID, not on the host
//!   network, that a selector entry's namespace selector (on the Namespace's
//!   labels; present but empty: every namespace) and Pod selector (present
//!   but empty: every Pod) both select. Every entry's `nodeSelector` is
//!   collected into one list, and the Pod's node must match one of them when
//!   there are any (the reference's global flattening).
//! - **Gateways** (§3.4.3): nodes in name order; the first a gateway's
//!   `nodeSelector` selects that has an IPv4 InternalIP. With
//!   `egressGateways`, a Pod's gateway is the FNV-1a of its UID modulo the
//!   resolved gateways, in address order. With none resolved, the entries
//!   carry gateway 0.0.0.0 and the Pod's matching traffic is dropped.
//! - **Egress address** (§3.4.4), only on the gateway node: the named
//!   interface's first IPv4 (with its index); else `egressIP` if this node
//!   holds it (index 0: the FIB chooses); else the first IPv4 of the uplink
//!   holding the node's address. On an error the address stays 0.0.0.0 and the
//!   gateway drops the traffic.
//! - **Entries** (§3.4.5): one per (source address, destination CIDR), and
//!   one per excluded CIDR with gateway 0.0.0.1 (passed on). Policies are taken
//!   in name order, and the first to write a key keeps it.
//!
//! - **IPv6** (#580): an IPv6 source and destination get an entry in
//!   `flowsdn_egress_gw_policy_v6` with the same gateway IPv4. Each resolved
//!   gateway's first IPv6 InternalIP goes into `flowsdn_egress_gw_nexthop6`,
//!   the next hop of IPv6 packets. A gateway without one has no next hop, and
//!   its IPv6 traffic is dropped. The IPv6 egress address is derived only when
//!   a destination is IPv6, the same way as the IPv4 one, from IPv6
//!   addresses: the interface's first, `egressIP` when it is IPv6 and held
//!   (else the first IPv6 of the interface holding it), else the uplink's.
//!   Mixed families (an IPv4 source with an IPv6 destination) match nothing.
use crate::kubernetes::{NodeInfo, PodInfo};
use flowsdn_bpf_abi::{
    MapBytes,
    egress::{
        EgressGw4Key, EgressGw4Value, EgressGw6Key, EgressGw6Value, GATEWAY_EXCLUDED,
        GATEWAY_NONE, SOURCE_BITS, SOURCE_BITS6,
    },
};
use flowsdn_policy::k8s::LabelSelector;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// One selector entry: namespace and Pod selectors (None: absent).
#[derive(Clone, Debug)]
struct Source {
    namespace: Option<LabelSelector>,
    pod: Option<LabelSelector>,
}
/// One gateway entry.
#[derive(Clone, Debug)]
struct Gateway {
    node: LabelSelector,
    interface: Option<String>,
    egress_ip: Option<IpAddr>,
}
/// A parsed, valid policy.
#[derive(Clone, Debug)]
pub struct Policy {
    pub name: String,
    sources: Vec<Source>,
    nodes: Vec<LabelSelector>,
    destinations: Vec<(IpAddr, u8)>,
    excluded: Vec<(IpAddr, u8)>,
    gateways: Vec<Gateway>,
}

fn cidr(text: &str) -> Result<(IpAddr, u8), String> {
    let (address, length) = text
        .split_once('/')
        .ok_or_else(|| format!("{text:?} is not a CIDR"))?;
    let ip: IpAddr = address
        .trim()
        .parse()
        .map_err(|_| format!("{text:?} is not a CIDR"))?;
    let length: u8 = length
        .trim()
        .parse()
        .ok()
        .filter(|l| *l <= if ip.is_ipv4() { 32 } else { 128 })
        .ok_or_else(|| format!("{text:?} is not a CIDR"))?;
    Ok((ip, length))
}
fn cidrs(value: Option<&Value>, what: &str) -> Result<Vec<(IpAddr, u8)>, String> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .map(|v| {
                    cidr(v.as_str().unwrap_or(""))
                        .map_err(|e| format!("failed to parse {what}: {e}"))
                })
                .collect()
        })
        .unwrap_or_else(|| Ok(Vec::new()))
}
fn selector(value: Option<&Value>, what: &str) -> Result<Option<LabelSelector>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => LabelSelector::parse(Some(v))
            .map(Some)
            .map_err(|e| format!("{what}: {e}")),
    }
}
fn gateway(value: &Value) -> Result<Gateway, String> {
    if value.is_null() {
        return Err("egress gateway can't be empty".into());
    }
    let node = selector(value.get("nodeSelector"), "nodeSelector")?.unwrap_or_default();
    let interface = value
        .get("interface")
        .and_then(Value::as_str)
        .filter(|i| !i.is_empty())
        .map(str::to_owned);
    let egress_ip = match value
        .get("egressIP")
        .and_then(Value::as_str)
        .filter(|i| !i.is_empty())
    {
        None => None,
        Some(text) => Some(
            text.parse()
                .map_err(|_| format!("failed to parse egress IP {text:?}"))?,
        ),
    };
    if interface.is_some() && egress_ip.is_some() {
        return Err("cannot specify both interface and egressIP".into());
    }
    Ok(Gateway {
        node,
        interface,
        egress_ip,
    })
}

/// Validate a FlowsdnEgressGatewayPolicy (spec 14 §3.4.2).
pub fn parse(object: &Value) -> Result<Policy, String> {
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    if name.is_empty() {
        return Err("must have a name".into());
    }
    let spec = object.get("spec").unwrap_or(&Value::Null);
    match spec.get("destinationCIDRs") {
        None | Some(Value::Null) => return Err("destination CIDRs can't be empty".into()),
        Some(_) => {}
    }
    let mut gateways = Vec::new();
    for entry in spec
        .get("egressGateways")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        gateways.push(gateway(entry)?);
    }
    if gateways.is_empty() {
        gateways.push(gateway(spec.get("egressGateway").unwrap_or(&Value::Null))?);
    }
    let destinations = cidrs(spec.get("destinationCIDRs"), "destination CIDR")?;
    let excluded = cidrs(spec.get("excludedCIDRs"), "excluded CIDR")?;
    let mut sources = Vec::new();
    let mut nodes = Vec::new();
    for entry in spec
        .get("selectors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let namespace = selector(entry.get("namespaceSelector"), "namespaceSelector")?;
        let pod = selector(entry.get("podSelector"), "podSelector")?;
        if namespace.is_none() && pod.is_none() {
            return Err("cannot have both nil namespace selector and nil pod selector".into());
        }
        if let Some(node) = selector(entry.get("nodeSelector"), "nodeSelector")? {
            nodes.push(node);
        }
        sources.push(Source { namespace, pod });
    }
    Ok(Policy {
        name,
        sources,
        nodes,
        destinations,
        excluded,
        gateways,
    })
}

/// A local interface: name, index, IPv4 addresses and global IPv6 addresses
/// (in kernel order).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Interface {
    pub name: String,
    pub index: u32,
    pub addresses: Vec<Ipv4Addr>,
    pub addresses6: Vec<Ipv6Addr>,
}
/// What this node knows about itself for the egress address.
#[derive(Clone, Debug, Default)]
pub struct Local<'a> {
    pub node: &'a str,
    pub interfaces: &'a [Interface],
    /// The uplink holding the node's address (the default route's device).
    pub primary: Option<&'a str>,
}

/// Derive the egress address and interface index on the gateway node.
fn egress(gateway: &Gateway, local: &Local<'_>) -> Result<(Ipv4Addr, u32), String> {
    if let Some(name) = &gateway.interface {
        let interface = local
            .interfaces
            .iter()
            .find(|i| i.name == *name)
            .ok_or_else(|| format!("no interface {name}"))?;
        let address = interface
            .addresses
            .first()
            .ok_or_else(|| format!("interface {name} has no IPv4 address"))?;
        return Ok((*address, interface.index));
    }
    if let Some(ip) = gateway.egress_ip {
        let IpAddr::V4(v4) = ip else {
            return Err(format!("egress IP {ip} is not IPv4"));
        };
        if !local.interfaces.iter().any(|i| i.addresses.contains(&v4)) {
            return Err(format!("no interface holds egress IP {v4}"));
        }
        return Ok((v4, 0));
    }
    let name = local.primary.ok_or("no uplink holds the node's address")?;
    let interface = local
        .interfaces
        .iter()
        .find(|i| i.name == name)
        .ok_or_else(|| format!("no interface {name}"))?;
    let address = interface
        .addresses
        .first()
        .ok_or_else(|| format!("interface {name} has no IPv4 address"))?;
    Ok((*address, interface.index))
}

/// The IPv6 egress address and interface index on the gateway node (#580).
fn egress6(gateway: &Gateway, local: &Local<'_>) -> Result<(Ipv6Addr, u32), String> {
    let first = |name: &str| -> Result<(Ipv6Addr, u32), String> {
        let interface = local
            .interfaces
            .iter()
            .find(|i| i.name == name)
            .ok_or_else(|| format!("no interface {name}"))?;
        let address = interface
            .addresses6
            .first()
            .ok_or_else(|| format!("interface {name} has no IPv6 address"))?;
        Ok((*address, interface.index))
    };
    if let Some(name) = &gateway.interface {
        return first(name);
    }
    if let Some(ip) = gateway.egress_ip {
        return match ip {
            IpAddr::V6(v6) => {
                if local.interfaces.iter().any(|i| i.addresses6.contains(&v6)) {
                    Ok((v6, 0))
                } else {
                    Err(format!("no interface holds egress IP {v6}"))
                }
            }
            IpAddr::V4(v4) => {
                let holder = local
                    .interfaces
                    .iter()
                    .find(|i| i.addresses.contains(&v4))
                    .ok_or_else(|| format!("no interface holds egress IP {v4}"))?;
                // The egressIP case leaves the index at 0 (the FIB chooses).
                first(&holder.name).map(|(address, _)| (address, 0))
            }
        };
    }
    first(local.primary.ok_or("no uplink holds the node's address")?)
}

/// The map's desired contents: (LPM prefix length, source ++ destination) ->
/// value bytes, as the loader writes them.
pub type Entries = BTreeMap<(u32, [u8; 8]), [u8; 28]>;
/// The IPv6 map's desired contents (#580).
pub type Entries6 = BTreeMap<(u32, [u8; 32]), [u8; 40]>;
/// A gateway's IPv4 -> its IPv6 InternalIP (#580).
pub type Nexthops6 = BTreeMap<[u8; 4], [u8; 16]>;
/// Everything [`plan`] writes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Maps {
    pub v4: Entries,
    pub v6: Entries6,
    pub nexthop6: Nexthops6,
}

/// An egress address and interface index, or why there is none.
pub type Derived = Result<(Ipv4Addr, u32), String>;
/// A resolved gateway: its address, its node, this node's egress when it is
/// that node, and the same for IPv6.
type Resolved = (
    Ipv4Addr,
    String,
    Option<(Ipv4Addr, u32)>,
    Option<(Ipv6Addr, u32)>,
);

/// What [`plan`] decided, for `GET /v1/egress-gateway`.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Policy name -> why it was dropped, or None.
    pub problems: BTreeMap<String, Option<String>>,
    /// Policy name -> its resolved gateways: (address, node).
    pub gateways: BTreeMap<String, Vec<(Ipv4Addr, String)>>,
    /// Policy name -> the number of selected source Pods.
    pub sources: BTreeMap<String, usize>,
    /// This node as a gateway: (policy, egress address, interface index, or
    /// the derivation error).
    pub local: Vec<(String, Derived)>,
    /// The same for the IPv6 egress address (#580), when a destination is IPv6.
    pub local6: Vec<(String, Result<(Ipv6Addr, u32), String>)>,
    /// A gateway's IPv4 -> its IPv6 next hop.
    pub nexthop6: BTreeMap<Ipv4Addr, Ipv6Addr>,
}
impl Report {
    pub fn json(&self, enabled: bool, entries: usize, entries6: usize) -> Value {
        let policies: Vec<Value> = self
            .problems
            .iter()
            .map(|(name, problem)| {
                let gateways: Vec<Value> = self
                    .gateways
                    .get(name)
                    .into_iter()
                    .flatten()
                    .map(|(ip, node)| {
                        json!({"ip": ip.to_string(), "node": node,
                               "ip6": self.nexthop6.get(ip).map(ToString::to_string)})
                    })
                    .collect();
                let local = self
                    .local
                    .iter()
                    .filter(|(policy, _)| policy == name)
                    .map(|(_, egress)| match egress {
                        Ok((ip, index)) => json!({"egress-ip": ip.to_string(), "ifindex": index}),
                        Err(error) => json!({"error": error}),
                    })
                    .chain(
                        self.local6
                            .iter()
                            .filter(|(policy, _)| policy == name)
                            .map(|(_, egress)| match egress {
                                Ok((ip, index)) => {
                                    json!({"egress-ip": ip.to_string(), "ifindex": index})
                                }
                                Err(error) => json!({"error": error}),
                            }),
                    )
                    .collect::<Vec<_>>();
                json!({"name": name, "ok": problem.is_none(), "error": problem,
                       "gateways": gateways, "sources": self.sources.get(name).copied().unwrap_or(0),
                       "this-node": local})
            })
            .collect();
        json!({"enabled": enabled, "entries": entries, "entries6": entries6,
               "policies": policies})
    }
}

fn selects(selector: Option<&LabelSelector>, labels: Option<&BTreeMap<String, String>>) -> bool {
    match selector {
        None => true,
        Some(s) => labels.is_some_and(|l| s.matches(l)),
    }
}

/// Plan the map from the policy objects and the cluster.
pub fn plan(
    objects: &[Value],
    pods: &[PodInfo],
    namespaces: &BTreeMap<String, BTreeMap<String, String>>,
    nodes: &[NodeInfo],
    local: &Local<'_>,
) -> (Maps, Report) {
    let mut report = Report::default();
    let mut policies = Vec::new();
    for object in objects {
        let name = object
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        match parse(object) {
            Ok(policy) => {
                report.problems.insert(name, None);
                policies.push(policy);
            }
            Err(problem) => {
                report.problems.insert(name, Some(problem));
            }
        }
    }
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    let mut sorted: Vec<&NodeInfo> = nodes.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let node_labels: BTreeMap<&str, &BTreeMap<String, String>> =
        nodes.iter().map(|n| (n.name.as_str(), &n.labels)).collect();
    let mut entries = Entries::new();
    let mut entries6 = Entries6::new();
    let mut nexthop6 = Nexthops6::new();
    for policy in &policies {
        let needs6 = policy.destinations.iter().any(|(ip, _)| ip.is_ipv6());
        // Gateways: (address, node, this node's egress when it is the node).
        let mut resolved: Vec<Resolved> = Vec::new();
        for gateway in &policy.gateways {
            let found = sorted.iter().find_map(|node| {
                if !gateway.node.matches(&node.labels) {
                    return None;
                }
                let v6 = node.internal_ips.iter().find_map(|ip| match ip {
                    IpAddr::V6(v6) if !v6.is_unicast_link_local() => Some(*v6),
                    _ => None,
                });
                node.internal_ips.iter().find_map(|ip| match ip {
                    IpAddr::V4(v4) => Some((*v4, node.name.clone(), v6)),
                    IpAddr::V6(_) => None,
                })
            });
            let Some((ip, node, ip6)) = found else { continue };
            if let Some(ip6) = ip6 {
                nexthop6.insert(ip.octets(), ip6.octets());
                report.nexthop6.insert(ip, ip6);
            }
            let (egress_here, egress6_here) = if node == local.node {
                let derived = egress(gateway, local);
                report.local.push((policy.name.clone(), derived.clone()));
                let derived6 = needs6.then(|| egress6(gateway, local));
                if let Some(derived6) = &derived6 {
                    report.local6.push((policy.name.clone(), derived6.clone()));
                }
                (
                    Some(derived.unwrap_or((Ipv4Addr::UNSPECIFIED, 0))),
                    derived6.map(|d| d.unwrap_or((Ipv6Addr::UNSPECIFIED, 0))),
                )
            } else {
                (None, None)
            };
            resolved.push((ip, node, egress_here, egress6_here));
        }
        report.gateways.insert(
            policy.name.clone(),
            resolved
                .iter()
                .map(|(ip, node, _, _)| (*ip, node.clone()))
                .collect(),
        );
        let addresses: Vec<Ipv4Addr> = resolved.iter().map(|(ip, _, _, _)| *ip).collect();
        let mut own = Entries::new();
        let mut own6 = Entries6::new();
        let mut count = 0usize;
        for pod in pods {
            if pod.host_network || pod.uid.is_empty() {
                continue;
            }
            let namespace = namespaces.get(&pod.namespace);
            let selected = policy.sources.iter().any(|source| {
                selects(source.namespace.as_ref(), namespace)
                    && selects(source.pod.as_ref(), Some(&pod.labels))
            }) && (policy.nodes.is_empty()
                || node_labels
                    .get(pod.node.as_str())
                    .is_some_and(|labels| policy.nodes.iter().any(|n| n.matches(labels))));
            if !selected {
                continue;
            }
            count = count.saturating_add(1);
            // This Pod's gateway: the only one, or FNV-1a(UID) mod n in
            // address order (#564, spec 14 §3.4.3).
            let chosen = if addresses.len() <= 1 {
                addresses.first().copied()
            } else {
                flowsdn_encryption::gateway::choose(
                    pod.uid.as_bytes(),
                    &addresses,
                    flowsdn_encryption::gateway::Selection::Modulo,
                )
                .ok()
                .flatten()
            };
            let (gateway_ip, egress_ip, ifindex) = match chosen {
                None => (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED, 0),
                Some(ip) => {
                    let here = resolved
                        .iter()
                        .find(|(address, _, _, _)| *address == ip)
                        .and_then(|(_, _, egress, _)| *egress);
                    let (egress_ip, ifindex) = here.unwrap_or((Ipv4Addr::UNSPECIFIED, 0));
                    (ip, egress_ip, ifindex)
                }
            };
            let (egress_ip6, ifindex6) = chosen
                .and_then(|ip| {
                    resolved
                        .iter()
                        .find(|(address, _, _, _)| *address == ip)
                        .and_then(|(_, _, _, egress6)| *egress6)
                })
                .unwrap_or((Ipv6Addr::UNSPECIFIED, 0));
            for source in &pod.ips {
                let IpAddr::V4(source) = source else {
                    let IpAddr::V6(source6) = source else { continue };
                    for (list, gateway) in [
                        (&policy.destinations, gateway_ip.octets()),
                        (&policy.excluded, GATEWAY_EXCLUDED),
                    ] {
                        for (destination, length) in list {
                            let IpAddr::V6(destination) = destination else {
                                continue;
                            };
                            let key = EgressGw6Key {
                                prefixlen: SOURCE_BITS6.saturating_add(u32::from(*length)),
                                saddr: source6.octets(),
                                daddr: destination.octets(),
                            };
                            let value = EgressGw6Value {
                                egress_ip: egress_ip6.octets(),
                                gateway_ip: if gateway == GATEWAY_EXCLUDED {
                                    GATEWAY_EXCLUDED
                                } else if chosen.is_none() {
                                    GATEWAY_NONE
                                } else {
                                    gateway
                                },
                                egress_ifindex: ifindex6,
                                ..EgressGw6Value::default()
                            };
                            let mut data = [0u8; 32];
                            for (slot, byte) in data
                                .iter_mut()
                                .zip(key.saddr.iter().chain(key.daddr.iter()))
                            {
                                *slot = *byte;
                            }
                            own6.insert((key.prefixlen, data), value.to_bytes());
                        }
                    }
                    continue;
                };
                for (list, gateway) in [
                    (&policy.destinations, gateway_ip.octets()),
                    (&policy.excluded, GATEWAY_EXCLUDED),
                ] {
                    for (destination, length) in list {
                        let IpAddr::V4(destination) = destination else {
                            continue;
                        };
                        let key = EgressGw4Key {
                            prefixlen: SOURCE_BITS.saturating_add(u32::from(*length)),
                            saddr: source.octets(),
                            daddr: destination.octets(),
                        };
                        let value = EgressGw4Value {
                            egress_ip: egress_ip.octets(),
                            gateway_ip: if gateway == GATEWAY_EXCLUDED {
                                GATEWAY_EXCLUDED
                            } else if chosen.is_none() {
                                GATEWAY_NONE
                            } else {
                                gateway
                            },
                            egress_ifindex: ifindex,
                            ..EgressGw4Value::default()
                        };
                        let [a, b, c, d] = key.saddr;
                        let [e, f, g, h] = key.daddr;
                        // Within a policy an excluded CIDR replaces a
                        // destination of the same key.
                        own.insert((key.prefixlen, [a, b, c, d, e, f, g, h]), value.to_bytes());
                    }
                }
            }
        }
        report.sources.insert(policy.name.clone(), count);
        for (key, value) in own {
            entries.entry(key).or_insert(value);
        }
        for (key, value) in own6 {
            entries6.entry(key).or_insert(value);
        }
    }
    (
        Maps {
            v4: entries,
            v6: entries6,
            nexthop6,
        },
        report,
    )
}

#[cfg(test)]
#[path = "egress_gateway_tests.rs"]
mod tests;
