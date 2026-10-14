//! Kubernetes NetworkPolicy to the endpoint policy maps (#292, ADR-0021):
//! a pure compiler from the controller's view to the desired contents of
//! `flowsdn_policy_ep`, `flowsdn_policy` and `flowsdn_ipcache`.
//!
//! - A local endpoint is enforced in a direction when a NetworkPolicy
//!   selects its Pod for that direction (Kubernetes isolation); its Pod's
//!   identity labels are computed from the Pod and Namespace, so enforcement
//!   does not wait for the identity allocator.
//! - Each allowed peer becomes LPM entries per identity: selector peers are
//!   resolved against every known identity's labels, `from`/`to` absent is
//!   the wildcard identity 0, and `ipBlock` peers get a local CIDR identity
//!   per distinct prefix (excepted prefixes have their own, unselected), with
//!   the ipcache holding those prefixes; the host is selected when one of
//!   its addresses is inside the block. Port ranges are masked blocks
//!   (spec 06 §5.2); named ports resolve to the subject's container ports
//!   (ingress) or the peer Pods' (egress).
//! - The ipcache maps every Pod IP with an identity, this node's addresses
//!   (host, 1), other nodes' InternalIPs (remote-node, 6) and the CIDR
//!   prefixes. An `ipBlock` selects the host and remote nodes whose
//!   addresses it holds, so node traffic is judged as before they had
//!   identities.
//! - The host firewall (#379, [`crate::host_policy`]): with
//!   `kubernetes.host-firewall` on, the host endpoint ([`HOST_ENDPOINT`]) is
//!   in `flowsdn_policy_ep` under each uplink's index, tracked always and
//!   ingress-enforced (or audited) when a host policy selects this node and
//!   the uplink's learning time is over. Denies win over allows they cover.
use crate::{
    host_policy::{self, HostPolicies, Peer as HostPeer, REMOTE_NODE},
    kubernetes::{HostFirewall, LocalEndpoint, PodInfo, View},
};
use flowsdn_bpf_abi::{
    IpCacheKey, MapBytes, RemoteEndpointInfo,
    policy::{EndpointPolicyKey, HOST_ENDPOINT, PolicyEndpoint, PolicyEntry, PolicyKey, enforce},
};
use flowsdn_identity::{cidr::CidrPrefix, filter::LabelFilter};
use flowsdn_policy::{
    k8s::{self, Entry, Peer},
    oracle::Verdict,
    ports::{PortBlock, PortRange},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// Every allow entry's precedence (spec 06 §3.5.2: allow verdict byte 1;
/// Kubernetes NetworkPolicy has one tier and no denies).
pub const ALLOW_PRECEDENCE: u32 = 1;
/// Host policy precedences (spec 06 §3.5.2, tier Normal priority 0):
/// `MaxAllowPrecedence` and `MaxPrecedence` (a deny).
pub const HOST_ALLOW_PRECEDENCE: u32 = 0xFFFF_FF01;
pub const HOST_DENY_PRECEDENCE: u32 = u32::MAX;
pub const HOST: u32 = 1;
/// First local (CIDR) identity: scope 1 in the top byte (spec 03).
const CIDR_IDENTITY_BASE: u32 = 1 << 24;

/// The policy maps' desired contents. Keys are the map ABI bytes; endpoints
/// are keyed by their host interface index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Desired {
    pub endpoints: BTreeMap<u32, PolicyEndpoint>,
    pub entries: BTreeMap<[u8; 16], PolicyEntry>,
    pub ipcache: BTreeMap<[u8; 24], RemoteEndpointInfo>,
    /// What could not be enforced as written (one line each).
    pub problems: Vec<String>,
    /// Per enforced endpoint: (id, namespace/name, ingress, egress, entries).
    pub enforced: Vec<(u16, String, bool, bool, usize)>,
    /// The host firewall's state (`null` when it is off).
    pub host: Value,
}
impl Desired {
    pub fn status(&self) -> Value {
        json!({
            "endpoints": self.enforced.iter().map(|(id, pod, ingress, egress, entries)| json!({
                "id": id, "pod": pod, "ingress-enforced": ingress,
                "egress-enforced": egress, "entries": entries,
            })).collect::<Vec<_>>(),
            "ipcache": self.ipcache.len(),
            "host-firewall": self.host,
            "problems": self.problems,
        })
    }
}

/// `k8s:<key>=<value>` label strings to the selector's key/value map.
fn label_map<'a>(labels: impl IntoIterator<Item = &'a String>) -> BTreeMap<String, String> {
    labels
        .into_iter()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

fn ip_key(ip: IpAddr, bits: u8) -> Option<[u8; 24]> {
    match ip {
        IpAddr::V4(a) => IpCacheKey::v4(a.octets(), u32::from(bits), 0),
        IpAddr::V6(a) => IpCacheKey::v6(a.octets(), u32::from(bits), 0),
    }
    .ok()
    .map(MapBytes::to_bytes)
}
fn host_bits(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}

struct Compiler<'a> {
    view: &'a View,
    /// Identity -> its labels as a selector reads them.
    identities: BTreeMap<u32, BTreeMap<String, String>>,
    /// CIDR prefix -> its local identity.
    cidrs: BTreeMap<CidrPrefix, u32>,
    /// This node's addresses (the host identity).
    host: Vec<IpAddr>,
    /// Other nodes' addresses (the remote-node identity).
    remote_nodes: Vec<IpAddr>,
    problems: BTreeSet<String>,
}

/// The policies' entries, each with its policy's `namespace/name`.
fn import(view: &View, problems: &mut BTreeSet<String>) -> Vec<(String, Entry)> {
    let mut out = Vec::new();
    for object in &view.network_policies {
        let text = |p: &str| object.pointer(p).and_then(Value::as_str).unwrap_or("");
        let name = format!("{}/{}", text("/metadata/namespace"), text("/metadata/name"));
        match k8s::network_policy(object, Some(view.cluster_name.as_str())) {
            Ok(entries) => out.extend(entries.into_iter().map(|e| (name.clone(), e))),
            Err(error) => {
                problems.insert(format!("{name}: not enforced, {error}"));
            }
        }
    }
    out
}

impl Compiler<'_> {
    /// The identities a peer selects (0 is every identity).
    fn peers(&mut self, policy: &str, entry: &Entry) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        let Some(list) = &entry.l3 else {
            out.insert(0);
            return out;
        };
        for peer in list {
            match peer {
                Peer::Selector(selector) => {
                    out.extend(
                        self.identities
                            .iter()
                            .filter(|(_, labels)| selector.matches(labels))
                            .map(|(id, _)| *id),
                    );
                }
                Peer::Cidr { cidr, except } => {
                    out.extend(self.cidr_peer(policy, cidr, except));
                }
            }
        }
        out
    }

    /// The identities a CIDR minus its exceptions selects: the local CIDR
    /// identities inside it, and the host and remote nodes whose addresses
    /// are.
    fn cidr_peer(&mut self, policy: &str, cidr: &str, except: &[String]) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        let parsed = cidr.parse::<CidrPrefix>().and_then(|allow| {
            except
                .iter()
                .map(|e| e.parse::<CidrPrefix>())
                .collect::<Result<Vec<_>, _>>()
                .map(|except| (allow, except))
        });
        let Ok((allow, except)) = parsed else {
            self.problems.insert(format!(
                "{policy}: CIDR {cidr} is not a CIDR; it allows nothing"
            ));
            return out;
        };
        let selected =
            |p: CidrPrefix| allow.contains_prefix(p) && !except.iter().any(|e| e.contains_prefix(p));
        out.extend(
            self.cidrs
                .iter()
                .filter(|(p, _)| selected(**p))
                .map(|(_, id)| *id),
        );
        let holds = |ips: &[IpAddr]| {
            ips.iter()
                .any(|ip| CidrPrefix::new(*ip, host_bits(*ip)).is_ok_and(selected))
        };
        if holds(&self.host) {
            out.insert(HOST);
        }
        if holds(&self.remote_nodes) {
            out.insert(REMOTE_NODE);
        }
        out
    }

    /// The identities a host rule's peers select.
    fn host_peers(&mut self, policy: &str, peers: Option<&[HostPeer]>) -> BTreeSet<u32> {
        let Some(peers) = peers else {
            return BTreeSet::from([0]);
        };
        let mut out = BTreeSet::new();
        for peer in peers {
            match peer {
                HostPeer::Identities(ids) => out.extend(ids.iter().copied()),
                HostPeer::Cidr { cidr, except } => {
                    out.extend(self.cidr_peer(policy, cidr, except));
                }
                HostPeer::Endpoints(selector) => out.extend(
                    self.identities
                        .iter()
                        .filter(|(_, labels)| selector.matches(labels))
                        .map(|(id, _)| *id),
                ),
            }
        }
        out
    }

    /// Named ports a peer identity's Pods expose: (protocol, name) -> ports.
    fn named_ports(&self, pods: &[&PodInfo]) -> BTreeMap<(u8, String), BTreeSet<u16>> {
        let mut out: BTreeMap<(u8, String), BTreeSet<u16>> = BTreeMap::new();
        for pod in pods {
            for (protocol, name, port) in &pod.named_ports {
                out.entry((*protocol, name.clone()))
                    .or_default()
                    .insert(*port);
            }
        }
        out
    }

    /// The Pods holding `identity` (every Pod for the wildcard).
    fn pods_of(&self, identity: u32) -> Vec<&PodInfo> {
        self.view
            .pods
            .iter()
            .filter(|p| {
                !p.host_network
                    && (identity == 0
                        || self.view.pod_identity(&p.namespace, &p.name) == Some(identity))
            })
            .collect()
    }

    /// (identity, protocol, port range) triples one entry allows.
    fn rules(
        &mut self,
        policy: &str,
        entry: &Entry,
        subject: &PodInfo,
    ) -> Vec<(u32, u8, PortRange)> {
        let mut out = Vec::new();
        let peers = self.peers(policy, entry);
        let Some(ports) = &entry.l4 else {
            out.extend(peers.iter().map(|id| (*id, 0, PortRange::any())));
            return out;
        };
        for rule in ports {
            let protocol = rule.protocol.number();
            match rule.port.parse::<u16>() {
                Ok(port) => match PortRange::from_api(port, rule.end_port) {
                    Ok(range) => out.extend(peers.iter().map(|id| (*id, protocol, range))),
                    Err(error) => {
                        self.problems.insert(format!(
                            "{policy}: port {port}-{:?}: {error}; it allows nothing",
                            rule.end_port
                        ));
                    }
                },
                Err(_) => {
                    let key = (protocol, rule.port.clone());
                    for id in &peers {
                        // The destination's container ports name the port.
                        let named = if entry.ingress {
                            self.named_ports(&[subject])
                        } else {
                            self.named_ports(&self.pods_of(*id))
                        };
                        for port in named.get(&key).into_iter().flatten() {
                            if let Ok(range) = PortRange::from_api(*port, None) {
                                out.push((*id, protocol, range));
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// Compile the view. `gateways` are this node's router addresses, which the
/// host also sends from.
pub fn compile(view: &View, gateways: &[IpAddr]) -> Desired {
    let mut problems = BTreeSet::new();
    let entries = import(view, &mut problems);
    let mut desired = Desired::default();
    if !view.identity && !entries.is_empty() {
        problems.insert(
            "identity allocation is off: selector peers match no identity, so they allow nothing"
                .into(),
        );
    }
    let hosts = match view.host_firewall {
        HostFirewall::Off => None,
        _ => Some(host_policy::select(
            &view.clusterwide_policies,
            &view
                .nodes
                .iter()
                .find(|n| n.name == view.local_node)
                .map(|n| n.labels.clone())
                .unwrap_or_default(),
        )),
    };
    // Every CIDR an ipBlock or host rule names (and its exceptions) gets a
    // local identity.
    let mut prefixes = BTreeSet::new();
    for rule in hosts.iter().flat_map(|h| &h.rules) {
        for peer in rule.peers.iter().flatten() {
            if let HostPeer::Cidr { cidr, except } = peer {
                for text in std::iter::once(cidr).chain(except) {
                    if let Ok(prefix) = text.parse::<CidrPrefix>() {
                        prefixes.insert(prefix);
                    }
                }
            }
        }
    }
    for (_, entry) in &entries {
        for peer in entry.l3.iter().flatten() {
            if let Peer::Cidr { cidr, except } = peer {
                for text in std::iter::once(cidr).chain(except) {
                    if let Ok(prefix) = text.parse::<CidrPrefix>() {
                        prefixes.insert(prefix);
                    }
                }
            }
        }
    }
    let cidrs: BTreeMap<CidrPrefix, u32> = prefixes
        .into_iter()
        .zip(1u32..)
        .map(|(p, n)| (p, CIDR_IDENTITY_BASE.saturating_add(n)))
        .collect();
    let mut host: Vec<IpAddr> = view
        .nodes
        .iter()
        .filter(|n| n.name == view.local_node)
        .flat_map(|n| n.internal_ips.iter().copied())
        .collect();
    host.extend(gateways.iter().copied());
    let remote_nodes: Vec<IpAddr> = view
        .nodes
        .iter()
        .filter(|n| n.name != view.local_node)
        .flat_map(|n| n.internal_ips.iter().copied())
        .filter(|ip| !host.contains(ip))
        .collect();
    let mut compiler = Compiler {
        view,
        identities: view
            .identities
            .iter()
            .map(|(id, labels)| (*id, label_map(labels)))
            .collect(),
        cidrs: cidrs.clone(),
        host: host.clone(),
        remote_nodes: remote_nodes.clone(),
        problems,
    };

    let filter = LabelFilter::identity(&[]).ok();
    let subjects: BTreeMap<(String, String), BTreeMap<String, String>> = filter
        .as_ref()
        .map(|f| {
            view.pod_label_sets(f)
                .into_iter()
                .filter(|(_, local, _)| *local)
                .map(|(pod, _, labels)| (pod, label_map(&crate::identity::label_strings(&labels))))
                .collect()
        })
        .unwrap_or_default();

    for endpoint in &view.endpoints {
        let LocalEndpoint {
            id,
            namespace,
            name,
            ifindex,
            ..
        } = endpoint;
        let pod_key = (namespace.clone(), name.clone());
        let (Some(labels), Some(pod)) = (
            subjects.get(&pod_key),
            view.pods
                .iter()
                .find(|p| p.namespace == *namespace && p.name == *name),
        ) else {
            continue;
        };
        let mut flags = 0;
        let mut count = 0usize;
        for (ingress, bit) in [(true, enforce::INGRESS), (false, enforce::EGRESS)] {
            let selected: Vec<&(String, Entry)> = entries
                .iter()
                .filter(|(_, e)| e.ingress == ingress && e.subject.matches(labels))
                .collect();
            if selected.is_empty() {
                continue;
            }
            flags |= bit;
            for (policy, entry) in selected {
                if entry.verdict != Verdict::Allow {
                    compiler
                        .problems
                        .insert(format!("{policy}: only allow rules are enforced"));
                    continue;
                }
                for (identity, protocol, range) in compiler.rules(policy, entry, pod) {
                    for (key, lpm) in keys(identity, !ingress, protocol, range) {
                        let Ok(value) =
                            PolicyEntry::new(0, false, lpm, 0, false, ALLOW_PRECEDENCE, 0)
                        else {
                            continue;
                        };
                        if desired
                            .entries
                            .insert(EndpointPolicyKey::new(*id, key).to_bytes(), value)
                            .is_none()
                        {
                            count = count.saturating_add(1);
                        }
                    }
                }
            }
        }
        if flags != 0 && *ifindex != 0 {
            desired.endpoints.insert(
                *ifindex,
                PolicyEndpoint {
                    endpoint: u32::from(*id),
                    flags,
                },
            );
            desired.enforced.push((
                *id,
                format!("{namespace}/{name}"),
                flags & enforce::INGRESS != 0,
                flags & enforce::EGRESS != 0,
                count,
            ));
        }
    }

    if let Some(hosts) = hosts {
        host_firewall(view, &mut compiler, hosts, &mut desired);
    }

    let mut identity = |key: Option<[u8; 24]>, id: u32| {
        if let Some(key) = key {
            desired.ipcache.insert(
                key,
                RemoteEndpointInfo {
                    sec_identity: id,
                    ..RemoteEndpointInfo::default()
                },
            );
        }
    };
    for (prefix, id) in &cidrs {
        let text = prefix.to_string();
        if let Some((ip, bits)) = text
            .split_once('/')
            .and_then(|(ip, bits)| Some((ip.parse().ok()?, bits.parse().ok()?)))
        {
            identity(ip_key(ip, bits), *id);
        }
    }
    for pod in view.pods.iter().filter(|p| !p.host_network) {
        if let Some(id) = view.pod_identity(&pod.namespace, &pod.name) {
            for ip in &pod.ips {
                identity(ip_key(*ip, host_bits(*ip)), id);
            }
        }
    }
    for ip in &remote_nodes {
        identity(ip_key(*ip, host_bits(*ip)), REMOTE_NODE);
    }
    for ip in &host {
        identity(ip_key(*ip, host_bits(*ip)), HOST);
    }
    desired.problems = compiler.problems.into_iter().collect();
    desired
}

/// One host rule key before encoding: (identity, protocol, port, port
/// prefix); protocol 0 is every L4.
type HostKey = (u32, u8, u16, u8);

/// Whether `outer`'s L4 holds every packet `inner`'s does.
fn l4_holds(outer: HostKey, inner: HostKey) -> bool {
    let (_, op, oport, oprefix) = outer;
    let (_, ip, iport, iprefix) = inner;
    op == 0
        || (op == ip
            && oprefix <= iprefix
            && PortBlock {
                port: oport,
                prefix: oprefix,
            }
            .matches(iport))
}

/// Make the datapath's answer "deny wins" (spec 06 §3.5.3): an allow a deny
/// of its identity (or of every identity) covers is dropped, and a deny
/// inside an allow is repeated at the allow's identity, where its longer
/// prefix wins the LPM lookup. Denies of an aggregate identity need nothing:
/// the datapath compares them with the specific entry by precedence.
pub fn deny_over_allow(
    allows: &BTreeSet<HostKey>,
    denies: &BTreeSet<HostKey>,
) -> (BTreeSet<HostKey>, BTreeSet<HostKey>) {
    let mut kept = BTreeSet::new();
    let mut out_denies = denies.clone();
    'allow: for allow in allows {
        for deny in denies {
            if deny.0 != allow.0 && deny.0 != 0 {
                continue;
            }
            if l4_holds(*deny, *allow) {
                continue 'allow;
            }
            if l4_holds(*allow, *deny) {
                out_denies.insert((allow.0, deny.1, deny.2, deny.3));
            }
        }
        kept.insert(*allow);
    }
    (kept, out_denies)
}

/// The host endpoint's entries and its uplinks' `flowsdn_policy_ep` rows.
fn host_firewall(view: &View, compiler: &mut Compiler<'_>, hosts: HostPolicies, desired: &mut Desired) {
    let mut allows = BTreeSet::new();
    let mut denies = BTreeSet::new();
    for rule in &hosts.rules {
        let peers = compiler.host_peers(&rule.policy, rule.peers.as_deref());
        let mut l4: Vec<(u8, u16, u8)> = Vec::new();
        if rule.ports.is_empty() {
            l4.push((0, 0, 0));
        }
        for (protocol, range) in &rule.ports {
            l4.extend(range.blocks().into_iter().map(|b| (*protocol, b.port, b.prefix)));
        }
        for id in peers {
            for (protocol, port, prefix) in &l4 {
                let key = (id, *protocol, *port, *prefix);
                if rule.deny {
                    denies.insert(key);
                } else {
                    allows.insert(key);
                }
            }
        }
    }
    let (allows, denies) = deny_over_allow(&allows, &denies);
    let mut count = 0usize;
    for ((id, protocol, port, prefix), deny) in allows
        .iter()
        .map(|k| (*k, false))
        .chain(denies.iter().map(|k| (*k, true)))
    {
        let Ok(key) = PolicyKey::new(id, false, protocol, port, prefix) else {
            continue;
        };
        let lpm = if protocol == 0 {
            0
        } else {
            prefix.saturating_add(8)
        };
        let precedence = if deny {
            HOST_DENY_PRECEDENCE
        } else {
            HOST_ALLOW_PRECEDENCE
        };
        let Ok(value) = PolicyEntry::new(0, deny, lpm, 0, false, precedence, 0) else {
            continue;
        };
        // A deny replaces an allow at the same key.
        if desired
            .entries
            .insert(EndpointPolicyKey::for_endpoint(HOST_ENDPOINT, key).to_bytes(), value)
            .is_none()
        {
            count = count.saturating_add(1);
        }
    }
    let audit = hosts.audit || view.host_firewall == HostFirewall::Audit;
    let mut enforced = Vec::new();
    for (name, ifindex) in &view.host_interfaces {
        let learning = view.host_learning.contains(ifindex);
        let mut flags = 0;
        if hosts.enforce_ingress && !learning {
            flags = enforce::INGRESS;
            if audit {
                flags |= enforce::AUDIT;
            }
            enforced.push(name.clone());
        }
        desired.endpoints.insert(
            *ifindex,
            PolicyEndpoint {
                endpoint: HOST_ENDPOINT,
                flags,
            },
        );
    }
    compiler
        .problems
        .extend(hosts.problems.iter().map(|p| format!("host firewall: {p}")));
    desired.host = json!({
        "mode": match view.host_firewall {
            HostFirewall::Off => "off",
            HostFirewall::Audit => "audit",
            HostFirewall::Enforce => "enforce",
        },
        "policies": hosts.names,
        "ingress-enforced": hosts.enforce_ingress,
        "audit": audit,
        "interfaces": view.host_interfaces.keys().collect::<Vec<_>>(),
        "learning": view.host_interfaces.iter()
            .filter(|(_, i)| view.host_learning.contains(i))
            .map(|(n, _)| n).collect::<Vec<_>>(),
        "enforcing-on": enforced,
        "entries": count,
    });
}

/// The LPM keys (with each entry's L4 prefix length) for one allowed
/// (identity, protocol, port range): protocol 0 is every L4.
fn keys(identity: u32, egress: bool, protocol: u8, range: PortRange) -> Vec<(PolicyKey, u8)> {
    if protocol == 0 {
        return PolicyKey::new(identity, egress, 0, 0, 0)
            .map(|k| vec![(k, 0)])
            .unwrap_or_default();
    }
    range
        .blocks()
        .into_iter()
        .filter_map(|block| {
            let key = PolicyKey::new(identity, egress, protocol, block.port, block.prefix).ok()?;
            Some((key, block.prefix.saturating_add(8)))
        })
        .collect()
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
