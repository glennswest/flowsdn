//! Kubernetes node discovery for the agent: settings, pod CIDR selection
//! (spec 07 §3.4), direct node routes (spec 10 §3.2.3) and the IP cache view.
//! This part is pure data; the watch/route controller needs the `kubernetes`
//! feature (Fedora OpenSSL through flowsdn-k8s, ADR-0016).
use crate::state::Result;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

/// The reserved identities an IP cache entry can carry before cluster identity
/// allocation exists (spec 03 §4.4): this node and other nodes.
pub const IDENTITY_HOST: u32 = 1;
pub const IDENTITY_REMOTE_NODE: u32 = 6;
/// `ipv6-cluster-alloc-cidr` default `f00d::/64` (spec 07 §3.4).
const IPV6_CLUSTER_ALLOC_BASE: [u16; 4] = [0xf00d, 0, 0, 0];

/// A network address and prefix length.
pub type Cidr = (IpAddr, u8);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    pub node_name: String,
    /// Explicit kubeconfig; otherwise in-cluster service account credentials.
    pub kubeconfig: Option<PathBuf>,
    pub auto_direct_node_routes: bool,
    pub skip_unreachable: bool,
}
impl Settings {
    /// `kubernetes` absent or null disables discovery. `node-name` falls back to
    /// `K8S_NODE_NAME`, then `NODE_NAME` (the DaemonSet's downward API).
    pub fn parse(
        value: Option<&Value>,
        env: &BTreeMap<OsString, OsString>,
    ) -> Result<Option<Self>> {
        let object = match value {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(object)) => object,
            Some(_) => return Err("kubernetes must be an object".into()),
        };
        let text = |key: &str| -> Result<String> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(value)) => Ok(value.clone()),
                Some(_) => Err(format!("invalid kubernetes.{key}").into()),
            }
        };
        let flag = |key: &str, default: bool| -> Result<bool> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(Value::Bool(value)) => Ok(*value),
                Some(_) => Err(format!("kubernetes.{key} must be boolean").into()),
            }
        };
        let mut node_name = text("node-name")?;
        for key in ["K8S_NODE_NAME", "NODE_NAME"] {
            if node_name.is_empty()
                && let Some(value) = env.get(&OsString::from(key))
            {
                node_name = value.to_str().ok_or("node name is not UTF-8")?.into();
            }
        }
        if node_name.is_empty()
            || node_name.len() > 253
            || node_name
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.')
        {
            return Err(
                "kubernetes.node-name (or K8S_NODE_NAME/NODE_NAME) must be a node name".into(),
            );
        }
        let kubeconfig = text("kubeconfig")?;
        Ok(Some(Self {
            node_name,
            kubeconfig: (!kubeconfig.is_empty()).then(|| PathBuf::from(kubeconfig)),
            auto_direct_node_routes: flag("auto-direct-node-routes", true)?,
            skip_unreachable: flag("direct-routing-skip-unreachable", false)?,
        }))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeInfo {
    pub name: String,
    pub pod_cidrs: Vec<(IpAddr, u8)>,
    pub internal_ips: Vec<IpAddr>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PodInfo {
    pub namespace: String,
    pub name: String,
    pub node: String,
    pub host_network: bool,
    pub ips: Vec<IpAddr>,
    pub labels: BTreeMap<String, String>,
}

/// The node's allocation CIDR for one family: the first `spec.podCIDRs` entry of
/// that family, else the reference default (spec 07 §3.4): IPv4
/// `10.<last byte of the node IPv4>.0.0/16`; IPv6 `f00d::<4 bytes of the IPv4
/// alloc CIDR, else of the node IPv6>:0:0/96`. None when nothing derives it.
pub fn alloc_cidr(node: &NodeInfo, v6: bool) -> Option<(IpAddr, u8)> {
    if let Some(cidr) = node.pod_cidrs.iter().find(|(ip, _)| ip.is_ipv6() == v6) {
        return Some(*cidr);
    }
    let node_v4 = node.internal_ips.iter().find_map(|ip| match ip {
        IpAddr::V4(ip) => Some(*ip),
        IpAddr::V6(_) => None,
    });
    if !v6 {
        let [_, _, _, last] = node_v4?.octets();
        return Some((IpAddr::V4(Ipv4Addr::new(10, last, 0, 0)), 16));
    }
    let tail = match alloc_cidr(node, false) {
        Some((IpAddr::V4(ip), _)) => ip.octets(),
        _ => {
            let ip = node.internal_ips.iter().find_map(|ip| match ip {
                IpAddr::V6(ip) => Some(*ip),
                IpAddr::V4(_) => None,
            })?;
            let [.., a, b, c, d] = ip.octets();
            [a, b, c, d]
        }
    };
    let [b0, b1, b2, b3] = IPV6_CLUSTER_ALLOC_BASE;
    let [t0, t1, t2, t3] = tail;
    let ip = Ipv6Addr::new(
        b0,
        b1,
        b2,
        b3,
        u16::from_be_bytes([t0, t1]),
        u16::from_be_bytes([t2, t3]),
        0,
        0,
    );
    Some((IpAddr::V6(ip), 96))
}

/// The router address: the first address after the network (what the
/// reference's first `allocate_next` returns). The prefix must leave room.
pub fn router_ip((network, prefix): (IpAddr, u8)) -> Result<IpAddr> {
    match network {
        IpAddr::V4(ip) if prefix <= 30 => {
            let host = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            let base = u32::from(ip) & !host;
            Ok(IpAddr::V4(Ipv4Addr::from(
                base.checked_add(1).ok_or("router overflow")?,
            )))
        }
        IpAddr::V6(ip) if prefix <= 126 => {
            let host = u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            let base = u128::from(ip) & !host;
            Ok(IpAddr::V6(Ipv6Addr::from(
                base.checked_add(1).ok_or("router overflow")?,
            )))
        }
        _ => Err("pod CIDR too small for a router address".into()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DesiredRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: IpAddr,
    pub node: String,
}

/// `<podCIDR> via <nodeIP>` for every other node and each of its pod CIDRs
/// (spec 10 §3.2.3 native routing), using the node's first InternalIP of that
/// family. A node without one gets no route; the view records it.
pub fn desired_routes(local: &str, nodes: &[NodeInfo]) -> Vec<DesiredRoute> {
    let mut routes = BTreeSet::new();
    for node in nodes.iter().filter(|node| node.name != local) {
        for (destination, prefix) in &node.pod_cidrs {
            if let Some(gateway) = node
                .internal_ips
                .iter()
                .find(|ip| ip.is_ipv6() == destination.is_ipv6())
            {
                routes.insert(DesiredRoute {
                    destination: *destination,
                    prefix: *prefix,
                    gateway: *gateway,
                    node: node.name.clone(),
                });
            }
        }
    }
    routes.into_iter().collect()
}

pub type Shared = Arc<Mutex<View>>;
/// A panicked writer leaves a usable view; never poison the API with it.
pub fn lock(view: &Shared) -> MutexGuard<'_, View> {
    view.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shared between the controller thread and the API thread.
#[derive(Debug, Default)]
pub struct View {
    pub local_node: String,
    pub nodes: Vec<NodeInfo>,
    pub pods: Vec<PodInfo>,
    pub nodes_synced: bool,
    pub pods_synced: bool,
    pub direct_routes: bool,
    /// Destination CIDR text -> (route, state text).
    pub routes: BTreeMap<String, (DesiredRoute, String)>,
    /// The latest failure of each controller part (`nodes`, `pods`, `routes`).
    pub errors: BTreeMap<String, String>,
}
impl View {
    fn host_ip(&self, node: &str, v6: bool) -> Option<IpAddr> {
        self.nodes
            .iter()
            .find(|n| n.name == node)
            .and_then(|n| n.internal_ips.iter().find(|ip| ip.is_ipv6() == v6).copied())
    }
    /// `GET /v1/ip` (reference `IPListEntry`): node InternalIPs with the
    /// reserved host/remote-node identities, and every Pod IP of a Pod that is
    /// not host-network. Pod entries carry no `identity` until cluster identity
    /// allocation exists; `labels` is a flowsdn extension with the Pod's
    /// `k8s:` source labels (spec 03 §4.2), the identity input.
    pub fn ip_list(&self) -> Value {
        let mut rows = BTreeMap::new();
        for node in &self.nodes {
            let identity = if node.name == self.local_node {
                IDENTITY_HOST
            } else {
                IDENTITY_REMOTE_NODE
            };
            for ip in &node.internal_ips {
                rows.insert(
                    *ip,
                    json!({"cidr":host_cidr(*ip),"identity":identity,
                        "metadata":{"source":"kube-apiserver","name":node.name}}),
                );
            }
        }
        for pod in self.pods.iter().filter(|pod| !pod.host_network) {
            let mut labels: Vec<_> = pod
                .labels
                .iter()
                .map(|(key, value)| format!("k8s:{key}={value}"))
                .collect();
            labels.push(format!("k8s:io.kubernetes.pod.namespace={}", pod.namespace));
            for ip in &pod.ips {
                let mut row = json!({"cidr":host_cidr(*ip),"labels":labels,
                    "metadata":{"source":"kube-apiserver","namespace":pod.namespace,"name":pod.name}});
                if let (Some(host), Some(object)) =
                    (self.host_ip(&pod.node, ip.is_ipv6()), row.as_object_mut())
                {
                    object.insert("hostIP".into(), json!(host.to_string()));
                }
                rows.entry(*ip).or_insert(row);
            }
        }
        Value::Array(rows.into_values().collect())
    }
    /// `GET /v1/node/routes` (flowsdn): the direct routes and their state.
    pub fn route_list(&self) -> Value {
        Value::Array(
            self.routes
                .iter()
                .map(|(cidr, (route, state))| {
                    json!({"destination":cidr,"gateway":route.gateway.to_string(),
                        "node":route.node,"state":state})
                })
                .collect(),
        )
    }
    /// The `kubernetes` member of `GET /v1/healthz`.
    pub fn health(&self) -> Value {
        let errors: Vec<_> = self
            .errors
            .iter()
            .map(|(part, error)| format!("{part}: {error}"))
            .collect();
        let (state, msg) = match (errors.is_empty(), self.nodes_synced && self.pods_synced) {
            (false, _) => ("Warning", errors.join("; ")),
            (true, false) => ("Warning", "waiting for the initial Node/Pod lists".into()),
            (true, true) => (
                "Ok",
                format!("{} nodes, {} pods", self.nodes.len(), self.pods.len()),
            ),
        };
        json!({"state":state,"msg":msg,"node-name":self.local_node,
            "auto-direct-node-routes":self.direct_routes})
    }
}

pub fn cidr_text(ip: IpAddr, prefix: u8) -> String {
    format!("{ip}/{prefix}")
}
fn host_cidr(ip: IpAddr) -> String {
    cidr_text(ip, if ip.is_ipv4() { 32 } else { 128 })
}

#[cfg(feature = "kubernetes")]
#[path = "kubernetes_controller.rs"]
pub mod controller;

#[cfg(test)]
#[path = "kubernetes_tests.rs"]
mod tests;
