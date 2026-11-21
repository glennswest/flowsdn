//! Services and EndpointSlices to socket-LB frontends (spec 05 §3.1–§3.3).
//! A Service's frontends are its cluster IPs, external IPs and (type
//! LoadBalancer) load-balancer ingress IPs on each port, and (NodePort and
//! LoadBalancer) every node's InternalIP on each `nodePort`. The socket LB
//! translates them for clients inside the cluster: pods and node processes.
//! Backends are the addresses of that Service's EndpointSlices of the same
//! family, on the slice port with the Service port's name and protocol.
//! Ready endpoints serve; when none is ready, serving-terminating ones do
//! (KEP-1669). With traffic policy Cluster, ready endpoints are chosen by
//! their topology hints as kube-proxy does (#459, [`Topology`]).
//! `internalTrafficPolicy: Local` limits a cluster IP to this
//! node's endpoints, and `externalTrafficPolicy: Local` limits a NodePort on a
//! node's address to that node's endpoints, as for a packet arriving there.
//! Each NodePort, external and LoadBalancer frontend also has a node-local
//! copy (scope 1) for packets from outside the cluster arriving on this
//! node's uplink: every backend (the uplink programs SNAT to other nodes'),
//! or this node's only with `externalTrafficPolicy: Local`. With
//! `lb-external-clusterip` (#465) a ClusterIP has one too, limited to this
//! node's backends by `internalTrafficPolicy: Local` (the policy of a
//! cluster IP). Those copies use Maglev when the Service asks for it (spec
//! 05 §3.13).
//! Pure data; the `kubernetes` controller feeds and applies it.
use flowsdn_lb::socket::{Address, PROTO_TCP, PROTO_UDP, SCOPE_CLUSTER, SCOPE_NODE_LOCAL, Service};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServicePort {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub node_port: Option<u16>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceInfo {
    pub namespace: String,
    pub name: String,
    pub service_type: String,
    pub cluster_ips: Vec<IpAddr>,
    pub ports: Vec<ServicePort>,
    pub external_ips: Vec<IpAddr>,
    pub load_balancer_ips: Vec<IpAddr>,
    pub internal_local: bool,
    pub external_local: bool,
    /// ClientIP session affinity timeout in seconds.
    pub affinity: Option<u32>,
    /// Maglev for traffic from outside the cluster (the node-local
    /// frontends); the socket LB always picks at random.
    pub maglev: bool,
    /// Direct server return for this Service's TCP ports, and its others
    /// (`lb-mode: hybrid` differs), for traffic from outside the cluster.
    pub dsr_tcp: bool,
    pub dsr_other: bool,
    /// Service NAT46/64 (`kubernetes.nat46x64`): a node-local frontend with no
    /// backend of its own family balances over the other family's backends on
    /// other nodes.
    pub nat46x64: bool,
    /// `kubernetes.lb-external-clusterip` (#465): its cluster IPs get a
    /// node-local copy for traffic from outside the cluster.
    pub external_clusterip: bool,
    /// For LB-IPAM and L2 announcements (#475): labels, creation time,
    /// `loadBalancerClass`, `ipFamilies`, the addresses it asks for and
    /// the resourceVersion a status patch is guarded by.
    pub labels: BTreeMap<String, String>,
    pub created: String,
    pub load_balancer_class: Option<String>,
    pub ip_families: Vec<String>,
    pub requested_ips: Vec<IpAddr>,
    pub resource_version: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Endpoint {
    pub addresses: Vec<IpAddr>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
    pub node_name: String,
    /// `hints.forZones` and `hints.forNodes` (#459).
    pub zone_hints: Vec<String>,
    pub node_hints: Vec<String>,
}
/// The Node label topology-aware routing compares zone hints with.
pub const ZONE_LABEL: &str = "topology.kubernetes.io/zone";
/// A node's name and InternalIPs (NodePort frontends), and its zone (the
/// [`ZONE_LABEL`], empty without it).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeAddresses {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub zone: String,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SlicePort {
    pub name: String,
    pub protocol: String,
    pub port: Option<u16>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SliceInfo {
    pub namespace: String,
    pub name: String,
    /// The owning Service (`kubernetes.io/service-name`).
    pub service: String,
    /// `IPv4`, `IPv6` or `FQDN`.
    pub address_type: String,
    pub endpoints: Vec<Endpoint>,
    pub ports: Vec<SlicePort>,
}

/// One programmed frontend and where it came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frontend {
    pub namespace: String,
    pub name: String,
    pub port_name: String,
    pub service_type: String,
    /// `ClusterIP`, `ExternalIPs`, `LoadBalancer` or `NodePort`: which
    /// address of the Service this frontend is.
    pub kind: &'static str,
    pub service: Service,
}

fn protocol(name: &str) -> Option<u8> {
    match name {
        "TCP" => Some(PROTO_TCP),
        "UDP" => Some(PROTO_UDP),
        // SCTP and anything else: socket LB translates TCP and UDP only.
        _ => None,
    }
}

/// Topology-aware routing (#459), as kube-proxy chooses among a port's ready
/// endpoints: when every one has node hints and one names `node`, those
/// naming it; else when every one has zone hints and one names `zone`, those
/// naming it; else all of them.
#[derive(Clone, Copy)]
pub struct Topology<'a> {
    pub node: &'a str,
    pub zone: &'a str,
}
fn by_topology<'a>(
    ready: Vec<(&'a Endpoint, u16)>,
    topology: Topology<'_>,
) -> Vec<(&'a Endpoint, u16)> {
    let node_hints: fn(&Endpoint) -> &[String] = |e| e.node_hints.as_slice();
    let zone_hints: fn(&Endpoint) -> &[String] = |e| e.zone_hints.as_slice();
    for (hints, name) in [(node_hints, topology.node), (zone_hints, topology.zone)] {
        let names = |e: &Endpoint| hints(e).iter().any(|h| h == name);
        if !name.is_empty()
            && ready.iter().all(|(e, _)| !hints(e).is_empty())
            && ready.iter().any(|(e, _)| names(e))
        {
            return ready.into_iter().filter(|(e, _)| names(e)).collect();
        }
    }
    ready
}

/// The backends of `service`'s `port` in `family` (true: IPv6), limited to
/// endpoints on node `only` when given and not on node `not_on` when given.
/// With `topology` (traffic policy Cluster), ready endpoints are chosen by
/// their hints ([`Topology`]).
fn backends(
    port: &ServicePort,
    proto: u8,
    v6: bool,
    slices: &[&SliceInfo],
    only: Option<&str>,
    not_on: Option<&str>,
    topology: Option<Topology<'_>>,
) -> Vec<Address> {
    let family = if v6 { "IPv6" } else { "IPv4" };
    let mut ready = Vec::new();
    let mut terminating = Vec::new();
    for slice in slices.iter().filter(|s| s.address_type == family) {
        let Some(target) = slice
            .ports
            .iter()
            .find(|p| p.name == port.name && p.protocol == port.protocol)
            .and_then(|p| p.port)
        else {
            continue;
        };
        for endpoint in &slice.endpoints {
            if only.is_some_and(|node| endpoint.node_name != node)
                || not_on.is_some_and(|node| endpoint.node_name == node)
            {
                continue;
            }
            if endpoint.ready {
                ready.push((endpoint, target));
            } else if endpoint.serving && endpoint.terminating {
                terminating.push((endpoint, target));
            }
        }
    }
    // Hints choose among ready endpoints only; the serving-terminating
    // fallback ignores them, as kube-proxy does.
    if let Some(topology) = topology {
        ready = by_topology(ready, topology);
    }
    let chosen = if ready.is_empty() { terminating } else { ready };
    let mut set = BTreeSet::new();
    for (endpoint, target) in chosen {
        for address in endpoint.addresses.iter().filter(|a| a.is_ipv6() == v6) {
            set.insert(Address {
                ip: *address,
                port: target,
                proto,
            });
        }
    }
    set.into_iter().collect()
}

/// The frontends for `services` as seen from node `local`, sorted by
/// frontend address. `nodes` gives every node's InternalIPs for NodePorts.
pub fn frontends(
    services: &[ServiceInfo],
    slices: &[SliceInfo],
    local: &str,
    nodes: &[NodeAddresses],
) -> Vec<Frontend> {
    let mut by_service: BTreeMap<(&str, &str), Vec<&SliceInfo>> = BTreeMap::new();
    for slice in slices.iter().filter(|s| !s.service.is_empty()) {
        by_service
            .entry((slice.namespace.as_str(), slice.service.as_str()))
            .or_default()
            .push(slice);
    }
    let topology = Topology {
        node: local,
        zone: nodes
            .iter()
            .find(|n| n.name == local)
            .map_or("", |n| n.zone.as_str()),
    };
    let mut out: BTreeMap<(Address, u8), Frontend> = BTreeMap::new();
    for service in services {
        let slices = by_service
            .get(&(service.namespace.as_str(), service.name.as_str()))
            .map(Vec::as_slice)
            .unwrap_or_default();
        let load_balancer = service.service_type == "LoadBalancer";
        let node_ports = load_balancer || service.service_type == "NodePort";
        for port in &service.ports {
            let Some(proto) = protocol(&port.protocol) else {
                continue;
            };
            // (kind, frontend IP, frontend port, node the backends must be on)
            let mut addresses: Vec<(&'static str, IpAddr, u16, Option<&str>)> = Vec::new();
            let internal = service.internal_local.then_some(local);
            for ip in &service.cluster_ips {
                addresses.push(("ClusterIP", *ip, port.port, internal));
            }
            for ip in &service.external_ips {
                addresses.push(("ExternalIPs", *ip, port.port, None));
            }
            if load_balancer {
                for ip in &service.load_balancer_ips {
                    addresses.push(("LoadBalancer", *ip, port.port, None));
                }
            }
            if let (true, Some(node_port)) = (node_ports, port.node_port) {
                for node in nodes {
                    let only = service.external_local.then_some(node.name.as_str());
                    for ip in &node.ips {
                        addresses.push(("NodePort", *ip, node_port, only));
                    }
                }
            }
            for (kind, ip, frontend_port, only) in addresses {
                let frontend = Address {
                    ip,
                    port: frontend_port,
                    proto,
                };
                // Packets from outside the cluster reach a NodePort, external
                // or LoadBalancer address on this node's uplink (scope 1): every
                // backend, other nodes' through SNAT, or with
                // `externalTrafficPolicy: Local` this node's only.
                // A cluster IP only with `lb-external-clusterip` (#465).
                let scopes: &[u8] = if kind == "ClusterIP" && !service.external_clusterip {
                    &[SCOPE_CLUSTER]
                } else {
                    &[SCOPE_CLUSTER, SCOPE_NODE_LOCAL]
                };
                for &scope in scopes {
                    let only = if scope == SCOPE_NODE_LOCAL && kind == "ClusterIP" {
                        // A cluster IP's policy is internalTrafficPolicy.
                        internal
                    } else if scope == SCOPE_NODE_LOCAL {
                        service.external_local.then_some(local)
                    } else {
                        only
                    };
                    // Topology hints for traffic policy Cluster only (#459).
                    let same = backends(
                        port,
                        proto,
                        ip.is_ipv6(),
                        slices,
                        only,
                        None,
                        only.is_none().then_some(topology),
                    );
                    // Translated backends must be on other nodes: a local pod's
                    // reply to this node's address never reaches the uplink. So
                    // `externalTrafficPolicy: Local` never translates.
                    let translated = if service.nat46x64
                        && scope == SCOPE_NODE_LOCAL
                        && same.is_empty()
                        && only.is_none()
                    {
                        backends(port, proto, !ip.is_ipv6(), slices, None, Some(local), None)
                    } else {
                        Vec::new()
                    };
                    let nat46x64 = !translated.is_empty();
                    // An address can front one Service port; the first one wins.
                    out.entry((frontend, scope)).or_insert_with(|| Frontend {
                        namespace: service.namespace.clone(),
                        name: service.name.clone(),
                        port_name: port.name.clone(),
                        service_type: service.service_type.clone(),
                        kind,
                        service: Service {
                            frontend,
                            backends: if nat46x64 { translated } else { same },
                            affinity: service.affinity,
                            scope,
                            maglev: service.maglev && scope == SCOPE_NODE_LOCAL,
                            dsr: scope == SCOPE_NODE_LOCAL
                                && !nat46x64
                                && if proto == PROTO_TCP {
                                    service.dsr_tcp
                                } else {
                                    service.dsr_other
                                },
                            nat46x64,
                        },
                    });
                }
            }
        }
    }
    out.into_values().collect()
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        PROTO_TCP => "TCP",
        PROTO_UDP => "UDP",
        _ => "ANY",
    }
}
fn address_json(address: &Address) -> Value {
    json!({"ip":address.ip.to_string(),"port":address.port,"protocol":protocol_name(address.proto)})
}

/// `GET /v1/service` (reference `Service` model, ClusterIP subset): `id` is
/// the programmed service ID (`rev_nat_index`), 0 until the maps hold it;
/// `status.realized` is present once they do.
pub fn service_list(frontends: &[Frontend], ids: &BTreeMap<(Address, u8), u16>) -> Value {
    Value::Array(
        frontends
            .iter()
            .map(|f| {
                let mut front = address_json(&f.service.frontend);
                if let Some(object) = front.as_object_mut() {
                    // `node-local`: the uplink copy with this node's backends.
                    let scope = if f.service.scope == SCOPE_NODE_LOCAL {
                        "node-local"
                    } else {
                        "external"
                    };
                    object.insert("scope".into(), json!(scope));
                }
                let backends: Vec<_> = f
                    .service
                    .backends
                    .iter()
                    .map(|b| {
                        let mut row = address_json(b);
                        if let Some(object) = row.as_object_mut() {
                            object.insert("state".into(), json!("active"));
                        }
                        row
                    })
                    .collect();
                let id = ids
                    .get(&(f.service.frontend, f.service.scope))
                    .copied()
                    .unwrap_or(0);
                let mut flags = json!({"type":f.kind,"name":f.name,"namespace":f.namespace,
                    "port-name":f.port_name,"service-type":f.service_type});
                if let (Some(seconds), Some(object)) = (f.service.affinity, flags.as_object_mut()) {
                    object.insert("session-affinity-timeout".into(), json!(seconds));
                }
                if let (true, Some(object)) = (f.service.maglev, flags.as_object_mut()) {
                    object.insert("lb-algorithm".into(), json!("maglev"));
                }
                if let (true, Some(object)) = (f.service.dsr, flags.as_object_mut()) {
                    object.insert("forwarding-mode".into(), json!("dsr"));
                }
                if let (true, Some(object)) = (f.service.nat46x64, flags.as_object_mut()) {
                    let policy = if f.service.frontend.ip.is_ipv4() {
                        "Nat46"
                    } else {
                        "Nat64"
                    };
                    object.insert("nat-policy".into(), json!(policy));
                }
                let spec = json!({"id":id,"frontend-address":front,"backend-addresses":backends,
                    "flags":flags});
                let mut row = json!({"spec":spec});
                if id != 0
                    && let Some(object) = row.as_object_mut()
                {
                    object.insert("status".into(), json!({"realized":spec}));
                }
                row
            })
            .collect(),
    )
}

/// Spec 05 §3.8: at most one socket termination pass per 50 ms (#392).
pub const TERMINATION_BATCH: std::time::Duration = std::time::Duration::from_millis(50);

/// The backends that left and wait for a termination pass (#392): gathered
/// while passes are less than [`TERMINATION_BATCH`] apart, then ended in one.
#[derive(Debug, Default)]
pub struct TerminationBatch {
    pending: BTreeSet<flowsdn_connector::sock_diag::Backend>,
    last: Option<std::time::Instant>,
}
impl TerminationBatch {
    pub fn add(&mut self, gone: impl IntoIterator<Item = flowsdn_connector::sock_diag::Backend>) {
        self.pending.extend(gone);
    }
    /// The pending backends, when a pass is due at `now` (nothing pending,
    /// or the last pass less than 50 ms ago: None). Taking them starts the
    /// next 50 ms.
    pub fn take(
        &mut self,
        now: std::time::Instant,
    ) -> Option<BTreeSet<flowsdn_connector::sock_diag::Backend>> {
        if self.pending.is_empty() || self.wait(now).is_some_and(|w| !w.is_zero()) {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.pending))
    }
    /// How long until the pending backends are due; None with none pending.
    pub fn wait(&self, now: std::time::Instant) -> Option<std::time::Duration> {
        if self.pending.is_empty() {
            return None;
        }
        Some(self.last.map_or(std::time::Duration::ZERO, |last| {
            TERMINATION_BATCH.saturating_sub(now.saturating_duration_since(last))
        }))
    }
}

/// The backends of `services` socket termination watches (#392): UDP, and
/// TCP with `tcp` (`kubernetes.lb-sock-terminate-all-protos`). IPv4-mapped
/// addresses as IPv4.
pub fn terminable_backends(
    services: &[Service],
    tcp: bool,
) -> BTreeSet<flowsdn_connector::sock_diag::Backend> {
    services
        .iter()
        .flat_map(|s| &s.backends)
        .filter(|b| b.proto == PROTO_UDP || (tcp && b.proto == PROTO_TCP))
        .map(|b| {
            (
                b.proto,
                flowsdn_connector::sock_diag::unmapped(b.ip),
                b.port,
            )
        })
        .collect()
}

/// At start (#392): the UDP backends the socket LB translated sockets to
/// before (`_reverse_sk`, kept across agent restarts) that no Service has
/// now; those sockets lost their backend while the agent was down.
pub fn stale_udp_backends(
    reverse: &[(u64, IpAddr, u16)],
    now: &BTreeSet<flowsdn_connector::sock_diag::Backend>,
) -> BTreeSet<flowsdn_connector::sock_diag::Backend> {
    reverse
        .iter()
        .map(|(_, ip, port)| {
            (
                PROTO_UDP,
                flowsdn_connector::sock_diag::unmapped(*ip),
                *port,
            )
        })
        .filter(|backend| !now.contains(backend))
        .collect()
}

#[cfg(test)]
#[path = "services_tests.rs"]
mod tests;
