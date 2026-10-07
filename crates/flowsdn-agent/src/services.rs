//! Services and EndpointSlices to socket-LB frontends (spec 05 §3.1–§3.3).
//! A Service's frontends are its cluster IPs, external IPs and (type
//! LoadBalancer) load-balancer ingress IPs on each port, and (NodePort and
//! LoadBalancer) every node's InternalIP on each `nodePort`. The socket LB
//! translates them for clients inside the cluster: pods and node processes.
//! Backends are the addresses of that Service's EndpointSlices of the same
//! family, on the slice port with the Service port's name and protocol.
//! Ready endpoints serve; when none is ready, serving-terminating ones do
//! (KEP-1669). `internalTrafficPolicy: Local` limits a cluster IP to this
//! node's endpoints, and `externalTrafficPolicy: Local` limits a NodePort on a
//! node's address to that node's endpoints, as for a packet arriving there.
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
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Endpoint {
    pub addresses: Vec<IpAddr>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
    pub node_name: String,
}
/// A node's name and InternalIPs (NodePort frontends).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeAddresses {
    pub name: String,
    pub ips: Vec<IpAddr>,
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

/// The backends of `service`'s `port` in `family` (true: IPv6), limited to
/// endpoints on node `only` when given.
fn backends(
    port: &ServicePort,
    proto: u8,
    v6: bool,
    slices: &[&SliceInfo],
    only: Option<&str>,
) -> Vec<Address> {
    let family = if v6 { "IPv6" } else { "IPv4" };
    let mut ready = BTreeSet::new();
    let mut terminating = BTreeSet::new();
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
            if only.is_some_and(|node| endpoint.node_name != node) {
                continue;
            }
            let set = if endpoint.ready {
                &mut ready
            } else if endpoint.serving && endpoint.terminating {
                &mut terminating
            } else {
                continue;
            };
            for address in endpoint.addresses.iter().filter(|a| a.is_ipv6() == v6) {
                set.insert(Address {
                    ip: *address,
                    port: target,
                    proto,
                });
            }
        }
    }
    let chosen = if ready.is_empty() { terminating } else { ready };
    chosen.into_iter().collect()
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
                // or LoadBalancer address on this node's uplink, and are only
                // sent to this node's backends (no SNAT yet).
                let scopes: &[u8] = if kind == "ClusterIP" {
                    &[SCOPE_CLUSTER]
                } else {
                    &[SCOPE_CLUSTER, SCOPE_NODE_LOCAL]
                };
                for &scope in scopes {
                    let only = if scope == SCOPE_NODE_LOCAL { Some(local) } else { only };
                    // An address can front one Service port; the first one wins.
                    out.entry((frontend, scope)).or_insert_with(|| Frontend {
                        namespace: service.namespace.clone(),
                        name: service.name.clone(),
                        port_name: port.name.clone(),
                        service_type: service.service_type.clone(),
                        kind,
                        service: Service {
                            frontend,
                            backends: backends(port, proto, ip.is_ipv6(), slices, only),
                            affinity: service.affinity,
                            scope,
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

#[cfg(test)]
#[path = "services_tests.rs"]
mod tests;
