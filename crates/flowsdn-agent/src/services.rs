//! Services and EndpointSlices to socket-LB frontends (spec 05 §3.1–§3.3,
//! ClusterIP only): every cluster IP x port of a Service is a frontend; its
//! backends are the addresses of that Service's EndpointSlices of the same
//! family, on the slice port with the Service port's name and protocol.
//! Ready endpoints serve; when none is ready, serving-terminating ones do
//! (KEP-1669). Pure data; the `kubernetes` controller feeds and applies it.
use flowsdn_lb::socket::{Address, PROTO_TCP, PROTO_UDP, Service};
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
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ServiceInfo {
    pub namespace: String,
    pub name: String,
    pub service_type: String,
    pub cluster_ips: Vec<IpAddr>,
    pub ports: Vec<ServicePort>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Endpoint {
    pub addresses: Vec<IpAddr>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
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

/// The frontends for `services`, sorted by frontend address.
pub fn frontends(services: &[ServiceInfo], slices: &[SliceInfo]) -> Vec<Frontend> {
    let mut by_service: BTreeMap<(&str, &str), Vec<&SliceInfo>> = BTreeMap::new();
    for slice in slices.iter().filter(|s| !s.service.is_empty()) {
        by_service
            .entry((slice.namespace.as_str(), slice.service.as_str()))
            .or_default()
            .push(slice);
    }
    let mut out = BTreeMap::new();
    for service in services {
        let slices = by_service
            .get(&(service.namespace.as_str(), service.name.as_str()))
            .map(Vec::as_slice)
            .unwrap_or_default();
        for ip in &service.cluster_ips {
            let family = if ip.is_ipv4() { "IPv4" } else { "IPv6" };
            for port in &service.ports {
                let Some(proto) = protocol(&port.protocol) else {
                    continue;
                };
                let frontend = Address {
                    ip: *ip,
                    port: port.port,
                    proto,
                };
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
                        let set = if endpoint.ready {
                            &mut ready
                        } else if endpoint.serving && endpoint.terminating {
                            &mut terminating
                        } else {
                            continue;
                        };
                        for address in endpoint.addresses.iter().filter(|a| a.is_ipv4() == ip.is_ipv4()) {
                            set.insert(Address {
                                ip: *address,
                                port: target,
                                proto,
                            });
                        }
                    }
                }
                let backends = if ready.is_empty() { terminating } else { ready };
                // Two Services cannot share a cluster IP; first one wins.
                out.entry(frontend).or_insert_with(|| Frontend {
                    namespace: service.namespace.clone(),
                    name: service.name.clone(),
                    port_name: port.name.clone(),
                    service_type: service.service_type.clone(),
                    service: Service {
                        frontend,
                        backends: backends.into_iter().collect(),
                    },
                });
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
pub fn service_list(frontends: &[Frontend], ids: &BTreeMap<Address, u16>) -> Value {
    Value::Array(
        frontends
            .iter()
            .map(|f| {
                let mut front = address_json(&f.service.frontend);
                if let Some(object) = front.as_object_mut() {
                    object.insert("scope".into(), json!("external"));
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
                let id = ids.get(&f.service.frontend).copied().unwrap_or(0);
                let spec = json!({"id":id,"frontend-address":front,"backend-addresses":backends,
                    "flags":{"type":"ClusterIP","name":f.name,"namespace":f.namespace,
                        "port-name":f.port_name,"service-type":f.service_type}});
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
