//! Local redirect policy (#565, spec 05 §3.9, §4.6): FlowsdnLocalRedirectPolicy
//! frontends redirected to this node's Pods in the socket LB.
//!
//! A policy names a frontend: an address and ports (`addressMatcher`), or a
//! Service and optionally some of its ports (`serviceMatcher`). Its backends
//! are this node's Ready, non-host-network Pods in the policy's namespace that
//! `localEndpointSelector` selects, on the container ports `toPorts` names.
//! Frontend and backend ports pair up as the reference's frontend types do:
//! when each side has one port they pair; otherwise they pair by name (every
//! port must then be named). Single-port pairs must have one protocol.
//!
//! - **serviceMatcher**: each `ClusterIP` frontend of the Service whose port
//!   pairs gets the local backends, marked `LOCAL_REDIRECT`, while at least
//!   one backend exists; with none it keeps the Service's own backends.
//! - **addressMatcher**: a new `LOCAL_REDIRECT` frontend at each `ip:port`,
//!   only while it has backends. An address another Service already serves
//!   is refused.
//! - **skipRedirectFromBackend**: each backend Pod's network namespace
//!   cookie is put in the skip-LB map for the frontend. flowsdn translates
//!   Pods' traffic only in the socket LB, so a skipped socket to a
//!   serviceMatcher frontend gets the Service's own backends (a copy at scope
//!   `SCOPE_REDIRECT_SKIPPED`); to an addressMatcher frontend it is not
//!   translated.
//!
//! A policy that fails validation is reported (`status.ok: false`) and does
//! nothing.
use crate::kubernetes::{LocalEndpoint, PodInfo};
use crate::services::Frontend;
use flowsdn_lb::socket::{
    Address, PROTO_TCP, PROTO_UDP, SCOPE_CLUSTER, SCOPE_REDIRECT_SKIPPED, Service,
};
use flowsdn_policy::k8s::LabelSelector;
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::IpAddr};

/// A port of a policy: name (may be empty), number, protocol number.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Port {
    pub name: String,
    pub port: u16,
    pub proto: u8,
}

/// What a policy redirects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Matcher {
    Address {
        ip: IpAddr,
        ports: Vec<Port>,
    },
    /// The Service's name (in the policy's namespace) and the ports given,
    /// None for all of the Service's ports.
    Service {
        name: String,
        ports: Option<Vec<Port>>,
    },
}

/// A parsed, valid policy.
#[derive(Clone, Debug)]
pub struct Policy {
    pub namespace: String,
    pub name: String,
    pub matcher: Matcher,
    pub selector: LabelSelector,
    pub backend_ports: Vec<Port>,
    pub skip: bool,
}

fn port(value: &Value) -> Result<Port, String> {
    let text = value.get("port").and_then(Value::as_str).unwrap_or("");
    let port = text
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("port {text:?} is not a port number"))?;
    let proto = match value.get("protocol").and_then(Value::as_str) {
        Some("TCP") => PROTO_TCP,
        Some("UDP") => PROTO_UDP,
        other => return Err(format!("protocol {other:?} is not TCP or UDP")),
    };
    Ok(Port {
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        port,
        proto,
    })
}
fn ports(value: Option<&Value>) -> Result<Vec<Port>, String> {
    value
        .and_then(Value::as_array)
        .map(|ports| ports.iter().map(port).collect())
        .unwrap_or_else(|| Ok(Vec::new()))
}
fn named(ports: &[Port], side: &str) -> Result<(), String> {
    if ports.len() > 1 && ports.iter().any(|p| p.name.is_empty()) {
        return Err(format!(
            "{side} has several ports, so every one needs a name"
        ));
    }
    Ok(())
}

/// Validate a FlowsdnLocalRedirectPolicy object (spec 05 §3.9).
pub fn parse(object: &Value) -> Result<Policy, String> {
    let text = |pointer: &str| {
        object
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let (namespace, name) = (text("/metadata/namespace"), text("/metadata/name"));
    if namespace.is_empty() || name.is_empty() {
        return Err("no namespace or name".into());
    }
    let frontend = object.pointer("/spec/redirectFrontend");
    let address = frontend.and_then(|f| f.get("addressMatcher"));
    let service = frontend.and_then(|f| f.get("serviceMatcher"));
    let matcher = match (address, service) {
        (Some(address), None) => {
            let ip_text = address.get("ip").and_then(Value::as_str).unwrap_or("");
            let ip = ip_text
                .parse()
                .map_err(|_| format!("addressMatcher ip {ip_text:?} is not an address"))?;
            let ports = ports(address.get("toPorts"))?;
            if ports.is_empty() {
                return Err("addressMatcher has no toPorts".into());
            }
            named(&ports, "addressMatcher")?;
            Matcher::Address { ip, ports }
        }
        (None, Some(service)) => {
            let target_namespace = service
                .get("namespace")
                .and_then(Value::as_str)
                .unwrap_or("");
            if target_namespace != namespace {
                return Err(format!(
                    "serviceMatcher namespace {target_namespace:?} is not the policy's namespace"
                ));
            }
            let service_name = service
                .get("serviceName")
                .and_then(Value::as_str)
                .unwrap_or("");
            if service_name.is_empty() {
                return Err("serviceMatcher has no serviceName".into());
            }
            let ports = match service.get("toPorts") {
                None | Some(Value::Null) => None,
                Some(list) => {
                    let ports = ports(Some(list))?;
                    named(&ports, "serviceMatcher")?;
                    Some(ports)
                }
            };
            Matcher::Service {
                name: service_name.to_owned(),
                ports,
            }
        }
        _ => return Err("exactly one of addressMatcher and serviceMatcher is required".into()),
    };
    let selector =
        LabelSelector::parse(object.pointer("/spec/redirectBackend/localEndpointSelector"))
            .map_err(|e| format!("localEndpointSelector: {e}"))?;
    let backend_ports = ports(object.pointer("/spec/redirectBackend/toPorts"))?;
    if backend_ports.is_empty() {
        return Err("redirectBackend has no toPorts".into());
    }
    named(&backend_ports, "redirectBackend")?;
    Ok(Policy {
        namespace,
        name,
        matcher,
        selector,
        backend_ports,
        skip: object
            .pointer("/spec/skipRedirectFromBackend")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// The backend port a frontend port pairs with: the only one when each side
/// has one (same protocol), else the one with its name.
fn pair<'a>(frontend: &Port, frontends: usize, backends: &'a [Port]) -> Option<&'a Port> {
    if frontends == 1 && backends.len() == 1 {
        return backends.first().filter(|b| b.proto == frontend.proto);
    }
    backends
        .iter()
        .find(|b| !frontend.name.is_empty() && b.name == frontend.name && b.proto == frontend.proto)
}

/// A local backend Pod: its addresses, container ports and netns cookie.
struct Backend<'a> {
    pod: &'a PodInfo,
    cookie: Option<u64>,
}

/// The local backends of `policy`, on `port` (a backend port): the Pods'
/// addresses of `family`.
fn addresses(backends: &[Backend<'_>], port: &Port, v4: bool) -> Vec<Address> {
    let mut out: Vec<Address> = backends
        .iter()
        .filter(|b| {
            b.pod
                .ports
                .iter()
                .any(|(proto, _, number)| *proto == port.proto && *number == port.port)
        })
        .flat_map(|b| b.pod.ips.iter().filter(|ip| ip.is_ipv4() == v4))
        .map(|ip| Address {
            ip: *ip,
            port: port.port,
            proto: port.proto,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
fn cookies(backends: &[Backend<'_>]) -> Vec<u64> {
    let mut out: Vec<u64> = backends.iter().filter_map(|b| b.cookie).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// What [`apply`] did, for `GET /v1/lrp` and the status writer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    /// Each policy by (namespace, name): None when valid and applied, else
    /// why not.
    pub problems: BTreeMap<(String, String), Option<String>>,
    /// Redirected frontends: (policy, frontend, backends).
    pub redirected: Vec<((String, String), Address, Vec<Address>)>,
}
impl Report {
    /// `GET /v1/lrp`.
    pub fn json(&self, enabled: bool) -> Value {
        let policies: Vec<Value> = self
            .problems
            .iter()
            .map(|((namespace, name), problem)| {
                let frontends: Vec<Value> = self
                    .redirected
                    .iter()
                    .filter(|(policy, _, _)| policy.0 == *namespace && policy.1 == *name)
                    .map(|(_, frontend, backends)| {
                        json!({"frontend": frontend.to_string(),
                               "backends": backends.iter().map(ToString::to_string).collect::<Vec<_>>()})
                    })
                    .collect();
                json!({"namespace": namespace, "name": name, "ok": problem.is_none(),
                       "error": problem, "frontends": frontends})
            })
            .collect();
        json!({"enabled": enabled, "policies": policies})
    }
}

/// Apply the policies (raw objects) to `frontends` for `local_node`'s Pods.
pub fn apply(
    frontends: &mut Vec<Frontend>,
    objects: &[Value],
    pods: &[PodInfo],
    local_node: &str,
    endpoints: &[LocalEndpoint],
) -> Report {
    let mut report = Report::default();
    let mut policies = Vec::new();
    for object in objects {
        let key = (
            object
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            object
                .pointer("/metadata/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        );
        match parse(object) {
            Ok(policy) => policies.push(policy),
            Err(problem) => {
                report.problems.insert(key, Some(problem));
            }
        }
    }
    policies.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    for policy in &policies {
        let key = (policy.namespace.clone(), policy.name.clone());
        let backends: Vec<Backend<'_>> = pods
            .iter()
            .filter(|p| {
                p.node == local_node
                    && p.namespace == policy.namespace
                    && p.ready
                    && !p.host_network
                    && policy.selector.matches(&p.labels)
            })
            .map(|pod| Backend {
                pod,
                cookie: endpoints
                    .iter()
                    .find(|e| e.namespace == pod.namespace && e.name == pod.name)
                    .map(|e| e.netns_cookie)
                    .filter(|c| *c != 0),
            })
            .collect();
        let skip = if policy.skip {
            cookies(&backends)
        } else {
            Vec::new()
        };
        let problem = match &policy.matcher {
            Matcher::Service { name, ports } => {
                redirect_service(
                    frontends,
                    policy,
                    name,
                    ports.as_deref(),
                    &backends,
                    &skip,
                    &mut report,
                );
                None
            }
            Matcher::Address { ip, ports } => {
                redirect_address(frontends, policy, *ip, ports, &backends, &skip, &mut report)
            }
        };
        report.problems.insert(key, problem);
    }
    report
}

fn redirect_service(
    frontends: &mut Vec<Frontend>,
    policy: &Policy,
    service: &str,
    ports: Option<&[Port]>,
    backends: &[Backend<'_>],
    skip: &[u64],
    report: &mut Report,
) {
    let key = (policy.namespace.clone(), policy.name.clone());
    let selected = |f: &Frontend| {
        f.namespace == policy.namespace
            && f.name == service
            && f.kind == "ClusterIP"
            && f.service.scope == SCOPE_CLUSTER
    };
    // The Service's ports, for pairing when the policy names none.
    let mut service_ports: Vec<(u16, u8)> = frontends
        .iter()
        .filter(|f| selected(f))
        .map(|f| (f.service.frontend.port, f.service.frontend.proto))
        .collect();
    service_ports.sort_unstable();
    service_ports.dedup();
    let mut copies = Vec::new();
    for frontend in frontends.iter_mut() {
        if !selected(frontend) {
            continue;
        }
        let address = frontend.service.frontend;
        let own = Port {
            name: frontend.port_name.clone(),
            port: address.port,
            proto: address.proto,
        };
        // The policy's frontend port for this one, and how many it gives.
        let (port, count) = match ports {
            None => (own, service_ports.len()),
            Some(list) => match list.iter().find(|p| {
                p.proto == own.proto
                    && (p.port == own.port || (!p.name.is_empty() && p.name == own.name))
            }) {
                Some(p) => (p.clone(), list.len()),
                None => continue,
            },
        };
        let paired = pair(&port, count, &policy.backend_ports);
        let Some(backend_port) = paired else {
            continue;
        };
        let local = addresses(backends, backend_port, address.ip.is_ipv4());
        if local.is_empty() {
            continue;
        }
        if !skip.is_empty() {
            let mut own = frontend.service.clone();
            own.scope = SCOPE_REDIRECT_SKIPPED;
            copies.push(Frontend {
                service: own,
                ..frontend.clone()
            });
        }
        frontend.service.backends = local.clone();
        frontend.service.local_redirect = true;
        frontend.service.skip = skip.to_vec();
        report.redirected.push((key.clone(), address, local));
    }
    frontends.extend(copies);
}

fn redirect_address(
    frontends: &mut Vec<Frontend>,
    policy: &Policy,
    ip: IpAddr,
    ports: &[Port],
    backends: &[Backend<'_>],
    skip: &[u64],
    report: &mut Report,
) -> Option<String> {
    let key = (policy.namespace.clone(), policy.name.clone());
    let mut added = Vec::new();
    for port in ports {
        let address = Address {
            ip,
            port: port.port,
            proto: port.proto,
        };
        if let Some(owner) = frontends
            .iter()
            .find(|f| f.service.frontend == address && f.service.scope == SCOPE_CLUSTER)
        {
            return Some(format!(
                "{address} is already the frontend of {}/{}",
                owner.namespace, owner.name
            ));
        }
        let Some(backend_port) = pair(port, ports.len(), &policy.backend_ports) else {
            continue;
        };
        let local = addresses(backends, backend_port, ip.is_ipv4());
        if local.is_empty() {
            continue;
        }
        report
            .redirected
            .push((key.clone(), address, local.clone()));
        added.push(Frontend {
            namespace: policy.namespace.clone(),
            name: policy.name.clone(),
            port_name: port.name.clone(),
            service_type: "LocalRedirect".into(),
            kind: "LocalRedirect",
            service: Service {
                frontend: address,
                backends: local,
                affinity: None,
                scope: SCOPE_CLUSTER,
                maglev: false,
                dsr: false,
                nat46x64: false,
                local_redirect: true,
                skip: skip.to_vec(),
            },
        });
    }
    frontends.extend(added);
    None
}

#[cfg(test)]
#[path = "local_redirect_tests.rs"]
mod tests;
