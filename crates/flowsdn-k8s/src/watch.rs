//! Transport-independent built-in resource ListWatch state (spec 13 §5.2).
//!
//! The caller owns HTTP authentication, selectors, retry/backoff and watch
//! framing. Pass each decoded list page/event here, and call `failed` for every
//! transport error. Only a complete list publishes a replacement snapshot.
use crate::Error;
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub name: String,
    pub namespace: String,
    pub uid: String,
    pub resource_version: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub metadata: Metadata,
    pub pod_cidrs: Vec<(IpAddr, u8)>,
    pub internal_ips: Vec<IpAddr>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pod {
    pub metadata: Metadata,
    pub node_name: String,
    pub host_network: bool,
    pub pod_ips: Vec<IpAddr>,
    pub labels: BTreeMap<String, String>,
    /// `spec.serviceAccountName`; empty when absent.
    pub service_account: String,
    /// `metadata.ownerReferences` (the workload, #328).
    pub owners: Vec<OwnerReference>,
    /// `status.containerStatuses` then `status.initContainerStatuses`.
    pub containers: Vec<ContainerStatus>,
    /// Only the annotations the agent writes (`flowsdn.io/` and
    /// [`NETWORK_STATUS`]), each at most [`ANNOTATION_MAX`] bytes; other
    /// annotations are not kept.
    pub annotations: BTreeMap<String, String>,
    /// Those annotations present but over [`ANNOTATION_MAX`] (not kept): a
    /// writer that merges into one must not take it for absent.
    pub oversized: Vec<String>,
}
/// The Multus/NPWG network-status annotation (#371): written by every
/// network plugin of a Pod, so flowsdn keeps it to merge its own entry.
pub const NETWORK_STATUS: &str = "k8s.v1.cni.cncf.io/network-status";
/// The longest `flowsdn.io/` annotation value a Pod row keeps.
pub const ANNOTATION_MAX: usize = 16 * 1024;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerReference {
    pub kind: String,
    pub name: String,
    pub controller: bool,
}
/// A container of the Pod: its name and the runtime's ID
/// (`<runtime>://<id>`, empty until the container is created).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerStatus {
    pub name: String,
    pub container_id: String,
    pub init: bool,
}
/// A Service port: `name` is empty for an unnamed port; `protocol` is the
/// Kubernetes spelling (`TCP`, `UDP`, `SCTP`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePort {
    pub name: String,
    pub protocol: String,
    pub port: u16,
    /// `nodePort` of a NodePort or LoadBalancer Service.
    pub node_port: Option<u16>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub metadata: Metadata,
    /// `spec.type`; `ClusterIP` when absent.
    pub service_type: String,
    /// `spec.clusterIPs` (else `spec.clusterIP`) without `None` (headless)
    /// and values that are not addresses.
    pub cluster_ips: Vec<IpAddr>,
    pub ports: Vec<ServicePort>,
    /// `spec.externalIPs` that are addresses.
    pub external_ips: Vec<IpAddr>,
    /// `status.loadBalancer.ingress[].ip`.
    pub load_balancer_ips: Vec<IpAddr>,
    /// `spec.internalTrafficPolicy` is `Local` (default `Cluster`).
    pub internal_local: bool,
    /// `spec.externalTrafficPolicy` is `Local` (default `Cluster`).
    pub external_local: bool,
    /// `spec.sessionAffinity: ClientIP`: the timeout in seconds
    /// (`sessionAffinityConfig.clientIP.timeoutSeconds`, default 10800).
    pub affinity: Option<u32>,
}
/// An EndpointSlice port; `port` is absent for "all ports".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointPort {
    pub name: String,
    pub protocol: String,
    pub port: Option<u16>,
}
/// One endpoint. Unset `ready`/`serving` conditions count as true and unset
/// `terminating` as false, as the EndpointSlice API asks consumers to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub addresses: Vec<IpAddr>,
    pub ready: bool,
    pub serving: bool,
    pub terminating: bool,
    pub node_name: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointSlice {
    pub metadata: Metadata,
    /// The `kubernetes.io/service-name` label; empty when absent.
    pub service_name: String,
    /// `IPv4`, `IPv6` or `FQDN`.
    pub address_type: String,
    pub endpoints: Vec<Endpoint>,
    pub ports: Vec<EndpointPort>,
}
/// A Namespace's labels: they are part of its Pods' identities (spec 03 §3.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Namespace {
    pub metadata: Metadata,
    pub labels: BTreeMap<String, String>,
}
/// The `io.flowsdn.heartbeat` annotation the operator's identity GC sets on
/// an identity it thinks is unused; an agent that holds it removes it.
pub const HEARTBEAT_ANNOTATION: &str = "io.flowsdn.heartbeat";
/// A `flowsdn.io/v1alpha1` FlowsdnIdentity (spec 03 §4.3): the name is the
/// numeric identity, `security-labels` maps `<source>:<key>` to the value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    pub metadata: Metadata,
    pub id: u32,
    pub security_labels: BTreeMap<String, String>,
    /// `metadata.creationTimestamp` (RFC 3339, so text order is time order).
    pub created: String,
    pub heartbeat: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resource {
    Node(Node),
    Pod(Pod),
    Service(Service),
    EndpointSlice(EndpointSlice),
    Namespace(Namespace),
    Identity(Identity),
}
impl Resource {
    pub fn metadata(&self) -> &Metadata {
        match self {
            Self::Node(n) => &n.metadata,
            Self::Pod(p) => &p.metadata,
            Self::Service(s) => &s.metadata,
            Self::EndpointSlice(e) => &e.metadata,
            Self::Namespace(n) => &n.metadata,
            Self::Identity(i) => &i.metadata,
        }
    }
}
impl Keyed for Resource {
    fn primary_key(&self) -> Key {
        let m = self.metadata();
        format!("{}/{}", m.namespace, m.name).into_bytes()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Nodes,
    LocalPods {
        node_name: String,
    },
    /// Every Pod in the cluster (the IP cache); unscheduled Pods have an empty node.
    Pods,
    /// Every Service in the cluster (socket LB frontends).
    Services,
    /// Every `discovery.k8s.io/v1` EndpointSlice (socket LB backends).
    EndpointSlices,
    /// Every Namespace (its labels are part of Pod identities).
    Namespaces,
    /// Every `flowsdn.io/v1alpha1` FlowsdnIdentity (identity allocation).
    Identities,
}
impl Scope {
    pub fn field_selector(&self) -> Option<String> {
        match self {
            Self::LocalPods { node_name } => Some(format!("spec.nodeName={node_name}")),
            _ => None,
        }
    }
    pub fn namespaced(&self) -> bool {
        !matches!(self, Self::Nodes | Self::Namespaces | Self::Identities)
    }
    pub fn parse(&self, value: &Value) -> Result<Resource, Error> {
        let namespaced = self.namespaced();
        if let Some(kind) = value.get("kind") {
            let expected = match self {
                Self::Nodes => "Node",
                Self::LocalPods { .. } | Self::Pods => "Pod",
                Self::Services => "Service",
                Self::EndpointSlices => "EndpointSlice",
                Self::Namespaces => "Namespace",
                Self::Identities => "FlowsdnIdentity",
            };
            if text(kind)? != expected {
                return Err(error("unexpected resource kind"));
            }
        }
        let metadata = metadata(value, namespaced)?;
        match self {
            Self::Nodes => {
                let mut cidrs = Vec::new();
                for cidr in array(value.pointer("/spec/podCIDRs"))? {
                    cidrs.push(parse_cidr(text(cidr)?)?);
                }
                if cidrs.is_empty()
                    && let Some(cidr) = value.pointer("/spec/podCIDR").filter(|v| !v.is_null())
                {
                    let cidr = text(cidr)?;
                    if !cidr.is_empty() {
                        cidrs.push(parse_cidr(cidr)?);
                    }
                }
                let mut ips = Vec::new();
                for address in array(value.pointer("/status/addresses"))? {
                    if required(address, "type")? == "InternalIP" {
                        ips.push(parse_ip(required(address, "address")?)?);
                    }
                }
                Ok(Resource::Node(Node {
                    metadata,
                    pod_cidrs: cidrs,
                    internal_ips: ips,
                }))
            }
            Self::LocalPods { .. } | Self::Pods => {
                let spec = value.get("spec").ok_or_else(|| error("missing Pod spec"))?;
                let actual = match self {
                    Self::LocalPods { node_name } => {
                        let actual = required(spec, "nodeName")?;
                        if actual != node_name {
                            return Err(error("Pod does not match local node selector"));
                        }
                        actual
                    }
                    _ => match spec.get("nodeName") {
                        None | Some(Value::Null) => "",
                        Some(v) => text(v)?,
                    },
                };
                let host_network = match value.pointer("/spec/hostNetwork") {
                    None | Some(Value::Null) => false,
                    Some(v) => v.as_bool().ok_or_else(|| error("invalid hostNetwork"))?,
                };
                let mut ips = Vec::new();
                for address in array(value.pointer("/status/podIPs"))? {
                    ips.push(parse_ip(required(address, "ip")?)?);
                }
                if ips.is_empty()
                    && let Some(ip) = value.pointer("/status/podIP").filter(|v| !v.is_null())
                {
                    let ip = text(ip)?;
                    if !ip.is_empty() {
                        ips.push(parse_ip(ip)?);
                    }
                }
                Ok(Resource::Pod(Pod {
                    service_account: optional_text(spec, "serviceAccountName", "")?.into(),
                    labels: labels(value)?,
                    metadata,
                    node_name: actual.into(),
                    host_network,
                    pod_ips: ips,
                    owners: owner_references(value),
                    containers: container_statuses(value),
                    annotations: flowsdn_annotations(value),
                    oversized: oversized_annotations(value),
                }))
            }
            Self::Services => parse_service(value, metadata).map(Resource::Service),
            Self::EndpointSlices => parse_slice(value, metadata).map(Resource::EndpointSlice),
            Self::Namespaces => Ok(Resource::Namespace(Namespace {
                labels: labels(value)?,
                metadata,
            })),
            Self::Identities => parse_identity(value, metadata).map(Resource::Identity),
        }
    }
}

fn labels(value: &Value) -> Result<BTreeMap<String, String>, Error> {
    let mut labels = BTreeMap::new();
    if let Some(raw) = value.pointer("/metadata/labels").filter(|v| !v.is_null()) {
        for (key, val) in raw.as_object().ok_or_else(|| error("invalid labels"))? {
            labels.insert(key.clone(), text(val)?.to_owned());
        }
    }
    Ok(labels)
}
/// The name must be a decimal identity without leading zeros (the allocator
/// writes it so; anything else is not an identity and fails the object).
fn parse_identity(value: &Value, metadata: Metadata) -> Result<Identity, Error> {
    let name = &metadata.name;
    let id = name
        .parse::<u32>()
        .ok()
        .filter(|id| *id != 0 && id.to_string() == *name)
        .ok_or_else(|| error("FlowsdnIdentity name is not a numeric identity"))?;
    let mut security_labels = BTreeMap::new();
    let raw = value
        .get("security-labels")
        .and_then(Value::as_object)
        .ok_or_else(|| error("missing security-labels"))?;
    for (key, val) in raw {
        security_labels.insert(key.clone(), text(val)?.to_owned());
    }
    let created = match value.pointer("/metadata/creationTimestamp") {
        None | Some(Value::Null) => "",
        Some(v) => text(v)?,
    };
    let heartbeat = value
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
        .is_some_and(|a| a.contains_key(HEARTBEAT_ANNOTATION));
    Ok(Identity {
        metadata,
        id,
        security_labels,
        created: created.into(),
        heartbeat,
    })
}

// Tagging metadata (#328) is informational: an odd entry is skipped rather
// than failing the Pod, whose IPs the IP cache needs.
fn owner_references(value: &Value) -> Vec<OwnerReference> {
    let Some(owners) = value
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    owners
        .iter()
        .filter_map(|owner| {
            Some(OwnerReference {
                kind: owner.get("kind")?.as_str()?.to_owned(),
                name: owner.get("name")?.as_str()?.to_owned(),
                controller: owner.get("controller").and_then(Value::as_bool) == Some(true),
            })
        })
        .collect()
}
fn container_statuses(value: &Value) -> Vec<ContainerStatus> {
    let mut containers = Vec::new();
    for (key, init) in [
        ("containerStatuses", false),
        ("initContainerStatuses", true),
    ] {
        let Some(list) = value
            .pointer(&format!("/status/{key}"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for status in list {
            let Some(name) = status.get("name").and_then(Value::as_str) else {
                continue;
            };
            containers.push(ContainerStatus {
                name: name.to_owned(),
                container_id: status
                    .get("containerID")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                init,
            });
        }
    }
    containers
}
fn kept_annotation(key: &str) -> bool {
    key.starts_with("flowsdn.io/") || key == NETWORK_STATUS
}
fn flowsdn_annotations(value: &Value) -> BTreeMap<String, String> {
    let Some(annotations) = value
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
    else {
        return BTreeMap::new();
    };
    annotations
        .iter()
        .filter(|(key, _)| kept_annotation(key))
        .filter_map(|(key, value)| {
            let value = value.as_str().filter(|v| v.len() <= ANNOTATION_MAX)?;
            Some((key.clone(), value.to_owned()))
        })
        .collect()
}
fn oversized_annotations(value: &Value) -> Vec<String> {
    let Some(annotations) = value
        .pointer("/metadata/annotations")
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    annotations
        .iter()
        .filter(|(key, value)| {
            kept_annotation(key) && value.as_str().is_none_or(|v| v.len() > ANNOTATION_MAX)
        })
        .map(|(key, _)| key.clone())
        .collect()
}

fn optional_text<'a>(value: &'a Value, key: &str, default: &'a str) -> Result<&'a str, Error> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => text(v),
    }
}
fn port_number(value: &Value) -> Result<u16, Error> {
    value
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0)
        .ok_or_else(|| error("invalid port"))
}
fn condition(value: &Value, key: &str, default: bool) -> Result<bool, Error> {
    match value.pointer(&format!("/conditions/{key}")) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => v
            .as_bool()
            .ok_or_else(|| Error(format!("invalid {key} condition"))),
    }
}
fn parse_service(value: &Value, metadata: Metadata) -> Result<Service, Error> {
    let spec = value
        .get("spec")
        .ok_or_else(|| error("missing Service spec"))?;
    let mut raw = Vec::new();
    for ip in array(spec.get("clusterIPs"))? {
        raw.push(text(ip)?);
    }
    if raw.is_empty() {
        raw.push(optional_text(spec, "clusterIP", "")?);
    }
    // "None" (headless) and empty mean no virtual IP; the API server
    // validates the rest, and one odd value must not fail the whole list.
    let cluster_ips = raw.into_iter().filter_map(|ip| ip.parse().ok()).collect();
    let mut ports = Vec::new();
    for port in array(spec.get("ports"))? {
        ports.push(ServicePort {
            name: optional_text(port, "name", "")?.into(),
            protocol: optional_text(port, "protocol", "TCP")?.into(),
            port: port_number(port.get("port").unwrap_or(&Value::Null))?,
            node_port: match port.get("nodePort") {
                None | Some(Value::Null) => None,
                Some(v) => Some(port_number(v)?),
            },
        });
    }
    // Like cluster IPs: an odd value is skipped, not a failed list.
    let addresses = |list: Option<&Value>, key: Option<&str>| -> Vec<IpAddr> {
        list.and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| match key {
                        Some(key) => item.get(key).and_then(Value::as_str),
                        None => item.as_str(),
                    })
                    .filter_map(|ip| ip.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(Service {
        metadata,
        service_type: optional_text(spec, "type", "ClusterIP")?.into(),
        cluster_ips,
        ports,
        external_ips: addresses(spec.get("externalIPs"), None),
        load_balancer_ips: addresses(value.pointer("/status/loadBalancer/ingress"), Some("ip")),
        internal_local: optional_text(spec, "internalTrafficPolicy", "Cluster")? == "Local",
        external_local: optional_text(spec, "externalTrafficPolicy", "Cluster")? == "Local",
        affinity: (optional_text(spec, "sessionAffinity", "None")? == "ClientIP").then(|| {
            spec.pointer("/sessionAffinityConfig/clientIP/timeoutSeconds")
                .and_then(Value::as_u64)
                .and_then(|t| u32::try_from(t).ok())
                .filter(|t| *t > 0)
                .unwrap_or(10800)
        }),
    })
}
fn parse_slice(value: &Value, metadata: Metadata) -> Result<EndpointSlice, Error> {
    let service_name = match value.pointer("/metadata/labels/kubernetes.io~1service-name") {
        None | Some(Value::Null) => "",
        Some(v) => text(v)?,
    };
    let address_type = required(value, "addressType")?;
    let mut endpoints = Vec::new();
    for endpoint in array(value.get("endpoints"))? {
        let mut addresses = Vec::new();
        if address_type != "FQDN" {
            for address in array(endpoint.get("addresses"))? {
                addresses.push(parse_ip(text(address)?)?);
            }
        }
        let ready = condition(endpoint, "ready", true)?;
        endpoints.push(Endpoint {
            addresses,
            ready,
            serving: condition(endpoint, "serving", ready)?,
            terminating: condition(endpoint, "terminating", false)?,
            node_name: optional_text(endpoint, "nodeName", "")?.into(),
        });
    }
    let mut ports = Vec::new();
    for port in array(value.get("ports"))? {
        ports.push(EndpointPort {
            name: optional_text(port, "name", "")?.into(),
            protocol: optional_text(port, "protocol", "TCP")?.into(),
            port: match port.get("port") {
                None | Some(Value::Null) => None,
                Some(v) => Some(port_number(v)?),
            },
        });
    }
    Ok(EndpointSlice {
        metadata,
        service_name: service_name.into(),
        address_type: address_type.into(),
        endpoints,
        ports,
    })
}

fn error(message: &str) -> Error {
    Error(message.into())
}
fn text(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or_else(|| error("expected string"))
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error(format!("missing or invalid {key}")))
}
fn array(value: Option<&Value>) -> Result<&[Value], Error> {
    match value {
        None | Some(Value::Null) => Ok(&[]),
        Some(v) => v
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| error("expected array")),
    }
}
fn metadata(value: &Value, namespaced: bool) -> Result<Metadata, Error> {
    let meta = value
        .get("metadata")
        .ok_or_else(|| error("missing metadata"))?;
    let name = required(meta, "name")?;
    let namespace = if namespaced {
        required(meta, "namespace")?
    } else {
        ""
    };
    // Keys must be unambiguous even when fed malformed server data.
    if name.contains('/') || namespace.contains('/') {
        return Err(error("invalid object name"));
    }
    Ok(Metadata {
        name: name.into(),
        namespace: namespace.into(),
        uid: required(meta, "uid")?.into(),
        resource_version: required(meta, "resourceVersion")?.into(),
    })
}
fn parse_ip(value: &str) -> Result<IpAddr, Error> {
    value.parse().map_err(|_| error("invalid IP address"))
}
fn parse_cidr(value: &str) -> Result<(IpAddr, u8), Error> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| error("invalid PodCIDR"))?;
    let ip = parse_ip(ip)?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| error("invalid PodCIDR prefix"))?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } {
        return Err(error("invalid PodCIDR prefix"));
    }
    Ok((ip, prefix))
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_objects: usize,
    pub max_pages: usize,
    /// Total encoded JSON bytes in a list, or in one watch event. The transport
    /// must independently bound HTTP/frame bytes before decoding JSON.
    pub max_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_pages: 10_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}
struct Listing {
    rows: BTreeMap<Key, Resource>,
    resource_version: Option<String>,
    tokens: BTreeSet<String>,
    pages: usize,
    bytes: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageResult {
    Continue(String),
    Complete,
}

/// Single writer, one table, immutable consumer snapshots. Resource versions
/// are opaque strings, never numeric ordering or cross-resource clocks.
pub struct WatchState {
    scope: Scope,
    limits: Limits,
    table: Table<Resource>,
    listing: Option<Listing>,
    resource_version: Option<String>,
    needs_relist: bool,
    initialized: bool,
}
impl WatchState {
    pub fn new(scope: Scope, limits: Limits) -> Result<Self, Error> {
        if limits.max_objects == 0 || limits.max_pages == 0 || limits.max_bytes == 0 {
            return Err(error("watch limits must be positive"));
        }
        if let Scope::LocalPods { node_name } = &scope
            && (node_name.is_empty()
                || node_name
                    .chars()
                    .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.'))
        {
            return Err(error("invalid local node name"));
        }
        Ok(Self {
            scope,
            limits,
            table: Table::new(vec![]).map_err(|e| Error(e.to_string()))?,
            listing: None,
            resource_version: None,
            needs_relist: true,
            initialized: false,
        })
    }
    pub fn snapshot(&self) -> Snapshot<Resource> {
        self.table.snapshot()
    }
    pub fn needs_relist(&self) -> bool {
        self.needs_relist
    }
    pub fn initialized(&self) -> bool {
        self.initialized
    }
    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }
    /// Discard staging only. Forwarding consumers retain the last good table.
    pub fn failed(&mut self) {
        self.listing = None;
        self.needs_relist = true;
    }
    pub fn begin_list(&mut self) {
        self.failed();
        self.listing = Some(Listing {
            rows: BTreeMap::new(),
            resource_version: None,
            tokens: BTreeSet::new(),
            pages: 0,
            bytes: 0,
        });
    }
    pub async fn list_page(&mut self, page: &Value) -> Result<PageResult, Error> {
        let result = self.stage_page(page).await;
        if result.is_err() {
            self.failed();
        }
        result
    }
    async fn stage_page(&mut self, page: &Value) -> Result<PageResult, Error> {
        let list = self
            .listing
            .as_mut()
            .ok_or_else(|| error("list has not begun"))?;
        list.pages = list
            .pages
            .checked_add(1)
            .ok_or_else(|| error("page count overflow"))?;
        list.bytes = list
            .bytes
            .checked_add(encoded_size(page)?)
            .ok_or_else(|| error("list byte count overflow"))?;
        if list.pages > self.limits.max_pages || list.bytes > self.limits.max_bytes {
            return Err(error("list exceeds limits"));
        }
        let meta = page
            .get("metadata")
            .ok_or_else(|| error("missing list metadata"))?;
        let rv = required(meta, "resourceVersion")?;
        if list
            .resource_version
            .as_deref()
            .is_some_and(|old| old != rv)
        {
            return Err(error("list resourceVersion changed between pages"));
        }
        list.resource_version = Some(rv.into());
        let items = page
            .get("items")
            .and_then(Value::as_array)
            .ok_or_else(|| error("missing list items"))?;
        if list
            .rows
            .len()
            .checked_add(items.len())
            .is_none_or(|n| n > self.limits.max_objects)
        {
            return Err(error("list exceeds object limit"));
        }
        for item in items {
            let row = self.scope.parse(item)?;
            if list.rows.insert(row.primary_key(), row).is_some() {
                return Err(error("duplicate list object"));
            }
        }
        let token = match meta.get("continue") {
            None => "",
            Some(v) => text(v)?,
        };
        if !token.is_empty() {
            if !list.tokens.insert(token.into()) {
                return Err(error("repeated continuation token"));
            }
            return Ok(PageResult::Continue(token.into()));
        }
        let list = self.listing.take().ok_or_else(|| error("list missing"))?;
        let snapshot = self.table.snapshot();
        let writes = snapshot
            .len()
            .checked_add(list.rows.len())
            .ok_or_else(|| error("revision budget overflow"))?;
        revision_budget(&snapshot, writes)?;
        // No indexes and no outside writer: preflight excludes the sole table
        // error (revision exhaustion), so batch cannot commit a partial prefix.
        self.table
            .batch(|writer| {
                writer.delete_all()?;
                for row in list.rows.into_values() {
                    writer.insert(row)?;
                }
                Ok::<_, flowsdn_table::TableError>(())
            })
            .await
            .map_err(|e| Error(e.to_string()))?;
        self.resource_version = list.resource_version;
        self.needs_relist = false;
        self.initialized = true;
        Ok(PageResult::Complete)
    }
    pub async fn event(&mut self, event: &Value) -> Result<(), Error> {
        let result = self.apply_event(event).await;
        if result.is_err() {
            self.failed();
        }
        result
    }
    async fn apply_event(&mut self, event: &Value) -> Result<(), Error> {
        if self.needs_relist || self.listing.is_some() {
            return Err(error("watch requires completed list"));
        }
        if encoded_size(event)? > self.limits.max_bytes {
            return Err(error("watch event exceeds byte limit"));
        }
        let kind = required(event, "type")?;
        let object = event
            .get("object")
            .ok_or_else(|| error("missing event object"))?;
        if kind == "BOOKMARK" {
            self.resource_version = Some(
                required(
                    object
                        .get("metadata")
                        .ok_or_else(|| error("missing bookmark metadata"))?,
                    "resourceVersion",
                )?
                .into(),
            );
            return Ok(());
        }
        if !matches!(kind, "ADDED" | "MODIFIED" | "DELETED") {
            return Err(error("watch error or unsupported event; relist required"));
        }
        // Deleted objects need only metadata; deletion must not depend on spec
        // fields that may be absent from tombstones.
        if kind == "DELETED"
            && let Scope::LocalPods { node_name } = &self.scope
            && let Some(actual) = object.pointer("/spec/nodeName")
            && text(actual)? != node_name
        {
            return Err(error("Pod does not match local node selector"));
        }
        let row = if kind == "DELETED" {
            None
        } else {
            Some(self.scope.parse(object)?)
        };
        let meta = metadata(object, self.scope.namespaced())?;
        let key = format!("{}/{}", meta.namespace, meta.name).into_bytes();
        let snapshot = self.table.snapshot();
        let previous = snapshot
            .get("primary", &key)
            .map_err(|e| Error(e.to_string()))?;
        if let Some(row) = row {
            revision_budget(&snapshot, 1)?;
            if previous.is_none() && snapshot.len() >= self.limits.max_objects {
                return Err(error("watch exceeds object limit"));
            }
            self.table
                .insert(row)
                .await
                .map_err(|e| Error(e.to_string()))?;
        } else if previous.is_some_and(|(row, _)| row.metadata().uid == meta.uid) {
            revision_budget(&snapshot, 1)?;
            self.table
                .delete(&key)
                .await
                .map_err(|e| Error(e.to_string()))?;
        }
        self.resource_version = Some(meta.resource_version);
        Ok(())
    }
}
fn encoded_size(value: &Value) -> Result<usize, Error> {
    serde_json::to_vec(value)
        .map(|v| v.len())
        .map_err(|e| Error(e.to_string()))
}
fn revision_budget(snapshot: &Snapshot<Resource>, count: usize) -> Result<(), Error> {
    let count = u64::try_from(count).map_err(|_| error("revision budget overflow"))?;
    snapshot
        .revision()
        .checked_add(count)
        .ok_or_else(|| error("table revision exhausted"))?;
    Ok(())
}
