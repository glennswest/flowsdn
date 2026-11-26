//! The ClusterMesh apiserver's export converters (spec 20 §3.8.2, §4.1–4.6,
//! §5.1, with the `flowsdn/` names of ADR-0023): pure functions from
//! flowsdn's own kinds and core Kubernetes objects, given as whole JSON
//! objects, to the kvstore key names and value bytes a `SyncStore` writes.
//! No Kubernetes client, no kvstore client and no synchronizer loop live
//! here.
//!
//! Same input gives the same bytes: every map is built from a sorted map
//! (`serde_json::Map` is a `BTreeMap` without `preserve_order`; inputs whose
//! order could vary are sorted before they are copied). Peers parse the JSON,
//! so the reference's Go field order does not matter; byte stability does,
//! because a `SyncStore` skips a rewrite only when the bytes are identical.
use crate::{Error, prefixes::validate_cluster};
use flowsdn_identity::labels::{Label, Labels};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Node records: `<cluster>/<node>` (§4.3).
pub const NODES: &str = "flowsdn/state/nodes/v1";
/// The identities prefix readers register; data lives under [`IDENTITIES_ID`].
pub const IDENTITIES: &str = "flowsdn/state/identities/v1";
/// Identity master keys: `<decimal id>` -> canonical label string (§4.5).
pub const IDENTITIES_ID: &str = "flowsdn/state/identities/v1/id";
/// The ipcache prefix readers register; data lives under [`IP_DEFAULT`].
pub const IP: &str = "flowsdn/state/ip/v1";
/// ipcache entries: `<ip>` -> `IPIdentityPair` JSON (§4.4).
pub const IP_DEFAULT: &str = "flowsdn/state/ip/v1/default";
/// Global services: `<cluster>/<namespace>/<name>` (§4.6).
pub const SERVICES: &str = "flowsdn/state/services/v1";
/// Synced canaries: `flowsdn/synced/<cluster>/<prefix>`.
pub const SYNCED: &str = "flowsdn/synced";
/// Cluster configs: `flowsdn/cluster-config/<cluster>` (§4.2).
pub const CLUSTER_CONFIG: &str = "flowsdn/cluster-config";

/// Service annotation: `"true"` (any case) exports the Service.
pub const GLOBAL_SERVICE: &str = "service.flowsdn.io/global";
/// Service annotation: whether a global Service shares this cluster's backends.
pub const SHARED_SERVICE: &str = "service.flowsdn.io/shared";
/// Namespace annotation: `"true"`/`"false"` overrides the default.
pub const GLOBAL_NAMESPACE: &str = "clustermesh.flowsdn.io/global";
/// `clustermesh-default-global-namespace`'s default.
pub const DEFAULT_GLOBAL_NAMESPACE: bool = true;
/// The node record's `Source` for a record built from a FlowsdnNode.
pub const SOURCE_CUSTOM_RESOURCE: &str = "custom-resource";

/// §5.1: join with `/`, collapse every `//`, trim a trailing `/`. `.` and
/// `..` are ordinary key bytes and are kept.
pub fn join(elements: &[&str]) -> String {
    let mut key = elements.join("/");
    while key.contains("//") {
        key = key.replace("//", "/");
    }
    if key.ends_with('/') {
        key.pop();
    }
    key
}

/// The synced canary of a prefix. The identities and ipcache canaries name
/// the prefix readers register ([`IDENTITIES`], [`IP`]), not the `/id` and
/// `/default` sub-prefixes the data is written under (§3.8.2).
pub fn canary(cluster: &str, prefix: &str) -> String {
    let registered = match prefix {
        IDENTITIES_ID => IDENTITIES,
        IP_DEFAULT => IP,
        other => other,
    };
    join(&[SYNCED, cluster, registered])
}

/// `flowsdn/cluster-config/<cluster>`.
pub fn cluster_config_key(cluster: &str) -> String {
    join(&[CLUSTER_CONFIG, cluster])
}

/// A non-empty string at a JSON pointer.
fn text<'a>(object: &'a Value, pointer: &str) -> Option<&'a str> {
    object
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

/// The string-valued entries of an object (others are ignored), sorted.
fn string_map(object: Option<&Value>) -> BTreeMap<String, String> {
    object
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
        .collect()
}

fn map_value(map: BTreeMap<String, String>) -> Map<String, Value> {
    map.into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect()
}

/// A Go nil map marshals as `null`; an absent or empty map is written so.
fn go_map(map: BTreeMap<String, String>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map_value(map))
    }
}

fn ip(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}

/// A Go `net.IP` marshals as its text, and a nil one as `""`.
fn ip_text(object: &Value, pointer: &str) -> String {
    text(object, pointer)
        .and_then(ip)
        .map_or_else(String::new, |ip| ip.to_string())
}

/// A CIDR in canonical text, the address masked to the network as Go's
/// `net.ParseCIDR` does. Malformed text is `None`.
fn cidr(text: &str) -> Option<String> {
    let (address, length) = text.split_once('/')?;
    if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: u8 = length.parse().ok()?;
    match ip(address)? {
        IpAddr::V4(address) => {
            if length > 32 {
                return None;
            }
            let mask = u32::MAX
                .checked_shl(u32::from(32u8.saturating_sub(length)))
                .unwrap_or(0);
            let network = Ipv4Addr::from(u32::from(address) & mask);
            Some(format!("{network}/{length}"))
        }
        IpAddr::V6(address) => {
            if length > 128 {
                return None;
            }
            let mask = u128::MAX
                .checked_shl(u32::from(128u8.saturating_sub(length)))
                .unwrap_or(0);
            let network = Ipv6Addr::from(u128::from(address) & mask);
            Some(format!("{network}/{length}"))
        }
    }
}

/// An IPsec key index (`u8`); absent or out of range is 0.
fn key_index(object: &Value, pointer: &str) -> u8 {
    object
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|key| u8::try_from(key).ok())
        .unwrap_or(0)
}

/// A port number in 1..=65535.
fn port(object: &Value) -> Option<u64> {
    object
        .get("port")
        .and_then(Value::as_u64)
        .filter(|port| (1..=65535).contains(port))
}

/// The node record (§4.3) of a FlowsdnNode, keyed `<cluster>/<node>`
/// relative to [`NODES`].
///
/// The reference type has no JSON tags, so Go's `encoding/json` writes
/// every field: strings as `""` when empty, nil slices and maps as `null`,
/// numbers as 0, a nil `net.IP` as `""`. This writes the same. CIDRs are
/// written as their canonical text (`10.21.0.0/16`), flowsdn's encoding.
///
/// Field sources: `IPAddresses` from `spec.addresses` (unparsable IPs are
/// skipped, as the reference does; the CRD's `FlowsdnInternalIP` type is
/// written as the frozen value `CiliumInternalIP`, other types as given);
/// the alloc CIDRs from `spec.ipam.podCIDRs` (first of each family primary,
/// the rest secondary); health and ingress IPs from `spec.health` and
/// `spec.ingress`; `EncryptionKey` from `spec.encryption.key`; `Labels` and
/// `Annotations` from metadata; `BootID` from `spec.bootid`.
/// `WireguardPubKey` is `""`: flowsdn's nodes publish no WireGuard key.
/// `Cluster` and `ClusterID` are this cluster's; `Source` is
/// `custom-resource`.
///
/// `Ok(None)` when the object has no name (nothing to key). `Err` for an
/// invalid cluster name, a non-object or a name containing `/`.
pub fn node_record(
    object: &Value,
    cluster: &str,
    cluster_id: u32,
) -> Result<Option<(String, Vec<u8>)>, Error> {
    validate_cluster(cluster)?;
    if !object.is_object() {
        return Err(Error("node must be a JSON object".into()));
    }
    let Some(name) = text(object, "/metadata/name") else {
        return Ok(None);
    };
    if name.contains('/') {
        return Err(Error("node name must not contain '/'".into()));
    }
    let addresses: Vec<Value> = object
        .pointer("/spec/addresses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|address| {
            let ip = address.get("ip").and_then(Value::as_str).and_then(ip)?;
            let kind = match address.get("type").and_then(Value::as_str).unwrap_or("") {
                "FlowsdnInternalIP" => "CiliumInternalIP",
                other => other,
            };
            Some(json!({"Type": kind, "IP": ip.to_string()}))
        })
        .collect();
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for cidr in object
        .pointer("/spec/ipam/podCIDRs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(cidr)
    {
        if cidr.contains(':') {
            v6.push(cidr);
        } else {
            v4.push(cidr);
        }
    }
    let primary = |list: &[String]| list.first().map_or(Value::Null, |c| json!(c));
    let secondary = |list: &[String]| {
        if list.len() > 1 {
            Value::Array(list.iter().skip(1).map(|c| json!(c)).collect())
        } else {
            Value::Null
        }
    };
    let addresses = if addresses.is_empty() {
        Value::Null
    } else {
        Value::Array(addresses)
    };
    let record = json!({
        "Name": name,
        "Cluster": cluster,
        "IPAddresses": addresses,
        "IPv4AllocCIDR": primary(v4.as_slice()),
        "IPv4SecondaryAllocCIDRs": secondary(v4.as_slice()),
        "IPv6AllocCIDR": primary(v6.as_slice()),
        "IPv6SecondaryAllocCIDRs": secondary(v6.as_slice()),
        "IPv4HealthIP": ip_text(object, "/spec/health/ipv4"),
        "IPv6HealthIP": ip_text(object, "/spec/health/ipv6"),
        "IPv4IngressIP": ip_text(object, "/spec/ingress/ipv4"),
        "IPv6IngressIP": ip_text(object, "/spec/ingress/ipv6"),
        "ClusterID": cluster_id,
        "Source": SOURCE_CUSTOM_RESOURCE,
        "EncryptionKey": key_index(object, "/spec/encryption/key"),
        "Labels": go_map(string_map(object.pointer("/metadata/labels"))),
        "Annotations": go_map(string_map(object.pointer("/metadata/annotations"))),
        "WireguardPubKey": "",
        "BootID": text(object, "/spec/bootid").unwrap_or(""),
    });
    let bytes = serde_json::to_vec(&record).map_err(|error| Error(error.to_string()))?;
    Ok(Some((format!("{cluster}/{name}"), bytes)))
}

/// The identity master key (§4.5): key name `id/<n>` relative to
/// [`IDENTITIES`], value the bare canonical label string (not JSON).
/// `security_labels` maps `source:key` to the value; a key without `:` has
/// source `unspec`. Labels are sorted by key and rendered by
/// [`Labels::canonical_key`] (`<source>:<key>=<value>;` each). `None` (skip:
/// neither write nor delete) when no label remains or `id_name` is not a
/// canonical nonzero decimal `u32`.
pub fn identity_value(
    id_name: &str,
    security_labels: &BTreeMap<String, String>,
) -> Option<(String, Vec<u8>)> {
    let id: u32 = id_name.parse().ok()?;
    if id == 0 || id.to_string() != id_name {
        return None;
    }
    let labels: Labels = security_labels
        .iter()
        .filter_map(|(key, value)| {
            let (source, key) = key.split_once(':').unwrap_or(("unspec", key.as_str()));
            Label::new(source, key, value).ok()
        })
        .collect();
    if labels.is_empty() {
        return None;
    }
    Some((format!("id/{id}"), labels.canonical_key().into_bytes()))
}

/// [`identity_value`] of a whole FlowsdnIdentity (`metadata.name`,
/// `security-labels`).
pub fn identity_record(object: &Value) -> Option<(String, Vec<u8>)> {
    let name = text(object, "/metadata/name")?;
    identity_value(name, &string_map(object.get("security-labels")))
}

/// The namespace of a FlowsdnIdentity's security labels
/// (`k8s:io.kubernetes.pod.namespace`), for the global-namespace check.
pub fn identity_namespace(security_labels: &BTreeMap<String, String>) -> Option<&str> {
    security_labels
        .get("k8s:io.kubernetes.pod.namespace")
        .map(String::as_str)
}

/// The `IPIdentityPair`s (§4.4) of a FlowsdnEndpoint, one per IPv4/IPv6
/// address of `status.networking.addressing`, key names `default/<ip>`
/// relative to [`IP`], sorted by key and deduplicated.
///
/// `ID` is `status.identity.id`; `HostIP` is `status.networking.node` (the
/// node IP flowsdn's agent writes there), `""` when absent; `Key` is
/// `status.encryption.key`, 0 when absent; `Mask` is null and `Metadata`
/// `""`. `K8sNamespace`/`K8sPodName` are the object's namespace and name,
/// `K8sServiceAccount` is `status.service-account`, `NamedPorts` is
/// `status.named-ports` (protocol defaults to TCP); each is omitted when
/// empty. Empty when the endpoint has no nonzero identity.
pub fn ip_pairs(object: &Value) -> Vec<(String, Vec<u8>)> {
    let Some(status) = object.get("status") else {
        return Vec::new();
    };
    let Some(id) = status
        .pointer("/identity/id")
        .and_then(Value::as_u64)
        .and_then(|id| u32::try_from(id).ok())
        .filter(|id| *id != 0)
    else {
        return Vec::new();
    };
    let mut base = Map::new();
    base.insert("Mask".into(), Value::Null);
    let host = ip_text(status, "/networking/node");
    base.insert("HostIP".into(), json!(host));
    base.insert("ID".into(), json!(id));
    base.insert("Key".into(), json!(key_index(status, "/encryption/key")));
    base.insert("Metadata".into(), json!(""));
    for (field, value) in [
        ("K8sNamespace", text(object, "/metadata/namespace")),
        ("K8sPodName", text(object, "/metadata/name")),
        ("K8sServiceAccount", text(status, "/service-account")),
    ] {
        if let Some(value) = value {
            base.insert(field.into(), json!(value));
        }
    }
    let named_ports: Vec<Value> = status
        .get("named-ports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|named| {
            let number = port(named)?;
            let name = named.get("name").and_then(Value::as_str).unwrap_or("");
            let protocol = named
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("TCP");
            Some(json!({"Name": name, "Port": number, "Protocol": protocol}))
        })
        .collect();
    if !named_ports.is_empty() {
        base.insert("NamedPorts".into(), Value::Array(named_ports));
    }
    let addresses: BTreeSet<String> = status
        .pointer("/networking/addressing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|pair| ["ipv4", "ipv6"].map(|family| pair.get(family)))
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(ip)
        .map(|ip| ip.to_string())
        .collect();
    addresses
        .into_iter()
        .filter_map(|address| {
            let mut pair = base.clone();
            pair.insert("IP".into(), json!(address));
            let bytes = serde_json::to_vec(&Value::Object(pair)).ok()?;
            Some((format!("default/{address}"), bytes))
        })
        .collect()
}

/// One kvstore write from [`IpOwners`]: the key name as given to it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Write {
    Put(String, Vec<u8>),
    Delete(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Owners {
    primary: (String, Vec<u8>),
    pending: VecDeque<(String, Vec<u8>)>,
}

/// IP ownership arbitration (§3.8.2): each IP key has one primary owner,
/// whose value is the one written, and a FIFO of pending owners. When the
/// primary releases, the next pending owner's value is written; the key is
/// deleted only when the last owner releases. A pending owner's updates are
/// remembered but write nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IpOwners {
    keys: BTreeMap<String, Owners>,
}

impl IpOwners {
    pub fn new() -> Self {
        Self::default()
    }

    /// `owner` (e.g. `<namespace>/<name>` of the object) claims `ip` with
    /// `value`. A primary rewriting identical bytes writes nothing.
    pub fn upsert(&mut self, ip: &str, owner: &str, value: Vec<u8>) -> Option<Write> {
        let Some(owners) = self.keys.get_mut(ip) else {
            self.keys.insert(
                ip.to_owned(),
                Owners {
                    primary: (owner.to_owned(), value.clone()),
                    pending: VecDeque::new(),
                },
            );
            return Some(Write::Put(ip.to_owned(), value));
        };
        if owners.primary.0 == owner {
            if owners.primary.1 == value {
                return None;
            }
            owners.primary.1.clone_from(&value);
            return Some(Write::Put(ip.to_owned(), value));
        }
        if let Some(pending) = owners.pending.iter_mut().find(|(id, _)| id == owner) {
            pending.1 = value;
        } else {
            owners.pending.push_back((owner.to_owned(), value));
        }
        None
    }

    /// `owner` releases `ip`. Unknown owners and IPs write nothing.
    pub fn remove(&mut self, ip: &str, owner: &str) -> Option<Write> {
        let owners = self.keys.get_mut(ip)?;
        if owners.primary.0 != owner {
            owners.pending.retain(|(id, _)| id != owner);
            return None;
        }
        if let Some(next) = owners.pending.pop_front() {
            let write = Write::Put(ip.to_owned(), next.1.clone());
            owners.primary = next;
            return Some(write);
        }
        self.keys.remove(ip);
        Some(Write::Delete(ip.to_owned()))
    }

    /// The value currently written for `ip` and its owner.
    pub fn primary(&self, ip: &str) -> Option<(&str, &[u8])> {
        self.keys
            .get(ip)
            .map(|owners| (owners.primary.0.as_str(), owners.primary.1.as_slice()))
    }

    /// How many IPs have an owner.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Whether a Service carries `service.flowsdn.io/global: "true"` (any case).
pub fn service_global(service: &Value) -> bool {
    service_annotation(service, GLOBAL_SERVICE)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

/// Whether a global Service shares this cluster's backends: absent means
/// shared; present, it must be `"true"` (any case), as in the reference.
pub fn service_shared(service: &Value) -> bool {
    let shared = service_annotation(service, SHARED_SERVICE);
    service_global(service) && shared.is_none_or(|value| value.eq_ignore_ascii_case("true"))
}

fn service_annotation<'a>(service: &'a Value, name: &str) -> Option<&'a str> {
    service
        .pointer("/metadata/annotations")
        .and_then(|annotations| annotations.get(name))
        .and_then(Value::as_str)
}

/// A port map keyed by port name (`""` when unnamed) with the capitalised
/// nested `{Protocol, Port}`; entries without a valid port are skipped.
fn port_map(ports: Option<&Value>) -> Map<String, Value> {
    ports
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let protocol = entry
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("TCP");
            let number = port(entry)?;
            Some((
                name.to_owned(),
                json!({"Protocol": protocol, "Port": number}),
            ))
        })
        .collect()
}

/// The `ClusterService` (§4.6) of a Service (`v1`) and its
/// `discovery.k8s.io/v1` EndpointSlices, key `<cluster>/<ns>/<name>`
/// relative to [`SERVICES`]. `None` means delete: the Service is not global,
/// not shared, has no name or namespace, or `cluster` is invalid.
///
/// Frontends are `spec.clusterIPs` (or `spec.clusterIP`) that parse as IPs
/// (headless `None` gives none), each with the Service's ports. Backends are
/// the addresses of IPv4/IPv6 slices labelled
/// `kubernetes.io/service-name: <name>` in the same namespace (others are
/// ignored), from endpoints that are ready or serving (`ready` absent means
/// ready, `serving` absent means as ready), each with the slice's ports;
/// one address in several slices merges their ports. `hostnames` is
/// `endpoint.hostname`, `zones` is `endpoint.zone` with
/// `hints.forZones`; both are omitted when empty. `labels` and `selector` are
/// the Service's (`{}` when absent).
pub fn cluster_service(
    service: &Value,
    slices: &[&Value],
    cluster: &str,
    cluster_id: u32,
) -> Option<(String, Vec<u8>)> {
    validate_cluster(cluster).ok()?;
    let namespace = text(service, "/metadata/namespace")?;
    let name = text(service, "/metadata/name")?;
    if !service_shared(service) {
        return None;
    }
    let ports = port_map(service.pointer("/spec/ports"));
    let mut cluster_ips: Vec<&str> = service
        .pointer("/spec/clusterIPs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if cluster_ips.is_empty() {
        cluster_ips.extend(text(service, "/spec/clusterIP"));
    }
    let frontends: Map<String, Value> = cluster_ips
        .into_iter()
        .filter_map(ip)
        .map(|ip| (ip.to_string(), Value::Object(ports.clone())))
        .collect();
    let (mut backends, mut hostnames, mut zones) = (Map::new(), Map::new(), Map::new());
    for slice in slices {
        if text(slice, "/metadata/namespace") != Some(namespace)
            || slice
                .pointer("/metadata/labels")
                .and_then(|labels| labels.get("kubernetes.io/service-name"))
                .and_then(Value::as_str)
                != Some(name)
            || !matches!(
                slice.get("addressType").and_then(Value::as_str),
                Some("IPv4" | "IPv6")
            )
        {
            continue;
        }
        let slice_ports = port_map(slice.get("ports"));
        for endpoint in slice
            .get("endpoints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let condition = |name: &str| {
                endpoint
                    .pointer("/conditions")
                    .and_then(|c| c.get(name))
                    .and_then(Value::as_bool)
            };
            let ready = condition("ready").unwrap_or(true);
            let serving = condition("serving").unwrap_or(ready);
            if !ready && !serving {
                continue;
            }
            let hostname = text(endpoint, "/hostname");
            let zone = text(endpoint, "/zone").map(|zone| {
                let mut entry = Map::new();
                entry.insert("zone".into(), json!(zone));
                let for_zones: Vec<Value> = endpoint
                    .pointer("/hints/forZones")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|hint| text(hint, "/name"))
                    .map(|name| json!({"name": name}))
                    .collect();
                if !for_zones.is_empty() {
                    entry.insert("forZones".into(), Value::Array(for_zones));
                }
                Value::Object(entry)
            });
            for address in endpoint
                .get("addresses")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter_map(ip)
            {
                let key = address.to_string();
                if let Some(entry) = backends
                    .entry(key.clone())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                {
                    for (port_name, port) in &slice_ports {
                        entry.insert(port_name.clone(), port.clone());
                    }
                }
                if let Some(hostname) = hostname {
                    hostnames.insert(key.clone(), json!(hostname));
                }
                if let Some(zone) = &zone {
                    zones.insert(key, zone.clone());
                }
            }
        }
    }
    let mut record = Map::new();
    record.insert("cluster".into(), json!(cluster));
    record.insert("namespace".into(), json!(namespace));
    record.insert("name".into(), json!(name));
    record.insert("frontends".into(), Value::Object(frontends));
    record.insert("backends".into(), Value::Object(backends));
    if !hostnames.is_empty() {
        record.insert("hostnames".into(), Value::Object(hostnames));
    }
    if !zones.is_empty() {
        record.insert("zones".into(), Value::Object(zones));
    }
    record.insert(
        "labels".into(),
        Value::Object(map_value(string_map(service.pointer("/metadata/labels")))),
    );
    record.insert(
        "selector".into(),
        Value::Object(map_value(string_map(service.pointer("/spec/selector")))),
    );
    record.insert("includeExternal".into(), json!(true));
    record.insert("shared".into(), json!(true));
    record.insert("clusterID".into(), json!(cluster_id));
    let bytes = serde_json::to_vec(&Value::Object(record)).ok()?;
    Some((format!("{cluster}/{namespace}/{name}"), bytes))
}

/// The cluster config (§4.2) this apiserver publishes, the `desired` input
/// of [`crate::ownership::plan_claim`] (which adds `flowsdnInstanceUUID`).
/// Every field is omitted when empty, as the reference's `omitempty` does:
/// `endpointSlicesExportMode` `""` (services only: endpoint slices are not
/// exported yet) and `cached: false` are therefore absent, and so is
/// `serviceExportsEnabled` (this apiserver does not know the concept).
pub fn cluster_config(id: u32, max_connected_clusters: u32) -> Value {
    let mut capabilities = Map::new();
    capabilities.insert("syncedCanaries".into(), json!(true));
    if max_connected_clusters != 0 {
        capabilities.insert("maxConnectedClusters".into(), json!(max_connected_clusters));
    }
    let mut config = Map::new();
    if id != 0 {
        config.insert("id".into(), json!(id));
    }
    config.insert("capabilities".into(), Value::Object(capabilities));
    Value::Object(config)
}

/// Whether a namespace is global (§3.8.2): its `clustermesh.flowsdn.io/global`
/// annotation, `"true"` or `"false"` (any case), overrides `default_global`
/// (`clustermesh-default-global-namespace`, [`DEFAULT_GLOBAL_NAMESPACE`]);
/// an unknown namespace or any other value takes the default.
pub fn namespace_global(namespace: Option<&Value>, default_global: bool) -> bool {
    match namespace
        .and_then(|namespace| namespace.pointer("/metadata/annotations"))
        .and_then(|annotations| annotations.get(GLOBAL_NAMESPACE))
        .and_then(Value::as_str)
    {
        Some(value) if value.eq_ignore_ascii_case("true") => true,
        Some(value) if value.eq_ignore_ascii_case("false") => false,
        _ => default_global,
    }
}
