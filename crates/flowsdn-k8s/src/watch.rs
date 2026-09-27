//! Transport-independent built-in resource ListWatch state (spec 13 §5.2).
//!
//! The caller owns HTTP authentication, selectors, retry/backoff and watch
//! framing. Pass each decoded list page/event here, and call `failed` for every
//! transport error. Only a complete list publishes a replacement snapshot.
use crate::Error;
use flowsdn_table::{Key, Keyed, Snapshot, Table};
use serde_json::Value;
use std::{collections::{BTreeMap, BTreeSet}, net::IpAddr};

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
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resource { Node(Node), Pod(Pod) }
impl Resource {
    pub fn metadata(&self) -> &Metadata {
        match self { Self::Node(n) => &n.metadata, Self::Pod(p) => &p.metadata }
    }
}
impl Keyed for Resource {
    fn primary_key(&self) -> Key {
        let m = self.metadata();
        format!("{}/{}", m.namespace, m.name).into_bytes()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope { Nodes, LocalPods { node_name: String } }
impl Scope {
    pub fn field_selector(&self) -> Option<String> {
        match self { Self::Nodes => None, Self::LocalPods { node_name } => Some(format!("spec.nodeName={node_name}")) }
    }
    pub fn parse(&self, value: &Value) -> Result<Resource, Error> {
        let namespaced = matches!(self, Self::LocalPods { .. });
        if let Some(kind) = value.get("kind") {
            let expected = if namespaced { "Pod" } else { "Node" };
            if text(kind)? != expected { return Err(error("unexpected resource kind")); }
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
                    if !cidr.is_empty() { cidrs.push(parse_cidr(cidr)?); }
                }
                let mut ips = Vec::new();
                for address in array(value.pointer("/status/addresses"))? {
                    if required(address, "type")? == "InternalIP" {
                        ips.push(parse_ip(required(address, "address")?)?);
                    }
                }
                Ok(Resource::Node(Node { metadata, pod_cidrs: cidrs, internal_ips: ips }))
            }
            Self::LocalPods { node_name } => {
                let actual = required(value.get("spec").ok_or_else(|| error("missing Pod spec"))?, "nodeName")?;
                if actual != node_name { return Err(error("Pod does not match local node selector")); }
                let host_network = match value.pointer("/spec/hostNetwork") {
                    None | Some(Value::Null) => false,
                    Some(v) => v.as_bool().ok_or_else(|| error("invalid hostNetwork"))?,
                };
                let mut ips = Vec::new();
                for address in array(value.pointer("/status/podIPs"))? { ips.push(parse_ip(required(address, "ip")?)?); }
                if ips.is_empty()
                    && let Some(ip) = value.pointer("/status/podIP").filter(|v| !v.is_null())
                {
                    let ip = text(ip)?;
                    if !ip.is_empty() { ips.push(parse_ip(ip)?); }
                }
                let mut labels = BTreeMap::new();
                if let Some(raw) = value.pointer("/metadata/labels").filter(|v| !v.is_null()) {
                    for (key, val) in raw.as_object().ok_or_else(|| error("invalid labels"))? {
                        labels.insert(key.clone(), text(val)?.to_owned());
                    }
                }
                Ok(Resource::Pod(Pod { metadata, node_name: actual.into(), host_network, pod_ips: ips, labels }))
            }
        }
    }
}

fn error(message: &str) -> Error { Error(message.into()) }
fn text(value: &Value) -> Result<&str, Error> { value.as_str().ok_or_else(|| error("expected string")) }
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or_else(|| Error(format!("missing or invalid {key}")))
}
fn array(value: Option<&Value>) -> Result<&[Value], Error> {
    match value { None | Some(Value::Null) => Ok(&[]), Some(v) => v.as_array().map(Vec::as_slice).ok_or_else(|| error("expected array")) }
}
fn metadata(value: &Value, namespaced: bool) -> Result<Metadata, Error> {
    let meta = value.get("metadata").ok_or_else(|| error("missing metadata"))?;
    let name = required(meta, "name")?;
    let namespace = if namespaced { required(meta, "namespace")? } else { "" };
    // Keys must be unambiguous even when fed malformed server data.
    if name.contains('/') || namespace.contains('/') { return Err(error("invalid object name")); }
    Ok(Metadata { name: name.into(), namespace: namespace.into(), uid: required(meta, "uid")?.into(), resource_version: required(meta, "resourceVersion")?.into() })
}
fn parse_ip(value: &str) -> Result<IpAddr, Error> { value.parse().map_err(|_| error("invalid IP address")) }
fn parse_cidr(value: &str) -> Result<(IpAddr, u8), Error> {
    let (ip, prefix) = value.split_once('/').ok_or_else(|| error("invalid PodCIDR"))?;
    let ip = parse_ip(ip)?;
    let prefix: u8 = prefix.parse().map_err(|_| error("invalid PodCIDR prefix"))?;
    if prefix > if ip.is_ipv4() { 32 } else { 128 } { return Err(error("invalid PodCIDR prefix")); }
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
    fn default() -> Self { Self { max_objects: 100_000, max_pages: 10_000, max_bytes: 64 * 1024 * 1024 } }
}
struct Listing {
    rows: BTreeMap<Key, Resource>,
    resource_version: Option<String>,
    tokens: BTreeSet<String>,
    pages: usize,
    bytes: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageResult { Continue(String), Complete }

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
        if limits.max_objects == 0 || limits.max_pages == 0 || limits.max_bytes == 0 { return Err(error("watch limits must be positive")); }
        if let Scope::LocalPods { node_name } = &scope {
            if node_name.is_empty() || node_name.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.') { return Err(error("invalid local node name")); }
        }
        Ok(Self { scope, limits, table: Table::new(vec![]).map_err(|e| Error(e.to_string()))?, listing: None, resource_version: None, needs_relist: true, initialized: false })
    }
    pub fn snapshot(&self) -> Snapshot<Resource> { self.table.snapshot() }
    pub fn needs_relist(&self) -> bool { self.needs_relist }
    pub fn initialized(&self) -> bool { self.initialized }
    pub fn resource_version(&self) -> Option<&str> { self.resource_version.as_deref() }
    /// Discard staging only. Forwarding consumers retain the last good table.
    pub fn failed(&mut self) { self.listing = None; self.needs_relist = true; }
    pub fn begin_list(&mut self) {
        self.failed();
        self.listing = Some(Listing { rows: BTreeMap::new(), resource_version: None, tokens: BTreeSet::new(), pages: 0, bytes: 0 });
    }
    pub async fn list_page(&mut self, page: &Value) -> Result<PageResult, Error> {
        let result = self.stage_page(page).await;
        if result.is_err() { self.failed(); }
        result
    }
    async fn stage_page(&mut self, page: &Value) -> Result<PageResult, Error> {
        let list = self.listing.as_mut().ok_or_else(|| error("list has not begun"))?;
        list.pages = list.pages.checked_add(1).ok_or_else(|| error("page count overflow"))?;
        list.bytes = list.bytes.checked_add(encoded_size(page)?).ok_or_else(|| error("list byte count overflow"))?;
        if list.pages > self.limits.max_pages || list.bytes > self.limits.max_bytes { return Err(error("list exceeds limits")); }
        let meta = page.get("metadata").ok_or_else(|| error("missing list metadata"))?;
        let rv = required(meta, "resourceVersion")?;
        if list.resource_version.as_deref().is_some_and(|old| old != rv) { return Err(error("list resourceVersion changed between pages")); }
        list.resource_version = Some(rv.into());
        let items = page.get("items").and_then(Value::as_array).ok_or_else(|| error("missing list items"))?;
        if list.rows.len().checked_add(items.len()).is_none_or(|n| n > self.limits.max_objects) { return Err(error("list exceeds object limit")); }
        for item in items {
            let row = self.scope.parse(item)?;
            if list.rows.insert(row.primary_key(), row).is_some() { return Err(error("duplicate list object")); }
        }
        let token = match meta.get("continue") { None => "", Some(v) => text(v)? };
        if !token.is_empty() {
            if !list.tokens.insert(token.into()) { return Err(error("repeated continuation token")); }
            return Ok(PageResult::Continue(token.into()));
        }
        let list = self.listing.take().ok_or_else(|| error("list missing"))?;
        let snapshot = self.table.snapshot();
        let writes = snapshot.len().checked_add(list.rows.len()).ok_or_else(|| error("revision budget overflow"))?;
        revision_budget(&snapshot, writes)?;
        // No indexes and no outside writer: preflight excludes the sole table
        // error (revision exhaustion), so batch cannot commit a partial prefix.
        self.table.batch(|writer| {
            writer.delete_all()?;
            for row in list.rows.into_values() { writer.insert(row)?; }
            Ok::<_, flowsdn_table::TableError>(())
        }).await.map_err(|e| Error(e.to_string()))?;
        self.resource_version = list.resource_version;
        self.needs_relist = false;
        self.initialized = true;
        Ok(PageResult::Complete)
    }
    pub async fn event(&mut self, event: &Value) -> Result<(), Error> {
        let result = self.apply_event(event).await;
        if result.is_err() { self.failed(); }
        result
    }
    async fn apply_event(&mut self, event: &Value) -> Result<(), Error> {
        if self.needs_relist || self.listing.is_some() { return Err(error("watch requires completed list")); }
        if encoded_size(event)? > self.limits.max_bytes { return Err(error("watch event exceeds byte limit")); }
        let kind = required(event, "type")?;
        let object = event.get("object").ok_or_else(|| error("missing event object"))?;
        if kind == "BOOKMARK" {
            self.resource_version = Some(required(object.get("metadata").ok_or_else(|| error("missing bookmark metadata"))?, "resourceVersion")?.into());
            return Ok(());
        }
        if !matches!(kind, "ADDED" | "MODIFIED" | "DELETED") { return Err(error("watch error or unsupported event; relist required")); }
        // Deleted objects need only metadata; deletion must not depend on spec
        // fields that may be absent from tombstones.
        if kind == "DELETED"
            && let Scope::LocalPods { node_name } = &self.scope
            && let Some(actual) = object.pointer("/spec/nodeName")
            && text(actual)? != node_name
        {
            return Err(error("Pod does not match local node selector"));
        }
        let row = if kind == "DELETED" { None } else { Some(self.scope.parse(object)?) };
        let meta = metadata(object, matches!(self.scope, Scope::LocalPods { .. }))?;
        let key = format!("{}/{}", meta.namespace, meta.name).into_bytes();
        let snapshot = self.table.snapshot();
        let previous = snapshot.get("primary", &key).map_err(|e| Error(e.to_string()))?;
        if let Some(row) = row {
            revision_budget(&snapshot, 1)?;
            if previous.is_none() && snapshot.len() >= self.limits.max_objects { return Err(error("watch exceeds object limit")); }
            self.table.insert(row).await.map_err(|e| Error(e.to_string()))?;
        } else if previous.is_some_and(|(row, _)| row.metadata().uid == meta.uid) {
            revision_budget(&snapshot, 1)?;
            self.table.delete(&key).await.map_err(|e| Error(e.to_string()))?;
        }
        self.resource_version = Some(meta.resource_version);
        Ok(())
    }
}
fn encoded_size(value: &Value) -> Result<usize, Error> {
    serde_json::to_vec(value).map(|v| v.len()).map_err(|e| Error(e.to_string()))
}
fn revision_budget(snapshot: &Snapshot<Resource>, count: usize) -> Result<(), Error> {
    let count = u64::try_from(count).map_err(|_| error("revision budget overflow"))?;
    snapshot.revision().checked_add(count).ok_or_else(|| error("table revision exhausted"))?;
    Ok(())
}
