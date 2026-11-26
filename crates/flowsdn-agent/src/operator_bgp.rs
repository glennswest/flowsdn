//! The operator's BGP compiler (#334, spec 15 §3.2): FlowsdnBGPClusterConfig,
//! FlowsdnBGPNodeConfigOverride and FlowsdnNode compiled into one
//! FlowsdnBGPNodeConfig per selected node, and the conditions of the cluster
//! and peer configs (§3.2.1, §3.2.2).
//!
//! [`plan`] is pure (lists in, writes out) so it is tested without an API
//! server; [`run`] lists, plans and writes through a `send` function like the
//! garbage collectors'. **DEVIATION:** the reference reconciles on watch
//! events; the operator runs a pass every `--bgp-interval` (default 10 s)
//! while leading, which converges the same way: a pass reads everything and
//! is idempotent, and writes only what changed.
//!
//! For each cluster config, by name: select FlowsdnNodes by `nodeSelector`
//! (absent: every node); skip a node whose node config another cluster config
//! owns (first owner wins, reported as `flowsdn.io/ConflictingClusterConfig`);
//! merge the node's override (router ID, local port and ASN per instance,
//! local address per peer, by name; unmatched entries ignored); in `ip-pool`
//! mode give each (node, instance) a router ID from the pool; create the node
//! config with one controller owner reference, update it only when its spec
//! differs, and delete the node configs it owns whose node is no longer
//! selected. An error on one cluster config or node does not stop the rest.
use crate::operator_gc::Send;
use flowsdn_k8s::kinds::{
    BgpNodeInstance, BgpNodePeer, Condition, ConditionsStatus, FlowsdnBGPClusterConfig,
    FlowsdnBGPNodeConfig, FlowsdnBGPNodeConfigOverride, FlowsdnBGPNodeConfigSpec,
    FlowsdnBGPPeerConfig, Kind, OwnerReference, API_VERSION,
};
use flowsdn_policy::k8s::LabelSelector;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;

pub const CONDITION_NO_MATCHING_NODE: &str = "flowsdn.io/NoMatchingNode";
pub const CONDITION_MISSING_PEER_CONFIGS: &str = "flowsdn.io/MissingPeerConfigs";
pub const CONDITION_CONFLICTING_CLUSTER_CONFIG: &str = "flowsdn.io/ConflictingClusterConfig";
pub const CONDITION_MISSING_AUTH_SECRET: &str = "flowsdn.io/MissingAuthSecret";
const CLUSTER_CONDITIONS: [&str; 3] = [
    CONDITION_CONFLICTING_CLUSTER_CONFIG,
    CONDITION_MISSING_PEER_CONFIGS,
    CONDITION_NO_MATCHING_NODE,
];
const FLOWSDN_NODES: &str = "/apis/flowsdn.io/v1alpha1/flowsdnnodes";

/// How router IDs are given (`--bgp-router-id-allocation-mode`, §3.14).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouterIdMode {
    /// The agent derives them; the operator writes only an override's.
    #[default]
    Default,
    /// The operator allocates them from this pool.
    Pool(Pool),
}

/// The operator's BGP settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BgpSettings {
    /// `--enable-bgp-control-plane`: off, no node config is created or deleted.
    pub enabled: bool,
    /// `--bgp-secrets-namespace`: where peer configs' auth Secrets live;
    /// unset, `MissingAuthSecret` is not evaluated.
    pub secrets_namespace: Option<String>,
    /// `--enable-bgp-control-plane-status-report`: off, the operator's
    /// conditions are removed instead of written.
    pub status_report: bool,
    pub router_ids: RouterIdMode,
    /// `--bgp-interval`: the time between passes.
    pub interval: Duration,
}
impl Default for BgpSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            secrets_namespace: None,
            status_report: true,
            router_ids: RouterIdMode::Default,
            interval: Duration::from_secs(10),
        }
    }
}

/// An inclusive IPv4 range: a CIDR or `first-last`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pool {
    first: u32,
    last: u32,
}
impl Pool {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || format!("bgp router-ID pool {text:?}: want an IPv4 CIDR or first-last range");
        let address = |s: &str| s.trim().parse::<Ipv4Addr>().map(u32::from).map_err(|_| bad());
        let (first, last) = if let Some((base, length)) = text.split_once('/') {
            let length: u32 = length.trim().parse().map_err(|_| bad())?;
            if length > 32 {
                return Err(bad());
            }
            let mask = u32::MAX.checked_shl(32u32.saturating_sub(length)).unwrap_or(0);
            let base = address(base)? & mask;
            (base, base | !mask)
        } else if let Some((first, last)) = text.split_once('-') {
            (address(first)?, address(last)?)
        } else {
            return Err(bad());
        };
        if first > last {
            return Err(bad());
        }
        Ok(Self { first, last })
    }
    fn contains(&self, ip: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(ip))
    }
    fn size(&self) -> u64 {
        u64::from(self.last.saturating_sub(self.first)).saturating_add(1)
    }
}

/// A (node, instance) router-ID key.
type Key = (String, String);

/// The `ip-pool` router-ID allocator (§3.14): one address per (node,
/// instance), first tried at a hash of the key, then the next free one. It
/// lasts one leader term and is restored from the node configs at its first
/// pass.
#[derive(Clone, Debug, Default)]
pub struct RouterIds {
    restored: bool,
    by_key: BTreeMap<Key, Ipv4Addr>,
    holders: BTreeMap<Ipv4Addr, Key>,
}
impl RouterIds {
    fn hold(&mut self, key: Key, ip: Ipv4Addr) {
        self.free(&key);
        self.holders.insert(ip, key.clone());
        self.by_key.insert(key, ip);
    }
    fn free(&mut self, key: &Key) {
        if let Some(ip) = self.by_key.remove(key) {
            self.holders.remove(&ip);
        }
    }
    fn clear(&mut self) {
        self.by_key.clear();
        self.holders.clear();
    }
    /// Take the router IDs existing node configs hold inside the pool.
    fn restore(&mut self, pool: &Pool, configs: &[FlowsdnBGPNodeConfig]) {
        for config in configs {
            let node = config.metadata.name.clone().unwrap_or_default();
            for instance in &config.spec.bgp_instances {
                if let Some(ip) = instance
                    .router_id
                    .as_deref()
                    .and_then(|r| r.parse::<Ipv4Addr>().ok())
                    .filter(|ip| pool.contains(*ip) && !self.holders.contains_key(ip))
                {
                    self.hold((node.clone(), instance.name.clone()), ip);
                }
            }
        }
        self.restored = true;
    }
    /// The key's address, allocating one if it has none.
    fn allocate(&mut self, pool: &Pool, key: &Key) -> Result<Ipv4Addr, String> {
        if let Some(ip) = self.by_key.get(key) {
            return Ok(*ip);
        }
        let size = pool.size();
        let start = fnv1a(&format!("{}/{}", key.0, key.1))
            .checked_rem(size)
            .unwrap_or(0);
        for step in 0..size {
            let offset = start.saturating_add(step).checked_rem(size).unwrap_or(0);
            let ip = Ipv4Addr::from(pool.first.saturating_add(u32::try_from(offset).unwrap_or(0)));
            if !self.holders.contains_key(&ip) {
                self.hold(key.clone(), ip);
                return Ok(ip);
            }
        }
        Err(format!(
            "router-ID pool exhausted for node {} instance {}",
            key.0, key.1
        ))
    }
    /// An override's router ID: outside the pool it is used as written (and
    /// the key's pool address freed); inside, it must be free or the key's.
    fn claim(&mut self, pool: &Pool, key: &Key, ip: Ipv4Addr) -> Result<(), String> {
        if !pool.contains(ip) {
            self.free(key);
            return Ok(());
        }
        match self.holders.get(&ip) {
            Some(holder) if holder != key => Err(format!(
                "router ID {ip} of the override for node {} instance {} is held by node {} instance {}",
                key.0, key.1, holder.0, holder.1
            )),
            _ => {
                self.hold(key.clone(), ip);
                Ok(())
            }
        }
    }
}

fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// What a pass reads.
#[derive(Clone, Debug, Default)]
pub struct Inputs {
    pub clusters: Vec<FlowsdnBGPClusterConfig>,
    pub peers: Vec<FlowsdnBGPPeerConfig>,
    pub overrides: Vec<FlowsdnBGPNodeConfigOverride>,
    pub node_configs: Vec<FlowsdnBGPNodeConfig>,
    /// FlowsdnNode names and labels.
    pub nodes: BTreeMap<String, BTreeMap<String, String>>,
    /// The Secret names of the secrets namespace (None: not configured).
    pub secrets: Option<BTreeSet<String>>,
}

/// One write of a pass.
#[derive(Clone, Debug, PartialEq)]
pub enum Write {
    Create(FlowsdnBGPNodeConfig),
    /// The stored object (its resourceVersion) with the new spec.
    Update(FlowsdnBGPNodeConfig),
    /// Delete if still the object seen.
    Delete { name: String, uid: String },
    /// The object (its resourceVersion) with the new status.
    ClusterStatus(FlowsdnBGPClusterConfig),
    PeerStatus(FlowsdnBGPPeerConfig),
}

/// A pass's writes and the errors that did not stop it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub writes: Vec<Write>,
    pub errors: Vec<String>,
}

fn name(meta: &flowsdn_k8s::kinds::ObjectMeta) -> String {
    meta.name.clone().unwrap_or_default()
}

/// The cluster configs among an object's owners: (uid, name).
fn cluster_owners(config: &FlowsdnBGPNodeConfig) -> Vec<(String, String)> {
    config
        .metadata
        .owner_references
        .iter()
        .flatten()
        .filter(|o| o.kind == FlowsdnBGPClusterConfig::KIND)
        .map(|o| (o.uid.clone(), o.name.clone()))
        .collect()
}

fn selector(cluster: &FlowsdnBGPClusterConfig) -> Result<Option<LabelSelector>, String> {
    match &cluster.spec.node_selector {
        None => Ok(None),
        Some(s) => {
            let value = serde_json::to_value(s).map_err(|e| e.to_string())?;
            LabelSelector::parse(Some(&value))
                .map(Some)
                .map_err(|e| format!("nodeSelector: {e}"))
        }
    }
}

/// The node config spec of `cluster` on `node`, with its override merged.
fn render(
    cluster: &FlowsdnBGPClusterConfig,
    node: &str,
    override_: Option<&FlowsdnBGPNodeConfigOverride>,
    mode: &RouterIdMode,
    ids: &mut RouterIds,
) -> Result<FlowsdnBGPNodeConfigSpec, String> {
    let mut instances = Vec::new();
    for instance in &cluster.spec.bgp_instances {
        let over = override_.and_then(|o| {
            o.spec
                .bgp_instances
                .iter()
                .find(|i| i.name == instance.name)
        });
        let peers = instance.peers.as_ref().map(|peers| {
            peers
                .iter()
                .map(|peer| BgpNodePeer {
                    auto_discovery: peer.auto_discovery.clone(),
                    local_address: over
                        .and_then(|o| o.peers.as_ref())
                        .and_then(|ps| ps.iter().find(|p| p.name == peer.name))
                        .and_then(|p| p.local_address.clone()),
                    name: peer.name.clone(),
                    peer_asn: peer.peer_asn,
                    peer_address: peer.peer_address.clone(),
                    peer_config_ref: peer.peer_config_ref.clone(),
                })
                .collect()
        });
        let key = (node.to_owned(), instance.name.clone());
        let mut router_id = over.and_then(|o| o.router_id.clone());
        if let RouterIdMode::Pool(pool) = mode {
            match router_id.as_deref() {
                Some(text) => {
                    let ip = text.parse::<Ipv4Addr>().map_err(|_| {
                        format!(
                            "router ID {text:?} of the override for node {node} instance {} is not IPv4",
                            instance.name
                        )
                    })?;
                    ids.claim(pool, &key, ip)?;
                }
                None => router_id = Some(ids.allocate(pool, &key)?.to_string()),
            }
        }
        instances.push(BgpNodeInstance {
            local_asn: over.and_then(|o| o.local_asn).or(instance.local_asn),
            local_port: over.and_then(|o| o.local_port).or(instance.local_port),
            name: instance.name.clone(),
            peers,
            router_id,
        });
    }
    Ok(FlowsdnBGPNodeConfigSpec {
        bgp_instances: instances,
    })
}

/// `conditions` with `wanted` set (keeping a condition's
/// lastTransitionTime while its status holds) and the types in `owned` but
/// not in `wanted` removed; sorted by type.
fn merge_conditions(
    existing: Option<&Vec<Condition>>,
    owned: &[&str],
    wanted: Vec<(&str, bool, &str, String)>,
    generation: Option<i64>,
    now: &str,
) -> Vec<Condition> {
    let existing = existing.cloned().unwrap_or_default();
    let mut out: Vec<Condition> = existing
        .iter()
        .filter(|c| !owned.contains(&c.type_.as_str()))
        .cloned()
        .collect();
    for (kind, status, reason, message) in wanted {
        let status = if status { "True" } else { "False" };
        let since = existing
            .iter()
            .find(|c| c.type_ == kind && c.status == status)
            .map_or_else(|| now.to_owned(), |c| c.last_transition_time.clone());
        out.push(Condition {
            last_transition_time: since,
            message,
            observed_generation: generation,
            reason: reason.into(),
            status: status.into(),
            type_: kind.into(),
        });
    }
    out.sort_by(|a, b| a.type_.cmp(&b.type_));
    out
}

/// Whether two condition lists differ (absent and empty are the same).
fn changed(old: Option<&Vec<Condition>>, new: &[Condition]) -> bool {
    old.map_or(&[][..], Vec::as_slice) != new
}

/// Plan one pass. `now` is the RFC 3339 time a changed condition gets.
pub fn plan(inputs: &Inputs, settings: &BgpSettings, ids: &mut RouterIds, now: &str) -> Plan {
    let mut plan = Plan::default();
    if !settings.enabled {
        return plan;
    }
    if let RouterIdMode::Pool(pool) = &settings.router_ids {
        if inputs.clusters.is_empty() {
            // The node configs go by garbage collection, with no delete to
            // free their addresses from (§3.2).
            ids.clear();
        } else if !ids.restored {
            ids.restore(pool, &inputs.node_configs);
        }
    }
    let existing: BTreeMap<String, &FlowsdnBGPNodeConfig> = inputs
        .node_configs
        .iter()
        .map(|c| (name(&c.metadata), c))
        .collect();
    let overrides: BTreeMap<String, &FlowsdnBGPNodeConfigOverride> = inputs
        .overrides
        .iter()
        .map(|o| (name(&o.metadata), o))
        .collect();
    let peer_names: BTreeSet<String> = inputs.peers.iter().map(|p| name(&p.metadata)).collect();
    // node -> (uid, name) of the cluster config that owns or now claims it.
    let mut claimed: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (node, config) in &existing {
        if let Some(owner) = cluster_owners(config).into_iter().next() {
            claimed.insert(node.clone(), owner);
        }
    }
    let mut kept_keys: BTreeSet<Key> = BTreeSet::new();
    let mut deleted_nodes: BTreeSet<String> = BTreeSet::new();
    let mut rendered_nodes: BTreeSet<String> = BTreeSet::new();
    let mut clusters: Vec<&FlowsdnBGPClusterConfig> = inputs.clusters.iter().collect();
    clusters.sort_by_key(|c| name(&c.metadata));
    let mut pass_failed = false;
    for cluster in clusters {
        let cluster_name = name(&cluster.metadata);
        let Some(uid) = cluster.metadata.uid.clone().filter(|u| !u.is_empty()) else {
            plan.errors
                .push(format!("cluster config {cluster_name}: no uid"));
            pass_failed = true;
            continue;
        };
        let selected: Vec<&String> = match selector(cluster) {
            Ok(selector) => inputs
                .nodes
                .iter()
                .filter(|(_, labels)| selector.as_ref().is_none_or(|s| s.matches(labels)))
                .map(|(node, _)| node)
                .collect(),
            Err(error) => {
                plan.errors
                    .push(format!("cluster config {cluster_name}: {error}"));
                pass_failed = true;
                continue;
            }
        };
        let mut conflicts: BTreeSet<String> = BTreeSet::new();
        let mut failed: BTreeSet<&str> = BTreeSet::new();
        for node in &selected {
            let stored = existing.get(*node);
            let owned = stored.is_some_and(|c| cluster_owners(c).iter().any(|(u, _)| *u == uid));
            let other = match stored {
                Some(stored) => (!owned).then(|| {
                    cluster_owners(stored)
                        .into_iter()
                        .next()
                        .map_or_else(|| "(no cluster config)".to_owned(), |(_, n)| n)
                }),
                None => claimed
                    .get(*node)
                    .filter(|(u, _)| *u != uid)
                    .map(|(_, n)| n.clone()),
            };
            if let Some(other) = other {
                conflicts.insert(other);
                continue;
            }
            let spec = match render(
                cluster,
                node,
                overrides.get(*node).copied(),
                &settings.router_ids,
                ids,
            ) {
                Ok(spec) => spec,
                Err(error) => {
                    plan.errors
                        .push(format!("cluster config {cluster_name}: {error}"));
                    failed.insert(node.as_str());
                    pass_failed = true;
                    continue;
                }
            };
            for instance in &spec.bgp_instances {
                kept_keys.insert(((*node).clone(), instance.name.clone()));
            }
            rendered_nodes.insert((*node).clone());
            claimed.insert((*node).clone(), (uid.clone(), cluster_name.clone()));
            match stored {
                Some(stored) if stored.spec == spec => {}
                Some(stored) => {
                    let mut object = (*stored).clone();
                    object.spec = spec;
                    plan.writes.push(Write::Update(object));
                }
                None => {
                    let mut object = FlowsdnBGPNodeConfig::named(node);
                    object.metadata.owner_references = Some(vec![OwnerReference {
                        api_version: API_VERSION.into(),
                        kind: FlowsdnBGPClusterConfig::KIND.into(),
                        name: cluster_name.clone(),
                        uid: uid.clone(),
                        controller: Some(true),
                        block_owner_deletion: None,
                    }]);
                    object.spec = spec;
                    plan.writes.push(Write::Create(object));
                }
            }
        }
        // Node configs of this cluster config whose node it no longer selects.
        for (node, config) in &existing {
            let mine = cluster_owners(config).iter().any(|(u, _)| *u == uid);
            if mine && !selected.contains(&node) && !failed.contains(node.as_str()) {
                plan.writes.push(Write::Delete {
                    name: node.clone(),
                    uid: config.metadata.uid.clone().unwrap_or_default(),
                });
                deleted_nodes.insert(node.clone());
                if claimed.get(node).is_some_and(|(u, _)| *u == uid) {
                    claimed.remove(node);
                }
            }
        }
        // Conditions (§3.2.1).
        let wanted = if settings.status_report {
            let missing: Vec<String> = cluster
                .spec
                .bgp_instances
                .iter()
                .flat_map(|i| i.peers.iter().flatten())
                .filter_map(|p| p.peer_config_ref.as_ref().map(|r| r.name.clone()))
                .filter(|n| !peer_names.contains(n))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let conflicts: Vec<String> = conflicts.into_iter().collect();
            vec![
                if selected.is_empty() {
                    (
                        CONDITION_NO_MATCHING_NODE,
                        true,
                        "MatchingNodeUnavailable",
                        "No node matches spec.nodeSelector".to_owned(),
                    )
                } else {
                    (
                        CONDITION_NO_MATCHING_NODE,
                        false,
                        "MatchingNodeSelected",
                        String::new(),
                    )
                },
                if missing.is_empty() {
                    (
                        CONDITION_MISSING_PEER_CONFIGS,
                        false,
                        "PeerConfigsResolved",
                        String::new(),
                    )
                } else {
                    (
                        CONDITION_MISSING_PEER_CONFIGS,
                        true,
                        "PeerConfigsMissing",
                        format!("Referenced peer configs missing: {}", missing.join(", ")),
                    )
                },
                if conflicts.is_empty() {
                    (
                        CONDITION_CONFLICTING_CLUSTER_CONFIG,
                        false,
                        "ClusterConfigValidated",
                        String::new(),
                    )
                } else {
                    (
                        CONDITION_CONFLICTING_CLUSTER_CONFIG,
                        true,
                        "ClusterConfigConflict",
                        format!(
                            "Selected nodes already have a node config of: {}",
                            conflicts.join(", ")
                        ),
                    )
                },
            ]
        } else {
            Vec::new()
        };
        let old = cluster.status.as_ref().and_then(|s| s.conditions.as_ref());
        let new = merge_conditions(
            old,
            &CLUSTER_CONDITIONS,
            wanted,
            cluster.metadata.generation,
            now,
        );
        if changed(old, &new) {
            let mut object = cluster.clone();
            object.status = Some(ConditionsStatus {
                conditions: (!new.is_empty()).then_some(new),
            });
            plan.writes.push(Write::ClusterStatus(object));
        }
    }
    // Peer config conditions (§3.2.2).
    for peer in &inputs.peers {
        let wanted = match (&inputs.secrets, &peer.spec.auth_secret_ref, settings.status_report) {
            (_, _, false) | (Some(_), None, true) => Some(Vec::new()),
            (Some(secrets), Some(secret), true) => Some(vec![if secrets.contains(secret) {
                (
                    CONDITION_MISSING_AUTH_SECRET,
                    false,
                    "AuthSecretFound",
                    String::new(),
                )
            } else {
                (
                    CONDITION_MISSING_AUTH_SECRET,
                    true,
                    "AuthSecretMissing",
                    format!(
                        "Secret {secret} is not in namespace {}",
                        settings.secrets_namespace.as_deref().unwrap_or("")
                    ),
                )
            }]),
            (None, _, true) => None,
        };
        let Some(wanted) = wanted else { continue };
        let old = peer.status.as_ref().and_then(|s| s.conditions.as_ref());
        let new = merge_conditions(
            old,
            &[CONDITION_MISSING_AUTH_SECRET],
            wanted,
            peer.metadata.generation,
            now,
        );
        if changed(old, &new) {
            let mut object = peer.clone();
            object.status = Some(ConditionsStatus {
                conditions: (!new.is_empty()).then_some(new),
            });
            plan.writes.push(Write::PeerStatus(object));
        }
    }
    // Router IDs no node config keeps any more: a rendered node keeps what
    // it was rendered with; one not rendered (another owner's, waiting for
    // garbage collection) keeps what it holds; a deleted one, nothing.
    if matches!(settings.router_ids, RouterIdMode::Pool(_)) && !pass_failed {
        for (node, config) in &existing {
            if !deleted_nodes.contains(node) && !rendered_nodes.contains(node) {
                for instance in &config.spec.bgp_instances {
                    kept_keys.insert((node.clone(), instance.name.clone()));
                }
            }
        }
        let stale: Vec<Key> = ids
            .by_key
            .keys()
            .filter(|k| !kept_keys.contains(*k))
            .cloned()
            .collect();
        for key in stale {
            ids.free(&key);
        }
    }
    plan
}

/// What one pass did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub statuses: usize,
    /// Writes the API refused because the object changed or went (409/404).
    pub skipped: usize,
}

fn message(body: &Value) -> &str {
    body.get("message").and_then(Value::as_str).unwrap_or("")
}

fn list_items<K: Kind>(send: &mut Send<'_>, errors: &mut Vec<String>) -> Result<Vec<K>, String> {
    let path = K::collection("");
    match send(http::Method::GET, &path, None).map_err(|e| format!("{path}: {e}"))? {
        (200, body) => Ok(body
            .get("items")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(|item| match serde_json::from_value::<K>(item.clone()) {
                Ok(object) => Some(object),
                Err(error) => {
                    errors.push(format!(
                        "{} {}: {error}",
                        K::KIND,
                        item.pointer("/metadata/name")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                    ));
                    None
                }
            })
            .collect()),
        (status, body) => Err(format!("{path}: HTTP {status} {}", message(&body))),
    }
}

/// Read what a pass needs. A list failure aborts the pass.
pub fn read(
    settings: &BgpSettings,
    send: &mut Send<'_>,
    errors: &mut Vec<String>,
) -> Result<Inputs, String> {
    let clusters = list_items::<FlowsdnBGPClusterConfig>(send, errors)?;
    let peers = list_items::<FlowsdnBGPPeerConfig>(send, errors)?;
    let overrides = list_items::<FlowsdnBGPNodeConfigOverride>(send, errors)?;
    let node_configs = list_items::<FlowsdnBGPNodeConfig>(send, errors)?;
    let nodes = match send(http::Method::GET, FLOWSDN_NODES, None)
        .map_err(|e| format!("{FLOWSDN_NODES}: {e}"))?
    {
        (200, body) => body
            .get("items")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice)
            .iter()
            .filter_map(|n| {
                let name = n.pointer("/metadata/name").and_then(Value::as_str)?;
                let labels = n
                    .pointer("/metadata/labels")
                    .and_then(Value::as_object)
                    .map(|l| {
                        l.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default();
                Some((name.to_owned(), labels))
            })
            .collect(),
        (status, body) => {
            return Err(format!("{FLOWSDN_NODES}: HTTP {status} {}", message(&body)));
        }
    };
    let secrets = match &settings.secrets_namespace {
        None => None,
        Some(namespace) => {
            let path = format!("/api/v1/namespaces/{namespace}/secrets");
            match send(http::Method::GET, &path, None).map_err(|e| format!("{path}: {e}"))? {
                // Only the names are kept; the data is dropped here.
                (200, body) => Some(
                    body.get("items")
                        .and_then(Value::as_array)
                        .map_or(&[][..], Vec::as_slice)
                        .iter()
                        .filter_map(|s| s.pointer("/metadata/name").and_then(Value::as_str))
                        .map(str::to_owned)
                        .collect(),
                ),
                (404, _) => Some(BTreeSet::new()),
                (status, body) => {
                    return Err(format!("{path}: HTTP {status} {}", message(&body)));
                }
            }
        }
    };
    Ok(Inputs {
        clusters,
        peers,
        overrides,
        node_configs,
        nodes,
        secrets,
    })
}

fn body<T: serde::Serialize>(object: &T) -> Result<Value, String> {
    serde_json::to_value(object).map_err(|e| e.to_string())
}

/// One pass: read, plan, write. The errors of the pass (plan errors and
/// failed writes) come back with the summary; the pass still writes what it
/// can.
pub fn run(
    settings: &BgpSettings,
    ids: &mut RouterIds,
    now: &str,
    send: &mut Send<'_>,
) -> Result<(Summary, Vec<String>), String> {
    let mut errors = Vec::new();
    let inputs = read(settings, send, &mut errors)?;
    let plan = plan(&inputs, settings, ids, now);
    errors.extend(plan.errors);
    let mut summary = Summary::default();
    for write in plan.writes {
        let (method, path, payload, count): (_, String, Option<Value>, fn(&mut Summary)) =
            match &write {
                Write::Create(object) => (
                    http::Method::POST,
                    FlowsdnBGPNodeConfig::collection(""),
                    Some(body(object)?),
                    |s| s.created = s.created.saturating_add(1),
                ),
                Write::Update(object) => (
                    http::Method::PUT,
                    FlowsdnBGPNodeConfig::path("", &name(&object.metadata)),
                    Some(body(object)?),
                    |s| s.updated = s.updated.saturating_add(1),
                ),
                Write::Delete { name, uid } => (
                    http::Method::DELETE,
                    FlowsdnBGPNodeConfig::path("", name),
                    Some(json!({"preconditions": {"uid": uid}})),
                    |s| s.deleted = s.deleted.saturating_add(1),
                ),
                Write::ClusterStatus(object) => (
                    http::Method::PUT,
                    format!(
                        "{}/status",
                        FlowsdnBGPClusterConfig::path("", &name(&object.metadata))
                    ),
                    Some(body(object)?),
                    |s| s.statuses = s.statuses.saturating_add(1),
                ),
                Write::PeerStatus(object) => (
                    http::Method::PUT,
                    format!(
                        "{}/status",
                        FlowsdnBGPPeerConfig::path("", &name(&object.metadata))
                    ),
                    Some(body(object)?),
                    |s| s.statuses = s.statuses.saturating_add(1),
                ),
            };
        match send(method, &path, payload.as_ref()) {
            Ok((200..=299, _)) => count(&mut summary),
            Ok((404 | 409, _)) => summary.skipped = summary.skipped.saturating_add(1),
            Ok((status, body)) => errors.push(format!("{path}: HTTP {status} {}", message(&body))),
            Err(error) => errors.push(format!("{path}: {error}")),
        }
    }
    Ok((summary, errors))
}

#[cfg(test)]
#[path = "operator_bgp_tests.rs"]
mod tests;
