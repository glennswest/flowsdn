//! `flowsdn-agent clustermesh-apiserver` (#567, spec 20 §3.8): the cluster's
//! ClusterMesh publisher. It watches this cluster's flowsdn kinds and
//! Services and writes them into the kvstore peers read:
//!
//! | Store | From | Keys | Canary |
//! |---|---|---|---|
//! | nodes | FlowsdnNode | `flowsdn/state/nodes/v1/<cluster>/<node>` | `flowsdn/synced/<cluster>/flowsdn/state/nodes/v1` |
//! | identities | FlowsdnIdentity (+ Namespace) | `flowsdn/state/identities/v1/id/<id>` (unleased) | `.../identities/v1` |
//! | ip | FlowsdnEndpoint (+ Namespace) | `flowsdn/state/ip/v1/default/<ip>` | `.../ip/v1` |
//! | services | Service + EndpointSlice + Namespace | `flowsdn/state/services/v1/<cluster>/<ns>/<name>` | `.../services/v1` |
//!
//! Values are spec 20 §4.3-4.6's ([`flowsdn_clustermesh::export`]). Each
//! store is a [`SyncStore`]; its canary is written once the sources it
//! depends on have listed and everything from those lists is in the store.
//! A resource in a namespace that is not global is exported as a delete
//! (§3.8.2). One IP claimed by several endpoints is written from its primary
//! owner ([`IpOwners`]).
//!
//! It also publishes `flowsdn/cluster-config/<cluster>` (§3.8.3) through the
//! guarded ownership claim of §12 decision 9 (the instance UUID is
//! `--cluster-instance-uuid`, provisioned once for the cluster), re-writing
//! it when it changes and every 5 minutes, writes `flowsdn/.heartbeat` every
//! 60 s (§3.5.1), and answers `GET /readyz` on `--health-port` (§3.8.7).
//!
//! **DEVIATION (#337 precedent):** it is a mode of the agent binary, which the
//! flowsdn golden already carries, not a separate executable.
use crate::log::logln;
use flowsdn_clustermesh::export::{self, IpOwners, Write};
use flowsdn_clustermesh::ownership::{self, InstanceUuid, Record};
use flowsdn_k8s::client::{JsonClient, Query, TransportLimits, WATCH_ENDED};
use flowsdn_k8s::watch::{Identity, Limits, PageResult, Resource, Scope, WatchState, WholeKind};
use flowsdn_kvstore::sync_store::{SyncConfig, SyncStore};
use flowsdn_kvstore::{Compare, EventKind, Kvstore, Lease, TxnPut, Value as KvValue};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

pub const HELP: &str = "flowsdn-agent clustermesh-apiserver — publish this cluster into the ClusterMesh kvstore

Usage: flowsdn-agent clustermesh-apiserver [OPTIONS]

Options:
  --cluster-name NAME                This cluster's name (required)
  --cluster-id ID                    This cluster's ID, 1-511 (required)
  --cluster-instance-uuid UUID       The cluster's durable instance UUID (required; see spec 20 §12 decision 9)
  --kvstore-config PATH              etcd client YAML (endpoints, trusted-ca-file, cert-file, key-file)
  --kvstore-address URL              One endpoint instead of --kvstore-config (http:// or https://)
  --kubeconfig PATH                  Explicit kubeconfig (default: the in-cluster service account)
  --health-port PORT                 /readyz port (default 9880)
  --clustermesh-default-global-namespace true|false
                                     Export namespaces without clustermesh.flowsdn.io/global (default true)
  --max-connected-clusters N         Advertised in the cluster config (default 255)
  --enable-heartbeat true|false      Write flowsdn/.heartbeat every 60 s (default true)
  --kvstore-lease-ttl SECONDS        Key lease TTL, 25-86400 (default 900)
";

/// The apiserver's settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub cluster: String,
    pub cluster_id: u32,
    pub instance: String,
    pub kvstore_config: Option<PathBuf>,
    pub kvstore_address: Option<String>,
    pub kubeconfig: Option<PathBuf>,
    pub health_port: u16,
    pub default_global: bool,
    pub max_connected: u32,
    pub heartbeat: bool,
    pub lease_ttl: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            cluster: String::new(),
            cluster_id: 0,
            instance: String::new(),
            kvstore_config: None,
            kvstore_address: None,
            kubeconfig: None,
            health_port: 9880,
            default_global: true,
            max_connected: 255,
            heartbeat: true,
            lease_ttl: flowsdn_kvstore::KEY_LEASE_TTL,
        }
    }
}

fn boolean(value: Option<&str>, name: &str) -> Result<bool, String> {
    match value {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        _ => Err(format!("{name} needs true or false")),
    }
}

/// Parse the arguments after `clustermesh-apiserver`.
pub fn parse(args: &[std::ffi::OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let name = arg.to_str().unwrap_or("");
        let mut value = || {
            rest.next()
                .and_then(|v| v.to_str())
                .map(str::to_owned)
                .ok_or(format!("{name} needs a value"))
        };
        match name {
            "--cluster-name" => options.cluster = value()?,
            "--cluster-id" => {
                options.cluster_id = value()?
                    .parse()
                    .ok()
                    .filter(|id| (1..=511).contains(id))
                    .ok_or("--cluster-id needs a number from 1 to 511")?;
            }
            "--cluster-instance-uuid" => options.instance = value()?,
            "--kvstore-config" => options.kvstore_config = Some(PathBuf::from(value()?)),
            "--kvstore-address" => options.kvstore_address = Some(value()?),
            "--kubeconfig" => options.kubeconfig = Some(PathBuf::from(value()?)),
            "--health-port" => {
                options.health_port = value()?
                    .parse()
                    .map_err(|_| "--health-port needs a port number")?;
            }
            "--clustermesh-default-global-namespace" => {
                options.default_global = boolean(Some(&value()?), name)?;
            }
            "--max-connected-clusters" => {
                options.max_connected = value()?
                    .parse()
                    .ok()
                    .filter(|n| (1..=511).contains(n))
                    .ok_or("--max-connected-clusters needs a number from 1 to 511")?;
            }
            "--enable-heartbeat" => options.heartbeat = boolean(Some(&value()?), name)?,
            "--kvstore-lease-ttl" => {
                let seconds: u64 = value()?
                    .parse()
                    .ok()
                    .filter(|s| (25..=86_400).contains(s))
                    .ok_or("--kvstore-lease-ttl needs 25 to 86400 seconds")?;
                options.lease_ttl = Duration::from_secs(seconds);
            }
            _ => return Err(format!("unknown clustermesh-apiserver argument {arg:?}")),
        }
    }
    flowsdn_clustermesh::prefixes::validate_cluster(&options.cluster)
        .map_err(|e| format!("--cluster-name: {e}"))?;
    if options.cluster_id == 0 {
        return Err("--cluster-id is required".into());
    }
    InstanceUuid::parse(&options.instance).map_err(|e| format!("--cluster-instance-uuid: {e}"))?;
    if options.kvstore_config.is_some() == options.kvstore_address.is_some() {
        return Err("give exactly one of --kvstore-config and --kvstore-address".into());
    }
    Ok(options)
}

/// A Kubernetes source of the exporter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Source {
    Nodes,
    Identities,
    Endpoints,
    Services,
    Slices,
    Namespaces,
}

/// The four stores and what each needs listed before its canary.
const NEEDS: [(&str, &[Source]); 4] = [
    ("nodes", &[Source::Nodes]),
    ("identities", &[Source::Identities, Source::Namespaces]),
    ("ip", &[Source::Endpoints, Source::Namespaces]),
    (
        "services",
        &[Source::Services, Source::Slices, Source::Namespaces],
    ),
];

/// The exporter's view of this cluster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cluster {
    pub name: String,
    pub id: u32,
    pub default_global: bool,
}

/// The state → kvstore exporter (§3.8.2). Feed it each source's full
/// snapshot as it changes; it diffs into the stores.
pub struct Exporter<K: Kvstore> {
    cluster: Cluster,
    stores: BTreeMap<&'static str, SyncStore<K>>,
    objects: BTreeMap<Source, Vec<Value>>,
    identities: Vec<Identity>,
    listed: BTreeSet<Source>,
    synced: BTreeSet<&'static str>,
    owners: IpOwners,
    /// (ip name, owner) -> value last given to [`IpOwners`].
    claims: BTreeMap<(String, String), Vec<u8>>,
}

impl<K: Kvstore> Exporter<K> {
    pub fn new(kv: &Arc<K>, cluster: Cluster) -> Self {
        let store = |prefix: &str, canary_of: &str, leased: bool| {
            let mut config = SyncConfig::new(prefix, Some(export::canary(&cluster.name, canary_of)));
            config.leased = leased;
            SyncStore::new(Arc::clone(kv), config)
        };
        let stores = BTreeMap::from([
            ("nodes", store(export::NODES, export::NODES, true)),
            // Identity master keys are unleased (§4.1).
            (
                "identities",
                store(export::IDENTITIES, export::IDENTITIES, false),
            ),
            ("ip", store(export::IP, export::IP, true)),
            ("services", store(export::SERVICES, export::SERVICES, true)),
        ]);
        Self {
            cluster,
            stores,
            objects: BTreeMap::new(),
            identities: Vec::new(),
            listed: BTreeSet::new(),
            synced: BTreeSet::new(),
            owners: IpOwners::new(),
            claims: BTreeMap::new(),
        }
    }

    /// The stores, to run each one's worker.
    pub fn stores(&self) -> Vec<SyncStore<K>> {
        self.stores.values().cloned().collect()
    }

    /// Whether every store has written its canary.
    pub fn ready(&self) -> bool {
        self.stores.values().all(|s| s.stats().synced)
    }

    /// A source's whole current state (`listed`: it has completed a list).
    pub fn update(&mut self, source: Source, objects: Vec<Value>, listed: bool) {
        self.objects.insert(source, objects);
        self.changed(source, listed);
    }

    /// The FlowsdnIdentities' current state.
    pub fn update_identities(&mut self, identities: Vec<Identity>, listed: bool) {
        self.identities = identities;
        self.changed(Source::Identities, listed);
    }

    fn changed(&mut self, source: Source, listed: bool) {
        if listed {
            self.listed.insert(source);
        }
        match source {
            Source::Nodes => self.export_nodes(),
            Source::Identities => self.export_identities(),
            Source::Endpoints => self.export_ip(),
            Source::Services | Source::Slices => self.export_services(),
            Source::Namespaces => {
                self.export_identities();
                self.export_ip();
                self.export_services();
            }
        }
        for (store, needs) in NEEDS {
            if !self.synced.contains(store) && needs.iter().all(|n| self.listed.contains(n)) {
                // Only once every source it reads has listed, so the canary
                // means "the initial lists are in".
                if let Some(sync) = self.stores.get(store) {
                    sync.synced(None);
                }
                self.synced.insert(store);
            }
        }
    }

    fn objects(&self, source: Source) -> &[Value] {
        self.objects.get(&source).map_or(&[], Vec::as_slice)
    }

    fn global(&self, namespace: &str) -> bool {
        let object = self
            .objects(Source::Namespaces)
            .iter()
            .find(|n| n.pointer("/metadata/name").and_then(Value::as_str) == Some(namespace));
        export::namespace_global(object, self.cluster.default_global)
    }

    /// Upsert `desired` into `store` and delete every other name it holds.
    fn replace(&self, store: &str, desired: BTreeMap<String, Vec<u8>>) {
        let Some(sync) = self.stores.get(store) else {
            return;
        };
        for name in sync.names() {
            if !desired.contains_key(&name) {
                sync.delete(&name);
            }
        }
        for (name, data) in desired {
            sync.upsert(&name, data);
        }
    }

    fn export_nodes(&self) {
        let mut desired = BTreeMap::new();
        for object in self.objects(Source::Nodes) {
            match export::node_record(object, &self.cluster.name, self.cluster.id) {
                Ok(Some((name, data))) => {
                    desired.insert(name, data);
                }
                Ok(None) => {}
                Err(error) => logln!("clustermesh: FlowsdnNode skipped: {error}"),
            }
        }
        self.replace("nodes", desired);
    }

    fn export_identities(&self) {
        let mut desired = BTreeMap::new();
        for identity in &self.identities {
            if export::identity_namespace(&identity.security_labels).is_some_and(|ns| !self.global(ns)) {
                continue;
            }
            match export::identity_value(&identity.metadata.name, &identity.security_labels) {
                Some((name, data)) => {
                    desired.insert(name, data);
                }
                None => logln!(
                    "clustermesh: FlowsdnIdentity {} has no security labels; not exported",
                    identity.metadata.name
                ),
            }
        }
        self.replace("identities", desired);
    }

    fn export_ip(&mut self) {
        let mut wanted: BTreeMap<(String, String), Vec<u8>> = BTreeMap::new();
        for object in self.objects(Source::Endpoints) {
            let namespace = object
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !self.global(namespace) {
                continue;
            }
            let owner = format!(
                "{namespace}/{}",
                object
                    .pointer("/metadata/name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            );
            for (name, data) in export::ip_pairs(object) {
                wanted.insert((name, owner.clone()), data);
            }
        }
        let mut writes = Vec::new();
        let gone: Vec<(String, String)> = self
            .claims
            .keys()
            .filter(|k| !wanted.contains_key(*k))
            .cloned()
            .collect();
        for (name, owner) in gone {
            self.claims.remove(&(name.clone(), owner.clone()));
            writes.extend(self.owners.remove(&name, &owner));
        }
        for ((name, owner), data) in wanted {
            if self.claims.get(&(name.clone(), owner.clone())) == Some(&data) {
                continue;
            }
            writes.extend(self.owners.upsert(&name, &owner, data.clone()));
            self.claims.insert((name, owner), data);
        }
        if let Some(sync) = self.stores.get("ip") {
            for write in writes {
                match write {
                    Write::Put(name, data) => sync.upsert(&name, data),
                    Write::Delete(name) => sync.delete(&name),
                }
            }
        }
    }

    fn export_services(&self) {
        let slices = self.objects(Source::Slices);
        let mut desired = BTreeMap::new();
        for service in self.objects(Source::Services) {
            let namespace = service
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !self.global(namespace) {
                continue;
            }
            let mine: Vec<&Value> = slices
                .iter()
                .filter(|s| s.pointer("/metadata/namespace").and_then(Value::as_str) == Some(namespace))
                .collect();
            if let Some((name, data)) =
                export::cluster_service(service, &mine, &self.cluster.name, self.cluster.id)
            {
                desired.insert(name, data);
            }
        }
        self.replace("services", desired);
    }
}

fn record(value: Option<KvValue>) -> Option<Record> {
    value.map(|v| Record {
        value: v.data,
        mod_revision: u64::try_from(v.mod_revision).unwrap_or(0),
        lease_id: (v.lease_id != 0).then_some(v.lease_id),
    })
}

/// Publish `flowsdn/cluster-config/<cluster>` through the guarded claim
/// (§12 decision 9): read owner and config, plan, run the plan as one
/// transaction, and replan when a compare failed. True: something written.
pub async fn publish_config<K: Kvstore>(
    kv: &K,
    cluster: &str,
    instance: &InstanceUuid,
    desired: &Value,
) -> Result<bool, String> {
    let owner_key = format!("flowsdn/cluster-owners/{cluster}");
    let config_key = export::cluster_config_key(cluster);
    for _ in 0..5 {
        let owner = record(kv.get(&owner_key, None).await.map_err(|e| e.to_string())?);
        let config = record(kv.get(&config_key, None).await.map_err(|e| e.to_string())?);
        let lease = kv.lease_for(&config_key).await.map_err(|e| e.to_string())?;
        let plan = ownership::plan_claim(cluster, instance, owner.as_ref(), config.as_ref(), desired, lease)
            .map_err(|e| e.to_string())?;
        if plan.puts.is_empty() {
            return Ok(false);
        }
        let compares = plan
            .guards
            .into_iter()
            .map(|guard| match guard.expected {
                None => Compare::Absent(guard.key),
                Some(record) => Compare::Exact {
                    key: guard.key,
                    data: record.value,
                    mod_revision: i64::try_from(record.mod_revision).unwrap_or(0),
                    lease_id: record.lease_id.unwrap_or(0),
                },
            })
            .collect();
        let puts = plan
            .puts
            .into_iter()
            .map(|put| TxnPut {
                key: put.key,
                data: put.value,
                lease: match put.lease {
                    ownership::Lease::None => Lease::None,
                    ownership::Lease::Config(_) => Lease::Attached,
                },
            })
            .collect();
        if kv.txn(compares, puts).await.map_err(|e| e.to_string())? {
            return Ok(true);
        }
    }
    Err("cluster config: the keys kept changing under the claim".into())
}

/// Enforce the cluster config (§3.8.3): watch the key first, wait 5 s,
/// write (three attempts, 2 s to 30 s apart; the last failure ends the
/// process), then re-claim on any change and every 5 minutes.
pub async fn enforce_config<K: Kvstore>(
    kv: Arc<K>,
    cluster: String,
    instance: InstanceUuid,
    desired: Value,
) -> Result<(), String> {
    let key = export::cluster_config_key(&cluster);
    let mut events = kv.watch(&key).await.map_err(|e| e.to_string())?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut wait = Duration::from_secs(2);
    let mut attempt = 0u32;
    loop {
        match publish_config(&*kv, &cluster, &instance, &desired).await {
            Ok(_) => break,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                if attempt >= 3 {
                    return Err(format!("cluster config not published: {error}"));
                }
                logln!("clustermesh: cluster config: {error}; retrying in {wait:?}");
                tokio::time::sleep(wait).await;
                wait = wait.saturating_mul(4).min(Duration::from_secs(30));
            }
        }
    }
    logln!("clustermesh: published {key}");
    let mut refresh = tokio::time::interval(Duration::from_secs(300));
    refresh.tick().await;
    loop {
        tokio::select! {
            event = events.recv() => match event {
                None => return Err("cluster config watch ended".into()),
                Some(event) if event.key != key || event.kind == EventKind::ListDone => continue,
                Some(_) => {}
            },
            _ = refresh.tick() => {}
        }
        match publish_config(&*kv, &cluster, &instance, &desired).await {
            Ok(true) => logln!("clustermesh: re-published {key}"),
            Ok(false) => {}
            // A foreign owner or config fails closed: say so, do not adopt.
            Err(error) => logln!("clustermesh: cluster config: {error}"),
        }
    }
}

/// Write `flowsdn/.heartbeat` every 60 s, each write bounded at 25 s (§3.5.1).
pub async fn heartbeat<K: Kvstore>(kv: Arc<K>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let now = flowsdn_kvstore::rfc3339(SystemTime::now()).into_bytes();
        match tokio::time::timeout(
            Duration::from_secs(25),
            kv.put("flowsdn/.heartbeat", now, Lease::Attached, None),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => logln!("clustermesh: heartbeat: {error}"),
            Err(_) => logln!("clustermesh: heartbeat: timed out"),
        }
    }
}

/// What a watch task sends: a source's rows (whole objects or identities).
enum Update {
    Objects(Source, Vec<Value>, bool),
    Identities(Vec<Identity>, bool),
}

const LIST_PAGE: u32 = 500;

async fn relist(client: &JsonClient, scope: &Scope, state: &mut WatchState) -> Result<(), flowsdn_k8s::Error> {
    state.begin_list();
    let mut token: Option<String> = None;
    loop {
        let query = Query {
            limit: Some(LIST_PAGE),
            continue_token: token.as_deref(),
            ..Query::default()
        };
        let page = client.list(scope, &query).await.inspect_err(|_| state.failed())?;
        match state.list_page(&page).await? {
            PageResult::Continue(next) => token = Some(next),
            PageResult::Complete => return Ok(()),
        }
    }
}

fn rows(source: Option<Source>, state: &WatchState) -> Update {
    let listed = state.initialized();
    let snapshot = state.snapshot();
    match source {
        None => Update::Identities(
            snapshot
                .all()
                .filter_map(|(row, _)| match &*row {
                    Resource::Identity(i) => Some(i.clone()),
                    _ => None,
                })
                .collect(),
            listed,
        ),
        Some(source) => Update::Objects(
            source,
            snapshot
                .all()
                .filter_map(|(row, _)| match &*row {
                    Resource::Whole(o) => Some(o.object.clone()),
                    _ => None,
                })
                .collect(),
            listed,
        ),
    }
}

/// List and watch one scope for ever, sending its rows on every change.
async fn watch(client: Arc<JsonClient>, scope: Scope, source: Option<Source>, tx: mpsc::Sender<Update>) {
    let Ok(mut state) = WatchState::new(scope.clone(), Limits::default()) else {
        return;
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        let result: Result<(), flowsdn_k8s::Error> = async {
            if state.needs_relist() {
                relist(&client, &scope, &mut state).await?;
                let _ = tx.send(rows(source, &state)).await;
            }
            let version = state.resource_version().map(str::to_owned);
            let query = Query {
                resource_version: version.as_deref(),
                watch: true,
                ..Query::default()
            };
            let mut frames = client.watch(&scope, &query).await?;
            loop {
                let event = match frames.next().await {
                    Ok(event) => event,
                    Err(error) if error.0 == WATCH_ENDED => return Ok(()),
                    Err(error) => return Err(error),
                };
                state.event(&event).await?;
                let _ = tx.send(rows(source, &state)).await;
            }
        }
        .await;
        match result {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(error) => {
                state.failed();
                logln!("clustermesh: watch {scope:?}: {error}; relisting in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(30));
            }
        }
    }
}

/// Answer `GET /readyz`: 200 `Ready` once every store has its canary.
async fn health(port: u16, ready: Arc<std::sync::atomic::AtomicBool>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => listener,
        Err(error) => {
            logln!("clustermesh: health port {port}: {error}");
            return;
        }
    };
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let ready = Arc::clone(&ready);
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
            let request = String::from_utf8_lossy(buffer.get(..n).unwrap_or(&[]));
            let (status, body) = if !request.starts_with("GET /readyz") {
                ("404 Not Found", "not found")
            } else if ready.load(std::sync::atomic::Ordering::SeqCst) {
                ("200 OK", "Ready")
            } else {
                ("500 Internal Server Error", "NotReady")
            };
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// The etcd client settings from the options.
pub fn etcd_config(options: &Options) -> Result<flowsdn_kvstore::etcd::EtcdConfig, String> {
    let mut config = match (&options.kvstore_config, &options.kvstore_address) {
        (Some(path), _) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            flowsdn_kvstore::etcd::parse_client_yaml(&text).map_err(|e| e.to_string())?
        }
        (None, Some(address)) => flowsdn_kvstore::etcd::EtcdConfig {
            endpoints: vec![address.clone()],
            ..flowsdn_kvstore::etcd::EtcdConfig::default()
        },
        (None, None) => return Err("no kvstore configured".into()),
    };
    // The apiserver's own store: 50 qps, 10000 while the initial lists are
    // flushed (§3.8.4).
    config.qps = 50;
    config.max_inflight = 50;
    config.bootstrap_qps = 10_000;
    config.key_lease_ttl = options.lease_ttl;
    Ok(config)
}

/// Run until a fatal error.
pub fn run(options: &Options) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(serve(options))
}

async fn serve(options: &Options) -> Result<(), String> {
    let instance = InstanceUuid::parse(&options.instance).map_err(|e| e.to_string())?;
    let client = Arc::new(
        JsonClient::load(options.kubeconfig.as_deref(), TransportLimits::default())
            .await
            .map_err(|e| e.to_string())?,
    );
    let config = etcd_config(options)?;
    let endpoints = config.endpoints.join(", ");
    let kv = Arc::new(
        flowsdn_kvstore::etcd::EtcdBackend::connect(config)
            .await
            .map_err(|e| format!("kvstore {endpoints}: {e}"))?,
    );
    logln!(
        "clustermesh-apiserver: cluster {} (id {}), kvstore {endpoints}",
        options.cluster,
        options.cluster_id
    );
    let mut exporter = Exporter::new(
        &kv,
        Cluster {
            name: options.cluster.clone(),
            id: options.cluster_id,
            default_global: options.default_global,
        },
    );
    for store in exporter.stores() {
        tokio::spawn(async move { store.run().await });
    }
    let desired = export::cluster_config(options.cluster_id, options.max_connected);
    let config_task = tokio::spawn(enforce_config(
        Arc::clone(&kv),
        options.cluster.clone(),
        instance,
        desired,
    ));
    if options.heartbeat {
        tokio::spawn(heartbeat(Arc::clone(&kv)));
    }
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    tokio::spawn(health(options.health_port, Arc::clone(&ready)));
    let (tx, mut rx) = mpsc::channel(64);
    for (scope, source) in [
        (Scope::Whole(WholeKind::FlowsdnNodes), Some(Source::Nodes)),
        (Scope::Identities, None),
        (Scope::Whole(WholeKind::FlowsdnEndpoints), Some(Source::Endpoints)),
        (Scope::Whole(WholeKind::Services), Some(Source::Services)),
        (Scope::Whole(WholeKind::EndpointSlices), Some(Source::Slices)),
        (Scope::Whole(WholeKind::Namespaces), Some(Source::Namespaces)),
    ] {
        tokio::spawn(watch(Arc::clone(&client), scope, source, tx.clone()));
    }
    drop(tx);
    let mut ready_tick = tokio::time::interval(Duration::from_secs(1));
    let mut config_task = config_task;
    loop {
        tokio::select! {
            update = rx.recv() => match update {
                Some(Update::Objects(source, objects, listed)) => exporter.update(source, objects, listed),
                Some(Update::Identities(identities, listed)) => exporter.update_identities(identities, listed),
                None => return Err("every watch ended".into()),
            },
            _ = ready_tick.tick() => {
                let now = exporter.ready();
                if now && !ready.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    logln!("clustermesh-apiserver: initial sync complete; ready");
                    kv.bootstrap_done();
                }
            }
            result = &mut config_task => {
                return match result {
                    Ok(Ok(())) => Err("cluster config enforcement ended".into()),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(error.to_string()),
                };
            }
        }
    }
}

#[cfg(test)]
#[path = "clustermesh_apiserver_tests.rs"]
mod tests;
