//! The Kubernetes controller thread: Node, cluster Pod, Service and
//! EndpointSlice ListWatch through flowsdn-k8s (relist with backoff),
//! publishing into the shared view; a route thread that owns the direct node
//! routes (spec 10 §3.2.3, §5.2); and a services thread that owns the
//! socket-LB maps (spec 05 §3.4, §3.8).
use super::*;
use crate::events::Type::Warning;
use crate::services::{self, ServiceInfo, SliceInfo};
use flowsdn_bpf_loader::kernel::{Object, socket_lb::SocketLb};
use flowsdn_connector::Connector;
use flowsdn_k8s::{
    client::{JsonClient, Query, TransportLimits, WATCH_ENDED},
    watch::{Limits, PageResult, Resource, Scope, WatchState},
};
use flowsdn_lb::socket;
use futures::FutureExt;
use std::{
    fs,
    io::Write,
    path::Path,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

type Key = (IpAddr, u8, IpAddr);

const LIST_PAGE: u32 = 500;
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ROUTES_FILE: &str = "direct-routes.json";
const ANNOTATE_INTERVAL: Duration = Duration::from_secs(2);
const ANNOTATE_RETRY: Duration = Duration::from_secs(30);

pub struct Controller {
    runtime: tokio::runtime::Runtime,
    client: JsonClient,
    settings: Settings,
    routes_file: PathBuf,
}
impl Controller {
    /// Load credentials (explicit kubeconfig, else in-cluster) and verify TLS
    /// set-up; no request is sent yet.
    pub fn connect(settings: Settings, state_dir: &Path) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let client = runtime.block_on(JsonClient::load(
            settings.kubeconfig.as_deref(),
            TransportLimits::default(),
        ))?;
        crate::events::start(settings.kubeconfig.clone(), settings.node_name.clone())?;
        Ok(Self {
            runtime,
            client,
            settings,
            routes_file: state_dir.join(ROUTES_FILE),
        })
    }
    /// Block until this node's Node object yields an allocation CIDR for every
    /// requested family (spec 07 §3.4/§3.5: IPAM waits, logging every 5 s).
    pub fn wait_for_pools(&self, v4: bool, v6: bool) -> Result<(Option<Cidr>, Option<Cidr>)> {
        let mut logged: Option<Instant> = None;
        loop {
            let reason = match self.runtime.block_on(list_nodes(&self.client)) {
                Ok(nodes) => match nodes.iter().find(|n| n.name == self.settings.node_name) {
                    Some(node) => {
                        let pool4 = if v4 { alloc_cidr(node, false) } else { None };
                        let pool6 = if v6 { alloc_cidr(node, true) } else { None };
                        if pool4.is_some() == v4 && pool6.is_some() == v6 {
                            return Ok((pool4, pool6));
                        }
                        "the Node has no pod CIDR or InternalIP for an enabled family".to_owned()
                    }
                    None => "the Node is not registered yet".to_owned(),
                },
                Err(error) => error.to_string(),
            };
            if logged.is_none_or(|at| at.elapsed() >= Duration::from_secs(5)) {
                eprintln!(
                    "waiting for Node {} pod CIDRs: {reason}",
                    self.settings.node_name
                );
                logged = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    /// Set the datapath-init sysctls, then start the watch thread (and the
    /// route thread when auto-direct-node-routes is on); the returned view is
    /// what the API serves. With service-lb on, Services and EndpointSlices
    /// are watched too; given the socket-lb object it is loaded (maps pinned
    /// under `pin_root`), attached to the cgroup root and kept programmed by
    /// a services thread. A load or attach failure is reported in the view's
    /// health, and the rest of the agent keeps running.
    pub fn spawn(
        self,
        ipv6: bool,
        socket_lb: Option<&[u8]>,
        pin_root: Option<&Path>,
    ) -> Result<Shared> {
        let view: Shared = Arc::new(Mutex::new(View {
            local_node: self.settings.node_name.clone(),
            direct_routes: self.settings.auto_direct_node_routes,
            service_lb: self.settings.service_lb,
            ..View::default()
        }));
        let failed = apply_sysctls(Path::new("/proc/sys"), ipv6);
        if !failed.is_empty() {
            crate::events::node(Warning, "SysctlFailed", failed.join("; "));
            lock(&view)
                .errors
                .insert("sysctl".into(), failed.join("; "));
        }
        let routes = if self.settings.auto_direct_node_routes {
            let (sender, receiver) = mpsc::channel();
            let route_view = Arc::clone(&view);
            let file = self.routes_file.clone();
            let skip = self.settings.skip_unreachable;
            std::thread::Builder::new()
                .name("flowsdn-routes".into())
                .spawn(move || route_loop(&receiver, &route_view, &file, skip))?;
            Some(sender)
        } else {
            None
        };
        let lb = match socket_lb.filter(|_| self.settings.service_lb) {
            Some(object) => match load_socket_lb(object, pin_root, &self.settings.cgroup_root) {
                Ok(lb) => {
                    let (sender, receiver) = mpsc::channel();
                    let lb_view = Arc::clone(&view);
                    std::thread::Builder::new()
                        .name("flowsdn-services".into())
                        .spawn(move || {
                            let mut lb = lb;
                            service_loop(&receiver, &lb_view, &mut lb);
                        })?;
                    Some(sender)
                }
                Err(error) => {
                    eprintln!("socket LB unavailable: {error}");
                    crate::events::node(
                        Warning,
                        "ServiceLBUnavailable",
                        format!("ClusterIP Services are not load balanced: {error}"),
                    );
                    lock(&view).errors.insert("services".into(), error);
                    None
                }
            },
            None => None,
        };
        let annotate_view = Arc::clone(&view);
        let kubeconfig = self.settings.kubeconfig.clone();
        std::thread::Builder::new()
            .name("flowsdn-annotate".into())
            .spawn(move || annotation_loop(&annotate_view, kubeconfig.as_deref()))?;
        let watch_view = Arc::clone(&view);
        std::thread::Builder::new()
            .name("flowsdn-k8s".into())
            .spawn(move || {
                let Self {
                    runtime,
                    client,
                    settings,
                    ..
                } = self;
                let local = settings.node_name;
                let node_view = Arc::clone(&watch_view);
                let mut sent: Option<Vec<DesiredRoute>> = None;
                let nodes =
                    watch_forever(&client, Scope::Nodes, "nodes", &watch_view, move |state| {
                        let nodes = node_rows(state);
                        let desired = desired_routes(&local, &nodes);
                        {
                            let mut view = lock(&node_view);
                            view.nodes = nodes;
                            view.nodes_synced = true;
                        }
                        // Heartbeats modify Nodes constantly; reconcile on change only
                        // (the route thread also repairs every 30 s).
                        if let Some(sender) = &routes
                            && sent.as_ref() != Some(&desired)
                        {
                            let _ = sender.send(desired.clone());
                            sent = Some(desired);
                        }
                    });
                let pod_view = Arc::clone(&watch_view);
                let pods = watch_forever(&client, Scope::Pods, "pods", &watch_view, move |state| {
                    let pods = pod_rows(state);
                    let mut view = lock(&pod_view);
                    view.pods = pods;
                    view.pods_synced = true;
                });
                let mut parts = vec![nodes.boxed_local(), pods.boxed_local()];
                if settings.service_lb {
                    let (svc_view, svc_lb) = (Arc::clone(&watch_view), lb.clone());
                    parts.push(
                        watch_forever(
                            &client,
                            Scope::Services,
                            "services-watch",
                            &watch_view,
                            move |state| {
                                let rows = service_rows(state);
                                let frontends = {
                                    let mut view = lock(&svc_view);
                                    view.services = rows;
                                    view.services_synced = true;
                                    view.refresh_frontends()
                                };
                                if let (Some(sender), Some(frontends)) = (&svc_lb, frontends) {
                                    let _ = sender.send(frontends);
                                }
                            },
                        )
                        .boxed_local(),
                    );
                    let slice_view = Arc::clone(&watch_view);
                    parts.push(
                        watch_forever(
                            &client,
                            Scope::EndpointSlices,
                            "endpointslices-watch",
                            &watch_view,
                            move |state| {
                                let rows = slice_rows(state);
                                let frontends = {
                                    let mut view = lock(&slice_view);
                                    view.slices = rows;
                                    view.slices_synced = true;
                                    view.refresh_frontends()
                                };
                                if let (Some(sender), Some(frontends)) = (&lb, frontends) {
                                    let _ = sender.send(frontends);
                                }
                            },
                        )
                        .boxed_local(),
                    );
                }
                runtime.block_on(futures::future::join_all(parts));
            })?;
        Ok(view)
    }
}

/// The `flowsdn.io/pod-networks` writer (#328), with its own client: every
/// few seconds, merge-patch each local Pod whose annotation differs from its
/// endpoint (written at ADD, rewritten if removed or edited). A value already
/// tried is not retried for a while; a Pod that is gone (404) is skipped.
fn annotation_loop(view: &Shared, kubeconfig: Option<&Path>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            lock(view)
                .errors
                .insert("annotations".into(), error.to_string());
            return;
        }
    };
    let client = match runtime.block_on(JsonClient::load(kubeconfig, TransportLimits::default()))
    {
        Ok(client) => client,
        Err(error) => {
            lock(view)
                .errors
                .insert("annotations".into(), error.to_string());
            return;
        }
    };
    let mut tried: BTreeMap<(String, String), (String, Instant)> = BTreeMap::new();
    loop {
        std::thread::sleep(ANNOTATE_INTERVAL);
        let patches = lock(view).annotation_patches();
        tried.retain(|_, (_, at)| at.elapsed() < ANNOTATE_RETRY);
        let mut attempted = false;
        let mut failures = Vec::new();
        for patch in patches {
            let key = (patch.namespace.clone(), patch.name.clone());
            if tried.get(&key).is_some_and(|(value, _)| *value == patch.value) {
                continue;
            }
            tried.insert(key, (patch.value.clone(), Instant::now()));
            attempted = true;
            let reply = runtime.block_on(client.send_json(
                http::Method::PATCH,
                &patch.path(),
                Some(&patch.body()),
            ));
            let failure = match reply {
                Ok((200..=299 | 404, _)) => continue,
                Ok((status, body)) => format!(
                    "HTTP {status} {}",
                    body.get("message").and_then(Value::as_str).unwrap_or("")
                ),
                Err(error) => error.to_string(),
            };
            failures.push(format!("{}/{}: {failure}", patch.namespace, patch.name));
        }
        if attempted {
            let mut view = lock(view);
            if failures.is_empty() {
                view.errors.remove("annotations");
            } else {
                view.errors.insert("annotations".into(), failures.join("; "));
            }
        }
    }
}

/// Spec 10 §3.6 datapath init: forwarding on (pods on other nodes reach ours
/// through this host) and `all.rp_filter` 0. Returns the keys that failed.
fn apply_sysctls(root: &Path, ipv6: bool) -> Vec<String> {
    let mut keys = vec![
        "net/ipv4/conf/all/rp_filter",
        "net/ipv4/ip_forward",
        "net/ipv4/conf/all/forwarding",
    ];
    if ipv6 {
        keys.push("net/ipv6/conf/all/forwarding");
    }
    let mut failed = Vec::new();
    for key in keys {
        let value = if key.ends_with("rp_filter") { "0" } else { "1" };
        if let Err(error) = fs::write(root.join(key), value) {
            eprintln!("cannot set {key}={value}: {error}");
            failed.push(format!("{}={value}: {error}", key.replace('/', ".")));
        }
    }
    failed
}

fn node_info(node: &flowsdn_k8s::watch::Node) -> NodeInfo {
    NodeInfo {
        name: node.metadata.name.clone(),
        pod_cidrs: node.pod_cidrs.clone(),
        internal_ips: node.internal_ips.clone(),
    }
}
fn node_rows(state: &WatchState) -> Vec<NodeInfo> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::Node(node) => Some(node_info(node)),
            _ => None,
        })
        .collect()
}
fn pod_rows(state: &WatchState) -> Vec<PodInfo> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::Pod(pod) => Some(PodInfo {
                namespace: pod.metadata.namespace.clone(),
                name: pod.metadata.name.clone(),
                node: pod.node_name.clone(),
                host_network: pod.host_network,
                ips: pod.pod_ips.clone(),
                labels: pod.labels.clone(),
                uid: pod.metadata.uid.clone(),
                workload: flowsdn_hubble::endpoint::workload(
                    pod.owners
                        .iter()
                        .map(|o| (o.kind.as_str(), o.name.as_str(), o.controller)),
                    pod.labels.get("pod-template-hash").map(String::as_str),
                ),
                containers: pod
                    .containers
                    .iter()
                    .map(|c| Container {
                        name: c.name.clone(),
                        id: c.container_id.clone(),
                        init: c.init,
                    })
                    .collect(),
                pod_networks: pod
                    .annotations
                    .get(crate::tagging::POD_NETWORKS)
                    .cloned(),
            }),
            _ => None,
        })
        .collect()
}
fn service_rows(state: &WatchState) -> Vec<ServiceInfo> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::Service(service) => Some(ServiceInfo {
                namespace: service.metadata.namespace.clone(),
                name: service.metadata.name.clone(),
                service_type: service.service_type.clone(),
                cluster_ips: service.cluster_ips.clone(),
                ports: service
                    .ports
                    .iter()
                    .map(|p| services::ServicePort {
                        name: p.name.clone(),
                        protocol: p.protocol.clone(),
                        port: p.port,
                    })
                    .collect(),
            }),
            _ => None,
        })
        .collect()
}
fn slice_rows(state: &WatchState) -> Vec<SliceInfo> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::EndpointSlice(slice) => Some(SliceInfo {
                namespace: slice.metadata.namespace.clone(),
                name: slice.metadata.name.clone(),
                service: slice.service_name.clone(),
                address_type: slice.address_type.clone(),
                endpoints: slice
                    .endpoints
                    .iter()
                    .map(|e| services::Endpoint {
                        addresses: e.addresses.clone(),
                        ready: e.ready,
                        serving: e.serving,
                        terminating: e.terminating,
                    })
                    .collect(),
                ports: slice
                    .ports
                    .iter()
                    .map(|p| services::SlicePort {
                        name: p.name.clone(),
                        protocol: p.protocol.clone(),
                        port: p.port,
                    })
                    .collect(),
            }),
            _ => None,
        })
        .collect()
}

/// Load the socket-lb object and attach it to the cgroup root.
fn load_socket_lb(
    object: &[u8],
    pin_root: Option<&Path>,
    cgroup_root: &Path,
) -> std::result::Result<SocketLb, String> {
    let pins = pin_root.map(|root| root.join("socket-lb"));
    let mut lb = SocketLb::load(Object::Bytes(object), pins.as_deref())
        .map_err(|e| format!("load socket-lb: {e}"))?;
    lb.attach(cgroup_root)
        .map_err(|e| format!("attach socket-lb to {}: {e}", cgroup_root.display()))?;
    Ok(lb)
}

/// Own the socket-LB maps: on every new frontend set (after both lists are
/// complete) and every 30 s, plan from what the kernel holds and apply.
/// Nothing is pruned before the first complete lists.
fn service_loop(receiver: &mpsc::Receiver<Vec<socket::Service>>, view: &Shared, lb: &mut SocketLb) {
    let mut desired: Option<Vec<socket::Service>> = None;
    loop {
        match receiver.recv_timeout(RECONCILE_INTERVAL) {
            Ok(next) => {
                let mut next = next;
                while let Ok(newer) = receiver.try_recv() {
                    next = newer;
                }
                desired = Some(next);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if let Some(services) = &desired {
            let result = program(lb, services);
            let mut view = lock(view);
            match result {
                Ok(ids) => {
                    view.service_ids = ids;
                    view.errors.remove("services");
                }
                Err(error) => {
                    eprintln!("socket LB: {error}");
                    view.errors.insert("services".into(), error);
                }
            }
        }
    }
}
fn program(
    lb: &mut SocketLb,
    services: &[socket::Service],
) -> std::result::Result<BTreeMap<socket::Address, u16>, String> {
    let current = lb.dump().map_err(|e| format!("read LB maps: {e}"))?;
    let want = socket::desired(&current, services)?;
    let ops = socket::plan(&current, &want.maps);
    lb.apply(&ops).map_err(|e| format!("write LB maps: {e}"))?;
    Ok(want.ids)
}

async fn list_nodes(client: &JsonClient) -> std::result::Result<Vec<NodeInfo>, flowsdn_k8s::Error> {
    let mut state = WatchState::new(Scope::Nodes, Limits::default())?;
    relist(client, &Scope::Nodes, &mut state).await?;
    Ok(node_rows(&state))
}

async fn relist(
    client: &JsonClient,
    scope: &Scope,
    state: &mut WatchState,
) -> std::result::Result<(), flowsdn_k8s::Error> {
    state.begin_list();
    let mut token: Option<String> = None;
    loop {
        let query = Query {
            limit: Some(LIST_PAGE),
            continue_token: token.as_deref(),
            ..Query::default()
        };
        let page = match client.list(scope, &query).await {
            Ok(page) => page,
            Err(error) => {
                state.failed();
                return Err(error);
            }
        };
        match state.list_page(&page).await? {
            PageResult::Continue(next) => token = Some(next),
            PageResult::Complete => return Ok(()),
        }
    }
}

/// List, then watch from the list's resourceVersion. A watch the server ends
/// (its 60 s timeout) resumes from the last resourceVersion; any other failure
/// relists after a backoff (1 s doubling to 30 s). Forwarding consumers keep
/// the last good snapshot meanwhile.
async fn watch_forever(
    client: &JsonClient,
    scope: Scope,
    part: &str,
    view: &Shared,
    mut publish: impl FnMut(&WatchState),
) {
    let mut state = match WatchState::new(scope.clone(), Limits::default()) {
        Ok(state) => state,
        Err(error) => {
            lock(view).errors.insert(part.into(), error.to_string());
            return;
        }
    };
    let mut backoff = Duration::from_secs(1);
    loop {
        match cycle(client, &scope, &mut state, &mut publish, view, part).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(error) => {
                state.failed();
                eprintln!("kubernetes {part}: {error}; relisting in {backoff:?}");
                lock(view).errors.insert(part.into(), error.to_string());
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
            }
        }
    }
}
async fn cycle(
    client: &JsonClient,
    scope: &Scope,
    state: &mut WatchState,
    publish: &mut impl FnMut(&WatchState),
    view: &Shared,
    part: &str,
) -> std::result::Result<(), flowsdn_k8s::Error> {
    if state.needs_relist() {
        relist(client, scope, state).await?;
        publish(state);
        lock(view).errors.remove(part);
    }
    let version = state.resource_version().map(str::to_owned);
    let query = Query {
        resource_version: version.as_deref(),
        watch: true,
        ..Query::default()
    };
    let mut frames = client.watch(scope, &query).await?;
    let opened = Instant::now();
    loop {
        let event = match frames.next().await {
            Ok(event) => event,
            Err(error) if error.0 == WATCH_ENDED => {
                // A server that ends watches at once must not make us spin.
                if opened.elapsed() < Duration::from_secs(1) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        state.event(&event).await?;
        publish(state);
    }
}

/// Own the direct routes: persist each route before installing it so a route
/// left by a crash is still pruned, delete routes no longer desired, repair the
/// desired set every 30 s, and never replace a route of another protocol.
fn route_loop(
    receiver: &mpsc::Receiver<Vec<DesiredRoute>>,
    view: &Shared,
    file: &Path,
    skip_unreachable: bool,
) {
    let connector = match Connector::open() {
        Ok(connector) => connector,
        Err(error) => {
            lock(view)
                .errors
                .insert("routes".into(), format!("netlink: {error}"));
            return;
        }
    };
    let mut installed = match load_routes(file) {
        Ok(routes) => routes,
        Err(error) => {
            eprintln!("ignoring unreadable {}: {error}", file.display());
            BTreeSet::new()
        }
    };
    let mut desired: Option<Vec<DesiredRoute>> = None;
    loop {
        match receiver.recv_timeout(RECONCILE_INTERVAL) {
            Ok(next) => {
                let mut next = next;
                while let Ok(newer) = receiver.try_recv() {
                    next = newer;
                }
                desired = Some(next);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        // Nothing is pruned before the first complete Node list.
        if let Some(desired) = &desired {
            let (states, error) =
                reconcile(&connector, desired, &mut installed, file, skip_unreachable);
            let mut view = lock(view);
            view.routes = states;
            if let Some(error) = &error {
                crate::events::node(Warning, "DirectRouteFailed", error.clone());
            }
            match error {
                Some(error) => view.errors.insert("routes".into(), error),
                None => view.errors.remove("routes"),
            };
        }
    }
}

fn key(route: &DesiredRoute) -> Key {
    (route.destination, route.prefix, route.gateway)
}

fn reconcile(
    connector: &Connector,
    desired: &[DesiredRoute],
    installed: &mut BTreeSet<Key>,
    file: &Path,
    skip_unreachable: bool,
) -> (BTreeMap<String, (DesiredRoute, String)>, Option<String>) {
    let mut failures = Vec::new();
    let want: BTreeSet<Key> = desired.iter().map(key).collect();
    let stale: Vec<Key> = installed.difference(&want).copied().collect();
    for (destination, prefix, gateway) in stale {
        match connector.delete_gateway_route(destination, prefix, gateway) {
            Ok(()) => {
                installed.remove(&(destination, prefix, gateway));
            }
            Err(error) => failures.push(format!(
                "delete {} via {gateway}: {error}",
                cidr_text(destination, prefix)
            )),
        }
    }
    let mut states = BTreeMap::new();
    for route in desired {
        let cidr = cidr_text(route.destination, route.prefix);
        let state = match install(connector, route, installed, file, skip_unreachable) {
            Ok(state) => state,
            Err(error) => {
                failures.push(format!("{cidr} via {}: {error}", route.gateway));
                format!("error: {error}")
            }
        };
        states.insert(cidr, (route.clone(), state));
    }
    if let Err(error) = save_routes(file, installed) {
        failures.push(format!("persist {}: {error}", file.display()));
    }
    let error = (!failures.is_empty()).then(|| failures.join("; "));
    (states, error)
}

fn install(
    connector: &Connector,
    route: &DesiredRoute,
    installed: &mut BTreeSet<Key>,
    file: &Path,
    skip_unreachable: bool,
) -> Result<String> {
    // Spec 10 §3.2.3 step 1: the node must be directly reachable.
    let (gateway, _) = connector.lookup(route.gateway)?;
    if let Some(gateway) = gateway.filter(|g| !g.is_unspecified() && *g != route.gateway) {
        if skip_unreachable {
            return Ok(format!(
                "skipped: route to {} uses gateway {gateway}",
                route.gateway
            ));
        }
        return Err(format!(
            "route to destination {} contains gateway {gateway}, must be directly reachable. \
             Add direct-routing-skip-unreachable to skip unreachable routes",
            route.gateway
        )
        .into());
    }
    // Spec 10 §5.2: never clobber a static/boot/dhcp/ra route to the prefix.
    let existing = connector.main_routes_to(route.destination, route.prefix)?;
    if let Some(other) = existing.iter().find(|r| r.protocol != RTPROT_KERNEL) {
        return Err(format!("route conflict with proto {}", other.protocol).into());
    }
    if installed.insert(key(route)) {
        save_routes(file, installed)?;
    }
    connector.replace_gateway_route(route.destination, route.prefix, route.gateway)?;
    Ok("installed".into())
}

const RTPROT_KERNEL: u8 = 2;

fn load_routes(file: &Path) -> Result<BTreeSet<Key>> {
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error.into()),
    };
    let value: Value = serde_json::from_slice(&bytes)?;
    let mut routes = BTreeSet::new();
    for row in value.as_array().ok_or("routes file must be an array")? {
        let text = |key: &str| -> Result<&str> {
            row.get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("route without {key}").into())
        };
        let (ip, prefix) = text("destination")?
            .split_once('/')
            .ok_or("route destination must be a CIDR")?;
        routes.insert((ip.parse()?, prefix.parse()?, text("gateway")?.parse()?));
    }
    Ok(routes)
}
fn save_routes(file: &Path, routes: &BTreeSet<Key>) -> Result<()> {
    let rows: Vec<_> = routes
        .iter()
        .map(|(ip, prefix, gateway)| {
            json!({"destination":cidr_text(*ip, *prefix),"gateway":gateway.to_string()})
        })
        .collect();
    let temporary = file.with_extension("json.tmp");
    let mut output = fs::File::create(&temporary)?;
    output.write_all(&serde_json::to_vec(&rows)?)?;
    output.sync_all()?;
    fs::rename(&temporary, file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctls_follow_the_enabled_families() {
        let root = std::env::temp_dir().join(format!("flowsdn-sysctl-{}", std::process::id()));
        for dir in ["net/ipv4/conf/all", "net/ipv6/conf/all"] {
            fs::create_dir_all(root.join(dir)).expect("dir");
        }
        assert!(apply_sysctls(&root, false).is_empty());
        let read = |key: &str| fs::read_to_string(root.join(key)).ok();
        assert_eq!(read("net/ipv4/ip_forward").as_deref(), Some("1"));
        assert_eq!(read("net/ipv4/conf/all/forwarding").as_deref(), Some("1"));
        assert_eq!(read("net/ipv4/conf/all/rp_filter").as_deref(), Some("0"));
        assert_eq!(read("net/ipv6/conf/all/forwarding"), None);
        assert!(apply_sysctls(&root, true).is_empty());
        assert_eq!(read("net/ipv6/conf/all/forwarding").as_deref(), Some("1"));
        let _ = fs::remove_dir_all(&root);
        assert_eq!(apply_sysctls(&root, true).len(), 4);
    }

    #[test]
    fn persisted_routes_round_trip() {
        let dir = std::env::temp_dir().join(format!("flowsdn-routes-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join(ROUTES_FILE);
        assert!(load_routes(&file).expect("absent").is_empty());
        let routes: BTreeSet<Key> = [
            (
                "10.173.0.0".parse().expect("ip"),
                16,
                "192.0.2.173".parse().expect("ip"),
            ),
            (
                "f00d::aad:0:0:0".parse().expect("ip"),
                96,
                "2001:db8::173".parse().expect("ip"),
            ),
        ]
        .into_iter()
        .collect();
        save_routes(&file, &routes).expect("save");
        assert_eq!(load_routes(&file).expect("load"), routes);
        fs::write(&file, b"{}").expect("corrupt");
        assert!(load_routes(&file).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
