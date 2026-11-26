//! The Kubernetes controller thread: Node, cluster Pod, Service and
//! EndpointSlice ListWatch through flowsdn-k8s (relist with backoff),
//! publishing into the shared view; a route thread that owns the direct node
//! routes (spec 10 §3.2.3, §5.2); a services thread that owns the
//! socket-LB maps (spec 05 §3.4, §3.8); and an identities thread that holds
//! a FlowsdnIdentity for each local Pod's labels (spec 03 §3.3), fed by
//! Namespace and FlowsdnIdentity watches; and a policy thread that keeps the
//! endpoint policy maps from the NetworkPolicy watch (#292, ADR-0021) and,
//! with the host firewall on, the FlowsdnClusterwideNetworkPolicy watch
//! (#379).
use super::*;
use crate::events::Type::Warning;
use crate::identity::{self, Allocator, Outcome};
use crate::services::{self, ServiceInfo, SliceInfo};
use flowsdn_bpf_abi::policy::HOST_PODS;
use flowsdn_bpf_loader::kernel::{Object, PolicyMaps, socket_lb::SocketLb};
use flowsdn_connector::Connector;
use flowsdn_k8s::{
    client::{IDENTITIES_PATH, JsonClient, Query, TransportLimits, WATCH_ENDED},
    watch::{Limits, PageResult, Resource, Scope, WatchState},
};
use flowsdn_lb::socket;
use futures::FutureExt;
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

#[path = "kubernetes_lb.rs"]
mod lb;
#[path = "uplinks_monitor.rs"]
mod uplinks_monitor;

const LIST_PAGE: u32 = 500;
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// How long a 404 keeps a watch retrying every second.
const NOT_FOUND_FLAT: Duration = Duration::from_secs(60);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ROUTES_FILE: &str = "direct-routes.json";
const ANNOTATE_INTERVAL: Duration = Duration::from_secs(2);
/// How often an unchanged "waiting for CRDs" is logged again (#337).
const CRD_WAIT_LOG: Duration = Duration::from_secs(15);
const ANNOTATE_RETRY: Duration = Duration::from_secs(30);
const IDENTITY_INTERVAL: Duration = Duration::from_secs(1);
const POLICY_INTERVAL: Duration = Duration::from_secs(1);
/// The policy maps are compared with the kernel at least this often.
const POLICY_RESYNC: Duration = Duration::from_secs(60);
/// The host firewall only remembers flows on a new uplink for this long
/// before it enforces there (#379), so connections the node already has
/// (kubelet, the API server, sessions) are known and keep their replies.
const HOST_LEARNING: Duration = Duration::from_secs(60);

pub struct Controller {
    runtime: tokio::runtime::Runtime,
    client: JsonClient,
    settings: Settings,
    routes_file: PathBuf,
    state_dir: PathBuf,
    derive: Derive,
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
            state_dir: state_dir.to_path_buf(),
            derive: Derive::default(),
        })
    }
    /// The families whose pools are `auto` here: other Nodes without a pod
    /// CIDR of that family get the derived one too (#296, option C).
    pub fn derive_pod_cidrs(&mut self, v4: bool, v6: bool) {
        self.derive = Derive { v4, v6 };
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
                crate::log::logln!(
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
    /// With network-policy on and the endpoint policy maps given, a policy
    /// thread keeps them from the NetworkPolicies; `gateways` are this
    /// node's router addresses (the host identity, with its InternalIPs).
    pub fn spawn(
        self,
        ipv6: bool,
        socket_lb: Option<&[u8]>,
        pin_root: Option<&Path>,
        policy: Option<(PolicyMaps, Vec<IpAddr>)>,
    ) -> Result<Shared> {
        let view: Shared = Arc::new(Mutex::new(View {
            local_node: self.settings.node_name.clone(),
            direct_routes: self.settings.auto_direct_node_routes,
            service_lb: self.settings.service_lb,
            identity: self.settings.identity_allocation,
            network_policy: self.settings.network_policy,
            flowsdn_policy: self.settings.flowsdn_policy,
            policy_audit: self.settings.policy_audit,
            host_firewall: self.settings.host_firewall,
            cluster_name: self.settings.cluster_name.clone(),
            lb_ipam: self.settings.lb_ipam_on(),
            l2_announcements: self.settings.l2_on(),
            local_redirect: self.settings.local_redirect_on(),
            egress_gateway: self.settings.egress_gateway,
            derive: self.derive,
            node_config: self.settings.node_config.clone(),
            ..View::default()
        }));
        let host_firewall = self.settings.host_firewall != HostFirewall::Off;
        if let Some((mut maps, gateways)) = policy.filter(|_| {
            self.settings.network_policy || self.settings.flowsdn_policy || host_firewall
        }) {
            let policy_view = Arc::clone(&view);
            let wake = Arc::new(crate::dns_proxy::Wake::default());
            // The DNS proxy (#536) with the flowsdn policy kinds.
            let answerer = self
                .settings
                .dns_proxy
                .clone()
                .filter(|_| self.settings.flowsdn_policy)
                .and_then(|settings| start_dns_proxy(&view, &wake, settings, ipv6));
            std::thread::Builder::new()
                .name("flowsdn-policy".into())
                .spawn(move || {
                    policy_loop(
                        &policy_view,
                        &mut maps,
                        &gateways,
                        &wake,
                        answerer.as_deref(),
                    );
                })?;
        }
        let failed = apply_sysctls(Path::new("/proc/sys"), ipv6);
        if !failed.is_empty() {
            crate::events::node(Warning, "SysctlFailed", failed.join("; "));
            lock(&view)
                .errors
                .insert("sysctl".into(), failed.join("; "));
        }
        if self.settings.l2_neigh_discovery {
            // No fallback (#132): without managed neighbors the agent stops.
            crate::neighbors::probe()?;
            let neighbor_view = Arc::clone(&view);
            std::thread::Builder::new()
                .name("flowsdn-neighbors".into())
                .spawn(move || crate::neighbors::run(&neighbor_view))?;
        }
        {
            let uplink_view = Arc::clone(&view);
            let uplink_settings = self.settings.uplinks.clone();
            let state_dir = self.state_dir.clone();
            std::thread::Builder::new()
                .name("flowsdn-uplinks".into())
                .spawn(move || {
                    uplinks_monitor::monitor_loop(&uplink_view, &uplink_settings, &state_dir);
                })?;
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
            Some(object) => match load_socket_lb(
                object,
                pin_root,
                &self.settings.cgroup_root,
                self.settings.lb_dsr_dispatch,
            ) {
                Ok(lb) => {
                    let (sender, receiver) = mpsc::channel();
                    let lb_view = Arc::clone(&view);
                    let uplink = UplinkSettings {
                        node_port: self.settings.node_port,
                        terminate_tcp: self.settings.terminate_tcp,
                        masquerade: self
                            .settings
                            .bpf_masquerade
                            .then(|| self.settings.non_masquerade.clone()),
                        gateway64: self.settings.gateway64,
                        nat46x64: self.settings.nat46x64,
                        egress_gateway: self.settings.egress_gateway,
                    };
                    std::thread::Builder::new()
                        .name("flowsdn-services".into())
                        .spawn(move || {
                            let mut lb = lb;
                            service_loop(&receiver, &lb_view, &mut lb, &uplink);
                        })?;
                    Some(sender)
                }
                Err(error) => {
                    crate::log::logln!("socket LB unavailable: {error}");
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
        if self.settings.identity_allocation {
            let identity_view = Arc::clone(&view);
            let kubeconfig = self.settings.kubeconfig.clone();
            std::thread::Builder::new()
                .name("flowsdn-identity".into())
                .spawn(move || identity_loop(&identity_view, kubeconfig.as_deref()))?;
        }
        if self.settings.lb_ipam_on() {
            let ipam_view = Arc::clone(&view);
            let kubeconfig = self.settings.kubeconfig.clone();
            let identity = self.settings.node_name.clone();
            std::thread::Builder::new()
                .name("flowsdn-lb-ipam".into())
                .spawn(move || lb::ipam_loop(&ipam_view, kubeconfig.as_deref(), &identity))?;
        }
        if self.settings.l2_on() {
            let l2_view = Arc::clone(&view);
            std::thread::Builder::new()
                .name("flowsdn-l2".into())
                .spawn(move || lb::announce_loop(&l2_view))?;
            let lease_view = Arc::clone(&view);
            let kubeconfig = self.settings.kubeconfig.clone();
            let identity = self.settings.node_name.clone();
            std::thread::Builder::new()
                .name("flowsdn-l2-lease".into())
                .spawn(move || {
                    lb::l2_lease_loop(&lease_view, kubeconfig.as_deref(), &identity);
                })?;
        }
        if let (true, Some(sender)) = (self.settings.local_redirect_on(), &lb) {
            let redirect_view = Arc::clone(&view);
            let kubeconfig = self.settings.kubeconfig.clone();
            let sender = sender.clone();
            std::thread::Builder::new()
                .name("flowsdn-lrp".into())
                .spawn(move || lb::redirect_loop(&redirect_view, &sender, kubeconfig.as_deref()))?;
        }
        if self.settings.endpoint_crd || self.settings.node_crd {
            let crd_view = Arc::clone(&view);
            let kubeconfig = self.settings.kubeconfig.clone();
            let (endpoints, node) = (self.settings.endpoint_crd, self.settings.node_crd);
            std::thread::Builder::new()
                .name("flowsdn-crds".into())
                .spawn(move || crd_loop(&crd_view, kubeconfig.as_deref(), endpoints, node))?;
        }
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
                    derive,
                    ..
                } = self;
                let (lb_ipam_on, l2_on) = (settings.lb_ipam_on(), settings.l2_on());
                let redirect_on = settings.local_redirect_on();
                let egress_on = settings.egress_gateway;
                // flowsdn.io watchers start once their CRDs exist (#337).
                let required: BTreeSet<String> = settings
                    .required_crds()
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                let gate =
                    wait_for_crds(&client, &required, settings.crd_wait_timeout, &watch_view)
                        .boxed_local()
                        .shared();
                let local = settings.node_name;
                let node_view = Arc::clone(&watch_view);
                let node_lb = lb.clone();
                let mut sent: Option<Vec<DesiredRoute>> = None;
                let mut reported: Vec<String> = Vec::new();
                let mut addresses: Option<Vec<(String, Vec<IpAddr>)>> = None;
                let nodes =
                    watch_forever(&client, Scope::Nodes, "nodes", &watch_view, move |state| {
                        let nodes = node_rows(state);
                        let RoutePlan {
                            routes: desired,
                            collisions,
                        } = desired_routes(&local, &nodes, derive);
                        if collisions != reported {
                            let text = collisions.join("; ");
                            let mut view = lock(&node_view);
                            if collisions.is_empty() {
                                view.errors.remove("pod-cidrs");
                            } else {
                                crate::events::node(Warning, "PodCIDRCollision", text.clone());
                                view.errors.insert("pod-cidrs".into(), text);
                            }
                            reported = collisions;
                        }
                        // NodePort frontends follow the nodes' InternalIPs.
                        let current: Vec<_> = nodes
                            .iter()
                            .map(|n| (n.name.clone(), n.internal_ips.clone()))
                            .collect();
                        let moved = addresses.as_ref() != Some(&current);
                        addresses = Some(current);
                        let frontends = {
                            let mut view = lock(&node_view);
                            view.nodes = nodes;
                            view.nodes_synced = true;
                            if moved {
                                view.refresh_frontends()
                            } else {
                                None
                            }
                        };
                        if let (Some(sender), Some(frontends)) = (&node_lb, frontends) {
                            let _ = sender.send(frontends);
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
                let host_firewall = settings.host_firewall != HostFirewall::Off;
                if settings.identity_allocation
                    || settings.network_policy
                    || settings.flowsdn_policy
                    || host_firewall
                    || settings.egress_gateway
                {
                    let ns_view = Arc::clone(&watch_view);
                    parts.push(
                        watch_forever(
                            &client,
                            Scope::Namespaces,
                            "namespaces",
                            &watch_view,
                            move |state| {
                                let rows = namespace_rows(state);
                                let mut view = lock(&ns_view);
                                view.namespaces = rows;
                                view.namespaces_synced = true;
                            },
                        )
                        .boxed_local(),
                    );
                }
                if settings.network_policy {
                    let np_view = Arc::clone(&watch_view);
                    parts.push(
                        watch_forever(
                            &client,
                            Scope::NetworkPolicies,
                            "networkpolicies-watch",
                            &watch_view,
                            move |state| {
                                let rows = policy_rows(state);
                                let mut view = lock(&np_view);
                                view.network_policies = rows;
                                view.policies_synced = true;
                            },
                        )
                        .boxed_local(),
                    );
                }
                if settings.flowsdn_policy {
                    let pod_policy_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::PodPolicies,
                            "pod-policies",
                            &watch_view,
                            move |state| {
                                let rows = pod_policy_rows(state);
                                let mut view = lock(&pod_policy_view);
                                view.pod_policies = rows;
                                view.pod_policies_synced = true;
                            },
                        ),
                    ));
                }
                if host_firewall || settings.flowsdn_policy {
                    let cw_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::ClusterwidePolicies,
                            "host-policies",
                            &watch_view,
                            move |state| {
                                let rows = clusterwide_rows(state);
                                let mut view = lock(&cw_view);
                                view.clusterwide_policies = rows;
                                view.clusterwide_synced = true;
                            },
                        ),
                    ));
                }
                if settings.identity_allocation {
                    let id_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::Identities,
                            "identities-watch",
                            &watch_view,
                            move |state| {
                                let rows = identity_rows(state);
                                let mut view = lock(&id_view);
                                view.identity_objects = rows;
                                view.identities_synced = true;
                            },
                        ),
                    ));
                }
                if settings.service_lb {
                    let (svc_view, svc_lb) = (Arc::clone(&watch_view), lb.clone());
                    let (maglev, lb_mode, nat46x64, external_clusterip) = (
                        settings.maglev,
                        settings.lb_mode,
                        settings.nat46x64,
                        settings.external_clusterip,
                    );
                    parts.push(
                        watch_forever(
                            &client,
                            Scope::Services,
                            "services-watch",
                            &watch_view,
                            move |state| {
                                let rows = service_rows(
                                    state,
                                    maglev,
                                    lb_mode,
                                    nat46x64,
                                    external_clusterip,
                                );
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
                if lb_ipam_on {
                    let pool_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::LbIpPools,
                            "lb-ip-pools",
                            &watch_view,
                            move |state| {
                                let rows = object_rows(state);
                                let mut view = lock(&pool_view);
                                view.lb_pools = rows;
                                view.lb_pools_synced = true;
                            },
                        ),
                    ));
                }
                if l2_on {
                    let l2_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::L2Policies,
                            "l2-policies",
                            &watch_view,
                            move |state| {
                                let rows = object_rows(state);
                                let mut view = lock(&l2_view);
                                view.l2_policies = rows;
                                view.l2_policies_synced = true;
                            },
                        ),
                    ));
                }
                if egress_on {
                    let egress_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::EgressPolicies,
                            "egress-gateway-policies",
                            &watch_view,
                            move |state| {
                                let rows = object_rows(state);
                                let mut view = lock(&egress_view);
                                view.egress_policies = rows;
                                view.egress_policies_synced = true;
                            },
                        ),
                    ));
                }
                if redirect_on {
                    let redirect_view = Arc::clone(&watch_view);
                    parts.push(gated(
                        gate.clone(),
                        watch_forever(
                            &client,
                            Scope::RedirectPolicies,
                            "local-redirect-policies",
                            &watch_view,
                            move |state| {
                                let rows = object_rows(state);
                                let mut view = lock(&redirect_view);
                                view.redirect_policies = rows;
                                view.redirect_policies_synced = true;
                            },
                        ),
                    ));
                }
                runtime.block_on(futures::future::join_all(parts));
            })?;
        Ok(view)
    }
}

/// The identities thread (spec 03 §3.3), with its own client: once the Pod,
/// Namespace and FlowsdnIdentity lists are complete, every second reconcile
/// the local Pods' label sets against the identity list, send the creates
/// and heartbeat removals, and publish each Pod's identity for the API.
/// Remote Pods get the oldest object with their labels (what their node
/// converges on) or a well-known identity.
fn identity_loop(view: &Shared, kubeconfig: Option<&Path>) {
    let started = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|runtime| {
            let client = runtime
                .block_on(JsonClient::load(kubeconfig, TransportLimits::default()))
                .map_err(|e| e.to_string())?;
            let filter =
                flowsdn_identity::filter::LabelFilter::identity(&[]).map_err(|e| e.to_string())?;
            Ok((runtime, client, filter))
        });
    let (runtime, client, filter) = match started {
        Ok(parts) => parts,
        Err(error) => {
            lock(view).errors.insert("identities".into(), error);
            return;
        }
    };
    let mut allocator = Allocator::default();
    loop {
        std::thread::sleep(IDENTITY_INTERVAL);
        let (sets, objects, cluster) = {
            let view = lock(view);
            if !view.identities_synced {
                continue;
            }
            let sets = view.pod_label_sets(&filter);
            if sets.is_empty() && !(view.pods_synced && view.namespaces_synced) {
                continue;
            }
            (
                sets,
                view.identity_objects.clone(),
                view.cluster_name.clone(),
            )
        };
        let desired: BTreeMap<String, flowsdn_identity::labels::Labels> = sets
            .iter()
            .filter(|(_, local, _)| *local)
            .map(|(_, _, labels)| (labels.canonical_key(), labels.clone()))
            .collect();
        let start = (uuid::Uuid::new_v4().as_u128() & 0xFFFF_FFFF) as u32;
        let actions = allocator.reconcile(&desired, &objects, &cluster, start);
        let mut failures = Vec::new();
        for action in actions {
            let (method, key) = match &action {
                identity::Action::Create { labels, .. } => {
                    (http::Method::POST, Some(labels.canonical_key()))
                }
                identity::Action::Acquire { .. } => (http::Method::PUT, None),
            };
            let reply = runtime.block_on(client.send_json(
                method,
                &action.path(IDENTITIES_PATH),
                Some(&action.body()),
            ));
            let outcome = match &reply {
                Ok((200..=299, _)) => Outcome::Done,
                Ok((409, _)) => Outcome::Conflict,
                Ok((status, body)) => {
                    failures.push(format!(
                        "{} {}: HTTP {status} {}",
                        action.id(),
                        if key.is_some() { "create" } else { "update" },
                        body.get("message").and_then(Value::as_str).unwrap_or("")
                    ));
                    Outcome::Failed
                }
                Err(error) => {
                    failures.push(format!("{}: {error}", action.id()));
                    Outcome::Failed
                }
            };
            if let Some(key) = key {
                allocator.created(&key, action.id(), outcome);
            }
        }
        let by_key = identity::oldest(&objects);
        let mut pods = BTreeMap::new();
        let mut identities: BTreeMap<u32, Vec<String>> = objects
            .iter()
            .filter_map(|o| Some((o.id, identity::label_strings(o.labels.as_ref()?))))
            .collect();
        for (pod, local, labels) in &sets {
            let key = labels.canonical_key();
            let id = if *local { allocator.get(&key) } else { None }
                .or_else(|| identity::well_known(labels, &cluster))
                .or_else(|| by_key.get(&key).map(|o| o.id));
            if let Some(id) = id {
                pods.insert(pod.clone(), id);
                identities
                    .entry(id)
                    .or_insert_with(|| identity::label_strings(labels));
            }
        }
        let waiting = allocator.waiting(&desired);
        let mut view = lock(view);
        view.pod_identities = pods;
        view.identities = identities;
        view.identities_waiting = waiting;
        if failures.is_empty() {
            view.errors.remove("identities");
        } else {
            view.errors.insert("identities".into(), failures.join("; "));
        }
    }
}

/// The `flowsdn.io/pod-networks` (#328) and `network-status` (#371) writer,
/// with its own client: every few seconds, merge-patch each local Pod whose
/// annotations differ from its endpoint (written at ADD, rewritten if removed
/// or edited). A value already tried is not retried for a while, except after
/// a failed precondition (409); a Pod that is gone (404) is skipped.
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
    let client = match runtime.block_on(JsonClient::load(kubeconfig, TransportLimits::default())) {
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
            let value = patch.annotations_text();
            if tried.get(&key).is_some_and(|(tried, _)| *tried == value) {
                continue;
            }
            tried.insert(key, (value, Instant::now()));
            attempted = true;
            let reply = runtime.block_on(client.send_json(
                http::Method::PATCH,
                &patch.path(),
                Some(&patch.body()),
            ));
            let failure = match reply {
                Ok((200..=299 | 404, _)) => continue,
                // A precondition (UID or resourceVersion) failed: another
                // writer got there first; retry on the next tick's view.
                Ok((409, _)) => {
                    tried.remove(&(patch.namespace.clone(), patch.name.clone()));
                    continue;
                }
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
                view.errors
                    .insert("annotations".into(), failures.join("; "));
            }
        }
    }
}

/// The FlowsdnEndpoint and FlowsdnNode writers (#332,
/// [`crate::endpoint_crd`], [`crate::node_crd`]), with their own client:
/// every few seconds, bring each local Pod's FlowsdnEndpoint and this
/// node's FlowsdnNode to the view. A write the server refuses is a
/// `flowsdn-endpoints` (and a Warning Event on the Pod) or `flowsdn-node`
/// part error.
fn crd_loop(view: &Shared, kubeconfig: Option<&Path>, endpoints: bool, node: bool) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            lock(view)
                .errors
                .insert("flowsdn-endpoints".into(), error.to_string());
            return;
        }
    };
    let client = match runtime.block_on(JsonClient::load(kubeconfig, TransportLimits::default())) {
        Ok(client) => client,
        Err(error) => {
            lock(view)
                .errors
                .insert("flowsdn-endpoints".into(), error.to_string());
            return;
        }
    };
    let mut writer = crate::endpoint_crd::Writer::default();
    let mut node_writer = crate::node_crd::NodeWriter::default();
    let bootid = crate::node_crd::boot_id();
    let mut said_unserved = false;
    loop {
        std::thread::sleep(ANNOTATE_INTERVAL);
        let mut send = |method: http::Method, path: &str, body: Option<&Value>| {
            runtime
                .block_on(client.send_json(method, path, body))
                .map_err(|e| e.to_string())
        };
        if node {
            let desired = crate::node_crd::desired(&lock(view), &bootid);
            let result = node_writer.sync(desired.as_ref(), &mut send);
            let mut view = lock(view);
            match result {
                Ok(served) => {
                    view.errors.remove("flowsdn-node");
                    view.node_crd_status = json!({"served": served});
                }
                Err(error) => {
                    view.errors.insert("flowsdn-node".into(), error);
                }
            }
        }
        if !endpoints {
            continue;
        }
        let desired = crate::endpoint_crd::desired(&lock(view));
        let outcome = writer.sync(&desired, &mut send);
        if outcome.unserved && !said_unserved {
            crate::log::logln!(
                "FlowsdnEndpoint is not served (its CRD is not applied); retrying every minute"
            );
        }
        said_unserved = outcome.unserved;
        for ((namespace, name), failure) in &outcome.failures {
            let uid = desired
                .get(&(namespace.clone(), name.clone()))
                .map(|d| d.pod_uid.clone())
                .unwrap_or_default();
            crate::events::pod(
                namespace,
                name,
                &uid,
                Warning,
                "FlowsdnEndpointFailed",
                format!("FlowsdnEndpoint {namespace}/{name}: {failure}"),
            );
        }
        let mut view = lock(view);
        view.endpoint_crd_status = json!({
            "served": !outcome.unserved,
            "objects": writer.held(),
        });
        if outcome.failures.is_empty() {
            view.errors.remove("flowsdn-endpoints");
        } else {
            let text: Vec<String> = outcome
                .failures
                .iter()
                .map(|((ns, name), f)| format!("{ns}/{name}: {f}"))
                .collect();
            view.errors
                .insert("flowsdn-endpoints".into(), text.join("; "));
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
            crate::log::logln!("cannot set {key}={value}: {error}");
            failed.push(format!("{}={value}: {error}", key.replace('/', ".")));
        }
    }
    failed
}

fn node_info(node: &flowsdn_k8s::watch::Node) -> NodeInfo {
    NodeInfo {
        name: node.metadata.name.clone(),
        uid: node.metadata.uid.clone(),
        pod_cidrs: node.pod_cidrs.clone(),
        internal_ips: node.internal_ips.clone(),
        labels: node.labels.clone(),
        ready: node.ready,
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
                service_account: pod.service_account.clone(),
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
                pod_networks: pod.annotations.get(crate::tagging::POD_NETWORKS).cloned(),
                network_status: pod.annotations.get(crate::tagging::NETWORK_STATUS).cloned(),
                network_status_oversized: pod
                    .oversized
                    .iter()
                    .any(|key| key == crate::tagging::NETWORK_STATUS),
                resource_version: pod.metadata.resource_version.clone(),
                named_ports: pod.named_ports.clone(),
                ports: pod.ports.clone(),
                ready: pod.ready,
            }),
            _ => None,
        })
        .collect()
}
fn namespace_rows(state: &WatchState) -> BTreeMap<String, BTreeMap<String, String>> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::Namespace(ns) => Some((ns.metadata.name.clone(), ns.labels.clone())),
            _ => None,
        })
        .collect()
}
fn pod_policy_rows(state: &WatchState) -> Vec<Value> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::PodPolicy(p) => Some(p.object.clone()),
            _ => None,
        })
        .collect()
}
fn clusterwide_rows(state: &WatchState) -> Vec<Value> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::ClusterwidePolicy(p) => Some(p.object.clone()),
            _ => None,
        })
        .collect()
}
/// The FlowsdnLoadBalancerIPPool or FlowsdnL2AnnouncementPolicy objects.
fn object_rows(state: &WatchState) -> Vec<Value> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::LbIpPool(p)
            | Resource::L2Policy(p)
            | Resource::RedirectPolicy(p)
            | Resource::EgressPolicy(p) => Some(p.object.clone()),
            _ => None,
        })
        .collect()
}
fn policy_rows(state: &WatchState) -> Vec<Value> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::NetworkPolicy(p) => Some(p.object.clone()),
            _ => None,
        })
        .collect()
}

/// The policy thread (#292, ADR-0021): once the lists it needs are complete,
/// compile the view every second; when the result changes (or a minute has
/// passed) bring the maps to it, comparing with what the kernel holds.
/// Writes come before removals, so a change never passes through a state
/// that allows less than both ends (new entries, then ipcache and
/// enforcement, then stale entries).
fn policy_loop(
    view: &Shared,
    maps: &mut PolicyMaps,
    gateways: &[IpAddr],
    wake: &crate::dns_proxy::Wake,
    answerer: Option<&crate::dns_proxy::Answerer>,
) {
    let mut applied: Option<(crate::policy::Desired, Instant)> = None;
    // When the host firewall first wanted each uplink (#379): it only
    // learns flows for HOST_LEARNING before enforcing there.
    let mut wanted: BTreeMap<u32, Instant> = BTreeMap::new();
    // The host firewall's last announced state (#384).
    let mut announced: Option<String> = None;
    loop {
        // A DNS answer waiting for its addresses (#536) wakes the pass early.
        let requests = wake.wait(POLICY_INTERVAL);
        let host_firewall = lock(view).host_firewall != HostFirewall::Off;
        let (uplinks, host_addresses) = if host_firewall {
            match host_scope() {
                Ok((mut found, addresses)) => {
                    let mut view = lock(view);
                    view.errors.remove("host-firewall");
                    found.extend(uplink_ports(&view));
                    (found, addresses)
                }
                Err(error) => {
                    lock(view).errors.insert("host-firewall".into(), error);
                    (BTreeMap::new(), Vec::new())
                }
            }
        } else {
            (BTreeMap::new(), Vec::new())
        };
        // Local Pods' traffic to the host learns under HOST_PODS (#384).
        wanted.retain(|index, _| {
            (host_firewall && *index == HOST_PODS) || uplinks.values().any(|i| i == index)
        });
        if host_firewall {
            wanted.entry(HOST_PODS).or_insert_with(Instant::now);
        }
        for index in uplinks.values() {
            wanted.entry(*index).or_insert_with(Instant::now);
        }
        let desired = {
            let mut view = lock(view);
            view.host_interfaces = uplinks;
            view.host_addresses = host_addresses;
            view.host_learning = wanted
                .iter()
                .filter(|(_, since)| since.elapsed() < HOST_LEARNING)
                .map(|(index, _)| *index)
                .collect();
            if !view.policy_lists_ready() {
                continue;
            }
            // Answers whose TTL ran out allow nothing more (#536).
            view.fqdn.expire(crate::dns_proxy::now());
            crate::policy::compile(&view, gateways)
        };
        if applied
            .as_ref()
            .is_some_and(|(last, at)| *last == desired && at.elapsed() < POLICY_RESYNC)
        {
            wake.applied(requests);
            continue;
        }
        let result = apply_policy(maps, &desired);
        if result.is_ok() {
            // The proxy judges by what the maps now hold, and answers held
            // for this pass are released.
            if let Some(answerer) = answerer {
                answerer.publish(&desired.dns);
            }
            wake.applied(requests);
        }
        let mut view = lock(view);
        if let Some(answerer) = answerer {
            view.dns_status = answerer.status(view.dns_proxy_port);
        }
        view.policy_status = desired.status();
        view.applied_policies = desired.applied.clone();
        match result {
            Ok(()) if desired.problems.is_empty() => {
                view.errors.remove("policy");
            }
            Ok(()) => {
                view.errors
                    .insert("policy".into(), desired.problems.join("; "));
            }
            Err(error) => {
                view.errors.insert("policy".into(), error.clone());
                drop(view);
                crate::log::logln!("policy maps: {error}");
                continue;
            }
        }
        drop(view);
        let summary = crate::policy::host_summary(&desired.host);
        if summary != announced {
            if let Some(text) = &summary {
                crate::log::logln!("{text}");
                crate::events::node(crate::events::Type::Normal, "HostFirewall", text.clone());
            }
            announced = summary;
        }
        applied = Some((desired, Instant::now()));
    }
}

/// Start the DNS proxy (#536): its routing (the proxy mark's rule and local
/// route, ADR-0024), its sockets on `tofqdns-proxy-port`, and the hold that
/// puts an answer in the view's FQDN cache and waits for the policy pass.
/// A failure is the view's `dns-proxy` error and an Event; DNS rules then
/// allow nothing (the compiler fails closed without a port).
fn start_dns_proxy(
    view: &Shared,
    wake: &Arc<crate::dns_proxy::Wake>,
    settings: crate::dns_proxy::Settings,
    ipv6: bool,
) -> Option<Arc<crate::dns_proxy::Answerer>> {
    lock(view).fqdn = flowsdn_l7::dns::cache::Cache::new(settings.limits);
    let cache_view = Arc::clone(view);
    let insert = move |names: &[String], ips: &[IpAddr], ttl: u32| {
        lock(&cache_view)
            .fqdn
            .insert(names, ips, ttl, crate::dns_proxy::now())
    };
    let answerer = crate::dns_proxy::Answerer::new(crate::dns_proxy::hold(
        insert,
        Arc::clone(wake),
        settings.max_delay,
    ));
    let started = proxy_routing(ipv6).and_then(|()| {
        let policy: Arc<dyn flowsdn_l7::dns::Policy> = answerer.clone();
        flowsdn_l7::dns::proxy::DnsProxy::start(settings.port, ipv6, policy, settings.config)
            .map_err(|e| format!("DNS proxy sockets: {e}"))
    });
    match started {
        Ok(proxy) => {
            let mut view = lock(view);
            view.dns_proxy_port = proxy.port();
            view.dns_status = answerer.status(proxy.port());
            view.errors.remove("dns-proxy");
            crate::log::logln!("DNS proxy on port {}", proxy.port());
            Some(answerer)
        }
        Err(error) => {
            crate::log::logln!("DNS proxy: {error}");
            crate::events::node(Warning, "DnsProxyFailed", error.clone());
            lock(view).errors.insert("dns-proxy".into(), error);
            None
        }
    }
}

/// The proxy's routing for each family (ADR-0024): packets marked
/// `TO_PROXY` are delivered locally.
fn proxy_routing(ipv6: bool) -> std::result::Result<(), String> {
    use flowsdn_bpf_abi::policy::proxy_mark;
    let loopback: u32 = fs::read_to_string("/sys/class/net/lo/ifindex")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let connector = Connector::open().map_err(|e| format!("netlink: {e}"))?;
    for v6 in [false].into_iter().chain(ipv6.then_some(true)) {
        connector
            .ensure_mark_route(
                v6,
                proxy_mark::RULE_PRIORITY,
                (proxy_mark::TO_PROXY, proxy_mark::MASK),
                proxy_mark::TABLE,
                loopback,
            )
            .map_err(|e| format!("the proxy's ip rule and local route: {e}"))?;
    }
    Ok(())
}

fn apply_policy(
    maps: &mut PolicyMaps,
    desired: &crate::policy::Desired,
) -> std::result::Result<(), String> {
    use flowsdn_bpf_abi::{IpCacheKey, MapBytes, policy::EndpointPolicyKey};
    let text = |e: Box<dyn std::error::Error>| e.to_string();
    let entries: BTreeMap<[u8; 16], _> = maps
        .policy_entries()
        .map_err(text)?
        .into_iter()
        .map(|(k, v)| (k.to_bytes(), v))
        .collect();
    let ipcache: BTreeMap<[u8; 24], _> = maps
        .ipcache_entries()
        .map_err(text)?
        .into_iter()
        .map(|(k, v)| (k.to_bytes(), v))
        .collect();
    let endpoints: BTreeMap<u32, _> = maps.policy_endpoints().map_err(text)?.into_iter().collect();
    for (key, value) in &desired.entries {
        if entries.get(key) != Some(value) {
            maps.upsert_policy(EndpointPolicyKey::from_bytes(*key), *value)
                .map_err(text)?;
        }
    }
    for (key, value) in &desired.ipcache {
        if ipcache.get(key) != Some(value) {
            maps.upsert_ipcache(IpCacheKey::from_bytes(*key), *value)
                .map_err(text)?;
        }
    }
    for (ifindex, value) in &desired.endpoints {
        if endpoints.get(ifindex) != Some(value) {
            maps.set_policy_endpoint(*ifindex, *value).map_err(text)?;
        }
    }
    for ifindex in endpoints
        .iter()
        .filter(|(k, v)| crate::policy::stale_row(desired, **k, v.flags))
        .map(|(k, _)| k)
    {
        maps.remove_policy_endpoint(*ifindex).map_err(text)?;
    }
    for key in ipcache.keys().filter(|k| !desired.ipcache.contains_key(*k)) {
        maps.remove_ipcache(IpCacheKey::from_bytes(*key))
            .map_err(text)?;
    }
    for key in entries.keys().filter(|k| !desired.entries.contains_key(*k)) {
        maps.remove_policy(EndpointPolicyKey::from_bytes(*key))
            .map_err(text)?;
    }
    Ok(())
}

fn identity_rows(state: &WatchState) -> Vec<identity::Object> {
    state
        .snapshot()
        .all()
        .filter_map(|(row, _)| match &*row {
            Resource::Identity(i) => Some(identity::Object::new(
                i.id,
                &i.security_labels,
                &i.created,
                i.heartbeat,
                &i.metadata.resource_version,
            )),
            _ => None,
        })
        .collect()
}
/// The Services; `maglev` is the `lb-algorithm` default a Service's
/// annotation overrides, as its annotation does `lb_mode`.
fn service_rows(
    state: &WatchState,
    maglev: bool,
    lb_mode: LbMode,
    nat46x64: bool,
    external_clusterip: bool,
) -> Vec<ServiceInfo> {
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
                        node_port: p.node_port,
                    })
                    .collect(),
                external_ips: service.external_ips.clone(),
                load_balancer_ips: service.load_balancer_ips.clone(),
                internal_local: service.internal_local,
                external_local: service.external_local,
                affinity: service.affinity,
                maglev: match service.lb_algorithm.as_deref() {
                    Some("maglev") => true,
                    Some(_) => false,
                    None => maglev,
                },
                dsr_tcp: match service.forwarding_mode.as_deref() {
                    Some(mode) => mode == "dsr",
                    None => lb_mode != LbMode::Snat,
                },
                dsr_other: match service.forwarding_mode.as_deref() {
                    Some(mode) => mode == "dsr",
                    None => lb_mode == LbMode::Dsr,
                },
                nat46x64,
                external_clusterip,
                labels: service.labels.clone(),
                created: service.created.clone(),
                load_balancer_class: service.load_balancer_class.clone(),
                ip_families: service.ip_families.clone(),
                requested_ips: service.requested_ips.clone(),
                resource_version: service.metadata.resource_version.clone(),
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
                        node_name: e.node_name.clone(),
                        zone_hints: e.zone_hints.clone(),
                        node_hints: e.node_hints.clone(),
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

/// Load the socket-lb object, set how its DSR packets carry their frontend
/// (#447), and attach it to the cgroup root.
fn load_socket_lb(
    object: &[u8],
    pin_root: Option<&Path>,
    cgroup_root: &Path,
    dispatch: flowsdn_bpf_abi::lb::DsrDispatch,
) -> std::result::Result<SocketLb, String> {
    let pins = pin_root.map(|root| root.join("socket-lb"));
    let mut lb = SocketLb::load(Object::Bytes(object), pins.as_deref())
        .map_err(|e| format!("load socket-lb: {e}"))?;
    lb.set_dsr_dispatch(dispatch)
        .map_err(|e| format!("socket-lb DSR dispatch {}: {e}", dispatch.name()))?;
    lb.attach(cgroup_root)
        .map_err(|e| format!("attach socket-lb to {}: {e}", cgroup_root.display()))?;
    Ok(lb)
}

/// Own the socket-LB maps: on every new frontend set (after both lists are
/// complete) and every 30 s, plan from what the kernel holds and apply.
/// Nothing is pruned before the first complete lists.
///
/// Socket termination (spec 05 §3.8, #292, #392): a backend that leaves the
/// programmed services (UDP; TCP too with `terminate_tcp`) has its sockets
/// ended, in passes at most every 50 ms. The first successful programming
/// also ends sockets to UDP backends `_reverse_sk` remembers from before
/// (the agent was down when they left).
/// What the services thread does besides programming the services.
struct UplinkSettings {
    node_port: bool,
    terminate_tcp: bool,
    /// BPF masquerade's never-masqueraded CIDRs, when it is on.
    masquerade: Option<Vec<crate::kubernetes::Cidr>>,
    gateway64: Option<[u8; 12]>,
    /// NAT46/64 to local backends (#450): `nodeport_endpoint` on endpoints.
    nat46x64: bool,
    /// Egress gateway (#564): keep `flowsdn_egress_gw_policy_v4` planned.
    egress_gateway: bool,
}
/// How often the egress gateway map is planned again (spec 14 §6.4's
/// `egress-gateway-reconciliation-trigger-interval`).
const EGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// This node's interfaces with their IPv4 and global IPv6 addresses, from
/// sysfs and netlink.
fn egress_interfaces() -> Vec<crate::egress_gateway::Interface> {
    let Ok(connector) = Connector::open() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(index) = std::fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|i| i.trim().parse::<u32>().ok())
        else {
            continue;
        };
        let all = connector.addresses(index).unwrap_or_default();
        let addresses = all
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .collect();
        let addresses6 = all
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) if !v6.is_unicast_link_local() && !v6.is_loopback() => Some(*v6),
                _ => None,
            })
            .collect();
        out.push(crate::egress_gateway::Interface {
            name,
            index,
            addresses,
            addresses6,
        });
    }
    out
}

/// Plan the egress gateway maps from the view and write them when they
/// changed (#564, IPv6 #580). Interfaces this node is the IPv4 gateway on get
/// loose `rp_filter`.
fn program_egress(
    lb: &mut SocketLb,
    view: &Shared,
    written: &mut Option<crate::egress_gateway::Maps>,
) {
    let interfaces = egress_interfaces();
    let (entries, report) = {
        let view = lock(view);
        if !(view.egress_policies_synced && view.pods_synced && view.nodes_synced) {
            return;
        }
        let primary = view
            .uplinks
            .uplinks
            .iter()
            .find(|u| u.primary)
            .map(|u| u.name.clone());
        let local = crate::egress_gateway::Local {
            node: &view.local_node,
            interfaces: &interfaces,
            primary: primary.as_deref(),
        };
        crate::egress_gateway::plan(
            &view.egress_policies,
            &view.pods,
            &view.namespaces,
            &view.nodes,
            &local,
        )
    };
    for (_, egress) in &report.local {
        if let Ok((_, index)) = egress
            && let Some(interface) = interfaces.iter().find(|i| i.index == *index && *index != 0)
        {
            let path = format!("/proc/sys/net/ipv4/conf/{}/rp_filter", interface.name);
            if std::fs::read_to_string(&path)
                .map(|v| v.trim() != "2")
                .unwrap_or(false)
            {
                let _ = std::fs::write(&path, "2");
            }
        }
    }
    let result = if written.as_ref() == Some(&entries) {
        Ok(())
    } else {
        // The next hops first, so an IPv6 entry never names a gateway whose
        // next hop is not there yet.
        lb.set_egress_nexthop6(&entries.nexthop6)
            .and_then(|()| lb.set_egress_gateway4(&entries.v4))
            .and_then(|()| lb.set_egress_gateway6(&entries.v6))
            .map_err(|e| e.to_string())
    };
    let mut view = lock(view);
    view.egress_status = report.json(true, entries.v4.len(), entries.v6.len());
    match result {
        Ok(()) => {
            *written = Some(entries);
            view.errors.remove("egress-gateway");
        }
        Err(error) => {
            crate::log::logln!("egress gateway: {error}");
            *written = None;
            view.errors.insert("egress-gateway".into(), error);
        }
    }
}

fn service_loop(
    receiver: &mpsc::Receiver<Vec<socket::Service>>,
    view: &Shared,
    lb: &mut SocketLb,
    settings: &UplinkSettings,
) {
    let UplinkSettings {
        node_port,
        terminate_tcp,
        masquerade,
        gateway64,
        nat46x64,
        egress_gateway,
    } = settings;
    let egress_gateway = *egress_gateway;
    let (node_port, terminate_tcp, gateway64, nat46x64) =
        (*node_port, *terminate_tcp, *gateway64, *nat46x64);
    let masquerade = masquerade.as_deref();
    let mut desired: Option<Vec<socket::Service>> = None;
    // The terminable backends last programmed; None until the first success.
    let mut programmed: Option<BTreeSet<flowsdn_connector::sock_diag::Backend>> = None;
    let mut batch = services::TerminationBatch::default();
    // Egress gateway (#564): what was last written, and when the Services
    // were last programmed (they keep their 30 s cadence while egress
    // gateway wakes this thread every second).
    let mut egress_written: Option<crate::egress_gateway::Maps> = None;
    let mut serviced = Instant::now();
    let mut fresh = false;
    loop {
        let mut timeout = batch
            .wait(Instant::now())
            .unwrap_or(RECONCILE_INTERVAL)
            .min(RECONCILE_INTERVAL);
        if egress_gateway {
            timeout = timeout.min(EGRESS_INTERVAL);
        }
        match receiver.recv_timeout(timeout) {
            Ok(next) => {
                let mut next = next;
                while let Ok(newer) = receiver.try_recv() {
                    next = newer;
                }
                desired = Some(next);
                fresh = true;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if egress_gateway {
            program_egress(lb, view, &mut egress_written);
        }
        let due = fresh
            || serviced.elapsed() >= RECONCILE_INTERVAL
            || batch.wait(Instant::now()).is_some();
        if !due {
            continue;
        }
        fresh = false;
        serviced = Instant::now();
        if let Some(services) = &desired {
            let result = program(lb, services);
            if result.is_ok() {
                let now = services::terminable_backends(services, terminate_tcp);
                match &programmed {
                    Some(before) => batch.add(before.difference(&now).copied()),
                    None => match lb.reverse_sockets() {
                        Ok(reverse) => batch.add(services::stale_udp_backends(&reverse, &now)),
                        Err(error) => crate::log::logln!("read reverse socket maps: {error}"),
                    },
                }
                programmed = Some(now);
            }
            let mut view = lock(view);
            match result {
                Ok(ids) => {
                    view.service_ids = ids;
                    view.errors.remove("services");
                }
                Err(error) => {
                    crate::log::logln!("socket LB: {error}");
                    view.errors.insert("services".into(), error);
                }
            }
        }
        if let Some(gone) = batch.take(Instant::now()) {
            let namespaces = lock(view)
                .endpoints
                .iter()
                .filter(|e| !e.netns_path.is_empty())
                .map(|e| (PathBuf::from(&e.netns_path), e.netns_cookie))
                .collect();
            let outcome = terminate(lb, &gone, namespaces, terminate_tcp);
            let mut view = lock(view);
            match outcome {
                Ok(count) => {
                    if count > 0 {
                        crate::log::logln!(
                            "socket termination: {count} sockets to {} removed backends ended",
                            gone.len()
                        );
                    }
                    view.errors.remove("socket-termination");
                }
                Err(error) => {
                    crate::log::logln!("socket termination: {error}");
                    view.errors.insert("socket-termination".into(), error);
                }
            }
        }
        // BPF masquerade (#460): its prefixes follow the Node list.
        if let Some(non_masquerade) = masquerade {
            let ((sources, exclude), (sources6, exclude6)) = {
                let view = lock(view);
                (
                    crate::kubernetes::masquerade_prefixes(
                        &view.local_node,
                        &view.nodes,
                        view.derive,
                        non_masquerade,
                    ),
                    // IPv6 (#513).
                    crate::kubernetes::masquerade_prefixes6(
                        &view.local_node,
                        &view.nodes,
                        view.derive,
                        non_masquerade,
                    ),
                )
            };
            let result = lb
                .set_masquerade(&sources, &exclude)
                .and_then(|()| lb.set_masquerade6(&sources6, &exclude6))
                .map_err(|e| format!("masquerade maps: {e}"));
            let mut view = lock(view);
            match result {
                Ok(()) => view.errors.remove("masquerade"),
                Err(error) => view.errors.insert("masquerade".into(), error),
            };
        }
        // The RFC 6052 gateway (#454): its sources follow the Node list.
        if gateway64.is_some() {
            let sources = {
                let view = lock(view);
                crate::kubernetes::gateway64_sources(&view.local_node, &view.nodes, view.derive)
            };
            let result = lb
                .set_gateway64(gateway64, &sources)
                .map_err(|e| format!("NAT46/64 gateway maps: {e}"));
            let mut view = lock(view);
            match result {
                Ok(()) => view.errors.remove("nat46x64-gateway"),
                Err(error) => view.errors.insert("nat46x64-gateway".into(), error),
            };
        }
        if node_port || masquerade.is_some() || gateway64.is_some() {
            let (addresses, ports) = {
                let view = lock(view);
                (
                    view.nodes
                        .iter()
                        .find(|n| n.name == view.local_node)
                        .map(|n| n.internal_ips.clone())
                        .unwrap_or_default(),
                    uplink_ports(&view),
                )
            };
            let result = attach_uplinks(lb, &addresses, &ports);
            let mut view = lock(view);
            match result {
                Ok(()) => {
                    view.errors.remove("node-port");
                }
                Err(error) => {
                    view.errors.insert("node-port".into(), error);
                }
            }
        }
        // NAT46/64 to local backends (#450): every local endpoint's veth
        // translates its replies back.
        if nat46x64 {
            let endpoints = endpoint_interfaces(&lock(view).endpoints);
            let result = attach_endpoints(lb, &endpoints);
            let mut view = lock(view);
            match result {
                Ok(()) => view.errors.remove("nat46x64-endpoints"),
                Err(error) => view.errors.insert("nat46x64-endpoints".into(), error),
            };
        }
    }
}

/// Local endpoints' host-side interfaces and indexes (#450).
fn endpoint_interfaces(endpoints: &[crate::kubernetes::LocalEndpoint]) -> BTreeMap<String, u32> {
    endpoints
        .iter()
        .filter(|e| !e.interface.is_empty() && e.ifindex != 0)
        .map(|e| (e.interface.clone(), e.ifindex))
        .collect()
}
/// Bring `nodeport_endpoint` to exactly `want` (name -> index): detach the
/// gone and the re-created, attach the rest. Every endpoint is tried; the
/// failures are reported together.
fn attach_endpoints(
    lb: &mut SocketLb,
    want: &BTreeMap<String, u32>,
) -> std::result::Result<(), String> {
    let stale: Vec<String> = lb
        .endpoints()
        .filter(|(name, index)| want.get(*name) != Some(index))
        .map(|(name, _)| name.to_owned())
        .collect();
    for name in stale {
        lb.detach_endpoint(&name);
    }
    let mut failures = Vec::new();
    for (name, index) in want {
        if let Err(error) = lb.attach_endpoint(name, *index) {
            failures.push(format!(
                "attach the NAT46/64 reply program to {name}: {error}"
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// The interfaces holding any of `addresses`, by name (`/sys/class/net`).
fn interfaces_with(addresses: &[IpAddr]) -> std::result::Result<BTreeSet<String>, String> {
    Ok(interfaces_holding(addresses)?.into_keys().collect())
}
/// The uplink ports the monitor found (#408), name -> ifindex: a second
/// port's address need not be an InternalIP yet (rustkube-node#366).
fn uplink_ports(view: &View) -> BTreeMap<String, u32> {
    view.uplinks
        .uplinks
        .iter()
        .map(|u| (u.name.clone(), u.index))
        .collect()
}
/// The host firewall's interfaces (name -> ifindex) and the node's global
/// addresses ([`crate::host_policy::scope`], #384).
fn host_scope() -> std::result::Result<(BTreeMap<String, u32>, Vec<IpAddr>), String> {
    let connector = Connector::open().map_err(|e| format!("netlink: {e}"))?;
    let addresses = connector
        .all_addresses()
        .map_err(|e| format!("netlink addresses: {e}"))?;
    let mut links = Vec::new();
    for entry in fs::read_dir("/sys/class/net").map_err(|e| format!("/sys/class/net: {e}"))? {
        let Ok(entry) = entry else { continue };
        let Some(index) = fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|i| i.trim().parse::<u32>().ok())
        else {
            continue;
        };
        links.push(crate::host_policy::Link {
            name: entry.file_name().to_string_lossy().into_owned(),
            index,
            has_master: entry.path().join("master").exists(),
        });
    }
    Ok(crate::host_policy::scope(&links, &addresses))
}

/// The interfaces (name -> ifindex) that hold one of `addresses`.
fn interfaces_holding(addresses: &[IpAddr]) -> std::result::Result<BTreeMap<String, u32>, String> {
    let connector = Connector::open().map_err(|e| format!("netlink: {e}"))?;
    let mut out = BTreeMap::new();
    for entry in fs::read_dir("/sys/class/net").map_err(|e| format!("/sys/class/net: {e}"))? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(index) = fs::read_to_string(entry.path().join("ifindex"))
            .ok()
            .and_then(|i| i.trim().parse::<u32>().ok())
        else {
            continue;
        };
        if connector
            .addresses(index)
            .is_ok_and(|held| held.iter().any(|ip| addresses.contains(ip)))
        {
            out.insert(name, index);
        }
    }
    Ok(out)
}

/// NodePort from outside the cluster (#292): the NodePort programs on every
/// interface that holds one of this node's InternalIPs, and on no other.
fn attach_uplinks(
    lb: &mut SocketLb,
    addresses: &[IpAddr],
    ports: &BTreeMap<String, u32>,
) -> std::result::Result<(), String> {
    if addresses.is_empty() {
        return Ok(());
    }
    let mut want = interfaces_with(addresses)?;
    want.extend(ports.keys().cloned());
    let stale: Vec<String> = lb
        .uplinks()
        .filter(|name| !want.contains(*name))
        .map(str::to_owned)
        .collect();
    for name in stale {
        lb.detach_uplink(&name);
    }
    for name in &want {
        lb.attach_uplink(name)
            .map_err(|e| format!("attach NodePort programs to {name}: {e}"))?;
    }
    if want.is_empty() {
        return Err("no interface holds this node's InternalIP".into());
    }
    Ok(())
}
/// Spec 05 §3.8 socket termination ([`flowsdn_connector::sock_diag::ends`]):
/// destroy the UDP sockets the socket LB translated to a backend that is
/// gone (their cookies are in `_reverse_sk` with that backend) and, with
/// `tcp`, the TCP sockets connected to a gone TCP backend, in the host
/// network namespace and in each local endpoint's (entered by its path only
/// when the namespace cookie matches). Returns how many were destroyed; a
/// namespace that cannot be entered or a kernel without `SOCK_DESTROY` is an
/// error after the rest were tried.
fn terminate(
    lb: &SocketLb,
    gone: &BTreeSet<flowsdn_connector::sock_diag::Backend>,
    namespaces: Vec<(PathBuf, u64)>,
    tcp: bool,
) -> std::result::Result<usize, String> {
    use flowsdn_connector::sock_diag;
    let cookies: BTreeSet<u64> = lb
        .reverse_sockets()
        .map_err(|e| format!("read reverse socket maps: {e}"))?
        .into_iter()
        .filter(|(_, ip, port)| {
            gone.contains(&(socket::PROTO_UDP, sock_diag::unmapped(*ip), *port))
        })
        .map(|(cookie, _, _)| cookie)
        .collect();
    if cookies.is_empty() && !tcp {
        return Ok(0);
    }
    let kill = move |cookies: BTreeSet<u64>, gone: BTreeSet<sock_diag::Backend>| {
        move || -> flowsdn_connector::Result<usize> { sock_diag::destroy_to(&gone, &cookies, tcp) }
    };
    let mut count = 0usize;
    let mut failures = Vec::new();
    match kill(cookies.clone(), gone.clone())() {
        Ok(n) => count = count.saturating_add(n),
        Err(e) => failures.push(format!("host: {e}")),
    }
    for (path, cookie) in namespaces {
        match sock_diag::in_endpoint_namespace(&path, cookie, kill(cookies.clone(), gone.clone())) {
            Ok(n) => count = count.saturating_add(n),
            Err(e) => failures.push(format!("{}: {e}", path.display())),
        }
    }
    if failures.is_empty() {
        Ok(count)
    } else {
        Err(failures.join("; "))
    }
}

fn program(
    lb: &mut SocketLb,
    services: &[socket::Service],
) -> std::result::Result<BTreeMap<(socket::Address, u8), u16>, String> {
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
/// relists after [`next_wait`]. Forwarding consumers keep the last good
/// snapshot meanwhile.
/// How long to wait after a failure, and the backoff after that: 1 s doubling to
/// 30 s, but a 404 stays at 1 s for a watch's first minute. A CRD is not served
/// at the start of a boot (the apiserver applies its manifests as it starts), and
/// doubling would sleep through its arrival (#397).
fn next_wait(not_found: bool, since_start: Duration, backoff: Duration) -> (Duration, Duration) {
    if not_found && since_start < NOT_FOUND_FLAT {
        return (Duration::from_secs(1), Duration::from_secs(1));
    }
    (backoff, backoff.saturating_mul(2).min(MAX_BACKOFF))
}
/// `part` after `gate` (#337: a flowsdn.io watcher after its CRDs exist).
fn gated<'a>(
    gate: futures::future::Shared<futures::future::LocalBoxFuture<'a, ()>>,
    part: impl std::future::Future<Output = ()> + 'a,
) -> futures::future::LocalBoxFuture<'a, ()> {
    async move {
        gate.await;
        part.await;
    }
    .boxed_local()
}

/// The CRD readiness gate (#337, spec 13 §3.2): list the CRDs as metadata
/// only, every second, until every `required` name exists. While waiting it
/// is the `crds` part error; past `timeout` the agent exits, naming the
/// missing CRDs (the operator registers them).
async fn wait_for_crds(
    client: &JsonClient,
    required: &BTreeSet<String>,
    timeout: Duration,
    view: &Shared,
) {
    use flowsdn_k8s::register::{CRDS_PATH, listed_names};
    let started = Instant::now();
    let mut said: Option<(Vec<String>, Instant)> = None;
    while !required.is_empty() {
        let missing: Vec<String> = match client.list_metadata(CRDS_PATH).await {
            Ok((200, list)) => {
                let present = listed_names(&list);
                required
                    .iter()
                    .filter(|name| !present.contains(*name))
                    .cloned()
                    .collect()
            }
            Ok((status, body)) => {
                crate::log::logln!(
                    "CRD list: HTTP {status} {}",
                    body.get("message").and_then(Value::as_str).unwrap_or("")
                );
                required.iter().cloned().collect()
            }
            Err(error) => {
                crate::log::logln!("CRD list: {error}");
                required.iter().cloned().collect()
            }
        };
        if missing.is_empty() {
            break;
        }
        let text = format!("waiting for CRDs: {}", missing.join(", "));
        if said
            .as_ref()
            .is_none_or(|(last, at)| *last != missing || at.elapsed() >= CRD_WAIT_LOG)
        {
            crate::log::logln!("{text}");
            said = Some((missing.clone(), Instant::now()));
        }
        lock(view).errors.insert("crds".into(), text);
        if started.elapsed() >= timeout {
            crate::log::logln!(
                "CRDs still missing after {}s: {}; the flowsdn operator (Deployment \
                 kube-system/flowsdn-operator) registers them; exiting",
                timeout.as_secs(),
                missing.join(", ")
            );
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    lock(view).errors.remove("crds");
    if !required.is_empty() {
        crate::log::logln!("CRDs present: {}", required.len());
    }
}

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
    let started = Instant::now();
    let mut last_error = String::new();
    loop {
        match cycle(client, &scope, &mut state, &mut publish, view, part).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(error) => {
                state.failed();
                let since = started.elapsed();
                let (wait, next) = next_wait(error.is_not_found(), since, backoff);
                let text = error.to_string();
                // A kind not served yet retries every second: say so once.
                let flat = error.is_not_found() && since < NOT_FOUND_FLAT;
                if !(flat && text == last_error) {
                    crate::log::logln!("kubernetes {part}: {error}; relisting in {wait:?}");
                }
                lock(view).errors.insert(part.into(), text.clone());
                last_error = text;
                tokio::time::sleep(wait).await;
                backoff = next;
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
        if lock(view).errors.remove(part).is_some() {
            crate::log::logln!("kubernetes {part}: listed");
        }
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

/// Own the direct routes (#576 stage 2, [`crate::direct_routes`]): plan the
/// desired routes into the `direct-routes` owner of spec 10's
/// `desired-routes`, and reconcile the selected rows into the kernel. Prune
/// waits for the first complete Node list; every row is refreshed every 30 s;
/// a route of another protocol is never replaced.
fn route_loop(
    receiver: &mpsc::Receiver<Vec<DesiredRoute>>,
    view: &Shared,
    file: &Path,
    skip_unreachable: bool,
) {
    use crate::direct_routes::{self, ConnectorOps, Planned};
    use flowsdn_node::routes::{RouteManager, RouteTarget};
    use flowsdn_reconcile::{Kind, Options, Reconciler};
    let fail = |message: String| {
        lock(view).errors.insert("routes".into(), message);
    };
    let connector = match Connector::open() {
        Ok(connector) => connector,
        Err(error) => return fail(format!("netlink: {error}")),
    };
    let manager = match RouteManager::new() {
        Ok(manager) => manager,
        Err(error) => return fail(format!("desired-routes: {error}")),
    };
    let table = manager.table();
    let initializer = match table.register_initializer(direct_routes::OWNER) {
        Ok(initializer) => initializer,
        Err(error) => return fail(format!("desired-routes: {error}")),
    };
    table.seal_initializers();
    let held = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
    let target = RouteTarget::new(
        direct_routes::Holding {
            inner: ConnectorOps::new(connector, file.to_path_buf()),
            held: Arc::clone(&held),
        },
        Arc::clone(&table),
    );
    let options = Options {
        refresh_interval: RECONCILE_INTERVAL,
        prune_interval: RECONCILE_INTERVAL,
        ..Options::default()
    };
    let mut reconciler = match Reconciler::new(&table, target, options) {
        Ok(reconciler) => reconciler,
        Err(error) => return fail(format!("route reconciler: {error}")),
    };
    let mut desired: Option<Vec<DesiredRoute>> = None;
    // The uplinks a reconcile last saw (#408): a port leaving or joining
    // rewrites the paths at once, not at the next 30 s repair.
    let mut generation = lock(view).uplinks.generation;
    let mut last = Instant::now();
    loop {
        match receiver.recv_timeout(uplinks_monitor::TICK) {
            Ok(next) => {
                let mut next = next;
                while let Ok(newer) = receiver.try_recv() {
                    next = newer;
                }
                desired = Some(next);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = lock(view).uplinks.generation;
                if now == generation && last.elapsed() < RECONCILE_INTERVAL {
                    continue;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        generation = lock(view).uplinks.generation;
        last = Instant::now();
        // Nothing is planned, nor pruned, before the first complete Node list.
        let Some(desired) = &desired else { continue };
        let planned: Vec<(DesiredRoute, Planned)> = {
            let ops = &reconciler.target().ops.inner;
            desired
                .iter()
                .map(|route| {
                    let hops = uplinks_monitor::route_hops(view, route);
                    let planned = direct_routes::plan(
                        route,
                        hops.as_deref(),
                        |a| ops.direct(a),
                        |a| ops.router(a),
                        skip_unreachable,
                    );
                    (route.clone(), planned)
                })
                .collect()
        };
        *held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = direct_routes::held(&planned);
        let rows: Vec<flowsdn_node::rows::DesiredRoute> = planned
            .iter()
            .filter_map(|(_, p)| match p {
                Planned::Row(row) => Some((**row).clone()),
                _ => None,
            })
            .collect();
        let mut failures = Vec::new();
        if let Err(error) =
            futures::executor::block_on(manager.set_owner(direct_routes::OWNER, rows))
        {
            failures.push(format!("desired-routes: {error}"));
        }
        if initializer.complete() {
            reconciler.prune_now();
        }
        // The connector runs its own runtime, so the reconciler is driven
        // without one.
        for _ in 0..16 {
            let _ = futures::executor::block_on(reconciler.run_round(std::time::Instant::now()));
            if !reconciler.has_pending_work() {
                break;
            }
        }
        let mut states = BTreeMap::new();
        for (route, planned) in planned {
            let cidr = direct_routes::cidr_text(route.destination, route.prefix);
            let state = match &planned {
                Planned::Row(row) => {
                    let status = reconciler.status(&flowsdn_table::Keyed::primary_key(&**row));
                    match status {
                        Some(status) if status.kind == Kind::Error => {
                            let error = status.error.unwrap_or_default();
                            failures.push(format!("{cidr} via {}: {error}", route.gateway));
                            format!("error: {error}")
                        }
                        Some(status) if status.kind == Kind::Pending => "pending".to_owned(),
                        _ => direct_routes::installed_text(row),
                    }
                }
                Planned::Skipped(why) => why.clone(),
                Planned::Failed(error) => {
                    failures.push(format!("{cidr} via {}: {error}", route.gateway));
                    format!("error: {error}")
                }
            };
            states.insert(cidr, (route, state));
        }
        if let Some(error) = reconciler.prune_status().and_then(|p| p.error.clone()) {
            failures.push(format!("prune: {error}"));
        }
        let error = (!failures.is_empty()).then(|| failures.join("; "));
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

#[cfg(test)]
mod tests {
    #[test]
    fn a_404_retries_every_second_for_a_minute_then_backs_off() {
        let s = Duration::from_secs;
        assert_eq!(next_wait(true, s(0), s(1)), (s(1), s(1)));
        assert_eq!(next_wait(true, s(59), s(1)), (s(1), s(1)));
        assert_eq!(next_wait(true, s(60), s(1)), (s(1), s(2)));
        assert_eq!(next_wait(true, s(90), s(16)), (s(16), s(30)));
        // Any other failure doubles from the start, to 30 s.
        assert_eq!(next_wait(false, s(0), s(1)), (s(1), s(2)));
        assert_eq!(next_wait(false, s(5), s(30)), (s(30), s(30)));
    }

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
        use crate::direct_routes::{Key, load, save};
        assert!(load(&file).expect("absent").is_empty());
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
        save(&file, &routes).expect("save");
        assert_eq!(load(&file).expect("load"), routes);
        fs::write(&file, b"{}").expect("corrupt");
        assert!(load(&file).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
