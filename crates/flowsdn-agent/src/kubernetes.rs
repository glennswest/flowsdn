//! Kubernetes node discovery for the agent: settings, pod CIDR selection
//! (spec 07 §3.4), direct node routes (spec 10 §3.2.3) and the IP cache view.
//! This part is pure data; the watch/route controller needs the `kubernetes`
//! feature (Fedora OpenSSL through flowsdn-k8s, ADR-0016).
use crate::services::{Frontend, ServiceInfo, SliceInfo};
use crate::state::Result;
pub use flowsdn_hubble::endpoint::{EndpointInfo, Workload};
use flowsdn_lb::socket::Address;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

/// The reserved identities of node addresses (spec 03 §4.4): this node and
/// other nodes.
pub const IDENTITY_HOST: u32 = 1;
pub const IDENTITY_REMOTE_NODE: u32 = 6;
/// `ipv6-cluster-alloc-cidr` default `f00d::/64` (spec 07 §3.4).
const IPV6_CLUSTER_ALLOC_BASE: [u16; 4] = [0xf00d, 0, 0, 0];

/// A network address and prefix length.
pub type Cidr = (IpAddr, u8);

/// `kubernetes.lb-mode` (spec 05 §3.12).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LbMode {
    /// Source-NAT to this node's address.
    #[default]
    Snat,
    /// Direct server return.
    Dsr,
    /// Direct server return for TCP, source NAT otherwise.
    Hybrid,
}

/// `kubernetes.hubble-drop-events` (#470, the reference's names and
/// defaults): `PacketDrop` Events on Pods for policy drops.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DropEvents {
    /// `hubble-drop-events-interval` (default 2 minutes): the same Pod,
    /// reason and message are written at most once per interval.
    pub interval: std::time::Duration,
    /// `hubble-drop-events-reasons` (default `auth_required`,
    /// `policy_denied`), as `flowsdn_bpf_abi::policy::drop_reason` codes.
    pub reasons: Vec<u8>,
    /// `hubble-drop-events-extended` (default false): the message lists the
    /// policies applied to the Pod in that direction.
    pub extended: bool,
    /// `hubble-drop-events-rate-limit` (default 1): Events a second at most,
    /// 0 for no limit.
    pub rate_limit: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    pub node_name: String,
    /// Explicit kubeconfig; otherwise in-cluster service account credentials.
    pub kubeconfig: Option<PathBuf>,
    pub auto_direct_node_routes: bool,
    pub skip_unreachable: bool,
    /// Socket LB for ClusterIP Services (spec 05 §3.8), default on: watch
    /// Services and EndpointSlices and attach the socket-lb programs.
    pub service_lb: bool,
    /// The cgroup v2 directory the socket-lb programs attach to; the host's
    /// root covers every pod and host process.
    pub cgroup_root: PathBuf,
    /// NodePort, external and LoadBalancer addresses from outside the
    /// cluster (#292), default on with `service-lb`: tc programs on the
    /// interfaces holding this node's InternalIPs.
    pub node_port: bool,
    /// `l2-neigh-discovery` (#469, spec 10 §3.4; the reference's
    /// `enable-l2-neigh-discovery`, default false): kernel-managed neighbor
    /// entries for the next hops to other nodes on the uplinks
    /// ([`crate::neighbors`]). On, the agent refuses to start on a kernel
    /// without managed neighbors.
    pub l2_neigh_discovery: bool,
    /// `xdp-prefilter` (#467; the reference's `enable-xdp-prefilter`,
    /// default false): the XDP prefilter on the uplinks and its
    /// `/v1/prefilter` deny list ([`crate::prefilter`]).
    pub xdp_prefilter: bool,
    /// `lb-algorithm: maglev` (default `random`): NodePort, external and
    /// LoadBalancer traffic from outside the cluster picks backends by
    /// Maglev (spec 05 §3.13), so every node sends a flow to the same
    /// backend. A Service's `service.flowsdn.io/lb-algorithm` annotation
    /// overrides it.
    pub maglev: bool,
    /// `lb-mode` (default `snat`), which a Service's
    /// `service.flowsdn.io/forwarding-mode` annotation overrides: how traffic
    /// from outside reaches a backend on another node.
    pub lb_mode: LbMode,
    /// `lb-dsr-dispatch` (#447; the reference's `bpf-lb-dsr-dispatch`,
    /// default `opt`): how a DSR packet carries its frontend to the backend's
    /// node: `opt` (IP option / Destination Options header), `ipip` (IPIP /
    /// IP6IP6) or `geneve`.
    pub lb_dsr_dispatch: flowsdn_bpf_abi::lb::DsrDispatch,
    /// `nat46x64` (default off; spec 04 §3.15): traffic from outside reaches a
    /// frontend with no backend of its family through the other family's
    /// backends on other nodes.
    pub nat46x64: bool,
    /// `lb-external-clusterip` (#465; the reference's
    /// `bpf-lb-external-clusterip`, default false): ClusterIP frontends get
    /// a node-local copy too, so traffic from outside the cluster routed to
    /// a ClusterIP (a route or BGP advertisement to this node) reaches its
    /// backends through the uplink programs, with Maglev under the same
    /// selection as NodePort.
    pub external_clusterip: bool,
    /// Cluster identity allocation (spec 03 §3.3, #291), default on: watch
    /// Namespaces and FlowsdnIdentity objects and hold an identity for each
    /// local Pod's labels.
    pub identity_allocation: bool,
    /// `io.flowsdn.k8s.policy.cluster` on every Pod identity; `default`.
    pub cluster_name: String,
    /// Kubernetes NetworkPolicy enforcement in the datapath (#292,
    /// ADR-0021), default on: watch NetworkPolicies (and Namespaces) and keep
    /// the endpoint policy maps.
    pub network_policy: bool,
    /// Pod rules of FlowsdnNetworkPolicy and FlowsdnClusterwideNetworkPolicy
    /// (#292; the CRDs must exist, the policy thread waits for their lists).
    pub flowsdn_policy: bool,
    /// `kubernetes.l7-proxy` (#536; the reference's `enable-l7-proxy`,
    /// default true) with `flowsdn-policy`: the agent's DNS proxy runs, so
    /// `toFQDNs` and DNS rules are enforced; the `tofqdns-*` keys tune it.
    /// `None` when off.
    pub dns_proxy: Option<crate::dns_proxy::Settings>,
    /// `policy-audit-mode` (#461; the reference's `policy-audit-mode`,
    /// default false): Pod endpoints judge and count (`audit` in
    /// `/v1/policy/verdicts`) but never drop. The host firewall has its own
    /// `host-firewall: audit`.
    pub policy_audit: bool,
    /// The host firewall (#379): `off` (default), `audit` or `enforce`.
    pub host_firewall: HostFirewall,
    /// `kubernetes.uplinks` (#408): how several uplink ports are used.
    pub uplinks: crate::uplinks::Settings,
    /// LB-IPAM (#475), default on with `service-lb`: watch
    /// FlowsdnLoadBalancerIPPools and, holding the LB-IPAM Lease, write
    /// LoadBalancer Services' ingress addresses. Nothing without a pool.
    pub lb_ipam: bool,
    /// L2 announcements (#475), default on with `service-lb` and
    /// `node-port`: watch FlowsdnL2AnnouncementPolicies and answer ARP/NDP
    /// for the addresses they give this node. Nothing without a policy.
    pub l2_announcements: bool,
    /// `kubernetes.local-redirect-policy` (#565; the reference's
    /// `enable-local-redirect-policy`, default off, needs `service-lb`):
    /// watch FlowsdnLocalRedirectPolicies and redirect their frontends to
    /// this node's Pods in the socket LB ([`crate::local_redirect`]).
    pub local_redirect: bool,
    /// `kubernetes.egress-gateway` (#564; the reference's
    /// `enable-egress-gateway`, default off, needs `bpf-masquerade`): watch
    /// FlowsdnEgressGatewayPolicies and keep `flowsdn_egress_gw_policy_v4`
    /// ([`crate::egress_gateway`]).
    pub egress_gateway: bool,
    /// `kubernetes.endpoint-crd` (#332), default on: keep a FlowsdnEndpoint
    /// for each local Pod endpoint ([`crate::endpoint_crd`]).
    pub endpoint_crd: bool,
    /// `kubernetes.node-crd` (#332), default on: keep this node's
    /// FlowsdnNode ([`crate::node_crd`]).
    pub node_crd: bool,
    /// `kubernetes.crd-wait-timeout` (#337, seconds, default 300): how long
    /// the flowsdn.io watchers wait for their CRDs before the agent exits.
    pub crd_wait_timeout: std::time::Duration,
    /// `kubernetes.hubble-drop-events` (#470, default off).
    pub drop_events: Option<DropEvents>,
    /// `kubernetes.lb-sock-terminate-all-protos` (#392, default false):
    /// socket termination ends TCP sockets to a removed backend too.
    pub terminate_tcp: bool,
    /// `bpf-masquerade` (#460; the reference's `enable-bpf-masquerade`,
    /// default false): the uplink programs masquerade local Pods' IPv4
    /// traffic leaving the cluster ([`masquerade_prefixes`]), except to
    /// `non-masquerade-cidrs` (IPv4 CIDRs). Needs `service-lb`.
    pub bpf_masquerade: bool,
    pub non_masquerade: Vec<Cidr>,
    /// `nat46x64-gateway` (#454; the reference's `enable-nat46x64-gateway`,
    /// default false): the uplink programs translate local Pods' IPv6
    /// TCP/UDP to `nat46x64-gateway-prefix` (a /96, default `64:ff9b::/96`,
    /// RFC 6052) into IPv4 from this node's address, and the replies back.
    /// Needs `service-lb`. The prefix's first 12 bytes when on.
    pub gateway64: Option<[u8; 12]>,
    /// What FlowsdnNodeConfigs changed at start (#480), for `/v1/healthz`;
    /// null when none was read.
    pub node_config: Value,
}
/// `kubernetes.host-firewall`: whether the agent filters traffic to the
/// node itself from FlowsdnClusterwideNetworkPolicy host rules, and whether
/// it drops (`enforce`) or only counts (`audit`) what they refuse.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostFirewall {
    #[default]
    Off,
    Audit,
    Enforce,
}
impl Settings {
    /// The flowsdn.io CRDs this configuration uses (#337, spec 13 §3.2):
    /// the agent's flowsdn.io watchers start only once all exist.
    pub fn required_crds(&self) -> std::collections::BTreeSet<&'static str> {
        let mut out = std::collections::BTreeSet::new();
        if self.identity_allocation {
            out.insert("flowsdnidentities.flowsdn.io");
        }
        if self.lb_ipam_on() {
            out.insert("flowsdnloadbalancerippools.flowsdn.io");
        }
        if self.l2_on() {
            out.insert("flowsdnl2announcementpolicies.flowsdn.io");
        }
        if self.local_redirect_on() {
            out.insert("flowsdnlocalredirectpolicies.flowsdn.io");
        }
        if self.egress_gateway {
            out.insert("flowsdnegressgatewaypolicies.flowsdn.io");
        }
        if self.flowsdn_policy {
            out.insert("flowsdnnetworkpolicies.flowsdn.io");
        }
        if self.flowsdn_policy || self.host_firewall != HostFirewall::Off {
            out.insert("flowsdnclusterwidenetworkpolicies.flowsdn.io");
        }
        if self.endpoint_crd {
            out.insert("flowsdnendpoints.flowsdn.io");
        }
        if self.node_crd {
            out.insert("flowsdnnodes.flowsdn.io");
        }
        out
    }
    /// LB-IPAM runs: `lb-ipam`, with `service-lb` (it reads the Services).
    pub fn lb_ipam_on(&self) -> bool {
        self.lb_ipam && self.service_lb
    }
    /// Local redirect policy runs: `local-redirect-policy`, with `service-lb`.
    pub fn local_redirect_on(&self) -> bool {
        self.local_redirect && self.service_lb
    }
    /// The L2 announcer runs: `l2-announcements`, with `service-lb` and
    /// `node-port` (the uplink programs serve what it announces).
    pub fn l2_on(&self) -> bool {
        self.l2_announcements && self.service_lb && self.node_port
    }
}
/// Where a DaemonSet mounts the host's cgroup v2 root.
pub const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
impl Settings {
    /// `kubernetes` absent or null disables discovery. `node-name` falls back to
    /// `K8S_NODE_NAME`, then `NODE_NAME` (the DaemonSet's downward API).
    pub fn parse(
        value: Option<&Value>,
        env: &BTreeMap<OsString, OsString>,
    ) -> Result<Option<Self>> {
        let object = match value {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Object(object)) => object,
            Some(_) => return Err("kubernetes must be an object".into()),
        };
        let text = |key: &str| -> Result<String> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::String(value)) => Ok(value.clone()),
                Some(_) => Err(format!("invalid kubernetes.{key}").into()),
            }
        };
        let flag = |key: &str, default: bool| -> Result<bool> {
            match object.get(key) {
                None | Some(Value::Null) => Ok(default),
                Some(Value::Bool(value)) => Ok(*value),
                Some(_) => Err(format!("kubernetes.{key} must be boolean").into()),
            }
        };
        let mut node_name = text("node-name")?;
        for key in ["K8S_NODE_NAME", "NODE_NAME"] {
            if node_name.is_empty()
                && let Some(value) = env.get(&OsString::from(key))
            {
                node_name = value.to_str().ok_or("node name is not UTF-8")?.into();
            }
        }
        if node_name.is_empty()
            || node_name.len() > 253
            || node_name
                .chars()
                .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '.')
        {
            return Err(
                "kubernetes.node-name (or K8S_NODE_NAME/NODE_NAME) must be a node name".into(),
            );
        }
        let maglev = match text("lb-algorithm")?.as_str() {
            "" | "random" => false,
            "maglev" => true,
            _ => return Err("kubernetes.lb-algorithm must be random or maglev".into()),
        };
        let lb_mode = match text("lb-mode")?.as_str() {
            "" | "snat" => LbMode::Snat,
            "dsr" => LbMode::Dsr,
            "hybrid" => LbMode::Hybrid,
            _ => return Err("kubernetes.lb-mode must be snat, dsr or hybrid".into()),
        };
        let lb_dsr_dispatch = match text("lb-dsr-dispatch")?.as_str() {
            "" => flowsdn_bpf_abi::lb::DsrDispatch::Opt,
            other => flowsdn_bpf_abi::lb::DsrDispatch::parse(other)
                .ok_or("kubernetes.lb-dsr-dispatch must be opt, ipip or geneve")?,
        };
        // Egress gateway (#564) SNATs on the uplink programs' masquerade
        // path: without them it would do nothing, so it is refused (spec 14
        // §3.4.7: never silently disabled).
        if flag("egress-gateway", false)?
            && !(flag("bpf-masquerade", false)? && flag("service-lb", true)?)
        {
            return Err(
                "kubernetes.egress-gateway needs kubernetes.bpf-masquerade and kubernetes.service-lb".into(),
            );
        }
        let host_firewall = match text("host-firewall")?.as_str() {
            "" | "off" => HostFirewall::Off,
            "audit" => HostFirewall::Audit,
            "enforce" => HostFirewall::Enforce,
            _ => return Err("kubernetes.host-firewall must be off, audit or enforce".into()),
        };
        let kubeconfig = text("kubeconfig")?;
        let cgroup_root = text("cgroup-root")?;
        let cgroup_root = if cgroup_root.is_empty() {
            PathBuf::from(DEFAULT_CGROUP_ROOT)
        } else {
            PathBuf::from(cgroup_root)
        };
        if !cgroup_root.is_absolute() {
            return Err("kubernetes.cgroup-root must be an absolute path".into());
        }
        // spec 03 §4.5: ^([a-z0-9][-a-z0-9]*)?[a-z0-9]$, at most 32 bytes.
        let mut cluster_name = text("cluster-name")?;
        if cluster_name.is_empty() {
            cluster_name = "default".into();
        }
        if cluster_name.len() > 32
            || cluster_name.starts_with('-')
            || cluster_name.ends_with('-')
            || !cluster_name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("kubernetes.cluster-name must be a DNS label of at most 32 bytes".into());
        }
        Ok(Some(Self {
            node_name,
            kubeconfig: (!kubeconfig.is_empty()).then(|| PathBuf::from(kubeconfig)),
            auto_direct_node_routes: flag("auto-direct-node-routes", true)?,
            skip_unreachable: flag("direct-routing-skip-unreachable", false)?,
            service_lb: flag("service-lb", true)?,
            node_port: flag("node-port", true)?,
            l2_neigh_discovery: flag("l2-neigh-discovery", false)?,
            xdp_prefilter: flag("xdp-prefilter", false)?,
            maglev,
            lb_mode,
            lb_dsr_dispatch,
            nat46x64: flag("nat46x64", false)?,
            external_clusterip: flag("lb-external-clusterip", false)?,
            identity_allocation: flag("identity-allocation", true)?,
            network_policy: flag("network-policy", true)?,
            flowsdn_policy: flag("flowsdn-policy", false)?,
            dns_proxy: if flag("flowsdn-policy", false)? && flag("l7-proxy", true)? {
                Some(crate::dns_proxy::Settings::parse(object)?)
            } else {
                None
            },
            policy_audit: flag("policy-audit-mode", false)?,
            host_firewall,
            cluster_name,
            cgroup_root,
            uplinks: crate::uplinks::Settings::parse(object.get("uplinks"))?,
            lb_ipam: flag("lb-ipam", true)?,
            l2_announcements: flag("l2-announcements", true)?,
            local_redirect: flag("local-redirect-policy", false)?,
            egress_gateway: flag("egress-gateway", false)?,
            endpoint_crd: flag("endpoint-crd", true)?,
            node_crd: flag("node-crd", true)?,
            terminate_tcp: flag("lb-sock-terminate-all-protos", false)?,
            bpf_masquerade: flag("bpf-masquerade", false)?,
            gateway64: if flag("nat46x64-gateway", false)? {
                let text = match text("nat46x64-gateway-prefix")?.as_str() {
                    "" => "64:ff9b::/96".to_owned(),
                    other => other.to_owned(),
                };
                match crate::prefilter::parse_cidr(&text) {
                    Some((IpAddr::V6(prefix), 96)) => {
                        let mut out = [0u8; 12];
                        for (slot, byte) in out.iter_mut().zip(prefix.octets()) {
                            *slot = byte;
                        }
                        Some(out)
                    }
                    _ => {
                        return Err(format!(
                            "kubernetes.nat46x64-gateway-prefix: {text} is not an IPv6 /96"
                        )
                        .into());
                    }
                }
            } else {
                None
            },
            non_masquerade: match object.get("non-masquerade-cidrs") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(list)) => list
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .and_then(crate::prefilter::parse_cidr)
                            .ok_or_else(|| {
                                format!("kubernetes.non-masquerade-cidrs: {item} is not a CIDR")
                            })
                    })
                    .collect::<std::result::Result<_, _>>()?,
                Some(_) => {
                    return Err("kubernetes.non-masquerade-cidrs must be a list".into());
                }
            },
            node_config: Value::Null,
            drop_events: if flag("hubble-drop-events", false)? {
                Some(drop_events(object)?)
            } else {
                None
            },
            crd_wait_timeout: match object.get("crd-wait-timeout") {
                None | Some(Value::Null) => std::time::Duration::from_secs(300),
                Some(value) => value
                    .as_u64()
                    .filter(|s| (1..=86_400).contains(s))
                    .map(std::time::Duration::from_secs)
                    .ok_or("kubernetes.crd-wait-timeout must be seconds, 1 to 86400")?,
            },
        }))
    }
}

/// The `hubble-drop-events-*` settings (see [`DropEvents`]).
fn drop_events(object: &serde_json::Map<String, Value>) -> Result<DropEvents> {
    use flowsdn_bpf_abi::policy::drop_reason;
    let interval = match object.get("hubble-drop-events-interval") {
        None | Some(Value::Null) => std::time::Duration::from_secs(120),
        Some(value) => duration(value)
            .filter(|d| (1..=86_400).contains(&d.as_secs()))
            .ok_or(
                "kubernetes.hubble-drop-events-interval must be seconds or a duration (90s, 2m, 1h), 1 s to 24 h",
            )?,
    };
    let reasons = match object.get("hubble-drop-events-reasons") {
        None | Some(Value::Null) => vec![drop_reason::AUTH_REQUIRED, drop_reason::POLICY_DENIED],
        Some(Value::Array(list)) => list
            .iter()
            .map(|item| match item.as_str().map(str::to_lowercase).as_deref() {
                Some("policy_denied") => Ok(drop_reason::POLICY_DENIED),
                Some("policy_deny") => Ok(drop_reason::POLICY_DENY),
                Some("auth_required") => Ok(drop_reason::AUTH_REQUIRED),
                _ => Err(format!(
                    "kubernetes.hubble-drop-events-reasons: {item} is not policy_denied, policy_deny or auth_required (the reasons the policy programs drop for)"
                )),
            })
            .collect::<std::result::Result<_, _>>()?,
        Some(_) => return Err("kubernetes.hubble-drop-events-reasons must be a list".into()),
    };
    let extended = match object.get("hubble-drop-events-extended") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err("kubernetes.hubble-drop-events-extended must be boolean".into()),
    };
    let rate_limit = match object.get("hubble-drop-events-rate-limit") {
        None | Some(Value::Null) => 1,
        Some(value) => value
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n <= 1_000_000)
            .ok_or(
                "kubernetes.hubble-drop-events-rate-limit must be events a second, 0 to 1000000",
            )?,
    };
    Ok(DropEvents {
        interval,
        reasons,
        extended,
        rate_limit,
    })
}

/// Seconds (a number) or a duration of one unit (`90s`, `2m`, `1h`).
fn duration(value: &Value) -> Option<std::time::Duration> {
    if let Some(seconds) = value.as_u64() {
        return Some(std::time::Duration::from_secs(seconds));
    }
    let text = value.as_str()?;
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
    let number: u64 = number.parse().ok()?;
    let seconds = match unit {
        "s" => number,
        "m" => number.checked_mul(60)?,
        "h" => number.checked_mul(3600)?,
        _ => return None,
    };
    Some(std::time::Duration::from_secs(seconds))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeInfo {
    pub name: String,
    /// `metadata.uid` (the FlowsdnNode's owner, #332).
    pub uid: String,
    pub pod_cidrs: Vec<(IpAddr, u8)>,
    pub internal_ips: Vec<IpAddr>,
    /// The Node's labels (host policy `nodeSelector`).
    pub labels: BTreeMap<String, String>,
    /// The Node's `Ready` condition is `True` (L2 announcement candidates).
    pub ready: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PodInfo {
    pub namespace: String,
    pub name: String,
    pub node: String,
    pub host_network: bool,
    pub ips: Vec<IpAddr>,
    pub labels: BTreeMap<String, String>,
    /// `spec.serviceAccountName` (part of the identity labels).
    pub service_account: String,
    pub uid: String,
    /// The controlling workload (a Deployment for its ReplicaSets), #328.
    pub workload: Option<Workload>,
    pub containers: Vec<Container>,
    /// The Pod's current `flowsdn.io/pod-networks` annotation.
    pub pod_networks: Option<String>,
    /// The Pod's current `k8s.v1.cni.cncf.io/network-status` (#371), and
    /// whether it is present but too large to have been kept.
    pub network_status: Option<String>,
    pub network_status_oversized: bool,
    pub resource_version: String,
    /// Named container ports: (protocol number, name, port).
    pub named_ports: Vec<(u8, String, u16)>,
    /// Every container port: (protocol number, name or empty, port).
    pub ports: Vec<(u8, String, u16)>,
    /// The Pod's `Ready` condition is `True`.
    pub ready: bool,
}
/// A container of a Pod: name and runtime ID (`<runtime>://<id>`, empty
/// until created); `init` for init containers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Container {
    pub name: String,
    pub id: String,
    pub init: bool,
}
impl PodInfo {
    /// What a flow names this Pod by (#328): Hubble's flow `Endpoint`.
    pub fn endpoint_info(&self) -> EndpointInfo {
        let mut labels: Vec<_> = self
            .labels
            .iter()
            .map(|(key, value)| format!("k8s:{key}={value}"))
            .collect();
        labels.push(format!(
            "k8s:io.kubernetes.pod.namespace={}",
            self.namespace
        ));
        EndpointInfo {
            namespace: self.namespace.clone(),
            pod_name: self.name.clone(),
            pod_uid: self.uid.clone(),
            node: self.node.clone(),
            labels,
            workloads: self.workload.iter().cloned().collect(),
            ..EndpointInfo::default()
        }
    }
    pub fn containers_json(&self) -> Value {
        Value::Array(
            self.containers
                .iter()
                .map(|c| json!({"name":c.name,"container-id":c.id,"init":c.init}))
                .collect(),
        )
    }
}

/// A local endpoint's Pod and the `flowsdn.io/pod-networks` value flowsdn
/// keeps on it, published by the API thread for the annotation writer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalEndpoint {
    pub id: u16,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub value: Value,
    /// The endpoint's host-side interface (where its programs are attached)
    /// and its index (the policy-endpoint map key).
    pub interface: String,
    pub ifindex: u32,
    /// The Pod's network namespace path as the CNI saw it, and the
    /// namespace's cookie (socket termination enters it only on a match).
    pub netns_path: String,
    pub netns_cookie: u64,
}
/// One annotation write: merge-patch the Pod's `flowsdn.io/pod-networks`
/// and/or `network-status` (JSON text, None = already current), with the UID
/// as a precondition when known, and the resourceVersion when network-status
/// is written (it is merged with other plugins' entries, so a concurrent
/// write by one of them must fail the patch rather than be lost).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnnotationPatch {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub pod_networks: Option<String>,
    pub network_status: Option<String>,
}
impl AnnotationPatch {
    pub fn path(&self) -> String {
        format!("/api/v1/namespaces/{}/pods/{}", self.namespace, self.name)
    }
    fn annotations(&self) -> Map<String, Value> {
        let mut annotations = Map::new();
        if let Some(value) = &self.pod_networks {
            annotations.insert(crate::tagging::POD_NETWORKS.into(), json!(value));
        }
        if let Some(value) = &self.network_status {
            annotations.insert(crate::tagging::NETWORK_STATUS.into(), json!(value));
        }
        annotations
    }
    /// The annotations this patch writes, as text (what a retry compares).
    pub fn annotations_text(&self) -> String {
        Value::Object(self.annotations()).to_string()
    }
    pub fn body(&self) -> Value {
        let mut metadata = Map::new();
        metadata.insert("annotations".into(), Value::Object(self.annotations()));
        if !self.uid.is_empty() {
            metadata.insert("uid".into(), json!(self.uid));
        }
        if self.network_status.is_some() && !self.resource_version.is_empty() {
            metadata.insert("resourceVersion".into(), json!(self.resource_version));
        }
        json!({ "metadata": metadata })
    }
}
/// Pod names and namespaces are DNS names; anything else never reaches a URL.
fn dns_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// The node's allocation CIDR for one family: the first `spec.podCIDRs` entry of
/// that family, else the reference default (spec 07 §3.4): IPv4
/// `10.<last byte of the node IPv4>.0.0/16`; IPv6 `f00d::<4 bytes of the IPv4
/// alloc CIDR, else of the node IPv6>:0:0/96`. None when nothing derives it.
pub fn alloc_cidr(node: &NodeInfo, v6: bool) -> Option<(IpAddr, u8)> {
    if let Some(cidr) = node.pod_cidrs.iter().find(|(ip, _)| ip.is_ipv6() == v6) {
        return Some(*cidr);
    }
    let node_v4 = node.internal_ips.iter().find_map(|ip| match ip {
        IpAddr::V4(ip) => Some(*ip),
        IpAddr::V6(_) => None,
    });
    if !v6 {
        let [_, _, _, last] = node_v4?.octets();
        return Some((IpAddr::V4(Ipv4Addr::new(10, last, 0, 0)), 16));
    }
    let tail = match alloc_cidr(node, false) {
        Some((IpAddr::V4(ip), _)) => ip.octets(),
        _ => {
            let ip = node.internal_ips.iter().find_map(|ip| match ip {
                IpAddr::V6(ip) => Some(*ip),
                IpAddr::V4(_) => None,
            })?;
            let [.., a, b, c, d] = ip.octets();
            [a, b, c, d]
        }
    };
    let [b0, b1, b2, b3] = IPV6_CLUSTER_ALLOC_BASE;
    let [t0, t1, t2, t3] = tail;
    let ip = Ipv6Addr::new(
        b0,
        b1,
        b2,
        b3,
        u16::from_be_bytes([t0, t1]),
        u16::from_be_bytes([t2, t3]),
        0,
        0,
    );
    Some((IpAddr::V6(ip), 96))
}

/// The router address: the first address after the network (what the
/// reference's first `allocate_next` returns). The prefix must leave room.
pub fn router_ip((network, prefix): (IpAddr, u8)) -> Result<IpAddr> {
    match network {
        IpAddr::V4(ip) if prefix <= 30 => {
            let host = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            let base = u32::from(ip) & !host;
            Ok(IpAddr::V4(Ipv4Addr::from(
                base.checked_add(1).ok_or("router overflow")?,
            )))
        }
        IpAddr::V6(ip) if prefix <= 126 => {
            let host = u128::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            let base = u128::from(ip) & !host;
            Ok(IpAddr::V6(Ipv6Addr::from(
                base.checked_add(1).ok_or("router overflow")?,
            )))
        }
        _ => Err("pod CIDR too small for a router address".into()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DesiredRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    /// The node's first InternalIP of the family (the plain route's gateway).
    pub gateway: IpAddr,
    /// Every InternalIP of the family, first one first: the ECMP paths over
    /// this node's uplinks pair with them (#408).
    pub gateways: Vec<IpAddr>,
    pub node: String,
}

/// The families whose pod CIDRs are derived for a Node that has none (#296,
/// option C): those where this agent's own pool is `auto`. Every agent of the
/// cluster applies `alloc_cidr`'s rule to every Node, so each one knows the
/// others' pools without an operator or Kubernetes node IPAM.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Derive {
    pub v4: bool,
    pub v6: bool,
}

/// A node's pod CIDRs: its `spec.podCIDRs`, plus, for each derived family it
/// has none of, the CIDR `alloc_cidr` derives (what that node's agent uses).
pub fn node_cidrs(node: &NodeInfo, derive: Derive) -> Vec<(IpAddr, u8)> {
    let mut cidrs = node.pod_cidrs.clone();
    for (v6, on) in [(false, derive.v4), (true, derive.v6)] {
        if on && !cidrs.iter().any(|(ip, _)| ip.is_ipv6() == v6) {
            cidrs.extend(alloc_cidr(node, v6));
        }
    }
    cidrs
}

/// The RFC 6052 gateway's sources (#454): this node's IPv6 pod CIDRs.
pub fn gateway64_sources(local: &str, nodes: &[NodeInfo], derive: Derive) -> Vec<([u8; 16], u8)> {
    nodes
        .iter()
        .filter(|n| n.name == local)
        .flat_map(|n| node_cidrs(n, derive))
        .filter_map(|(ip, prefix)| match ip {
            IpAddr::V6(v6) => Some((v6.octets(), prefix)),
            IpAddr::V4(_) => None,
        })
        .collect()
}

/// An IPv4 prefix (address octets, length).
pub type Prefix4 = ([u8; 4], u8);
/// The BPF masquerade's IPv4 prefixes (#460): (sources, never masqueraded).
/// Sources are this node's pod CIDRs. Not masqueraded: every node's pod
/// CIDRs and InternalIPs (traffic inside the cluster, as the reference
/// leaves it), and `non_masquerade`.
pub fn masquerade_prefixes(
    local: &str,
    nodes: &[NodeInfo],
    derive: Derive,
    non_masquerade: &[Cidr],
) -> (Vec<Prefix4>, Vec<Prefix4>) {
    let v4 = |(ip, prefix): (IpAddr, u8)| match ip {
        IpAddr::V4(v4) => Some((v4.octets(), prefix)),
        IpAddr::V6(_) => None,
    };
    let mut sources = BTreeSet::new();
    let mut exclude: BTreeSet<Prefix4> = non_masquerade.iter().copied().filter_map(v4).collect();
    for node in nodes {
        let cidrs = node_cidrs(node, derive);
        if node.name == local {
            sources.extend(cidrs.iter().copied().filter_map(v4));
        }
        exclude.extend(cidrs.into_iter().filter_map(v4));
        exclude.extend(node.internal_ips.iter().map(|ip| (*ip, 32)).filter_map(v4));
    }
    (sources.into_iter().collect(), exclude.into_iter().collect())
}

/// An IPv6 prefix (address octets, length).
pub type Prefix6 = ([u8; 16], u8);
/// [`masquerade_prefixes`] for IPv6 (#513): this node's IPv6 pod CIDRs, and
/// every node's IPv6 pod CIDRs and InternalIPs and the IPv6 `non_masquerade`
/// entries never masqueraded.
pub fn masquerade_prefixes6(
    local: &str,
    nodes: &[NodeInfo],
    derive: Derive,
    non_masquerade: &[Cidr],
) -> (Vec<Prefix6>, Vec<Prefix6>) {
    let v6 = |(ip, prefix): (IpAddr, u8)| match ip {
        IpAddr::V6(v6) => Some((v6.octets(), prefix)),
        IpAddr::V4(_) => None,
    };
    let mut sources = BTreeSet::new();
    let mut exclude: BTreeSet<Prefix6> = non_masquerade.iter().copied().filter_map(v6).collect();
    for node in nodes {
        let cidrs = node_cidrs(node, derive);
        if node.name == local {
            sources.extend(cidrs.iter().copied().filter_map(v6));
        }
        exclude.extend(cidrs.into_iter().filter_map(v6));
        exclude.extend(node.internal_ips.iter().map(|ip| (*ip, 128)).filter_map(v6));
    }
    (sources.into_iter().collect(), exclude.into_iter().collect())
}

/// Whether two CIDRs share an address (same family, equal under the shorter
/// prefix).
pub fn overlaps((a, a_len): (IpAddr, u8), (b, b_len): (IpAddr, u8)) -> bool {
    let shorter = u32::from(a_len.min(b_len));
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX
                .checked_shl(32u32.saturating_sub(shorter))
                .unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX
                .checked_shl(128u32.saturating_sub(shorter))
                .unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// The direct routes, and the pod CIDR collisions that withheld some.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutePlan {
    pub routes: Vec<DesiredRoute>,
    /// One line per pair of nodes whose pod CIDRs overlap.
    pub collisions: Vec<String>,
}

/// `<podCIDR> via <nodeIP>` for every other node and each of its pod CIDRs
/// (`node_cidrs`; spec 10 §3.2.3 native routing), using the node's first
/// InternalIP of that family. A node without one gets no route. Two nodes
/// whose CIDRs overlap (a derived rule can give the same 10.<byte>/16 to nodes
/// on different subnets) get no route for the overlapping CIDRs, and the
/// collision is reported: refusing is better than routing a pod's traffic to
/// the wrong node.
pub fn desired_routes(local: &str, nodes: &[NodeInfo], derive: Derive) -> RoutePlan {
    let cidrs: Vec<(&NodeInfo, Vec<(IpAddr, u8)>)> = nodes
        .iter()
        .map(|node| (node, node_cidrs(node, derive)))
        .collect();
    let mut refused = BTreeSet::new();
    let mut collisions = Vec::new();
    for (at, (a, a_cidrs)) in cidrs.iter().enumerate() {
        for (b, b_cidrs) in cidrs.iter().skip(at.saturating_add(1)) {
            for x in a_cidrs {
                for y in b_cidrs.iter().filter(|y| overlaps(*x, **y)) {
                    collisions.push(format!(
                        "nodes {} ({}) and {} ({}) have overlapping pod CIDRs",
                        a.name,
                        cidr_text(x.0, x.1),
                        b.name,
                        cidr_text(y.0, y.1)
                    ));
                    refused.insert((a.name.as_str(), *x));
                    refused.insert((b.name.as_str(), *y));
                }
            }
        }
    }
    let mut routes = BTreeSet::new();
    for (node, node_cidrs) in cidrs.iter().filter(|(node, _)| node.name != local) {
        for cidr in node_cidrs {
            if refused.contains(&(node.name.as_str(), *cidr)) {
                continue;
            }
            let (destination, prefix) = *cidr;
            let gateways: Vec<IpAddr> = node
                .internal_ips
                .iter()
                .copied()
                .filter(|ip| ip.is_ipv6() == destination.is_ipv6())
                .collect();
            if let Some(gateway) = gateways.first().copied() {
                routes.insert(DesiredRoute {
                    destination,
                    prefix,
                    gateway,
                    gateways,
                    node: node.name.clone(),
                });
            }
        }
    }
    RoutePlan {
        routes: routes.into_iter().collect(),
        collisions,
    }
}

pub type Shared = Arc<Mutex<View>>;
/// A panicked writer leaves a usable view; never poison the API with it.
pub fn lock(view: &Shared) -> MutexGuard<'_, View> {
    view.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Shared between the controller thread and the API thread.
#[derive(Debug, Default)]
pub struct View {
    pub local_node: String,
    pub nodes: Vec<NodeInfo>,
    pub pods: Vec<PodInfo>,
    pub nodes_synced: bool,
    pub pods_synced: bool,
    pub direct_routes: bool,
    /// Destination CIDR text -> (route, state text).
    pub routes: BTreeMap<String, (DesiredRoute, String)>,
    /// Socket LB: Services and EndpointSlices are watched.
    pub service_lb: bool,
    pub services: Vec<ServiceInfo>,
    pub slices: Vec<SliceInfo>,
    pub services_synced: bool,
    pub slices_synced: bool,
    /// The frontends derived from both lists, and the service ID the maps
    /// hold for each one that is programmed.
    pub frontends: Vec<Frontend>,
    pub service_ids: BTreeMap<(Address, u8), u16>,
    /// This node's endpoints and their Pods' annotation values (#328);
    /// nothing is written before the API thread first publishes them.
    pub endpoints: Vec<LocalEndpoint>,
    pub endpoints_published: bool,
    /// Cluster identities (spec 03 §3.3): allocation is on.
    pub identity: bool,
    pub cluster_name: String,
    /// Namespace name -> its labels (part of Pod identities).
    pub namespaces: BTreeMap<String, BTreeMap<String, String>>,
    pub namespaces_synced: bool,
    pub identity_objects: Vec<crate::identity::Object>,
    pub identities_synced: bool,
    /// (namespace, name) -> the Pod's identity: the one this node holds for a
    /// local Pod, else the oldest object with its labels (or well-known).
    pub pod_identities: BTreeMap<(String, String), u32>,
    /// Identity -> its labels: every FlowsdnIdentity plus well-known ones in use.
    pub identities: BTreeMap<u32, Vec<String>>,
    /// Local label sets still without an identity.
    pub identities_waiting: usize,
    /// NetworkPolicy enforcement (#292): the NetworkPolicy objects, and
    /// what the policy thread last programmed (`Desired::status`).
    pub network_policy: bool,
    pub network_policies: Vec<Value>,
    pub policies_synced: bool,
    pub policy_status: Value,
    /// The policies selecting each local endpoint, per direction, from the
    /// last policy pass (PacketDrop Events, #470).
    pub applied_policies: crate::policy::Applied,
    /// Pod rules of the flowsdn policy kinds (#292): the setting and the
    /// FlowsdnNetworkPolicy objects (the clusterwide kind is below).
    pub flowsdn_policy: bool,
    /// `policy-audit-mode` (#461): Pod endpoint rows carry the AUDIT flag.
    pub policy_audit: bool,
    pub pod_policies: Vec<Value>,
    pub pod_policies_synced: bool,
    /// The DNS proxy (#536): its port (0: not running), the names it saw
    /// answered and their addresses (`toFQDNs` selects from them), and its
    /// counters (`GET /v1/policy`'s `dns-proxy`).
    pub dns_proxy_port: u16,
    pub fqdn: flowsdn_l7::dns::cache::Cache,
    pub dns_status: Value,
    /// The host firewall (#379): its mode, the FlowsdnClusterwideNetworkPolicy
    /// objects, the uplinks (name -> ifindex) the policy thread wants it on
    /// (the API thread attaches it), and those still learning flows
    /// (`HOST_PODS`, 0, for local Pods' traffic to the host, #384). With it
    /// on, `host_addresses` are every global address of the node's
    /// interfaces, all with the host identity (#384).
    pub host_firewall: HostFirewall,
    pub clusterwide_policies: Vec<Value>,
    pub clusterwide_synced: bool,
    pub host_interfaces: BTreeMap<String, u32>,
    pub host_learning: BTreeSet<u32>,
    pub host_addresses: Vec<IpAddr>,
    /// The node's uplink ports, their carrier and failover (#408).
    pub uplinks: crate::uplinks::View,
    /// Managed neighbors (#469): what the neighbors thread last did; null
    /// while `l2-neigh-discovery` is off.
    pub neighbors: Value,
    /// The XDP prefilter's uplinks and modes (#467); null while off.
    pub prefilter: Value,
    /// LB-IPAM (#475): on, the FlowsdnLoadBalancerIPPool objects, and what
    /// the LB-IPAM thread last planned (`GET /v1/lb-ipam`).
    pub lb_ipam: bool,
    pub lb_pools: Vec<Value>,
    pub lb_pools_synced: bool,
    pub lb_ipam_status: Value,
    /// The FlowsdnEndpoint writer (#332): `{served, objects}` after its
    /// first pass, null before or when `kubernetes.endpoint-crd` is off.
    pub endpoint_crd_status: Value,
    /// The pod CIDR families derived when the Node has none (#296), so the
    /// FlowsdnNode writer publishes the pools this agent uses (#332), and
    /// that writer's last result (`{served}`, null before or when off).
    pub derive: Derive,
    pub node_crd_status: Value,
    /// The FlowsdnNodeConfig report of this start (#480).
    pub node_config: Value,
    /// L2 announcements (#475): on, the FlowsdnL2AnnouncementPolicy
    /// objects, and what the announcer last answered for.
    pub l2_announcements: bool,
    pub l2_policies: Vec<Value>,
    pub l2_policies_synced: bool,
    pub l2_status: Value,
    /// Local redirect policy (#565): on, the FlowsdnLocalRedirectPolicy
    /// objects, and what the last [`Self::refresh_frontends`] did with them.
    pub local_redirect: bool,
    pub redirect_policies: Vec<Value>,
    pub redirect_policies_synced: bool,
    pub redirect_report: crate::local_redirect::Report,
    /// Egress gateway (#564): on, the FlowsdnEgressGatewayPolicy objects,
    /// and what the services thread last planned (`GET /v1/egress-gateway`).
    pub egress_gateway: bool,
    pub egress_policies: Vec<Value>,
    pub egress_policies_synced: bool,
    pub egress_status: Value,
    /// The Services this node may announce, for the election thread (#549);
    /// `None` until the announcer has planned with complete lists.
    pub l2_eligible: Option<BTreeSet<crate::l2_announce::ServiceKey>>,
    /// The Services whose L2 announcement Lease this node holds, and until
    /// when (#549).
    pub l2_held: BTreeMap<crate::l2_announce::ServiceKey, std::time::Instant>,
    /// The latest failure of each controller part (`nodes`, `pods`, `routes`).
    pub errors: BTreeMap<String, String>,
}
impl View {
    /// Whether the policy thread has the lists it needs to compile (#292,
    /// #379). The host firewall alone does not wait for the
    /// FlowsdnClusterwideNetworkPolicy list (#402): before it is listed (the
    /// CRD may not be applied yet, stormcos#303) the host endpoint has no
    /// rules, so its uplinks stay as they are while learning (nothing judged,
    /// nothing dropped), and NetworkPolicy is not held back. Pod rules of the
    /// flowsdn kinds still wait: they may isolate Pods.
    pub fn policy_lists_ready(&self) -> bool {
        (!self.network_policy || self.policies_synced)
            && (!self.flowsdn_policy || (self.clusterwide_synced && self.pod_policies_synced))
            && self.pods_synced
            && self.nodes_synced
            && self.namespaces_synced
            && self.endpoints_published
    }
    fn host_ip(&self, node: &str, v6: bool) -> Option<IpAddr> {
        self.nodes
            .iter()
            .find(|n| n.name == node)
            .and_then(|n| n.internal_ips.iter().find(|ip| ip.is_ipv6() == v6).copied())
    }
    /// The identity labels of every Pod that is not host-network, with
    /// whether it is on this node; none before the Pod and Namespace lists
    /// are complete (a missing Namespace would change the labels).
    pub fn pod_label_sets(
        &self,
        filter: &flowsdn_identity::filter::LabelFilter,
    ) -> Vec<((String, String), bool, flowsdn_identity::labels::Labels)> {
        if !(self.pods_synced && self.namespaces_synced) {
            return Vec::new();
        }
        self.pods
            .iter()
            .filter(|pod| !pod.host_network)
            .map(|pod| {
                let labels = crate::identity::pod_labels(
                    &pod.namespace,
                    &pod.labels,
                    self.namespaces.get(&pod.namespace),
                    &pod.service_account,
                    &self.cluster_name,
                    filter,
                );
                (
                    (pod.namespace.clone(), pod.name.clone()),
                    pod.node == self.local_node,
                    labels,
                )
            })
            .collect()
    }
    pub fn pod_identity(&self, namespace: &str, name: &str) -> Option<u32> {
        self.pod_identities
            .get(&(namespace.to_owned(), name.to_owned()))
            .copied()
    }
    /// `GET /v1/identity` (reference `Identity` list): id and labels.
    pub fn identity_list(&self) -> Value {
        Value::Array(
            self.identities
                .iter()
                .map(|(id, labels)| json!({"id":id,"labels":labels}))
                .collect(),
        )
    }
    /// `GET /v1/ip` (reference `IPListEntry`): node InternalIPs with the
    /// reserved host/remote-node identities, and every Pod IP of a Pod that is
    /// not host-network, with its identity once it has one. `labels` is a
    /// flowsdn extension with the Pod's `k8s:` source labels (spec 03 §4.2),
    /// and the Pod metadata carries its UID, containers and workload (#328).
    pub fn ip_list(&self) -> Value {
        let mut rows = BTreeMap::new();
        for node in &self.nodes {
            let identity = if node.name == self.local_node {
                IDENTITY_HOST
            } else {
                IDENTITY_REMOTE_NODE
            };
            for ip in &node.internal_ips {
                rows.insert(
                    *ip,
                    json!({"cidr":host_cidr(*ip),"identity":identity,
                        "metadata":{"source":"kube-apiserver","name":node.name}}),
                );
            }
        }
        for pod in self.pods.iter().filter(|pod| !pod.host_network) {
            let labels = pod.endpoint_info().labels;
            for ip in &pod.ips {
                let mut metadata = json!({"source":"kube-apiserver","namespace":pod.namespace,
                    "name":pod.name,"uid":pod.uid,"containers":pod.containers_json()});
                if let (Some(workload), Some(object)) = (&pod.workload, metadata.as_object_mut()) {
                    object.insert(
                        "workloads".into(),
                        json!([{"name":workload.name,"kind":workload.kind}]),
                    );
                }
                let mut row = json!({"cidr":host_cidr(*ip),"labels":labels,"metadata":metadata});
                if let Some(object) = row.as_object_mut() {
                    if let Some(host) = self.host_ip(&pod.node, ip.is_ipv6()) {
                        object.insert("hostIP".into(), json!(host.to_string()));
                    }
                    if let Some(identity) = self.pod_identity(&pod.namespace, &pod.name) {
                        object.insert("identity".into(), json!(identity));
                    }
                }
                rows.entry(*ip).or_insert(row);
            }
        }
        Value::Array(rows.into_values().collect())
    }
    /// The Pod an endpoint belongs to: same namespace and name, on this node,
    /// and the same UID when both are known (a recreated Pod is another Pod).
    pub fn local_pod(&self, namespace: &str, name: &str, uid: &str) -> Option<&PodInfo> {
        self.pods.iter().find(|pod| {
            pod.namespace == namespace
                && pod.name == name
                && pod.node == self.local_node
                && (uid.is_empty() || pod.uid.is_empty() || pod.uid == uid)
        })
    }
    /// The `flowsdn.io/pod-networks` and `network-status` writes that would
    /// bring every local Pod up to date: none before the Pod list and the
    /// endpoints are known. Values compare as JSON, so key order never causes
    /// a rewrite. With two endpoints for one Pod (a sandbox being replaced),
    /// the newest ID wins. A network-status too large to have been kept is
    /// left alone (merging into what was not seen would drop entries).
    pub fn annotation_patches(&self) -> Vec<AnnotationPatch> {
        if !(self.pods_synced && self.endpoints_published) {
            return Vec::new();
        }
        let mut newest: BTreeMap<(&str, &str), &LocalEndpoint> = BTreeMap::new();
        for endpoint in &self.endpoints {
            if !dns_name(&endpoint.namespace) || !dns_name(&endpoint.name) {
                continue;
            }
            let entry = newest
                .entry((&endpoint.namespace, &endpoint.name))
                .or_insert(endpoint);
            if endpoint.id > entry.id {
                *entry = endpoint;
            }
        }
        let parse = |text: Option<&str>| text.and_then(|t| serde_json::from_str::<Value>(t).ok());
        newest
            .into_values()
            .filter_map(|endpoint| {
                let pod = self.local_pod(&endpoint.namespace, &endpoint.name, &endpoint.uid)?;
                let pod_networks = (parse(pod.pod_networks.as_deref()).as_ref()
                    != Some(&endpoint.value))
                .then(|| endpoint.value.to_string());
                let network_status = if pod.network_status_oversized {
                    None
                } else {
                    let current = parse(pod.network_status.as_deref());
                    let wanted = crate::tagging::network_status(
                        current.as_ref(),
                        &crate::tagging::network_status_entry(&endpoint.value),
                    );
                    (current.as_ref() != Some(&wanted)).then(|| wanted.to_string())
                };
                (pod_networks.is_some() || network_status.is_some()).then(|| AnnotationPatch {
                    namespace: endpoint.namespace.clone(),
                    name: endpoint.name.clone(),
                    uid: if endpoint.uid.is_empty() {
                        pod.uid.clone()
                    } else {
                        endpoint.uid.clone()
                    },
                    resource_version: pod.resource_version.clone(),
                    pod_networks,
                    network_status,
                })
            })
            .collect()
    }
    /// `GET /v1/node/routes` (flowsdn): the direct routes and their state.
    pub fn route_list(&self) -> Value {
        Value::Array(
            self.routes
                .iter()
                .map(|(cidr, (route, state))| {
                    json!({"destination":cidr,"gateway":route.gateway.to_string(),
                        "gateways":route.gateways.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "node":route.node,"state":state})
                })
                .collect(),
        )
    }
    /// Recompute the frontends once both Service and EndpointSlice lists
    /// are complete; None until then (nothing may be pruned before).
    pub fn refresh_frontends(&mut self) -> Option<Vec<flowsdn_lb::socket::Service>> {
        if !(self.services_synced && self.slices_synced) {
            return None;
        }
        let nodes: Vec<_> = self
            .nodes
            .iter()
            .map(|n| crate::services::NodeAddresses {
                name: n.name.clone(),
                ips: n.internal_ips.clone(),
                zone: n
                    .labels
                    .get(crate::services::ZONE_LABEL)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect();
        self.frontends =
            crate::services::frontends(&self.services, &self.slices, &self.local_node, &nodes);
        if self.local_redirect {
            self.redirect_report = crate::local_redirect::apply(
                &mut self.frontends,
                &self.redirect_policies,
                &self.pods,
                &self.local_node,
                &self.endpoints,
            );
        }
        Some(self.frontends.iter().map(|f| f.service.clone()).collect())
    }
    /// `GET /v1/lb-ipam`.
    pub fn lb_ipam_json(&self) -> Value {
        if self.lb_ipam_status.is_null() {
            json!({"enabled": self.lb_ipam, "leader": false, "synced": false,
                   "pools": [], "services": []})
        } else {
            let mut status = self.lb_ipam_status.clone();
            if let Some(object) = status.as_object_mut() {
                object.insert("enabled".into(), json!(self.lb_ipam));
            }
            status
        }
    }
    /// `GET /v1/l2-announcements`.
    pub fn l2_json(&self) -> Value {
        if self.l2_status.is_null() {
            json!({"enabled": self.l2_announcements, "policies": [], "announcing": [],
                   "errors": []})
        } else {
            let mut status = self.l2_status.clone();
            if let Some(object) = status.as_object_mut() {
                object.insert("enabled".into(), json!(self.l2_announcements));
            }
            status
        }
    }
    /// `GET /v1/egress-gateway`.
    pub fn egress_json(&self) -> Value {
        if self.egress_status.is_null() {
            json!({"enabled": self.egress_gateway, "entries": 0, "policies": []})
        } else {
            let mut status = self.egress_status.clone();
            if let Some(object) = status.as_object_mut() {
                object.insert("enabled".into(), json!(self.egress_gateway));
            }
            status
        }
    }
    /// `GET /v1/lrp`.
    pub fn lrp_json(&self) -> Value {
        self.redirect_report.json(self.local_redirect)
    }
    /// `GET /v1/service`.
    pub fn service_list(&self) -> Value {
        crate::services::service_list(&self.frontends, &self.service_ids)
    }
    /// The `kubernetes` member of `GET /v1/healthz`.
    /// Every list the enabled features need has been received once.
    pub fn synced(&self) -> bool {
        self.nodes_synced
            && self.pods_synced
            && (!self.service_lb || (self.services_synced && self.slices_synced))
            && (!self.identity || (self.namespaces_synced && self.identities_synced))
            && (!self.network_policy || (self.namespaces_synced && self.policies_synced))
            && (!self.flowsdn_policy
                || (self.namespaces_synced && self.pod_policies_synced && self.clusterwide_synced))
    }
    pub fn health(&self) -> Value {
        let errors: Vec<_> = self
            .errors
            .iter()
            .map(|(part, error)| format!("{part}: {error}"))
            .collect();
        let synced = self.synced();
        let (state, msg) = match (errors.is_empty(), synced) {
            (false, _) => ("Warning", errors.join("; ")),
            (true, false) => ("Warning", "waiting for the initial Kubernetes lists".into()),
            (true, true) => (
                "Ok",
                format!(
                    "{} nodes, {} pods, {} service frontends ({} programmed){}",
                    self.nodes.len(),
                    self.pods.len(),
                    self.frontends.len(),
                    self.service_ids.len(),
                    if self.identity {
                        format!(
                            ", {} identities ({} local label sets waiting)",
                            self.identities.len(),
                            self.identities_waiting
                        )
                    } else {
                        String::new()
                    }
                ),
            ),
        };
        json!({"state":state,"msg":msg,"node-name":self.local_node,
            "auto-direct-node-routes":self.direct_routes,"service-lb":self.service_lb,
            "identity-allocation":self.identity,"network-policy":self.network_policy,"flowsdn-policy":self.flowsdn_policy,
            "lb-ipam":self.lb_ipam,"l2-announcements":self.l2_announcements,
            "local-redirect-policy":self.local_redirect,"egress-gateway":self.egress_gateway,
            "flowsdn-endpoints":self.endpoint_crd_status,"flowsdn-node":self.node_crd_status,
            "node-config":self.node_config,
            "policy":self.policy_status,"dns-proxy":self.dns_status,"uplinks":self.uplinks.summary(),
            "neighbors":self.neighbors,"prefilter":self.prefilter})
    }
}

pub fn cidr_text(ip: IpAddr, prefix: u8) -> String {
    format!("{ip}/{prefix}")
}
fn host_cidr(ip: IpAddr) -> String {
    cidr_text(ip, if ip.is_ipv4() { 32 } else { 128 })
}

#[cfg(feature = "kubernetes")]
#[path = "kubernetes_controller.rs"]
pub mod controller;

#[cfg(test)]
#[path = "kubernetes_tests.rs"]
mod tests;
