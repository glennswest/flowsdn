//! The LoadBalancer threads (#475): LB-IPAM, which holds the LB-IPAM Lease
//! and writes Services' ingress addresses and pools' conditions, and the L2
//! announcer, which answers ARP and NDP for the addresses this node is
//! elected for. Both plan from the shared view the watches fill
//! (`crate::lb_ipam`, `crate::l2_announce`).
use super::*;
use crate::l2_announce::{self, Announcement};
use crate::lb_ipam::{self, Pool};
use crate::lease::{Elector, Step, micro_time};
use flowsdn_connector::announce::{
    self, ALL_NODES, ALL_NODES_MAC, BROADCAST, ETH_P_ARP, ETH_P_IPV6, Socket,
};
use std::time::SystemTime;

/// The LB-IPAM Lease: one agent in the cluster writes.
pub(super) const LEASE_NAMESPACE: &str = "kube-system";
pub(super) const LEASE_NAME: &str = "flowsdn-lb-ipam";
const LEASE_DURATION: Duration = Duration::from_secs(15);
const IPAM_INTERVAL: Duration = Duration::from_secs(2);
/// The announcer waits for packets this long at a time, and re-plans
/// (and re-reads the interfaces) every `REPLAN`.
const ANNOUNCE_TICK: Duration = Duration::from_millis(250);
const REPLAN: Duration = Duration::from_secs(1);
/// Gratuitous ARPs / unsolicited NAs when an address arrives, one a second.
const ANNOUNCEMENTS: u8 = 3;

fn message(body: &Value) -> &str {
    body.get("message").and_then(Value::as_str).unwrap_or("")
}

/// The LB-IPAM thread, with its own client.
pub(super) fn ipam_loop(view: &Shared, kubeconfig: Option<&Path>, identity: &str) {
    let started = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|runtime| {
            let client = runtime
                .block_on(JsonClient::load(kubeconfig, TransportLimits::default()))
                .map_err(|e| e.to_string())?;
            Ok((runtime, client))
        });
    let (runtime, client) = match started {
        Ok(parts) => parts,
        Err(error) => {
            lock(view).errors.insert("lb-ipam".into(), error);
            return;
        }
    };
    let mut elector = Elector::new(LEASE_NAMESPACE, LEASE_NAME, identity, LEASE_DURATION);
    let mut reported: BTreeMap<(String, String), (Vec<IpAddr>, Option<String>)> = BTreeMap::new();
    loop {
        std::thread::sleep(IPAM_INTERVAL);
        let (pools, services) = {
            let view = lock(view);
            if !(view.services_synced && view.lb_pools_synced) {
                continue;
            }
            (view.lb_pools.clone(), view.services.clone())
        };
        let mut failures = Vec::new();
        let now = Instant::now();
        let read = runtime.block_on(client.send_json(http::Method::GET, &elector.path(), None));
        let step = match read {
            Ok((200, lease)) => {
                Some(elector.step(now, &micro_time(SystemTime::now()), Some(&lease)))
            }
            Ok((404, _)) => Some(elector.step(now, &micro_time(SystemTime::now()), None)),
            Ok((status, body)) => {
                failures.push(format!("lease: HTTP {status} {}", message(&body)));
                None
            }
            Err(error) => {
                failures.push(format!("lease: {error}"));
                None
            }
        };
        let write = match step {
            Some(Step::Create(body)) => Some((http::Method::POST, elector.collection(), body)),
            Some(Step::Update(body)) => Some((http::Method::PUT, elector.path(), body)),
            Some(Step::Wait) | None => None,
        };
        if let Some((method, path, body)) = write {
            match runtime.block_on(client.send_json(method, &path, Some(&body))) {
                Ok((200..=299, _)) => elector.wrote(now, true),
                // Another agent wrote first: it leads.
                Ok((409, _)) => elector.wrote(now, false),
                Ok((status, body)) => {
                    elector.wrote(now, false);
                    failures.push(format!("lease: HTTP {status} {}", message(&body)));
                }
                Err(error) => {
                    elector.wrote(now, false);
                    failures.push(format!("lease: {error}"));
                }
            }
        }
        let leading = elector.leading(Instant::now());
        let pools: Vec<Pool> = pools.iter().map(Pool::parse).collect();
        let plan = lb_ipam::plan(
            &pools,
            &services,
            &crate::events::rfc3339(SystemTime::now()),
        );
        for desired in plan.services.values() {
            let key = (desired.namespace.clone(), desired.name.clone());
            let seen = (desired.ips.clone(), desired.problem.clone());
            if reported.get(&key) != Some(&seen) {
                let ips: Vec<String> = desired.ips.iter().map(ToString::to_string).collect();
                crate::log::logln!(
                    "lb-ipam: {}/{} -> [{}]{}",
                    desired.namespace,
                    desired.name,
                    ips.join(", "),
                    desired
                        .problem
                        .as_ref()
                        .map(|p| format!(" ({p})"))
                        .unwrap_or_default()
                );
                reported.insert(key, seen);
            }
        }
        reported.retain(|key, _| plan.services.contains_key(key));
        if leading {
            for desired in plan.patches(&services) {
                let reply = runtime.block_on(client.send_json(
                    http::Method::PATCH,
                    &desired.path(),
                    Some(&desired.body()),
                ));
                match reply {
                    // 409: the Service changed since it was listed; the
                    // watch brings it and the next tick plans again.
                    Ok((200..=299 | 404 | 409, _)) => {}
                    Ok((status, body)) => failures.push(format!(
                        "{}/{}: HTTP {status} {}",
                        desired.namespace,
                        desired.name,
                        message(&body)
                    )),
                    Err(error) => {
                        failures.push(format!("{}/{}: {error}", desired.namespace, desired.name));
                    }
                }
            }
            for pool in &plan.pools {
                let Some(conditions) = &pool.conditions else {
                    continue;
                };
                let reply = runtime.block_on(client.send_json(
                    http::Method::PATCH,
                    &pool.path(),
                    Some(&lb_ipam::pool_body(conditions)),
                ));
                match reply {
                    Ok((200..=299 | 404 | 409, _)) => {}
                    Ok((status, body)) => failures.push(format!(
                        "pool {}: HTTP {status} {}",
                        pool.name,
                        message(&body)
                    )),
                    Err(error) => failures.push(format!("pool {}: {error}", pool.name)),
                }
            }
        }
        let mut view = lock(view);
        view.lb_ipam_status = lb_ipam::status_json(&plan, leading, true);
        if failures.is_empty() {
            view.errors.remove("lb-ipam");
        } else {
            view.errors.insert("lb-ipam".into(), failures.join("; "));
        }
    }
}

/// This node's interfaces: name -> (ifindex, MAC).
fn interfaces() -> BTreeMap<String, (u32, [u8; 6])> {
    let mut out = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let read = |key: &str| fs::read_to_string(entry.path().join(key)).ok();
        let Some(index) = read("ifindex").and_then(|i| i.trim().parse::<u32>().ok()) else {
            continue;
        };
        let mac = read("address")
            .map(|m| crate::uplinks::apply::parse_mac(&m))
            .unwrap_or_default();
        out.insert(name, (index, mac));
    }
    out
}

/// One interface the announcer answers on.
struct Port {
    index: u32,
    mac: [u8; 6],
    arp: Option<Socket>,
    nd: Option<Socket>,
    groups: BTreeSet<[u8; 6]>,
    addresses: Vec<IpAddr>,
}

/// An address still to be announced `left` more times on an interface.
struct Pending {
    interface: String,
    ip: IpAddr,
    left: u8,
    next: Instant,
}

/// The L2 announcer thread.
pub(super) fn announce_loop(view: &Shared) {
    let mut ports: BTreeMap<String, Port> = BTreeMap::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut parsed: Option<(Vec<Value>, Vec<l2_announce::Policy>)> = None;
    let mut current: Vec<Announcement> = Vec::new();
    let mut planned: Option<Instant> = None;
    let mut names: BTreeMap<String, (u32, [u8; 6])> = BTreeMap::new();
    // Problems found while reconciling, kept until the next plan.
    let mut setup: Vec<String> = Vec::new();
    loop {
        let mut errors: Vec<String> = Vec::new();
        let replan = planned.is_none_or(|at| at.elapsed() >= REPLAN);
        if replan {
            planned = Some(Instant::now());
            names = interfaces();
        }
        let wanted = if !replan {
            None
        } else {
            let view = lock(view);
            if !(view.l2_policies_synced
                && view.services_synced
                && view.slices_synced
                && view.nodes_synced)
            {
                None
            } else {
                if parsed
                    .as_ref()
                    .is_none_or(|(raw, _)| *raw != view.l2_policies)
                {
                    let policies = view
                        .l2_policies
                        .iter()
                        .map(l2_announce::Policy::parse)
                        .collect();
                    parsed = Some((view.l2_policies.clone(), policies));
                }
                let policies = parsed
                    .as_ref()
                    .map(|(_, p)| p.as_slice())
                    .unwrap_or_default();
                let interface_names: Vec<String> = names.keys().cloned().collect();
                Some(l2_announce::plan(
                    policies,
                    &view.services,
                    &view.slices,
                    &view.nodes,
                    &view.local_node,
                    &view.uplinks.uplinks,
                    &interface_names,
                ))
            }
        };
        if let Some(wanted) = wanted {
            setup.clear();
            for gone in current.iter().filter(|a| !wanted.contains(a)) {
                crate::log::logln!(
                    "l2: no longer answering for {} ({}/{})",
                    gone.ip,
                    gone.namespace,
                    gone.name
                );
            }
            for new in wanted.iter().filter(|a| !current.contains(a)) {
                crate::log::logln!(
                    "l2: answering for {} ({}/{}) on {}",
                    new.ip,
                    new.namespace,
                    new.name,
                    new.interfaces.join(", ")
                );
            }
            let mut by_port: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
            for a in &wanted {
                for name in &a.interfaces {
                    by_port.entry(name.clone()).or_default().push(a.ip);
                }
            }
            ports.retain(|name, _| by_port.contains_key(name));
            for (name, addresses) in by_port {
                let Some((index, mac)) = names.get(&name).copied() else {
                    setup.push(format!("{name}: no such interface"));
                    continue;
                };
                let port = ports.entry(name.clone()).or_insert_with(|| Port {
                    index,
                    mac,
                    arp: None,
                    nd: None,
                    groups: BTreeSet::new(),
                    addresses: Vec::new(),
                });
                if port.index != index || port.mac != mac {
                    *port = Port {
                        index,
                        mac,
                        arp: None,
                        nd: None,
                        groups: BTreeSet::new(),
                        addresses: Vec::new(),
                    };
                }
                let v4 = addresses.iter().any(IpAddr::is_ipv4);
                let v6 = addresses.iter().any(IpAddr::is_ipv6);
                if !v4 {
                    port.arp = None;
                } else if port.arp.is_none() {
                    match Socket::open(index, ETH_P_ARP) {
                        Ok(socket) => port.arp = Some(socket),
                        Err(error) => setup.push(format!("{name} ARP: {error}")),
                    }
                }
                if !v6 {
                    port.nd = None;
                    port.groups.clear();
                } else if port.nd.is_none() {
                    match Socket::open(index, ETH_P_IPV6) {
                        Ok(socket) => {
                            port.nd = Some(socket);
                            port.groups.clear();
                        }
                        Err(error) => setup.push(format!("{name} NDP: {error}")),
                    }
                }
                if let Some(nd) = &port.nd {
                    let groups: BTreeSet<[u8; 6]> = addresses
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V6(v6) => Some(announce::solicited_node_mac(*v6)),
                            IpAddr::V4(_) => None,
                        })
                        .collect();
                    for group in groups.difference(&port.groups) {
                        if let Err(error) = nd.membership(*group, true) {
                            setup.push(format!("{name} multicast: {error}"));
                        }
                    }
                    for group in port.groups.difference(&groups) {
                        let _ = nd.membership(*group, false);
                    }
                    port.groups = groups;
                }
                for ip in addresses.iter().filter(|ip| !port.addresses.contains(ip)) {
                    pending.retain(|p| !(p.interface == name && p.ip == *ip));
                    pending.push(Pending {
                        interface: name.clone(),
                        ip: *ip,
                        left: ANNOUNCEMENTS,
                        next: Instant::now(),
                    });
                }
                port.addresses = addresses;
            }
            current = wanted;
        }
        // Gratuitous ARP / unsolicited NA for addresses this node took.
        let now = Instant::now();
        for item in pending.iter_mut().filter(|p| p.next <= now) {
            let Some(port) = ports.get(&item.interface) else {
                item.left = 0;
                continue;
            };
            let sent = match item.ip {
                IpAddr::V4(v4) => port.arp.as_ref().map(|s| {
                    s.send(
                        BROADCAST,
                        &flowsdn_connector::multihome::gratuitous_arp_payload(port.mac, v4),
                    )
                }),
                IpAddr::V6(v6) => port.nd.as_ref().map(|s| {
                    s.send(
                        ALL_NODES_MAC,
                        &announce::advertisement(v6, port.mac, ALL_NODES, false),
                    )
                }),
            };
            if let Some(Err(error)) = sent {
                errors.push(format!("{} announce {}: {error}", item.interface, item.ip));
            }
            item.left = item.left.saturating_sub(1);
            item.next = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        }
        pending.retain(|p| p.left > 0 && ports.contains_key(&p.interface));
        // Answer until the next plan.
        let sockets: Vec<&Socket> = ports
            .values()
            .flat_map(|p| p.arp.iter().chain(p.nd.iter()))
            .collect();
        if let Err(error) = Socket::wait(&sockets, ANNOUNCE_TICK) {
            errors.push(format!("poll: {error}"));
            std::thread::sleep(ANNOUNCE_TICK);
        }
        for (name, port) in &ports {
            for socket in port.arp.iter().chain(port.nd.iter()) {
                loop {
                    match socket.receive() {
                        Ok(Some(received)) => {
                            if let Some((to, reply)) = announce::answer(
                                socket.protocol,
                                &received,
                                &port.addresses,
                                port.mac,
                            ) && let Err(error) = socket.send(to, &reply)
                            {
                                errors.push(format!("{name} reply: {error}"));
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            errors.push(format!("{name} receive: {error}"));
                            break;
                        }
                    }
                }
            }
        }
        errors.extend(setup.iter().cloned());
        let mut view = lock(view);
        let policies = parsed
            .as_ref()
            .map(|(_, p)| p.as_slice())
            .unwrap_or_default();
        view.l2_status = l2_announce::status_json(&current, policies, &errors);
        if errors.is_empty() {
            view.errors.remove("l2-announcements");
        } else {
            view.errors
                .insert("l2-announcements".into(), errors.join("; "));
        }
    }
}
