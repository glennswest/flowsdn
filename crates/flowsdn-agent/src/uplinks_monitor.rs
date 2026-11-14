//! The uplink monitor thread (#408). Every 500 ms, for the node's whole life,
//! it reads every interface's carrier and addresses and applies
//! `crate::uplinks`' plan: failover host addresses with gratuitous ARP, the
//! sysctls balancing needs, flowsdn's source rules and tables. It publishes
//! the uplinks for the route thread, the NodePort attach and `/v1/uplinks`.
use super::*;
use crate::uplinks::apply::{
    FecCache, MOVES_FILE, default_gateways, global, load_moves, port_stats, read_ports, reconcile_kernel,
    save_moves, tune,
};
use crate::uplinks::{self, Change, Move, Port, Settings as UplinkSettings, Uplink};
use flowsdn_connector::multihome::{self, NextHop};

pub(super) const TICK: Duration = Duration::from_millis(500);
/// The kernel's rules and tables are compared at least this often.
const RESYNC: Duration = Duration::from_secs(30);
/// Gratuitous ARPs per announcement, one per tick.
const ANNOUNCEMENTS: u8 = 3;

struct Announce {
    index: u32,
    mac: [u8; 6],
    ip: std::net::Ipv4Addr,
    left: u8,
}

pub(super) fn monitor_loop(view: &Shared, settings: &UplinkSettings, state_dir: &Path) {
    let connector = match Connector::open() {
        Ok(connector) => connector,
        Err(error) => {
            lock(view)
                .errors
                .insert("uplinks".into(), format!("netlink: {error}"));
            return;
        }
    };
    let file = state_dir.join(MOVES_FILE);
    // Host addresses a previous agent added stay ours: they are not port
    // addresses, and the plan removes them once they are not wanted.
    let mut current: Vec<Move> = load_moves(&file).unwrap_or_else(|error| {
        crate::log::logln!("ignoring unreadable {}: {error}", file.display());
        Vec::new()
    });
    {
        let mut view = lock(view);
        view.uplinks.started = true;
        view.uplinks.mode = settings.mode;
    }
    let mut remembered: BTreeMap<String, Vec<Cidr>> = BTreeMap::new();
    let mut before: Vec<Uplink> = Vec::new();
    let mut announce: Vec<Announce> = Vec::new();
    let mut tuned: BTreeSet<String> = BTreeSet::new();
    let mut applied: Option<(uplinks::Desired, Instant)> = None;
    let mut fec = FecCache::new();
    let mut first = true;
    loop {
        if !first {
            std::thread::sleep(TICK);
        }
        first = false;
        let node_ips: Vec<IpAddr> = {
            let view = lock(view);
            view.nodes
                .iter()
                .find(|n| n.name == view.local_node)
                .map(|n| n.internal_ips.clone())
                .unwrap_or_default()
        };
        if node_ips.is_empty() {
            continue;
        }
        let mut failures = Vec::new();
        let ports = match read_ports(&connector, &current) {
            Ok(ports) => ports,
            Err(error) => {
                lock(view).errors.insert("uplinks".into(), error);
                continue;
            }
        };
        // A down port may lose its lease's address; it still owns it.
        let ports: Vec<Port> = ports
            .into_iter()
            .map(|mut port| {
                if port.addresses.iter().any(|(ip, _)| global(*ip)) {
                    remembered.insert(port.name.clone(), port.addresses.clone());
                } else if let Some(known) = remembered.get(&port.name).filter(|_| !port.carrier) {
                    port.addresses.clone_from(known);
                }
                port
            })
            .collect();
        let now = uplinks::select(&ports, &node_ips, settings);
        for change in uplinks::changes(&before, &now, &crate::log::now()) {
            report(&change);
            // A port back up announces its own addresses from itself.
            if change.joined
                && let Some(uplink) = now.iter().find(|u| u.name == change.port)
                && uplinks::balancing(&now, settings.mode)
            {
                queue(&mut announce, uplink.index, uplink.mac, &uplink.addresses);
            }
            lock(view).uplinks.record(change);
        }
        let wanted = uplinks::moves(&now, settings.mode);
        let moves_changed = wanted != current;
        for gone in current.iter().filter(|m| !wanted.contains(m)) {
            match connector.delete_address(gone.to_index, gone.address, gone.prefix()) {
                Ok(()) => crate::log::logln!(
                    "uplink failover: {} back to {} (removed from {})",
                    gone.address,
                    gone.from,
                    gone.to
                ),
                Err(error) => failures.push(format!(
                    "remove {}/{} from {}: {error}",
                    gone.address,
                    gone.prefix(),
                    gone.to
                )),
            }
        }
        for new in wanted.iter().filter(|m| !current.contains(m)) {
            match connector.add_address(new.to_index, new.address, new.prefix()) {
                Ok(()) => {}
                Err(error) if error.to_string().contains("exists") => {}
                Err(error) => {
                    failures.push(format!(
                        "add {}/{} on {}: {error}",
                        new.address,
                        new.prefix(),
                        new.to
                    ));
                    continue;
                }
            }
            crate::log::logln!(
                "uplink failover: {} of {} now held by {}",
                new.address,
                new.from,
                new.to
            );
            queue(
                &mut announce,
                new.to_index,
                new.to_mac,
                &[(new.address, new.prefix())],
            );
        }
        if moves_changed {
            current.clone_from(&wanted);
            if let Err(error) = save_moves(&file, &current) {
                failures.push(format!("persist {}: {error}", file.display()));
            }
        }
        for item in &mut announce {
            if let Err(error) = multihome::gratuitous_arp(item.index, item.mac, item.ip) {
                failures.push(format!("gratuitous ARP for {}: {error}", item.ip));
            }
            item.left = item.left.saturating_sub(1);
        }
        announce.retain(|a| a.left > 0);
        if uplinks::balancing(&now, settings.mode) {
            let fresh: Vec<String> = now
                .iter()
                .map(|u| u.name.clone())
                .filter(|name| !tuned.contains(name))
                .collect();
            for name in fresh {
                failures.extend(tune(Path::new("/proc/sys"), &name, &node_ips));
                tuned.insert(name);
            }
        }
        let defaults = default_gateways(&connector);
        let desired = uplinks::desired(&now, &current, settings, &defaults);
        let due = applied
            .as_ref()
            .is_none_or(|(last, at)| *last != desired || at.elapsed() >= RESYNC);
        if due {
            match reconcile_kernel(&connector, settings, &desired) {
                Ok(()) => applied = Some((desired, Instant::now())),
                Err(error) => {
                    failures.push(error);
                    applied = None;
                }
            }
        }
        let stats = port_stats(&now, &mut fec);
        let changed = before != now || moves_changed;
        before.clone_from(&now);
        let mut view = lock(view);
        view.uplinks.uplinks = now;
        view.uplinks.moves.clone_from(&current);
        view.uplinks.ports = stats;
        if changed {
            view.uplinks.generation = view.uplinks.generation.wrapping_add(1);
        }
        if failures.is_empty() {
            view.errors.remove("uplinks");
        } else {
            view.errors.insert("uplinks".into(), failures.join("; "));
        }
    }
}

fn report(change: &Change) {
    crate::log::logln!("{}", change.message);
    if change.joined {
        crate::events::node(
            crate::events::Type::Normal,
            "UplinkJoined",
            change.message.clone(),
        );
    } else {
        crate::events::node(Warning, "UplinkLeft", change.message.clone());
    }
}

fn queue(announce: &mut Vec<Announce>, index: u32, mac: [u8; 6], addresses: &[Cidr]) {
    for (ip, _) in addresses {
        if let IpAddr::V4(ip) = ip {
            announce.retain(|a| a.ip != *ip);
            announce.push(Announce {
                index,
                mac,
                ip: *ip,
                left: ANNOUNCEMENTS,
            });
        }
    }
}

/// The route thread's paths for a direct route (None: the plain route).
pub(super) fn route_hops(view: &Shared, route: &DesiredRoute) -> Option<Vec<NextHop>> {
    lock(view).uplinks.hops(&route.gateways)
}
