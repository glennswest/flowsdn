//! The uplink monitor thread (#408). Every 500 ms, for the node's whole life,
//! it reads every interface's carrier and addresses and applies
//! `crate::uplinks`' plan: failover host addresses with gratuitous ARP or an
//! unsolicited Neighbor Advertisement (IPv6, #497), the
//! sysctls balancing needs, flowsdn's source rules and tables. It publishes
//! the uplinks for the route thread, the NodePort attach and `/v1/uplinks`.
use super::*;
use crate::uplinks::apply::{
    FecCache, MOVES_FILE, default_gateways, global, load_moves, port_stats, read_ports,
    reconcile_kernel, save_moves, tune_pending,
};
use crate::uplinks::{self, Change, Move, Port, Settings as UplinkSettings, Uplink};
use flowsdn_connector::multihome::{self, NextHop};

pub(super) const TICK: Duration = Duration::from_millis(500);
/// The kernel's rules and tables are compared at least this often.
const RESYNC: Duration = Duration::from_secs(30);
/// Gratuitous ARPs or unsolicited NAs per announcement, one per tick.
const ANNOUNCEMENTS: u8 = 3;

#[derive(Debug, Eq, PartialEq)]
struct Announce {
    index: u32,
    mac: [u8; 6],
    ip: IpAddr,
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
        // Only changes that succeeded are held, so a failed one is tried
        // again next tick (#497).
        let result = uplinks::reconcile_moves(
            &current,
            &wanted,
            |gone| {
                connector
                    .delete_address(gone.to_index, gone.address, gone.prefix())
                    .map_err(|error| error.to_string())?;
                crate::log::logln!(
                    "uplink failover: {} back to {} (removed from {})",
                    gone.address,
                    gone.from,
                    gone.to
                );
                Ok(())
            },
            |new| match connector.add_address(new.to_index, new.address, new.prefix()) {
                Ok(()) => Ok(()),
                Err(error) if error.to_string().contains("exists") => Ok(()),
                Err(error) => Err(error.to_string()),
            },
        );
        failures.extend(result.failures);
        for new in &result.added {
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
        let moves_changed = result.held != current;
        if moves_changed {
            current = result.held;
            if let Err(error) = save_moves(&file, &current) {
                failures.push(format!("persist {}: {error}", file.display()));
            }
        }
        for item in &mut announce {
            let sent = match item.ip {
                IpAddr::V4(ip) => multihome::gratuitous_arp(item.index, item.mac, ip),
                IpAddr::V6(ip) => multihome::unsolicited_na(item.index, item.mac, ip),
            };
            if let Err(error) = sent {
                failures.push(format!("announce {}: {error}", item.ip));
            }
            item.left = item.left.saturating_sub(1);
        }
        announce.retain(|a| a.left > 0);
        if uplinks::balancing(&now, settings.mode) {
            // An uplink is tuned once every write succeeded (#497).
            failures.extend(tune_pending(
                Path::new("/proc/sys"),
                now.iter().map(|u| u.name.as_str()),
                &node_ips,
                &mut tuned,
            ));
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

/// Announce `addresses` from `index`/`mac`: IPv4 by gratuitous ARP, IPv6 by
/// unsolicited NA (#497; link-local addresses never move, so they are not
/// announced). A newer announcement of an address replaces an older one.
fn queue(announce: &mut Vec<Announce>, index: u32, mac: [u8; 6], addresses: &[Cidr]) {
    for (ip, _) in addresses {
        if let IpAddr::V6(v6) = ip
            && v6.is_unicast_link_local()
        {
            continue;
        }
        announce.retain(|a| a.ip != *ip);
        announce.push(Announce {
            index,
            mac,
            ip: *ip,
            left: ANNOUNCEMENTS,
        });
    }
}

/// The route thread's paths for a direct route (None: the plain route).
pub(super) fn route_hops(view: &Shared, route: &DesiredRoute) -> Option<Vec<NextHop>> {
    lock(view).uplinks.hops(&route.gateways)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #497 (finding 0cf4d2dfd14d): IPv6 failover addresses are announced
    /// (unsolicited NA) as IPv4 ones are (gratuitous ARP); link-local ones
    /// are not; a newer announcement replaces an older one.
    #[test]
    fn ipv6_addresses_are_announced_too() {
        let mut announce = Vec::new();
        let v4: IpAddr = "192.0.2.204".parse().expect("ip");
        let v6: IpAddr = "2001:db8::204".parse().expect("ip");
        let local: IpAddr = "fe80::1".parse().expect("ip");
        queue(&mut announce, 3, [2; 6], &[(v4, 32), (v6, 128), (local, 64)]);
        assert_eq!(
            announce,
            [
                Announce { index: 3, mac: [2; 6], ip: v4, left: ANNOUNCEMENTS },
                Announce { index: 3, mac: [2; 6], ip: v6, left: ANNOUNCEMENTS },
            ]
        );
        // The original port rejoins: it announces from itself.
        queue(&mut announce, 4, [4; 6], &[(v6, 64)]);
        assert_eq!(announce.len(), 2);
        assert!(announce.iter().any(|a| a.ip == v6 && a.index == 4 && a.mac == [4; 6]));
    }
}
