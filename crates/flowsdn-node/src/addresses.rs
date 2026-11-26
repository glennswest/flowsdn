//! `node-addresses` from `devices` and the local table (spec 10 §3.1.6).
use crate::rows::{Device, NodeAddress, Prefix, Route};
use std::net::IpAddr;

/// `RT_SCOPE_HOST`: the default `address-scope-max`.
pub const SCOPE_HOST: u8 = 254;
/// `RT_SCOPE_LINK`.
pub const SCOPE_LINK: u8 = 253;
/// The local routing table.
pub const LOCAL_TABLE: u32 = 255;
/// The host device whose link-scope addresses always count.
pub const HOST_DEVICE: &str = "cilium_host";
/// The synthetic device of the fallback addresses.
pub const WILDCARD: &str = "*";

/// RFC 1918, RFC 4193 (ULA), link-local and loopback are private.
pub fn private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_unique_local() || v6.is_unicast_link_local() || v6.is_loopback()
        }
    }
}
fn within(addr: IpAddr, (net, len): &Prefix) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let shift = 32u32.saturating_sub(u32::from(*len));
            let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
            (u32::from(a) & mask) == (u32::from(*n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let shift = 128u32.saturating_sub(u32::from(*len));
            let mask = u128::MAX.checked_shl(shift).unwrap_or(0);
            (u128::from(a) & mask) == (u128::from(*n) & mask)
        }
        _ => false,
    }
}

/// Settings of the derivation.
#[derive(Clone, Debug, Default)]
pub struct Settings {
    /// `address-scope-max` (None: [`SCOPE_HOST`]).
    pub scope_max: Option<u8>,
    /// `nodeport-addresses`; empty: the first private address per family.
    pub nodeport_cidrs: Vec<Prefix>,
}

/// The `node-addresses` rows for `devices` (selected ones and [`HOST_DEVICE`])
/// and `local_routes` (every route: the local table's host-scope routes add
/// aliases, a default route picks the fallback device), sorted.
pub fn derive(devices: &[Device], local_routes: &[Route], settings: &Settings) -> Vec<NodeAddress> {
    let scope_max = settings.scope_max.unwrap_or(SCOPE_HOST);
    let mut out = Vec::new();
    for device in devices {
        let host = device.name == HOST_DEVICE;
        if !(device.selected || host) {
            continue;
        }
        let mut candidates: Vec<_> = device
            .addresses
            .iter()
            .filter(|a| !a.addr.is_loopback())
            .filter(|a| a.scope <= scope_max || (host && a.scope == SCOPE_LINK))
            .filter(|a| match a.addr {
                IpAddr::V6(v6) if v6.is_unicast_link_local() => host,
                _ => true,
            })
            .collect();
        // Non-secondary first, lower scope first, public first, then address.
        candidates.sort_by_key(|a| (a.secondary, a.scope, private(a.addr), a.addr));
        let mut primary4 = false;
        let mut primary6 = false;
        let mut node_port4 = false;
        let mut node_port6 = false;
        // Without nodeport-addresses: the first private address per family,
        // else the first public one.
        let pick = |v4: bool| -> Option<IpAddr> {
            let family: Vec<IpAddr> = candidates
                .iter()
                .map(|a| a.addr)
                .filter(|a| a.is_ipv4() == v4)
                .filter(|a| !matches!(a, IpAddr::V6(v6) if v6.is_unicast_link_local()))
                .collect();
            family
                .iter()
                .copied()
                .find(|a| private(*a))
                .or_else(|| family.first().copied())
        };
        let default_node_port = [pick(true), pick(false)];
        for candidate in &candidates {
            let addr = candidate.addr;
            let link_local = matches!(addr, IpAddr::V6(v6) if v6.is_unicast_link_local());
            let primary = !link_local
                && if addr.is_ipv4() {
                    !std::mem::replace(&mut primary4, true)
                } else {
                    !std::mem::replace(&mut primary6, true)
                };
            let node_port = !host
                && !link_local
                && if settings.nodeport_cidrs.is_empty() {
                    device.up
                        && default_node_port.contains(&Some(addr))
                        && if addr.is_ipv4() {
                            !std::mem::replace(&mut node_port4, true)
                        } else {
                            !std::mem::replace(&mut node_port6, true)
                        }
                } else {
                    settings.nodeport_cidrs.iter().any(|p| within(addr, p))
                };
            out.push(NodeAddress {
                addr,
                device: device.name.clone(),
                node_port,
                primary,
            });
        }
    }
    // Local-table host routes on a selected device (GCE-style alias IPs).
    for route in local_routes {
        if route.table != LOCAL_TABLE || route.scope != SCOPE_HOST || route.src.is_some() {
            continue;
        }
        let addr = route.dst.0;
        if addr.is_loopback() || addr.is_unspecified() {
            continue;
        }
        let Some(device) = devices
            .iter()
            .find(|d| d.index == route.link_index && d.selected)
        else {
            continue;
        };
        if out.iter().any(|a| a.addr == addr && a.device == device.name) {
            continue;
        }
        let has_primary = out
            .iter()
            .any(|a| a.device == device.name && a.primary && a.addr.is_ipv4() == addr.is_ipv4());
        out.push(NodeAddress {
            addr,
            device: device.name.clone(),
            node_port: settings.nodeport_cidrs.iter().any(|p| within(addr, p)),
            primary: !has_primary,
        });
    }
    // The fallback: the primaries of the best device (a default route's,
    // else the lowest index), not an lxc and not the host device.
    let best = devices
        .iter()
        .filter(|d| d.selected && !d.name.starts_with("lxc") && d.name != HOST_DEVICE)
        .min_by_key(|d| (!default_route(local_routes, d.index), d.index));
    if let Some(best) = best {
        let primaries: Vec<IpAddr> = out
            .iter()
            .filter(|a| a.device == best.name && a.primary)
            .map(|a| a.addr)
            .collect();
        for addr in primaries {
            out.push(NodeAddress {
                addr,
                device: WILDCARD.to_owned(),
                node_port: false,
                primary: true,
            });
        }
    }
    out.sort_by(|a, b| (a.addr, &a.device).cmp(&(b.addr, &b.device)));
    out
}

fn default_route(routes: &[Route], index: u32) -> bool {
    routes
        .iter()
        .any(|r| r.link_index == index && r.dst.1 == 0 && r.table != LOCAL_TABLE)
}

#[cfg(test)]
#[path = "addresses_tests.rs"]
mod tests;
