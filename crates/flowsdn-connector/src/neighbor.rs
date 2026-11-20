//! Managed neighbor entries (spec 10 §3.4, #469): the next hops a device
//! uses to reach an address (`RTM_GETROUTE` with `RTM_F_FIB_MATCH`), and
//! kernel-managed neighbor entries (`NTF_EXT_LEARNED` with
//! `NTF_EXT_MANAGED`, `NUD_NONE`) for them, which the kernel resolves and
//! keeps fresh by itself. Entries without `NTF_EXT_LEARNED` (an
//! administrator's) are never listed for removal here.
use super::{Connector, Result};
use futures_util::TryStreamExt;
use rtnetlink::packet_route::{
    AddressFamily,
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourExtFlags, NeighbourFlags, NeighbourMessage,
        NeighbourState,
    },
    route::{RouteAddress, RouteAttribute, RouteFlags, RouteMessage},
};
use std::net::IpAddr;

const ENETUNREACH: i32 = 101;
const EHOSTUNREACH: i32 = 113;
const ENOENT: i32 = 2;

/// How a device reaches an address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Lookup {
    /// The next hops on that device: gateways, or the address itself
    /// on-link.
    Hops(Vec<IpAddr>),
    /// No route on that device (`ENETUNREACH`, `EHOSTUNREACH`, or a route
    /// that leaves by another device).
    Unreachable,
}

fn route_address(address: &RouteAddress) -> Option<IpAddr> {
    match address {
        RouteAddress::Inet(ip) => Some((*ip).into()),
        RouteAddress::Inet6(ip) => Some((*ip).into()),
        _ => None,
    }
}

/// The next hops on device `oif` for `ip` in a FIB-match route answer
/// (spec 10 §3.4 step 2): its gateway; with multipath, every path's gateway
/// on `oif`; without a gateway, `ip` itself (on-link). A single-path route
/// that leaves by another device gives none.
pub fn hops_of(message: &RouteMessage, ip: IpAddr, oif: u32) -> Lookup {
    let mut gateway = None;
    let mut output = None;
    let mut multipath = None;
    for attribute in &message.attributes {
        match attribute {
            RouteAttribute::Gateway(address) => gateway = route_address(address),
            RouteAttribute::Oif(index) => output = Some(*index),
            RouteAttribute::MultiPath(hops) => multipath = Some(hops),
            _ => {}
        }
    }
    if let Some(hops) = multipath {
        let mut on_device = Vec::new();
        let mut on_link = false;
        for hop in hops.iter().filter(|h| h.interface_index == oif) {
            let mut via = None;
            for attribute in &hop.attributes {
                if let RouteAttribute::Gateway(address) = attribute {
                    via = route_address(address);
                }
            }
            match via {
                Some(gateway) if !on_device.contains(&gateway) => on_device.push(gateway),
                Some(_) => {}
                None => on_link = true,
            }
        }
        if on_link && !on_device.contains(&ip) {
            on_device.push(ip);
        }
        return if on_device.is_empty() {
            Lookup::Unreachable
        } else {
            Lookup::Hops(on_device)
        };
    }
    if output.is_some_and(|o| o != oif) {
        return Lookup::Unreachable;
    }
    Lookup::Hops(vec![gateway.unwrap_or(ip)])
}

fn family(ip: IpAddr) -> AddressFamily {
    if ip.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    }
}

impl Connector {
    /// `ip link set <index> up`.
    pub fn set_up(&self, index: u32) -> Result<()> {
        self.run(async {
            self.handle
                .link()
                .set(rtnetlink::LinkUnspec::new_with_index(index).up().build())
                .execute()
                .await?;
            Ok(())
        })
    }

    /// `ip route get <ip> oif <device> fibmatch`: how `oif` reaches `ip`.
    pub fn next_hops(&self, ip: IpAddr, oif: u32) -> Result<Lookup> {
        let mut request = RouteMessage::default();
        request.header.address_family = family(ip);
        request.header.destination_prefix_length = if ip.is_ipv4() { 32 } else { 128 };
        request.header.flags = RouteFlags::FibMatch | RouteFlags::LookupTable;
        request
            .attributes
            .push(RouteAttribute::Destination(match ip {
                IpAddr::V4(v4) => RouteAddress::Inet(v4),
                IpAddr::V6(v6) => RouteAddress::Inet6(v6),
            }));
        request.attributes.push(RouteAttribute::Oif(oif));
        self.run(async {
            match self.handle.route().get(request).execute().try_next().await {
                Ok(Some(message)) => Ok(hops_of(&message, ip, oif)),
                Ok(None) => Ok(Lookup::Unreachable),
                Err(rtnetlink::Error::NetlinkError(error))
                    if matches!(
                        error.raw_code().checked_neg(),
                        Some(ENETUNREACH | EHOSTUNREACH)
                    ) =>
                {
                    Ok(Lookup::Unreachable)
                }
                Err(error) => Err(error.into()),
            }
        })
    }

    /// Every `NTF_EXT_LEARNED` neighbor entry: (interface index, address).
    pub fn learned(&self) -> Result<Vec<(u32, IpAddr)>> {
        self.run(async {
            let mut stream = self.handle.neighbours().get().execute();
            let mut out = Vec::new();
            while let Some(message) = stream.try_next().await? {
                if !message.header.flags.contains(NeighbourFlags::ExtLearned) {
                    continue;
                }
                for attribute in &message.attributes {
                    if let NeighbourAttribute::Destination(address) = attribute {
                        let ip = match address {
                            NeighbourAddress::Inet(ip) => IpAddr::from(*ip),
                            NeighbourAddress::Inet6(ip) => IpAddr::from(*ip),
                            _ => continue,
                        };
                        out.push((message.header.ifindex, ip));
                    }
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        })
    }

    /// Whether the entry for `ip` on `index` is managed (`NTF_EXT_MANAGED`)
    /// and learned (`NTF_EXT_LEARNED`).
    pub fn is_managed(&self, index: u32, ip: IpAddr) -> Result<bool> {
        self.run(async {
            let mut stream = self.handle.neighbours().get().execute();
            while let Some(message) = stream.try_next().await? {
                if message.header.ifindex != index {
                    continue;
                }
                let mut matches = false;
                let mut managed = false;
                for attribute in &message.attributes {
                    match attribute {
                        NeighbourAttribute::Destination(NeighbourAddress::Inet(a)) => {
                            matches = IpAddr::from(*a) == ip;
                        }
                        NeighbourAttribute::Destination(NeighbourAddress::Inet6(a)) => {
                            matches = IpAddr::from(*a) == ip;
                        }
                        NeighbourAttribute::ExtFlags(flags) => {
                            managed = flags.contains(NeighbourExtFlags::Managed);
                        }
                        _ => {}
                    }
                }
                if matches {
                    return Ok(managed && message.header.flags.contains(NeighbourFlags::ExtLearned));
                }
            }
            Ok(false)
        })
    }

    /// `ip neigh replace <ip> dev <index> extern_learn managed`: the kernel
    /// resolves the entry and keeps it fresh.
    pub fn add_managed(&self, index: u32, ip: IpAddr) -> Result<()> {
        let mut request = self
            .handle
            .neighbours()
            .add(index, ip)
            .state(NeighbourState::None)
            .flags(NeighbourFlags::ExtLearned)
            .replace();
        request
            .message_mut()
            .attributes
            .push(NeighbourAttribute::ExtFlags(NeighbourExtFlags::Managed));
        self.run(async {
            request.execute().await?;
            Ok(())
        })
    }

    /// Delete the entry for `ip` on `index`; an absent one is success.
    pub fn delete_neighbor(&self, index: u32, ip: IpAddr) -> Result<()> {
        let mut message = NeighbourMessage::default();
        message.header.family = family(ip);
        message.header.ifindex = index;
        message
            .attributes
            .push(NeighbourAttribute::Destination(match ip {
                IpAddr::V4(v4) => NeighbourAddress::Inet(v4),
                IpAddr::V6(v6) => NeighbourAddress::Inet6(v6),
            }));
        self.run(async {
            match self.handle.neighbours().del(message).execute().await {
                Err(rtnetlink::Error::NetlinkError(error))
                    if error.raw_code().checked_neg() == Some(ENOENT) =>
                {
                    Ok(())
                }
                result => Ok(result?),
            }
        })
    }
}

/// The startup probe for managed neighbors (spec 10 §3.4,
/// kernel-requirements §4.7): in a network namespace of its own (on a
/// thread of its own, gone with it), a veth pair gets a managed entry, which
/// must read back as managed. Needs CAP_NET_ADMIN, as the agent has.
pub fn probe_managed() -> Result<()> {
    std::thread::Builder::new()
        .name("flowsdn-neigh-probe".into())
        .spawn(|| -> Result<()> {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)?;
            let connector = Connector::open()?;
            let link = connector.create_veth("probe0", "probe1", 1500)?;
            let peer = connector.require_link("probe1")?;
            connector.set_up(link.index)?;
            connector.set_up(peer.index)?;
            let probe = IpAddr::from([192, 0, 2, 1]);
            connector.add_managed(link.index, probe)?;
            if connector.is_managed(link.index, probe)? {
                Ok(())
            } else {
                Err(
                    "a managed neighbor entry (NTF_EXT_MANAGED) did not read back as managed"
                        .into(),
                )
            }
        })?
        .join()
        .map_err(|_| "the managed-neighbor probe panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtnetlink::packet_route::route::RouteNextHop;

    fn v4(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }
    fn gateway(text: &str) -> RouteAttribute {
        match v4(text) {
            IpAddr::V4(ip) => RouteAttribute::Gateway(RouteAddress::Inet(ip)),
            IpAddr::V6(ip) => RouteAttribute::Gateway(RouteAddress::Inet6(ip)),
        }
    }
    fn route(attributes: Vec<RouteAttribute>) -> RouteMessage {
        let mut message = RouteMessage::default();
        message.attributes = attributes;
        message
    }
    fn hop(index: u32, via: Option<&str>) -> RouteNextHop {
        let mut hop = RouteNextHop::default();
        hop.interface_index = index;
        hop.attributes = via.map(gateway).into_iter().collect();
        hop
    }

    #[test]
    fn a_gateway_route_gives_the_gateway() {
        let message = route(vec![gateway("192.0.2.9"), RouteAttribute::Oif(4)]);
        assert_eq!(
            hops_of(&message, v4("198.51.100.7"), 4),
            Lookup::Hops(vec![v4("192.0.2.9")])
        );
    }

    #[test]
    fn an_on_link_route_gives_the_address() {
        let message = route(vec![RouteAttribute::Oif(4)]);
        assert_eq!(
            hops_of(&message, v4("192.0.2.20"), 4),
            Lookup::Hops(vec![v4("192.0.2.20")])
        );
    }

    #[test]
    fn a_route_by_another_device_gives_none() {
        let message = route(vec![gateway("192.0.2.9"), RouteAttribute::Oif(5)]);
        assert_eq!(
            hops_of(&message, v4("198.51.100.7"), 4),
            Lookup::Unreachable
        );
    }

    #[test]
    fn multipath_gives_the_gateways_on_the_device() {
        let message = route(vec![RouteAttribute::MultiPath(vec![
            hop(4, Some("192.0.2.9")),
            hop(5, Some("192.0.2.10")),
            hop(4, Some("192.0.2.11")),
            hop(4, Some("192.0.2.9")),
        ])]);
        assert_eq!(
            hops_of(&message, v4("198.51.100.7"), 4),
            Lookup::Hops(vec![v4("192.0.2.9"), v4("192.0.2.11")])
        );
        assert_eq!(
            hops_of(&message, v4("198.51.100.7"), 6),
            Lookup::Unreachable
        );
        let on_link = route(vec![RouteAttribute::MultiPath(vec![hop(4, None)])]);
        assert_eq!(
            hops_of(&on_link, v4("198.51.100.7"), 4),
            Lookup::Hops(vec![v4("198.51.100.7")])
        );
    }
}
