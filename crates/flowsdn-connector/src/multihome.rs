//! The kernel operations a node with several uplink ports needs (#408):
//! per-flow ECMP routes (one nexthop per port), source rules that pin an
//! address to its port, the failover host address on a live port and its
//! gratuitous ARP, and a port's FEC through `SIOCETHTOOL`.
use crate::{Connector, Result};
use futures_util::TryStreamExt;
use rtnetlink::{
    IpVersion, RouteMessageBuilder, RouteNextHopBuilder,
    packet_route::{
        AddressFamily,
        route::{
            RouteAddress, RouteAttribute, RouteMessage, RouteNextHop, RouteProtocol, RouteScope,
            RouteType,
        },
        rule::{RuleAction, RuleAttribute, RuleMessage},
    },
};
use std::net::{IpAddr, Ipv4Addr};

/// One path of a route: through `index`, via `gateway` (None: on the link),
/// with a relative `weight` of at least 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct NextHop {
    pub gateway: Option<IpAddr>,
    pub index: u32,
    pub weight: u8,
}

/// An `ip rule`: at `priority`, look up `table` for packets from `source`
/// and to `destination` (both optional); `suppress_prefix` is
/// `suppress_prefixlength`.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Rule {
    pub v6: bool,
    pub priority: u32,
    pub table: u32,
    pub source: Option<(IpAddr, u8)>,
    pub destination: Option<(IpAddr, u8)>,
    pub suppress_prefix: Option<u32>,
}

/// A route this module owns (protocol kernel) in some table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    pub table: u32,
    pub protocol: u8,
    pub multipath: bool,
    pub gateway: Option<IpAddr>,
}

const RTPROT_KERNEL: u8 = 2;

impl Connector {
    /// `ip route replace <destination/prefix> [table] [metric] proto kernel`
    /// with one path per hop: a single hop is a plain route with its device;
    /// several are an ECMP route the kernel hashes per flow
    /// (`fib_multipath_hash_policy`). `source` is the preferred source.
    pub fn replace_multipath_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        hops: &[NextHop],
        table: u32,
        metric: Option<u32>,
        source: Option<IpAddr>,
    ) -> Result<()> {
        let message = multipath_route(destination, prefix, hops, table, metric, source)?;
        self.run(async {
            self.handle.route().add(message).replace().execute().await?;
            Ok(())
        })
    }
    /// Delete the protocol-kernel route to exactly `destination/prefix` in
    /// `table` (and `metric`), all its paths; an absent route is success.
    pub fn delete_owned_route(
        &self,
        destination: IpAddr,
        prefix: u8,
        table: u32,
        metric: Option<u32>,
    ) -> Result<()> {
        let mut builder = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(destination, prefix)?
            .protocol(RouteProtocol::Kernel)
            .table_id(table);
        if let Some(metric) = metric {
            builder = builder.priority(metric);
        }
        let message = builder.build();
        self.run(async {
            match self.handle.route().del(message).execute().await {
                Err(rtnetlink::Error::NetlinkError(error)) if error.raw_code() == -3 => Ok(()),
                result => Ok(result?),
            }
        })
    }
    /// The unicast routes of one family in `table` (any protocol).
    pub fn table_routes(&self, table: u32, v6: bool) -> Result<Vec<TableRoute>> {
        self.run(async {
            let mut request = RouteMessage::default();
            request.header.address_family = family(v6);
            let mut stream = self.handle.route().get(request).execute();
            let mut result = Vec::new();
            while let Some(message) = stream.try_next().await? {
                if let Some(route) = table_route(message)
                    && route.table == table
                {
                    result.push(route);
                }
            }
            Ok(result)
        })
    }
    /// The rules of one family.
    pub fn rules(&self, v6: bool) -> Result<Vec<Rule>> {
        self.run(async {
            let version = if v6 { IpVersion::V6 } else { IpVersion::V4 };
            let mut stream = self.handle.rule().get(version).execute();
            let mut result = Vec::new();
            while let Some(message) = stream.try_next().await? {
                result.push(rule_info(&message, v6));
            }
            Ok(result)
        })
    }
    pub fn add_rule(&self, rule: &Rule) -> Result<()> {
        let message = rule_message(rule);
        self.run(async {
            let mut request = self.handle.rule().add();
            *request.message_mut() = message;
            request.execute().await?;
            Ok(())
        })
    }
    /// Delete exactly that rule; an absent rule (ENOENT) is success.
    pub fn delete_rule(&self, rule: &Rule) -> Result<()> {
        let message = rule_message(rule);
        self.run(async {
            match self.handle.rule().del(message).execute().await {
                Err(rtnetlink::Error::NetlinkError(error)) if error.raw_code() == -2 => Ok(()),
                result => Ok(result?),
            }
        })
    }
    /// `ip address del <address>/<prefix> dev <index>`; absent is success.
    pub fn delete_address(&self, index: u32, address: IpAddr, prefix: u8) -> Result<()> {
        let message = match address {
            IpAddr::V4(ip) => rtnetlink::AddressMessageBuilder::<Ipv4Addr>::new()
                .index(index)
                .address(ip, prefix)
                .build(),
            IpAddr::V6(ip) => rtnetlink::AddressMessageBuilder::<std::net::Ipv6Addr>::new()
                .index(index)
                .address(ip, prefix)
                .build(),
        };
        self.run(async {
            match self.handle.address().del(message).execute().await {
                Err(rtnetlink::Error::NetlinkError(error))
                    if matches!(error.raw_code(), -99 | -19) =>
                {
                    Ok(())
                }
                result => Ok(result?),
            }
        })
    }
}

fn family(v6: bool) -> AddressFamily {
    if v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    }
}

pub(crate) fn multipath_route(
    destination: IpAddr,
    prefix: u8,
    hops: &[NextHop],
    table: u32,
    metric: Option<u32>,
    source: Option<IpAddr>,
) -> Result<RouteMessage> {
    let v6 = destination.is_ipv6();
    if hops.is_empty() {
        return Err("a route needs at least one path".into());
    }
    if hops
        .iter()
        .any(|h| h.index == 0 || h.weight == 0 || h.gateway.is_some_and(|g| g.is_ipv6() != v6))
        || source.is_some_and(|s| s.is_ipv6() != v6)
    {
        return Err("invalid route path".into());
    }
    let mut builder = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(destination, prefix)?
        .protocol(RouteProtocol::Kernel)
        .table_id(table);
    if hops.iter().all(|h| h.gateway.is_none()) {
        builder = builder.scope(RouteScope::Link);
    }
    if let Some(metric) = metric {
        builder = builder.priority(metric);
    }
    match hops {
        [hop] => {
            builder = builder.output_interface(hop.index);
            if let Some(gateway) = hop.gateway {
                builder = builder.gateway(gateway)?;
            }
        }
        _ => {
            let mut paths: Vec<RouteNextHop> = Vec::with_capacity(hops.len());
            for hop in hops {
                let mut path = RouteNextHopBuilder::new(family(v6)).interface(hop.index);
                if let Some(gateway) = hop.gateway {
                    path = path.via(gateway)?;
                }
                let mut path = path.build();
                path.hops = hop.weight.saturating_sub(1);
                paths.push(path);
            }
            builder = builder.multipath(paths);
        }
    }
    let mut message = builder.build();
    if let Some(source) = source {
        message
            .attributes
            .push(RouteAttribute::PrefSource(RouteAddress::from(source)));
    }
    Ok(message)
}

fn table_route(message: RouteMessage) -> Option<TableRoute> {
    let mut route = TableRoute {
        destination: match message.header.address_family {
            AddressFamily::Inet => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            AddressFamily::Inet6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            _ => return None,
        },
        prefix: message.header.destination_prefix_length,
        table: u32::from(message.header.table),
        protocol: u8::from(message.header.protocol),
        multipath: false,
        gateway: None,
    };
    for attribute in message.attributes {
        match attribute {
            RouteAttribute::Table(value) => route.table = value,
            RouteAttribute::Destination(RouteAddress::Inet(ip)) => route.destination = ip.into(),
            RouteAttribute::Destination(RouteAddress::Inet6(ip)) => route.destination = ip.into(),
            RouteAttribute::Gateway(RouteAddress::Inet(ip)) => route.gateway = Some(ip.into()),
            RouteAttribute::Gateway(RouteAddress::Inet6(ip)) => route.gateway = Some(ip.into()),
            RouteAttribute::MultiPath(_) => route.multipath = true,
            _ => {}
        }
    }
    (message.header.kind == RouteType::Unicast).then_some(route)
}

/// Whether a dumped route is one flowsdn installed (protocol kernel through a
/// gateway or several paths; the kernel's own subnet routes have neither).
pub fn owned(route: &TableRoute) -> bool {
    route.protocol == RTPROT_KERNEL && (route.multipath || route.gateway.is_some())
}

fn rule_message(rule: &Rule) -> RuleMessage {
    let mut message = RuleMessage::default();
    message.header.family = family(rule.v6);
    message.header.action = RuleAction::ToTable;
    if let Ok(table) = u8::try_from(rule.table) {
        message.header.table = table;
    } else {
        message.header.table = 0;
        message.attributes.push(RuleAttribute::Table(rule.table));
    }
    message
        .attributes
        .push(RuleAttribute::Priority(rule.priority));
    if let Some((ip, prefix)) = rule.source {
        message.header.src_len = prefix;
        message.attributes.push(RuleAttribute::Source(ip));
    }
    if let Some((ip, prefix)) = rule.destination {
        message.header.dst_len = prefix;
        message.attributes.push(RuleAttribute::Destination(ip));
    }
    if let Some(length) = rule.suppress_prefix {
        message
            .attributes
            .push(RuleAttribute::SuppressPrefixLen(length));
    }
    message
}

fn rule_info(message: &RuleMessage, v6: bool) -> Rule {
    let mut rule = Rule {
        v6,
        priority: 0,
        table: u32::from(message.header.table),
        source: None,
        destination: None,
        suppress_prefix: None,
    };
    for attribute in &message.attributes {
        match attribute {
            RuleAttribute::Priority(value) => rule.priority = *value,
            RuleAttribute::Table(value) => rule.table = *value,
            RuleAttribute::Source(ip) => rule.source = Some((*ip, message.header.src_len)),
            RuleAttribute::Destination(ip) => {
                rule.destination = Some((*ip, message.header.dst_len));
            }
            // The kernel reports "no suppression" as u32::MAX.
            RuleAttribute::SuppressPrefixLen(value) if *value != u32::MAX => {
                rule.suppress_prefix = Some(*value);
            }
            _ => {}
        }
    }
    rule
}

/// The 28-byte ARP request announcing `ip` at `mac` (sender = target).
pub fn gratuitous_arp_payload(mac: [u8; 6], ip: Ipv4Addr) -> [u8; 28] {
    let mut packet = [0u8; 28];
    let mut at = 0usize;
    let mut put = |bytes: &[u8]| {
        for byte in bytes {
            if let Some(slot) = packet.get_mut(at) {
                *slot = *byte;
            }
            at = at.saturating_add(1);
        }
    };
    put(&1u16.to_be_bytes()); // Ethernet
    put(&0x0800u16.to_be_bytes()); // IPv4
    put(&[6, 4]);
    put(&1u16.to_be_bytes()); // request
    put(&mac);
    put(&ip.octets());
    put(&[0; 6]);
    put(&ip.octets());
    packet
}

const ETH_P_ARP: u16 = 0x0806;

/// Broadcast a gratuitous ARP for `ip` from `mac` on interface `index`, so
/// the switch and the peers move the address to this port at once.
#[allow(unsafe_code)]
pub fn gratuitous_arp(index: u32, mac: [u8; 6], ip: Ipv4Addr) -> Result<()> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let payload = gratuitous_arp_payload(mac, ip);
    // SAFETY: plain socket(2); the descriptor is owned at once.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_ARP.to_be()),
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: raw is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = ETH_P_ARP.to_be();
    address.sll_ifindex = i32::try_from(index)?;
    address.sll_halen = 6;
    for slot in address.sll_addr.iter_mut().take(6) {
        *slot = 0xff;
    }
    // SAFETY: payload and address are live for the call and their lengths
    // are the ones passed.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            0,
            std::ptr::from_ref(&address).cast(),
            u32::try_from(std::mem::size_of::<libc::sockaddr_ll>())?,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// `ETHTOOL_GFECPARAM`: the configured and active FEC bit sets of a port
/// (`ETHTOOL_FEC_*_BIT`), or None when the driver has no FEC.
#[allow(unsafe_code)]
pub fn fec(name: &str) -> Result<Option<(u32, u32)>> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[repr(C)]
    struct FecParam {
        cmd: u32,
        active_fec: u32,
        fec: u32,
        reserved: u32,
    }
    const ETHTOOL_GFECPARAM: u32 = 0x50;
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err("invalid interface name".into());
    }
    // SAFETY: plain socket(2); the descriptor is owned at once.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: raw is a fresh descriptor nothing else owns.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut param = FecParam {
        cmd: ETHTOOL_GFECPARAM,
        active_fec: 0,
        fec: 0,
        reserved: 0,
    };
    // SAFETY: ifreq is plain data; all-zero is a valid value.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_data = std::ptr::from_mut(&mut param).cast();
    // SAFETY: request names a NUL-terminated interface and points at param,
    // which outlives the call and has the layout ETHTOOL_GFECPARAM writes.
    let result = unsafe {
        libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCETHTOOL as _,
            std::ptr::from_mut(&mut request),
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EINVAL | libc::ENODEV)
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some((param.fec, param.active_fec)))
}

/// The names of the `ETHTOOL_FEC_*` bits set in `bits`.
pub fn fec_names(bits: u32) -> Vec<&'static str> {
    ["none", "auto", "off", "rs", "baser", "llrs"]
        .iter()
        .enumerate()
        .filter(|(bit, _)| u32::try_from(*bit).is_ok_and(|b| bits & (1u32 << b) != 0))
        .map(|(_, name)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_hops_are_one_ecmp_route_with_weights() {
        let hops = [
            NextHop {
                gateway: Some("192.0.2.1".parse().expect("ip")),
                index: 3,
                weight: 1,
            },
            NextHop {
                gateway: Some("192.0.2.2".parse().expect("ip")),
                index: 4,
                weight: 3,
            },
        ];
        let message = multipath_route("10.9.0.0".parse().expect("ip"), 16, &hops, 254, None, None)
            .expect("route");
        let paths: Vec<_> = message
            .attributes
            .iter()
            .filter_map(|a| match a {
                RouteAttribute::MultiPath(paths) => Some(paths.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(paths.len(), 2);
        assert_eq!(
            paths.iter().map(|p| (p.interface_index, p.hops)).collect::<Vec<_>>(),
            [(3, 0), (4, 2)]
        );
        assert_eq!(u8::from(message.header.protocol), RTPROT_KERNEL);
        assert!(
            !message
                .attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Oif(_) | RouteAttribute::Gateway(_)))
        );
    }

    #[test]
    fn one_hop_is_a_plain_route_and_no_gateway_is_scope_link() {
        let hop = NextHop {
            gateway: None,
            index: 7,
            weight: 1,
        };
        let source: IpAddr = "192.0.2.204".parse().expect("ip");
        let message = multipath_route(
            "192.0.2.0".parse().expect("ip"),
            24,
            &[hop],
            2081,
            None,
            Some(source),
        )
        .expect("route");
        assert_eq!(message.header.scope, RouteScope::Link);
        assert!(message.attributes.contains(&RouteAttribute::Oif(7)));
        assert!(message.attributes.contains(&RouteAttribute::Table(2081)));
        assert!(
            message
                .attributes
                .contains(&RouteAttribute::PrefSource(source.into()))
        );
        assert!(multipath_route(source, 32, &[], 254, None, None).is_err());
        let v6 = NextHop {
            gateway: Some("2001:db8::1".parse().expect("ip")),
            ..hop
        };
        assert!(multipath_route(source, 32, &[v6], 254, None, None).is_err());
    }

    #[test]
    fn rules_round_trip_through_their_message() {
        let rule = Rule {
            v6: false,
            priority: 9110,
            table: 2081,
            source: Some(("192.0.2.204".parse().expect("ip"), 32)),
            destination: Some(("192.0.2.0".parse().expect("ip"), 24)),
            suppress_prefix: None,
        };
        assert_eq!(rule_info(&rule_message(&rule), false), rule);
        let main = Rule {
            v6: true,
            priority: 9150,
            table: 254,
            source: None,
            destination: None,
            suppress_prefix: Some(0),
        };
        let message = rule_message(&main);
        assert_eq!(message.header.table, 254);
        assert_eq!(rule_info(&message, true), main);
    }

    #[test]
    fn gratuitous_arp_announces_the_address_as_sender_and_target() {
        let packet = gratuitous_arp_payload([2, 0, 0, 0, 0, 9], Ipv4Addr::new(192, 0, 2, 204));
        assert_eq!(
            packet,
            [
                0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 9, 192, 0, 2, 204, 0, 0, 0, 0, 0, 0, 192,
                0, 2, 204
            ]
        );
    }

    #[test]
    fn fec_bits_are_named() {
        assert_eq!(fec_names(1 << 3), ["rs"]);
        assert_eq!(fec_names((1 << 1) | (1 << 4)), ["auto", "baser"]);
        assert!(fec_names(0).is_empty());
    }

    #[test]
    fn only_gateway_or_multipath_kernel_routes_are_owned() {
        let mut route = TableRoute {
            destination: "10.9.0.0".parse().expect("ip"),
            prefix: 16,
            table: 254,
            protocol: RTPROT_KERNEL,
            multipath: false,
            gateway: None,
        };
        assert!(!owned(&route));
        route.multipath = true;
        assert!(owned(&route));
        route.protocol = 3;
        assert!(!owned(&route));
    }
}
