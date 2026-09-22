//! Bounded SET_DEVICE peer plans. Transport must serialize and ACK each fragment.
use crate::Error;
use netlink_packet_core::Emitable;
use netlink_packet_wireguard::{WireguardAddressFamily as Family, WireguardAllowedIp,
    WireguardAllowedIpAttr as IpAttr, WireguardAttribute as Attr, WireguardCmd,
    WireguardDeviceFlags, WireguardMessage, WireguardPeer, WireguardPeerAttribute as PeerAttr};
pub use netlink_packet_wireguard::WireguardPeerFlags as PeerFlags;
use std::{collections::HashSet, net::{IpAddr, SocketAddr}};

#[derive(Clone, Debug)]
pub struct Peer {
    pub public_key: [u8; 32],
    pub flags: PeerFlags,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u16>,
    pub allowed_ips: Vec<(IpAddr, u8)>,
}
fn message(ifindex: u32, replace: bool, attributes: Vec<PeerAttr>) -> WireguardMessage {
    let mut attrs = vec![Attr::IfIndex(ifindex)];
    if replace { attrs.push(Attr::Flags(WireguardDeviceFlags::ReplacePeers)); }
    attrs.push(Attr::Peers(vec![WireguardPeer(attributes)]));
    WireguardMessage { cmd: WireguardCmd::SetDevice, attributes: attrs }
}
fn prefix(address: IpAddr, cidr: u8) -> WireguardAllowedIp {
    WireguardAllowedIp(vec![IpAttr::Family(if address.is_ipv4() { Family::Ipv4 } else { Family::Ipv6 }), IpAttr::IpAddr(address), IpAttr::Cidr(cidr)])
}
fn attrs(peer: &Peer, first: bool, ips: Vec<WireguardAllowedIp>) -> Vec<PeerAttr> {
    let mut flags = peer.flags;
    if !first { flags.remove(PeerFlags::ReplaceAllowedIps); }
    let mut result = vec![PeerAttr::PublicKey(peer.public_key), PeerAttr::Flags(flags)];
    if first {
        if let Some(endpoint) = peer.endpoint { result.push(PeerAttr::Endpoint(endpoint)); }
        if let Some(keepalive) = peer.keepalive { result.push(PeerAttr::PersistentKeepalive(keepalive)); }
    }
    if !peer.flags.contains(PeerFlags::RemoveMe) { result.push(PeerAttr::AllowedIps(ips)); }
    result
}
/// Budget is total netlink message size, including the 20-byte envelope.
/// No socket writes occur. On any invalid operation the entire plan is rejected.
pub fn plan(ifindex: u32, replace_peers: bool, peers: &[Peer], budget: usize) -> Result<Vec<WireguardMessage>, Error> {
    if ifindex == 0 || !(128..=60_000).contains(&budget) || peers.len() > 65_535 {
        return Err(Error("invalid WireGuard device, budget or peer count"));
    }
    let mut keys = HashSet::new();
    let mut total = 0usize;
    for peer in peers {
        total = total.checked_add(peer.allowed_ips.len()).ok_or(Error("prefix count overflow"))?;
        if total > 1_000_000 || !keys.insert(peer.public_key) || peer.public_key == [0;32] || peer.flags.bits() & !7 != 0 {
            return Err(Error("invalid or duplicate peer, flags or prefix count"));
        }
        if peer.flags.contains(PeerFlags::RemoveMe) && (!peer.allowed_ips.is_empty() || peer.endpoint.is_some() || peer.keepalive.is_some() || peer.flags.contains(PeerFlags::ReplaceAllowedIps)) {
            return Err(Error("remove-peer cannot include peer settings"));
        }
        if peer.allowed_ips.iter().any(|(ip, mask)| *mask > if ip.is_ipv4() {32} else {128}) {
            return Err(Error("invalid AllowedIP prefix length"));
        }
    }
    if peers.is_empty() {
        let mut attributes = vec![Attr::IfIndex(ifindex)];
        if replace_peers { attributes.push(Attr::Flags(WireguardDeviceFlags::ReplacePeers)); }
        attributes.push(Attr::Peers(Vec::new()));
        return Ok(vec![WireguardMessage {cmd: WireguardCmd::SetDevice, attributes}]);
    }
    let mut output = Vec::new();
    for peer in peers {
        let mut first = true;
        let mut pending = peer.allowed_ips.iter().peekable();
        loop {
            let replace = replace_peers && output.is_empty();
            let base = message(ifindex, replace, attrs(peer, first, Vec::new())).buffer_len().checked_add(20).ok_or(Error("message length overflow"))?;
            if base > budget { return Err(Error("budget cannot fit peer metadata")); }
            let mut length = base;
            let mut ips = Vec::new();
            while let Some((address, cidr)) = pending.peek() {
                let ip = prefix(*address, *cidr);
                let next = length.checked_add(ip.buffer_len()).ok_or(Error("message length overflow"))?;
                if next > budget { break; }
                length = next;
                ips.push(ip);
                pending.next();
            }
            if ips.is_empty() && pending.peek().is_some() { return Err(Error("budget cannot fit an AllowedIP with peer metadata")); }
            output.push(message(ifindex, replace, attrs(peer, first, ips)));
            if pending.peek().is_none() { break; }
            first = false;
        }
    }
    Ok(output)
}
