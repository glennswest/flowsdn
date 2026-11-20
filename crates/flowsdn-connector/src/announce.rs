//! ARP and NDP answers for addresses this node announces but does not hold
//! (#475: Service load-balancer addresses in L2 mode).
//!
//! The kernel answers only for its own addresses, and a load-balancer
//! address must not be one (local sockets would take its traffic before the
//! uplink programs see it). So an AF_PACKET socket per interface and family
//! receives ARP requests and, through a classic BPF filter, IPv6 Neighbor
//! Solicitations, and answers those for an announced address with this
//! interface's MAC. For IPv6 the socket joins each address's solicited-node
//! multicast group, so the NIC delivers the solicitations. Taking an address
//! over is announced with a gratuitous ARP or an unsolicited Neighbor
//! Advertisement.
//!
//! The packet builders and parsers are pure; [`Socket`] is the kernel part.
use crate::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV6: u16 = 0x86dd;
const ICMPV6: u8 = 58;
const NEIGHBOR_SOLICITATION: u8 = 135;
const NEIGHBOR_ADVERTISEMENT: u8 = 136;
pub const BROADCAST: [u8; 6] = [0xff; 6];
/// `ff02::1` and its Ethernet multicast address.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
pub const ALL_NODES_MAC: [u8; 6] = [0x33, 0x33, 0, 0, 0, 1];

/// An ARP request: who asks (MAC, address) for which address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpRequest {
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

fn take<const N: usize>(packet: &[u8], at: usize) -> Option<[u8; N]> {
    packet.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// An Ethernet/IPv4 ARP request (the ARP header on, without the link header).
pub fn parse_arp_request(packet: &[u8]) -> Option<ArpRequest> {
    let header: [u8; 8] = take(packet, 0)?;
    if header != [0, 1, 8, 0, 6, 4, 0, 1] {
        return None;
    }
    Some(ArpRequest {
        sender_mac: take(packet, 8)?,
        sender_ip: Ipv4Addr::from(take::<4>(packet, 14)?),
        target_ip: Ipv4Addr::from(take::<4>(packet, 24)?),
    })
}

/// The ARP reply saying `ip` is at `mac`, to the request's sender.
pub fn arp_reply(request: &ArpRequest, mac: [u8; 6]) -> [u8; 28] {
    let mut packet = [0u8; 28];
    packet[..8].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    packet[8..14].copy_from_slice(&mac);
    packet[14..18].copy_from_slice(&request.target_ip.octets());
    packet[18..24].copy_from_slice(&request.sender_mac);
    packet[24..28].copy_from_slice(&request.sender_ip.octets());
    packet
}

/// A Neighbor Solicitation: the asker's address and the target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Solicitation {
    pub source: Ipv6Addr,
    pub target: Ipv6Addr,
}

/// An IPv6 Neighbor Solicitation (the IPv6 header on): hop limit 255, no
/// extension header, ICMPv6 type 135 code 0.
pub fn parse_solicitation(packet: &[u8]) -> Option<Solicitation> {
    let first = *packet.first()?;
    if first >> 4 != 6 || *packet.get(6)? != ICMPV6 || *packet.get(7)? != 255 {
        return None;
    }
    if *packet.get(40)? != NEIGHBOR_SOLICITATION || *packet.get(41)? != 0 {
        return None;
    }
    Some(Solicitation {
        source: Ipv6Addr::from(take::<16>(packet, 8)?),
        target: Ipv6Addr::from(take::<16>(packet, 48)?),
    })
}

/// The ICMPv6 checksum over the pseudo-header and `message`.
fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            let high = u32::from(pair[0]) << 8;
            let low = pair.get(1).copied().map_or(0, u32::from);
            sum = sum.wrapping_add(high | low);
        }
    };
    add(&source.octets());
    add(&destination.octets());
    let length = u32::try_from(message.len()).unwrap_or(u32::MAX);
    add(&length.to_be_bytes());
    add(&[0, 0, 0, ICMPV6]);
    add(message);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// A Neighbor Advertisement (IPv6 header on) that `target` is at `mac`, from
/// `target` to `destination`: solicited (S) for an answer, override (O),
/// with the target link-layer address option.
pub fn advertisement(
    target: Ipv6Addr,
    mac: [u8; 6],
    destination: Ipv6Addr,
    solicited: bool,
) -> [u8; 72] {
    let mut message = [0u8; 32];
    message[0] = NEIGHBOR_ADVERTISEMENT;
    message[4] = if solicited { 0x60 } else { 0x20 };
    message[8..24].copy_from_slice(&target.octets());
    message[24] = 2; // target link-layer address
    message[25] = 1; // 8 bytes
    message[26..32].copy_from_slice(&mac);
    let checksum = icmpv6_checksum(target, destination, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = [0u8; 72];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&32u16.to_be_bytes());
    packet[6] = ICMPV6;
    packet[7] = 255;
    packet[8..24].copy_from_slice(&target.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..].copy_from_slice(&message);
    packet
}

/// The Ethernet multicast address of `ip`'s solicited-node group
/// (`ff02::1:ffXX:XXXX`).
pub fn solicited_node_mac(ip: Ipv6Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x33, 0x33, 0xff, o[13], o[14], o[15]]
}

/// The classic BPF program that keeps only ICMPv6 Neighbor Solicitations
/// on an `ETH_P_IPV6` datagram socket (offsets from the IPv6 header):
/// (code, jt, jf, k).
pub const SOLICITATION_FILTER: [(u16, u8, u8, u32); 6] = [
    (0x30, 0, 0, 6),         // ldb [6]: next header
    (0x15, 0, 3, 58),        // jeq ICMPv6, else drop
    (0x30, 0, 0, 40),        // ldb [40]: ICMPv6 type
    (0x15, 0, 1, 135),       // jeq Neighbor Solicitation, else drop
    (0x06, 0, 0, 0x0004_0000), // accept
    (0x06, 0, 0, 0),         // drop
];

/// One received packet: its payload and the sender's MAC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Received {
    pub payload: Vec<u8>,
    pub source_mac: [u8; 6],
}

/// An AF_PACKET datagram socket on one interface for ARP or IPv6.
#[derive(Debug)]
pub struct Socket {
    fd: std::os::fd::OwnedFd,
    pub index: u32,
    pub protocol: u16,
}

#[allow(unsafe_code)]
impl Socket {
    /// Open and bind; IPv6 sockets get [`SOLICITATION_FILTER`] before they
    /// are bound, so they never see other traffic.
    pub fn open(index: u32, protocol: u16) -> Result<Self> {
        use nix::libc;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        // SAFETY: plain socket(2); protocol 0 receives nothing until bound.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: raw is a fresh descriptor nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if protocol == ETH_P_IPV6 {
            let mut program: Vec<libc::sock_filter> = SOLICITATION_FILTER
                .iter()
                .map(|(code, jt, jf, k)| libc::sock_filter {
                    code: *code,
                    jt: *jt,
                    jf: *jf,
                    k: *k,
                })
                .collect();
            let fprog = libc::sock_fprog {
                len: u16::try_from(program.len())?,
                filter: program.as_mut_ptr(),
            };
            // SAFETY: fprog points at `program`, alive for the call.
            let set = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ATTACH_FILTER,
                    std::ptr::from_ref(&fprog).cast(),
                    u32::try_from(std::mem::size_of::<libc::sock_fprog>())?,
                )
            };
            if set < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = u16::try_from(libc::AF_PACKET)?;
        address.sll_protocol = protocol.to_be();
        address.sll_ifindex = i32::try_from(index)?;
        // SAFETY: address is a live sockaddr_ll of the length passed.
        let bound = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::from_ref(&address).cast(),
                u32::try_from(std::mem::size_of::<libc::sockaddr_ll>())?,
            )
        };
        if bound < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            fd,
            index,
            protocol,
        })
    }
    /// Join (`true`) or leave an Ethernet multicast group on the interface.
    pub fn membership(&self, mac: [u8; 6], join: bool) -> Result<()> {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let mut address = [0u8; 8];
        address[..6].copy_from_slice(&mac);
        let request = libc::packet_mreq {
            mr_ifindex: i32::try_from(self.index)?,
            mr_type: u16::try_from(libc::PACKET_MR_MULTICAST)?,
            mr_alen: 6,
            mr_address: address,
        };
        let option = if join {
            libc::PACKET_ADD_MEMBERSHIP
        } else {
            libc::PACKET_DROP_MEMBERSHIP
        };
        // SAFETY: request is a live packet_mreq of the length passed.
        let set = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                option,
                std::ptr::from_ref(&request).cast(),
                u32::try_from(std::mem::size_of::<libc::packet_mreq>())?,
            )
        };
        if set < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
    /// Send `payload` to `mac` with this socket's protocol.
    pub fn send(&self, mac: [u8; 6], payload: &[u8]) -> Result<()> {
        use nix::libc;
        use std::os::fd::AsRawFd;
        // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = u16::try_from(libc::AF_PACKET)?;
        address.sll_protocol = self.protocol.to_be();
        address.sll_ifindex = i32::try_from(self.index)?;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&mac);
        // SAFETY: payload and address are live for the call and their
        // lengths are the ones passed.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
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
    /// The next packet another host sent (this host's own are skipped), or
    /// None when nothing is waiting.
    pub fn receive(&self) -> Result<Option<Received>> {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let mut buffer = [0u8; 1500];
        loop {
            // SAFETY: sockaddr_ll is plain data; all-zero is a valid value.
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut length = u32::try_from(std::mem::size_of::<libc::sockaddr_ll>())?;
            // SAFETY: buffer and address are live and their lengths are passed.
            let got = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                    std::ptr::from_mut(&mut address).cast(),
                    &mut length,
                )
            };
            if got < 0 {
                let error = std::io::Error::last_os_error();
                return match error.kind() {
                    std::io::ErrorKind::WouldBlock => Ok(None),
                    std::io::ErrorKind::Interrupted => continue,
                    _ => Err(error.into()),
                };
            }
            if address.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let size = usize::try_from(got)?;
            let mut source_mac = [0u8; 6];
            source_mac.copy_from_slice(&address.sll_addr[..6]);
            return Ok(Some(Received {
                payload: buffer.get(..size).unwrap_or_default().to_vec(),
                source_mac,
            }));
        }
    }
    /// Wait up to `timeout` for any of `sockets` to have a packet.
    pub fn wait(sockets: &[&Socket], timeout: std::time::Duration) -> Result<()> {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let mut fds: Vec<libc::pollfd> = sockets
            .iter()
            .map(|s| libc::pollfd {
                fd: s.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        if fds.is_empty() {
            std::thread::sleep(timeout);
            return Ok(());
        }
        // SAFETY: fds is a live array of the length passed.
        let ready = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                libc::nfds_t::try_from(fds.len())?,
                millis,
            )
        };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        Ok(())
    }
}

/// The answer to `received` on a socket of `protocol`, when it asks for one
/// of `announced`: (destination MAC, payload).
pub fn answer(
    protocol: u16,
    received: &Received,
    announced: &[IpAddr],
    mac: [u8; 6],
) -> Option<([u8; 6], Vec<u8>)> {
    if protocol == ETH_P_ARP {
        let request = parse_arp_request(&received.payload)?;
        if !announced.contains(&IpAddr::V4(request.target_ip)) {
            return None;
        }
        return Some((request.sender_mac, arp_reply(&request, mac).to_vec()));
    }
    let solicitation = parse_solicitation(&received.payload)?;
    // Duplicate address detection (unspecified source) is not answered.
    if solicitation.source.is_unspecified()
        || !announced.contains(&IpAddr::V6(solicitation.target))
    {
        return None;
    }
    Some((
        received.source_mac,
        advertisement(solicitation.target, mac, solicitation.source, true).to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x10];
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x20];

    fn arp_request(target: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0, 1, 8, 0, 6, 4, 0, 1];
        p.extend_from_slice(&PEER);
        p.extend_from_slice(&[192, 168, 30, 9]);
        p.extend_from_slice(&[0; 6]);
        p.extend_from_slice(&target.octets());
        p
    }
    fn solicitation(source: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0, 0, 32, ICMPV6, 255];
        p.extend_from_slice(&source.octets());
        p.extend_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0x5).octets());
        p.extend_from_slice(&[NEIGHBOR_SOLICITATION, 0, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&target.octets());
        p.extend_from_slice(&[1, 1]);
        p.extend_from_slice(&PEER);
        p
    }

    #[test]
    fn arp_requests_for_announced_addresses_are_answered() {
        let lb = Ipv4Addr::new(192, 168, 30, 240);
        let request = Received {
            payload: arp_request(lb),
            source_mac: PEER,
        };
        let (to, reply) = answer(ETH_P_ARP, &request, &[IpAddr::V4(lb)], MAC).expect("answer");
        assert_eq!(to, PEER);
        assert_eq!(&reply[..8], &[0, 1, 8, 0, 6, 4, 0, 2]);
        assert_eq!(&reply[8..14], &MAC);
        assert_eq!(&reply[14..18], &lb.octets());
        assert_eq!(&reply[18..24], &PEER);
        assert_eq!(&reply[24..28], &[192, 168, 30, 9]);
        // Another address, or a reply instead of a request: nothing.
        let other = Received {
            payload: arp_request(Ipv4Addr::new(192, 168, 30, 241)),
            source_mac: PEER,
        };
        assert!(answer(ETH_P_ARP, &other, &[IpAddr::V4(lb)], MAC).is_none());
        let mut not_request = arp_request(lb);
        not_request[7] = 2;
        assert!(parse_arp_request(&not_request).is_none());
        assert!(parse_arp_request(&not_request[..20]).is_none());
    }

    #[test]
    fn solicitations_get_a_checksummed_advertisement() {
        let lb: Ipv6Addr = "fd00:30::f0".parse().expect("v6");
        let peer: Ipv6Addr = "fd00:30::9".parse().expect("v6");
        let ns = Received {
            payload: solicitation(peer, lb),
            source_mac: PEER,
        };
        let (to, na) = answer(ETH_P_IPV6, &ns, &[IpAddr::V6(lb)], MAC).expect("answer");
        assert_eq!(to, PEER);
        assert_eq!(na[0], 0x60);
        assert_eq!((na[6], na[7]), (ICMPV6, 255));
        assert_eq!(&na[8..24], &lb.octets());
        assert_eq!(&na[24..40], &peer.octets());
        assert_eq!(na[40], NEIGHBOR_ADVERTISEMENT);
        assert_eq!(na[44], 0x60, "solicited and override");
        assert_eq!(&na[48..64], &lb.octets());
        assert_eq!(&na[64..66], &[2, 1]);
        assert_eq!(&na[66..72], &MAC);
        // The checksum verifies: summing the message with it gives 0.
        assert_eq!(icmpv6_checksum(lb, peer, &na[40..]), 0);
        // Duplicate address detection and other targets are not answered.
        let dad = Received {
            payload: solicitation(Ipv6Addr::UNSPECIFIED, lb),
            source_mac: PEER,
        };
        assert!(answer(ETH_P_IPV6, &dad, &[IpAddr::V6(lb)], MAC).is_none());
        let mut low_hop = solicitation(peer, lb);
        low_hop[7] = 64;
        assert!(parse_solicitation(&low_hop).is_none());
        let unsolicited = advertisement(lb, MAC, ALL_NODES, false);
        assert_eq!(unsolicited[44], 0x20);
        assert_eq!(icmpv6_checksum(lb, ALL_NODES, &unsolicited[40..]), 0);
    }

    #[test]
    fn solicited_node_group() {
        let ip: Ipv6Addr = "fd00::12:3456".parse().expect("v6");
        assert_eq!(solicited_node_mac(ip), [0x33, 0x33, 0xff, 0x12, 0x34, 0x56]);
    }
}
