//! UDP socket termination through `NETLINK_SOCK_DIAG` (spec 05 §3.8, #292):
//! list the UDP sockets of the current network namespace (`inet_diag`) and
//! destroy one (`SOCK_DESTROY`, needs `CONFIG_INET_DIAG_DESTROY`). A
//! destroyed socket's next call fails with `ECONNABORTED`, so the
//! application reconnects through the socket LB to a live backend.
use crate::Result;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto, socket,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, OwnedFd},
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const IPPROTO_UDP: u8 = 17;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const HEADER: usize = 16;
/// `inet_diag_req_v2`: family, protocol, ext, pad, states, then the socket id.
const REQUEST: usize = 56;
/// `inet_diag_sockid`: sport, dport (big endian), src[16], dst[16], if, cookie[8].
const SOCKID: usize = 48;
/// `inet_diag_msg`: family, state, timer, retrans, id, then five u32.
const MESSAGE: usize = 72;

/// One UDP socket as `inet_diag` reports it; `id` is the raw socket id the
/// kernel matches a destroy against (addresses, ports, interface, cookie).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpSocket {
    pub family: u8,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
    pub cookie: u64,
    id: [u8; SOCKID],
}

fn open() -> Result<OwnedFd> {
    Ok(socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )?)
}

/// A request: netlink header and `inet_diag_req_v2` with `id`.
pub fn request(kind: u16, flags: u16, family: u8, id: &[u8; SOCKID]) -> Vec<u8> {
    let length = u32::try_from(HEADER.saturating_add(REQUEST)).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(HEADER.saturating_add(REQUEST));
    out.extend_from_slice(&length.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&1u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&[family, IPPROTO_UDP, 0, 0]);
    out.extend_from_slice(&u32::MAX.to_ne_bytes());
    out.extend_from_slice(id);
    out
}

fn address(family: u8, bytes: &[u8]) -> Option<IpAddr> {
    if family == AF_INET {
        let v4: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(v4)))
    } else {
        let v6: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(v6)))
    }
}

/// One `inet_diag_msg` payload.
pub fn parse_message(payload: &[u8]) -> Option<UdpSocket> {
    if payload.len() < MESSAGE {
        return None;
    }
    let family = *payload.first()?;
    let id: [u8; SOCKID] = payload
        .get(4..4usize.saturating_add(SOCKID))?
        .try_into()
        .ok()?;
    let port = |at: usize| {
        Some(u16::from_be_bytes(
            id.get(at..at.saturating_add(2))?.try_into().ok()?,
        ))
    };
    let cookie = u64::from_ne_bytes(id.get(40..48)?.try_into().ok()?);
    Some(UdpSocket {
        family,
        source_port: port(0)?,
        destination_port: port(2)?,
        source: address(family, id.get(4..20)?)?,
        destination: address(family, id.get(20..36)?)?,
        cookie,
        id,
    })
}

/// Split a receive buffer into (type, payload) messages.
pub fn messages(buffer: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(header) = buffer.get(at..at.saturating_add(HEADER)) {
        let length = header
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_ne_bytes)
            .and_then(|l| usize::try_from(l).ok())
            .unwrap_or(0);
        let kind = header
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
            .unwrap_or(0);
        if length < HEADER {
            break;
        }
        let Some(payload) = buffer.get(at.saturating_add(HEADER)..at.saturating_add(length)) else {
            break;
        };
        out.push((kind, payload));
        // Messages are 4-byte aligned.
        at = at.saturating_add(length.saturating_add(3) & !3);
    }
    out
}

fn error_code(payload: &[u8]) -> i32 {
    payload
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(i32::from_ne_bytes)
        .unwrap_or(0)
}

/// Every UDP socket (IPv4 and IPv6) of this thread's network namespace.
pub fn udp_sockets() -> Result<Vec<UdpSocket>> {
    let mut out = Vec::new();
    for family in [AF_INET, AF_INET6] {
        let fd = open()?;
        let message = request(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            family,
            &[0; SOCKID],
        );
        sendto(
            fd.as_raw_fd(),
            &message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        let mut buffer = vec![0u8; 65536];
        'dump: loop {
            let n = recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty())?;
            if n == 0 {
                break;
            }
            for (kind, payload) in messages(buffer.get(..n).unwrap_or_default()) {
                match kind {
                    NLMSG_DONE => break 'dump,
                    NLMSG_ERROR => {
                        let code = error_code(payload);
                        return Err(std::io::Error::from_raw_os_error(code.saturating_neg()).into());
                    }
                    SOCK_DIAG_BY_FAMILY => out.extend(parse_message(payload)),
                    _ => {}
                }
            }
        }
    }
    Ok(out)
}

/// Destroy one socket. A socket already gone is not an error; a kernel
/// without `SOCK_DESTROY` support returns `EOPNOTSUPP`.
pub fn destroy(socket: &UdpSocket) -> Result<()> {
    let fd = open()?;
    let message = request(
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        socket.family,
        &socket.id,
    );
    sendto(
        fd.as_raw_fd(),
        &message,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )?;
    let mut buffer = vec![0u8; 4096];
    let n = recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty())?;
    for (kind, payload) in messages(buffer.get(..n).unwrap_or_default()) {
        if kind == NLMSG_ERROR {
            let code = error_code(payload).saturating_neg();
            if code == 0 || code == nix::libc::ENOENT {
                return Ok(());
            }
            return Err(std::io::Error::from_raw_os_error(code).into());
        }
    }
    Ok(())
}

/// Run `work` in the network namespace at `path`, only if that namespace's
/// cookie is `cookie` (a path alone is not proof of the endpoint's namespace,
/// #130).
pub fn in_endpoint_namespace<T: Send + 'static>(
    path: &std::path::Path,
    cookie: u64,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let namespace = std::fs::File::open(path)?;
    crate::in_namespace(namespace, move || {
        let found = crate::namespace_cookie()?;
        if cookie == 0 || found != cookie {
            return Err(format!("namespace cookie {found}, endpoint has {cookie}").into());
        }
        work()
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn dump_request_layout() {
        let message = request(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            AF_INET,
            &[0; SOCKID],
        );
        assert_eq!(message.len(), 72);
        assert_eq!(message.get(..4), Some(&72u32.to_ne_bytes()[..]));
        assert_eq!(message.get(4..6), Some(&20u16.to_ne_bytes()[..]));
        assert_eq!(message.get(6..8), Some(&0x301u16.to_ne_bytes()[..]));
        assert_eq!(message.get(16..20), Some(&[AF_INET, 17, 0, 0][..]));
        assert_eq!(message.get(20..24), Some(&[0xff; 4][..]));
    }

    #[test]
    fn parses_a_dumped_ipv4_socket_and_keeps_its_id() {
        let mut payload = vec![AF_INET, 1, 0, 0];
        let mut id = [0u8; SOCKID];
        id[..2].copy_from_slice(&40000u16.to_be_bytes());
        id[2..4].copy_from_slice(&53u16.to_be_bytes());
        id[4..8].copy_from_slice(&[10, 1, 0, 5]);
        id[20..24].copy_from_slice(&[10, 2, 0, 9]);
        id[40..48].copy_from_slice(&77u64.to_ne_bytes());
        payload.extend_from_slice(&id);
        payload.extend_from_slice(&[0; 20]);
        let mut buffer = Vec::new();
        let length = u32::try_from(payload.len() + 16).unwrap_or(0);
        buffer.extend_from_slice(&length.to_ne_bytes());
        buffer.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        buffer.extend_from_slice(&[0; 10]);
        buffer.extend_from_slice(&payload);
        buffer.extend_from_slice(&20u32.to_ne_bytes());
        buffer.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        buffer.extend_from_slice(&[0; 14]);
        let found = messages(&buffer);
        assert_eq!(found.len(), 2);
        let socket = parse_message(found[0].1).expect("socket");
        assert_eq!(socket.source, IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5)));
        assert_eq!(socket.destination, IpAddr::V4(Ipv4Addr::new(10, 2, 0, 9)));
        assert_eq!((socket.source_port, socket.destination_port), (40000, 53));
        assert_eq!(socket.cookie, 77);
        let destroy = request(SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, AF_INET, &socket.id);
        assert_eq!(destroy.get(24..72), Some(&id[..]));
        assert_eq!(found[1].0, NLMSG_DONE);
    }
}
