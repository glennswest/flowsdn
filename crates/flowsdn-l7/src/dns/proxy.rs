//! The DNS proxy's sockets and its pipeline (spec 16 §3.6.2, §3.6.4): UDP
//! and TCP listeners on IPv4 and IPv6, all on one port, each transparent;
//! a UDP query's original destination from `IP_RECVORIGDSTADDR`, a TCP
//! one's from the accepted socket. The upstream socket carries the
//! endpoint's identity in `SO_MARK`; a UDP reply is sent from a socket
//! bound to the address the endpoint queried.
use super::{
    Config, Policy,
    message::{self, rcode},
};
use crate::{
    listener::{Listener, io_error, ipv6_transparent, unmapped},
    record::{Direction, Record},
};
use flowsdn_bpf_abi::policy::proxy_mark;
use nix::sys::socket::{
    AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
    SockaddrStorage, bind, connect, getsockname, recvmsg, setsockopt, socket,
    sockopt::{IpTransparent, Ipv4OrigDstAddr, Ipv6OrigDstAddr, Ipv6V6Only, Mark, ReuseAddr},
};
use serde_json::json;
use std::{
    io::{self, IoSliceMut, Read, Write},
    net::{
        IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, UdpSocket,
    },
    os::fd::{AsRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

/// Queries in flight when `dnsproxy-concurrency-limit` is 0.
pub const MAX_IN_FLIGHT: usize = 1024;
const TCP: u8 = 6;
const UDP: u8 = 17;
/// The largest DNS message (a TCP length prefix's range).
const MAX_MESSAGE: usize = 65535;
/// How long a TCP client may stay silent between queries.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// A running DNS proxy.
#[derive(Debug)]
pub struct DnsProxy {
    port: u16,
}

struct Shared {
    policy: Arc<dyn Policy>,
    config: Config,
    port: u16,
    in_flight: AtomicUsize,
}

/// One query in flight, counted until dropped.
struct Slot<'a>(&'a AtomicUsize);
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Shared {
    fn slot(&self) -> Option<Slot<'_>> {
        let limit = if self.config.concurrency == 0 {
            MAX_IN_FLIGHT
        } else {
            self.config.concurrency
        };
        let before = self.in_flight.fetch_add(1, Ordering::AcqRel);
        let slot = Slot(&self.in_flight);
        (before < limit).then_some(slot)
    }
}

impl DnsProxy {
    /// Bind UDP and TCP on IPv4 and, with `v6`, IPv6, all on `port` (0: the
    /// first bind chooses), and serve each on its own thread.
    pub fn start(port: u16, v6: bool, policy: Arc<dyn Policy>, config: Config) -> io::Result<Self> {
        let udp4 = udp_listener(port, false)?;
        let port = getsockname::<SockaddrIn>(udp4.as_raw_fd())
            .map_err(io_error)?
            .port();
        let tcp4 = Listener::bind(port, false)?;
        let six = if v6 {
            Some((udp_listener(port, true)?, Listener::bind(port, true)?))
        } else {
            None
        };
        let shared = Arc::new(Shared {
            policy,
            config,
            port,
            in_flight: AtomicUsize::new(0),
        });
        let mut udp = vec![udp4];
        let mut tcp = vec![tcp4];
        if let Some((u, t)) = six {
            udp.push(u);
            tcp.push(t);
        }
        for socket in udp {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("dns-proxy-udp".into())
                .spawn(move || serve_udp(&socket, &shared))?;
        }
        for listener in tcp {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("dns-proxy-tcp".into())
                .spawn(move || serve_tcp(&listener, &shared))?;
        }
        Ok(Self { port })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

fn udp_listener(port: u16, v6: bool) -> io::Result<OwnedFd> {
    let family = if v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let fd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None).map_err(io_error)?;
    setsockopt(&fd, ReuseAddr, &true).map_err(io_error)?;
    if v6 {
        setsockopt(&fd, Ipv6V6Only, &true).map_err(io_error)?;
        ipv6_transparent(&fd)?;
        setsockopt(&fd, Ipv6OrigDstAddr, &true).map_err(io_error)?;
        let address = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
        bind(fd.as_raw_fd(), &SockaddrIn6::from(address)).map_err(io_error)?;
    } else {
        setsockopt(&fd, IpTransparent, &true).map_err(io_error)?;
        setsockopt(&fd, Ipv4OrigDstAddr, &true).map_err(io_error)?;
        let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        bind(fd.as_raw_fd(), &SockaddrIn::from(address)).map_err(io_error)?;
    }
    Ok(fd)
}

/// One datagram: its length, its source and its original destination.
fn receive(fd: &OwnedFd, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buffer)];
    let mut space = nix::cmsg_space!(nix::libc::sockaddr_in6);
    let msg = recvmsg::<SockaddrStorage>(
        fd.as_raw_fd(),
        &mut iov,
        Some(&mut space),
        MsgFlags::empty(),
    )
    .map_err(io_error)?;
    let mut original = None;
    for cmsg in msg.cmsgs().map_err(io_error)? {
        match cmsg {
            ControlMessageOwned::Ipv4OrigDstAddr(sin) => {
                original = Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))),
                    u16::from_be(sin.sin_port),
                ));
            }
            ControlMessageOwned::Ipv6OrigDstAddr(sin6) => {
                original = Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)),
                    u16::from_be(sin6.sin6_port),
                ));
            }
            _ => {}
        }
    }
    let source = msg.address.as_ref().and_then(socket_addr);
    let missing = || io::Error::new(io::ErrorKind::InvalidData, "no source or destination");
    Ok((
        msg.bytes,
        source.ok_or_else(missing)?,
        original.ok_or_else(missing)?,
    ))
}

fn socket_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = storage.as_sockaddr_in() {
        return Some(SocketAddr::V4(SocketAddrV4::from(*v4)));
    }
    storage
        .as_sockaddr_in6()
        .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
}

fn serve_udp(fd: &OwnedFd, shared: &Arc<Shared>) {
    let mut buffer = vec![0u8; MAX_MESSAGE];
    loop {
        let (length, source, original) = match receive(fd, &mut buffer) {
            Ok(received) => received,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let Some(query) = buffer.get(..length).map(<[u8]>::to_vec) else {
            continue;
        };
        let worker = Arc::clone(shared);
        let spawned = std::thread::Builder::new()
            .name("dns-proxy-query".into())
            .spawn(move || {
                let reply = match worker.slot() {
                    Some(_slot) => answer(&worker, &query, source, original, UDP),
                    None => busy(&worker, &query, source, original),
                };
                if let Some(reply) = reply {
                    let _ = send_from(unmapped(original), unmapped(source), &reply);
                }
            });
        if spawned.is_err() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn serve_tcp(listener: &Listener, shared: &Arc<Shared>) {
    loop {
        let Ok(redirected) = listener.accept(&|_| 0) else {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        let worker = Arc::clone(shared);
        let _ = std::thread::Builder::new()
            .name("dns-proxy-tcp-conn".into())
            .spawn(move || {
                let mut stream = redirected.stream;
                let _ = stream.set_read_timeout(Some(TCP_IDLE));
                while let Some(query) = read_framed(&mut stream) {
                    let reply = match worker.slot() {
                        Some(_slot) => answer(
                            &worker,
                            &query,
                            redirected.source,
                            redirected.original,
                            TCP,
                        ),
                        None => busy(&worker, &query, redirected.source, redirected.original),
                    };
                    if let Some(reply) = reply {
                        if write_framed(&mut stream, &reply).is_err() {
                            return;
                        }
                    }
                }
            });
    }
}

fn read_framed(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).ok()?;
    let mut out = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut out).ok()?;
    Some(out)
}
fn write_framed(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    let length = u16::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too long"))?;
    let mut out = Vec::with_capacity(data.len().saturating_add(2));
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(data);
    stream.write_all(&out)
}

/// Over the concurrency limit (§3.6.8): SERVFAIL, nothing forwarded.
fn busy(shared: &Shared, query: &[u8], source: SocketAddr, original: SocketAddr) -> Option<Vec<u8>> {
    let question = message::question(query);
    record(shared, source, 0, original, "error", question.as_ref(), json!("concurrency limit"));
    match question {
        Some(q) => message::reply(query, &q, rcode::SERVFAIL),
        None => message::servfail_header(query),
    }
}

fn record(
    shared: &Shared,
    source: SocketAddr,
    identity: u32,
    destination: SocketAddr,
    verdict: &str,
    question: Option<&message::Question>,
    detail: serde_json::Value,
) {
    shared.policy.record(Record {
        direction: Direction::Egress,
        source,
        source_identity: identity,
        destination,
        proxy_port: shared.port,
        verdict: verdict.into(),
        detail: json!({
            "query": question.map(|q| q.name.clone()),
            "qtype": question.map(|q| q.qtype),
            "detail": detail,
        }),
    });
}

/// §3.6.4 for one query: the reply to send, or nothing (an upstream
/// timeout: the client retries).
fn answer(
    shared: &Shared,
    query: &[u8],
    source: SocketAddr,
    original: SocketAddr,
    protocol: u8,
) -> Option<Vec<u8>> {
    let (source, original) = (unmapped(source), unmapped(original));
    let Some(question) = message::question(query) else {
        record(shared, source, 0, original, "error", None, json!("not a query"));
        return message::servfail_header(query);
    };
    let servfail = || message::reply(query, &question, rcode::SERVFAIL);
    let Some((endpoint, identity)) = shared.policy.endpoint(source.ip()) else {
        record(shared, source, 0, original, "error", Some(&question), json!("no endpoint"));
        return servfail();
    };
    let server = shared.policy.identity(original.ip());
    if !shared
        .policy
        .allowed(endpoint, server, protocol, original.port(), &question.name)
    {
        let reply = message::reply(query, &question, shared.config.reject);
        record(shared, source, identity, original, "denied", Some(&question), json!({"server-identity": server}));
        return reply;
    }
    let response = match forward(query, original, identity, protocol, shared.config.upstream_timeout) {
        Ok(Some(response)) => response,
        Ok(None) => {
            record(shared, source, identity, original, "timeout", Some(&question), serde_json::Value::Null);
            return None;
        }
        Err(error) => {
            record(shared, source, identity, original, "error", Some(&question), json!(error.to_string()));
            return servfail();
        }
    };
    let Some(answers) = message::answers(&response, &question) else {
        record(shared, source, identity, original, "error", Some(&question), json!("upstream sent no response to it"));
        return servfail();
    };
    if answers.rcode == rcode::NOERROR && !answers.ips.is_empty() {
        shared
            .policy
            .learned(endpoint, &answers.names, &answers.ips, answers.ttl);
    }
    record(
        shared,
        source,
        identity,
        original,
        "forwarded",
        Some(&question),
        json!({
            "rcode": answers.rcode,
            "ips": answers.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "ttl": answers.ttl,
        }),
    );
    Some(response)
}

/// The upstream leg (§3.6.2): the same protocol the client used, with the
/// endpoint's identity in the mark. `Ok(None)`: no answer in time.
fn forward(
    query: &[u8],
    server: SocketAddr,
    identity: u32,
    protocol: u8,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mark = proxy_mark::egress(identity).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("identity {identity} does not fit the proxy mark"),
        )
    })?;
    let family = if server.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let kind = if protocol == TCP {
        SockType::Stream
    } else {
        SockType::Datagram
    };
    let fd = socket(family, kind, SockFlag::SOCK_CLOEXEC, None).map_err(io_error)?;
    setsockopt(&fd, Mark, &mark).map_err(io_error)?;
    let timed_out = |e: &io::Error| {
        matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        )
    };
    if protocol == TCP {
        let mut stream = TcpStream::from(fd);
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        match connect(stream.as_raw_fd(), &SockaddrStorage::from(server)) {
            Ok(()) => {}
            Err(nix::Error::EINPROGRESS | nix::Error::ETIMEDOUT) => return Ok(None),
            Err(error) => return Err(io_error(error)),
        }
        write_framed(&mut stream, query)?;
        let mut length = [0u8; 2];
        match stream.read_exact(&mut length) {
            Ok(()) => {}
            Err(e) if timed_out(&e) => return Ok(None),
            Err(e) => return Err(e),
        }
        let mut out = vec![0u8; usize::from(u16::from_be_bytes(length))];
        match stream.read_exact(&mut out) {
            Ok(()) => Ok(Some(out)),
            Err(e) if timed_out(&e) => Ok(None),
            Err(e) => Err(e),
        }
    } else {
        let socket = UdpSocket::from(fd);
        socket.connect(server)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.send(query)?;
        let mut buffer = vec![0u8; MAX_MESSAGE];
        match socket.recv(&mut buffer) {
            Ok(length) => {
                buffer.truncate(length);
                Ok(Some(buffer))
            }
            Err(e) if timed_out(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A UDP reply from the address the client queried (§3.6.2): a resolver
/// drops one from anywhere else.
fn send_from(from: SocketAddr, to: SocketAddr, data: &[u8]) -> io::Result<()> {
    let v6 = from.is_ipv6();
    let family = if v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let fd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None).map_err(io_error)?;
    setsockopt(&fd, ReuseAddr, &true).map_err(io_error)?;
    if v6 {
        setsockopt(&fd, Ipv6V6Only, &true).map_err(io_error)?;
        ipv6_transparent(&fd)?;
    } else {
        setsockopt(&fd, IpTransparent, &true).map_err(io_error)?;
    }
    bind(fd.as_raw_fd(), &SockaddrStorage::from(from)).map_err(io_error)?;
    let socket = UdpSocket::from(fd);
    socket.send_to(data, to)?;
    Ok(())
}
