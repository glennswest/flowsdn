//! Transparent listeners (`IP_TRANSPARENT`, `IPV6_TRANSPARENT`). A
//! connection the datapath assigned to one keeps its original destination as
//! its local address, so the proxy learns where the client was going without
//! any lookup; the source's identity comes from the agent's ipcache, given as
//! a resolver.
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, SockaddrIn6, bind, listen,
    setsockopt, socket,
    sockopt::{IpTransparent, ReuseAddr},
};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream},
};

/// A transparent TCP listener on every address of one family, on `port`.
#[derive(Debug)]
pub struct Listener {
    socket: TcpListener,
    port: u16,
}

/// A connection the datapath redirected to the proxy.
#[derive(Debug)]
pub struct Redirected {
    pub stream: TcpStream,
    /// The client (the endpoint) as it connected.
    pub source: SocketAddr,
    /// Where the client was connecting: the accepted socket's local address.
    pub original: SocketAddr,
    /// The source's security identity, from the resolver.
    pub identity: u32,
}

fn io_error(error: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

impl Listener {
    /// Bind a transparent listener on `port` (0: any) for IPv4 or IPv6.
    pub fn bind(port: u16, v6: bool) -> io::Result<Self> {
        let family = if v6 {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        };
        let fd = socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).map_err(io_error)?;
        setsockopt(&fd, ReuseAddr, &true).map_err(io_error)?;
        if v6 {
            ipv6_transparent(&fd)?;
            let address = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
            bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &SockaddrIn6::from(address))
                .map_err(io_error)?;
        } else {
            setsockopt(&fd, IpTransparent, &true).map_err(io_error)?;
            let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
            bind(std::os::fd::AsRawFd::as_raw_fd(&fd), &SockaddrIn::from(address))
                .map_err(io_error)?;
        }
        listen(&fd, Backlog::new(1024).map_err(io_error)?).map_err(io_error)?;
        let socket = TcpListener::from(fd);
        let port = socket.local_addr()?.port();
        Ok(Self { socket, port })
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    /// Accept one redirected connection; `identity` resolves its source.
    pub fn accept(&self, identity: &dyn Fn(IpAddr) -> u32) -> io::Result<Redirected> {
        let (stream, source) = self.socket.accept()?;
        let original = stream.local_addr()?;
        Ok(Redirected {
            identity: identity(source.ip()),
            stream,
            source: unmapped(source),
            original: unmapped(original),
        })
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.socket.set_nonblocking(nonblocking)
    }
}

/// `IPV6_TRANSPARENT` (nix has no option for it).
#[allow(unsafe_code)]
fn ipv6_transparent(fd: &std::os::fd::OwnedFd) -> io::Result<()> {
    let on: nix::libc::c_int = 1;
    // SAFETY: `fd` is a live socket; the value pointer and length describe
    // the local `on` exactly; the kernel keeps no pointer.
    let result = unsafe {
        nix::libc::setsockopt(
            std::os::fd::AsRawFd::as_raw_fd(fd),
            nix::libc::SOL_IPV6,
            nix::libc::IPV6_TRANSPARENT,
            std::ptr::from_ref(&on).cast(),
            std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `::ffff:a.b.c.d` as `a.b.c.d`.
fn unmapped(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => address,
        },
        SocketAddr::V4(_) => address,
    }
}
