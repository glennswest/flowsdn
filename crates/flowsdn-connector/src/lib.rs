//! Native Linux veth operations from CNI specification 09 §10.
//! Netlink connections must be created in the namespace they operate on.
use futures_util::TryStreamExt;
use nix::sched::{CloneFlags, setns};
use rtnetlink::{
    Handle, LinkUnspec, LinkVeth, RouteMessageBuilder,
    packet_route::{
        address::AddressHeaderFlags,
        link::{LinkAttribute, LinkMessage},
        neighbour::NeighbourState,
        route::{RouteAttribute, RouteMetric, RouteScope},
    },
};
use std::{error::Error, fs::File, future::Future, net::IpAddr, os::fd::AsRawFd, time::Duration};
use tokio::runtime::Runtime;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Read the kernel's namespace cookie. Older kernels lacking the option return
/// zero; other errors remain visible. The socket is never bound or connected.
#[allow(unsafe_code)]
pub fn namespace_cookie() -> Result<u64> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    let socket = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    let mut cookie = 0u64;
    let mut length = std::mem::size_of::<u64>() as nix::libc::socklen_t;
    // SAFETY: socket owns a live descriptor. Both output pointers refer to
    // writable stack values, and length is exactly the allocated cookie size.
    let result = unsafe {
        nix::libc::getsockopt(
            socket.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_NETNS_COOKIE,
            std::ptr::from_mut(&mut cookie).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::ENOPROTOOPT) {
            return Ok(0);
        }
        return Err(error.into());
    }
    if usize::try_from(length)? != std::mem::size_of::<u64>() {
        return Err("invalid namespace cookie length".into());
    }
    Ok(cookie)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mac: Vec<u8>,
}

/// A synchronous facade with one namespace-bound socket and a bounded request
/// timeout. Construct and call outside any async runtime; no worker pool enters
/// namespaces. Dropping this object closes the connection.
pub struct Connector {
    handle: Handle,
    runtime: Runtime,
}
impl Connector {
    pub fn addresses(&self, index: u32) -> Result<Vec<IpAddr>> {
        use rtnetlink::packet_route::address::AddressAttribute;
        self.run(async {
            let mut stream = self
                .handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute();
            let mut addresses = Vec::new();
            while let Some(message) = stream.try_next().await? {
                for attribute in message.attributes {
                    if let AddressAttribute::Address(ip) | AddressAttribute::Local(ip) = attribute
                        && !addresses.contains(&ip)
                    {
                        addresses.push(ip);
                    }
                }
            }
            Ok(addresses)
        })
    }
    pub fn open() -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (connection, handle, _) = {
            let _enter = runtime.enter();
            rtnetlink::new_connection()?
        };
        runtime.spawn(connection);
        Ok(Self { handle, runtime })
    }
    fn run<T>(&self, work: impl Future<Output = Result<T>>) -> Result<T> {
        self.runtime
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), work).await? })
    }
    pub fn link(&self, name: &str) -> Result<Option<Link>> {
        validate_name(name)?;
        self.run(async {
            let mut links = self
                .handle
                .link()
                .get()
                .match_name(name.to_string())
                .execute();
            match links.try_next().await {
                Ok(link) => link.map(link_info).transpose(),
                // A named RTM_GETLINK can report ENODEV/ENOENT rather than an
                // empty dump. Both mean the interface is already absent.
                Err(rtnetlink::Error::NetlinkError(error))
                    if matches!(error.raw_code(), -19 | -2) =>
                {
                    Ok(None)
                }
                Err(error) => Err(error.into()),
            }
        })
    }
    pub fn require_link(&self, name: &str) -> Result<Link> {
        self.link(name)?
            .ok_or_else(|| format!("interface {name} not found").into())
    }
    /// Creation is exclusive: EEXIST never grants ownership of an old link.
    pub fn create_veth(&self, host: &str, peer: &str, mtu: u32) -> Result<Link> {
        validate_name(host)?;
        validate_name(peer)?;
        if host == peer || mtu < 1280 {
            return Err("distinct names and dual-stack MTU >= 1280 required".into());
        }
        self.run(async {
            self.handle
                .link()
                .add(LinkVeth::new(host, peer).mtu(mtu).build())
                .execute()
                .await?;
            Ok(())
        })?;
        match self.require_link(host) {
            Ok(link) => Ok(link),
            Err(error) => {
                // Creation succeeded, so this name is ours to roll back.
                let _ = self.delete(host);
                Err(error)
            }
        }
    }
    pub fn configure(&self, index: u32, name: &str, mac: [u8; 6], mtu: u32) -> Result<()> {
        validate_name(name)?;
        if index == 0 || mtu < 1280 || mac == [0; 6] || mac.first().is_some_and(|b| b & 1 != 0) {
            return Err("invalid link index, MAC or dual-stack MTU".into());
        }
        self.run(async {
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(index)
                        .name(name)
                        .address(mac.to_vec())
                        .mtu(mtu)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    }
    pub fn move_to_namespace(&self, index: u32, namespace: &File) -> Result<()> {
        self.run(async {
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(index)
                        .setns_by_fd(namespace.as_raw_fd())
                        .build(),
                )
                .execute()
                .await?;
            Ok(())
        })
    }
    pub fn delete(&self, name: &str) -> Result<()> {
        let Some(link) = self.link(name)? else {
            return Ok(());
        };
        self.run(async {
            self.handle.link().del(link.index).execute().await?;
            Ok(())
        })
    }
    pub fn add_address(&self, index: u32, address: IpAddr, prefix: u8) -> Result<()> {
        if prefix > if address.is_ipv4() { 32 } else { 128 } {
            return Err("invalid address prefix".into());
        }
        self.run(async {
            let mut request = self.handle.address().add(index, address, prefix);
            if address.is_ipv6() {
                request.message_mut().header.flags |= AddressHeaderFlags::Nodad;
            }
            request.execute().await?;
            Ok(())
        })
    }
    pub fn add_route(
        &self,
        index: u32,
        destination: IpAddr,
        prefix: u8,
        gateway: Option<IpAddr>,
        mtu: Option<u32>,
    ) -> Result<()> {
        if gateway.is_some_and(|g| g.is_ipv4() != destination.is_ipv4()) || mtu == Some(0) {
            return Err("invalid route gateway family or MTU".into());
        }
        let mut route = RouteMessageBuilder::<IpAddr>::new()
            .destination_prefix(destination, prefix)?
            .output_interface(index);
        route = if let Some(gateway) = gateway {
            route.gateway(gateway)?
        } else {
            route.scope(RouteScope::Link)
        };
        let mut message = route.build();
        if let Some(mtu) = mtu {
            message
                .attributes
                .push(RouteAttribute::Metrics(vec![RouteMetric::Mtu(mtu)]));
        }
        self.run(async {
            self.handle.route().add(message).execute().await?;
            Ok(())
        })
    }
    pub fn neighbour(&self, index: u32, address: IpAddr, mac: [u8; 6]) -> Result<()> {
        self.run(async {
            self.handle
                .neighbours()
                .add(index, address)
                .link_layer_address(&mac)
                .state(NeighbourState::Permanent)
                .replace()
                .execute()
                .await?;
            Ok(())
        })
    }
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() >= 16
        || name.contains(['\0', '/', ':'])
        || name.chars().any(char::is_whitespace)
    {
        Err("invalid interface name".into())
    } else {
        Ok(())
    }
}
fn link_info(message: LinkMessage) -> Result<Link> {
    let mut name = None;
    let mut mac = Vec::new();
    for attr in message.attributes {
        match attr {
            LinkAttribute::IfName(value) => name = Some(value),
            LinkAttribute::Address(value) => mac = value,
            _ => {}
        }
    }
    Ok(Link {
        index: message.header.index,
        name: name.ok_or("link response has no name")?,
        mac,
    })
}

/// Run namespace work on a dedicated, joined OS thread. Even a panic cannot
/// strand a pooled thread in another namespace. Normal/error returns restore
/// the original namespace before the thread exits.
pub fn in_namespace<T: Send + 'static>(
    namespace: File,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    std::thread::spawn(move || {
        let original = File::open("/proc/thread-self/ns/net")?;
        setns(&namespace, CloneFlags::CLONE_NEWNET)?;
        let result = work();
        setns(&original, CloneFlags::CLONE_NEWNET)?;
        result
    })
    .join()
    .map_err(|_| "namespace worker panicked")?
}
