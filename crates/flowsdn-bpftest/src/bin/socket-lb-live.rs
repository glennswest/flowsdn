//! Socket LB against the real kernel (spec 05 §3.8): the agent's SocketLb
//! owner and planner program ClusterIP frontends; the socket-lb programs are
//! attached to a temporary child of this process's own cgroup, and every
//! socket lives in an anonymous network namespace with loopback only.
//! Covers TCP connect, unconnected and connected UDP with reverse
//! translation (recvmsg, getpeername), IPv6, IPv4-mapped IPv6, a frontend
//! without backends, backend churn and frontend removal.
use flowsdn_bpf_loader::kernel::{Object, socket_lb::SocketLb};
use flowsdn_lb::socket::{self, Address, PROTO_TCP, PROTO_UDP, Service};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[path = "cgroup/temporary.rs"]
mod cgroup;

const TIMEOUT: Duration = Duration::from_secs(3);

fn sa(text: &str) -> Result<SocketAddr> {
    Ok(text.parse()?)
}
fn address(text: &str, proto: u8) -> Result<Address> {
    let socket = sa(text)?;
    Ok(Address {
        ip: socket.ip(),
        port: socket.port(),
        proto,
    })
}
fn service(frontend: &str, proto: u8, backends: &[&str]) -> Result<Service> {
    Ok(Service {
        frontend: address(frontend, proto)?,
        backends: backends
            .iter()
            .map(|b| address(b, proto))
            .collect::<Result<_>>()?,
    })
}
/// Plan from the kernel's maps and apply, as the agent's services thread does.
fn program(lb: &mut SocketLb, services: &[Service]) -> Result<()> {
    let current = lb.dump()?;
    let want = socket::desired(&current, services)?;
    lb.apply(&socket::plan(&current, &want.maps))?;
    let after = lb.dump()?;
    if after != want.maps {
        return Err("kernel maps differ from the plan after apply".into());
    }
    if !socket::plan(&after, &want.maps).is_empty() {
        return Err("a second plan is not empty".into());
    }
    Ok(())
}

/// Connect to `frontend`; the TCP peer is the backend (TCP is not reverse
/// translated) and a payload round trip proves the listener got it.
fn tcp(listener: &TcpListener, frontend: SocketAddr, backend: SocketAddr) -> Result<()> {
    let mut client = TcpStream::connect_timeout(&frontend, TIMEOUT)?;
    if client.peer_addr()? != backend {
        return Err(format!(
            "TCP {frontend}: peer {} instead of backend {backend}",
            client.peer_addr()?
        )
        .into());
    }
    client.set_read_timeout(Some(TIMEOUT))?;
    let (mut server, _) = listener.accept()?;
    server.set_read_timeout(Some(TIMEOUT))?;
    client.write_all(b"flowsdn-socket-lb")?;
    let mut request = [0; 17];
    server.read_exact(&mut request)?;
    server.write_all(b"ok")?;
    let mut answer = [0; 2];
    client.read_exact(&mut answer)?;
    if &request != b"flowsdn-socket-lb" || &answer != b"ok" {
        return Err(format!("TCP {frontend}: payload mismatch").into());
    }
    println!("PASS TCP {frontend} -> {backend}, payload both ways");
    Ok(())
}

/// Unconnected then connected UDP to `frontend`: the backend server sees the
/// query, and the client sees the reply (and its peer) as `frontend`.
fn udp(server: &UdpSocket, frontend: SocketAddr, local: &str) -> Result<()> {
    server.set_read_timeout(Some(TIMEOUT))?;
    let client = UdpSocket::bind(local)?;
    client.set_read_timeout(Some(TIMEOUT))?;
    client.send_to(b"query", frontend)?;
    let mut buffer = [0; 16];
    let (n, from) = server.recv_from(&mut buffer)?;
    if buffer.get(..n) != Some(b"query".as_slice()) || from != client.local_addr()? {
        return Err(format!("UDP {frontend}: backend got {n} bytes from {from}").into());
    }
    server.send_to(b"answer", from)?;
    let (n, source) = client.recv_from(&mut buffer)?;
    if buffer.get(..n) != Some(b"answer".as_slice()) || source != frontend {
        return Err(format!("UDP {frontend}: reply from {source} instead of the frontend").into());
    }
    println!("PASS unconnected UDP {frontend}: reply source reverse translated");
    let connected = UdpSocket::bind(local)?;
    connected.set_read_timeout(Some(TIMEOUT))?;
    connected.connect(frontend)?;
    if connected.peer_addr()? != frontend {
        return Err(format!(
            "UDP {frontend}: getpeername {} instead of the frontend",
            connected.peer_addr()?
        )
        .into());
    }
    connected.send(b"query")?;
    let (n, from) = server.recv_from(&mut buffer)?;
    if buffer.get(..n) != Some(b"query".as_slice()) {
        return Err(format!("UDP {frontend}: connected query lost").into());
    }
    server.send_to(b"answer", from)?;
    let n = connected.recv(&mut buffer)?;
    if buffer.get(..n) != Some(b"answer".as_slice()) {
        return Err(format!("UDP {frontend}: connected reply lost").into());
    }
    println!("PASS connected UDP {frontend}: getpeername shows the frontend, reply delivered");
    Ok(())
}

fn main() -> Result<()> {
    let object = std::env::args_os()
        .nth(1)
        .ok_or("usage: socket-lb-live PATH_TO_SOCKET_LB_OBJECT")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    if !Command::new("ip")
        .args(["link", "set", "dev", "lo", "up"])
        .status()?
        .success()
    {
        return Err("failed to enable private loopback".into());
    }
    let mut cgroup = cgroup::Cgroup::create()?;
    let bytes = std::fs::read(&object)?;
    // Dropped before the cgroup is restored: links detach first.
    let mut lb = SocketLb::load(Object::Bytes(&bytes), None)?;
    lb.attach(&cgroup.temporary)?;
    println!("PASS socket-lb loaded and its 8 programs attached to a temporary cgroup");

    let tcp4 = TcpListener::bind("127.0.0.1:18080")?;
    let tcp4b = TcpListener::bind("127.0.0.2:18080")?;
    let tcp6 = TcpListener::bind("[::1]:18080")?;
    let udp4 = UdpSocket::bind("127.0.0.1:15353")?;
    let udp6 = UdpSocket::bind("[::1]:15353")?;
    let mut services = vec![
        service("192.0.2.10:80", PROTO_TCP, &["127.0.0.1:18080"])?,
        service("192.0.2.10:53", PROTO_UDP, &["127.0.0.1:15353"])?,
        service("[2001:db8::10]:80", PROTO_TCP, &["[::1]:18080"])?,
        service("[2001:db8::10]:53", PROTO_UDP, &["[::1]:15353"])?,
        service("192.0.2.11:80", PROTO_TCP, &[])?,
    ];
    program(&mut lb, &services)?;
    println!("PASS planner wrote the frontends; kernel maps equal the plan");

    tcp(&tcp4, sa("192.0.2.10:80")?, sa("127.0.0.1:18080")?)?;
    tcp(&tcp6, sa("[2001:db8::10]:80")?, sa("[::1]:18080")?)?;
    tcp(
        &tcp4,
        sa("[::ffff:192.0.2.10]:80")?,
        sa("[::ffff:127.0.0.1]:18080")?,
    )?;
    udp(&udp4, sa("192.0.2.10:53")?, "127.0.0.1:0")?;
    udp(&udp6, sa("[2001:db8::10]:53")?, "[::1]:0")?;

    match TcpStream::connect_timeout(&sa("192.0.2.11:80")?, TIMEOUT) {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            println!("PASS frontend without backends: connect fails with EPERM");
        }
        other => return Err(format!("frontend without backends: {other:?}").into()),
    }
    // Not a frontend: connect goes to the address as given.
    tcp(&tcp4, sa("127.0.0.1:18080")?, sa("127.0.0.1:18080")?)?;

    // Churn: the backend moves; existing IDs are kept, new sockets follow.
    if let Some(first) = services.first_mut() {
        first.backends = vec![address("127.0.0.2:18080", PROTO_TCP)?];
    }
    program(&mut lb, &services)?;
    tcp(&tcp4b, sa("192.0.2.10:80")?, sa("127.0.0.2:18080")?)?;
    // Two backends: both are chosen over enough connections.
    if let Some(first) = services.first_mut() {
        first.backends = vec![
            address("127.0.0.1:18080", PROTO_TCP)?,
            address("127.0.0.2:18080", PROTO_TCP)?,
        ];
    }
    program(&mut lb, &services)?;
    let (mut one, mut two) = (0, 0);
    for _ in 0..64 {
        let client = TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT)?;
        match client.peer_addr()?.ip() {
            IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 1] => {
                tcp4.accept()?;
                one += 1;
            }
            IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 2] => {
                tcp4b.accept()?;
                two += 1;
            }
            other => return Err(format!("unexpected backend {other}").into()),
        }
    }
    if one == 0 || two == 0 {
        return Err(format!("backend selection not spread: {one}/{two} of 64").into());
    }
    println!("PASS two backends both selected ({one}/{two} of 64 connects)");

    // Removal: the frontend is no longer translated (no route in this netns).
    services.retain(|s| s.frontend.port != 80 || s.frontend.ip.is_ipv6());
    program(&mut lb, &services)?;
    match TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT) {
        Ok(stream) => {
            return Err(format!("removed frontend still connects to {:?}", stream.peer_addr()).into());
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            return Err("removed frontend still rejected as a service".into());
        }
        Err(error) => println!("PASS removed frontend untranslated ({error})"),
    }
    program(&mut lb, &[])?;
    if lb.dump()? != socket::Maps::default() {
        return Err("maps not empty after removing every service".into());
    }
    println!("PASS every frontend removed; maps empty");

    lb.detach()?;
    drop(lb);
    cgroup.restore()?;
    println!("PASS links detached, own cgroup membership restored, temporary cgroup removed");
    Ok(())
}
