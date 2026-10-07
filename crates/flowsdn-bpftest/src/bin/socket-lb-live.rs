//! Socket LB against the real kernel (spec 05 §3.8): the agent's SocketLb
//! owner and planner program ClusterIP frontends; the socket-lb programs are
//! attached to a temporary child of this process's own cgroup, and every
//! socket lives in an anonymous network namespace with loopback only.
//! Covers TCP connect, unconnected and connected UDP with reverse
//! translation (recvmsg, getpeername), IPv6, IPv4-mapped IPv6, a frontend
//! without backends, backend churn and frontend removal; and the NodePort
//! uplink programs (#292) by BPF_PROG_TEST_RUN: destination rewrite to a
//! node-local backend and the reply's source rewrite, checksums checked.
use flowsdn_bpf_loader::kernel::{Object, socket_lb::SocketLb};
use aya::programs::{TestRun, TestRunOptions};
use flowsdn_lb::socket::{self, Address, PROTO_TCP, PROTO_UDP, SCOPE_NODE_LOCAL, Service};
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
        affinity: None,
        scope: socket::SCOPE_CLUSTER,
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

/// The one's-complement sum of `bytes` folded to 16 bits.
fn sum(bytes: &[u8], mut acc: u32) -> u32 {
    for pair in bytes.chunks(2) {
        let word = match pair {
            [a, b] => u16::from_be_bytes([*a, *b]),
            [a] => u16::from_be_bytes([*a, 0]),
            _ => 0,
        };
        acc = acc.wrapping_add(u32::from(word));
    }
    while acc > 0xffff {
        acc = (acc & 0xffff).wrapping_add(acc >> 16);
    }
    acc
}
/// An Ethernet + IPv4 + TCP/UDP frame with correct checksums (UDP: zero
/// checksum when `udp_zero`).
fn frame4(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, udp_zero: bool) -> Vec<u8> {
    let l4_len: u16 = if proto == 6 { 20 } else { 8 };
    let mut f = vec![0u8; 14];
    f.splice(12..14, [0x08, 0x00]);
    let total = 20u16.saturating_add(l4_len);
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, proto, 0, 0];
    ip.splice(2..4, total.to_be_bytes());
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let check = !(sum(&ip, 0) as u16);
    ip.splice(10..12, check.to_be_bytes());
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    if proto == 6 {
        l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
    } else {
        l4.extend_from_slice(&l4_len.to_be_bytes());
        l4.extend_from_slice(&[0, 0]);
    }
    if !(proto == 17 && udp_zero) {
        let check = !(l4_sum(proto, src, dst, &l4) as u16);
        let at = if proto == 6 { 16 } else { 6 };
        l4.splice(at..at.saturating_add(2), check.to_be_bytes());
    }
    f.extend(ip);
    f.extend(l4);
    f
}
fn l4_sum(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> u32 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&u16::try_from(l4.len()).unwrap_or(0).to_be_bytes());
    sum(l4, sum(&pseudo, 0))
}
/// (src, dst, sport, dport, IPv4 checksum ok, L4 checksum ok or zero UDP).
fn parse4(f: &[u8]) -> Result<([u8; 4], [u8; 4], u16, u16, bool, bool)> {
    let ip = f.get(14..34).ok_or("short frame")?;
    let l4 = f.get(34..).ok_or("short frame")?;
    let src: [u8; 4] = ip.get(12..16).ok_or("ip")?.try_into()?;
    let dst: [u8; 4] = ip.get(16..20).ok_or("ip")?.try_into()?;
    let proto = *ip.get(9).ok_or("ip")?;
    let port = |at: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(l4.get(at..at.saturating_add(2)).ok_or("l4")?.try_into()?))
    };
    let udp_zero = proto == 17 && port(6)? == 0;
    let l4_ok = udp_zero || l4_sum(proto, src, dst, l4) == 0xffff;
    Ok((src, dst, port(0)?, port(2)?, sum(ip, 0) == 0xffff, l4_ok))
}
fn run(lb: &mut SocketLb, program: &str, frame: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 512];
    let result = lb.classifier(program)?.test_run(TestRunOptions {
        data_in: Some(frame),
        data_out: Some(&mut out),
        repeat: 1,
        ..Default::default()
    })?;
    if result.return_value != 0 {
        return Err(format!("{program}: verdict {}, expected TC_ACT_OK", result.return_value).into());
    }
    out.truncate(usize::try_from(result.data_size_out)?);
    Ok(out)
}

/// NodePort from outside the cluster (#292): a client's packet to the
/// node-local frontend is sent to the backend, and the backend's reply is
/// shown as from the frontend; anything else passes untouched.
fn nodeport(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let (front, client, backend) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 0, 5]);
    for proto in [PROTO_TCP, PROTO_UDP] {
        services.push(Service {
            frontend: address("192.0.2.20:30080", proto)?,
            backends: vec![address("10.9.0.5:8080", proto)?],
            affinity: None,
            scope: SCOPE_NODE_LOCAL,
        });
    }
    program(lb, services)?;
    for (proto, udp_zero) in [(6u8, false), (17, false), (17, true)] {
        let sport = if udp_zero { 40001 } else { 40000 };
        let request = frame4(proto, client, front, sport, 30080, udp_zero);
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&run(lb, "nodeport_ingress", &request)?)?;
        if (src, dst, s, d) != (client, backend, sport, 8080) || !ip_ok || !l4_ok {
            return Err(format!(
                "nodeport_ingress proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        let reply = frame4(proto, backend, client, 8080, sport, udp_zero);
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&run(lb, "nodeport_egress", &reply)?)?;
        if (src, dst, s, d) != (front, client, 30080, sport) || !ip_ok || !l4_ok {
            return Err(format!(
                "nodeport_egress proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
    }
    // Not a node-local frontend (the cluster-scope ClusterIP, another port),
    // and a reply of a flow never seen: untouched.
    for (program, frame) in [
        ("nodeport_ingress", frame4(6, client, [192, 0, 2, 10], 40000, 80, false)),
        ("nodeport_ingress", frame4(6, client, front, 40000, 30081, false)),
        ("nodeport_egress", frame4(6, backend, client, 8080, 41000, false)),
    ] {
        if run(lb, program, &frame)? != frame {
            return Err(format!("{program} changed a frame it does not own").into());
        }
    }
    println!(
        "PASS NodePort uplink: TCP, UDP and checksum-less UDP to 192.0.2.20:30080 rewritten to the node-local backend and replies back to the frontend, checksums valid; other frames untouched"
    );
    services.retain(|s| s.scope != SCOPE_NODE_LOCAL);
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
    let (mut one, mut two) = (0u32, 0u32);
    for _ in 0..64 {
        let client = TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT)?;
        match client.peer_addr()?.ip() {
            IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 1] => {
                tcp4.accept()?;
                one = one.saturating_add(1);
            }
            IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 2] => {
                tcp4b.accept()?;
                two = two.saturating_add(1);
            }
            other => return Err(format!("unexpected backend {other}").into()),
        }
    }
    if one == 0 || two == 0 {
        return Err(format!("backend selection not spread: {one}/{two} of 64").into());
    }
    println!("PASS two backends both selected ({one}/{two} of 64 connects)");

    // ClientIP affinity: this process's network namespace sticks to one
    // backend; when that backend leaves, new connects move to the other.
    if let Some(first) = services.first_mut() {
        first.affinity = Some(60);
    }
    program(&mut lb, &services)?;
    let mut chosen = None;
    for _ in 0..32 {
        let client = TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT)?;
        let peer = client.peer_addr()?;
        match peer.ip() {
            IpAddr::V4(ip) if ip.octets() == [127, 0, 0, 1] => tcp4.accept()?,
            _ => tcp4b.accept()?,
        };
        if *chosen.get_or_insert(peer) != peer {
            return Err(format!("affinity broken: {peer} after {chosen:?}").into());
        }
    }
    let sticky = chosen.ok_or("no affinity connect")?;
    let other = if sticky.ip() == sa("127.0.0.1:0")?.ip() {
        "127.0.0.2:18080"
    } else {
        "127.0.0.1:18080"
    };
    if let Some(first) = services.first_mut() {
        first.backends = vec![address(other, PROTO_TCP)?];
    }
    program(&mut lb, &services)?;
    let client = TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT)?;
    if client.peer_addr()? != sa(other)? {
        return Err(format!("affinity kept a removed backend: {:?}", client.peer_addr()).into());
    }
    if other == "127.0.0.1:18080" {
        tcp4.accept()?;
    } else {
        tcp4b.accept()?;
    }
    println!("PASS ClientIP affinity: 32 connects on {sticky}; after it left, {other}");
    if let Some(first) = services.first_mut() {
        first.affinity = None;
    }

    // Removal: the frontend is no longer translated (no route in this netns).
    services.retain(|s| s.frontend.port != 80 || s.frontend.ip.is_ipv6());
    program(&mut lb, &services)?;
    match TcpStream::connect_timeout(&sa("192.0.2.10:80")?, TIMEOUT) {
        Ok(stream) => {
            return Err(format!(
                "removed frontend still connects to {:?}",
                stream.peer_addr()
            )
            .into());
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            return Err("removed frontend still rejected as a service".into());
        }
        Err(error) => println!("PASS removed frontend untranslated ({error})"),
    }
    nodeport(&mut lb, &mut services)?;

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
