//! Socket LB against the real kernel (spec 05 §3.8): the agent's SocketLb
//! owner and planner program ClusterIP frontends; the socket-lb programs are
//! attached to a temporary child of this process's own cgroup, and every
//! socket lives in an anonymous network namespace with loopback only.
//! Covers TCP connect, unconnected and connected UDP with reverse
//! translation (recvmsg, getpeername), IPv6, IPv4-mapped IPv6, a frontend
//! without backends, backend churn and frontend removal; and the NodePort
//! uplink programs (#292) by BPF_PROG_TEST_RUN: destination rewrite to a
//! node-local backend and the reply's source rewrite, checksums checked; and
//! SNAT to a backend on another node with the FIB redirect, run as arriving
//! on a dummy uplink in this netns; IPv4 and IPv6; Maglev backend selection
//! checked against the planner's tables; service NAT46/64; and UDP socket termination
//! through SOCK_DIAG when a backend leaves, and TCP termination only with
//! `lb-sock-terminate-all-protos` (#392); and external access to a ClusterIP
//! (`lb-external-clusterip`, #465) from the agent's own frontends, with Maglev;
//! and BPF masquerade (#460) on the uplink: TCP, UDP and ICMP echo of a local
//! Pod leaving the cluster, their replies, and an ICMP error about a flow;
//! and the RFC 6052 NAT46/64 gateway (#454) for a Pod's IPv6 TCP and UDP.
//! Local redirect policy (#565): redirected connects, a Service matcher and
//! skip-LB from a backend's network namespace. Egress gateway (#564): both
//! nodes' halves on the uplink programs.
use aya::programs::{TestRun, TestRunOptions};
use flowsdn_bpf_loader::kernel::{Object, socket_lb::SocketLb};
use flowsdn_lb::socket::{self, Address, PROTO_TCP, PROTO_UDP, SCOPE_NODE_LOCAL, Service};
use nix::sched::{CloneFlags, unshare};
use std::{
    collections::BTreeSet,
    error::Error,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::fd::{AsFd, AsRawFd},
    process::Command,
    time::Duration,
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[path = "cgroup/temporary.rs"]
mod cgroup;
#[path = "testrun/syscall.rs"]
mod syscall;

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
        maglev: false,
        dsr: false,
        nat46x64: false,
        local_redirect: false,
        skip: Vec::new(),
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

/// Service NAT46/64 in the socket LB (#542), IPv6 sockets only, as in the
/// reference: `[::ffff:192.0.2.13]` (an IPv4 frontend whose backends are
/// IPv6) reaches `[::1]`, and `[2001:db8::13]` (IPv6, IPv4 backends) reaches
/// `[::ffff:127.0.0.1]`, TCP and connected UDP; getpeername and the reply show
/// the frontend. An IPv4 socket to the IPv4 frontend fails with EPERM (it
/// cannot be pointed at an IPv6 backend). Unconnected UDP across families is
/// the kernel's to refuse: a `sendto` to `::ffff:` takes the IPv4 path, and a
/// sendmsg6 rewrite to `::ffff:` is unsupported.
fn socket_nat46x64(
    lb: &mut SocketLb,
    services: &mut Vec<Service>,
    tcp: (&TcpListener, &TcpListener),
    udp: (&UdpSocket, &UdpSocket),
) -> Result<()> {
    let (tcp4, tcp6) = tcp;
    let (udp4, udp6) = udp;
    for (frontend, backend, proto) in [
        ("192.0.2.13:80", "[::1]:18080", PROTO_TCP),
        ("192.0.2.13:53", "[::1]:15353", PROTO_UDP),
        ("[2001:db8::13]:80", "127.0.0.1:18080", PROTO_TCP),
        ("[2001:db8::13]:53", "127.0.0.1:15353", PROTO_UDP),
    ] {
        services.push(Service {
            nat46x64: true,
            local_redirect: false,
            skip: Vec::new(),
            ..service(frontend, proto, &[backend])?
        });
    }
    program(lb, services)?;
    self::tcp(tcp6, sa("[::ffff:192.0.2.13]:80")?, sa("[::1]:18080")?)?;
    self::tcp(
        tcp4,
        sa("[2001:db8::13]:80")?,
        sa("[::ffff:127.0.0.1]:18080")?,
    )?;
    for (server, frontend) in [
        (udp6, sa("[::ffff:192.0.2.13]:53")?),
        (udp4, sa("[2001:db8::13]:53")?),
    ] {
        server.set_read_timeout(Some(TIMEOUT))?;
        let client = UdpSocket::bind("[::]:0")?;
        client.set_read_timeout(Some(TIMEOUT))?;
        client.connect(frontend)?;
        if client.peer_addr()? != frontend {
            return Err(format!(
                "socket NAT46/64 UDP {frontend}: getpeername {} instead of the frontend",
                client.peer_addr()?
            )
            .into());
        }
        client.send(b"query")?;
        let mut buffer = [0; 16];
        let (n, from) = server.recv_from(&mut buffer)?;
        if buffer.get(..n) != Some(b"query".as_slice()) {
            return Err(format!("socket NAT46/64 UDP {frontend}: query lost").into());
        }
        server.send_to(b"answer", from)?;
        let n = client.recv(&mut buffer)?;
        if buffer.get(..n) != Some(b"answer".as_slice()) {
            return Err(format!("socket NAT46/64 UDP {frontend}: reply lost").into());
        }
        println!(
            "PASS socket NAT46/64 connected UDP {frontend} -> {}: getpeername shows the frontend, reply delivered",
            server.local_addr()?
        );
    }
    match TcpStream::connect_timeout(&sa("192.0.2.13:80")?, TIMEOUT) {
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            println!("PASS socket NAT46/64: an IPv4 socket to the NAT46 frontend fails with EPERM");
            Ok(())
        }
        other => Err(format!("IPv4 socket to a NAT46 frontend: {other:?}").into()),
    }
}

/// Local redirect policy (#565, spec 05 §3.9) in the socket LB. A
/// serviceMatcher frontend `192.0.2.20:80`, whose Service's own backend is
/// `127.0.0.2`, is redirected to the "local Pod" `127.0.0.1` (the master
/// carries `LOCAL_REDIRECT`). With this network namespace's cookie in
/// `flowsdn_skip_lb4` (`skipRedirectFromBackend`), its sockets reach the
/// Service's own backend (scope 2) instead. An addressMatcher frontend
/// `192.0.2.21:80` (no Service of its own) is redirected, and with the skip
/// entry left untranslated. IPv6: `[2001:db8::20]:80` redirected to `[::1]`,
/// and skipped to no translation.
fn local_redirect(
    lb: &mut SocketLb,
    services: &mut Vec<Service>,
    tcp4: (&TcpListener, &TcpListener),
    tcp6: &TcpListener,
) -> Result<()> {
    let (local, own) = tcp4;
    let cookie = flowsdn_connector::namespace_cookie().map_err(|e| e.to_string())?;
    if cookie == 0 {
        return Err("SO_NETNS_COOKIE unsupported".into());
    }
    let redirect = |frontend: &str, backend: &str, skip: &[u64]| -> Result<Service> {
        Ok(Service {
            local_redirect: true,
            skip: skip.to_vec(),
            ..service(frontend, PROTO_TCP, &[backend])?
        })
    };
    let own_service = Service {
        scope: socket::SCOPE_REDIRECT_SKIPPED,
        ..service("192.0.2.20:80", PROTO_TCP, &["127.0.0.2:18080"])?
    };
    let base = services.len();
    services.push(redirect("192.0.2.20:80", "127.0.0.1:18080", &[])?);
    services.push(own_service);
    services.push(redirect("192.0.2.21:80", "127.0.0.1:18080", &[])?);
    services.push(redirect("[2001:db8::20]:80", "[::1]:18080", &[])?);
    program(lb, services)?;
    tcp(local, sa("192.0.2.20:80")?, sa("127.0.0.1:18080")?)?;
    tcp(local, sa("192.0.2.21:80")?, sa("127.0.0.1:18080")?)?;
    tcp(tcp6, sa("[2001:db8::20]:80")?, sa("[::1]:18080")?)?;
    println!("PASS local redirect: service and address frontends go to the local backend");
    for index in [base, base.saturating_add(2), base.saturating_add(3)] {
        if let Some(entry) = services.get_mut(index) {
            entry.skip = vec![cookie];
        }
    }
    program(lb, services)?;
    let dump = lb.dump()?;
    if dump.skip4.len() != 2 || dump.skip6.len() != 1 {
        return Err(format!(
            "skip-LB maps hold {} IPv4 and {} IPv6 entries, not 2 and 1",
            dump.skip4.len(),
            dump.skip6.len()
        )
        .into());
    }
    tcp(own, sa("192.0.2.20:80")?, sa("127.0.0.2:18080")?)?;
    println!("PASS skip-LB: this netns reaches the redirected Service's own backend");
    for frontend in ["192.0.2.21:80", "[2001:db8::20]:80"] {
        match TcpStream::connect_timeout(&sa(frontend)?, TIMEOUT) {
            Ok(stream) => {
                return Err(
                    format!("skip-LB {frontend}: translated to {:?}", stream.peer_addr()).into(),
                );
            }
            // Untranslated: no route to the documentation address here.
            Err(error) if error.kind() != ErrorKind::PermissionDenied => {
                println!("PASS skip-LB {frontend}: not translated ({error})");
            }
            Err(error) => return Err(format!("skip-LB {frontend}: {error}").into()),
        }
    }
    services.truncate(base);
    program(lb, services)?;
    let dump = lb.dump()?;
    if !dump.skip4.is_empty() || !dump.skip6.is_empty() {
        return Err("skip-LB entries left after the redirects were removed".into());
    }
    println!("PASS local redirect removed: skip-LB maps empty");
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
fn frame4(
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    udp_zero: bool,
) -> Vec<u8> {
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
        let check = !(l4_sum(proto, &src, &dst, &l4) as u16);
        let at: usize = if proto == 6 { 16 } else { 6 };
        l4.splice(at..at.saturating_add(2), check.to_be_bytes());
    }
    f.extend(ip);
    f.extend(l4);
    f
}
/// The TCP/UDP checksum sum with the pseudo-header (IPv4 or IPv6: for both,
/// addresses, protocol and length sum the same way).
fn l4_sum(proto: u8, src: &[u8], dst: &[u8], l4: &[u8]) -> u32 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&[0, proto]);
    pseudo.extend_from_slice(&u16::try_from(l4.len()).unwrap_or(0).to_be_bytes());
    sum(l4, sum(&pseudo, 0))
}
/// (src, dst, sport, dport, IPv4 checksum ok, L4 checksum ok or zero UDP).
type Parsed4 = ([u8; 4], [u8; 4], u16, u16, bool, bool);
fn parse4(f: &[u8]) -> Result<Parsed4> {
    let ip = f.get(14..34).ok_or("short frame")?;
    let l4 = f.get(34..).ok_or("short frame")?;
    let src: [u8; 4] = ip.get(12..16).ok_or("ip")?.try_into()?;
    let dst: [u8; 4] = ip.get(16..20).ok_or("ip")?.try_into()?;
    let proto = *ip.get(9).ok_or("ip")?;
    let port = |at: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            l4.get(at..at.saturating_add(2)).ok_or("l4")?.try_into()?,
        ))
    };
    let udp_zero = proto == 17 && port(6)? == 0;
    let l4_ok = udp_zero || l4_sum(proto, &src, &dst, l4) == 0xffff;
    Ok((src, dst, port(0)?, port(2)?, sum(ip, 0) == 0xffff, l4_ok))
}

/// [`frame4`] for IPv6 (hop limit 64, no extension headers).
fn frame6(
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
    sport: u16,
    dport: u16,
    udp_zero: bool,
) -> Vec<u8> {
    let l4_len: u16 = if proto == 6 { 20 } else { 8 };
    let mut f = vec![0u8; 14];
    f.splice(12..14, [0x86, 0xdd]);
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&l4_len.to_be_bytes());
    f.extend_from_slice(&[proto, 64]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
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
        let check = !(l4_sum(proto, &src, &dst, &l4) as u16);
        let at: usize = if proto == 6 { 16 } else { 6 };
        l4.splice(at..at.saturating_add(2), check.to_be_bytes());
    }
    f.extend(l4);
    f
}
/// (src, dst, sport, dport, hop limit, L4 checksum ok or zero UDP).
type Parsed6 = ([u8; 16], [u8; 16], u16, u16, u8, bool);
fn parse6(f: &[u8]) -> Result<Parsed6> {
    let ip = f.get(14..54).ok_or("short frame")?;
    let l4 = f.get(54..).ok_or("short frame")?;
    let src: [u8; 16] = ip.get(8..24).ok_or("ip")?.try_into()?;
    let dst: [u8; 16] = ip.get(24..40).ok_or("ip")?.try_into()?;
    let proto = *ip.get(6).ok_or("ip")?;
    let hops = *ip.get(7).ok_or("ip")?;
    let port = |at: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            l4.get(at..at.saturating_add(2)).ok_or("l4")?.try_into()?,
        ))
    };
    let udp_zero = proto == 17 && port(6)? == 0;
    let l4_ok = udp_zero || l4_sum(proto, &src, &dst, l4) == 0xffff;
    Ok((src, dst, port(0)?, port(2)?, hops, l4_ok))
}
fn ip6(text: &str) -> Result<[u8; 16]> {
    Ok(text.parse::<std::net::Ipv6Addr>()?.octets())
}

const UPLINK_MAC: &str = "02:00:00:00:00:20";
const GATEWAY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x30];
/// What the NodePort programs return for a packet they neither redirect nor
/// drop: TCX_NEXT (-1), so the host firewall after them runs (#484).
const TCX_NEXT: u32 = u32::MAX;
const TC_ACT_REDIRECT: u32 = 7;
const TC_ACT_SHOT: u32 = 2;

fn ip(args: &[&str]) -> Result<()> {
    if Command::new("ip").args(args).status()?.success() {
        Ok(())
    } else {
        Err(format!("ip {} failed", args.join(" ")).into())
    }
}
/// A device's index in this netns (sysfs still shows the original one).
fn ifindex(name: &str) -> Result<u32> {
    let out = Command::new("ip")
        .args(["-o", "link", "show", name])
        .output()?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .split(':')
        .next()
        .ok_or("ip link output")?
        .trim()
        .parse()?)
}
/// This netns as a node: uplink `up0` (192.0.2.20/24, the node address and
/// NodePort frontend; default route via 192.0.2.1, neighbour unresolved),
/// another node's pod CIDR 10.9.1.0/24 via 192.0.2.30 (resolved), and a
/// local pod device `pod0` for 10.9.0.0/24. Forwarding on.
fn node() -> Result<u32> {
    ip(&["link", "add", "up0", "address", UPLINK_MAC, "type", "dummy"])?;
    ip(&["link", "set", "up0", "up"])?;
    ip(&["addr", "add", "192.0.2.20/24", "dev", "up0"])?;
    ip(&["link", "add", "pod0", "type", "dummy"])?;
    ip(&["link", "set", "pod0", "up"])?;
    ip(&["route", "add", "10.9.0.0/24", "dev", "pod0"])?;
    ip(&[
        "route",
        "add",
        "10.9.1.0/24",
        "via",
        "192.0.2.30",
        "dev",
        "up0",
    ])?;
    ip(&[
        "neigh",
        "replace",
        "192.0.2.30",
        "lladdr",
        "02:00:00:00:00:30",
        "dev",
        "up0",
        "nud",
        "permanent",
    ])?;
    ip(&["route", "add", "default", "via", "192.0.2.1", "dev", "up0"])?;
    std::fs::write("/proc/sys/net/ipv4/conf/all/forwarding", "1")?;
    ifindex("up0")
}
/// Test-run `program` on `frame` as if it arrived on device `ifindex`;
/// the verdict must be `verdict`.
fn run_on(
    lb: &mut SocketLb,
    program: &str,
    frame: &[u8],
    ifindex: u32,
    verdict: u32,
) -> Result<Vec<u8>> {
    let fd = lb.classifier(program)?.fd()?.as_fd().as_raw_fd();
    let mut ctx = [0u8; 256];
    ctx.get_mut(40..44)
        .ok_or("ctx")?
        .copy_from_slice(&ifindex.to_ne_bytes());
    // Room for the largest frame (the too-big DSR step) and an option.
    let mut out = vec![0u8; 2048];
    let mut ctx_out = [0u8; 256];
    let (got, size) = syscall::run(fd, frame, &mut out, &ctx, &mut ctx_out)?;
    if got != verdict {
        return Err(format!("{program}: verdict {got}, expected {verdict}").into());
    }
    out.truncate(size);
    Ok(out)
}
fn run(lb: &mut SocketLb, program: &str, frame: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 512];
    let result = lb.classifier(program)?.test_run(TestRunOptions {
        data_in: Some(frame),
        data_out: Some(&mut out),
        repeat: 1,
        ..Default::default()
    })?;
    if result.return_value != TCX_NEXT {
        return Err(format!(
            "{program}: verdict {}, expected TCX_NEXT",
            result.return_value
        )
        .into());
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
            maglev: false,
            dsr: false,
            nat46x64: false,
            local_redirect: false,
            skip: Vec::new(),
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
        (
            "nodeport_ingress",
            frame4(6, client, [192, 0, 2, 10], 40000, 80, false),
        ),
        (
            "nodeport_ingress",
            frame4(6, client, front, 40000, 30081, false),
        ),
        (
            "nodeport_egress",
            frame4(6, backend, client, 8080, 41000, false),
        ),
    ] {
        if run(lb, program, &frame)? != frame {
            return Err(format!("{program} changed a frame it does not own").into());
        }
    }
    println!(
        "PASS NodePort uplink: TCP, UDP and checksum-less UDP to 192.0.2.20:30080 rewritten to the node-local backend and replies back to the frontend, checksums valid; other frames untouched"
    );
    fragments(lb)?;
    nodeport6(lb, services)?;
    snat(lb, services)?;
    masquerade(lb)?;
    masquerade6(lb)?;
    egress_gateway(lb)?;
    maglev(lb, services)?;
    dsr(lb, services)?;
    dsr_encap(lb)?;
    icmp_errors(lb)?;
    icmp_errors_snat(lb)?;
    nat46x64(lb, services)?;
    nat46x64_local(lb, services)?;
    gateway64(lb)?;
    nat_expiry(lb, services)?;
    external_clusterip(lb, services)?;
    services.retain(|s| s.scope != SCOPE_NODE_LOCAL);
    Ok(())
}

/// External access to a ClusterIP (#465): the agent's `services::frontends`
/// for a ClusterIP Service, programmed as the agent does. Without
/// `lb-external-clusterip` the uplink leaves a packet to the cluster IP
/// alone; with it the packet reaches the backend and the reply leaves from
/// the cluster IP, and with Maglev the kernel's pick is the table's.
fn external_clusterip(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    use flowsdn_agent::services::{
        Endpoint, NodeAddresses, ServiceInfo, ServicePort, SliceInfo, SlicePort, frontends,
    };
    let (cluster_ip, client, backend) = ([10, 96, 5, 7], [198, 51, 100, 9], [10, 9, 0, 5]);
    let info = |external_clusterip: bool, maglev: bool| ServiceInfo {
        namespace: "default".into(),
        name: "web".into(),
        service_type: "ClusterIP".into(),
        cluster_ips: vec![IpAddr::from(cluster_ip)],
        ports: vec![ServicePort {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
            node_port: None,
        }],
        maglev,
        external_clusterip,
        ..ServiceInfo::default()
    };
    let slices = [SliceInfo {
        namespace: "default".into(),
        name: "web-x".into(),
        service: "web".into(),
        address_type: "IPv4".into(),
        endpoints: vec![Endpoint {
            addresses: vec![IpAddr::from(backend)],
            ready: true,
            serving: true,
            terminating: false,
            node_name: "n1".into(),
            zone_hints: Vec::new(),
            node_hints: Vec::new(),
        }],
        ports: vec![SlicePort {
            name: "http".into(),
            protocol: "TCP".into(),
            port: Some(8080),
        }],
    }];
    let nodes = [NodeAddresses {
        name: "n1".into(),
        ips: vec![IpAddr::from([192, 0, 2, 20])],
        zone: String::new(),
    }];
    let before = services.len();
    let request = frame4(6, client, cluster_ip, 40000, 80, false);
    for (external, maglev) in [(false, false), (true, false), (true, true)] {
        services.truncate(before);
        services.extend(
            frontends(&[info(external, maglev)], &slices, "n1", &nodes)
                .into_iter()
                .map(|f| f.service),
        );
        program(lb, services)?;
        let out = run(lb, "nodeport_ingress", &request)?;
        if !external {
            if out != request {
                return Err(
                    "nodeport_ingress translated a ClusterIP without lb-external-clusterip".into(),
                );
            }
            continue;
        }
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
        if (src, dst, s, d) != (client, backend, 40000, 8080) || !ip_ok || !l4_ok {
            return Err(format!(
                "external ClusterIP (maglev {maglev}): {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        let reply = frame4(6, backend, client, 8080, 40000, false);
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&run(lb, "nodeport_egress", &reply)?)?;
        if (src, dst, s, d) != (cluster_ip, client, 80, 40000) || !ip_ok || !l4_ok {
            return Err(format!(
                "external ClusterIP reply (maglev {maglev}): {src:?}:{s} -> {dst:?}:{d}"
            )
            .into());
        }
        if maglev {
            let maps = lb.dump()?;
            let pick = socket::maglev_pick(
                &maps,
                address("10.96.5.7:80", PROTO_TCP)?,
                SCOPE_NODE_LOCAL,
                IpAddr::from(client),
                40000,
            )
            .ok_or("no Maglev table for the external ClusterIP")?;
            if pick != address("10.9.0.5:8080", PROTO_TCP)? {
                return Err(format!("Maglev picked {}:{}", pick.ip, pick.port).into());
            }
        }
    }
    services.truncate(before);
    program(lb, services)?;
    println!(
        "PASS external ClusterIP: untouched on the uplink without lb-external-clusterip; with it 10.96.5.7:80 reaches the backend and replies leave from the cluster IP, Maglev table picks match"
    );
    Ok(())
}

/// IPv6 BPF masquerade (#513) on uplink `up0` (2001:db8:2::20, default
/// route out of it): a local Pod (fd00:9::7) reaching 2001:db8:64::9 leaves
/// from 2001:db8:2::20 and a NAT port (an echo: NAT identifier), the same
/// for the flow's next packet; the reply, an echo reply and an ICMPv6 error
/// about the flow come back to the Pod, checksums valid. Cluster
/// destinations and the node's own traffic are untouched, and with the
/// prefixes cleared nothing is masqueraded.
fn masquerade6(lb: &mut SocketLb) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (pod, server, node) = (
        ip6("fd00:9::7")?,
        ip6("2001:db8:64::9")?,
        ip6("2001:db8:2::20")?,
    );
    let sources = vec![(ip6("fd00:9::")?, 64)];
    let exclude = vec![(node, 128), (ip6("fd00:9::")?, 32)];
    lb.set_masquerade6(&sources, &exclude)?;
    let (mut have_sources, mut have_exclude) = lb.masquerade6()?;
    have_sources.sort_unstable();
    have_exclude.sort_unstable();
    let mut want_exclude = exclude.clone();
    want_exclude.sort_unstable();
    if (have_sources, have_exclude) != (sources, want_exclude) {
        return Err("IPv6 masquerade maps do not read back as written".into());
    }
    for (proto, sport) in [(17u8, 5200u16), (6, 5201)] {
        let request = frame6(proto, pod, server, sport, 53, false);
        let mut nat = None;
        for _ in 0..2 {
            let (src, dst, s, d, _, l4_ok) =
                parse6(&run_on(lb, "nodeport_egress", &request, up0, TCX_NEXT)?)?;
            if (src, dst, d) != (node, server, 53)
                || !(61000..=65535).contains(&s)
                || nat.is_some_and(|n| n != s)
                || !l4_ok
            {
                return Err(format!(
                    "IPv6 masquerade proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksum {l4_ok}"
                )
                .into());
            }
            nat = Some(s);
        }
        let nat = nat.ok_or("no NAT port")?;
        let reply = frame6(proto, server, node, 53, nat, false);
        let (src, dst, s, d, _, l4_ok) =
            parse6(&run_on(lb, "nodeport_ingress", &reply, up0, TCX_NEXT)?)?;
        if (src, dst, s, d) != (server, pod, 53, sport) || !l4_ok {
            return Err(format!(
                "IPv6 masquerade reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksum {l4_ok}"
            )
            .into());
        }
        if proto == 17 {
            // Port unreachable from a router about the masqueraded packet.
            let sent = frame6(17, node, server, nat, 53, false);
            let error = icmp_frame6(ip6("2001:db8:2::1")?, node, &error_message(1, 4, &sent)?);
            let out = run_on(lb, "nodeport_ingress", &error, up0, TCX_NEXT)?;
            let (quote, sum_ok) = quote6(&out)?;
            if out.get(38..54) != Some(&pod[..]) || quote != (pod, server, sport, 53) || !sum_ok {
                return Err(format!(
                    "ICMPv6 error about a masqueraded flow: to {:?}, quote {quote:?}, checksum {sum_ok}",
                    out.get(38..54)
                )
                .into());
            }
        }
    }
    // An echo request and its reply.
    let out = run_on(
        lb,
        "nodeport_egress",
        &icmp_frame6(pod, server, &echo(128, 0x2345)),
        up0,
        TCX_NEXT,
    )?;
    let nat_id = u16::from_be_bytes(out.get(58..60).ok_or("id")?.try_into()?);
    let icmp_ok = |f: &[u8]| -> Result<bool> {
        let src: [u8; 16] = f.get(22..38).ok_or("ip")?.try_into()?;
        let dst: [u8; 16] = f.get(38..54).ok_or("ip")?.try_into()?;
        Ok(l4_sum(58, &src, &dst, f.get(54..).ok_or("icmp")?) == 0xffff)
    };
    if out.get(22..38) != Some(&node[..]) || !(61000..=65535).contains(&nat_id) || !icmp_ok(&out)? {
        return Err(format!(
            "IPv6 masquerade echo: from {:?} id {nat_id}",
            out.get(22..38)
        )
        .into());
    }
    let out = run_on(
        lb,
        "nodeport_ingress",
        &icmp_frame6(server, node, &echo(129, nat_id)),
        up0,
        TCX_NEXT,
    )?;
    if out.get(38..54) != Some(&pod[..])
        || out.get(58..60) != Some(&[0x23, 0x45][..])
        || !icmp_ok(&out)?
    {
        return Err(format!("IPv6 masquerade echo reply: to {:?}", out.get(38..54)).into());
    }
    // A cluster destination, the node's own traffic: untouched.
    for frame in [
        frame6(17, pod, ip6("fd00:9:1::5")?, 5202, 53, false),
        frame6(17, node, server, 5203, 53, false),
    ] {
        if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
            return Err("the IPv6 masquerade changed a packet it must not".into());
        }
    }
    lb.set_masquerade6(&[], &[])?;
    let frame = frame6(17, pod, server, 5204, 53, false);
    if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
        return Err("IPv6 masquerade off, yet a new flow was masqueraded".into());
    }
    println!(
        "PASS IPv6 BPF masquerade: Pod TCP, UDP and echo to 2001:db8:64::9 leave from 2001:db8:2::20 and a NAT port, replies and an ICMPv6 error come back to the Pod, checksums valid; cluster and node traffic untouched; off when cleared"
    );
    Ok(())
}

/// Service NAT46/64 to a backend on this node (#450): 192.0.2.20:30098 to
/// [fd00:9::5]:8080 and [2001:db8:2::20]:30098 to 10.9.0.5:8080, both on the
/// local pod device `pod0`. The uplink translates the client's packet and
/// redirects it toward the pod, source-NATed to the node's address of the
/// backend's family and a NAT port; the pod's reply to that address is
/// translated back by `nodeport_endpoint` on `pod0` and redirected toward
/// the client from the frontend. A pod packet that is no reply passes.
fn nat46x64_local(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let (up0, pod0) = (ifindex("up0")?, ifindex("pod0")?);
    ip(&["-6", "route", "replace", "fd00:9::/64", "dev", "pod0"])?;
    let (front, client, local) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 0, 5]);
    let (front6, client6, local6) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:64::9")?,
        ip6("fd00:9::5")?,
    );
    for proto in [PROTO_TCP, PROTO_UDP] {
        for (frontend, backend) in [
            ("192.0.2.20:30098", "[fd00:9::5]:8080"),
            ("[2001:db8:2::20]:30098", "10.9.0.5:8080"),
        ] {
            services.push(Service {
                frontend: address(frontend, proto)?,
                backends: vec![address(backend, proto)?],
                affinity: None,
                scope: SCOPE_NODE_LOCAL,
                maglev: false,
                dsr: false,
                nat46x64: true,
                local_redirect: false,
                skip: Vec::new(),
            });
        }
    }
    program(lb, services)?;
    for (proto, sport) in [(6u8, 42200u16), (17, 42201)] {
        // NAT46 to the local IPv6 backend.
        let request = frame4(proto, client, front, sport, 30098, false);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, hops, l4_ok) = parse6(&out)?;
        if out.get(12..14) != Some(&[0x86, 0xdd][..])
            || (src, dst, d) != (front6, local6, 8080)
            || !(61000..=65535).contains(&s)
            || hops != 63
            || !l4_ok
        {
            return Err(format!(
                "NAT46 local forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}"
            )
            .into());
        }
        let reply = frame6(proto, local6, src, 8080, s, false);
        let out = run_on(lb, "nodeport_endpoint", &reply, pod0, TC_ACT_REDIRECT)?;
        let (rsrc, rdst, rs, rd, ip_ok, l4_ok) = parse4(&out)?;
        if out.get(12..14) != Some(&[0x08, 0x00][..])
            || (rsrc, rdst, rs, rd) != (front, client, 30098, sport)
            || !ip_ok
            || !l4_ok
            || out.get(22) != Some(&63)
        {
            return Err(format!(
                "NAT46 local reply proto {proto}: {rsrc:?}:{rs} -> {rdst:?}:{rd}, ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        // NAT64 to the local IPv4 backend.
        let request = frame6(proto, client6, front6, sport, 30098, false);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
        if out.get(12..14) != Some(&[0x08, 0x00][..])
            || (src, dst, d) != (front, local, 8080)
            || !(61000..=65535).contains(&s)
            || out.get(22) != Some(&63)
            || !ip_ok
            || !l4_ok
        {
            return Err(format!(
                "NAT64 local forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        let reply = frame4(proto, local, src, 8080, s, false);
        let out = run_on(lb, "nodeport_endpoint", &reply, pod0, TC_ACT_REDIRECT)?;
        let (rsrc, rdst, rs, rd, hops, l4_ok) = parse6(&out)?;
        if out.get(12..14) != Some(&[0x86, 0xdd][..])
            || (rsrc, rdst, rs, rd) != (front6, client6, 30098, sport)
            || hops != 63
            || !l4_ok
        {
            return Err(format!(
                "NAT64 local reply proto {proto}: {rsrc:?}:{rs} -> {rdst:?}:{rd}, hops {hops}, checksum {l4_ok}"
            )
            .into());
        }
    }
    // The pod's other traffic goes on to local-delivery untouched.
    for frame in [
        frame4(6, local, client, 8080, 40000, false),
        frame6(17, local6, client6, 8080, 40001, false),
    ] {
        if run_on(lb, "nodeport_endpoint", &frame, pod0, TCX_NEXT)? != frame {
            return Err("nodeport_endpoint changed a frame that is no NAT46/64 reply".into());
        }
    }
    println!(
        "PASS NAT46/64 to local backends: TCP and UDP from an IPv4 client to an IPv6 backend and from an IPv6 client to an IPv4 backend on this node's pod device, source-NATed to the node's address and a NAT port, hop limit and TTL 63, checksums valid; the pod's reply translated back by nodeport_endpoint on its device and sent from the frontend; other pod traffic passed on"
    );
    Ok(())
}

/// The RFC 6052 gateway (#454) on uplink `up0`: a local Pod (fd00:9::7)
/// reaching 64:ff9b::198.51.100.9 leaves as IPv4 from 192.0.2.20 and a NAT
/// port, the same for the flow's next packet; the IPv4 reply comes back to
/// the Pod as IPv6 from 64:ff9b::198.51.100.9. Other destinations and other
/// sources are untouched, and with the gateway off nothing is translated.
fn gateway64(lb: &mut SocketLb) -> Result<()> {
    let up0 = ifindex("up0")?;
    ip(&["-6", "route", "replace", "fd00:9::/64", "dev", "pod0"])?;
    let (pod6, front6) = (ip6("fd00:9::7")?, ip6("64:ff9b::c633:6409")?);
    let (server, node) = ([198, 51, 100, 9], [192, 0, 2, 20]);
    let prefix = [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    let sources = [(ip6("fd00:9::")?, 64)];
    lb.set_gateway64(Some(prefix), &sources)?;
    if lb.gateway64()? != (Some(prefix), sources.to_vec()) {
        return Err("gateway maps do not read back as written".into());
    }
    for (proto, sport) in [(17u8, 5100u16), (6, 5101)] {
        let request = frame6(proto, pod6, front6, sport, 53, false);
        let mut nat = None;
        for _ in 0..2 {
            let out = run_on(lb, "nodeport_egress", &request, up0, TC_ACT_REDIRECT)?;
            let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
            if out.get(12..14) != Some(&[0x08, 0x00][..])
                || (src, dst, d) != (node, server, 53)
                || !(61000..=65535).contains(&s)
                || nat.is_some_and(|n| n != s)
                || !ip_ok
                || !l4_ok
            {
                return Err(format!(
                    "gateway forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
                )
                .into());
            }
            nat = Some(s);
        }
        let nat = nat.ok_or("no NAT port")?;
        let reply = frame4(proto, server, node, 53, nat, false);
        let out = run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, _, l4_ok) = parse6(&out)?;
        if out.get(12..14) != Some(&[0x86, 0xdd][..])
            || (src, dst, s, d) != (front6, pod6, 53, sport)
            || !l4_ok
        {
            return Err(format!(
                "gateway reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksum {l4_ok}"
            )
            .into());
        }
    }
    for frame in [
        frame6(17, pod6, ip6("2001:db8:3::9")?, 5102, 53, false),
        frame6(17, ip6("2001:db8:5::1")?, front6, 5103, 53, false),
    ] {
        if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
            return Err("the gateway changed a packet it must not".into());
        }
    }
    lb.set_gateway64(None, &[])?;
    let frame = frame6(17, pod6, front6, 5104, 53, false);
    if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
        return Err("gateway off, yet a new flow was translated".into());
    }
    println!(
        "PASS RFC 6052 gateway: a Pod's IPv6 TCP and UDP to 64:ff9b::198.51.100.9 leave as IPv4 from 192.0.2.20 and a NAT port, replies come back as IPv6, checksums valid; other traffic untouched; off when cleared"
    );
    Ok(())
}

/// An Ethernet + IPv4 ICMP frame carrying `icmp` (its checksum filled in).
fn icmp_frame4(src: [u8; 4], dst: [u8; 4], icmp: &[u8]) -> Vec<u8> {
    let mut message = icmp.to_vec();
    if let Some(check) = message.get_mut(2..4) {
        check.copy_from_slice(&[0, 0]);
    }
    let check = !(sum(&message, 0) as u16);
    message.splice(2..4, check.to_be_bytes());
    let mut f = fragment4(src, dst, 0, 0x4000, &message);
    // fragment4 writes UDP's protocol: ICMP, and the header checksum again.
    if let Some(proto) = f.get_mut(23) {
        *proto = 1;
    }
    let mut ip = f
        .get(14..34)
        .ok_or("ip")
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    ip.splice(10..12, [0, 0]);
    let check = !(sum(&ip, 0) as u16);
    if let Some(field) = f.get_mut(24..26) {
        field.copy_from_slice(&check.to_be_bytes());
    }
    f
}
/// An echo request (8) or reply (0) with `id`.
fn echo(kind: u8, id: u16) -> Vec<u8> {
    let mut m = vec![kind, 0, 0, 0];
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0, 1, b'p', b'i', b'n', b'g']);
    m
}

/// BPF masquerade (#460) on uplink `up0` (192.0.2.20): a local Pod
/// (10.9.0.7) reaching 198.51.100.9 leaves from 192.0.2.20 and a NAT port
/// (an echo: NAT identifier), the same one for the flow's later packets;
/// replies and an ICMP error about the flow come back to the Pod, checksums
/// valid. Cluster destinations and the node's own traffic are untouched, and
/// with the prefixes cleared nothing is masqueraded.
fn masquerade(lb: &mut SocketLb) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (pod, server, node) = ([10, 9, 0, 7], [198, 51, 100, 9], [192, 0, 2, 20]);
    lb.set_masquerade(&[([10, 9, 0, 0], 24)], &[([10, 9, 0, 0], 16), (node, 32)])?;
    if lb.masquerade()?
        != (
            vec![([10, 9, 0, 0], 24)],
            vec![([10, 9, 0, 0], 16), (node, 32)],
        )
    {
        return Err("masquerade maps do not read back as written".into());
    }
    for (proto, sport) in [(17u8, 5000u16), (6, 5001)] {
        let request = frame4(proto, pod, server, sport, 53, false);
        let mut nat = None;
        for _ in 0..2 {
            let (src, dst, s, d, ip_ok, l4_ok) =
                parse4(&run_on(lb, "nodeport_egress", &request, up0, TCX_NEXT)?)?;
            if (src, dst, d) != (node, server, 53)
                || !(61000..=65535).contains(&s)
                || nat.is_some_and(|n| n != s)
                || !ip_ok
                || !l4_ok
            {
                return Err(format!(
                    "masquerade proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
                )
                .into());
            }
            nat = Some(s);
        }
        let nat = nat.ok_or("no NAT port")?;
        let reply = frame4(proto, server, node, 53, nat, false);
        let (src, dst, s, d, ip_ok, l4_ok) =
            parse4(&run_on(lb, "nodeport_ingress", &reply, up0, TCX_NEXT)?)?;
        if (src, dst, s, d) != (server, pod, 53, sport) || !ip_ok || !l4_ok {
            return Err(format!(
                "masquerade reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        if proto == 17 {
            // Port unreachable from a router about the masqueraded packet.
            let sent = frame4(17, node, server, nat, 53, false);
            let mut error = vec![3, 3, 0, 0, 0, 0, 0, 0];
            error.extend_from_slice(sent.get(14..).ok_or("sent")?);
            let frame = icmp_frame4([192, 0, 2, 1], node, &error);
            let out = run_on(lb, "nodeport_ingress", &frame, up0, TCX_NEXT)?;
            let dst = out.get(30..34);
            let icmp = out.get(34..).ok_or("icmp")?;
            let inner = icmp.get(8..28).ok_or("inner")?;
            let inner_src = inner.get(12..16);
            let inner_port = icmp.get(28..30);
            if dst != Some(&pod[..])
                || inner_src != Some(&pod[..])
                || inner_port != Some(&sport.to_be_bytes()[..])
                || sum(icmp, 0) != 0xffff
                || sum(inner, 0) != 0xffff
                || sum(out.get(14..34).ok_or("ip")?, 0) != 0xffff
            {
                return Err(format!(
                    "ICMP error about a masqueraded flow: dst {dst:?}, inner {inner_src:?}:{inner_port:?}, icmp sum {:x}, inner sum {:x}",
                    sum(icmp, 0),
                    sum(inner, 0)
                )
                .into());
            }
        }
    }
    // An echo request and its reply.
    let out = run_on(
        lb,
        "nodeport_egress",
        &icmp_frame4(pod, server, &echo(8, 0x1234)),
        up0,
        TCX_NEXT,
    )?;
    let nat_id = u16::from_be_bytes(out.get(38..40).ok_or("id")?.try_into()?);
    if out.get(26..30) != Some(&node[..])
        || !(61000..=65535).contains(&nat_id)
        || sum(out.get(34..).ok_or("icmp")?, 0) != 0xffff
        || sum(out.get(14..34).ok_or("ip")?, 0) != 0xffff
    {
        return Err(format!("masqueraded echo: {:?}", out.get(26..40)).into());
    }
    let back = run_on(
        lb,
        "nodeport_ingress",
        &icmp_frame4(server, node, &echo(0, nat_id)),
        up0,
        TCX_NEXT,
    )?;
    if back.get(30..34) != Some(&pod[..])
        || back.get(38..40) != Some(&0x1234u16.to_be_bytes()[..])
        || sum(back.get(34..).ok_or("icmp")?, 0) != 0xffff
    {
        return Err(format!("echo reply to the Pod: {:?}", back.get(26..40)).into());
    }
    // Untouched: to another node's pod, from the node itself.
    for frame in [
        frame4(17, pod, [10, 9, 1, 5], 5002, 53, false),
        frame4(17, node, server, 5003, 53, false),
    ] {
        if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
            return Err("masquerade changed a packet it must not".into());
        }
    }
    lb.set_masquerade(&[], &[])?;
    let frame = frame4(17, pod, server, 5004, 53, false);
    if run_on(lb, "nodeport_egress", &frame, up0, TCX_NEXT)? != frame {
        return Err("masquerade off, yet a new flow was translated".into());
    }
    println!(
        "PASS BPF masquerade: Pod TCP, UDP and echo to 198.51.100.9 leave from 192.0.2.20 and a NAT port, replies and an ICMP error come back to the Pod, checksums valid; cluster and node traffic untouched; off when cleared"
    );
    Ok(())
}

/// Egress gateway (#564, spec 14 §3.4, native routing), on the uplink's
/// egress program. A source node sends a selected Pod's packet unchanged to
/// the gateway node (redirected, next hop the gateway); an excluded
/// destination goes on as if no policy matched; no gateway drops. On the
/// gateway node a Pod's packet (from another node) leaves from the egress
/// address and a NAT port, and the reply comes back to that Pod. This node
/// as gateway without an egress address drops.
fn egress_gateway(lb: &mut SocketLb) -> Result<()> {
    use flowsdn_bpf_abi::{
        MapBytes,
        egress::{EgressGw4Value, GATEWAY_EXCLUDED, GATEWAY_NONE},
    };
    let up0 = ifindex("up0")?;
    let (server, egress) = ([203, 0, 113, 5], [198, 51, 100, 77]);
    let entry = |src: [u8; 4], dst: [u8; 4], len: u32, egress_ip: [u8; 4], gateway_ip: [u8; 4]| {
        let [a, b, c, d] = src;
        let [e, f, g, h] = dst;
        (
            (32 + len, [a, b, c, d, e, f, g, h]),
            EgressGw4Value {
                egress_ip,
                gateway_ip,
                ..EgressGw4Value::default()
            }
            .to_bytes(),
        )
    };
    let desired: std::collections::BTreeMap<_, _> = [
        // A local Pod; the gateway is another node on up0's subnet.
        entry([10, 9, 0, 8], [203, 0, 113, 0], 24, [0; 4], [192, 0, 2, 30]),
        entry(
            [10, 9, 0, 8],
            [203, 0, 113, 128],
            25,
            [0; 4],
            GATEWAY_EXCLUDED,
        ),
        // No gateway resolved.
        entry([10, 9, 0, 9], [203, 0, 113, 0], 24, [0; 4], GATEWAY_NONE),
        // This node is the gateway for another node's Pod.
        entry([10, 9, 1, 5], [203, 0, 113, 0], 24, egress, [192, 0, 2, 20]),
        // This node is the gateway but has no egress address.
        entry(
            [10, 9, 0, 10],
            [203, 0, 113, 0],
            24,
            [0; 4],
            [192, 0, 2, 20],
        ),
    ]
    .into_iter()
    .collect();
    lb.set_egress_gateway4(&desired)?;
    if lb.egress_gateway4()? != desired {
        return Err("egress gateway map does not read back as written".into());
    }
    let sent = frame4(6, [10, 9, 0, 8], server, 40000, 443, false);
    let out = run_on(lb, "nodeport_egress", &sent, up0, TC_ACT_REDIRECT)?;
    if out.get(14..) != sent.get(14..) {
        return Err("egress gateway: the redirected packet was changed".into());
    }
    let excluded = frame4(6, [10, 9, 0, 8], [203, 0, 113, 200], 40001, 443, false);
    if run_on(lb, "nodeport_egress", &excluded, up0, TCX_NEXT)? != excluded {
        return Err("egress gateway: an excluded destination was changed".into());
    }
    run_on(
        lb,
        "nodeport_egress",
        &frame4(6, [10, 9, 0, 9], server, 40002, 443, false),
        up0,
        TC_ACT_SHOT,
    )?;
    run_on(
        lb,
        "nodeport_egress",
        &frame4(6, [10, 9, 0, 10], server, 40003, 443, false),
        up0,
        TC_ACT_SHOT,
    )?;
    for (proto, sport) in [(6u8, 40004u16), (17, 40005)] {
        let request = frame4(proto, [10, 9, 1, 5], server, sport, 443, false);
        let (src, dst, s, d, ip_ok, l4_ok) =
            parse4(&run_on(lb, "nodeport_egress", &request, up0, TCX_NEXT)?)?;
        if (src, dst, d) != (egress, server, 443)
            || !(61000..=65535).contains(&s)
            || !ip_ok
            || !l4_ok
        {
            return Err(format!(
                "egress gateway SNAT proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
        let reply = frame4(proto, server, egress, 443, s, false);
        let (src, dst, s2, d2, ip_ok, l4_ok) =
            parse4(&run_on(lb, "nodeport_ingress", &reply, up0, TCX_NEXT)?)?;
        if (src, dst, s2, d2) != (server, [10, 9, 1, 5], 443, sport) || !ip_ok || !l4_ok {
            return Err(format!(
                "egress gateway reply proto {proto}: {src:?}:{s2} -> {dst:?}:{d2}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
    }
    lb.set_egress_gateway4(&std::collections::BTreeMap::new())?;
    if run_on(lb, "nodeport_egress", &sent, up0, TCX_NEXT)? != sent {
        return Err("egress gateway cleared, yet a packet was redirected".into());
    }
    println!(
        "PASS egress gateway: a selected Pod's packet is redirected unchanged to the gateway, an excluded destination passes, no gateway drops; on the gateway TCP and UDP leave from 198.51.100.77 and a NAT port and the replies come back to the other node's Pod, checksums valid; a gateway without an egress address drops; cleared map: untouched"
    );
    Ok(())
}

/// An Ethernet + IPv4 fragment: `flags_offset` is the header's flags and
/// fragment offset word, `payload` what follows the 20-byte header.
fn fragment4(src: [u8; 4], dst: [u8; 4], id: u16, flags_offset: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f.splice(12..14, [0x08, 0x00]);
    let total = u16::try_from(payload.len().saturating_add(20)).unwrap_or(u16::MAX);
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&id.to_be_bytes());
    ip.extend_from_slice(&flags_offset.to_be_bytes());
    ip.extend_from_slice(&[64, 17, 0, 0]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    let check = !(sum(&ip, 0) as u16);
    ip.splice(10..12, check.to_be_bytes());
    f.extend(ip);
    f.extend_from_slice(payload);
    f
}
/// A UDP datagram of `sport -> dport` with 16 bytes of data, split after 8
/// of them: (first fragment, second fragment).
fn fragmented_udp(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    id: u16,
) -> (Vec<u8>, Vec<u8>) {
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&dport.to_be_bytes());
    udp.extend_from_slice(&24u16.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(b"flowsdn-fragment");
    let check = !(l4_sum(17, &src, &dst, &udp) as u16);
    udp.splice(6..8, check.to_be_bytes());
    let (head, tail) = udp.split_at(16);
    (
        fragment4(src, dst, id, 0x2000, head),
        fragment4(src, dst, id, 2, tail),
    )
}
/// (src, dst, IPv4 checksum ok) of a fragment, and what follows its header.
type FragmentParts = ([u8; 4], [u8; 4], bool, Vec<u8>);
fn fragment_parts(f: &[u8]) -> Result<FragmentParts> {
    let ip = f.get(14..34).ok_or("short fragment")?;
    Ok((
        ip.get(12..16).ok_or("ip")?.try_into()?,
        ip.get(16..20).ok_or("ip")?.try_into()?,
        sum(ip, 0) == 0xffff,
        f.get(34..).ok_or("short fragment")?.to_vec(),
    ))
}

/// IPv4 fragments (#458): a fragmented UDP datagram to the NodePort reaches
/// the backend whole, the first fragment's ports carried to the second, and
/// the backend's fragmented reply comes back from the frontend; the
/// reassembled UDP checksum is right at both ends. A later fragment whose
/// first was never seen passes untouched.
fn fragments(lb: &mut SocketLb) -> Result<()> {
    let (front, client, backend) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 0, 5]);
    let check = |what: &str,
                 first: &[u8],
                 second: &[u8],
                 want: ([u8; 4], [u8; 4], u16, u16)|
     -> Result<()> {
        let (s1, d1, ok1, head) = fragment_parts(first)?;
        let (s2, d2, ok2, tail) = fragment_parts(second)?;
        let mut udp = head.clone();
        udp.extend_from_slice(&tail);
        let ports = |at: usize| {
            u16::from_be_bytes([
                udp.get(at).copied().unwrap_or(0),
                udp.get(at.saturating_add(1)).copied().unwrap_or(0),
            ])
        };
        let checksum = l4_sum(17, &want.0, &want.1, &udp) == 0xffff;
        if (s1, d1) != (want.0, want.1)
            || (s2, d2) != (want.0, want.1)
            || (ports(0), ports(2)) != (want.2, want.3)
            || !ok1
            || !ok2
            || !checksum
            || tail.as_slice() != b"fragment"
        {
            return Err(format!(
                "{what}: first {s1:?}->{d1:?} second {s2:?}->{d2:?} ports {}:{}, ip checksums {ok1} {ok2}, udp checksum {checksum}",
                ports(0),
                ports(2)
            )
            .into());
        }
        Ok(())
    };
    let (first, second) = fragmented_udp(client, front, 40100, 30080, 0x4a58);
    let first = run(lb, "nodeport_ingress", &first)?;
    let second = run(lb, "nodeport_ingress", &second)?;
    check("request", &first, &second, (client, backend, 40100, 8080))?;
    let (first, second) = fragmented_udp(backend, client, 8080, 40100, 0x4a59);
    let first = run(lb, "nodeport_egress", &first)?;
    let second = run(lb, "nodeport_egress", &second)?;
    check("reply", &first, &second, (front, client, 30080, 40100))?;
    let (_, orphan) = fragmented_udp(client, front, 40101, 30080, 0x4a5a);
    if run(lb, "nodeport_ingress", &orphan)? != orphan {
        return Err("a fragment whose first fragment was never seen was changed".into());
    }
    println!(
        "PASS IPv4 fragments: a fragmented UDP datagram to 192.0.2.20:30080 reaches the backend whole and its fragmented reply leaves from the frontend, checksums valid; an orphan fragment is untouched"
    );
    Ok(())
}

/// Service NAT46/64 (spec 04 §3.15): a client of one family reaches a backend
/// of the other on another node, source-NATed to this node's address there; the
/// reply comes back in the client's family from the frontend.
/// `program`'s verdict on `frame` arriving on `ifindex`, whatever it is.
fn verdict_on(lb: &mut SocketLb, program: &str, frame: &[u8], ifindex: u32) -> Result<u32> {
    let fd = lb.classifier(program)?.fd()?.as_fd().as_raw_fd();
    let mut ctx = [0u8; 256];
    ctx.get_mut(40..44)
        .ok_or("ctx")?
        .copy_from_slice(&ifindex.to_ne_bytes());
    let mut out = vec![0u8; 2048];
    let mut ctx_out = [0u8; 256];
    Ok(syscall::run(fd, frame, &mut out, &ctx, &mut ctx_out)?.0)
}
/// `frame` (IPv4 TCP) with the TCP flags `flags` and its checksum redone.
fn tcp_flags(mut frame: Vec<u8>, flags: u8) -> Result<Vec<u8>> {
    *frame.get_mut(47).ok_or("tcp")? = flags;
    frame.splice(50..52, [0, 0]);
    let check = !(l4_sum(
        6,
        frame.get(26..30).ok_or("ip")?,
        frame.get(30..34).ok_or("ip")?,
        frame.get(34..).ok_or("l4")?,
    ) as u16);
    frame.splice(50..52, check.to_be_bytes());
    Ok(frame)
}

/// [`tcp_flags`] for an IPv6 TCP frame.
fn tcp_flags6(mut frame: Vec<u8>, flags: u8) -> Result<Vec<u8>> {
    *frame.get_mut(67).ok_or("tcp")? = flags;
    frame.splice(70..72, [0, 0]);
    let check = !(l4_sum(
        6,
        frame.get(22..38).ok_or("ip")?,
        frame.get(38..54).ok_or("ip")?,
        frame.get(54..).ok_or("l4")?,
    ) as u16);
    frame.splice(70..72, check.to_be_bytes());
    Ok(frame)
}

/// NAT port reservations expire (finding 1cb155baca89): one backend's pool
/// is 4536 ports. 3000 closed TCP connections (SYN, then FIN) and, 12 s
/// later (past the 10 s closing lifetime), 3000 more: the second round is
/// source-NATed as the first was, because the closed flows' ports are
/// reclaimed (without expiry at most 1536 of them could be). The same for
/// UDP flows across their 60 s lifetime. The same for NAT46 and NAT64
/// flows (#494, 192.0.2.20:30099 to [fd00:9:1::8]:8080 and
/// [2001:db8:2::20]:30099 to 10.9.1.8:8080, each its own pool), in the same
/// windows.
fn nat_expiry(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (front, client) = ([192, 0, 2, 20], [198, 51, 100, 9]);
    let (front6, client6) = (ip6("2001:db8:2::20")?, ip6("2001:db8:64::9")?);
    for proto in [PROTO_TCP, PROTO_UDP] {
        for (frontend, backend, nat46x64) in [
            ("192.0.2.20:30097", "10.9.1.7:8080", false),
            ("192.0.2.20:30099", "[fd00:9:1::8]:8080", true),
            ("[2001:db8:2::20]:30099", "10.9.1.8:8080", true),
        ] {
            services.push(Service {
                frontend: address(frontend, proto)?,
                backends: vec![address(backend, proto)?],
                affinity: None,
                scope: SCOPE_NODE_LOCAL,
                maglev: false,
                dsr: false,
                nat46x64,
                local_redirect: false,
                skip: Vec::new(),
            });
        }
    }
    program(lb, services)?;
    const ROUND: u16 = 3000;
    // kind 0: SNAT, 1: NAT46, 2: NAT64.
    let round = |lb: &mut SocketLb, kind: u8, proto: u8, first: u16| -> Result<u16> {
        let mut translated = 0u16;
        for i in 0..ROUND {
            let sport = first.saturating_add(i);
            let request = match kind {
                0 => frame4(proto, client, front, sport, 30097, false),
                1 => frame4(proto, client, front, sport, 30099, false),
                _ => frame6(proto, client6, front6, sport, 30099, false),
            };
            if verdict_on(lb, "nodeport_ingress", &request, up0)? == TC_ACT_REDIRECT {
                translated = translated.saturating_add(1);
            }
            if proto == 6 {
                let fin = if kind == 2 {
                    tcp_flags6(request, 0x11)?
                } else {
                    tcp_flags(request, 0x11)?
                };
                verdict_on(lb, "nodeport_ingress", &fin, up0)?;
            }
        }
        Ok(translated)
    };
    // Two live UDP flows across the 62 s window (#494): a NAT46 one renewed
    // by its client's packets, a NAT64 one by its backend's replies, half
    // way. Both keep their NAT port while the round around them reclaims.
    let live46 = frame4(17, client, front, 29990, 30099, false);
    let live64 = frame6(17, client6, front6, 29991, 30099, false);
    let port46 = |lb: &mut SocketLb| -> Result<u16> {
        Ok(parse6(&run_on(
            lb,
            "nodeport_ingress",
            &live46,
            up0,
            TC_ACT_REDIRECT,
        )?)?
        .2)
    };
    let port64 = |lb: &mut SocketLb| -> Result<([u8; 4], u16)> {
        let (src, _, s, _, _, _) = parse4(&run_on(
            lb,
            "nodeport_ingress",
            &live64,
            up0,
            TC_ACT_REDIRECT,
        )?)?;
        Ok((src, s))
    };
    for (proto, life, name) in [(6u8, 12u64, "closed TCP"), (17, 62, "UDP")] {
        // The live flows first, while the pool is empty: a new flow gets
        // eight tries at a free port, which a pool 3000 of 4536 full can
        // refuse (#534's run, 1 in ~27).
        let live = if proto == 17 {
            Some((port46(lb)?, port64(lb)?))
        } else {
            None
        };
        let mut first = [0u16; 3];
        for (kind, count) in first.iter_mut().enumerate() {
            *count = round(lb, kind as u8, proto, 20000)?;
        }
        if let Some((held46, (nat4, held64))) = live {
            std::thread::sleep(Duration::from_secs(life / 2));
            if port46(lb)? != held46 {
                return Err("NAT46: a live flow changed its NAT port".into());
            }
            let reply = frame4(17, [10, 9, 1, 8], nat4, 8080, held64, false);
            run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
            std::thread::sleep(Duration::from_secs(life.saturating_sub(life / 2)));
            let second46 = round(lb, 1, proto, 30000)?;
            let second64 = round(lb, 2, proto, 30000)?;
            let (now46, (_, now64)) = (port46(lb)?, port64(lb)?);
            if now46 != held46 || now64 != held64 {
                return Err(format!(
                    "NAT expiry: live flows lost their ports (NAT46 {held46} -> {now46}, NAT64 {held64} -> {now64}) after rounds of {second46} and {second64}"
                )
                .into());
            }
            println!(
                "PASS NAT expiry, live NAT46/64 flows: a UDP flow renewed by its client's packets and one renewed by its backend's replies keep their NAT ports past the 60 s lifetime while {second46} and {second64} new flows reclaim the expired ones"
            );
            let snat = round(lb, 0, proto, 30000)?;
            let before = first.first().copied().unwrap_or(0);
            let enough = ROUND / 10 * 9;
            for (label, before, second) in [
                ("SNAT", before, snat),
                ("NAT46", first.get(1).copied().unwrap_or(0), second46),
                ("NAT64", first.get(2).copied().unwrap_or(0), second64),
            ] {
                if before < enough || second < enough {
                    return Err(format!(
                        "NAT expiry, {label} {name}: {before} then {second} of {ROUND} flows translated (pool 4536 ports)"
                    )
                    .into());
                }
                println!(
                    "PASS NAT expiry, {label} {name}: {before} then, {life} s later, {second} of {ROUND} new flows translated: expired reservations are reclaimed"
                );
            }
            continue;
        }
        std::thread::sleep(Duration::from_secs(life));
        let enough = ROUND / 10 * 9;
        for (kind, label) in ["SNAT", "NAT46", "NAT64"].iter().enumerate() {
            let second = round(lb, kind as u8, proto, 30000)?;
            let before = first.get(kind).copied().unwrap_or(0);
            if before < enough || second < enough {
                return Err(format!(
                    "NAT expiry, {label} {name}: {before} then {second} of {ROUND} flows translated (pool 4536 ports)"
                )
                .into());
            }
            let what = if kind == 0 {
                "source-NATed"
            } else {
                "translated"
            };
            println!(
                "PASS NAT expiry, {label} {name}: {before} then, {life} s later, {second} of {ROUND} new flows {what}: expired reservations are reclaimed"
            );
        }
    }
    Ok(())
}

fn nat46x64(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (front, client, remote) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 1, 5]);
    let (front6, client6, remote6) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:64::9")?,
        ip6("fd00:9:1::5")?,
    );
    for proto in [PROTO_TCP, PROTO_UDP] {
        for (frontend, backend) in [
            ("192.0.2.20:30096", "[fd00:9:1::5]:8080"),
            ("[2001:db8:2::20]:30096", "10.9.1.5:8080"),
        ] {
            services.push(Service {
                frontend: address(frontend, proto)?,
                backends: vec![address(backend, proto)?],
                affinity: None,
                scope: SCOPE_NODE_LOCAL,
                maglev: false,
                dsr: false,
                nat46x64: true,
                local_redirect: false,
                skip: Vec::new(),
            });
        }
    }
    program(lb, services)?;
    for (proto, sport) in [(6u8, 42000u16), (17, 42001)] {
        // NAT46; the second packet of the flow keeps the first one's NAT port.
        let request = frame4(proto, client, front, sport, 30096, false);
        let mut nat_port = None;
        for _ in 0..2 {
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let (src, dst, s, d, hops, l4_ok) = parse6(&out)?;
            let length = u16::from_be_bytes(out.get(18..20).ok_or("ip")?.try_into()?);
            if out.get(12..14) != Some(&[0x86, 0xdd][..])
                || out.get(14).map(|b| b >> 4) != Some(6)
                || out.get(20) != Some(&proto)
                || (src, dst, d) != (front6, remote6, 8080)
                || !(61000..=65535).contains(&s)
                || nat_port.is_some_and(|p| p != s)
                || hops != 63
                || !l4_ok
                || usize::from(length) != out.len().saturating_sub(54)
            {
                return Err(format!(
                    "NAT46 forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}, length {length}, {} bytes",
                    out.len()
                )
                .into());
            }
            nat_port = Some(s);
        }
        let nat_port = nat_port.ok_or("no NAT port")?;
        let reply = frame6(proto, remote6, front6, 8080, nat_port, false);
        let out = run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
        if out.get(12..14) != Some(&[0x08, 0x00][..])
            || out.get(14) != Some(&0x45)
            || (src, dst, s, d) != (front, client, 30096, sport)
            || !ip_ok
            || !l4_ok
            || out.get(22) != Some(&63)
        {
            return Err(format!(
                "NAT46 reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ip {ip_ok} l4 {l4_ok}, ttl {:?}",
                out.get(22)
            )
            .into());
        }

        // NAT64.
        let request = frame6(proto, client6, front6, sport, 30096, false);
        let mut nat_port = None;
        for _ in 0..2 {
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
            let length = u16::from_be_bytes(out.get(16..18).ok_or("ip")?.try_into()?);
            if out.get(12..14) != Some(&[0x08, 0x00][..])
                || out.get(14) != Some(&0x45)
                || out.get(23) != Some(&proto)
                || (src, dst, d) != (front, remote, 8080)
                || !(61000..=65535).contains(&s)
                || nat_port.is_some_and(|p| p != s)
                || out.get(22) != Some(&63)
                || !ip_ok
                || !l4_ok
                || usize::from(length) != out.len().saturating_sub(14)
            {
                return Err(format!(
                    "NAT64 forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ip {ip_ok} l4 {l4_ok}, length {length}, {} bytes",
                    out.len()
                )
                .into());
            }
            nat_port = Some(s);
        }
        let nat_port = nat_port.ok_or("no NAT port")?;
        let reply = frame4(proto, remote, front, 8080, nat_port, false);
        let out = run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, hops, l4_ok) = parse6(&out)?;
        if out.get(12..14) != Some(&[0x86, 0xdd][..])
            || (src, dst, s, d) != (front6, client6, 30096, sport)
            || hops != 63
            || !l4_ok
        {
            return Err(format!(
                "NAT64 reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}"
            )
            .into());
        }
    }
    // Untranslatable: passes untouched. UDP without a checksum (IPv6 requires
    // one), a first fragment, TTL 1, and a UDP packet too big once translated.
    let no_checksum = frame4(17, client, front, 42100, 30096, true);
    let mut fragment = frame4(6, client, front, 42101, 30096, false);
    fragment.splice(20..22, [0x20, 0]);
    let check = refreshed_ip_check(&fragment)?;
    fragment.splice(24..26, check);
    let mut expiring = frame4(6, client, front, 42102, 30096, false);
    expiring.splice(22..23, [1]);
    let check = refreshed_ip_check(&expiring)?;
    expiring.splice(24..26, check);
    let mut big = frame4(17, client, front, 42103, 30096, false);
    big.resize(1514, 0);
    big.splice(16..18, 1500u16.to_be_bytes());
    big.splice(38..40, 1480u16.to_be_bytes());
    let check = refreshed_ip_check(&big)?;
    big.splice(24..26, check);
    for (name, frame) in [
        ("zero UDP checksum", no_checksum),
        ("first fragment", fragment),
        ("TTL 1", expiring),
        ("too big", big),
    ] {
        if run_on(lb, "nodeport_ingress", &frame, up0, TCX_NEXT)? != frame {
            return Err(format!("NAT46 changed a frame it must refuse: {name}").into());
        }
    }
    println!(
        "PASS NAT46/64: TCP and UDP from an IPv4 client to an IPv6 backend and from an IPv6 client to an IPv4 backend on another node, source-NATed to the node's address of the backend's family on a port in 61000-65535 (kept per flow), hop limit and TTL 63, checksums valid; replies translated back from the frontend; zero UDP checksum, first fragment, TTL 1 and a packet too big once translated untouched"
    );
    Ok(())
}

/// The IPv4 header checksum of a frame after a change to its header.
fn refreshed_ip_check(frame: &[u8]) -> Result<[u8; 2]> {
    let mut header = frame.get(14..34).ok_or("ip")?.to_vec();
    header.splice(10..12, [0, 0]);
    Ok((!(sum(&header, 0) as u16)).to_be_bytes())
}

/// TCP checksum of a frame whose L4 starts at `l4`, after a change of flags.
fn ack(mut frame: Vec<u8>, l4: usize) -> Result<Vec<u8>> {
    let (src, dst) = if l4 == 34 {
        (26..30, 30..34)
    } else {
        (22..38, 38..54)
    };
    *frame.get_mut(l4.saturating_add(13)).ok_or("tcp")? = 0x10;
    frame.splice(l4.saturating_add(16)..l4.saturating_add(18), [0, 0]);
    let check = !(l4_sum(
        6,
        frame.get(src).ok_or("ip")?,
        frame.get(dst).ok_or("ip")?,
        frame.get(l4..).ok_or("l4")?,
    ) as u16);
    frame.splice(
        l4.saturating_add(16)..l4.saturating_add(18),
        check.to_be_bytes(),
    );
    Ok(frame)
}

/// Direct server return (spec 05 §3.12, spec 02 §2.5): the front node keeps
/// the client's source and adds the frontend as an option; the backend's node
/// learns the frontend from it and rewrites the reply's source.
fn dsr(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (front, client, remote) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 1, 5]);
    let (front6, client6, remote6) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:64::9")?,
        ip6("fd00:9:1::5")?,
    );
    for proto in [PROTO_TCP, PROTO_UDP] {
        for (frontend, backend) in [
            ("192.0.2.20:30095", "10.9.1.5:8080"),
            ("[2001:db8:2::20]:30095", "[fd00:9:1::5]:8080"),
        ] {
            services.push(Service {
                frontend: address(frontend, proto)?,
                backends: vec![address(backend, proto)?],
                affinity: None,
                scope: SCOPE_NODE_LOCAL,
                maglev: false,
                dsr: true,
                nat46x64: false,
                local_redirect: false,
                skip: Vec::new(),
            });
        }
    }
    program(lb, services)?;
    let port = 30095u16.to_be_bytes();
    let [p0, p1] = port;
    let option4 = [0x9a, 8, p0, p1, 192, 0, 2, 20];
    for (proto, udp_zero, sport) in [
        (6u8, false, 41000u16),
        (17, false, 41001),
        (17, true, 41002),
    ] {
        let request = frame4(proto, client, front, sport, 30095, udp_zero);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        // The option moves L4 by 8 bytes; without it the frame parses as usual.
        let mut bare = out.clone();
        bare.drain(34..42);
        let length = u16::from_be_bytes(out.get(16..18).ok_or("ip")?.try_into()?);
        let ip_ok = sum(out.get(14..42).ok_or("ip")?, 0) == 0xffff;
        let (src, dst, s, d, _, l4_ok) = parse4(&bare)?;
        if out.get(14) != Some(&0x47)
            || out.get(34..42) != Some(&option4[..])
            || usize::from(length) != out.len().saturating_sub(14)
            || !ip_ok
            || !l4_ok
            || (src, dst, s, d) != (client, remote, sport, 8080)
            || out.get(22) != Some(&63)
        {
            return Err(format!(
                "DSR forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, header {:?}, ip {ip_ok} l4 {l4_ok}",
                out.get(14..42)
            )
            .into());
        }
        // The backend's node: nothing to rewrite before the option, then the
        // reply leaves with the frontend as its source.
        let reply = frame4(proto, remote, client, 8080, sport, udp_zero);
        if run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)? != reply {
            return Err(
                format!("DSR proto {proto}: a reply was rewritten before its option").into(),
            );
        }
        if run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)? != out {
            return Err(format!("DSR proto {proto}: the backend's node changed the packet").into());
        }
        let (src, dst, s, d, ip_ok, l4_ok) =
            parse4(&run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)?)?;
        if (src, dst, s, d) != (front, client, 30095, sport) || !ip_ok || !l4_ok {
            return Err(format!(
                "DSR reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
    }
    // A later TCP segment finds the reply entry the SYN left: no option.
    let later = ack(frame4(6, client, front, 41000, 30095, false), 34)?;
    let out = run_on(lb, "nodeport_ingress", &later, up0, TC_ACT_REDIRECT)?;
    let (src, dst, _, d, ip_ok, l4_ok) = parse4(&out)?;
    if out.get(14) != Some(&0x45) || (src, dst, d) != (client, remote, 8080) || !ip_ok || !l4_ok {
        return Err(format!(
            "DSR later segment: {src:?} -> {dst:?}:{d}, {:?}",
            out.get(14)
        )
        .into());
    }
    // A new flow whose first packet cannot carry the option is source-NATed,
    // never sent as DSR without it (finding 08ad0c4a7dca): UDP the option
    // would push over the MTU, and a TCP segment that is not a SYN.
    let mut big = frame4(17, client, front, 41003, 30095, true);
    big.resize(1514, 0);
    big.splice(16..18, 1500u16.to_be_bytes());
    big.splice(24..26, [0, 0]);
    big.splice(38..40, 1480u16.to_be_bytes());
    let check = !(sum(big.get(14..34).ok_or("ip")?, 0) as u16);
    big.splice(24..26, check.to_be_bytes());
    let mid_stream = ack(frame4(6, client, front, 41004, 30095, false), 34)?;
    for (what, first) in [("too-big UDP", big), ("TCP without SYN", mid_stream)] {
        let out = run_on(lb, "nodeport_ingress", &first, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, ip_ok, _) = parse4(&out)?;
        if out.get(14) != Some(&0x45)
            || src != front
            || !(61000..=65535).contains(&s)
            || (dst, d) != (remote, 8080)
            || !ip_ok
        {
            return Err(format!(
                "DSR {what}: not source-NATed: {src:?}:{s} -> {dst:?}:{d}, {:?}",
                out.get(14)
            )
            .into());
        }
    }
    // The backend's node refuses an option whose frontend is not a DSR
    // frontend, or whose destination is not one of its backends (finding
    // 0252b1736f32): a forged option cannot set a reply's source.
    let request = frame4(6, client, front, 41005, 30095, false);
    let valid = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
    let mut forged_front = valid.clone();
    forged_front.splice(38..42, [192, 0, 2, 99]);
    let mut forged_port = valid.clone();
    forged_port.splice(36..38, 30096u16.to_be_bytes());
    let mut not_backend = valid.clone();
    not_backend.splice(30..34, [10, 9, 1, 6]);
    for (what, frame) in [
        ("an unknown frontend", forged_front),
        ("a frontend port with no service", forged_port),
        ("a destination that is not a backend", not_backend),
    ] {
        run_on(lb, "nodeport_ingress", &frame, up0, TC_ACT_SHOT)
            .map_err(|e| format!("DSR option with {what}: {e}"))?;
        let reply = frame4(6, [10, 9, 1, 6], client, 8080, 41005, false);
        if run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)? != reply {
            return Err(format!("DSR option with {what} left a reply rewrite").into());
        }
    }

    let mut option6 = vec![2, 0x1b, 20];
    option6.extend_from_slice(&front6);
    option6.extend_from_slice(&port);
    option6.extend_from_slice(&[0, 0]);
    for (proto, sport) in [(6u8, 41100u16), (17, 41101)] {
        let request = frame6(proto, client6, front6, sport, 30095, false);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let mut bare = out.clone();
        bare.drain(54..78);
        *bare.get_mut(20).ok_or("ip")? = proto;
        let (src, dst, s, d, hops, l4_ok) = parse6(&bare)?;
        let length = u16::from_be_bytes(out.get(18..20).ok_or("ip")?.try_into()?);
        if out.get(20) != Some(&60)
            || out.get(54) != Some(&proto)
            || out.get(55..78) != Some(&option6[..])
            || usize::from(length) != out.len().saturating_sub(54)
            || (src, dst, s, d) != (client6, remote6, sport, 8080)
            || hops != 63
            || !l4_ok
        {
            return Err(format!(
                "DSR IPv6 forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}, header {:?}",
                out.get(54..78)
            )
            .into());
        }
        let reply = frame6(proto, remote6, client6, 8080, sport, false);
        if run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)? != reply {
            return Err(
                format!("DSR IPv6 proto {proto}: a reply was rewritten before its option").into(),
            );
        }
        if run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)? != out {
            return Err(
                format!("DSR IPv6 proto {proto}: the backend's node changed the packet").into(),
            );
        }
        let (src, dst, s, d, _, l4_ok) =
            parse6(&run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)?)?;
        if (src, dst, s, d) != (front6, client6, 30095, sport) || !l4_ok {
            return Err(format!("DSR IPv6 reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}").into());
        }
    }
    let later = ack(frame6(6, client6, front6, 41100, 30095, false), 54)?;
    let out = run_on(lb, "nodeport_ingress", &later, up0, TC_ACT_REDIRECT)?;
    let (src, dst, _, d, _, l4_ok) = parse6(&out)?;
    if out.get(20) != Some(&6) || (src, dst, d) != (client6, remote6, 8080) || !l4_ok {
        return Err(format!("DSR IPv6 later segment: {src:?} -> {dst:?}:{d}").into());
    }
    // IPv6: a forged option (frontend, or a destination not a backend) drops.
    let request = frame6(6, client6, front6, 41105, 30095, false);
    let valid = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
    let mut forged_front = valid.clone();
    if let Some(byte) = forged_front.get_mut(73) {
        *byte = 0x99;
    }
    let mut not_backend = valid.clone();
    if let Some(byte) = not_backend.get_mut(53) {
        *byte = 0x06;
    }
    for (what, frame) in [
        ("an unknown frontend", forged_front),
        ("a destination that is not a backend", not_backend),
    ] {
        run_on(lb, "nodeport_ingress", &frame, up0, TC_ACT_SHOT)
            .map_err(|e| format!("DSR IPv6 option with {what}: {e}"))?;
    }
    println!(
        "PASS DSR: to a backend on another node the client's source is kept and the frontend travels in the IPv4 option or IPv6 Destination Options header on a TCP SYN and each UDP packet (not on a later TCP segment); a new flow whose first packet cannot carry it (UDP over the MTU with it, TCP without SYN) is source-NATed instead; checksums valid; the backend's node leaves a valid packet alone and its egress rewrites the reply's source to the frontend, and it drops an option naming a frontend not in DSR mode or a destination not among its backends"
    );
    Ok(())
}

/// An Ethernet + IPv6 ICMPv6 frame carrying `icmp` (its checksum, with the
/// pseudo-header, filled in).
fn icmp_frame6(src: [u8; 16], dst: [u8; 16], icmp: &[u8]) -> Vec<u8> {
    let mut message = icmp.to_vec();
    if let Some(check) = message.get_mut(2..4) {
        check.copy_from_slice(&[0, 0]);
    }
    let check = !(l4_sum(58, &src, &dst, &message) as u16);
    message.splice(2..4, check.to_be_bytes());
    let mut f = vec![0u8; 14];
    f.splice(12..14, [0x86, 0xdd]);
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
    f.extend_from_slice(&[58, 64]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend(message);
    f
}
/// An ICMP(v6) error of `kind` and `code` quoting the IP packet of `frame`.
fn error_message(kind: u8, code: u8, frame: &[u8]) -> Result<Vec<u8>> {
    let mut message = vec![kind, code, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(frame.get(14..).ok_or("short frame")?);
    Ok(message)
}
/// The quote of an IPv4 ICMP error frame: (source, destination, source
/// port, destination port, its header checksum ok), and whether the outer
/// header's and the ICMP checksums are ok.
/// A quote: (source, destination, source port, destination port, and for
/// IPv4 its header checksum ok).
type Quote4 = ([u8; 4], [u8; 4], u16, u16, bool);
type Quote6 = ([u8; 16], [u8; 16], u16, u16);
fn quote4(f: &[u8]) -> Result<(Quote4, bool)> {
    let icmp = f.get(34..).ok_or("icmp")?;
    let inner = icmp.get(8..).ok_or("inner")?;
    let ihl = usize::from(inner.first().ok_or("inner")? & 15).saturating_mul(4);
    let port = |at: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            inner
                .get(at..at.saturating_add(2))
                .ok_or("ports")?
                .try_into()?,
        ))
    };
    Ok((
        (
            inner.get(12..16).ok_or("inner")?.try_into()?,
            inner.get(16..20).ok_or("inner")?.try_into()?,
            port(ihl)?,
            port(ihl.saturating_add(2))?,
            sum(inner.get(..ihl).ok_or("inner")?, 0) == 0xffff,
        ),
        sum(f.get(14..34).ok_or("ip")?, 0) == 0xffff && sum(icmp, 0) == 0xffff,
    ))
}
/// [`quote4`] for IPv6: the quote's L4 follows one Destination Options
/// header when it has one; the checksum is the ICMPv6 one.
fn quote6(f: &[u8]) -> Result<(Quote6, bool)> {
    let src: [u8; 16] = f.get(22..38).ok_or("ip")?.try_into()?;
    let dst: [u8; 16] = f.get(38..54).ok_or("ip")?.try_into()?;
    let icmp = f.get(54..).ok_or("icmp")?;
    let l4 = if f.get(68) == Some(&60) {
        let length = usize::from(*f.get(103).ok_or("options")?);
        102usize.saturating_add(length.saturating_add(1).saturating_mul(8))
    } else {
        102
    };
    let port = |at: usize| -> Result<u16> {
        Ok(u16::from_be_bytes(
            f.get(at..at.saturating_add(2)).ok_or("ports")?.try_into()?,
        ))
    };
    Ok((
        (
            f.get(70..86).ok_or("inner")?.try_into()?,
            f.get(86..102).ok_or("inner")?.try_into()?,
            port(l4)?,
            port(l4.saturating_add(2))?,
        ),
        l4_sum(58, &src, &dst, icmp) == 0xffff,
    ))
}

/// An outer IPv4 header's checks: (protocol, source, destination, header
/// checksum ok, total length matches the frame, TTL).
type Outer<const N: usize> = (u8, [u8; N], [u8; N], bool, bool, u8);
fn outer4(f: &[u8]) -> Result<Outer<4>> {
    let ip = f.get(14..34).ok_or("short frame")?;
    let total = u16::from_be_bytes(ip.get(2..4).ok_or("ip")?.try_into()?);
    Ok((
        *ip.get(9).ok_or("ip")?,
        ip.get(12..16).ok_or("ip")?.try_into()?,
        ip.get(16..20).ok_or("ip")?.try_into()?,
        sum(ip, 0) == 0xffff,
        usize::from(total) == f.len().saturating_sub(14),
        *ip.get(8).ok_or("ip")?,
    ))
}
/// [`outer4`] for IPv6: (next header, source, destination, -, payload length
/// matches, hop limit).
fn outer6(f: &[u8]) -> Result<Outer<16>> {
    let ip = f.get(14..54).ok_or("short frame")?;
    let payload = u16::from_be_bytes(ip.get(4..6).ok_or("ip")?.try_into()?);
    Ok((
        *ip.get(6).ok_or("ip")?,
        ip.get(8..24).ok_or("ip")?.try_into()?,
        ip.get(24..40).ok_or("ip")?.try_into()?,
        true,
        usize::from(payload) == f.len().saturating_sub(54),
        *ip.get(7).ok_or("ip")?,
    ))
}
/// The frame inside an encapsulation of `room` bytes after the Ethernet
/// header (IPIP: the outer IP header; Geneve: up to the inner Ethernet one,
/// whose type replaces the outer's).
fn inner(f: &[u8], room: usize, geneve: bool) -> Result<Vec<u8>> {
    let mut out = f.get(..14).ok_or("short frame")?.to_vec();
    if geneve {
        let eth = room.saturating_add(12)..room.saturating_add(14);
        out.splice(12..14, f.get(eth).ok_or("inner ethernet")?.iter().copied());
    }
    out.extend_from_slice(f.get(room.saturating_add(14)..).ok_or("short frame")?);
    Ok(out)
}

/// DSR by encapsulation (#447, `lb-dsr-dispatch`) on [`dsr`]'s frontends
/// (192.0.2.20:30095, [2001:db8:2::20]:30095 to 10.9.1.5:8080 /
/// [fd00:9:1::5]:8080, routed via 192.0.2.30 / 2001:db8:2::30). `ipip`: the
/// client's packet, its TTL lowered, leaves inside an outer header from this
/// node's address to the backend. `geneve`: the DNATed packet leaves in
/// Ethernet + Geneve (VNI 2, the DSR option naming the frontend; decoded by
/// `flowsdn_bpf_abi::tunnel`) over UDP 6081 (checksum 0) to the next hop. The
/// backend's node (this program on the same uplink) strips either, hands on
/// the DNATed packet with valid checksums and rewrites the reply's source to
/// the frontend; an encapsulation naming a destination that is not a
/// backend, or (Geneve) a frontend that is not DSR, drops. A later TCP
/// segment is plain DNAT. Back to `opt` at the end.
fn dsr_encap(lb: &mut SocketLb) -> Result<()> {
    use flowsdn_bpf_abi::{
        lb::DsrDispatch,
        tunnel::{DsrIpv4, DsrIpv6, GeneveHeader},
    };
    let up0 = ifindex("up0")?;
    let (front, client, remote, hop) = (
        [192, 0, 2, 20],
        [198, 51, 100, 9],
        [10, 9, 1, 5],
        [192, 0, 2, 30],
    );
    let (front6, client6, remote6, hop6) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:64::9")?,
        ip6("fd00:9:1::5")?,
        ip6("2001:db8:2::30")?,
    );
    for (mode, base) in [(DsrDispatch::Ipip, 42000u16), (DsrDispatch::Geneve, 42100)] {
        lb.set_dsr_dispatch(mode)?;
        if lb.dsr_dispatch()? != mode {
            return Err(format!("DSR dispatch {} does not read back", mode.name()).into());
        }
        let geneve = mode == DsrDispatch::Geneve;
        let name = mode.name();
        for (proto, sport) in [(6u8, base), (17, base.saturating_add(1))] {
            // IPv4.
            let request = frame4(proto, client, front, sport, 30095, false);
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let room = if geneve { 62 } else { 20 };
            let (outer_proto, src, dst, ip_ok, length_ok, ttl) = outer4(&out)?;
            let wire_ok = if geneve {
                let udp = out.get(34..42).ok_or("udp")?;
                let header = GeneveHeader::from_bytes(out.get(42..50).ok_or("geneve")?.try_into()?)
                    .map_err(|e| format!("{e:?}"))?;
                let option = DsrIpv4::from_bytes(out.get(50..62).ok_or("option")?.try_into()?)
                    .map_err(|e| format!("{e:?}"))?;
                udp.get(2..4) == Some(&6081u16.to_be_bytes()[..])
                    && udp.get(4..6)
                        == Some(&(out.len().saturating_sub(34) as u16).to_be_bytes()[..])
                    && udp.get(6..8) == Some(&[0, 0][..])
                    && header.option_words() == 3
                    && header.critical
                    && header.identity.get() == 2
                    && option
                        == DsrIpv4 {
                            address: front,
                            port: 30095,
                        }
                    && (outer_proto, dst) == (17, hop)
            } else {
                (outer_proto, dst) == (4, remote)
            };
            let carried = inner(&out, room, geneve)?;
            let (isrc, idst, is, id, iip_ok, il4_ok) = parse4(&carried)?;
            let want_inner = if geneve {
                (client, remote, sport, 8080)
            } else {
                (client, front, sport, 30095)
            };
            if !wire_ok
                || src != front
                || !ip_ok
                || !length_ok
                || ttl != 64
                || (isrc, idst, is, id) != want_inner
                || !iip_ok
                || !il4_ok
                || carried.get(22) != Some(&63)
            {
                return Err(format!(
                    "DSR {name} forward proto {proto}: outer {outer_proto} {src:?} -> {dst:?} ip {ip_ok} length {length_ok} ttl {ttl} wire {wire_ok}; inner {isrc:?}:{is} -> {idst:?}:{id} ip {iip_ok} l4 {il4_ok}"
                )
                .into());
            }
            // The backend's node strips it and hands on the DNATed packet.
            let reply = frame4(proto, remote, client, 8080, sport, false);
            if run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)? != reply {
                return Err(
                    format!("DSR {name} proto {proto}: a reply was rewritten early").into(),
                );
            }
            let got = run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)?;
            let (gsrc, gdst, gs, gd, gip_ok, gl4_ok) = parse4(&got)?;
            if (gsrc, gdst, gs, gd) != (client, remote, sport, 8080)
                || !gip_ok
                || !gl4_ok
                || got.len() != out.len().saturating_sub(room)
                || got.get(12..14) != Some(&[0x08, 0x00][..])
            {
                return Err(format!(
                    "DSR {name} decap proto {proto}: {gsrc:?}:{gs} -> {gdst:?}:{gd} ip {gip_ok} l4 {gl4_ok}, {} bytes",
                    got.len()
                )
                .into());
            }
            let (rsrc, rdst, rs, rd, rip_ok, rl4_ok) =
                parse4(&run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)?)?;
            if (rsrc, rdst, rs, rd) != (front, client, 30095, sport) || !rip_ok || !rl4_ok {
                return Err(format!(
                    "DSR {name} reply proto {proto}: {rsrc:?}:{rs} -> {rdst:?}:{rd}"
                )
                .into());
            }

            // IPv6.
            let request = frame6(proto, client6, front6, sport, 30095, false);
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let room = if geneve { 94 } else { 40 };
            let (outer_proto, src, dst, _, length_ok, hops) = outer6(&out)?;
            let wire_ok = if geneve {
                let udp = out.get(54..62).ok_or("udp")?;
                let header = GeneveHeader::from_bytes(out.get(62..70).ok_or("geneve")?.try_into()?)
                    .map_err(|e| format!("{e:?}"))?;
                let option = DsrIpv6::from_bytes(out.get(70..94).ok_or("option")?.try_into()?)
                    .map_err(|e| format!("{e:?}"))?;
                udp.get(2..4) == Some(&6081u16.to_be_bytes()[..])
                    && udp.get(4..6)
                        == Some(&(out.len().saturating_sub(54) as u16).to_be_bytes()[..])
                    && header.option_words() == 6
                    && header.critical
                    && header.identity.get() == 2
                    && option
                        == DsrIpv6 {
                            address: front6,
                            port: 30095,
                        }
                    && (outer_proto, dst) == (17, hop6)
            } else {
                (outer_proto, dst) == (41, remote6)
            };
            let carried = inner(&out, room, geneve)?;
            let (isrc, idst, is, id, ihops, il4_ok) = parse6(&carried)?;
            let want_inner = if geneve {
                (client6, remote6, sport, 8080)
            } else {
                (client6, front6, sport, 30095)
            };
            if !wire_ok
                || src != front6
                || !length_ok
                || hops != 64
                || (isrc, idst, is, id) != want_inner
                || ihops != 63
                || !il4_ok
            {
                return Err(format!(
                    "DSR {name} IPv6 forward proto {proto}: outer {outer_proto} {src:?} -> {dst:?} length {length_ok} hops {hops} wire {wire_ok}; inner {isrc:?}:{is} -> {idst:?}:{id} hops {ihops} l4 {il4_ok}"
                )
                .into());
            }
            let reply = frame6(proto, remote6, client6, 8080, sport, false);
            let got = run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)?;
            let (gsrc, gdst, gs, gd, _, gl4_ok) = parse6(&got)?;
            if (gsrc, gdst, gs, gd) != (client6, remote6, sport, 8080)
                || !gl4_ok
                || got.len() != out.len().saturating_sub(room)
            {
                return Err(format!(
                    "DSR {name} IPv6 decap proto {proto}: {gsrc:?}:{gs} -> {gdst:?}:{gd} l4 {gl4_ok}"
                )
                .into());
            }
            let (rsrc, rdst, rs, rd, _, rl4_ok) =
                parse6(&run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)?)?;
            if (rsrc, rdst, rs, rd) != (front6, client6, 30095, sport) || !rl4_ok {
                return Err(format!(
                    "DSR {name} IPv6 reply proto {proto}: {rsrc:?}:{rs} -> {rdst:?}:{rd}"
                )
                .into());
            }
        }
        // A later TCP segment finds the backend's reply entry: plain DNAT.
        let later = ack(frame4(6, client, front, base, 30095, false), 34)?;
        let out = run_on(lb, "nodeport_ingress", &later, up0, TC_ACT_REDIRECT)?;
        let (src, dst, _, d, ip_ok, l4_ok) = parse4(&out)?;
        if out.get(23) != Some(&6) || (src, dst, d) != (client, remote, 8080) || !ip_ok || !l4_ok {
            return Err(format!("DSR {name} later segment: {src:?} -> {dst:?}:{d}").into());
        }
        // Forged encapsulations drop on the backend's node.
        let request = frame4(6, client, front, base.saturating_add(5), 30095, false);
        let valid = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let mut forged: Vec<(&str, Vec<u8>)> = Vec::new();
        if geneve {
            let mut wrong_front = valid.clone();
            wrong_front.splice(54..58, [192, 0, 2, 99]);
            let mut not_backend = valid.clone();
            not_backend.splice(92..96, [10, 9, 1, 6]);
            forged.push(("a frontend that is not DSR", wrong_front));
            forged.push(("a destination that is not a backend", not_backend));
        } else {
            let mut not_backend = valid.clone();
            not_backend.splice(30..34, [10, 9, 1, 6]);
            forged.push(("an outer destination that is not a backend", not_backend));
        }
        for (what, frame) in forged {
            run_on(lb, "nodeport_ingress", &frame, up0, TC_ACT_SHOT)
                .map_err(|e| format!("DSR {name} with {what}: {e}"))?;
            let reply = frame4(
                6,
                [10, 9, 1, 6],
                client,
                8080,
                base.saturating_add(5),
                false,
            );
            if run_on(lb, "nodeport_egress", &reply, up0, TCX_NEXT)? != reply {
                return Err(format!("DSR {name} with {what} left a reply rewrite").into());
            }
        }
        // IPv6: a destination that is not a backend drops too.
        let request = frame6(6, client6, front6, base.saturating_add(6), 30095, false);
        let valid = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let mut not_backend = valid.clone();
        let last = if geneve { 147 } else { 53 };
        if let Some(byte) = not_backend.get_mut(last) {
            *byte = 0x06;
        }
        run_on(lb, "nodeport_ingress", &not_backend, up0, TC_ACT_SHOT)
            .map_err(|e| format!("DSR {name} IPv6 to a destination that is not a backend: {e}"))?;
    }
    lb.set_dsr_dispatch(DsrDispatch::Opt)?;
    println!(
        "PASS DSR by encapsulation: with lb-dsr-dispatch ipip the client's packet (TTL / hop limit lowered) leaves inside an outer IPv4 or IPv6 header from the node's address to the backend, with geneve the DNATed packet leaves in Ethernet + Geneve (VNI 2, the DSR option naming the frontend) over UDP 6081 to the next hop, TCP and UDP, IPv4 and IPv6; the backend's node strips either, hands on the packet DNATed with valid checksums and rewrites the reply's source to the frontend; a later TCP segment is plain DNAT; an encapsulation naming a destination that is not a backend, or a frontend that is not DSR, drops"
    );
    Ok(())
}

/// ICMP errors of Service flows (#449), for a DSR frontend (192.0.2.20:30095,
/// its backend 10.9.1.5 on another node) and a node-local one (:30080,
/// 10.9.0.5), TCP and UDP, IPv4 and IPv6. On the backend's node, an error
/// about the client's packet as the backend got it (a DSR packet with its
/// option) leaves `nodeport_egress` quoting the frontend, and from the
/// frontend when the backend sent it (a router's keeps its source). On the
/// frontend's node, a client's error about a reply goes to the backend: a DSR
/// flow's redirected (TTL 63), a local one to the stack. Checksums valid;
/// errors about other flows untouched.
fn icmp_errors(lb: &mut SocketLb) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (front, client) = ([192, 0, 2, 20], [198, 51, 100, 9]);
    let router = [10, 9, 1, 1];
    for proto in [6u8, 17] {
        for (front_port, backend, dsr) in [
            (30095u16, [10, 9, 1, 5], true),
            (30080, [10, 9, 0, 5], false),
        ] {
            let sport = 41200u16
                .saturating_add(u16::from(proto))
                .saturating_add(if dsr { 0 } else { 100 });
            let what = format!("proto {proto} {}", if dsr { "DSR" } else { "local" });
            let request = frame4(proto, client, front, sport, front_port, false);
            let received = if dsr {
                let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
                // The backend's node takes the option: the reply entry.
                run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)?;
                out
            } else {
                run(lb, "nodeport_ingress", &request)?
            };
            for (sender, kind, code) in [(backend, 3u8, 3u8), (router, 3, 4)] {
                let error = icmp_frame4(sender, client, &error_message(kind, code, &received)?);
                let out = run_on(lb, "nodeport_egress", &error, up0, TCX_NEXT)?;
                let (quote, sums) = quote4(&out)?;
                let source = if sender == backend { front } else { sender };
                if out.get(26..30) != Some(&source[..])
                    || out.get(30..34) != Some(&client[..])
                    || quote != (client, front, sport, front_port, true)
                    || !sums
                {
                    return Err(format!(
                        "ICMP error {what} from {sender:?} on the backend's node: {:?} -> {:?}, quote {quote:?}, checksums {sums}",
                        out.get(26..30),
                        out.get(30..34)
                    )
                    .into());
                }
            }
            let reply = frame4(proto, front, client, front_port, sport, false);
            let error = icmp_frame4(client, front, &error_message(3, 3, &reply)?);
            let out = if dsr {
                run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?
            } else {
                run(lb, "nodeport_ingress", &error)?
            };
            let (quote, sums) = quote4(&out)?;
            let ttl = if dsr { 63 } else { 64 };
            if out.get(26..30) != Some(&client[..])
                || out.get(30..34) != Some(&backend[..])
                || quote != (backend, client, 8080, sport, true)
                || out.get(22) != Some(&ttl)
                || !sums
            {
                return Err(format!(
                    "ICMP error {what} on the frontend's node: to {:?}, quote {quote:?}, ttl {:?}, checksums {sums}",
                    out.get(30..34),
                    out.get(22)
                )
                .into());
            }
        }
    }
    // Errors about flows never seen pass untouched.
    let unknown = frame4(17, [10, 9, 1, 5], client, 8080, 41999, false);
    let error = icmp_frame4([10, 9, 1, 5], client, &error_message(3, 3, &unknown)?);
    if run_on(lb, "nodeport_egress", &error, up0, TCX_NEXT)? != error {
        return Err("an ICMP error about an unknown flow was rewritten on egress".into());
    }
    let unknown = frame4(17, front, client, 30095, 41999, false);
    let error = icmp_frame4(client, front, &error_message(3, 3, &unknown)?);
    if run_on(lb, "nodeport_ingress", &error, up0, TCX_NEXT)? != error {
        return Err("an ICMP error about an unknown flow was rewritten on ingress".into());
    }

    let (front6, client6) = (ip6("2001:db8:2::20")?, ip6("2001:db8:64::9")?);
    let router6 = ip6("fd00:9:1::1")?;
    for proto in [6u8, 17] {
        for (front_port, backend, dsr) in [
            (30095u16, ip6("fd00:9:1::5")?, true),
            (30080, ip6("fd00:9::5")?, false),
        ] {
            let sport = 41400u16
                .saturating_add(u16::from(proto))
                .saturating_add(if dsr { 0 } else { 100 });
            let what = format!("IPv6 proto {proto} {}", if dsr { "DSR" } else { "local" });
            let request = frame6(proto, client6, front6, sport, front_port, false);
            let received = if dsr {
                let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
                run_on(lb, "nodeport_ingress", &out, up0, TCX_NEXT)?;
                out
            } else {
                run(lb, "nodeport_ingress", &request)?
            };
            // Port unreachable from the backend; packet too big from a router.
            for (sender, kind, code) in [(backend, 1u8, 4u8), (router6, 2, 0)] {
                let error = icmp_frame6(sender, client6, &error_message(kind, code, &received)?);
                let out = run_on(lb, "nodeport_egress", &error, up0, TCX_NEXT)?;
                let (quote, sum_ok) = quote6(&out)?;
                let source = if sender == backend { front6 } else { sender };
                if out.get(22..38) != Some(&source[..])
                    || out.get(38..54) != Some(&client6[..])
                    || quote != (client6, front6, sport, front_port)
                    || !sum_ok
                {
                    return Err(format!(
                        "ICMPv6 error {what} on the backend's node: from {:?}, quote {quote:?}, checksum {sum_ok}",
                        out.get(22..38)
                    )
                    .into());
                }
            }
            let reply = frame6(proto, front6, client6, front_port, sport, false);
            let error = icmp_frame6(client6, front6, &error_message(1, 4, &reply)?);
            let out = if dsr {
                run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?
            } else {
                run(lb, "nodeport_ingress", &error)?
            };
            let (quote, sum_ok) = quote6(&out)?;
            let hops = if dsr { 63 } else { 64 };
            if out.get(22..38) != Some(&client6[..])
                || out.get(38..54) != Some(&backend[..])
                || quote != (backend, client6, 8080, sport)
                || out.get(21) != Some(&hops)
                || !sum_ok
            {
                return Err(format!(
                    "ICMPv6 error {what} on the frontend's node: to {:?}, quote {quote:?}, hops {:?}, checksum {sum_ok}",
                    out.get(38..54),
                    out.get(21)
                )
                .into());
            }
        }
    }
    let unknown = frame6(17, front6, client6, 30095, 41999, false);
    let error = icmp_frame6(client6, front6, &error_message(1, 4, &unknown)?);
    if run_on(lb, "nodeport_ingress", &error, up0, TCX_NEXT)? != error {
        return Err("an ICMPv6 error about an unknown flow was rewritten".into());
    }
    println!(
        "PASS ICMP errors of Service flows: for a DSR and a node-local frontend, TCP and UDP, IPv4 and IPv6, an error about the client's packet (the DSR one quoted with its option) leaves the backend's node quoting the frontend, from the frontend when the backend sent it; a client's error about a reply goes to the backend, a DSR flow's redirected toward its node; checksums valid; errors about other flows untouched"
    );
    Ok(())
}

/// ICMP errors of source-NATed flows (#534), on [`snat`]'s and [`snat6`]'s
/// frontends (:30090, backends 10.9.1.5 / fd00:9:1::5 on another node): an
/// error the backend sends about a forwarded packet (quoting
/// `nat:natport -> backend`) reaches the client from the frontend, quoting
/// `client -> frontend`; a client's error about a reply goes to the backend
/// from the NAT address, quoting `backend -> nat:natport`. TCP and UDP, IPv4
/// and IPv6; TTL / hop limit 63, checksums valid.
fn icmp_errors_snat(lb: &mut SocketLb) -> Result<()> {
    let up0 = ifindex("up0")?;
    let (front, client, backend) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 1, 5]);
    for proto in [6u8, 17] {
        let sport = 41700u16.saturating_add(u16::from(proto));
        let request = frame4(proto, client, front, sport, 30090, false);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let (nat, _, nat_port, _, _, _) = parse4(&out)?;
        let error = icmp_frame4(backend, nat, &error_message(3, 3, &out)?);
        let back = run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?;
        let (quote, sums) = quote4(&back)?;
        if back.get(26..30) != Some(&front[..])
            || back.get(30..34) != Some(&client[..])
            || quote != (client, front, sport, 30090, true)
            || back.get(22) != Some(&63)
            || !sums
        {
            return Err(format!(
                "SNAT ICMP error proto {proto} from the backend: {:?} -> {:?}, quote {quote:?}, ttl {:?}, checksums {sums}",
                back.get(26..30),
                back.get(30..34),
                back.get(22)
            )
            .into());
        }
        let reply = frame4(proto, front, client, 30090, sport, false);
        let error = icmp_frame4(client, front, &error_message(3, 3, &reply)?);
        let to = run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?;
        let (quote, sums) = quote4(&to)?;
        if to.get(26..30) != Some(&nat[..])
            || to.get(30..34) != Some(&backend[..])
            || quote != (backend, nat, 8080, nat_port, true)
            || to.get(22) != Some(&63)
            || !sums
        {
            return Err(format!(
                "SNAT ICMP error proto {proto} from the client: {:?} -> {:?}, quote {quote:?}, ttl {:?}, checksums {sums}",
                to.get(26..30),
                to.get(30..34),
                to.get(22)
            )
            .into());
        }
    }
    let (front6, client6, backend6) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:64::9")?,
        ip6("fd00:9:1::5")?,
    );
    for proto in [6u8, 17] {
        let sport = 41800u16.saturating_add(u16::from(proto));
        let request = frame6(proto, client6, front6, sport, 30090, false);
        let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
        let (nat, _, nat_port, _, _, _) = parse6(&out)?;
        let error = icmp_frame6(backend6, nat, &error_message(1, 4, &out)?);
        let back = run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?;
        let (quote, sum_ok) = quote6(&back)?;
        if back.get(22..38) != Some(&front6[..])
            || back.get(38..54) != Some(&client6[..])
            || quote != (client6, front6, sport, 30090)
            || back.get(21) != Some(&63)
            || !sum_ok
        {
            return Err(format!(
                "SNAT ICMPv6 error proto {proto} from the backend: {:?} -> {:?}, quote {quote:?}, hops {:?}, checksum {sum_ok}",
                back.get(22..38),
                back.get(38..54),
                back.get(21)
            )
            .into());
        }
        let reply = frame6(proto, front6, client6, 30090, sport, false);
        let error = icmp_frame6(client6, front6, &error_message(1, 4, &reply)?);
        let to = run_on(lb, "nodeport_ingress", &error, up0, TC_ACT_REDIRECT)?;
        let (quote, sum_ok) = quote6(&to)?;
        if to.get(22..38) != Some(&nat[..])
            || to.get(38..54) != Some(&backend6[..])
            || quote != (backend6, nat, 8080, nat_port)
            || to.get(21) != Some(&63)
            || !sum_ok
        {
            return Err(format!(
                "SNAT ICMPv6 error proto {proto} from the client: {:?} -> {:?}, quote {quote:?}, hops {:?}, checksum {sum_ok}",
                to.get(22..38),
                to.get(38..54),
                to.get(21)
            )
            .into());
        }
    }
    // An error quoting a NAT port no flow holds passes untouched.
    let stray = frame4(17, front, backend, 64999, 8080, false);
    let error = icmp_frame4(backend, front, &error_message(3, 3, &stray)?);
    if run_on(lb, "nodeport_ingress", &error, up0, TCX_NEXT)? != error {
        return Err("an ICMP error about an unknown NAT port was rewritten".into());
    }
    println!(
        "PASS ICMP errors of source-NATed flows: TCP and UDP, IPv4 and IPv6, the backend's error about a forwarded packet reaches the client from the frontend quoting client -> frontend, and a client's error about a reply reaches the backend from the NAT address quoting backend -> nat:natport; TTL and hop limit 63, checksums valid; an error about an unknown NAT port untouched"
    );
    Ok(())
}

/// Maglev frontends (spec 05 §3.13): `nodeport_ingress` sends each new flow
/// to the backend the planner's table gives it ([`socket::maglev_pick`],
/// the flow hash both sides share), IPv4 and IPv6, over several backends;
/// a frame of a known flow keeps its backend.
fn maglev(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    services.push(Service {
        frontend: address("192.0.2.20:30070", PROTO_TCP)?,
        backends: ["10.9.0.5:8080", "10.9.0.6:8080", "10.9.0.7:8080"]
            .iter()
            .map(|b| address(b, PROTO_TCP))
            .collect::<Result<_>>()?,
        affinity: None,
        scope: SCOPE_NODE_LOCAL,
        maglev: true,
        dsr: false,
        nat46x64: false,
        local_redirect: false,
        skip: Vec::new(),
    });
    services.push(Service {
        frontend: address("[2001:db8:2::20]:30070", PROTO_UDP)?,
        backends: ["[fd00:9::5]:8080", "[fd00:9::6]:8080"]
            .iter()
            .map(|b| address(b, PROTO_UDP))
            .collect::<Result<_>>()?,
        affinity: None,
        scope: SCOPE_NODE_LOCAL,
        maglev: true,
        dsr: false,
        nat46x64: false,
        local_redirect: false,
        skip: Vec::new(),
    });
    program(lb, services)?;
    let maps = lb.dump()?;
    if maps.maglev4.len() != 1 || maps.maglev6.len() != 1 {
        return Err("the kernel does not hold one Maglev table per family".into());
    }
    let (front, client) = ([192, 0, 2, 20], [198, 51, 100, 9]);
    let (front6, client6) = (ip6("2001:db8:2::20")?, ip6("2001:db8:3::9")?);
    let mut seen = std::collections::BTreeSet::new();
    for sport in 41000..41032u16 {
        let want = socket::maglev_pick(
            &maps,
            address("192.0.2.20:30070", PROTO_TCP)?,
            SCOPE_NODE_LOCAL,
            IpAddr::from(client),
            sport,
        )
        .ok_or("no Maglev pick for an IPv4 flow")?;
        let request = frame4(6, client, front, sport, 30070, false);
        for _ in 0..2 {
            let (_, dst, _, d, ip_ok, l4_ok) = parse4(&run(lb, "nodeport_ingress", &request)?)?;
            let got = SocketAddr::from((dst, d));
            if got != SocketAddr::new(want.ip, want.port) || !ip_ok || !l4_ok {
                return Err(format!(
                    "Maglev IPv4 flow port {sport}: kernel picked {got}, the table {}:{}",
                    want.ip, want.port
                )
                .into());
            }
        }
        seen.insert(want.ip);
        let want = socket::maglev_pick(
            &maps,
            address("[2001:db8:2::20]:30070", PROTO_UDP)?,
            SCOPE_NODE_LOCAL,
            IpAddr::from(client6),
            sport,
        )
        .ok_or("no Maglev pick for an IPv6 flow")?;
        let request = frame6(17, client6, front6, sport, 30070, false);
        let (_, dst, _, d, _, l4_ok) = parse6(&run(lb, "nodeport_ingress", &request)?)?;
        let got = SocketAddr::from((dst, d));
        if got != SocketAddr::new(want.ip, want.port) || !l4_ok {
            return Err(format!(
                "Maglev IPv6 flow port {sport}: kernel picked {got}, the table {}:{}",
                want.ip, want.port
            )
            .into());
        }
        seen.insert(want.ip);
    }
    if seen.len() < 4 {
        return Err(format!("32 flows per family reached only {seen:?}").into());
    }
    println!(
        "PASS Maglev: 32 TCP flows to 192.0.2.20:30070 and 32 UDP flows to [2001:db8:2::20]:30070 each went to the backend the planner's table gives (flow hash shared with the agent), over {} backends; repeated frames kept theirs",
        seen.len()
    );
    Ok(())
}

/// [`nodeport`] for IPv6: [2001:db8:2::20]:30080 to the node-local backend
/// [fd00:9::5]:8080 and back.
fn nodeport6(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let (front, client, backend) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:3::9")?,
        ip6("fd00:9::5")?,
    );
    for proto in [PROTO_TCP, PROTO_UDP] {
        services.push(Service {
            frontend: address("[2001:db8:2::20]:30080", proto)?,
            backends: vec![address("[fd00:9::5]:8080", proto)?],
            affinity: None,
            scope: SCOPE_NODE_LOCAL,
            maglev: false,
            dsr: false,
            nat46x64: false,
            local_redirect: false,
            skip: Vec::new(),
        });
    }
    program(lb, services)?;
    for (proto, udp_zero) in [(6u8, false), (17, false), (17, true)] {
        let sport = if udp_zero { 40001 } else { 40000 };
        let request = frame6(proto, client, front, sport, 30080, udp_zero);
        let (src, dst, s, d, hops, l4_ok) = parse6(&run(lb, "nodeport_ingress", &request)?)?;
        if (src, dst, s, d, hops) != (client, backend, sport, 8080, 64) || !l4_ok {
            return Err(format!(
                "nodeport_ingress IPv6 proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}"
            )
            .into());
        }
        let reply = frame6(proto, backend, client, 8080, sport, udp_zero);
        let (src, dst, s, d, _, l4_ok) = parse6(&run(lb, "nodeport_egress", &reply)?)?;
        if (src, dst, s, d) != (front, client, 30080, sport) || !l4_ok {
            return Err(format!(
                "nodeport_egress IPv6 proto {proto}: {src:?}:{s} -> {dst:?}:{d}, checksum {l4_ok}"
            )
            .into());
        }
    }
    for (program, frame) in [
        (
            "nodeport_ingress",
            frame6(6, client, ip6("2001:db8::10")?, 40000, 80, false),
        ),
        (
            "nodeport_ingress",
            frame6(6, client, front, 40000, 30081, false),
        ),
        (
            "nodeport_egress",
            frame6(6, backend, client, 8080, 41000, false),
        ),
    ] {
        if run(lb, program, &frame)? != frame {
            return Err(format!("{program} changed an IPv6 frame it does not own").into());
        }
    }
    println!(
        "PASS NodePort uplink IPv6: TCP, UDP and checksum-less UDP to [2001:db8:2::20]:30080 rewritten to the node-local backend and replies back to the frontend, checksums valid; other frames untouched"
    );
    Ok(())
}

/// NodePort to a backend on another node (#292): SNAT to the node address,
/// redirected out of the uplink to the resolved next hop; the other node's
/// reply to the NAT port is reverse-NATed and redirected to the client.
fn snat(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    let up0 = node()?;
    let uplink_mac: Vec<u8> = UPLINK_MAC
        .split(':')
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<std::result::Result<_, _>>()?;
    let (front, client, remote) = ([192, 0, 2, 20], [198, 51, 100, 9], [10, 9, 1, 5]);
    for proto in [PROTO_TCP, PROTO_UDP] {
        services.push(Service {
            frontend: address("192.0.2.20:30090", proto)?,
            backends: vec![address("10.9.1.5:8080", proto)?],
            affinity: None,
            scope: SCOPE_NODE_LOCAL,
            maglev: false,
            dsr: false,
            nat46x64: false,
            local_redirect: false,
            skip: Vec::new(),
        });
    }
    program(lb, services)?;
    for (proto, udp_zero) in [(6u8, false), (17, false), (17, true)] {
        let sport = if udp_zero { 40003 } else { 40002 };
        let request = frame4(proto, client, front, sport, 30090, udp_zero);
        let mut nat_port = None;
        // The second packet of the flow must reuse the first one's NAT port.
        for _ in 0..2 {
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
            let ttl = out.get(22).copied();
            let macs = (out.get(0..6), out.get(6..12));
            if src != front
                || (dst, d) != (remote, 8080)
                || !(61000..=65535).contains(&s)
                || nat_port.is_some_and(|p| p != s)
                || !ip_ok
                || !l4_ok
                || ttl != Some(63)
                || macs != (Some(&GATEWAY_MAC[..]), Some(&uplink_mac[..]))
            {
                return Err(format!(
                    "SNAT forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ttl {ttl:?}, macs {macs:?}, checksums ip {ip_ok} l4 {l4_ok}"
                )
                .into());
            }
            nat_port = Some(s);
        }
        let nat_port = nat_port.ok_or("no NAT port")?;
        let reply = frame4(proto, remote, front, 8080, nat_port, udp_zero);
        // The client's next hop (192.0.2.1) is unresolved: redirect_neigh.
        let out = run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, ip_ok, l4_ok) = parse4(&out)?;
        let ttl = out.get(22).copied();
        if (src, dst, s, d) != (front, client, 30090, sport) || !ip_ok || !l4_ok || ttl != Some(63)
        {
            return Err(format!(
                "SNAT reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, ttl {ttl:?}, checksums ip {ip_ok} l4 {l4_ok}"
            )
            .into());
        }
    }
    // A reply to a NAT port no flow holds, and a TTL that forwarding would
    // expire: untouched, left to the stack.
    let stray = frame4(6, remote, front, 8081, 61000, false);
    let stray = run_on(lb, "nodeport_ingress", &stray, up0, TCX_NEXT)? == stray;
    let mut expiring = frame4(6, client, front, 40100, 30090, false);
    if let Some(ttl) = expiring.get_mut(22) {
        *ttl = 1;
    }
    let expiring_kept = run_on(lb, "nodeport_ingress", &expiring, up0, TCX_NEXT)? == expiring;
    if !stray || !expiring_kept {
        return Err(format!(
            "SNAT changed a frame it does not own (stray reply {stray}, TTL 1 {expiring_kept})"
        )
        .into());
    }
    println!(
        "PASS NodePort SNAT: TCP, UDP and checksum-less UDP to 192.0.2.20:30090 with a backend on another node source-NATed to 192.0.2.20 on a port in 61000-65535 (kept per flow), TTL 63, redirected to the resolved next hop's MAC; replies reverse-NATed and redirected toward the client; stray replies and TTL 1 untouched"
    );
    snat6(lb, services, up0, &uplink_mac)
}

/// [`snat`] for IPv6: up0 also holds 2001:db8:2::20/64; another node's pod
/// CIDR fd00:9:1::/64 is via 2001:db8:2::30 (resolved), the default route
/// via 2001:db8:2::1 (unresolved).
fn snat6(
    lb: &mut SocketLb,
    services: &mut Vec<Service>,
    up0: u32,
    uplink_mac: &[u8],
) -> Result<()> {
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:2::20/64",
        "dev",
        "up0",
        "nodad",
    ])?;
    ip(&[
        "-6",
        "route",
        "add",
        "fd00:9:1::/64",
        "via",
        "2001:db8:2::30",
        "dev",
        "up0",
    ])?;
    ip(&[
        "-6",
        "neigh",
        "replace",
        "2001:db8:2::30",
        "lladdr",
        "02:00:00:00:00:30",
        "dev",
        "up0",
        "nud",
        "permanent",
    ])?;
    ip(&[
        "-6",
        "route",
        "add",
        "default",
        "via",
        "2001:db8:2::1",
        "dev",
        "up0",
    ])?;
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    let (front, client, remote) = (
        ip6("2001:db8:2::20")?,
        ip6("2001:db8:3::9")?,
        ip6("fd00:9:1::5")?,
    );
    for proto in [PROTO_TCP, PROTO_UDP] {
        services.push(Service {
            frontend: address("[2001:db8:2::20]:30090", proto)?,
            backends: vec![address("[fd00:9:1::5]:8080", proto)?],
            affinity: None,
            scope: SCOPE_NODE_LOCAL,
            maglev: false,
            dsr: false,
            nat46x64: false,
            local_redirect: false,
            skip: Vec::new(),
        });
    }
    program(lb, services)?;
    for (proto, udp_zero) in [(6u8, false), (17, false), (17, true)] {
        let sport = if udp_zero { 40003 } else { 40002 };
        let request = frame6(proto, client, front, sport, 30090, udp_zero);
        let mut nat_port = None;
        // The second packet of the flow must reuse the first one's NAT port.
        for _ in 0..2 {
            let out = run_on(lb, "nodeport_ingress", &request, up0, TC_ACT_REDIRECT)?;
            let (src, dst, s, d, hops, l4_ok) = parse6(&out)?;
            let macs = (out.get(0..6), out.get(6..12));
            if src != front
                || (dst, d) != (remote, 8080)
                || !(61000..=65535).contains(&s)
                || nat_port.is_some_and(|p| p != s)
                || !l4_ok
                || hops != 63
                || macs != (Some(&GATEWAY_MAC[..]), Some(uplink_mac))
            {
                return Err(format!(
                    "SNAT IPv6 forward proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, macs {macs:?}, checksum {l4_ok}"
                )
                .into());
            }
            nat_port = Some(s);
        }
        let nat_port = nat_port.ok_or("no NAT port")?;
        let reply = frame6(proto, remote, front, 8080, nat_port, udp_zero);
        // The client's next hop (2001:db8:2::1) is unresolved: redirect_neigh.
        let out = run_on(lb, "nodeport_ingress", &reply, up0, TC_ACT_REDIRECT)?;
        let (src, dst, s, d, hops, l4_ok) = parse6(&out)?;
        if (src, dst, s, d, hops) != (front, client, 30090, sport, 63) || !l4_ok {
            return Err(format!(
                "SNAT IPv6 reply proto {proto}: {src:?}:{s} -> {dst:?}:{d}, hops {hops}, checksum {l4_ok}"
            )
            .into());
        }
    }
    // A reply to a NAT port no flow holds, and a hop limit that forwarding
    // would expire: untouched, left to the stack.
    let stray = frame6(6, remote, front, 8081, 61000, false);
    let stray = run_on(lb, "nodeport_ingress", &stray, up0, TCX_NEXT)? == stray;
    let mut expiring = frame6(6, client, front, 40100, 30090, false);
    if let Some(hops) = expiring.get_mut(21) {
        *hops = 1;
    }
    let expiring_kept = run_on(lb, "nodeport_ingress", &expiring, up0, TCX_NEXT)? == expiring;
    if !stray || !expiring_kept {
        return Err(format!(
            "SNAT IPv6 changed a frame it does not own (stray reply {stray}, hop limit 1 {expiring_kept})"
        )
        .into());
    }
    println!(
        "PASS NodePort SNAT IPv6: TCP, UDP and checksum-less UDP to [2001:db8:2::20]:30090 with a backend on another node source-NATed to 2001:db8:2::20 on a port in 61000-65535 (kept per flow), hop limit 63, redirected to the resolved next hop's MAC; replies reverse-NATed and redirected toward the client; stray replies and hop limit 1 untouched"
    );
    Ok(())
}

/// Socket termination (spec 05 §3.8, #292): a UDP socket connected through
/// the frontend to a backend that leaves is destroyed through SOCK_DIAG (its
/// cookie is in `_reverse_sk` with that backend), so its next receive fails
/// with ECONNABORTED; a socket connected to the backend address directly is
/// not the socket LB's and stays.
fn terminate(lb: &mut SocketLb, services: &mut Vec<Service>, server: &UdpSocket) -> Result<()> {
    use flowsdn_connector::sock_diag;
    let through = UdpSocket::bind("127.0.0.1:0")?;
    through.connect(sa("192.0.2.10:53")?)?;
    through.send(b"query")?;
    let direct = UdpSocket::bind("127.0.0.1:0")?;
    direct.connect(sa("127.0.0.1:15353")?)?;
    direct.send(b"query")?;
    server.set_read_timeout(Some(TIMEOUT))?;
    let mut buffer = [0; 16];
    for _ in 0..2 {
        server.recv_from(&mut buffer)?;
    }
    let udp = services
        .iter_mut()
        .find(|s| s.frontend.proto == PROTO_UDP && s.frontend.ip.is_ipv4())
        .ok_or("IPv4 UDP service")?;
    udp.backends = vec![address("127.0.0.2:15353", PROTO_UDP)?];
    program(lb, services)?;
    let backend = (IpAddr::from([127, 0, 0, 1]), 15353u16);
    let gone: BTreeSet<sock_diag::Backend> = [(PROTO_UDP, backend.0, backend.1)].into();
    let cookies: BTreeSet<u64> = lb
        .reverse_sockets()?
        .into_iter()
        .filter(|(_, ip, port)| (*ip, *port) == backend)
        .map(|(cookie, _, _)| cookie)
        .collect();
    // The agent's selection and destroy (#392).
    let destroyed = sock_diag::destroy_to(&gone, &cookies, false).map_err(|e| e.to_string())?;
    if destroyed != 1 {
        return Err(format!(
            "{destroyed} sockets destroyed, expected the one through the frontend"
        )
        .into());
    }
    through.set_read_timeout(Some(TIMEOUT))?;
    match through.recv(&mut buffer) {
        Err(error) if error.raw_os_error() == Some(nix::libc::ECONNABORTED) => {}
        other => return Err(format!("terminated socket: {other:?}, expected ECONNABORTED").into()),
    }
    direct.send(b"still")?;
    let (n, _) = server.recv_from(&mut buffer)?;
    if buffer.get(..n) != Some(b"still".as_slice()) {
        return Err("the directly connected socket stopped working".into());
    }
    let udp = services
        .iter_mut()
        .find(|s| s.frontend.proto == PROTO_UDP && s.frontend.ip.is_ipv4())
        .ok_or("IPv4 UDP service")?;
    udp.backends = vec![address("127.0.0.1:15353", PROTO_UDP)?];
    program(lb, services)?;
    println!(
        "PASS socket termination: the UDP socket connected through 192.0.2.10:53 to the removed backend was destroyed (ECONNABORTED); one connected to that backend directly stayed"
    );
    terminate_tcp(lb, services)
}

/// TCP termination (#392, `lb-sock-terminate-all-protos`): a TCP connection
/// through a frontend whose backend leaves is left alone by default and
/// ended (ECONNABORTED or reset) with TCP on; a connection to another
/// backend stays.
fn terminate_tcp(lb: &mut SocketLb, services: &mut Vec<Service>) -> Result<()> {
    use flowsdn_connector::sock_diag;
    let leaving = TcpListener::bind("127.0.0.1:18081")?;
    let staying = TcpListener::bind("127.0.0.1:18082")?;
    services.push(service("192.0.2.12:80", PROTO_TCP, &["127.0.0.1:18081"])?);
    program(lb, services)?;
    let mut through = TcpStream::connect_timeout(&sa("192.0.2.12:80")?, TIMEOUT)?;
    if through.peer_addr()? != sa("127.0.0.1:18081")? {
        return Err(format!(
            "TCP through 192.0.2.12:80 reached {:?}",
            through.peer_addr()
        )
        .into());
    }
    let (_held, _) = leaving.accept()?;
    let mut other = TcpStream::connect_timeout(&sa("127.0.0.1:18082")?, TIMEOUT)?;
    let (mut other_server, _) = staying.accept()?;
    if let Some(entry) = services
        .iter_mut()
        .find(|s| s.frontend.ip == IpAddr::from([192, 0, 2, 12]))
    {
        entry.backends = vec![address("127.0.0.1:18082", PROTO_TCP)?];
    }
    program(lb, services)?;
    let gone: BTreeSet<sock_diag::Backend> =
        [(PROTO_TCP, IpAddr::from([127, 0, 0, 1]), 18081u16)].into();
    let none = BTreeSet::new();
    let by_default = sock_diag::destroy_to(&gone, &none, false).map_err(|e| e.to_string())?;
    if by_default != 0 {
        return Err(format!("{by_default} TCP sockets ended without all protocols").into());
    }
    let ended = sock_diag::destroy_to(&gone, &none, true).map_err(|e| e.to_string())?;
    if ended != 1 {
        return Err(
            format!("{ended} TCP sockets ended, expected the one through the frontend").into(),
        );
    }
    through.set_read_timeout(Some(TIMEOUT))?;
    let mut buffer = [0u8; 4];
    match through.read(&mut buffer) {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(nix::libc::ECONNABORTED | nix::libc::ECONNRESET)
            ) => {}
        other => return Err(format!("ended TCP socket: {other:?}, expected ECONNABORTED").into()),
    }
    other.write_all(b"ok")?;
    other_server.set_read_timeout(Some(TIMEOUT))?;
    let mut two = [0u8; 2];
    other_server.read_exact(&mut two)?;
    if &two != b"ok" {
        return Err("the connection to the staying backend stopped working".into());
    }
    println!(
        "PASS TCP termination: the connection through 192.0.2.12:80 to the removed backend was left alone by default and ended with lb-sock-terminate-all-protos; one to another backend stayed"
    );
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
    socket_nat46x64(&mut lb, &mut services, (&tcp4, &tcp6), (&udp4, &udp6))?;

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
    terminate(&mut lb, &mut services, &udp4)?;
    local_redirect(&mut lb, &mut services, (&tcp4, &tcp4b), &tcp6)?;

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
