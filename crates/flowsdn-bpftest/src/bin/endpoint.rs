//! Privileged dual-stack endpoint delivery test in three anonymous namespaces.
use std::{
    error::Error,
    io::{BufRead, BufReader, Write, ErrorKind},
    net::{SocketAddr, UdpSocket},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};
use aya::{Ebpf, maps::{HashMap, MapData}, programs::{SchedClassifier, TcAttachType}};
use flowsdn_bpf_abi::{MapBytes, endpoint::{EndpointInfo, EndpointKey}};
use nix::sched::{unshare, CloneFlags};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
type Endpoints = HashMap<MapData, [u8; 20], [u8; 48]>;

fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").args(args).output()?;
    ensure(output.status.success(), &format!("ip {}: {}", args.join(" "), String::from_utf8_lossy(&output.stderr)))
}
fn isolate() -> Result<()> {
    let previous = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(std::fs::read_link("/proc/self/ns/net")? != previous, "namespace isolation failed")
}
fn address(id: u8, v6: bool) -> String {
    if v6 { format!("2001:db8:1::{id}") } else { format!("198.18.0.{id}") }
}
fn mac(id: u8, host: bool) -> String {
    format!("02:00:00:00:{}:{id:02x}", if host { "00" } else { "01" })
}
fn key(id: u8, v6: bool) -> Result<[u8; 20]> {
    Ok(if v6 {
        EndpointKey::v6(address(id, true).parse::<std::net::Ipv6Addr>()?.octets(), 0, 0).to_bytes()
    } else {
        EndpointKey::v4([198, 18, 0, id], 0, 0).to_bytes()
    })
}

struct Endpoint {
    child: Child,
    input: ChildStdin,
    replies: Receiver<String>,
    id: u8,
    ports: [u16; 2],
}
impl Endpoint {
    fn spawn(id: u8) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--endpoint", &id.to_string()])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        let input = child.stdin.take().ok_or("missing child stdin")?;
        let output = child.stdout.take().ok_or("missing child stdout")?;
        let (send, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                match line { Ok(line) if send.send(line).is_ok() => {}, _ => break }
            }
        });
        let endpoint = Self { child, input, replies, id, ports: [0; 2] };
        ensure(endpoint.reply()? == "READY", "endpoint failed to isolate")?;
        Ok(endpoint)
    }
    fn reply(&self) -> Result<String> { Ok(self.replies.recv_timeout(Duration::from_secs(5))?) }
    fn command(&mut self, command: &str) -> Result<String> {
        writeln!(self.input, "{command}")?;
        self.input.flush()?;
        self.reply()
    }
    fn configure(&mut self) -> Result<()> {
        let line = self.command("configure")?;
        let mut parts = line.split_whitespace();
        ensure(parts.next() == Some("PORTS"), "endpoint setup failed")?;
        self.ports = [parts.next().ok_or("missing IPv4 port")?.parse()?, parts.next().ok_or("missing IPv6 port")?.parse()?];
        ensure(parts.next().is_none(), "unexpected endpoint setup response")
    }
    fn socket(&self, v6: bool) -> Result<SocketAddr> {
        let port = self.ports.get(usize::from(v6)).ok_or("missing port")?;
        Ok(if v6 { format!("[{}]:{port}", address(self.id, true)) } else { format!("{}:{port}", address(self.id, false)) }.parse()?)
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        // Killing and reaping removes the anonymous namespace even on failures.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn worker(id: u8) -> Result<()> {
    ensure(matches!(id, 1 | 2), "invalid fixture endpoint")?;
    isolate()?;
    println!("READY"); std::io::stdout().flush()?;
    let mut lines = std::io::stdin().lock().lines();
    ensure(lines.next().transpose()?.as_deref() == Some("configure"), "missing setup request")?;
    ip(&["link", "set", &format!("e{id}"), "name", "eth0"])?;
    ip(&["link", "set", "eth0", "address", &mac(id, false)])?;
    ip(&["link", "set", "eth0", "mtu", "1500", "up"])?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["addr", "add", &format!("{}/32", address(id, false)), "dev", "eth0"])?;
    ip(&["-6", "addr", "add", &format!("{}/128", address(id, true)), "dev", "eth0", "nodad"])?;
    ip(&["route", "add", "198.18.0.0/24", "dev", "eth0"])?;
    ip(&["-6", "route", "add", "2001:db8:1::/64", "dev", "eth0"])?;
    let other = if id == 1 { 2 } else { 1 };
    for v6 in [false, true] {
        ip(&["neigh", "replace", &address(other, v6), "lladdr", &mac(id, true), "nud", "permanent", "dev", "eth0"])?;
    }
    let v4 = UdpSocket::bind(format!("{}:0", address(id, false)))?;
    let v6 = UdpSocket::bind(format!("[{}]:0", address(id, true)))?;
    v4.set_read_timeout(Some(Duration::from_millis(400)))?;
    v6.set_read_timeout(Some(Duration::from_millis(400)))?;
    println!("PORTS {} {}", v4.local_addr()?.port(), v6.local_addr()?.port());
    std::io::stdout().flush()?;
    for line in lines {
        let line = line?;
        let mut parts = line.split_whitespace();
        let command = parts.next().ok_or("empty worker request")?;
        let family = parts.next().ok_or("missing family")?;
        let socket = match family { "4" => &v4, "6" => &v6, _ => return Err("bad family".into()) };
        match command {
            "send" => {
                let to: SocketAddr = parts.next().ok_or("missing destination")?.parse()?;
                let payload = parts.next().ok_or("missing payload")?;
                ensure(socket.send_to(payload.as_bytes(), to)? == payload.len(), "short datagram send")?;
                println!("SENT");
            }
            "recv" => {
                let mut bytes = [0_u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((size, _)) => println!("DATA {}", std::str::from_utf8(bytes.get(..size).ok_or("receive overflow")?)?),
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => println!("TIMEOUT"),
                    Err(e) => return Err(e.into()),
                }
            }
            _ => return Err("unknown worker request".into()),
        }
        ensure(parts.next().is_none(), "extra worker arguments")?;
        std::io::stdout().flush()?;
    }
    Ok(())
}

fn exchange(from: &mut Endpoint, to: &mut Endpoint, v6: bool, payload: &str, allowed: bool) -> Result<()> {
    let family = if v6 { 6 } else { 4 };
    ensure(from.command(&format!("send {family} {} {payload}", to.socket(v6)?))? == "SENT", "send failed")?;
    let received = to.command(&format!("recv {family}"))?;
    ensure(received == if allowed { format!("DATA {payload}") } else { "TIMEOUT".into() }, &format!("IPv{family} delivery expectation failed: {received}"))
}

fn run(object: &str) -> Result<()> {
    isolate()?;
    let mut first = Endpoint::spawn(1)?;
    let mut second = Endpoint::spawn(2)?;
    let mut entries = Vec::new();
    for ep in [&mut first, &mut second] {
        let host = format!("p{}", ep.id);
        let peer = format!("e{}", ep.id);
        ip(&["link", "add", &host, "type", "veth", "peer", "name", &peer])?;
        ip(&["link", "set", &host, "address", &mac(ep.id, true), "mtu", "1500", "up"])?;
        ip(&["link", "set", &peer, "netns", &ep.child.id().to_string()])?;
        ep.configure()?;
        // ip -o reports the kernel ifindex before the colon; use netlink output,
        // not a sysfs mount that may reflect a different network namespace.
        let output = Command::new("ip").args(["-o", "link", "show", "dev", &host]).output()?;
        ensure(output.status.success(), "cannot inspect endpoint interface")?;
        let text = std::str::from_utf8(&output.stdout)?;
        let ifindex: u32 = text.split(':').next().ok_or("missing ifindex")?.parse()?;
        let info = EndpointInfo { ifindex, lxc_id: u16::from(ep.id),
            mac: u64::from_le_bytes([2, 0, 0, 0, 1, ep.id, 0, 0]),
            node_mac: u64::from_le_bytes([2, 0, 0, 0, 0, ep.id, 0, 0]),
            ..Default::default() }.to_bytes();
        entries.push((key(ep.id, false)?, info));
        entries.push((key(ep.id, true)?, info));
    }
    let mut bpf = Ebpf::load_file(object)?;
    let mut endpoints: Endpoints = HashMap::try_from(bpf.take_map("cilium_lxc").ok_or("missing endpoint map")?)?;
    for (key, value) in &entries { endpoints.insert(*key, *value, 0)?; }
    let program: &mut SchedClassifier = bpf.program_mut("local_delivery").ok_or("missing local delivery program")?.try_into()?;
    program.load()?;
    for host in ["p1", "p2"] { program.attach(host, TcAttachType::Ingress)?; }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, "forward", true)?;
        exchange(&mut second, &mut first, v6, "reverse", true)?;
        endpoints.remove(&key(2, v6)?)?;
        exchange(&mut first, &mut second, v6, "removed", false)?;
        let (key, value) = entries.iter().find(|(k, _)| Some(*k) == key(2, v6).ok()).ok_or("missing fixture entry")?;
        endpoints.insert(*key, *value, 0)?;
        exchange(&mut first, &mut second, v6, "restored", true)?;
    }
    println!("PASS: bidirectional IPv4/IPv6 between endpoints, deletion blocks and reinsertion restores traffic");
    drop(bpf);
    for host in ["p1", "p2"] {
        ensure(SchedClassifier::query_tcx(host, TcAttachType::Ingress)?.1.is_empty(), "attachment leaked")?;
    }
    for v6 in [false, true] { exchange(&mut first, &mut second, v6, "detached", false)?; }
    // Recreate the program owner and map, proving the restore path rather than
    // accidentally depending on a still-attached old program.
    let mut restored = Ebpf::load_file(object)?;
    let mut restored_map: Endpoints = HashMap::try_from(restored.take_map("cilium_lxc").ok_or("missing restored map")?)?;
    for (key, value) in &entries { restored_map.insert(*key, *value, 0)?; }
    let program: &mut SchedClassifier = restored.program_mut("local_delivery").ok_or("missing restored program")?.try_into()?;
    program.load()?;
    for host in ["p1", "p2"] { program.attach(host, TcAttachType::Ingress)?; }
    for v6 in [false, true] { exchange(&mut first, &mut second, v6, "reloaded", true)?; }
    drop(restored);
    drop(restored_map);
    drop(endpoints);
    for host in ["p1", "p2"] { ip(&["link", "del", host])?; }
    println!("PASS: detach blocks forwarding, fresh object/map reload restores it, endpoint links deleted");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, id] if mode == "--endpoint" => worker(id.parse()?),
        [object] => run(object),
        _ => Err("usage: flowsdn-endpoint-test PATH_TO_LOCAL_DELIVERY_OBJECT".into()),
    }
}
