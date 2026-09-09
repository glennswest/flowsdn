//! Privileged native dual-stack forwarding fixture in anonymous namespaces.
//! Requires iproute2 and nft; no Kubernetes or discovery controller is involved.
use flowsdn_bpf_abi::endpoint::EndpointInfo;
use flowsdn_bpf_loader::kernel::LocalDelivery;
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{BufRead, BufReader, ErrorKind, Write},
    net::{SocketAddr, UdpSocket},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}

fn ip(args: &[&str]) -> Result<String> {
    let output = Command::new("ip").args(args).output()?;
    ensure(
        output.status.success(),
        &format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    Ok(String::from_utf8(output.stdout)?)
}

fn isolate() -> Result<()> {
    let before = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        std::fs::read_link("/proc/self/ns/net")? != before,
        "namespace isolation failed",
    )
}

fn address(id: u8, v6: bool, host: bool) -> String {
    let last = if host { 1 } else { 2 };
    if v6 {
        format!("2001:db8:{id}::{last}")
    } else {
        format!("198.18.{id}.{last}")
    }
}

fn underlay(id: u8, v6: bool) -> String {
    if v6 {
        format!("2001:db8:ff::{id}")
    } else {
        format!("192.0.2.{id}")
    }
}

fn mac(id: u8, kind: u8) -> String {
    format!("02:00:00:00:{kind:02x}:{id:02x}")
}

fn mac_value(id: u8, kind: u8) -> u64 {
    u64::from_le_bytes([2, 0, 0, 0, kind, id, 0, 0])
}

fn peer(id: u8) -> u8 {
    if id == 1 { 2 } else { 1 }
}

fn host_prefix(v6: bool) -> u8 {
    if v6 { 128 } else { 32 }
}

fn family(v6: bool) -> &'static str {
    if v6 { "-6" } else { "-4" }
}

/// Every worker is a direct child of the coordinator, so failure cleanup never
/// depends on a killed router running destructors for grandchild endpoints.
struct Worker {
    child: Child,
    input: ChildStdin,
    replies: Receiver<String>,
}

impl Worker {
    fn spawn(mode: &str, id: u8, object: &str) -> Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([mode, &id.to_string(), object])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().ok_or("missing worker stdin")?;
        let output = child.stdout.take().ok_or("missing worker stdout")?;
        let (send, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                match line {
                    Ok(line) => {
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        let worker = Self {
            child,
            input,
            replies,
        };
        ensure(worker.reply()? == "READY", "worker failed to isolate")?;
        Ok(worker)
    }

    fn reply(&self) -> Result<String> {
        Ok(self.replies.recv_timeout(Duration::from_secs(10))?)
    }

    fn command(&mut self, line: &str) -> Result<String> {
        writeln!(self.input, "{line}")?;
        self.input.flush()?;
        self.reply()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn say(line: &str) -> Result<()> {
    println!("{line}");
    Ok(std::io::stdout().flush()?)
}

fn link_pair(a: &str, a_pid: u32, b: &str, b_pid: u32) -> Result<()> {
    ip(&["link", "add", a, "type", "veth", "peer", "name", b])?;
    ip(&["link", "set", a, "netns", &a_pid.to_string()])?;
    ip(&["link", "set", b, "netns", &b_pid.to_string()])?;
    Ok(())
}

fn configure_link(name: &str, id: u8, kind: u8) -> Result<()> {
    ip(&[
        "link",
        "set",
        name,
        "address",
        &mac(id, kind),
        "mtu",
        "1500",
        "up",
    ])?;
    Ok(())
}

fn add_address(name: &str, address: &str, prefix: u8, v6: bool) -> Result<()> {
    let cidr = format!("{address}/{prefix}");
    if v6 {
        ip(&["-6", "addr", "add", &cidr, "dev", name, "nodad"])?;
    } else {
        ip(&["-4", "addr", "add", &cidr, "dev", name])?;
    }
    Ok(())
}

fn neighbour(name: &str, address: &str, id: u8, kind: u8) -> Result<()> {
    ip(&[
        "neigh",
        "replace",
        address,
        "lladdr",
        &mac(id, kind),
        "nud",
        "permanent",
        "dev",
        name,
    ])?;
    Ok(())
}

fn remote_route(action: &str, id: u8, v6: bool) -> Result<()> {
    ip(&[
        family(v6),
        "route",
        action,
        &format!("{}/{}", address(peer(id), v6, false), host_prefix(v6)),
        "via",
        &underlay(peer(id), v6),
        "dev",
        "u",
    ])?;
    Ok(())
}

fn load_driver(object: &str, id: u8) -> Result<LocalDelivery> {
    let link = ip(&["-o", "link", "show", "dev", "p"])?;
    let ifindex = link
        .split(':')
        .next()
        .ok_or("missing ifindex")?
        .trim()
        .parse()?;
    let mut driver = LocalDelivery::load(object)?;
    let endpoint = EndpointInfo {
        ifindex,
        mac: mac_value(id, 0x30),
        node_mac: mac_value(id, 0x20),
        ..EndpointInfo::default()
    };
    // Deliberately insert only this router's own endpoint. The remote address
    // must miss this map and take the FIB path over the underlay interface.
    for v6 in [false, true] {
        driver.upsert(address(id, v6, false).parse()?, endpoint)?;
    }
    driver.attach("p")?;
    driver.attach("u")?;
    Ok(driver)
}

fn router(id: u8, object: &str) -> Result<()> {
    isolate()?;
    say("READY")?;
    let mut lines = std::io::stdin().lock().lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("configure"),
        "missing router setup",
    )?;
    ip(&["link", "set", &format!("u{id}"), "name", "u"])?;
    ip(&["link", "set", &format!("p{id}"), "name", "p"])?;
    configure_link("u", id, 0x10)?;
    configure_link("p", id, 0x20)?;
    ip(&["link", "set", "lo", "up"])?;
    // These sysctls are namespace-local and are written only after isolate().
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")?;
    std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0\n")?;
    std::fs::write("/proc/sys/net/ipv4/conf/p/rp_filter", "0\n")?;
    std::fs::write("/proc/sys/net/ipv4/conf/u/rp_filter", "0\n")?;
    // A hard prerequisite, not an optional check: kernel stack forwarding is
    // forbidden for both families. Successful datagrams therefore require BPF.
    let output = Command::new("nft").args([
        "add table inet flowsdn_fixture; add chain inet flowsdn_fixture forward { type filter hook forward priority 0; policy drop; }",
    ]).output()?;
    ensure(
        output.status.success(),
        &format!(
            "nft forward isolation: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    )?;
    for v6 in [false, true] {
        add_address("u", &underlay(id, v6), if v6 { 64 } else { 24 }, v6)?;
        add_address("p", &address(id, v6, true), host_prefix(v6), v6)?;
        neighbour("u", &underlay(peer(id), v6), peer(id), 0x10)?;
        neighbour("p", &address(id, v6, false), id, 0x30)?;
        ip(&[
            family(v6),
            "route",
            "add",
            &format!("{}/{}", address(id, v6, false), host_prefix(v6)),
            "dev",
            "p",
        ])?;
        remote_route("add", id, v6)?;
    }
    let mut driver = Some(load_driver(object, id)?);
    say("CONFIGURED")?;
    for line in lines {
        match line?.as_str() {
            "remove4" => remote_route("del", id, false)?,
            "remove6" => remote_route("del", id, true)?,
            "restore4" => remote_route("add", id, false)?,
            "restore6" => remote_route("add", id, true)?,
            "detach" => {
                drop(driver.take().ok_or("already detached")?);
            }
            "reload" => {
                ensure(driver.is_none(), "already attached")?;
                driver = Some(load_driver(object, id)?);
            }
            _ => return Err("unknown router command".into()),
        }
        say("OK")?;
    }
    Ok(())
}

fn endpoint(id: u8) -> Result<()> {
    isolate()?;
    say("READY")?;
    let mut lines = std::io::stdin().lock().lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("configure"),
        "missing endpoint setup",
    )?;
    ip(&["link", "set", &format!("e{id}"), "name", "eth0"])?;
    configure_link("eth0", id, 0x30)?;
    ip(&["link", "set", "lo", "up"])?;
    for v6 in [false, true] {
        add_address("eth0", &address(id, v6, false), host_prefix(v6), v6)?;
        ip(&[
            family(v6),
            "route",
            "add",
            &format!("{}/{}", address(id, v6, true), host_prefix(v6)),
            "dev",
            "eth0",
        ])?;
        ip(&[
            family(v6),
            "route",
            "add",
            "default",
            "via",
            &address(id, v6, true),
            "dev",
            "eth0",
        ])?;
        neighbour("eth0", &address(id, v6, true), id, 0x20)?;
    }
    let v4 = UdpSocket::bind(format!("{}:0", address(id, false, false)))?;
    let v6 = UdpSocket::bind(format!("[{}]:0", address(id, true, false)))?;
    v4.set_read_timeout(Some(Duration::from_millis(500)))?;
    v6.set_read_timeout(Some(Duration::from_millis(500)))?;
    say(&format!(
        "PORTS {} {}",
        v4.local_addr()?.port(),
        v6.local_addr()?.port()
    ))?;
    for line in lines {
        let line = line?;
        let mut args = line.split_whitespace();
        let command = args.next().ok_or("missing command")?;
        let socket = match args.next() {
            Some("4") => &v4,
            Some("6") => &v6,
            _ => return Err("bad family".into()),
        };
        match command {
            "send" => {
                let to: SocketAddr = args.next().ok_or("missing destination")?.parse()?;
                let payload = args.next().ok_or("missing payload")?;
                ensure(
                    socket.send_to(payload.as_bytes(), to)? == payload.len(),
                    "short UDP send",
                )?;
                say("SENT")?;
            }
            "recv" => {
                let mut bytes = [0u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((len, _)) => say(&format!(
                        "DATA {}",
                        std::str::from_utf8(bytes.get(..len).ok_or("receive overflow")?)?
                    ))?,
                    Err(error)
                        if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                    {
                        say("TIMEOUT")?
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            _ => return Err("unknown endpoint command".into()),
        }
        ensure(args.next().is_none(), "extra endpoint arguments")?;
    }
    Ok(())
}

fn ports(worker: &mut Worker) -> Result<[u16; 2]> {
    let response = worker.command("configure")?;
    let mut args = response.split_whitespace();
    ensure(args.next() == Some("PORTS"), "bad endpoint response")?;
    let ports = [
        args.next().ok_or("missing v4 port")?.parse()?,
        args.next().ok_or("missing v6 port")?.parse()?,
    ];
    ensure(args.next().is_none(), "extra endpoint response")?;
    Ok(ports)
}

fn exchange(
    from: &mut Worker,
    to: &mut Worker,
    destination: SocketAddr,
    payload: &str,
    allowed: bool,
) -> Result<()> {
    let family = if destination.is_ipv6() { 6 } else { 4 };
    ensure(
        from.command(&format!("send {family} {destination} {payload}"))? == "SENT",
        "send failed",
    )?;
    let received = to.command(&format!("recv {family}"))?;
    let expected = if allowed {
        format!("DATA {payload}")
    } else {
        "TIMEOUT".into()
    };
    ensure(
        received == expected,
        &format!("IPv{family} {payload}: expected {expected}, got {received}"),
    )
}

fn socket(id: u8, ports: [u16; 2], v6: bool) -> Result<SocketAddr> {
    let port = *ports.get(usize::from(v6)).ok_or("missing port")?;
    Ok(SocketAddr::new(address(id, v6, false).parse()?, port))
}

fn run(object: &str) -> Result<()> {
    let object = std::fs::canonicalize(object)?;
    let object = object.to_str().ok_or("non-UTF8 object path")?;
    isolate()?;
    let mut r1 = Worker::spawn("--router", 1, object)?;
    let mut r2 = Worker::spawn("--router", 2, object)?;
    let mut e1 = Worker::spawn("--endpoint", 1, object)?;
    let mut e2 = Worker::spawn("--endpoint", 2, object)?;
    link_pair("u1", r1.child.id(), "u2", r2.child.id())?;
    link_pair("p1", r1.child.id(), "e1", e1.child.id())?;
    link_pair("p2", r2.child.id(), "e2", e2.child.id())?;
    ensure(
        r1.command("configure")? == "CONFIGURED",
        "router 1 configuration failed",
    )?;
    ensure(
        r2.command("configure")? == "CONFIGURED",
        "router 2 configuration failed",
    )?;
    let ports1 = ports(&mut e1)?;
    let ports2 = ports(&mut e2)?;
    for v6 in [false, true] {
        let s1 = socket(1, ports1, v6)?;
        let s2 = socket(2, ports2, v6)?;
        exchange(&mut e1, &mut e2, s2, "native-forward", true)?;
        exchange(&mut e2, &mut e1, s1, "native-reverse", true)?;
        let suffix = if v6 { 6 } else { 4 };
        ensure(
            r1.command(&format!("remove{suffix}"))? == "OK",
            "route removal failed",
        )?;
        exchange(&mut e1, &mut e2, s2, "route-removed", false)?;
        ensure(
            r1.command(&format!("restore{suffix}"))? == "OK",
            "route restoration failed",
        )?;
        exchange(&mut e1, &mut e2, s2, "route-restored", true)?;
    }
    println!(
        "PASS: bidirectional IPv4/IPv6 across two BPF hops with kernel FORWARD blocked; route removal drops and restoration recovers"
    );
    // With intact routes, detach must still fail under the mandatory nft drop
    // policy. This distinguishes BPF forwarding from an unnoticed stack path.
    ensure(r1.command("detach")? == "OK", "detach failed")?;
    for v6 in [false, true] {
        exchange(&mut e1, &mut e2, socket(2, ports2, v6)?, "detached", false)?;
        exchange(
            &mut e2,
            &mut e1,
            socket(1, ports1, v6)?,
            "reverse-detached",
            false,
        )?;
    }
    ensure(r1.command("reload")? == "OK", "reload failed")?;
    for v6 in [false, true] {
        exchange(&mut e1, &mut e2, socket(2, ports2, v6)?, "reloaded", true)?;
        exchange(
            &mut e2,
            &mut e1,
            socket(1, ports1, v6)?,
            "reverse-reloaded",
            true,
        )?;
    }
    println!(
        "PASS: detached BPF cannot fall back to kernel forwarding; fresh object/map reload restores both directions"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, id, object] if mode == "--router" => {
            let id = id.parse()?;
            ensure((1..=2).contains(&id), "invalid router id")?;
            router(id, object)
        }
        [mode, id, _] if mode == "--endpoint" => {
            let id = id.parse()?;
            ensure((1..=2).contains(&id), "invalid endpoint id")?;
            endpoint(id)
        }
        [object] => run(object),
        _ => Err("usage: native-routing PATH_TO_LOCAL_DELIVERY_OBJECT".into()),
    }
}
