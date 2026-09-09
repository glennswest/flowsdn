//! Privileged dual-stack endpoint delivery test in three anonymous namespaces.
use aya::programs::{SchedClassifier, TcAttachType};
use flowsdn_bpf_loader::kernel::LocalDelivery;
use nix::sched::{CloneFlags, unshare};

#[path = "endpoint/packets.rs"]
mod packets;
#[path = "endpoint/cni.rs"]
mod cni;
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
fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").args(args).output()?;
    ensure(
        output.status.success(),
        &format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}
fn isolate() -> Result<()> {
    let previous = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        std::fs::read_link("/proc/self/ns/net")? != previous,
        "namespace isolation failed",
    )
}
fn address(id: u8, v6: bool) -> String {
    if v6 {
        format!("2001:db8:1::{id}")
    } else {
        format!("198.18.0.{id}")
    }
}
fn mac(id: u8, host: bool) -> String {
    format!("02:00:00:00:{}:{id:02x}", if host { "00" } else { "01" })
}
fn key(id: u8, v6: bool) -> Result<std::net::IpAddr> {
    Ok(address(id, v6).parse()?)
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child.stdin.take().ok_or("missing child stdin")?;
        let output = child.stdout.take().ok_or("missing child stdout")?;
        let (send, replies) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                match line {
                    Ok(line) => {
                        if send.send(line).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
        let endpoint = Self {
            child,
            input,
            replies,
            id,
            ports: [0; 2],
        };
        ensure(endpoint.reply()? == "READY", "endpoint failed to isolate")?;
        Ok(endpoint)
    }
    fn reply(&self) -> Result<String> {
        Ok(self.replies.recv_timeout(Duration::from_secs(5))?)
    }
    fn command(&mut self, command: &str) -> Result<String> {
        writeln!(self.input, "{command}")?;
        self.input.flush()?;
        self.reply()
    }
    fn configure(&mut self) -> Result<()> {
        let line = self.command("configure")?;
        let mut parts = line.split_whitespace();
        ensure(parts.next() == Some("PORTS"), "endpoint setup failed")?;
        self.ports = [
            parts.next().ok_or("missing IPv4 port")?.parse()?,
            parts.next().ok_or("missing IPv6 port")?.parse()?,
        ];
        ensure(parts.next().is_none(), "unexpected endpoint setup response")
    }
    fn socket(&self, v6: bool) -> Result<SocketAddr> {
        let port = self.ports.get(usize::from(v6)).ok_or("missing port")?;
        Ok(if v6 {
            format!("[{}]:{port}", address(self.id, true))
        } else {
            format!("{}:{port}", address(self.id, false))
        }
        .parse()?)
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
    ensure((1..=3).contains(&id), "invalid fixture endpoint")?;
    isolate()?;
    println!("READY");
    std::io::stdout().flush()?;
    let mut lines = std::io::stdin().lock().lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("configure"),
        "missing setup request",
    )?;
    ip(&["link", "set", &format!("e{id}"), "name", "eth0"])?;
    ip(&["link", "set", "eth0", "address", &mac(id, false)])?;
    ip(&["link", "set", "eth0", "mtu", "1500", "up"])?;
    ip(&["link", "set", "lo", "up"])?;
    for v6 in [true, false] {
        let family = if v6 { "-6" } else { "-4" };
        let prefix = if v6 { 128 } else { 32 };
        let local = format!("{}/{prefix}", address(id, v6));
        if v6 { ip(&["-6", "addr", "add", &local, "dev", "eth0", "nodad"])?; }
        else { ip(&["addr", "add", &local, "dev", "eth0"])?; }
        let gateway = cni::gateway(v6);
        ip(&[family,"route","add", &format!("{gateway}/{prefix}"), "dev", "eth0"])?;
        ip(&[family,"route","add","default","via",gateway,"dev","eth0","mtu","1450"])?;
        ip(&["neigh","replace",gateway,"lladdr",&mac(id,true),"nud","permanent","dev","eth0"])?;
    }
    let v4 = UdpSocket::bind(format!("{}:0", address(id, false)))?;
    let v6 = UdpSocket::bind(format!("[{}]:0", address(id, true)))?;
    v4.set_read_timeout(Some(Duration::from_millis(400)))?;
    v6.set_read_timeout(Some(Duration::from_millis(400)))?;
    println!(
        "PORTS {} {}",
        v4.local_addr()?.port(),
        v6.local_addr()?.port()
    );
    std::io::stdout().flush()?;
    for line in lines {
        let line = line?;
        let mut parts = line.split_whitespace();
        let command = parts.next().ok_or("empty worker request")?;
        let family = parts.next().ok_or("missing family")?;
        let socket = match family {
            "4" => &v4,
            "6" => &v6,
            _ => return Err("bad family".into()),
        };
        match command {
            "send" => {
                let to: SocketAddr = parts.next().ok_or("missing destination")?.parse()?;
                let payload = parts.next().ok_or("missing payload")?;
                ensure(
                    socket.send_to(payload.as_bytes(), to)? == payload.len(),
                    "short datagram send",
                )?;
                println!("SENT");
            }
            "recv" => {
                let mut bytes = [0_u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((size, _)) => println!(
                        "DATA {}",
                        std::str::from_utf8(bytes.get(..size).ok_or("receive overflow")?)?
                    ),
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                        println!("TIMEOUT")
                    }
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

fn exchange(
    from: &mut Endpoint,
    to: &mut Endpoint,
    v6: bool,
    payload: &str,
    allowed: bool,
) -> Result<()> {
    let family = if v6 { 6 } else { 4 };
    ensure(
        from.command(&format!("send {family} {} {payload}", to.socket(v6)?))? == "SENT",
        "send failed",
    )?;
    let received = to.command(&format!("recv {family}"))?;
    ensure(
        received
            == if allowed {
                format!("DATA {payload}")
            } else {
                "TIMEOUT".into()
            },
        &format!("IPv{family} delivery expectation failed: {received}"),
    )
}

fn run(object: &str) -> Result<()> {
    isolate()?;
    let mut first = Endpoint::spawn(1)?;
    let mut second = Endpoint::spawn(2)?;
    let v4 = flowsdn_ipam::HostScope::new("198.18.0.0".parse()?,24,Default::default())?;
    let v6 = flowsdn_ipam::HostScope::new("2001:db8:1::".parse()?,64,Default::default())?;
    let mut ipam = flowsdn_ipam::Ipam::new(Some(v4),Some(v6))?;
    for v6 in [false,true] { ipam.exclude_ip(cni::gateway(v6).parse()?,"router")?; }
    let mut driver = LocalDelivery::load(object)?;
    let mut entries = Vec::new();
    for ep in [&mut first, &mut second] {
        let info = {
            let mut backend = cni::Backend {process:ep,driver:&mut driver,ipam:&mut ipam,fail_finalize:false,info:None};
            let request = backend.request();
            let result = flowsdn_cni::add(&request,1450,&mut backend).map_err(|e|e.primary)?;
            ensure(result.get("ips").and_then(|v|v.as_array()).is_some_and(|v|v.len()==2),"CNI result missing dual-stack addresses")?;
            backend.info.ok_or("missing endpoint info")?
        };
        entries.push((key(ep.id, false)?, info));
        entries.push((key(ep.id, true)?, info));
    }
    // An ADD that fails after programming BPF must remove its endpoint, link
    // and addresses without disturbing the two established endpoints.
    {
        let mut third = Endpoint::spawn(3)?;
        let mut backend = cni::Backend {process:&mut third,driver:&mut driver,ipam:&mut ipam,fail_finalize:true,info:None};
        let request = backend.request();
        let error = flowsdn_cni::add(&request,1450,&mut backend).expect_err("injected post-create failure");
        ensure(error.primary.message=="injected post-create failure" && error.rollback_errors.is_empty(),"live CNI rollback failed")?;
    }
    ensure(!Command::new("ip").args(["link","show","dev","p3"]).output()?.status.success(),"rollback leaked endpoint interface")?;
    ensure(ipam.ipv4().ok_or("missing v4 pool")?.allocated()==2 && ipam.ipv6().ok_or("missing v6 pool")?.allocated()==2,"rollback leaked allocations")?;
    // A new process can reuse the same CNI attachment and address after rollback.
    {
        use flowsdn_cni::AddBackend;
        let mut third = Endpoint::spawn(3)?;
        let mut backend = cni::Backend {process:&mut third,driver:&mut driver,ipam:&mut ipam,fail_finalize:false,info:None};
        let request = backend.request();
        flowsdn_cni::add(&request,1450,&mut backend).map_err(|e|e.primary)?;
        backend.delete_endpoint(&request)?;
        backend.delete_link(&flowsdn_cni::Link {host_name:"p3".into(),host_index:backend.info.ok_or("missing third endpoint")?.ifindex,host_mac:mac(3,true),peer_mac:mac(3,false)})?;
        for v6 in [false,true] { backend.ipam.release(key(3,v6)?)?; }
    }
    packets::verify(driver.program()?)?;
    println!("PASS: CNI ADD configures real endpoints; post-create rollback frees BPF, veth and IPAM state; retry succeeds");
    ensure(
        driver.attach("p1").is_err(),
        "duplicate attachment accepted",
    )?;
    ensure(
        SchedClassifier::query_tcx("p1", TcAttachType::Ingress)?
            .1
            .len()
            == 1,
        "duplicate attempt changed attachment count",
    )?;
    let mut invalid = entries.first().ok_or("missing fixture")?.1;
    invalid.ifindex = 0;
    ensure(
        driver.upsert(key(1, false)?, invalid).is_err(),
        "invalid endpoint replaced valid route",
    )?;
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, "forward", true)?;
        exchange(&mut second, &mut first, v6, "reverse", true)?;
        driver.remove(key(2, v6)?)?;
        exchange(&mut first, &mut second, v6, "removed", false)?;
        let (key, value) = entries
            .iter()
            .find(|(k, _)| Some(*k) == key(2, v6).ok())
            .ok_or("missing fixture entry")?;
        driver.upsert(*key, *value)?;
        exchange(&mut first, &mut second, v6, "restored", true)?;
    }
    println!(
        "PASS: bidirectional IPv4/IPv6 between endpoints, deletion blocks and reinsertion restores traffic"
    );
    drop(driver);
    for host in ["p1", "p2"] {
        ensure(
            SchedClassifier::query_tcx(host, TcAttachType::Ingress)?
                .1
                .is_empty(),
            "attachment leaked",
        )?;
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, "detached", false)?;
    }
    // Recreate the program owner and map, proving the restore path rather than
    // accidentally depending on a still-attached old program.
    let mut restored = LocalDelivery::load(object)?;
    for (key, value) in &entries {
        restored.upsert(*key, *value)?;
    }
    for host in ["p1", "p2"] {
        restored.attach(host)?;
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, "reloaded", true)?;
    }
    drop(restored);
    for host in ["p1", "p2"] { ip(&["link", "del", host])?; }
    for id in [1,2] { for v6 in [false,true] {ipam.release(key(id,v6)?)?;} }
    ensure(ipam.ipv4().ok_or("v4 pool")?.allocated()==0 && ipam.ipv6().ok_or("v6 pool")?.allocated()==0,"final IPAM cleanup failed")?;
    println!(
        "PASS: detach blocks forwarding, fresh object/map reload restores it, endpoint links deleted"
    );
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
