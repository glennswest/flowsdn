//! Standalone agent/CNI process restart and offline deletion integration.
use flowsdn_api_client::Client;
use nix::sched::{CloneFlags, unshare};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn isolate() -> Result<()> {
    let original = fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        fs::read_link("/proc/self/ns/net")? != original,
        "network isolation failed",
    )
}
struct Temp(PathBuf);
impl Temp {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "flowsdn-agent-runtime-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Endpoint {
    process: Process,
    input: ChildStdin,
    replies: Receiver<String>,
    addresses: Vec<SocketAddr>,
    id: u8,
}
impl Endpoint {
    fn new(id: u8) -> Result<Self> {
        let mut process = Process(
            Command::new(std::env::current_exe()?)
                .arg("--endpoint")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let input = process.0.stdin.take().ok_or("worker input")?;
        let output = process.0.stdout.take().ok_or("worker output")?;
        let (send, replies) = mpsc::channel();
        thread::spawn(move || {
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
        let endpoint = Self {
            process,
            input,
            replies,
            addresses: Vec::new(),
            id,
        };
        ensure(
            endpoint.replies.recv_timeout(Duration::from_secs(5))? == "READY",
            "worker not ready",
        )?;
        Ok(endpoint)
    }
    fn namespace(&self) -> String {
        format!("/proc/{}/ns/net", self.process.0.id())
    }
    fn command(&mut self, command: &str) -> Result<String> {
        writeln!(self.input, "{command}")?;
        self.input.flush()?;
        Ok(self.replies.recv_timeout(Duration::from_secs(5))?)
    }
    fn configure(&mut self, result: &Value) -> Result<()> {
        let ips = result
            .get("ips")
            .and_then(Value::as_array)
            .ok_or("CNI addresses")?;
        let mut addresses = Vec::new();
        for ip in ips {
            addresses.push(
                ip.get("address")
                    .and_then(Value::as_str)
                    .ok_or("CNI address")?
                    .split('/')
                    .next()
                    .ok_or("IP")?
                    .parse::<IpAddr>()?,
            );
        }
        let v4 = addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or("IPv4 missing")?;
        let v6 = addresses
            .iter()
            .find(|ip| ip.is_ipv6())
            .ok_or("IPv6 missing")?;
        let response = self.command(&format!("configure {v4} {v6}"))?;
        self.addresses = response
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure(self.addresses.len() == 2, "worker socket count")
    }
    fn socket(&self, v6: bool) -> Result<SocketAddr> {
        self.addresses
            .iter()
            .find(|s| s.is_ipv6() == v6)
            .copied()
            .ok_or_else(|| "missing family socket".into())
    }
}
fn say(message: &str) -> Result<()> {
    println!("{message}");
    Ok(std::io::stdout().flush()?)
}
fn worker() -> Result<()> {
    isolate()?;
    say("READY")?;
    let mut lines = std::io::stdin().lock().lines();
    let configure = lines.next().transpose()?.ok_or("missing configure")?;
    let parts: Vec<_> = configure.split_whitespace().collect();
    ensure(
        parts.first() == Some(&"configure") && parts.len() == 3,
        "bad configure",
    )?;
    let v4 = UdpSocket::bind(SocketAddr::new(parts.get(1).ok_or("IPv4")?.parse()?, 0))?;
    let v6 = UdpSocket::bind(SocketAddr::new(parts.get(2).ok_or("IPv6")?.parse()?, 0))?;
    for socket in [&v4, &v6] {
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    }
    say(&format!("{} {}", v4.local_addr()?, v6.local_addr()?))?;
    for line in lines {
        let line = line?;
        let parts: Vec<_> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["send", to, payload] => {
                let to: SocketAddr = to.parse()?;
                let socket = if to.is_ipv6() { &v6 } else { &v4 };
                socket.send_to(payload.as_bytes(), to)?;
                say("SENT")?;
            }
            ["recv", family] => {
                let socket = match *family {
                    "4" => &v4,
                    "6" => &v6,
                    _ => return Err("bad family".into()),
                };
                let mut bytes = [0u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((n, _)) => say(std::str::from_utf8(bytes.get(..n).ok_or("packet size")?)?)?,
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                        say("TIMEOUT")?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ => return Err("unknown worker command".into()),
        }
    }
    Ok(())
}
fn capture(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.by_ref().take(8_388_609).read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}
fn cni(
    binary: &Path,
    temp: &Temp,
    verb: &str,
    endpoint: &Endpoint,
    config: &Value,
) -> Result<Value> {
    let mut process = Process(
        Command::new(binary)
            .env("CNI_COMMAND", verb)
            .env("CNI_CONTAINERID", format!("sandbox{}", endpoint.id))
            .env("CNI_IFNAME", "eth0")
            .env("CNI_NETNS", endpoint.namespace())
            .env("CNI_PATH", binary.parent().ok_or("binary directory")?)
            .env(
                "CNI_ARGS",
                format!("K8S_POD_NAMESPACE=fixture;K8S_POD_NAME=pod{}", endpoint.id),
            )
            .env("CILIUM_SOCK", temp.0.join("agent.sock"))
            .env("FLOWSDN_DELETE_QUEUE", temp.0.join("deleteQueue"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let out = capture(process.0.stdout.take().ok_or("stdout")?);
    let err = capture(process.0.stderr.take().ok_or("stderr")?);
    process
        .0
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(&serde_json::to_vec(config)?)?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = process.0.try_wait()? {
            break status;
        }
        ensure(start.elapsed() < Duration::from_secs(45), "CNI timeout")?;
        thread::sleep(Duration::from_millis(5));
    };
    let output = out.join().map_err(|_| "stdout reader")??;
    let stderr = err.join().map_err(|_| "stderr reader")??;
    ensure(
        status.success(),
        &format!(
            "CNI {verb}: {} {}",
            String::from_utf8_lossy(&output),
            String::from_utf8_lossy(&stderr)
        ),
    )?;
    if output.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&output)?)
    }
}
fn start_agent(binary: &Path, temp: &Temp) -> Result<Process> {
    let mut process = Process(
        Command::new(binary)
            .args(["--config"])
            .arg(temp.0.join("config.json"))
            .stdout(Stdio::null())
            .spawn()?,
    );
    let start = Instant::now();
    loop {
        ensure(
            process.0.try_wait()?.is_none(),
            "agent exited during startup",
        )?;
        if Client::new(temp.0.join("agent.sock"), Duration::from_millis(200))
            .config()
            .is_ok_and(|r| r.status == 200)
        {
            return Ok(process);
        }
        ensure(
            start.elapsed() < Duration::from_secs(15),
            "agent readiness timeout",
        )?;
        thread::sleep(Duration::from_millis(25));
    }
}
fn exchange(from: &mut Endpoint, to: &mut Endpoint, v6: bool, allowed: bool) -> Result<()> {
    let payload = format!("agent-{}-{}-{v6}", from.id, to.id);
    ensure(
        from.command(&format!("send {} {payload}", to.socket(v6)?))? == "SENT",
        "send",
    )?;
    let actual = to.command(if v6 { "recv 6" } else { "recv 4" })?;
    ensure(
        actual == if allowed { payload } else { "TIMEOUT".into() },
        "agent restart connectivity mismatch",
    )
}
fn run(cni_binary: &Path, agent_binary: &Path, object: &Path) -> Result<()> {
    let cni_binary = fs::canonicalize(cni_binary)?;
    let agent_binary = fs::canonicalize(agent_binary)?;
    let object = fs::canonicalize(object)?;
    isolate()?;
    let temp = Temp::new()?;
    fs::write(
        temp.0.join("config.json"),
        serde_json::to_vec(
            &json!({"socket-path":temp.0.join("agent.sock"),"state-dir":temp.0.join("state"),"bpf-object":object,
        "ipv4-pool":"198.18.0.0/24","ipv6-pool":"2001:db8:1::/64","ipv4-gateway":"198.18.0.254","ipv6-gateway":"2001:db8:1::ffff","device-mtu":1500,"route-mtu":1450}),
        )?,
    )?;
    let mut first = Endpoint::new(1)?;
    let mut second = Endpoint::new(2)?;
    let agent = start_agent(&agent_binary, &temp)?;
    let conf = json!({"cniVersion":"1.1.0","name":"flowsdn-test","type":"flowsdn-cni"});
    let mut previous = Vec::new();
    for endpoint in [&mut first, &mut second] {
        let result = cni(&cni_binary, &temp, "ADD", endpoint, &conf)?;
        endpoint.configure(&result)?;
        let mut check = conf.clone();
        check
            .as_object_mut()
            .ok_or("config")?
            .insert("prevResult".into(), result);
        previous.push(check);
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, true)?;
        exchange(&mut second, &mut first, v6, true)?;
    }
    drop(agent);
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, false)?;
    }
    let agent = start_agent(&agent_binary, &temp)?;
    for (endpoint, check) in [&first, &second].into_iter().zip(&previous) {
        cni(&cni_binary, &temp, "CHECK", endpoint, check)?;
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6, true)?;
        exchange(&mut second, &mut first, v6, true)?;
    }
    println!(
        "PASS: standalone agent and CNI create dual-stack endpoints; process restart restores CHECK and bidirectional traffic"
    );
    drop(agent);
    cni(&cni_binary, &temp, "DEL", &first, &conf)?;
    let agent = start_agent(&agent_binary, &temp)?;
    let client = Client::new(temp.0.join("agent.sock"), Duration::from_secs(2));
    ensure(
        client
            .endpoint_health("cni-attachment-id:sandbox1:eth0")?
            .status
            == 404,
        "offline deletion resurrected endpoint",
    )?;
    ensure(
        !fs::read_dir(temp.0.join("deleteQueue"))?
            .any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "delete"))),
        "offline queue not drained",
    )?;
    cni(
        &cni_binary,
        &temp,
        "CHECK",
        &second,
        previous.get(1).ok_or("second previous result")?,
    )?;
    cni(&cni_binary, &temp, "DEL", &second, &conf)?;
    cni(&cni_binary, &temp, "DEL", &second, &conf)?;
    ensure(
        !fs::read_dir(temp.0.join("state"))?
            .any(|e| e.is_ok_and(|e| e.file_name().to_string_lossy().parse::<u16>().is_ok())),
        "endpoint state leaked",
    )?;
    drop(agent);
    println!(
        "PASS: offline CNI deletion survives process restart, does not resurrect stale links, drains durable queue and tears down remaining endpoint"
    );
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "--endpoint" => worker(),
        [cni, agent, object] => run(Path::new(cni), Path::new(agent), Path::new(object)),
        _ => Err("usage: agent-runtime CNI_BINARY AGENT_BINARY BPF_OBJECT".into()),
    }
}
