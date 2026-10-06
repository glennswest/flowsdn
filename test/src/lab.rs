//! The commit's own agent and CNI, run the way a node runs them, in an
//! anonymous network and mount namespace of the test pod: a private bpffs,
//! state directory and socket, and one network namespace per endpoint (a
//! worker process of this binary). Nothing touches the node's links, bpffs or
//! CNI state, so a run is independent of whatever the node itself runs.
use crate::env::Env;
use flowsdn_api_client::{Client, Method};
use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    sched::{CloneFlags, unshare},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitCode, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub type Result<T> = std::result::Result<T, String>;

/// The endpoint BPF map holds 1024 entries, one per address family.
pub const MAX_ENDPOINTS: usize = 500;

fn ensure(ok: bool, message: impl Into<String>) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn text(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Move this process (and every child it starts) into its own network and
/// mount namespaces. Ordinary forwarding is refused there, so traffic between
/// endpoints proves BPF delivery rather than the kernel's routing.
pub fn isolate_process() -> Result<()> {
    let before = fs::read_link("/proc/self/ns/net").map_err(text)?;
    unshare(CloneFlags::CLONE_NEWNET).map_err(|e| format!("unshare(net): {e}"))?;
    ensure(
        fs::read_link("/proc/self/ns/net").map_err(text)? != before,
        "network namespace isolation failed",
    )?;
    run("ip", &["link", "set", "dev", "lo", "up"])?;
    run(
        "nft",
        &[
            "add table inet flowsdn_test; add chain inet flowsdn_test forward { type filter hook forward priority 0; policy drop; }",
        ],
    )?;
    unshare(CloneFlags::CLONE_NEWNS).map_err(|e| format!("unshare(mnt): {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("make / private: {e}"))
}

fn run(tool: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(tool)
        .args(args)
        .status()
        .map_err(|e| format!("{tool}: {e}"))?;
    ensure(status.success(), format!("{tool} {args:?}: {status}"))
}

/// One pod sandbox: a worker in its own network namespace with a UDP socket
/// per family on the addresses CNI ADD gave it.
pub struct Endpoint {
    process: Child,
    input: ChildStdin,
    replies: Receiver<String>,
    sockets: Vec<SocketAddr>,
    pub id: usize,
}

impl Endpoint {
    pub fn new(id: usize) -> Result<Self> {
        let exe = std::env::current_exe().map_err(text)?;
        let mut process = Command::new(exe)
            .arg("--endpoint")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("endpoint worker: {e}"))?;
        let input = process.stdin.take().ok_or("worker stdin")?;
        let output = process.stdout.take().ok_or("worker stdout")?;
        let (send, replies) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output)
                .lines()
                .map_while(std::result::Result::ok)
            {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let mut endpoint = Self {
            process,
            input,
            replies,
            sockets: Vec::new(),
            id,
        };
        let ready = endpoint.reply(Duration::from_secs(10))?;
        ensure(ready == "READY", format!("endpoint worker said {ready:?}"))?;
        Ok(endpoint)
    }
    fn reply(&mut self, wait: Duration) -> Result<String> {
        self.replies
            .recv_timeout(wait)
            .map_err(|_| format!("endpoint {} worker did not answer", self.id))
    }
    fn command(&mut self, command: &str) -> Result<String> {
        writeln!(self.input, "{command}").map_err(text)?;
        self.input.flush().map_err(text)?;
        self.reply(Duration::from_secs(5))
    }
    pub fn namespace(&self) -> String {
        format!("/proc/{}/ns/net", self.process.id())
    }
    /// Bind the worker's sockets to the addresses of a CNI ADD result.
    pub fn configure(&mut self, result: &Value) -> Result<()> {
        let mut addresses = Vec::new();
        for ip in result
            .get("ips")
            .and_then(Value::as_array)
            .ok_or("CNI result has no ips")?
        {
            let cidr = ip
                .get("address")
                .and_then(Value::as_str)
                .ok_or("CNI ip has no address")?;
            let address = cidr.split('/').next().unwrap_or_default();
            addresses.push(
                address
                    .parse::<IpAddr>()
                    .map_err(|e| format!("{cidr}: {e}"))?,
            );
        }
        let v4 = addresses
            .iter()
            .find(|a| a.is_ipv4())
            .ok_or("CNI result has no IPv4")?;
        let v6 = addresses
            .iter()
            .find(|a| a.is_ipv6())
            .ok_or("CNI result has no IPv6")?;
        let bound = self.command(&format!("configure {v4} {v6}"))?;
        self.sockets = bound
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| format!("worker sockets {bound:?}: {e}"))?;
        ensure(self.sockets.len() == 2, format!("worker sockets {bound:?}"))
    }
    fn socket(&self, v6: bool) -> Result<SocketAddr> {
        self.sockets
            .iter()
            .find(|s| s.is_ipv6() == v6)
            .copied()
            .ok_or_else(|| format!("endpoint {} has no {} socket", self.id, family(v6)))
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

pub fn family(v6: bool) -> &'static str {
    if v6 { "IPv6" } else { "IPv4" }
}

/// One datagram from `from` to `to`, which must arrive.
pub fn exchange(from: &mut Endpoint, to: &mut Endpoint, v6: bool) -> Result<()> {
    let payload = format!("flowsdn-{}-{}-{}", from.id, to.id, family(v6));
    let sent = from.command(&format!("send {} {payload}", to.socket(v6)?))?;
    ensure(sent == "SENT", format!("send: {sent}"))?;
    let got = to.command(if v6 { "recv 6" } else { "recv 4" })?;
    ensure(
        got == payload,
        format!(
            "{} endpoint {} -> {}: expected {payload:?}, got {got:?}",
            family(v6),
            from.id,
            to.id
        ),
    )
}

/// `/test --endpoint`: the sandbox side of an [`Endpoint`].
pub fn endpoint_worker() -> ExitCode {
    match worker() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("endpoint worker: {e}");
            ExitCode::FAILURE
        }
    }
}

fn say(line: &str) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").map_err(text)?;
    out.flush().map_err(text)
}

fn worker() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNET).map_err(|e| format!("unshare(net): {e}"))?;
    say("READY")?;
    let mut lines = std::io::stdin().lock().lines();
    let configure = lines.next().ok_or("no configure line")?.map_err(text)?;
    let parts: Vec<&str> = configure.split_whitespace().collect();
    let [verb, v4, v6] = parts.as_slice() else {
        return Err(format!("bad configure line {configure:?}"));
    };
    ensure(*verb == "configure", "expected configure")?;
    let bind = |ip: &str| -> Result<UdpSocket> {
        let ip: IpAddr = ip.parse().map_err(|e| format!("{ip}: {e}"))?;
        let socket =
            UdpSocket::bind(SocketAddr::new(ip, 0)).map_err(|e| format!("bind {ip}: {e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(text)?;
        Ok(socket)
    };
    let (v4, v6) = (bind(v4)?, bind(v6)?);
    say(&format!(
        "{} {}",
        v4.local_addr().map_err(text)?,
        v6.local_addr().map_err(text)?
    ))?;
    for line in lines {
        let line = line.map_err(text)?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.as_slice() {
            ["send", to, payload] => {
                let to: SocketAddr = to.parse().map_err(|e| format!("{to}: {e}"))?;
                let socket = if to.is_ipv6() { &v6 } else { &v4 };
                match socket.send_to(payload.as_bytes(), to) {
                    Ok(_) => say("SENT")?,
                    Err(e) => say(&format!("ERROR {e}"))?,
                }
            }
            ["recv", which] => {
                let socket = if *which == "6" { &v6 } else { &v4 };
                let mut bytes = [0u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((n, _)) => {
                        say(&String::from_utf8_lossy(bytes.get(..n).unwrap_or_default()))?
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                        say("TIMEOUT")?
                    }
                    Err(e) => say(&format!("ERROR {e}"))?,
                }
            }
            _ => return Err(format!("unknown worker command {line:?}")),
        }
    }
    Ok(())
}

/// What a drained lab still holds; compared across waves for leaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Residue {
    pub endpoints: usize,
    pub ipam_allocated: u64,
    pub pins: usize,
    pub links: usize,
    pub state: usize,
    pub agent_fds: usize,
    pub agent_rss_kib: u64,
}

impl Residue {
    pub fn json(&self) -> Value {
        json!({
            "endpoints": self.endpoints, "ipam_allocated": self.ipam_allocated,
            "pins": self.pins, "links": self.links, "state": self.state,
            "agent_fds": self.agent_fds, "agent_rss_kib": self.agent_rss_kib,
        })
    }
    /// Objects that must return to the first drained wave's count exactly.
    pub fn objects(&self) -> [(&'static str, u64); 5] {
        let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
        [
            ("endpoints", n(self.endpoints)),
            ("ipam_allocated", self.ipam_allocated),
            ("pins", n(self.pins)),
            ("links", n(self.links)),
            ("state", n(self.state)),
        ]
    }
}

pub struct Lab {
    dir: PathBuf,
    pins: PathBuf,
    mounted: bool,
    agent: Option<Child>,
    agent_binary: PathBuf,
    cni: PathBuf,
    log: PathBuf,
    conf: Value,
}

impl Lab {
    /// A fresh agent on a private bpffs, pools large enough for the biggest
    /// wave ([`MAX_ENDPOINTS`]).
    pub fn start(env: &Env, label: &str) -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(text)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("flowsdn-lab-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let pins = dir.join("bpf");
        let mut lab = Self {
            pins: pins.clone(),
            mounted: false,
            agent: None,
            agent_binary: env.agent(),
            cni: env.cni(),
            log: env.results.join(format!("agent-{label}.log")),
            conf: json!({"cniVersion": "1.1.0", "name": "flowsdn-test", "type": "flowsdn-cni"}),
            dir,
        };
        fs::create_dir(&pins).map_err(text)?;
        mount(
            Some("bpffs"),
            &pins,
            Some("bpf"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount bpffs: {e}"))?;
        lab.mounted = true;
        let config = json!({
            "socket-path": lab.socket(), "state-dir": lab.dir.join("state"),
            "delete-queue": lab.queue(), "bpf-object": env.bpf("local-delivery"),
            "bpf-pin-root": pins, "ipv4-pool": "198.18.0.0/22", "ipv4-gateway": "198.18.3.254",
            "ipv6-pool": "2001:db8:1::/64", "ipv6-gateway": "2001:db8:1::ffff",
            "device-mtu": 1500, "route-mtu": 1500, "endpoint-id-max": 1024,
        });
        fs::write(lab.dir.join("config.json"), config.to_string()).map_err(text)?;
        lab.start_agent()?;
        Ok(lab)
    }
    fn socket(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }
    fn queue(&self) -> PathBuf {
        self.dir.join("deleteQueue")
    }
    pub fn client(&self) -> Client {
        Client::new(self.socket(), Duration::from_secs(2))
    }
    fn start_agent(&mut self) -> Result<()> {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .map_err(|e| format!("{}: {e}", self.log.display()))?;
        let err = log.try_clone().map_err(text)?;
        let mut agent = Command::new(&self.agent_binary)
            .arg("--config")
            .arg(self.dir.join("config.json"))
            .stdout(log)
            .stderr(err)
            .spawn()
            .map_err(|e| format!("{}: {e}", self.agent_binary.display()))?;
        let start = Instant::now();
        loop {
            if let Some(status) = agent.try_wait().map_err(text)? {
                return Err(format!(
                    "agent exited during startup: {status}; see {}",
                    self.log.display()
                ));
            }
            let health = Client::new(self.socket(), Duration::from_millis(500)).request(
                Method::Get,
                "/v1/healthz",
                None,
            );
            if health.is_ok_and(|r| r.status == 200) {
                self.agent = Some(agent);
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = agent.kill();
                let _ = agent.wait();
                return Err("agent not healthy within 30 s".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
    /// Stop and start the agent on the same state, pins and socket.
    pub fn restart_agent(&mut self) -> Result<()> {
        if let Some(mut agent) = self.agent.take() {
            let _ = agent.kill();
            let _ = agent.wait();
        }
        self.start_agent()
    }
    pub fn agent_pid(&self) -> Option<u32> {
        self.agent.as_ref().map(Child::id)
    }
    pub fn add(&self, endpoint: &mut Endpoint) -> Result<Value> {
        let result = self.cni("ADD", endpoint)?;
        endpoint.configure(&result)?;
        Ok(result)
    }
    pub fn del(&self, endpoint: &Endpoint) -> Result<()> {
        self.cni("DEL", endpoint).map(drop)
    }
    fn cni(&self, verb: &str, endpoint: &Endpoint) -> Result<Value> {
        let mut process = Command::new(&self.cni)
            .env("CNI_COMMAND", verb)
            .env("CNI_CONTAINERID", format!("sandbox{}", endpoint.id))
            .env("CNI_IFNAME", "eth0")
            .env("CNI_NETNS", endpoint.namespace())
            .env("CNI_PATH", self.cni.parent().unwrap_or(Path::new("/")))
            .env(
                "CNI_ARGS",
                format!(
                    "K8S_POD_NAMESPACE=flowsdn-test;K8S_POD_NAME=pod{}",
                    endpoint.id
                ),
            )
            .env("FLOWSDN_SOCK", self.socket())
            .env("FLOWSDN_DELETE_QUEUE", self.queue())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.cni.display()))?;
        let out = capture(process.stdout.take());
        let err = capture(process.stderr.take());
        if let Some(mut stdin) = process.stdin.take() {
            stdin
                .write_all(self.conf.to_string().as_bytes())
                .map_err(text)?;
        }
        let start = Instant::now();
        let status = loop {
            if let Some(status) = process.try_wait().map_err(text)? {
                break status;
            }
            if start.elapsed() > Duration::from_secs(45) {
                let _ = process.kill();
                let _ = process.wait();
                return Err(format!("CNI {verb} endpoint {} timed out", endpoint.id));
            }
            thread::sleep(Duration::from_millis(2));
        };
        let out = out.join().unwrap_or_default();
        let err = err.join().unwrap_or_default();
        ensure(
            status.success(),
            format!(
                "CNI {verb} endpoint {}: {status}: {} {}",
                endpoint.id,
                String::from_utf8_lossy(&out).trim(),
                String::from_utf8_lossy(&err).trim()
            ),
        )?;
        if out.iter().all(u8::is_ascii_whitespace) {
            Ok(Value::Null)
        } else {
            serde_json::from_slice(&out).map_err(|e| format!("CNI {verb} output: {e}"))
        }
    }
    pub fn endpoints(&self) -> Result<Vec<Value>> {
        let response = self
            .client()
            .request(Method::Get, "/v1/endpoint", None)
            .map_err(|e| format!("GET /v1/endpoint: {e}"))?;
        ensure(
            response.status == 200,
            format!("GET /v1/endpoint: {}", response.status),
        )?;
        response
            .json
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| "GET /v1/endpoint: not an array".into())
    }
    fn ipam_allocated(&self) -> Result<u64> {
        let response = self
            .client()
            .request(Method::Get, "/v1/ipam", None)
            .map_err(|e| format!("GET /v1/ipam: {e}"))?;
        let pools = response
            .json
            .as_ref()
            .and_then(|v| v.get("pools"))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("GET /v1/ipam: {}", response.status))?;
        pools.iter().try_fold(0u64, |sum, pool| {
            let n: u64 = pool
                .get("allocated")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .ok_or("GET /v1/ipam: pool without allocated count")?;
            Ok(sum.saturating_add(n))
        })
    }
    pub fn residue(&self) -> Result<Residue> {
        let pid = self.agent_pid().ok_or("agent not running")?;
        let count = |dir: &Path| fs::read_dir(dir).map(Iterator::count).unwrap_or(0);
        let rss = fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("VmRSS:"))
                    .and_then(|v| v.split_whitespace().next()?.parse().ok())
            })
            .unwrap_or(0);
        Ok(Residue {
            endpoints: self.endpoints()?.len(),
            ipam_allocated: self.ipam_allocated()?,
            pins: count(&self.pins),
            links: links(),
            state: count(&self.dir.join("state")),
            agent_fds: count(Path::new(&format!("/proc/{pid}/fd"))),
            agent_rss_kib: rss,
        })
    }
}

/// Interfaces in this process's network namespace.
pub fn links() -> usize {
    fs::read_to_string("/proc/self/net/dev")
        .map(|s| s.lines().skip(2).count())
        .unwrap_or(0)
}

fn capture(stream: Option<impl Read + Send + 'static>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stream) = stream {
            let _ = stream.take(8_388_608).read_to_end(&mut bytes);
        }
        bytes
    })
}

impl Drop for Lab {
    fn drop(&mut self) {
        if let Some(mut agent) = self.agent.take() {
            let _ = agent.kill();
            let _ = agent.wait();
        }
        if self.mounted {
            let _ = umount2(&self.pins, MntFlags::MNT_DETACH);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
