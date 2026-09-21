//! Actual CNI executable integration against a fixture-only Unix fake agent.
//! All links, BPF attachments and network sysctls live in anonymous namespaces.
use flowsdn_agent::endpoints::Manager;
use flowsdn_cni::queue::{Queue, ReplayRequest};
use flowsdn_ipam::{HostScope, Ipam};
use nix::sched::{CloneFlags, unshare};
use serde_json::{Value, json};
use std::{
    error::Error,
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{SocketAddr, UdpSocket},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}").into())
}
fn isolate() -> Result<()> {
    let old = fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        fs::read_link("/proc/self/ns/net")? != old,
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
fn gateway(v6: bool) -> &'static str {
    if v6 {
        "2001:db8:1::ffff"
    } else {
        "198.18.0.254"
    }
}
fn say(line: &str) -> Result<()> {
    println!("{line}");
    Ok(std::io::stdout().flush()?)
}

struct Temp(PathBuf);
impl Temp {
    fn new() -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!("flowsdn-cni-{}-{stamp}", std::process::id()));
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
    id: u8,
    ports: [u16; 2],
}
impl Endpoint {
    fn spawn(id: u8) -> Result<Self> {
        let mut process = Process(
            Command::new(std::env::current_exe()?)
                .args(["--endpoint", &id.to_string()])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let input = process.0.stdin.take().ok_or("missing child stdin")?;
        let output = process.0.stdout.take().ok_or("missing child stdout")?;
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
            id,
            ports: [0; 2],
        };
        ensure(
            endpoint.replies.recv_timeout(Duration::from_secs(5))? == "READY",
            "endpoint isolation failed",
        )?;
        Ok(endpoint)
    }
    fn netns(&self) -> String {
        format!("/proc/{}/ns/net", self.process.0.id())
    }
    fn command(&mut self, request: &str) -> Result<String> {
        writeln!(self.input, "{request}")?;
        self.input.flush()?;
        Ok(self.replies.recv_timeout(Duration::from_secs(5))?)
    }
    fn configure(&mut self) -> Result<()> {
        let reply = self.command("configure")?;
        let mut fields = reply.split_whitespace();
        ensure(fields.next() == Some("PORTS"), "endpoint sockets failed")?;
        self.ports = [
            fields.next().ok_or("IPv4 port")?.parse()?,
            fields.next().ok_or("IPv6 port")?.parse()?,
        ];
        ensure(fields.next().is_none(), "extra port response")
    }
    fn socket(&self, v6: bool) -> Result<SocketAddr> {
        Ok(SocketAddr::new(
            address(self.id, v6).parse()?,
            *self.ports.get(usize::from(v6)).ok_or("port")?,
        ))
    }
}

fn endpoint_worker(id: u8) -> Result<()> {
    ensure((1..=2).contains(&id), "invalid endpoint id")?;
    isolate()?;
    say("READY")?;
    let mut lines = std::io::stdin().lock().lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("configure"),
        "missing setup",
    )?;
    // The real CNI ADD has already created and configured eth0 in this netns.
    let v4 = UdpSocket::bind(format!("{}:0", address(id, false)))?;
    let v6 = UdpSocket::bind(format!("[{}]:0", address(id, true)))?;
    for socket in [&v4, &v6] {
        socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    }
    say(&format!(
        "PORTS {} {}",
        v4.local_addr()?.port(),
        v6.local_addr()?.port()
    ))?;
    for line in lines {
        let line = line?;
        let mut args = line.split_whitespace();
        let command = args.next().ok_or("command")?;
        let socket = match args.next() {
            Some("4") => &v4,
            Some("6") => &v6,
            _ => return Err("family".into()),
        };
        match command {
            "send" => {
                let to: SocketAddr = args.next().ok_or("destination")?.parse()?;
                let payload = args.next().ok_or("payload")?;
                ensure(
                    socket.send_to(payload.as_bytes(), to)? == payload.len(),
                    "short UDP send",
                )?;
                say("SENT")?;
            }
            "recv" => {
                let mut bytes = [0u8; 2048];
                match socket.recv_from(&mut bytes) {
                    Ok((count, _)) => say(&format!(
                        "DATA {}",
                        std::str::from_utf8(bytes.get(..count).ok_or("receive length")?)?
                    ))?,
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                        say("TIMEOUT")?
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            _ => return Err("unknown endpoint command".into()),
        }
        ensure(args.next().is_none(), "extra endpoint arguments")?;
    }
    Ok(())
}

struct State {
    manager: Option<Manager>,
    object: PathBuf,
    store: PathBuf,
    offline_delete: bool,
    errors: Vec<String>,
}
impl State {
    fn new(object: &Path, store: &Path) -> Result<Self> {
        Ok(Self {
            manager: Some(managed(Manager::restore(store, object, fresh_ipam()?))?),
            object: object.to_owned(),
            store: store.to_owned(),
            offline_delete: false,
            errors: Vec::new(),
        })
    }
    fn manager(&self) -> Result<&Manager> {
        self.manager
            .as_ref()
            .ok_or_else(|| "endpoint manager stopped".into())
    }
    fn manager_mut(&mut self) -> Result<&mut Manager> {
        self.manager
            .as_mut()
            .ok_or_else(|| "endpoint manager stopped".into())
    }
    fn restart(&mut self) -> Result<()> {
        let mut ids = Vec::new();
        for id in [1, 2] {
            let attachment = format!("cni-attachment-id:cid{id}:eth0");
            ids.push((
                attachment.clone(),
                self.manager()?
                    .get(&attachment)
                    .ok_or("endpoint before restart")?
                    .id,
            ));
        }
        ensure(
            self.manager()?.len() == ids.len(),
            "unexpected endpoint count before restart",
        )?;
        // Drop all old BPF/map/IPAM/store-lock ownership. The Unix fake API
        // remains alive, but no endpoint state is copied into the new manager.
        drop(self.manager.take().ok_or("manager before restart")?);
        self.manager = Some(managed(Manager::restore(
            &self.store,
            &self.object,
            fresh_ipam()?,
        ))?);
        ensure(
            self.manager()?.len() == ids.len(),
            "restored endpoint count",
        )?;
        for (attachment, id) in ids {
            ensure(
                self.manager()?
                    .get(&attachment)
                    .ok_or("restored attachment")?
                    .id
                    == id,
                "endpoint ID changed on restore",
            )?;
        }
        let ipam = self.manager_mut()?.ipam_mut();
        ensure(
            ipam.ipv4().ok_or("restored IPv4")?.allocated() == 2
                && ipam.ipv6().ok_or("restored IPv6")?.allocated() == 2,
            "restored IP allocations",
        )
    }
    fn delete(&mut self, id: &str) -> Result<(u16, Value)> {
        if self.offline_delete {
            return Ok((503, json!({"error":"fixture unavailable"})));
        }
        if !managed(self.manager_mut()?.delete(id))? {
            return Ok((404, json!({"error":"missing endpoint"})));
        }
        Ok((200, json!({})))
    }
    fn handle(&mut self, method: &str, target: &str, body: Value) -> Result<(u16, Value)> {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if method == "GET" && path == "/v1/config" {
            return Ok((
                200,
                json!({"status":{"datapath-mode":"veth","ipam-mode":"kubernetes","device-mtu":1500,"route-mtu":1450,"host-addressing":{"ipv4":{"enabled":true,"ip":gateway(false)},"ipv6":{"enabled":true,"ip":gateway(true)}}}}),
            ));
        }
        if method == "POST" && path == "/v1/ipam" {
            let owner = query
                .split('&')
                .filter_map(|part| part.split_once('='))
                .find(|(key, _)| *key == "owner")
                .ok_or("IPAM owner")?
                .1;
            let owner = decode(owner)?;
            let id = match owner.as_str() {
                "fixture/pod1" => 1,
                "fixture/pod2" => 2,
                "fixture/pod3" => 3,
                _ => return Err("unknown fixture owner".into()),
            };
            for v6 in [true, false] {
                self.manager_mut()?
                    .ipam_mut()
                    .allocate(address(id, v6).parse()?, &owner)?;
            }
            return Ok((
                201,
                json!({"address":{"ipv4":address(id,false),"ipv6":address(id,true),"ipv4-pool-name":"default","ipv6-pool-name":"default","ipv4-expiration-uuid":"fixture-v4","ipv6-expiration-uuid":"fixture-v6"},
                "host-addressing":{"ipv4":{"enabled":true,"ip":gateway(false)},"ipv6":{"enabled":true,"ip":gateway(true)}}}),
            ));
        }
        if method == "DELETE"
            && let Some(ip) = path.strip_prefix("/v1/ipam/")
        {
            self.manager_mut()?
                .ipam_mut()
                .release(decode(ip)?.parse()?)?;
            return Ok((200, json!({})));
        }
        if let Some(id) = path.strip_prefix("/v1/endpoint/") {
            if method == "GET"
                && let Some(id) = id.strip_suffix("/healthz")
            {
                return Ok(if self.manager()?.get(&decode(id)?).is_some() {
                    (200, json!({"overallHealth":"OK"}))
                } else {
                    (404, json!({"error":"missing endpoint"}))
                });
            }
            let id = decode(id)?;
            if method == "GET" {
                let Some(record) = self.manager()?.get(&id) else {
                    return Ok((404, json!({"error":"missing endpoint"})));
                };
                let d = &record.document;
                return Ok((
                    200,
                    json!({"id":record.id,"status":{"state":"ready","networking":{
                        "interface-name":d.get("IfName"),"interface-index":d.get("IfIndex"),
                        "container-interface-name":d.get("ContainerIfName"),"mac":d.get("LXCMAC"),"host-mac":d.get("NodeMAC"),
                        "netns-cookie":d.get("NetnsCookie").and_then(Value::as_u64).unwrap_or(0).to_string(),"host-addressing":d.get("CNIHostAddressing"),"route-mtu":d.get("CNIRouteMTU"),
                        "addressing":[{"ipv4":d.get("IPv4"),"ipv6":d.get("IPv6")}]
                    }}}),
                ));
            }
            if method == "DELETE" {
                return self.delete(&id);
            }
            if method == "PUT" {
                ensure(self.manager()?.get(&id).is_none(), "duplicate endpoint")?;
                let host = text(&body, "interface-name")?.to_owned();
                let ifindex = body
                    .get("interface-index")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("interface index")?;
                let addressing = body.get("addressing").ok_or("addressing")?;
                let document = json!({"dockerID":text(&body,"container-id")?,"ContainerIfName":text(&body,"container-interface-name")?,
                    "IfName":host,"IfIndex":ifindex,"LXCMAC":text(&body,"mac")?,"NodeMAC":text(&body,"host-mac")?,
                    "IPv4":text(addressing,"ipv4")?,"IPv6":text(addressing,"ipv6")?,
                    "K8sNamespace":text(&body,"k8s-namespace")?,"K8sPodName":text(&body,"k8s-pod-name")?,"NetnsCookie":text(&body,"netns-cookie")?.parse::<u64>()?,"CNIRouteMTU":1450,"CNIHostAddressing":{"ipv4":{"enabled":true,"ip":gateway(false)},"ipv6":{"enabled":true,"ip":gateway(true)}}});
                ensure(
                    id == format!(
                        "cni-attachment-id:{}:{}",
                        text(&body, "container-id")?,
                        text(&body, "container-interface-name")?
                    ),
                    "endpoint URL/body identity mismatch",
                )?;
                let endpoint_id = managed(self.manager_mut()?.create(document))?;
                if text(&body, "container-id")? == "cid3" {
                    // Success followed by malformed networking response forces
                    // CNI rollback after the real endpoint was installed.
                    return Ok((201, json!({"id":endpoint_id,"status":{"networking":null}})));
                }

                return Ok((
                    201,
                    json!({"id":endpoint_id,"status":{"networking":{"mac":text(&body,"mac")?}}}),
                ));
            }
        }
        if method == "DELETE" && path == "/v1/endpoint" {
            return self.delete(&format!(
                "cni-attachment-id:{}:eth0",
                text(&body, "container-id")?
            ));
        }
        Err(format!("unsupported fixture request {method} {target}").into())
    }
}

fn managed<T>(result: flowsdn_agent::state::Result<T>) -> Result<T> {
    result.map_err(|error| error as Box<dyn Error>)
}
fn fresh_ipam() -> Result<Ipam> {
    let v4 = HostScope::new("198.18.0.0".parse()?, 24, Default::default())?;
    let v6 = HostScope::new("2001:db8:1::".parse()?, 64, Default::default())?;
    let mut ipam = Ipam::new(Some(v4), Some(v6))?;
    for v6 in [false, true] {
        ipam.exclude_ip(gateway(v6).parse()?, "router")?;
    }
    Ok(ipam)
}
fn decode(text: &str) -> Result<String> {
    let mut input = text.bytes();
    let mut output = Vec::new();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let a = char::from(input.next().ok_or("short percent escape")?)
                .to_digit(16)
                .ok_or("hex escape")?;
            let b = char::from(input.next().ok_or("short percent escape")?)
                .to_digit(16)
                .ok_or("hex escape")?;
            output.push(u8::try_from((a << 4) | b)?);
        } else {
            output.push(byte);
        }
    }
    Ok(String::from_utf8(output)?)
}

fn read_request(stream: &mut UnixStream) -> Result<(String, String, Value)> {
    let start = Instant::now();
    let mut bytes = Vec::new();
    loop {
        let remaining = Duration::from_secs(2).saturating_sub(start.elapsed());
        ensure(!remaining.is_zero(), "fixture request timeout")?;
        stream.set_read_timeout(Some(remaining))?;
        let mut part = [0u8; 4096];
        let count = stream.read(&mut part)?;
        ensure(count > 0, "truncated fixture request")?;
        bytes.extend_from_slice(part.get(..count).ok_or("read count")?);
        ensure(bytes.len() <= 1_048_576, "fixture request too large")?;
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        if let httparse::Status::Complete(header_len) = request.parse(&bytes)? {
            ensure(header_len <= 16_384, "fixture headers too large")?;
            let mut length = None;
            for header in request.headers.iter() {
                ensure(
                    !header.name.eq_ignore_ascii_case("transfer-encoding"),
                    "fixture does not accept chunked requests",
                )?;
                if header.name.eq_ignore_ascii_case("content-length") {
                    ensure(length.is_none(), "duplicate request length")?;
                    length = Some(std::str::from_utf8(header.value)?.parse::<usize>()?);
                }
            }
            let total = header_len
                .checked_add(length.unwrap_or(0))
                .ok_or("request overflow")?;
            ensure(total <= 1_048_576, "fixture body too large")?;
            if bytes.len() < total {
                continue;
            }
            ensure(bytes.len() == total, "extra request bytes")?;
            let body = bytes.get(header_len..total).ok_or("body bounds")?;
            return Ok((
                request.method.ok_or("method")?.into(),
                request.path.ok_or("target")?.into(),
                if body.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(body)?
                },
            ));
        }
        ensure(bytes.len() <= 16_384, "fixture headers too large")?;
    }
}

struct Agent {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Agent {
    fn start(socket: &Path, state: Arc<Mutex<State>>) -> Result<Self> {
        let listener = UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        // Threads inherit the already isolated coordinator network namespace.
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => {
                        if let Ok(mut state) = state.lock() {
                            state.errors.push(e.to_string());
                        }
                        break;
                    }
                };
                let result = read_request(&mut stream).and_then(|(method, path, body)| {
                    state
                        .lock()
                        .map_err(|_| "fixture state poisoned")?
                        .handle(&method, &path, body)
                });
                let (status, body) = match result {
                    Ok(reply) => reply,
                    Err(error) => {
                        if let Ok(mut state) = state.lock() {
                            state.errors.push(error.to_string());
                        }
                        (500, json!({"error":error.to_string()}))
                    }
                };
                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn cni(
    binary: &Path,
    temp: &Temp,
    command: &str,
    id: u8,
    netns: &str,
    conf: &Value,
    success: bool,
) -> Result<Value> {
    let mut process = Process(
        Command::new(binary)
            .env("CNI_COMMAND", command)
            .env("CNI_CONTAINERID", format!("cid{id}"))
            .env("CNI_NETNS", netns)
            .env("CNI_IFNAME", "eth0")
            .env("CNI_PATH", binary.parent().ok_or("binary parent")?)
            .env(
                "CNI_ARGS",
                format!("K8S_POD_NAMESPACE=fixture;K8S_POD_NAME=pod{id};K8S_POD_UID=uid{id}"),
            )
            .env("CILIUM_SOCK", temp.0.join("agent.sock"))
            .env("FLOWSDN_DELETE_QUEUE", temp.0.join("deleteQueue"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    process
        .0
        .stdin
        .take()
        .ok_or("CNI stdin")?
        .write_all(conf.to_string().as_bytes())?;
    let start = Instant::now();
    let status = loop {
        if let Some(status) = process.0.try_wait()? {
            break status;
        }
        ensure(
            start.elapsed() < Duration::from_secs(40),
            "CNI executable timed out",
        )?;
        thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    process
        .0
        .stdout
        .take()
        .ok_or("CNI stdout")?
        .take(1_048_577)
        .read_to_end(&mut stdout)?;
    process
        .0
        .stderr
        .take()
        .ok_or("CNI stderr")?
        .take(1_048_577)
        .read_to_end(&mut stderr)?;
    ensure(
        stdout.len() <= 1_048_576 && stderr.len() <= 1_048_576,
        "CNI output too large",
    )?;
    ensure(
        status.success() == success,
        &format!(
            "CNI {command} unexpected status {status}: {} {}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ),
    )?;
    Ok(if stdout.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&stdout)?
    })
}

fn exchange(from: &mut Endpoint, to: &mut Endpoint, v6: bool) -> Result<()> {
    let family = if v6 { 6 } else { 4 };
    let payload = format!("runtime-{}-{}-{family}", from.id, to.id);
    ensure(
        from.command(&format!("send {family} {} {payload}", to.socket(v6)?))? == "SENT",
        "send failed",
    )?;
    let received = to.command(&format!("recv {family}"))?;
    if received != format!("DATA {payload}") {
        for endpoint in [from, to] {
            let namespace = fs::File::open(endpoint.netns())?;
            let diagnostic = flowsdn_connector::in_namespace(namespace, || {
                let mut output = String::new();
                for args in [
                    vec!["-j", "link", "show"],
                    vec!["-j", "neigh", "show"],
                    vec!["-j", "route", "show"],
                ] {
                    output.push_str(&String::from_utf8(
                        Command::new("ip").args(args).output()?.stdout,
                    )?);
                }
                Ok(output)
            })
            .map_err(|e| e as Box<dyn Error>)?;
            eprintln!("endpoint {} diagnostic: {diagnostic}", endpoint.id);
        }
        return Err(format!("IPv{family} {payload}: expected datagram, got {received}").into());
    }
    Ok(())
}

fn run(binary: &Path, object: &Path) -> Result<()> {
    let binary = fs::canonicalize(binary)?;
    let object = fs::canonicalize(object)?;
    isolate()?;
    let temp = Temp::new()?;
    let mut first = Endpoint::spawn(1)?;
    let mut second = Endpoint::spawn(2)?;
    let state = Arc::new(Mutex::new(State::new(&object, &temp.0.join("state"))?));
    let _agent = Agent::start(&temp.0.join("agent.sock"), state.clone())?;
    let conf = json!({"cniVersion":"1.1.0","name":"flowsdn-fixture","type":"flowsdn-cni"});
    let mut previous = Vec::new();
    for endpoint in [&mut first, &mut second] {
        let result = cni(
            &binary,
            &temp,
            "ADD",
            endpoint.id,
            &endpoint.netns(),
            &conf,
            true,
        )?;
        ensure(
            result.get("cniVersion") == Some(&json!("1.1.0")),
            "CNI result version",
        )?;
        ensure(
            result
                .get("ips")
                .and_then(Value::as_array)
                .is_some_and(|ips| ips.len() == 2),
            "CNI result dual stack",
        )?;
        endpoint.configure()?;
        let mut check = conf.clone();
        check
            .as_object_mut()
            .ok_or("config")?
            .insert("prevResult".into(), result.clone());
        cni(
            &binary,
            &temp,
            "CHECK",
            endpoint.id,
            &endpoint.netns(),
            &check,
            true,
        )?;
        previous.push(check);
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6)?;
        exchange(&mut second, &mut first, v6)?;
    }
    state.lock().map_err(|_| "state")?.restart()?;
    for (endpoint, check) in [&first, &second].into_iter().zip(&previous) {
        cni(
            &binary,
            &temp,
            "CHECK",
            endpoint.id,
            &endpoint.netns(),
            check,
            true,
        )?;
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6)?;
        exchange(&mut second, &mut first, v6)?;
    }
    println!(
        "PASS: real endpoint manager restored persisted IDs, IPAM and fresh BPF ownership; CHECK and bidirectional dual-stack UDP survive manager restart inside the fixture API"
    );
    let rollback = Endpoint::spawn(3)?;
    cni(&binary, &temp, "ADD", 3, &rollback.netns(), &conf, false)?;
    {
        let mut guard = state.lock().map_err(|_| "state lock")?;
        ensure(
            guard
                .manager()?
                .get("cni-attachment-id:cid3:eth0")
                .is_none(),
            "rollback endpoint leaked",
        )?;
        let ipam = guard.manager_mut()?.ipam_mut();
        ensure(
            ipam.ipv4().ok_or("v4")?.allocated() == 2 && ipam.ipv6().ok_or("v6")?.allocated() == 2,
            "rollback touched another allocation",
        )?;
    }
    for v6 in [false, true] {
        exchange(&mut first, &mut second, v6)?;
        exchange(&mut second, &mut first, v6)?;
    }
    drop(rollback);
    println!(
        "PASS: post-create ADD rollback preserves both other endpoints, allocations and dual-stack traffic"
    );
    let mut bad = previous.first().ok_or("previous result")?.clone();
    bad.get_mut("prevResult")
        .and_then(|v| v.get_mut("ips"))
        .and_then(Value::as_array_mut)
        .and_then(|v| v.first_mut())
        .and_then(Value::as_object_mut)
        .ok_or("previous IP")?
        .insert("address".into(), json!("198.18.99.99/32"));
    let failure = cni(&binary, &temp, "CHECK", 1, &first.netns(), &bad, false)?;
    ensure(
        failure
            .get("msg")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("198.18.99.99")),
        "CHECK did not identify missing IP",
    )?;
    println!(
        "PASS: actual CNI ADD and CHECK, dual-stack BPF UDP, fabricated missing-address CHECK failure"
    );
    for endpoint in [&first, &second] {
        let host = {
            let state = state.lock().map_err(|_| "state")?;
            text(
                &state
                    .manager()?
                    .get(&format!("cni-attachment-id:cid{}:eth0", endpoint.id))
                    .ok_or("endpoint state")?
                    .document,
                "IfName",
            )?
            .to_owned()
        };
        cni(
            &binary,
            &temp,
            "DEL",
            endpoint.id,
            &endpoint.netns(),
            &conf,
            true,
        )?;
        cni(
            &binary,
            &temp,
            "DEL",
            endpoint.id,
            &endpoint.netns(),
            &conf,
            true,
        )?;
        ensure(
            !Command::new("ip")
                .args(["link", "show", "dev", &host])
                .output()?
                .status
                .success(),
            "DEL leaked host link",
        )?;
    }
    {
        let mut state = state.lock().map_err(|_| "state")?;
        ensure(state.manager()?.is_empty(), "DEL leaked endpoint state")?;
        let ipam = state.manager_mut()?.ipam_mut();
        ensure(
            ipam.ipv4().ok_or("v4")?.allocated() == 0 && ipam.ipv6().ok_or("v6")?.allocated() == 0,
            "DEL leaked IPAM",
        )?;
        for entry in fs::read_dir(&state.store)? {
            ensure(
                entry?
                    .file_name()
                    .to_str()
                    .is_none_or(|name| name.parse::<u16>().is_err()),
                "DEL leaked persisted endpoint directory",
            )?;
        }
        ensure(
            state.errors.is_empty(),
            &format!("fake agent errors: {:?}", state.errors),
        )?;
    }
    state.lock().map_err(|_| "state")?.offline_delete = true;
    cni(
        &binary,
        &temp,
        "DEL",
        3,
        temp.0.join("missing-netns").to_str().ok_or("netns path")?,
        &conf,
        true,
    )?;
    let queue = Queue::open(temp.0.join("deleteQueue"))?;
    let mut replay = queue.lock_exclusive(Duration::from_secs(1))?;
    let entries = replay.entries()?;
    ensure(
        entries.len() == 1,
        "offline DEL did not enqueue exactly once",
    )?;
    let entry = entries.first().ok_or("queue entry")?;
    ensure(
        entry.request
            == Ok(ReplayRequest::Attachment {
                container_id: "cid3".into(),
                ifname: "eth0".into(),
            }),
        "offline DEL queue content",
    )?;
    replay.remove(entry)?;
    println!(
        "PASS: actual CNI DEL clears endpoint, BPF attachment, veth and IPAM; repeated DEL succeeds; HTTP503 queues durable deletion"
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, id] if mode == "--endpoint" => endpoint_worker(id.parse()?),
        [binary, object] => run(Path::new(binary), Path::new(object)),
        _ => Err("usage: cni-runtime PATH_TO_CNI_BINARY PATH_TO_BPF_OBJECT".into()),
    }
}
