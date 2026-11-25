//! The L7 proxy redirect on a real kernel (#577, ADR-0024 step 1): a Pod in a
//! network namespace of its own behind a veth whose host side runs the
//! local-delivery object's endpoint programs, its egress enforced with a
//! policy entry that allows TCP 80 to any identity through proxy port 15001.
//! The host side has the proxy's ip rule and local route and a `flowsdn-l7`
//! transparent listener on 15001.
//!
//! * The Pod connects to 203.0.113.10:80, an address nothing on this node
//!   owns. The listener accepts the connection with that original
//!   destination, the Pod's address as the source, and the Pod's identity
//!   (from the ipcache map); data passes both ways.
//! * The flow's policy entry remembers the proxy port, so later packets of
//!   the connection reach the same socket.
//! * With the listener gone the redirect fails closed: the Pod's next
//!   connection does not reach anything.
//!
//! Usage: `proxy-live LOCAL_DELIVERY_OBJECT`. It needs iproute2 and root, as
//! kernel-check gives it.
use flowsdn_bpf_abi::{
    IpCacheKey, MapBytes, RemoteEndpointInfo,
    policy::{EndpointPolicyKey, PolicyEndpoint, PolicyEntry, PolicyKey, enforce},
};
use flowsdn_bpf_loader::kernel::{Egress, LocalDelivery, Object};
use flowsdn_l7::listener::Listener;
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const POD: [u8; 4] = [10, 0, 0, 7];
const POD_IDENTITY: u32 = 1234;
const ENDPOINT: u32 = 7;
const PROXY_PORT: u16 = 15001;
const TCP: u8 = 6;
const TIMEOUT: Duration = Duration::from_secs(3);

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

/// The Pod: its own namespace; once told `GO`, configure `eth0`; then for
/// each `CONNECT <addr>` send `hello`, read the reply, and print `OK <reply>`
/// or `FAIL <error>`.
fn pod() -> Result<()> {
    isolate()?;
    let mut out = std::io::stdout();
    writeln!(out, "READY")?;
    out.flush()?;
    let mut lines = BufReader::new(std::io::stdin()).lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("GO"),
        "pod: expected GO",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["addr", "add", "10.0.0.7/24", "dev", "eth0"])?;
    ip(&["link", "set", "eth0", "up"])?;
    ip(&["route", "add", "default", "via", "10.0.0.1"])?;
    writeln!(out, "UP")?;
    out.flush()?;
    for line in lines {
        let line = line?;
        let Some(target) = line.strip_prefix("CONNECT ") else {
            break;
        };
        let target: SocketAddr = target.parse()?;
        let result = (|| -> std::io::Result<String> {
            let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            stream.write_all(b"hello")?;
            let mut reply = [0u8; 5];
            stream.read_exact(&mut reply)?;
            Ok(String::from_utf8_lossy(&reply).into_owned())
        })();
        match result {
            Ok(reply) => writeln!(out, "OK {reply}")?,
            Err(e) => writeln!(out, "FAIL {e}")?,
        }
        out.flush()?;
    }
    Ok(())
}

fn run(object: &[u8]) -> Result<()> {
    isolate()?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("pod")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("pod stdin")?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("pod stdout")?).lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("READY"),
        "pod did not isolate",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["link", "add", "ep0", "type", "veth", "peer", "name", "eth0"])?;
    ip(&["link", "set", "eth0", "netns", &child.id().to_string()])?;
    ip(&["addr", "add", "10.0.0.1/24", "dev", "ep0"])?;
    ip(&["link", "set", "ep0", "up"])?;
    let ep0: u32 = ip(&["-o", "link", "show", "dev", "ep0"])?
        .split(':')
        .next()
        .map(str::trim)
        .ok_or("no ifindex")?
        .parse()?;
    for command in flowsdn_l7::route::ip_commands("-4") {
        let args: Vec<&str> = command.iter().map(String::as_str).collect();
        ip(&args)?;
    }

    let mut delivery = LocalDelivery::load_object(Object::Bytes(object), Egress::Stack)
        .map_err(|e| format!("load local-delivery: {e}"))?;
    delivery
        .attach("ep0")
        .map_err(|e| format!("attach to ep0: {e}"))?;
    let key = IpCacheKey::v4(POD, 32, 0).map_err(|_| "ipcache prefix")?;
    delivery.policy().upsert_ipcache(
        key,
        RemoteEndpointInfo {
            sec_identity: POD_IDENTITY,
            ..Default::default()
        },
    )
    .map_err(|e| format!("ipcache: {e}"))?;
    let rule = PolicyKey::new(0, true, TCP, 80, 16).map_err(|_| "policy key")?;
    let entry = PolicyEntry::new(PROXY_PORT, false, 24, 0, false, 0xFFFF_FF01, 0)
        .map_err(|_| "policy entry")?;
    delivery
        .policy()
        .upsert_policy(EndpointPolicyKey::for_endpoint(ENDPOINT, rule), entry)
        .map_err(|e| format!("policy entry: {e}"))?;
    delivery.policy().set_policy_endpoint(
        ep0,
        PolicyEndpoint {
            endpoint: ENDPOINT,
            flags: enforce::EGRESS,
        },
    )
    .map_err(|e| format!("policy endpoint: {e}"))?;
    let identities: Vec<(IpCacheKey, RemoteEndpointInfo)> = delivery
        .policy()
        .ipcache_entries()
        .map_err(|e| format!("read the ipcache: {e}"))?;
    let resolve = move |address: IpAddr| -> u32 {
        let IpAddr::V4(v4) = address else { return 0 };
        IpCacheKey::v4(v4.octets(), 32, 0)
            .ok()
            .and_then(|key| {
                identities
                    .iter()
                    .find(|(k, _)| k.to_bytes() == key.to_bytes())
            })
            .map_or(2, |(_, info)| info.sec_identity)
    };
    let listener =
        Listener::bind(PROXY_PORT, false).map_err(|e| format!("transparent listener: {e}"))?;
    let server = std::thread::spawn(
        move || -> std::result::Result<(SocketAddr, SocketAddr, u32), String> {
            let text = |e: std::io::Error| e.to_string();
            let mut redirected = listener.accept(&resolve).map_err(text)?;
            redirected
                .stream
                .set_read_timeout(Some(TIMEOUT))
                .map_err(text)?;
            let mut request = [0u8; 5];
            redirected.stream.read_exact(&mut request).map_err(text)?;
            if &request != b"hello" {
                return Err("the proxy got another request".into());
            }
            redirected.stream.write_all(b"world").map_err(text)?;
            Ok((redirected.original, redirected.source, redirected.identity))
        },
    );
    println!(
        "PASS endpoint ep0: egress enforced, TCP 80 to any identity through proxy port {PROXY_PORT}; ip rule fwmark 0x200/0xf00 -> table 2004 (local); transparent listener on {PROXY_PORT}"
    );

    writeln!(input, "GO")?;
    ensure(
        lines.next().transpose()?.as_deref() == Some("UP"),
        "pod did not come up",
    )?;
    let mut connect = |target: &str| -> Result<String> {
        writeln!(input, "CONNECT {target}")?;
        input.flush()?;
        Ok(lines.next().transpose()?.ok_or("pod ended")?)
    };
    let got = connect("203.0.113.10:80")?;
    ensure(
        got == "OK world",
        &format!("pod to 203.0.113.10:80 through the proxy: {got}"),
    )?;
    let (original, source, identity) = server.join().map_err(|_| "proxy thread panicked")??;
    ensure(
        original == SocketAddr::from(([203, 0, 113, 10], 80)),
        &format!("original destination {original}"),
    )?;
    ensure(
        source.ip() == IpAddr::from(POD),
        &format!("source {source}"),
    )?;
    ensure(
        identity == POD_IDENTITY,
        &format!("source identity {identity}"),
    )?;
    let remembered = delivery
        .policy()
        .policy_flows()?
        .iter()
        .any(|(k, v)| k.dport.get() == 80 && k.egress == 1 && v.pad == u32::from(PROXY_PORT));
    ensure(
        remembered,
        "the redirected flow does not carry its proxy port",
    )?;
    println!(
        "PASS the Pod's connection to 203.0.113.10:80 reaches the transparent listener: original destination {original}, source {source}, identity {identity}; request and reply pass; the flow remembers proxy port {PROXY_PORT}"
    );

    let got = connect("203.0.113.11:80")?;
    ensure(
        got.starts_with("FAIL"),
        &format!("with no listener the redirect must fail closed, got {got}"),
    )?;
    println!("PASS no listener on the proxy port: the Pod's connection fails ({got})");

    drop(input);
    let _ = child.wait();
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: proxy-live LOCAL_DELIVERY_OBJECT")?;
    if first == "pod" {
        return pod();
    }
    run(&std::fs::read(first)?)
}
