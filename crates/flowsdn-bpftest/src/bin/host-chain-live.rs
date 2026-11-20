//! The uplink's whole TCX chain on a real kernel (#484, finding
//! 9353481628e3): the socket-lb object's NodePort programs (attached first)
//! and the local-delivery object's host firewall (`from_netdev`/`to_netdev`,
//! attached last) on the same veth uplink, as the agent attaches them, with
//! real connections from a peer in a network namespace of its own.
//!
//! Test-running each program alone cannot see whether one ends the chain
//! before the other runs. Here, with ingress enforced on the host endpoint and
//! only TCP 7001 allowed from the world:
//! * the peer connects to the host's TCP 7001;
//! * the peer cannot connect to TCP 7002, and the denial is counted;
//! * the host connects out to the peer, and that flow is in the policy flow
//!   map (`to_netdev` ran), so its replies pass the enforced ingress.
//!
//! Usage: `host-chain-live LOCAL_DELIVERY_OBJECT SOCKET_LB_OBJECT`. It needs
//! iproute2 and root, as kernel-check gives it.
use flowsdn_bpf_abi::{
    IpCacheKey, RemoteEndpointInfo,
    policy::{
        EndpointPolicyKey, HOST_ENDPOINT, PolicyEndpoint, PolicyEntry, PolicyKey, enforce, verdict,
    },
};
use flowsdn_bpf_loader::kernel::{Egress, LocalDelivery, Object, socket_lb::SocketLb};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Command, Stdio},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const HOST_ADDR: [u8; 4] = [192, 0, 2, 1];
const ALLOWED: u16 = 7001;
const DENIED: u16 = 7002;
const PEER_PORT: u16 = 7003;
const TCP: u8 = 6;
const WORLD: u32 = 2;
const HOST: u32 = 1;
const TIMEOUT: Duration = Duration::from_secs(2);

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

/// The peer, outside the node: its own namespace; once told `GO`, configure
/// `b0` and listen on [`PEER_PORT`]; then for each `CONNECT <addr>` line
/// print `OK` or `FAIL <error>`.
fn peer() -> Result<()> {
    isolate()?;
    let mut out = std::io::stdout();
    writeln!(out, "READY")?;
    out.flush()?;
    let mut lines = BufReader::new(std::io::stdin()).lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("GO"),
        "peer: expected GO",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["addr", "add", "192.0.2.9/24", "dev", "b0"])?;
    ip(&["link", "set", "b0", "up"])?;
    let listener = TcpListener::bind(("192.0.2.9", PEER_PORT))?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    writeln!(out, "UP")?;
    out.flush()?;
    for line in lines {
        let line = line?;
        let Some(target) = line.strip_prefix("CONNECT ") else {
            break;
        };
        let target: SocketAddr = target.parse()?;
        match TcpStream::connect_timeout(&target, TIMEOUT) {
            Ok(_) => writeln!(out, "OK")?,
            Err(e) => writeln!(out, "FAIL {e}")?,
        }
        out.flush()?;
    }
    Ok(())
}

fn host_rule(delivery: &mut LocalDelivery, identity: u32, port: u16) -> Result<()> {
    let key = PolicyKey::new(identity, false, TCP, port, 16).map_err(|_| "policy key")?;
    let entry =
        PolicyEntry::new(0, false, 24, 0, false, 0xFFFF_FF01, 0).map_err(|_| "policy entry")?;
    delivery
        .policy()
        .upsert_policy(EndpointPolicyKey::for_endpoint(HOST_ENDPOINT, key), entry)
}

fn run(delivery_object: &[u8], lb_object: &[u8]) -> Result<()> {
    isolate()?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("peer")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("peer stdin")?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("peer stdout")?).lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("READY"),
        "peer did not isolate",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["link", "add", "a0", "type", "veth", "peer", "name", "b0"])?;
    ip(&["link", "set", "b0", "netns", &child.id().to_string()])?;
    ip(&["addr", "add", "192.0.2.1/24", "dev", "a0"])?;
    ip(&["link", "set", "a0", "up"])?;
    // `ip -o link` starts with "<ifindex>: a0@…".
    let a0: u32 = ip(&["-o", "link", "show", "dev", "a0"])?
        .split(':')
        .next()
        .map(str::trim)
        .ok_or("no ifindex")?
        .parse()?;

    // As the agent does: the host firewall last, the NodePort programs first.
    let mut delivery = LocalDelivery::load_object(Object::Bytes(delivery_object), Egress::Stack)?;
    delivery.attach_host("a0")?;
    let mut lb = SocketLb::load(Object::Bytes(lb_object), None)?;
    lb.attach_uplink("a0")?;
    let key = IpCacheKey::v4(HOST_ADDR, 32, 0).map_err(|_| "ipcache prefix")?;
    delivery.policy().upsert_ipcache(
        key,
        RemoteEndpointInfo {
            sec_identity: HOST,
            ..Default::default()
        },
    )?;
    host_rule(&mut delivery, WORLD, ALLOWED)?;
    delivery.policy().set_policy_endpoint(
        a0,
        PolicyEndpoint {
            endpoint: HOST_ENDPOINT,
            flags: enforce::INGRESS,
        },
    )?;
    println!(
        "PASS uplink a0: nodeport_ingress/nodeport_egress first, from_netdev/to_netdev last; host ingress enforced, world TCP {ALLOWED} allowed"
    );

    let allowed = TcpListener::bind(("192.0.2.1", ALLOWED))?;
    let denied = TcpListener::bind(("192.0.2.1", DENIED))?;
    writeln!(input, "GO")?;
    ensure(
        lines.next().transpose()?.as_deref() == Some("UP"),
        "peer did not come up",
    )?;
    let mut connect = |port: u16| -> Result<String> {
        writeln!(input, "CONNECT 192.0.2.1:{port}")?;
        input.flush()?;
        Ok(lines.next().transpose()?.ok_or("peer ended")?)
    };

    let got = connect(ALLOWED)?;
    ensure(got == "OK", &format!("peer to host TCP {ALLOWED}: {got}"))?;
    println!("PASS peer connects to the host's allowed TCP {ALLOWED} through both programs");

    let got = connect(DENIED)?;
    ensure(
        got.starts_with("FAIL"),
        &format!(
            "peer to host TCP {DENIED}: {got}: the host firewall did not run after the NodePort program"
        ),
    )?;
    let counted = delivery.policy().policy_verdicts()?.iter().any(|(k, v)| {
        k.endpoint == HOST_ENDPOINT
            && k.egress == 0
            && k.dport.get() == DENIED
            && k.verdict == verdict::DENIED
            && v.packets >= 1
    });
    ensure(counted, &format!("no denied verdict for host TCP {DENIED}"))?;
    println!(
        "PASS peer cannot connect to the host's denied TCP {DENIED} ({got}); the drop is counted"
    );

    let out = TcpStream::connect_timeout(&SocketAddr::from(([192, 0, 2, 9], PEER_PORT)), TIMEOUT);
    ensure(
        out.is_ok(),
        &format!("host to peer TCP {PEER_PORT}: {out:?}: its reply was not let in"),
    )?;
    let host = Some(HOST_ADDR.as_slice());
    let tracked = delivery.policy().policy_flows()?.iter().any(|(k, _)| {
        (k.saddr.get(..4) == host || k.daddr.get(..4) == host)
            && (k.dport.get() == PEER_PORT || k.sport.get() == PEER_PORT)
    });
    ensure(
        tracked,
        &format!(
            "the host's connection to the peer's TCP {PEER_PORT} is not in the policy flow map: to_netdev did not run after nodeport_egress"
        ),
    )?;
    println!(
        "PASS the host's own connection out is tracked by to_netdev after nodeport_egress, and its reply passes enforced ingress"
    );

    drop(input);
    drop((allowed, denied));
    let _ = child.wait();
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: host-chain-live LOCAL_DELIVERY_OBJECT SOCKET_LB_OBJECT")?;
    if first == "peer" {
        return peer();
    }
    let second = args
        .next()
        .ok_or("usage: host-chain-live LOCAL_DELIVERY_OBJECT SOCKET_LB_OBJECT")?;
    let delivery = std::fs::read(&first)?;
    let lb = std::fs::read(&second)?;
    run(&delivery, &lb)
}
