//! Managed neighbors on a real kernel (#469, spec 10 §3.4), in anonymous
//! network namespaces: this process holds uplink `a0` (192.0.2.1/24, a
//! route to 198.51.100.0/24 via 192.0.2.9); a peer in a namespace of its own
//! holds `b0` with 192.0.2.9 and 192.0.2.20. The fixture checks that:
//! * the startup probe for managed neighbors passes;
//! * next hops come from FIB-match route lookups: the gateway for a routed
//!   address, the address itself on-link, none when unreachable;
//! * the agent's reconcile makes managed (`NTF_EXT_LEARNED` +
//!   `NTF_EXT_MANAGED`) entries for them, removes a stray learned entry and
//!   leaves an administrator's static entry alone;
//! * the kernel resolves a managed entry by itself (the peer's MAC appears);
//! * an address no longer forwardable loses its entry on the next reconcile.
//!
//! It needs iproute2 and root, as kernel-check gives it.
use flowsdn_agent::neighbors::{self, Inputs};
use flowsdn_connector::{Connector, neighbor::Lookup};
use nix::sched::{CloneFlags, unshare};
use std::{
    collections::BTreeMap,
    error::Error,
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

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

fn addr(text: &str) -> IpAddr {
    text.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

/// The peer: its own namespace; once told `GO`, `b0` up with the gateway
/// and the on-link host addresses, then `UP`, then wait for stdin to close.
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
    ip(&["addr", "add", "192.0.2.20/24", "dev", "b0"])?;
    ip(&["link", "set", "b0", "up"])?;
    let mac = ip(&["-o", "link", "show", "dev", "b0"])?;
    let mac = mac
        .split_whitespace()
        .skip_while(|w| *w != "link/ether")
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    writeln!(out, "UP {mac}")?;
    out.flush()?;
    for line in lines {
        line?;
    }
    Ok(())
}

fn run() -> Result<()> {
    isolate()?;
    neighbors::probe()?;
    println!("PASS the managed-neighbor probe passes on this kernel");

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
    writeln!(input, "GO")?;
    input.flush()?;
    let up = lines.next().transpose()?.unwrap_or_default();
    let peer_mac = up
        .strip_prefix("UP ")
        .ok_or_else(|| format!("peer: {up}"))?
        .to_owned();
    ip(&["route", "add", "198.51.100.0/24", "via", "192.0.2.9", "dev", "a0"])?;
    let a0: u32 = ip(&["-o", "link", "show", "dev", "a0"])?
        .split(':')
        .next()
        .map(str::trim)
        .ok_or("no ifindex")?
        .parse()?;
    let connector = Connector::open()?;

    let routed = connector.next_hops(addr("198.51.100.7"), a0)?;
    ensure(
        routed == Lookup::Hops(vec![addr("192.0.2.9")]),
        &format!("198.51.100.7 on a0: {routed:?}"),
    )?;
    let on_link = connector.next_hops(addr("192.0.2.20"), a0)?;
    ensure(
        on_link == Lookup::Hops(vec![addr("192.0.2.20")]),
        &format!("192.0.2.20 on a0: {on_link:?}"),
    )?;
    let nowhere = connector.next_hops(addr("203.0.113.1"), a0)?;
    ensure(
        nowhere == Lookup::Unreachable,
        &format!("203.0.113.1 on a0: {nowhere:?}"),
    )?;
    println!("PASS next hops by FIB match: gateway for a routed address, the address on-link, none unreachable");

    // An administrator's static entry, and a stray learned one.
    ip(&[
        "neigh", "add", "192.0.2.50", "dev", "a0", "lladdr", "02:00:00:00:00:50", "nud",
        "permanent",
    ])?;
    ip(&[
        "neigh", "add", "192.0.2.77", "dev", "a0", "lladdr", "02:00:00:00:00:77",
        "extern_learn",
    ])?;
    let mut inputs = Inputs {
        forwardable: [
            addr("198.51.100.7"),
            addr("192.0.2.20"),
            addr("203.0.113.1"),
        ]
        .into_iter()
        .collect(),
        devices: BTreeMap::from([(a0, "a0".to_owned())]),
    };
    let outcome = neighbors::reconcile(&connector, &inputs);
    ensure(outcome.errors.is_empty(), &format!("{:?}", outcome.errors))?;
    let want: std::collections::BTreeSet<(u32, IpAddr)> =
        [(a0, addr("192.0.2.9")), (a0, addr("192.0.2.20"))]
            .into_iter()
            .collect();
    ensure(outcome.desired == want, &format!("desired {:?}", outcome.desired))?;
    ensure(outcome.unreachable == 1, "one unreachable address")?;
    ensure(
        outcome.removed == vec![(a0, addr("192.0.2.77"))],
        &format!("removed {:?}", outcome.removed),
    )?;
    for hop in ["192.0.2.9", "192.0.2.20"] {
        ensure(
            connector.is_managed(a0, addr(hop))?,
            &format!("{hop} on a0 is not a managed, learned entry"),
        )?;
    }
    ensure(
        ip(&["neigh", "show", "192.0.2.50", "dev", "a0"])?.contains("PERMANENT"),
        "the static entry was touched",
    )?;
    ensure(
        ip(&["neigh", "show", "192.0.2.77", "dev", "a0"])?.trim().is_empty(),
        "the stray learned entry is still there",
    )?;
    println!(
        "PASS reconcile: managed entries for both next hops, the stray learned entry removed, the static entry kept"
    );

    let start = Instant::now();
    let mut seen = String::new();
    while start.elapsed() < Duration::from_secs(20) {
        seen = ip(&["neigh", "show", "192.0.2.9", "dev", "a0"])?;
        if seen.contains(&peer_mac) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    ensure(
        seen.contains(&peer_mac),
        &format!("the kernel did not resolve the managed entry to {peer_mac}: {seen}"),
    )?;
    println!(
        "PASS the kernel resolved the managed entry by itself: {}",
        seen.trim()
    );

    inputs.forwardable.remove(&addr("192.0.2.20"));
    let outcome = neighbors::reconcile(&connector, &inputs);
    ensure(outcome.errors.is_empty(), &format!("{:?}", outcome.errors))?;
    ensure(
        outcome.removed == vec![(a0, addr("192.0.2.20"))],
        &format!("removed {:?}", outcome.removed),
    )?;
    ensure(
        connector.is_managed(a0, addr("192.0.2.9"))?,
        "the gateway entry was lost",
    )?;
    println!("PASS an address no longer forwardable loses its entry; the others stay");

    drop(input);
    let _ = child.wait();
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("peer") {
        return peer();
    }
    run()
}
