//! Several uplinks on a real kernel (#408), in an anonymous network namespace.
//! Two veth uplinks (u0 .203 and u1 .204 on 192.0.2.0/24) go through the
//! agent's own discovery, plan and kernel code (`flowsdn_agent::uplinks`).
//! The fixture checks that:
//! * both are uplinks, and per-flow ECMP to another node's pod CIDR uses both;
//! * each address leaves through its own port (source rules);
//! * a port that loses carrier is skipped at once, and its address is held as
//!   a /32 by the live port with a gratuitous ARP;
//! * a port whose carrier returns spreads flows again, twice over;
//! * `single` removes every rule and table entry flowsdn made.
//!
//! It needs iproute2 and root, as kernel-check gives it.
use flowsdn_agent::uplinks::{self, Mode, Settings, Uplink, View, apply};
use flowsdn_connector::{Connector, multihome};
use nix::sched::{CloneFlags, unshare};
use std::{
    collections::BTreeSet,
    error::Error,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::Command,
    time::{Duration, Instant},
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

const NODE: &str = "192.0.2.203";
const SECOND: &str = "192.0.2.204";
const GATEWAY: &str = "192.0.2.1";
const PEER: &str = "192.0.2.21";
const POD_CIDR: &str = "10.9.0.0";

fn addr(text: &str) -> Result<IpAddr> {
    Ok(text.parse()?)
}

fn wait_carrier(name: &str, up: bool) -> Result<()> {
    let start = Instant::now();
    let want = if up { "1" } else { "0" };
    while start.elapsed() < Duration::from_secs(5) {
        let now = std::fs::read_to_string(format!("/sys/class/net/{name}/carrier"))
            .map(|c| c.trim().to_owned())
            .unwrap_or_else(|_| "0".into());
        if now == want {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!("{name} carrier never became {want}").into())
}

/// The ports, uplinks and moves as the monitor computes them.
fn plan(connector: &Connector, settings: &Settings) -> Result<(Vec<Uplink>, Vec<uplinks::Move>)> {
    let ports = apply::read_ports(connector, &[])?;
    let found = uplinks::select(&ports, &[addr(NODE)?], settings);
    let moves = uplinks::moves(&found, settings.mode);
    Ok((found, moves))
}

/// Apply the plan as the monitor does: host addresses, rules, tables and the
/// direct route to the peer's pod CIDR.
fn apply_plan(
    connector: &Connector,
    settings: &Settings,
    found: &[Uplink],
    moves: &[uplinks::Move],
    held: &mut Vec<uplinks::Move>,
) -> Result<()> {
    for gone in held.iter().filter(|m| !moves.contains(m)) {
        connector.delete_address(gone.to_index, gone.address, gone.prefix())?;
    }
    for new in moves.iter().filter(|m| !held.contains(m)) {
        connector.add_address(new.to_index, new.address, new.prefix())?;
        if let IpAddr::V4(v4) = new.address {
            multihome::gratuitous_arp(new.to_index, new.to_mac, v4)?;
        }
    }
    *held = moves.to_vec();
    let desired = uplinks::desired(found, moves, settings, &apply::default_gateways(connector));
    apply::reconcile_kernel(connector, settings, &desired)?;
    let view = View {
        started: true,
        mode: settings.mode,
        uplinks: found.to_vec(),
        ..View::default()
    };
    match view.hops(&[addr(PEER)?]) {
        Some(hops) => connector.replace_multipath_route(addr(POD_CIDR)?, 16, &hops, 254, None, None)?,
        None => connector.replace_gateway_route(addr(POD_CIDR)?, 16, addr(PEER)?)?,
    }
    Ok(())
}

/// The devices `ip route get` picks for 64 TCP flows to the pod CIDR.
fn flow_devices() -> Result<BTreeSet<String>> {
    let mut devices = BTreeSet::new();
    for sport in 20_000u16..20_064 {
        let out = ip(&[
            "-4", "route", "get", "10.9.1.1", "ipproto", "tcp", "sport", &sport.to_string(),
            "dport", "80",
        ])?;
        if let Some(dev) = out
            .split_whitespace()
            .skip_while(|w| *w != "dev")
            .nth(1)
        {
            devices.insert(dev.to_owned());
        }
    }
    Ok(devices)
}

fn device_from(source: &str) -> Result<String> {
    let out = ip(&["-4", "route", "get", "192.0.2.50", "from", source])?;
    Ok(out
        .split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .unwrap_or_default()
        .to_owned())
}

fn names(found: &[Uplink]) -> Vec<(String, bool)> {
    found.iter().map(|u| (u.name.clone(), u.up)).collect()
}

fn run() -> Result<()> {
    let before = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    ensure(
        std::fs::read_link("/proc/self/ns/net")? != before,
        "namespace isolation failed",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    for (u, p) in [("u0", "p0"), ("u1", "p1")] {
        ip(&["link", "add", u, "type", "veth", "peer", "name", p])?;
    }
    ip(&["addr", "add", &format!("{NODE}/24"), "dev", "u0"])?;
    ip(&["addr", "add", &format!("{SECOND}/24"), "dev", "u1"])?;
    for dev in ["u0", "u1", "p0", "p1"] {
        ip(&["link", "set", dev, "up"])?;
    }
    wait_carrier("u0", true)?;
    wait_carrier("u1", true)?;
    // The boot uplink's default route, as stormpump leaves it.
    ip(&["route", "add", "default", "via", GATEWAY, "dev", "u0"])?;
    let connector = Connector::open()?;
    let settings = Settings::default();

    let (found, moves) = plan(&connector, &settings)?;
    ensure(
        names(&found) == [("u0".to_owned(), true), ("u1".to_owned(), true)],
        &format!("uplinks {:?}, want u0 and u1 up", names(&found)),
    )?;
    ensure(moves.is_empty(), "nothing moves with both up")?;
    for uplink in &found {
        let failed = apply::tune(Path::new("/proc/sys"), &uplink.name, &[addr(NODE)?]);
        ensure(failed.is_empty(), &format!("sysctls: {failed:?}"))?;
    }
    let mut held = Vec::new();
    apply_plan(&connector, &settings, &found, &moves, &mut held)?;
    let route = ip(&["-4", "route", "show", "10.9.0.0/16"])?;
    ensure(
        route.matches("nexthop").count() == 2,
        &format!("want a two-path ECMP route, got: {route}"),
    )?;
    let rules: Vec<_> = connector
        .rules(false)?
        .into_iter()
        .filter(|r| settings.owns_priority(r.priority))
        .collect();
    ensure(rules.len() == 6, &format!("want 6 flowsdn rules, got {rules:?}"))?;
    println!("both up: ECMP route, {} rules", rules.len());

    for round in 1..=2 {
        let spread = flow_devices()?;
        ensure(
            spread == BTreeSet::from(["u0".to_owned(), "u1".to_owned()]),
            &format!("round {round}: 64 flows used {spread:?}, want both ports"),
        )?;
        ensure(device_from(NODE)? == "u0", "the node address leaves through u0")?;
        ensure(device_from(SECOND)? == "u1", "the second address leaves through u1")?;
        println!("round {round}: both up, 64 flows over u0 and u1, each address on its port");

        // u1 loses carrier.
        ip(&["link", "set", "p1", "down"])?;
        wait_carrier("u1", false)?;
        // The kernel skips its paths before the agent does anything.
        let early = flow_devices()?;
        ensure(
            early == BTreeSet::from(["u0".to_owned()]),
            &format!("round {round}: with u1 down, flows used {early:?}"),
        )?;
        let (found, moves) = plan(&connector, &settings)?;
        ensure(
            names(&found) == [("u0".to_owned(), true), ("u1".to_owned(), false)],
            &format!("round {round}: uplinks {:?}", names(&found)),
        )?;
        let changes = uplinks::changes(&[], &found, "t");
        ensure(changes.len() == 1, "only u0 counts as joined from nothing")?;
        ensure(
            moves.len() == 1 && moves.first().is_some_and(|m| m.to == "u0"),
            &format!("round {round}: moves {moves:?}"),
        )?;
        apply_plan(&connector, &settings, &found, &moves, &mut held)?;
        let on_u0 = ip(&["-4", "addr", "show", "dev", "u0"])?;
        ensure(
            on_u0.contains(&format!("{SECOND}/32")),
            &format!("round {round}: {SECOND}/32 not on u0: {on_u0}"),
        )?;
        ensure(
            device_from(SECOND)? == "u0",
            "the second address follows its failover to u0",
        )?;
        ensure(flow_devices()? == BTreeSet::from(["u0".to_owned()]), "u0 only")?;
        // The monitor must not see its own /32 as a port address.
        let ports = apply::read_ports(&connector, &held)?;
        ensure(
            !ports.iter().any(|p| {
                p.name == "u0" && p.addresses.iter().any(|(a, len)| a.to_string() == SECOND && *len == 32)
            }),
            "the failover /32 is excluded from discovery",
        )?;
        println!("round {round}: u1 down, flows on u0, {SECOND}/32 on u0 with gratuitous ARP");

        // u1 returns.
        ip(&["link", "set", "p1", "up"])?;
        wait_carrier("u1", true)?;
        let (found, moves) = plan(&connector, &settings)?;
        ensure(moves.is_empty(), "nothing moves once u1 is back")?;
        apply_plan(&connector, &settings, &found, &moves, &mut held)?;
        let on_u0 = ip(&["-4", "addr", "show", "dev", "u0"])?;
        ensure(
            !on_u0.contains(&format!("{SECOND}/32")),
            "the failover /32 is removed",
        )?;
        multihome::gratuitous_arp(
            found.iter().find(|u| u.name == "u1").map_or(0, |u| u.index),
            found.iter().find(|u| u.name == "u1").map_or([0; 6], |u| u.mac),
            SECOND.parse::<Ipv4Addr>()?,
        )?;
        println!("round {round}: u1 back, /32 removed, announced from u1");
    }
    let spread = flow_devices()?;
    ensure(spread.len() == 2, "flows spread over both after the last return")?;

    // FEC on a veth: no FEC, not an error.
    ensure(multihome::fec("u0")?.is_none(), "a veth has no FEC")?;

    // single: flowsdn's rules and tables go.
    let single = Settings {
        mode: Mode::Single,
        ..Settings::default()
    };
    let (found, moves) = plan(&connector, &single)?;
    apply_plan(&connector, &single, &found, &moves, &mut held)?;
    ensure(
        !connector.rules(false)?.iter().any(|r| settings.owns_priority(r.priority)),
        "single leaves no flowsdn rule",
    )?;
    for table in settings.tables() {
        ensure(
            connector.table_routes(table, false)?.is_empty(),
            &format!("table {table} is empty under single"),
        )?;
    }
    connector.delete_owned_route(addr(POD_CIDR)?, 16, 254, None)?;
    ensure(
        ip(&["-4", "route", "show", "10.9.0.0/16"])?.trim().is_empty(),
        "the direct route is deleted",
    )?;
    println!("single: no rules, no tables, direct route deleted");
    Ok(())
}

fn main() -> Result<()> {
    run()
}
