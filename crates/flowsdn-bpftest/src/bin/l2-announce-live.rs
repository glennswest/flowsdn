//! L2 announcement answers on a real kernel (#475). Two network namespaces
//! joined by a veth pair: this process holds `a0` and answers for
//! 192.0.2.240 and 2001:db8:30::f0 with `flowsdn_connector::announce` (the
//! agent's responder sockets and answers), never adding them to the host. A
//! worker in the other namespace (`b0`, 192.0.2.9 and 2001:db8:30::9) sends
//! UDP to them, so its kernel resolves them by ARP and Neighbor
//! Solicitation. The fixture checks that:
//! * the worker's kernel takes the ARP reply and the Neighbor Advertisement
//!   (hop limit, checksum, option) and holds `a0`'s MAC for both addresses;
//! * an address that is not announced (192.0.2.241) stays unresolved;
//! * `a0`'s own kernel never holds the addresses;
//! * an unsolicited Neighbor Advertisement (`multihome::unsolicited_na`, the
//!   uplink monitor's IPv6 failover announcement, #497) with another MAC
//!   moves the worker's entry for 2001:db8:30::f0 to that MAC.
//!
//! It needs iproute2 and root, as kernel-check gives it.
use flowsdn_connector::{
    announce::{self, ETH_P_ARP, ETH_P_IPV6, Socket},
    multihome,
};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, UdpSocket},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
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

const ANNOUNCED: [&str; 2] = ["192.0.2.240", "2001:db8:30::f0"];
const NOT_ANNOUNCED: &str = "192.0.2.241";
/// The MAC the unsolicited NA moves 2001:db8:30::f0 to (#497).
const MOVED_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x04, 0x97];
const MOVED_TEXT: &str = "02:00:00:00:04:97";

/// `ip link show` of `name`'s MAC, as text.
fn mac_text(name: &str) -> Result<String> {
    let out = ip(&["-o", "link", "show", "dev", name])?;
    out.split_whitespace()
        .skip_while(|w| *w != "link/ether")
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| format!("no MAC in {out}").into())
}

/// The worker: its own namespace; once told `GO`, configure `b0`, make the
/// kernel resolve each address and print `NEIGH <ip> <ip neigh line>`.
fn worker() -> Result<()> {
    isolate()?;
    let mut out = std::io::stdout();
    writeln!(out, "READY")?;
    out.flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    ensure(line.trim() == "GO", "worker: expected GO")?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["addr", "add", "192.0.2.9/24", "dev", "b0"])?;
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:30::9/64",
        "dev",
        "b0",
        "nodad",
    ])?;
    ip(&["link", "set", "b0", "up"])?;
    let v4 = UdpSocket::bind("0.0.0.0:0")?;
    let v6 = UdpSocket::bind("[::]:0")?;
    for target in ANNOUNCED.into_iter().chain([NOT_ANNOUNCED]) {
        let address: IpAddr = target.parse()?;
        let socket = if address.is_ipv4() { &v4 } else { &v6 };
        let start = Instant::now();
        let mut neigh = String::new();
        while start.elapsed() < Duration::from_secs(4) {
            // Each send asks the kernel to resolve the address; the send
            // itself may fail while the entry is incomplete.
            let _ = socket.send_to(b"flowsdn", (address, 9));
            std::thread::sleep(Duration::from_millis(200));
            neigh = ip(&["neigh", "show", target, "dev", "b0"])?
                .trim()
                .to_owned();
            if neigh.contains("lladdr") {
                break;
            }
        }
        writeln!(out, "NEIGH {target} {neigh}")?;
        out.flush()?;
    }
    // The unsolicited NA (#497): the parent sends it, then says which MAC
    // the entry must now hold.
    writeln!(out, "RESOLVED")?;
    out.flush()?;
    line.clear();
    std::io::stdin().read_line(&mut line)?;
    let moved = line
        .trim()
        .strip_prefix("CHECK ")
        .ok_or("worker: expected CHECK")?
        .to_owned();
    let start = Instant::now();
    let mut neigh = String::new();
    while start.elapsed() < Duration::from_secs(3) {
        neigh = ip(&["neigh", "show", ANNOUNCED[1], "dev", "b0"])?
            .trim()
            .to_owned();
        if neigh.contains(&format!("lladdr {moved}")) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    writeln!(out, "AFTER {neigh}")?;
    writeln!(out, "DONE")?;
    out.flush()?;
    Ok(())
}

fn run() -> Result<()> {
    isolate()?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().ok_or("worker stdin")?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("worker stdout")?).lines();
    ensure(
        lines.next().transpose()?.as_deref() == Some("READY"),
        "worker did not isolate",
    )?;
    ip(&["link", "set", "lo", "up"])?;
    ip(&["link", "add", "a0", "type", "veth", "peer", "name", "b0"])?;
    ip(&["link", "set", "b0", "netns", &child.id().to_string()])?;
    ip(&["addr", "add", "192.0.2.1/24", "dev", "a0"])?;
    ip(&[
        "-6",
        "addr",
        "add",
        "2001:db8:30::1/64",
        "dev",
        "a0",
        "nodad",
    ])?;
    ip(&["link", "set", "a0", "up"])?;
    // `ip -o link` starts with "<ifindex>: a0@…": sysfs shows the namespace
    // it was mounted in, not this one.
    let link = ip(&["-o", "link", "show", "dev", "a0"])?;
    let index: u32 = link
        .split(':')
        .next()
        .map(str::trim)
        .ok_or("no ifindex")?
        .parse()?;
    let mac_string = mac_text("a0")?;
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(mac_string.split(':')) {
        *slot = u8::from_str_radix(part, 16)?;
    }
    let addresses: Vec<IpAddr> = ANNOUNCED
        .iter()
        .map(|a| a.parse())
        .collect::<std::result::Result<_, _>>()?;
    let arp = Socket::open(index, ETH_P_ARP)?;
    let nd = Socket::open(index, ETH_P_IPV6)?;
    for address in &addresses {
        if let IpAddr::V6(v6) = address {
            nd.membership(announce::solicited_node_mac(*v6), true)?;
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let answered = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let responder = {
        let (stop, answered, addresses) =
            (Arc::clone(&stop), Arc::clone(&answered), addresses.clone());
        std::thread::spawn(move || -> Result<()> {
            while !stop.load(Ordering::SeqCst) {
                Socket::wait(&[&arp, &nd], Duration::from_millis(100))?;
                for (slot, socket) in [&arp, &nd].into_iter().enumerate() {
                    while let Some(received) = socket.receive()? {
                        if let Some((to, reply)) =
                            announce::answer(socket.protocol, &received, &addresses, mac)
                        {
                            socket.send(to, &reply)?;
                            if let Some(count) = answered.get(slot) {
                                count.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    };
    writeln!(input, "GO")?;
    input.flush()?;
    let mut neighbours = Vec::new();
    let mut after = None;
    for line in lines.by_ref() {
        let line = line?;
        if line == "DONE" {
            break;
        }
        if let Some(rest) = line.strip_prefix("NEIGH ") {
            neighbours.push(rest.to_owned());
        }
        if line == "RESOLVED" {
            let target: std::net::Ipv6Addr = ANNOUNCED[1].parse()?;
            for _ in 0..3 {
                multihome::unsolicited_na(index, MOVED_MAC, target)?;
                std::thread::sleep(Duration::from_millis(100));
            }
            writeln!(input, "CHECK {MOVED_TEXT}")?;
            input.flush()?;
        }
        if let Some(rest) = line.strip_prefix("AFTER ") {
            after = Some(rest.to_owned());
        }
    }
    stop.store(true, Ordering::SeqCst);
    let joined = responder.join().map_err(|_| "responder panicked")?;
    let _ = child.wait();
    joined?;
    for target in ANNOUNCED {
        let entry = neighbours
            .iter()
            .find(|n| n.starts_with(&format!("{target} ")))
            .ok_or_else(|| format!("no neighbour line for {target}"))?;
        ensure(
            entry.contains(&format!("lladdr {mac_string}")),
            &format!("{target} not resolved to a0 ({mac_string}): {entry}"),
        )?;
        println!("{target}: worker's kernel holds {mac_string} ({entry})");
    }
    let other = neighbours
        .iter()
        .find(|n| n.starts_with(&format!("{NOT_ANNOUNCED} ")))
        .ok_or("no neighbour line for the unannounced address")?;
    ensure(
        !other.contains("lladdr"),
        &format!("{NOT_ANNOUNCED} must stay unresolved: {other}"),
    )?;
    let counts: Vec<usize> = answered.iter().map(|c| c.load(Ordering::SeqCst)).collect();
    ensure(
        counts.iter().all(|c| *c > 0),
        &format!("answers sent (ARP, NA): {counts:?}"),
    )?;
    for (family, target) in [("-4", ANNOUNCED[0]), ("-6", ANNOUNCED[1])] {
        let held = ip(&[family, "addr", "show"])?;
        ensure(
            !held.contains(target),
            &format!("{target} must not be a host address"),
        )?;
    }
    let after = after.ok_or("no neighbour line after the unsolicited NA")?;
    ensure(
        after.contains(&format!("lladdr {MOVED_TEXT}")),
        &format!(
            "the unsolicited NA must move {} to {MOVED_TEXT}: {after}",
            ANNOUNCED[1]
        ),
    )?;
    println!(
        "{}: an unsolicited NA moved the worker's entry to {MOVED_TEXT} ({after})",
        ANNOUNCED[1]
    );
    println!("{NOT_ANNOUNCED}: unresolved; answers sent (ARP, NA): {counts:?}; no address added");
    Ok(())
}

fn main() {
    let worker_mode = std::env::args().nth(1).as_deref() == Some("worker");
    let result = if worker_mode { worker() } else { run() };
    match result {
        Ok(()) => {
            if !worker_mode {
                println!("PASS: l2-announce-live");
            }
        }
        Err(error) => {
            eprintln!("FAIL: l2-announce-live: {error}");
            std::process::exit(1);
        }
    }
}
