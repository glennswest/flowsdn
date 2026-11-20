//! The XDP prefilter on a real kernel (#467), in anonymous network
//! namespaces, with the local-delivery object:
//! * `xdp_prefilter` test runs: a denied IPv4/IPv6 source drops, through the
//!   host-prefix hash maps and the LPM tries; other sources, ARP and short
//!   frames pass; removing an entry passes its source again;
//! * attached to a veth uplink `a0` as the agent attaches it (native, else
//!   generic): UDP from a peer namespace arrives while its source is
//!   allowed and does not while it is denied.
//!
//! Usage: `prefilter-live LOCAL_DELIVERY_OBJECT`. It needs iproute2 and
//! root, as kernel-check gives it.
use aya::programs::{TestRun, TestRunOptions};
use flowsdn_bpf_loader::kernel::{Egress, LocalDelivery, Object};
use nix::sched::{CloneFlags, unshare};
use std::{
    error::Error,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, UdpSocket},
    process::{Command, Stdio},
    time::Duration,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;

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

/// An Ethernet frame with an IP header from `source` (UDP, no payload).
fn frame(source: IpAddr) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
    match source {
        IpAddr::V4(v4) => {
            frame.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0]);
            frame.extend_from_slice(&v4.octets());
            frame.extend_from_slice(&[192, 0, 2, 1]);
            frame.extend_from_slice(&[0x9c, 0x40, 0x1b, 0x58, 0, 8, 0, 0]);
        }
        IpAddr::V6(v6) => {
            frame.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64]);
            frame.extend_from_slice(&v6.octets());
            frame.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            frame.extend_from_slice(&[0x9c, 0x40, 0x1b, 0x58, 0, 8, 0, 0]);
        }
    }
    frame
}

fn verdict(delivery: &mut LocalDelivery, data: &[u8]) -> Result<u32> {
    let mut out = vec![0u8; 256];
    let result = delivery.prefilter_program()?.test_run(TestRunOptions {
        data_in: Some(data),
        data_out: Some(&mut out),
        repeat: 1,
        ..Default::default()
    })?;
    Ok(result.return_value)
}

fn expect(delivery: &mut LocalDelivery, what: &str, data: &[u8], want: u32) -> Result<()> {
    let got = verdict(delivery, data)?;
    let name = |v| match v {
        XDP_DROP => "drop",
        XDP_PASS => "pass",
        _ => "other",
    };
    ensure(
        got == want,
        &format!("{what}: {} ({got}) instead of {}", name(got), name(want)),
    )
}

fn test_runs(delivery: &mut LocalDelivery) -> Result<()> {
    let maps = delivery.prefilter()?;
    maps.clear()?;
    maps.insert(addr("203.0.113.9"), 32)?;
    maps.insert(addr("198.51.100.77"), 24)?;
    maps.insert(addr("2001:db8:9::5"), 128)?;
    maps.insert(addr("2001:db8:7::"), 48)?;
    let listed = maps.entries()?;
    ensure(
        listed
            == vec![
                (addr("198.51.100.0"), 24),
                (addr("203.0.113.9"), 32),
                (addr("2001:db8:7::"), 48),
                (addr("2001:db8:9::5"), 128),
            ],
        &format!("entries {listed:?}"),
    )?;
    for (what, source, want) in [
        ("v4 host prefix", "203.0.113.9", XDP_DROP),
        ("v4 next to the host prefix", "203.0.113.10", XDP_PASS),
        ("v4 inside a /24", "198.51.100.200", XDP_DROP),
        ("v4 outside", "192.0.2.50", XDP_PASS),
        ("v6 host prefix", "2001:db8:9::5", XDP_DROP),
        ("v6 inside a /48", "2001:db8:7:1::9", XDP_DROP),
        ("v6 outside", "2001:db8:8::1", XDP_PASS),
    ] {
        expect(delivery, what, &frame(addr(source)), want)?;
    }
    let mut arp = vec![0xffu8; 6];
    arp.extend_from_slice(&[2, 0, 0, 0, 0, 2, 0x08, 0x06]);
    arp.resize(42, 0);
    expect(delivery, "ARP", &arp, XDP_PASS)?;
    let mut short = frame(addr("203.0.113.9"));
    short.truncate(20);
    expect(
        delivery,
        "a frame too short for its source",
        &short,
        XDP_PASS,
    )?;
    println!(
        "PASS test runs: denied v4/v6 sources drop through the hash and LPM maps; other sources, ARP and short frames pass"
    );
    let maps = delivery.prefilter()?;
    maps.remove(addr("198.51.100.0"), 24)?;
    maps.remove(addr("2001:db8:9::5"), 128)?;
    expect(
        delivery,
        "removed v4 /24",
        &frame(addr("198.51.100.200")),
        XDP_PASS,
    )?;
    expect(
        delivery,
        "removed v6 /128",
        &frame(addr("2001:db8:9::5")),
        XDP_PASS,
    )?;
    expect(
        delivery,
        "kept v4 /32",
        &frame(addr("203.0.113.9")),
        XDP_DROP,
    )?;
    delivery.prefilter()?.clear()?;
    ensure(
        delivery.prefilter()?.entries()?.is_empty(),
        "clear left entries",
    )?;
    expect(delivery, "cleared", &frame(addr("203.0.113.9")), XDP_PASS)?;
    println!("PASS removing an entry passes its source again; clear empties all four maps");
    Ok(())
}

/// The peer: its own namespace; on `GO` it configures `b0` (192.0.2.9);
/// then each `SEND` line sends one UDP datagram to 192.0.2.1:7000.
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
    let socket = UdpSocket::bind("192.0.2.9:0")?;
    writeln!(out, "UP")?;
    out.flush()?;
    for line in lines {
        if line? == "SEND" {
            let _ = socket.send_to(b"prefilter", "192.0.2.1:7000");
            writeln!(out, "SENT")?;
            out.flush()?;
        }
    }
    Ok(())
}

fn attached(delivery: &mut LocalDelivery) -> Result<()> {
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
    let mode = delivery.attach_prefilter("a0")?;
    ensure(
        delivery
            .prefilter_interfaces()
            .any(|(n, m)| n == "a0" && m == mode),
        "a0 not listed as attached",
    )?;
    writeln!(input, "GO")?;
    input.flush()?;
    ensure(
        lines.next().transpose()?.as_deref() == Some("UP"),
        "peer did not come up",
    )?;
    let server = UdpSocket::bind("192.0.2.1:7000")?;
    server.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut send = |input: &mut std::process::ChildStdin| -> Result<bool> {
        writeln!(input, "SEND")?;
        input.flush()?;
        ensure(
            lines.next().transpose()?.as_deref() == Some("SENT"),
            "peer did not send",
        )?;
        let mut buffer = [0u8; 64];
        Ok(server.recv_from(&mut buffer).is_ok())
    };
    ensure(send(&mut input)?, "allowed UDP did not arrive")?;
    delivery.prefilter()?.insert(addr("192.0.2.9"), 32)?;
    ensure(!send(&mut input)?, "UDP from a denied source arrived")?;
    delivery.prefilter()?.remove(addr("192.0.2.9"), 32)?;
    ensure(
        send(&mut input)?,
        "UDP did not arrive after the source was allowed again",
    )?;
    println!(
        "PASS attached to a0 ({mode} XDP): a denied source's UDP is dropped, an allowed one arrives"
    );
    delivery.detach_prefilter("a0");
    ensure(
        delivery.prefilter_interfaces().next().is_none(),
        "detach left a link",
    )?;
    drop(input);
    let _ = child.wait();
    println!("PASS detached");
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: prefilter-live LOCAL_DELIVERY_OBJECT")?;
    if first == "peer" {
        return peer();
    }
    isolate()?;
    let object = std::fs::read(&first)?;
    let mut delivery = LocalDelivery::load_object(Object::Bytes(&object), Egress::Stack)?;
    test_runs(&mut delivery)?;
    attached(&mut delivery)
}
