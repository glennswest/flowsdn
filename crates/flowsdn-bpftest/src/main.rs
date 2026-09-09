//! Privileged self-test of the Rust BPF build and kernel execution path.
use std::{
    error::Error, io::ErrorKind, net::UdpSocket, path::Path, process::Command, time::Duration,
};

use aya::{
    Ebpf,
    maps::{Array, MapData},
    programs::{SchedClassifier, TcAttachType, TestRun, TestRunOptions},
};
use nix::sched::{CloneFlags, unshare};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err(
            "usage: flowsdn-bpftest PATH_TO_SMOKE_OBJECT (requires network/BPF privileges)".into(),
        );
    }
    let path = Path::new(args.first().ok_or("missing object")?);
    // Single-threaded process: enter a fresh anonymous namespace before any
    // link changes. It disappears on exit, including error and panic paths.
    let previous = std::fs::read_link("/proc/self/ns/net")?;
    unshare(CloneFlags::CLONE_NEWNET)?;
    require(
        std::fs::read_link("/proc/self/ns/net")? != previous,
        "network namespace did not change",
    )?;
    require(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()?
            .success(),
        "could not enable isolated loopback",
    )?;

    let mut bpf = Ebpf::load_file(path)?;
    let mut state: Array<MapData, u32> =
        Array::try_from(bpf.take_map("SMOKE_STATE").ok_or("missing smoke map")?)?;
    require(state.len() == 2, "unexpected smoke map layout")?;
    let program: &mut SchedClassifier = bpf
        .program_mut("smoke")
        .ok_or("missing smoke program")?
        .try_into()?;
    program.load()?;

    for size in [64_usize, 128, 1500] {
        let mut input = vec![0_u8; size];
        input
            .get_mut(12..14)
            .ok_or("short fixture")?
            .copy_from_slice(&[0x08, 0x00]);
        *input.get_mut(14).ok_or("short fixture")? = 0x45;
        for verdict in [0_u32, 2] {
            state.set(0, 0, 0)?;
            state.set(1, verdict, 0)?;
            let mut output = vec![0_u8; size.checked_add(256).ok_or("fixture overflow")?];
            let result = program.test_run(TestRunOptions {
                data_in: Some(&input),
                data_out: Some(&mut output),
                repeat: 1,
                ..Default::default()
            })?;
            require(result.return_value == verdict, "incorrect test-run verdict")?;
            require(
                result.data_size_out == u32::try_from(size)?,
                "incorrect test-run output length",
            )?;
            require(
                output.get(..size) == Some(input.as_slice()),
                "test-run changed packet bytes",
            )?;
            require(
                state.get(&0, 0)? == u32::try_from(size)?,
                "BPF map did not observe input length",
            )?;
        }
    }
    println!("PASS: six kernel packet round trips, pass/drop verdicts and map observations");

    // No host interface or persistent pin is touched. Kernel 6.6+ uses TCX.
    require(
        SchedClassifier::query_tcx("lo", TcAttachType::Ingress)?
            .1
            .is_empty(),
        "new namespace has unexpected attachments",
    )?;
    let link = program.attach("lo", TcAttachType::Ingress)?;
    require(
        SchedClassifier::query_tcx("lo", TcAttachType::Ingress)?
            .1
            .len()
            == 1,
        "TCX attachment missing",
    )?;
    let receiver = UdpSocket::bind("127.0.0.1:0")?;
    receiver.set_read_timeout(Some(Duration::from_millis(250)))?;
    let sender = UdpSocket::bind("127.0.0.1:0")?;
    sender.connect(receiver.local_addr()?)?;
    let mut received = [0_u8; 32];
    for payload in [b"first-pass".as_slice(), b"resumed-pass".as_slice()] {
        state.set(1, 0, 0)?;
        state.set(0, 0, 0)?;
        sender.send(payload)?;
        let size = receiver.recv(&mut received)?;
        require(
            received.get(..size) == Some(payload),
            "attached pass changed UDP payload",
        )?;
        require(state.get(&0, 0)? > 0, "attached classifier did not execute")?;
        state.set(1, 2, 0)?;
        state.set(0, 0, 0)?;
        sender.send(b"must-drop")?;
        match receiver.recv(&mut received) {
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            _ => return Err("attached drop did not block UDP delivery".into()),
        }
        require(
            state.get(&0, 0)? > 0,
            "drop packet did not reach classifier",
        )?;
    }
    println!("PASS: live UDP pass, drop and recovery after map updates");

    program.detach(link)?;
    require(
        SchedClassifier::query_tcx("lo", TcAttachType::Ingress)?
            .1
            .is_empty(),
        "TCX link leaked after detach",
    )?;
    state.set(0, 0, 0)?; // Keep the drop rule: detached packets must still arrive.
    sender.send(b"detached")?;
    let size = receiver.recv(&mut received)?;
    require(
        received.get(..size) == Some(b"detached".as_slice()),
        "traffic failed after detach",
    )?;
    require(state.get(&0, 0)? == 0, "classifier still ran after detach")?;

    // Also exercise automatic attachment cleanup on owner drop.
    program.attach("lo", TcAttachType::Ingress)?;
    drop(bpf);
    require(
        SchedClassifier::query_tcx("lo", TcAttachType::Ingress)?
            .1
            .is_empty(),
        "TCX link leaked after owner drop",
    )?;
    drop(state);
    println!("PASS: explicit detach, resumed traffic and owner-drop attachment cleanup");
    Ok(())
}
