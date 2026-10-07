//! Packet-level assertions complement live delivery: TTL, checksum and rejection.
use super::{Result, ensure};
use aya::programs::{SchedClassifier, TestRun, TestRunOptions};

fn put(packet: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    let end = at
        .checked_add(bytes.len())
        .ok_or("packet offset overflow")?;
    packet
        .get_mut(at..end)
        .ok_or("packet too short")?
        .copy_from_slice(bytes);
    Ok(())
}
fn checksum(header: &[u8]) -> Result<u16> {
    let mut sum = 0_u32;
    for word in header.chunks_exact(2) {
        let bytes: [u8; 2] = word.try_into()?;
        sum = sum
            .checked_add(u32::from(u16::from_be_bytes(bytes)))
            .ok_or("checksum overflow")?;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff)
            .checked_add(sum >> 16)
            .ok_or("fold overflow")?;
    }
    Ok(!u16::try_from(sum)?)
}
fn ipv4() -> Result<Vec<u8>> {
    let mut packet = vec![0; 64];
    put(&mut packet, 12, &[8, 0])?;
    put(
        &mut packet,
        14,
        &[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 198, 18, 0, 1, 198, 18, 0, 2,
        ],
    )?;
    put(&mut packet, 34, &[0x9c, 0x40, 0x9c, 0x41, 0, 8, 0, 0])?;
    let sum = checksum(packet.get(14..34).ok_or("missing header")?)?;
    put(&mut packet, 24, &sum.to_be_bytes())?;
    Ok(packet)
}
fn ipv6() -> Result<Vec<u8>> {
    let mut packet = vec![0; 64];
    put(&mut packet, 12, &[0x86, 0xdd])?;
    put(&mut packet, 14, &[0x60, 0, 0, 0, 0, 8, 17, 64])?;
    put(
        &mut packet,
        22,
        &"2001:db8:1::1".parse::<std::net::Ipv6Addr>()?.octets(),
    )?;
    put(
        &mut packet,
        38,
        &"2001:db8:1::2".parse::<std::net::Ipv6Addr>()?.octets(),
    )?;
    put(&mut packet, 54, &[0x9c, 0x40, 0x9c, 0x41, 0, 8, 0, 1])?;
    Ok(packet)
}
/// The kernel's answer to one test run: the verdict and output frame, or
/// the errno it refused the run with.
fn attempt(
    program: &SchedClassifier,
    packet: &[u8],
) -> Result<std::result::Result<(u32, Vec<u8>), String>> {
    let mut output = vec![0; 2048];
    match program.test_run(TestRunOptions {
        data_in: Some(packet),
        data_out: Some(&mut output),
        repeat: 1,
        ..Default::default()
    }) {
        Ok(result) => {
            let size = usize::try_from(result.data_size_out)?;
            ensure(size <= output.len(), "output buffer overflow")?;
            output.truncate(size);
            Ok(Ok((result.return_value, output)))
        }
        Err(aya::programs::ProgramError::SyscallError(s)) => Ok(Err(s
            .io_error
            .raw_os_error()
            .map_or_else(|| s.io_error.to_string(), |n| format!("errno {n}")))),
        Err(other) => Err(other.into()),
    }
}
/// Run one case; an error names the case and its size, since a test-run
/// refusal (errno) alone does not say which of the 16 the kernel rejected.
fn run(program: &SchedClassifier, case: &str, packet: &[u8], verdict: u32) -> Result<Vec<u8>> {
    match attempt(program, packet)? {
        Ok((value, output)) => {
            ensure(
                value == verdict,
                &format!("case {case}: packet verdict {value}, expected {verdict}"),
            )?;
            Ok(output)
        }
        Err(errno) => Err(format!(
            "case {case} ({} bytes): test run refused: {errno}",
            packet.len()
        )
        .into()),
    }
}
/// A frame shorter than its IP header must be dropped. Kernels that check
/// the header before the program runs (7.2 refuses such a test run with
/// EINVAL) never hand it to the program, which is as good.
fn run_truncated(program: &SchedClassifier, case: &str, packet: &[u8]) -> Result<()> {
    match attempt(program, packet)? {
        Ok((value, _)) => ensure(
            value == 2,
            &format!("case {case}: packet verdict {value}, expected 2"),
        ),
        Err(errno) if errno == "errno 22" => {
            println!(
                "NOTE: case {case} ({} bytes): the kernel refuses the frame before the program runs",
                packet.len()
            );
            Ok(())
        }
        Err(errno) => Err(format!(
            "case {case} ({} bytes): test run refused: {errno}",
            packet.len()
        )
        .into()),
    }
}
pub fn verify(program: &SchedClassifier) -> Result<()> {
    for v6 in [false, true] {
        let input = if v6 { ipv6()? } else { ipv4()? };
        let family = if v6 { "ipv6" } else { "ipv4" };
        let case = |name: &str| format!("{family}-{name}");
        let out = run(program, &case("redirect"), &input, 7)?; // TC_ACT_REDIRECT
        ensure(out.len() == input.len(), "redirect changed frame length")?;
        ensure(
            out.get(..12) == Some([2, 0, 0, 0, 1, 2, 2, 0, 0, 0, 0, 2].as_slice()),
            "MAC rewrite failed",
        )?;
        let hop = if v6 { 21 } else { 22 };
        ensure(out.get(hop) == Some(&63), "hop count not decremented")?;
        let mut expected = input.clone();
        put(&mut expected, 0, &[2, 0, 0, 0, 1, 2, 2, 0, 0, 0, 0, 2])?;
        put(&mut expected, hop, &[63])?;
        if !v6 {
            put(&mut expected, 24, &[0, 0])?;
            let sum = checksum(expected.get(14..34).ok_or("missing header")?)?;
            put(&mut expected, 24, &sum.to_be_bytes())?;
            ensure(
                checksum(out.get(14..34).ok_or("missing output header")?)? == 0,
                "IPv4 checksum invalid after TTL change",
            )?;
        }
        ensure(out == expected, "redirect changed unrelated packet bytes")?;
        for expired in [0, 1] {
            let mut bad = input.clone();
            put(&mut bad, hop, &[expired])?;
            run(program, &case(&format!("hop-{expired}")), &bad, 2)?;
        }
        let mut short = input.clone();
        short.truncate(30);
        run_truncated(program, &case("short"), &short)?;
        let mut wrong_version = input.clone();
        put(&mut wrong_version, 14, &[0x75])?;
        run(program, &case("wrong-version"), &wrong_version, 2)?;
        let mut absent = input.clone();
        put(&mut absent, if v6 { 53 } else { 33 }, &[99])?;
        run(program, &case("unknown-destination"), &absent, 2)?;
    }
    let mut short_ihl = ipv4()?;
    put(&mut short_ihl, 14, &[0x44])?;
    run(program, "ipv4-short-ihl", &short_ihl, 2)?;
    let mut short_total = ipv4()?;
    put(&mut short_total, 16, &[0, 19])?;
    run(program, "ipv4-short-total-length", &short_total, 2)?;
    let mut jumbo = ipv6()?;
    put(&mut jumbo, 18, &[0, 0])?;
    run(program, "ipv6-zero-payload-length", &jumbo, 2)?;
    let mut unknown_l2 = ipv4()?;
    put(&mut unknown_l2, 12, &[0x81, 0])?;
    run(program, "vlan-ethertype", &unknown_l2, 2)?;
    println!(
        "PASS: 16 kernel packet cases for MAC/hop/checksum handling and fail-closed rejection"
    );
    Ok(())
}
