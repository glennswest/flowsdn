//! Real CGROUP_SOCK_ADDR test-run capability probe; no connect syscall or attach.
use aya::{EbpfLoader, programs::CgroupSockAddr};
use std::{
    error::Error,
    os::fd::{AsFd, AsRawFd},
};
#[path = "../../../flowsdn-bpf/src/bin/socket-context/model.rs"]
mod model;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const CONTEXT_SIZE: usize = 72;
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes
        .get_mut(offset..offset.saturating_add(4))
        .expect("field")
        .copy_from_slice(&value.to_ne_bytes());
}
fn get(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes
            .get(offset..offset.saturating_add(4))
            .expect("field")
            .try_into()
            .expect("u32"),
    )
}
fn input(ipv6: bool, matched: bool) -> [u8; CONTEXT_SIZE] {
    let mut bytes = [0; CONTEXT_SIZE];
    let family = if ipv6 { 10 } else { 2 };
    put(&mut bytes, 0, family);
    put(&mut bytes, 28, family);
    put(&mut bytes, 32, 1);
    put(&mut bytes, 36, 6);
    put(
        &mut bytes,
        24,
        u32::from(if matched { 80u16 } else { 81u16 }.to_be()),
    );
    if ipv6 {
        put(&mut bytes, 8, u32::from_ne_bytes([0x20, 1, 0x0d, 0xb8]));
        put(&mut bytes, 20, u32::from_ne_bytes([0, 0, 0, 0x80]));
    } else {
        put(&mut bytes, 4, u32::from_ne_bytes([192, 0, 2, 80]));
    }
    bytes
}
fn expected(mut bytes: [u8; CONTEXT_SIZE], ipv6: bool) -> (u32, [u8; CONTEXT_SIZE]) {
    let mut address = model::Address {
        family: get(&bytes, 0),
        ipv4: get(&bytes, 4),
        ipv6: [
            get(&bytes, 8),
            get(&bytes, 12),
            get(&bytes, 16),
            get(&bytes, 20),
        ],
        port: get(&bytes, 24),
    };
    let verdict = if ipv6 {
        model::rewrite6(&mut address)
    } else {
        model::rewrite4(&mut address)
    };
    if ipv6 {
        for (offset, value) in [8, 12, 16, 20].into_iter().zip(address.ipv6) {
            put(&mut bytes, offset, value);
        }
    } else {
        put(&mut bytes, 4, address.ipv4);
    }
    put(&mut bytes, 24, address.port);
    (verdict, bytes)
}
// Aya0.14 intentionally has no TestRun implementation for this program type.
// This narrow ABI adapter makes the kernel capability observable instead of
// substituting a different program type or attaching to the host cgroup.
#[allow(unsafe_code)]
mod syscall {
    use std::{io, os::fd::RawFd};
    #[repr(C)]
    #[derive(Default)]
    struct Attr {
        prog_fd: u32,
        retval: u32,
        data_size_in: u32,
        data_size_out: u32,
        data_in: u64,
        data_out: u64,
        repeat: u32,
        duration: u32,
        ctx_size_in: u32,
        ctx_size_out: u32,
        ctx_in: u64,
        ctx_out: u64,
        flags: u32,
        cpu: u32,
        batch_size: u32,
        padding: u32,
    }
    pub fn run(fd: RawFd, input: &[u8], output: &mut [u8]) -> io::Result<(u32, u32)> {
        let mut attr = Attr {
            prog_fd: u32::try_from(fd).map_err(|_| io::Error::other("negative BPF fd"))?,
            ctx_size_in: u32::try_from(input.len())
                .map_err(|_| io::Error::other("context too large"))?,
            ctx_size_out: u32::try_from(output.len())
                .map_err(|_| io::Error::other("output too large"))?,
            ctx_in: input.as_ptr() as u64,
            ctx_out: output.as_mut_ptr() as u64,
            repeat: 1,
            ..Default::default()
        };
        // SAFETY: repr(C) is the Linux bpf_attr.test layout (80 bytes); both
        // slice buffers remain valid for this synchronous syscall. Kernel writes
        // only the declared output buffer and mutable attr; all other fields zero.
        let result = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_bpf,
                10u32,
                &raw mut attr,
                std::mem::size_of::<Attr>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((attr.retval, attr.ctx_size_out))
        }
    }
    const _: () = assert!(std::mem::size_of::<Attr>() == 80);
}
fn probe(program: &mut CgroupSockAddr, ipv6: bool) -> Result<bool> {
    program.load()?;
    let fd = program.fd()?.as_fd().as_raw_fd();
    for matched in [true, false] {
        let original = input(ipv6, matched);
        let (verdict, want) = expected(original, ipv6);
        let mut output = [0; CONTEXT_SIZE];
        match syscall::run(fd, &original, &mut output) {
            Ok((actual, size)) => {
                if actual != verdict || usize::try_from(size)? != CONTEXT_SIZE || output != want {
                    return Err(format!("socket context mismatch: ipv6={ipv6}, matched={matched}, verdict={actual}, size={size}, actual={output:?}, expected={want:?}").into());
                }
                println!(
                    "PASS connect{} matched={matched}: return,address/port rewrite and preserved context",
                    if ipv6 { 6 } else { 4 }
                );
            }
            Err(error) => {
                eprintln!(
                    "NOT SUPPORTED/FAILED connect{} BPF_PROG_TEST_RUN: errno={:?}, {error}. No fallback or live socket was run.",
                    if ipv6 { 6 } else { 4 },
                    error.raw_os_error()
                );
                return Ok(false);
            }
        }
    }
    let mut invalid = input(ipv6, true);
    put(&mut invalid, 0, 0);
    let mut rejected = [0; CONTEXT_SIZE];
    match syscall::run(fd, &invalid, &mut rejected) {
        Ok((0, size)) if usize::try_from(size)? == CONTEXT_SIZE && rejected == invalid => {
            println!("PASS invalid address family denied unchanged")
        }
        Err(error) if error.raw_os_error() == Some(nix::libc::EINVAL) => {
            println!("PASS invalid address family rejected by kernel")
        }
        other => {
            return Err(format!("invalid-family test produced unexpected result: {other:?}").into());
        }
    }
    let mut output = [0; CONTEXT_SIZE];
    if syscall::run(fd, &[0; 4], &mut output).is_ok() {
        return Err("truncated socket context unexpectedly accepted".into());
    }
    println!("PASS truncated connect context rejected");
    Ok(true)
}
fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("usage: socket-context PATH_TO_SOCKET_CONTEXT_OBJECT")?;
    let mut object = EbpfLoader::new().load_file(path)?;
    let mut supported = true;
    for (name, ipv6) in [("socket_connect4", false), ("socket_connect6", true)] {
        let program: &mut CgroupSockAddr = object
            .program_mut(name)
            .ok_or("socket program missing")?
            .try_into()?;
        supported &= probe(program, ipv6)?;
    }
    if !supported {
        return Err("real socket context test-run unsupported or failed; use an isolated cgroup/netns socket attachment test for integration coverage".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_helper_ipv4_ipv6_rewrite_preservation_and_invalid_family() {
        for ipv6 in [false, true] {
            let original = input(ipv6, true);
            let (verdict, rewritten) = expected(original, ipv6);
            assert_eq!(verdict, 1);
            assert_ne!(rewritten, original);
            assert_eq!(get(&rewritten, 24), u32::from(18080u16.to_be()));
            if ipv6 {
                assert_eq!(get(&rewritten, 8), 0);
                assert_eq!(get(&rewritten, 20), u32::from_ne_bytes([0, 0, 0, 1]));
            } else {
                assert_eq!(get(&rewritten, 4), u32::from_ne_bytes([127, 0, 0, 1]));
            }
            for offset in [0, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68] {
                assert_eq!(get(&rewritten, offset), get(&original, offset));
            }
            let unmatched = input(ipv6, false);
            assert_eq!(expected(unmatched, ipv6), (1, unmatched));
            let mut invalid = original;
            put(&mut invalid, 0, 0);
            assert_eq!(expected(invalid, ipv6), (0, invalid));
        }
    }
    #[test]
    fn context_offsets_match_uapi_layout() {
        assert_eq!(CONTEXT_SIZE, 72);
        let value = input(false, true);
        assert_eq!(get(&value, 28), 2);
        assert_eq!(get(&value, 36), 6);
    }
}
