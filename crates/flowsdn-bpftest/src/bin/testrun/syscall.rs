//! `BPF_PROG_TEST_RUN` with a context (`ctx_in`/`ctx_out`), which aya's
//! `TestRunOptions` does not carry: the `__sk_buff` fields, `ifindex` among
//! them, that a tc program sees. Shared by the fixtures through `#[path]`.
#![allow(unsafe_code)]
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
const _: () = assert!(std::mem::size_of::<Attr>() == 80);
/// `BPF_PROG_TEST_RUN` with packet data and a context; returns the verdict
/// and the length of the output frame.
pub fn run(
    fd: RawFd,
    data: &[u8],
    data_out: &mut [u8],
    ctx: &[u8],
    ctx_out: &mut [u8],
) -> io::Result<(u32, usize)> {
    let size = |n: usize| u32::try_from(n).map_err(|_| io::Error::other("buffer too large"));
    let mut attr = Attr {
        prog_fd: u32::try_from(fd).map_err(|_| io::Error::other("negative BPF fd"))?,
        data_size_in: size(data.len())?,
        data_size_out: size(data_out.len())?,
        data_in: data.as_ptr() as u64,
        data_out: data_out.as_mut_ptr() as u64,
        ctx_size_in: size(ctx.len())?,
        ctx_size_out: size(ctx_out.len())?,
        ctx_in: ctx.as_ptr() as u64,
        ctx_out: ctx_out.as_mut_ptr() as u64,
        repeat: 1,
        ..Default::default()
    };
    // SAFETY: repr(C) is the Linux bpf_attr.test layout (80 bytes); all four
    // buffers stay valid for this synchronous syscall and the kernel writes
    // only within their declared sizes. BPF_PROG_TEST_RUN is command 10.
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
        let out = usize::try_from(attr.data_size_out).map_err(io::Error::other)?;
        Ok((attr.retval, out.min(data_out.len())))
    }
}
