//! `__sk_buff` `ctx_in`/`ctx_out` field matrix probe (spec 18 §3.3(d), §9.1,
//! #256). Test-run only; never attached. `ctx_observe` records every field the
//! kernel copied in from `ctx_in`, then writes the long-writable fields;
//! `ctx_write_extra` writes `tc_index` and `tstamp`, kept apart so a verifier
//! that refuses those writes does not hide the rest of the matrix.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};

/// Observed values by index; flowsdn-bpftest's `skb-ctx-matrix` owns the
/// numbering: 0 mark, 1 priority, 2..=6 cb[0..5], 7 ifindex, 8 tstamp,
/// 9 wire_len, 10 gso_segs, 11 gso_size, 12 hwtstamp, 13 tc_index,
/// 14 ingress_ifindex, 15 len.
#[map]
static OBSERVED: Array<u64> = Array::with_max_entries(16, 0);

/// What `ctx_observe` writes back, for the harness to find in `ctx_out`.
pub const WRITE_MARK: u32 = 0x5a5a_0001;
pub const WRITE_PRIORITY: u32 = 7;
pub const WRITE_CB: [u32; 5] = [0xc0, 0xc1, 0xc2, 0xc3, 0xc4];
pub const WRITE_TC_INDEX: u32 = 0x42;
pub const WRITE_TSTAMP: u64 = 0x1122_3344;

#[inline(always)]
fn record(index: u32, value: u64) {
    if let Some(slot) = OBSERVED.get_ptr_mut(index) {
        // SAFETY: a valid array slot pointer for this invocation; the probe is
        // test-run serially and the harness reads only after the run returns.
        unsafe { *slot = value };
    }
}

#[classifier]
pub fn ctx_observe(ctx: TcContext) -> i32 {
    let skb = ctx.skb.skb;
    // SAFETY: the kernel supplies a live __sk_buff context for this program;
    // every access is a whole, aligned, verifier-checked context field.
    unsafe {
        record(0, u64::from((*skb).mark));
        record(1, u64::from((*skb).priority));
        record(2, u64::from((*skb).cb[0]));
        record(3, u64::from((*skb).cb[1]));
        record(4, u64::from((*skb).cb[2]));
        record(5, u64::from((*skb).cb[3]));
        record(6, u64::from((*skb).cb[4]));
        record(7, u64::from((*skb).ifindex));
        record(8, (*skb).tstamp);
        record(9, u64::from((*skb).wire_len));
        record(10, u64::from((*skb).gso_segs));
        record(11, u64::from((*skb).gso_size));
        record(12, (*skb).hwtstamp);
        record(13, u64::from((*skb).tc_index));
        record(14, u64::from((*skb).ingress_ifindex));
        record(15, u64::from((*skb).len));
        (*skb).mark = WRITE_MARK;
        (*skb).priority = WRITE_PRIORITY;
        // One 4-byte store per word at its fixed offset: an array copy
        // compiles to stores through a pointer moved to `cb`, which the
        // verifier refuses ("dereference of modified ctx ptr", 7.2, #256).
        let [cb0, cb1, cb2, cb3, cb4] = WRITE_CB;
        core::ptr::write_volatile(&raw mut (*skb).cb[0], cb0);
        core::ptr::write_volatile(&raw mut (*skb).cb[1], cb1);
        core::ptr::write_volatile(&raw mut (*skb).cb[2], cb2);
        core::ptr::write_volatile(&raw mut (*skb).cb[3], cb3);
        core::ptr::write_volatile(&raw mut (*skb).cb[4], cb4);
    }
    TC_ACT_OK
}

#[classifier]
pub fn ctx_write_extra(ctx: TcContext) -> i32 {
    let skb = ctx.skb.skb;
    // SAFETY: as above; tc_index and tstamp are tc-writable context fields.
    unsafe {
        (*skb).tc_index = WRITE_TC_INDEX;
        (*skb).tstamp = WRITE_TSTAMP;
    }
    TC_ACT_OK
}

// SAFETY: unique immutable ELF license declaration, required by the loader.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
