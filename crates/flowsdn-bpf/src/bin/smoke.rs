//! Harness self-test from spec 18 §9.1; not a forwarding program.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};

// Slot 0 records the last skb length; slot 1 selects pass (0) or drop (2).
// This deliberately is not a concurrent traffic counter.
#[map]
static SMOKE_STATE: Array<u32> = Array::with_max_entries(2, 0);

#[classifier]
pub fn smoke(ctx: TcContext) -> i32 {
    if SMOKE_STATE.set(0, ctx.len(), 0).is_err() {
        return TC_ACT_SHOT;
    }
    match SMOKE_STATE.get(1) {
        Some(&0) => TC_ACT_OK,
        _ => TC_ACT_SHOT,
    }
}

// SAFETY: this unique immutable symbol supplies the kernel-required ELF license.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
