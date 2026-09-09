//! Isolated integration entrypoint for local delivery, not a complete policy pipeline.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use flowsdn_bpf::local_delivery::{deliver, destination};
use flowsdn_bpf_abi::endpoint::{EndpointInfo, EndpointKey};

#[map(name = "cilium_lxc")]
static CILIUM_LXC: HashMap<EndpointKey, EndpointInfo> =
    HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[classifier]
pub fn local_delivery(ctx: TcContext) -> i32 {
    let Some(key) = destination(&ctx) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: NO_PREALLOC prevents deleted entries being reused in place;
    // lookup storage is RCU protected for this invocation. Copy immediately,
    // retain no reference across helpers, and never write through the pointer.
    let Some(endpoint) = (unsafe { CILIUM_LXC.get(&key).copied() }) else {
        return flowsdn_bpf::native_routing::route(&ctx);
    };
    deliver(&ctx, endpoint)
}

// SAFETY: unique immutable ELF license declaration, required by the loader.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
