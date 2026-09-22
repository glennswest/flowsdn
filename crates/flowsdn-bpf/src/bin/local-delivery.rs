//! Isolated integration entrypoint for local delivery, not a complete policy pipeline.
#![no_std]
#![no_main]

#[path = "../helper_coverage.rs"]
mod helper_coverage;

use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use flowsdn_bpf::local_delivery::{deliver, destination, destination_candidate};
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
    let Some(endpoint) = (unsafe { CILIUM_LXC.get(key).copied() }) else {
        return flowsdn_bpf::native_routing::route(&ctx);
    };
    deliver(&ctx, endpoint)
}

/// Bounded native-device ingress: leave host/discovery/remote traffic to the
/// existing stack, and intercept only known local workload IP destinations.
/// This is the policy-disabled foundation path, not the complete from_netdev
/// pipeline. Loader/controller activation and policy integration are separate.
#[classifier]
pub fn uplink_ingress(ctx: TcContext) -> i32 {
    let Some(candidate) = destination_candidate(&ctx) else {
        return TC_ACT_OK;
    };
    // SAFETY: same NO_PREALLOC map/RCU copy discipline as local_delivery.
    let Some(endpoint) = (unsafe { CILIUM_LXC.get(candidate).copied() }) else {
        return TC_ACT_OK;
    };
    // Lookup precedes full parsing so invalid version/length at a known local
    // destination is dropped instead of escaping into the stack path.
    if destination(&ctx).is_none() {
        return TC_ACT_SHOT;
    }
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
