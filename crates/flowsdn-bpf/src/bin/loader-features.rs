//! Kernel feature probes only; never attached to a production interface.
#![no_std]
#![no_main]
use aya_ebpf::{bindings::{TC_ACT_OK,xdp_action},macros::{classifier,map,xdp},maps::Array,programs::{TcContext,XdpContext}};
// SAFETY: unique immutable symbol in the loader configuration datasec.
#[unsafe(link_section=".rodata.config")]
#[unsafe(no_mangle)]
static __config_probe:u32=17;
#[map]
static FEATURE_STATE:Array<u32>=Array::with_max_entries(2,0);
#[classifier]
pub fn global_probe(_ctx:TcContext)->i32 {
    // SAFETY: valid immutable global; volatile prevents constant folding so
    // userspace's pre-load replacement is observed by the kernel program.
    let value=unsafe{core::ptr::read_volatile(&raw const __config_probe)};
    let _=FEATURE_STATE.set(0,value,0);TC_ACT_OK
}
#[xdp]
pub fn ordinary_xdp(_ctx:XdpContext)->u32 {xdp_action::XDP_PASS}
#[xdp(frags)]
pub fn fragmented_xdp(ctx:XdpContext)->u32 {
    // SAFETY: ctx is the kernel-provided XDP context; this helper reads only
    // the total length, including non-linear fragments.
    let size=unsafe{aya_ebpf::helpers::bpf_xdp_get_buff_len(ctx.ctx)} as u32;
    let _=FEATURE_STATE.set(1,size,0);xdp_action::XDP_PASS
}
// SAFETY: unique immutable kernel-required license symbol.
#[unsafe(link_section="license")]
#[unsafe(no_mangle)]
static LICENSE:[u8;13]=*b"Dual BSD/GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>)->!{loop{}}
