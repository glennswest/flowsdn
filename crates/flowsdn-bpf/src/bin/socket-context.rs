//! CGROUP_SOCK_ADDR test-run capability fixture; never attached to a cgroup.
#![no_std]
#![no_main]
use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
#[path = "socket-context/model.rs"]
mod model;
#[cgroup_sock_addr(connect4)]
pub fn socket_connect4(ctx: SockAddrContext) -> i32 {
    // SAFETY: context is supplied by the kernel for the connect4 attach type.
    let raw = unsafe { &mut *ctx.sock_addr };
    let mut address = model::Address {
        family: raw.user_family,
        ipv4: raw.user_ip4,
        ipv6: [0; 4],
        port: raw.user_port,
    };
    let verdict = model::rewrite4(&mut address);
    raw.user_ip4 = address.ipv4;
    raw.user_port = address.port;
    if verdict == 0 { 0 } else { 1 }
}
#[cgroup_sock_addr(connect6)]
pub fn socket_connect6(ctx: SockAddrContext) -> i32 {
    // SAFETY: context is supplied by the kernel for the connect6 attach type.
    let raw = unsafe { &mut *ctx.sock_addr };
    let mut address = model::Address {
        family: raw.user_family,
        ipv4: 0,
        ipv6: raw.user_ip6,
        port: raw.user_port,
    };
    let verdict = model::rewrite6(&mut address);
    raw.user_ip6 = address.ipv6;
    raw.user_port = address.port;
    if verdict == 0 { 0 } else { 1 }
}
// SAFETY: unique immutable kernel license symbol.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
