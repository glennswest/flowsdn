//! Load-only external kfunc relocation probe. NEVER attach or iterate this
//! program: its call could destroy sockets. Separate from safe feature probes.
#![no_std]
#![no_main]
use core::ffi::c_void;
#[repr(C)]
pub struct IterTcp {meta:*mut c_void,sock:*mut c_void}
unsafe extern "C" {fn bpf_sock_destroy(sock:*mut c_void)->i32;}
// SAFETY: unique iterator entrypoint symbol and kernel-recognized section.
#[unsafe(no_mangle)]
#[unsafe(link_section="iter/tcp")]
pub unsafe extern "C" fn sock_destroy_probe(ctx:*mut IterTcp)->i32 {
    // SAFETY: kernel iterator context has meta and socket pointers. This
    // fixture is load-only; no userspace code attaches or executes it.
    let sock=unsafe{(*ctx).sock};
    if !sock.is_null(){
        // SAFETY: a non-null iterator socket is the kfunc's expected argument.
        // Resolving this external call is precisely the tested loader feature.
        let _=unsafe{bpf_sock_destroy(sock)};
    }
    0
}
// SAFETY: unique immutable kernel-required license symbol.
#[unsafe(link_section="license")]
#[unsafe(no_mangle)]
static LICENSE:[u8;13]=*b"Dual BSD/GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>)->!{loop{}}
