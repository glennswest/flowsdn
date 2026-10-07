//! Socket-level service load balancing (spec 05 §3.8, spec 02 socket hooks):
//! cgroup v2 `connect`/`sendmsg` rewrite a ClusterIP frontend to a backend,
//! `recvmsg`/`getpeername` rewrite a UDP backend back to its frontend. The
//! translation happens before routing, for the host and every pod netns, so
//! no packet DNAT or conntrack entry is needed. IPv4-mapped IPv6 addresses
//! use the IPv4 maps. Map layouts follow spec 01 §4.3; the agent
//! owns their contents. Session affinity, Maglev, NodePort surrogates,
//! skip-LB and socket termination are not implemented here.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_NO_PREALLOC, bpf_sock_addr},
    helpers::{bpf_get_prandom_u32, bpf_get_socket_cookie},
    macros::{cgroup_sock_addr, map},
    maps::{HashMap, LruHashMap},
    programs::SockAddrContext,
};
use flowsdn_bpf_abi::{
    Be16, Be32,
    lb::{
        Ipv4RevnatEntry, Ipv4RevnatTuple, Ipv6RevnatEntry, Ipv6RevnatTuple, Lb4Backend, Lb4Key,
        Lb6Backend, Lb6Key, LbService,
    },
};

const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;
/// cgroup sock_addr verdicts: 1 continues the syscall, 0 fails it with EPERM.
const ALLOW: i32 = 1;
const REJECT: i32 = 0;
/// The third word of an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`).
const MAPPED: u32 = u32::from_ne_bytes([0, 0, 0xff, 0xff]);

#[map(name = "flowsdn_lb4_services")]
static LB4_SERVICES: HashMap<Lb4Key, LbService> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb4_backends")]
static LB4_BACKENDS: HashMap<u32, Lb4Backend> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb4_reverse_sk")]
static LB4_REVERSE_SK: LruHashMap<Ipv4RevnatTuple, Ipv4RevnatEntry> =
    LruHashMap::with_max_entries(65536, 0);
#[map(name = "flowsdn_lb6_services")]
static LB6_SERVICES: HashMap<Lb6Key, LbService> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb6_backends")]
static LB6_BACKENDS: HashMap<u32, Lb6Backend> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb6_reverse_sk")]
static LB6_REVERSE_SK: LruHashMap<Ipv6RevnatTuple, Ipv6RevnatEntry> =
    LruHashMap::with_max_entries(65536, 0);

/// Outcome of a frontend lookup.
enum Lookup<B> {
    /// Not a service frontend: leave the address alone.
    None,
    /// A frontend without a usable backend: fail the syscall.
    Reject,
    Backend(B, u16),
}

/// Pick slot `1..=count` uniformly. The master entry is the single publish
/// point (spec 05 §3.4 step 10): slots up to its count exist before it does.
#[inline(always)]
fn slot(count: u16) -> Option<u16> {
    // SAFETY: no arguments; returns a pseudo-random scalar.
    let random = unsafe { bpf_get_prandom_u32() };
    let index = random.checked_rem(u32::from(count))?;
    u16::try_from(index).ok()?.checked_add(1)
}

#[inline(always)]
fn lookup4(address: [u8; 4], port: [u8; 2], proto: u8) -> Lookup<Lb4Backend> {
    let mut key = Lb4Key {
        address: Be32(address),
        dport: Be16(port),
        backend_slot: 0,
        proto,
        scope: 0,
        pad: [0; 2],
    };
    // SAFETY: values are copied at once and never written through; entries
    // are RCU protected for this invocation.
    let Some(service) = (unsafe { LB4_SERVICES.get(&key).copied() }) else {
        return Lookup::None;
    };
    let Some(index) = slot(service.count) else {
        return Lookup::Reject;
    };
    key.backend_slot = index;
    // SAFETY: as above.
    let Some(entry) = (unsafe { LB4_SERVICES.get(&key).copied() }) else {
        return Lookup::Reject;
    };
    // SAFETY: as above.
    match unsafe { LB4_BACKENDS.get(&entry.backend_id()).copied() } {
        Some(backend) => Lookup::Backend(backend, service.rev_nat_index),
        None => Lookup::Reject,
    }
}

#[inline(always)]
fn lookup6(address: [u8; 16], port: [u8; 2], proto: u8) -> Lookup<Lb6Backend> {
    let mut key = Lb6Key {
        address,
        dport: Be16(port),
        backend_slot: 0,
        proto,
        scope: 0,
        pad: [0; 2],
    };
    // SAFETY: see lookup4.
    let Some(service) = (unsafe { LB6_SERVICES.get(&key).copied() }) else {
        return Lookup::None;
    };
    let Some(index) = slot(service.count) else {
        return Lookup::Reject;
    };
    key.backend_slot = index;
    // SAFETY: see lookup4.
    let Some(entry) = (unsafe { LB6_SERVICES.get(&key).copied() }) else {
        return Lookup::Reject;
    };
    // SAFETY: see lookup4.
    match unsafe { LB6_BACKENDS.get(&entry.backend_id()).copied() } {
        Some(backend) => Lookup::Backend(backend, service.rev_nat_index),
        None => Lookup::Reject,
    }
}

/// TCP and UDP only; the kernel resolves protocol 0 to the socket's real one.
#[inline(always)]
fn protocol(raw: &bpf_sock_addr) -> Option<u8> {
    match raw.protocol {
        IPPROTO_TCP => Some(6),
        IPPROTO_UDP => Some(17),
        _ => None,
    }
}
/// `user_port` carries the port in network order in its low 16 bits.
#[inline(always)]
fn port_bytes(raw: &bpf_sock_addr) -> [u8; 2] {
    (raw.user_port as u16).to_ne_bytes()
}
#[inline(always)]
fn port_value(port: [u8; 2]) -> u32 {
    u32::from(u16::from_ne_bytes(port))
}
#[inline(always)]
fn ip6_bytes(words: [u32; 4]) -> [u8; 16] {
    let [a, b, c, d] = words;
    let [a0, a1, a2, a3] = a.to_ne_bytes();
    let [b0, b1, b2, b3] = b.to_ne_bytes();
    let [c0, c1, c2, c3] = c.to_ne_bytes();
    let [d0, d1, d2, d3] = d.to_ne_bytes();
    [
        a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3,
    ]
}
#[inline(always)]
fn ip6_words(bytes: [u8; 16]) -> [u32; 4] {
    let [a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3] = bytes;
    [
        u32::from_ne_bytes([a0, a1, a2, a3]),
        u32::from_ne_bytes([b0, b1, b2, b3]),
        u32::from_ne_bytes([c0, c1, c2, c3]),
        u32::from_ne_bytes([d0, d1, d2, d3]),
    ]
}
/// The IPv4 address inside `::ffff:a.b.c.d`, if it is one.
#[inline(always)]
fn mapped(words: [u32; 4]) -> Option<[u8; 4]> {
    let [a, b, c, d] = words;
    (a == 0 && b == 0 && c == MAPPED).then(|| d.to_ne_bytes())
}
#[inline(always)]
fn cookie(ctx: &SockAddrContext) -> u64 {
    // SAFETY: the kernel-supplied sock_addr context of this invocation.
    unsafe { bpf_get_socket_cookie(ctx.as_ptr()) }
}

/// Remember a UDP translation so replies can be shown as from the frontend.
/// A full LRU map evicts old entries; insertion failure only loses that.
#[inline(always)]
fn remember4(ctx: &SockAddrContext, backend: &Lb4Backend, front: ([u8; 4], [u8; 2]), rev: u16) {
    let key = Ipv4RevnatTuple {
        cookie: cookie(ctx),
        address: backend.address,
        port: backend.port,
        pad: 0,
    };
    let value = Ipv4RevnatEntry {
        address: Be32(front.0),
        port: Be16(front.1),
        rev_nat_index: rev,
    };
    let _ = LB4_REVERSE_SK.insert(&key, &value, 0);
}
#[inline(always)]
fn remember6(ctx: &SockAddrContext, backend: &Lb6Backend, front: ([u8; 16], [u8; 2]), rev: u16) {
    let key = Ipv6RevnatTuple {
        cookie: cookie(ctx),
        address: backend.address,
        port: backend.port,
        pad: 0,
        pad2: 0,
    };
    let value = Ipv6RevnatEntry {
        address: front.0,
        port: Be16(front.1),
        rev_nat_index: rev,
    };
    let _ = LB6_REVERSE_SK.insert(&key, &value, 0);
}

/// Translate an IPv4 frontend to a backend (connect, or unconnected sendmsg).
#[inline(always)]
fn forward4(ctx: &SockAddrContext) -> i32 {
    // SAFETY: kernel-supplied context for this attach type, used only here.
    let raw = unsafe { &mut *ctx.sock_addr };
    let Some(proto) = protocol(raw) else {
        return ALLOW;
    };
    let address = raw.user_ip4.to_ne_bytes();
    let port = port_bytes(raw);
    match lookup4(address, port, proto) {
        Lookup::None => ALLOW,
        Lookup::Reject => REJECT,
        Lookup::Backend(backend, rev) => {
            if raw.protocol == IPPROTO_UDP {
                remember4(ctx, &backend, (address, port), rev);
            }
            raw.user_ip4 = u32::from_ne_bytes(backend.address.0);
            raw.user_port = port_value(backend.port.0);
            ALLOW
        }
    }
}

/// Translate an IPv6 (or IPv4-mapped) frontend to a backend.
#[inline(always)]
fn forward6(ctx: &SockAddrContext) -> i32 {
    // SAFETY: kernel-supplied context for this attach type, used only here.
    let raw = unsafe { &mut *ctx.sock_addr };
    let Some(proto) = protocol(raw) else {
        return ALLOW;
    };
    let words = raw.user_ip6;
    let port = port_bytes(raw);
    if let Some(address) = mapped(words) {
        return match lookup4(address, port, proto) {
            Lookup::None => ALLOW,
            Lookup::Reject => REJECT,
            Lookup::Backend(backend, rev) => {
                if raw.protocol == IPPROTO_UDP {
                    remember4(ctx, &backend, (address, port), rev);
                }
                raw.user_ip6 = [0, 0, MAPPED, u32::from_ne_bytes(backend.address.0)];
                raw.user_port = port_value(backend.port.0);
                ALLOW
            }
        };
    }
    let address = ip6_bytes(words);
    match lookup6(address, port, proto) {
        Lookup::None => ALLOW,
        Lookup::Reject => REJECT,
        Lookup::Backend(backend, rev) => {
            if raw.protocol == IPPROTO_UDP {
                remember6(ctx, &backend, (address, port), rev);
            }
            raw.user_ip6 = ip6_words(backend.address);
            raw.user_port = port_value(backend.port.0);
            ALLOW
        }
    }
}

/// Show a UDP peer that is a translated backend as its frontend
/// (recvmsg source, getpeername). recvmsg programs must return 1.
#[inline(always)]
fn reverse4(ctx: &SockAddrContext) -> i32 {
    // SAFETY: kernel-supplied context for this attach type, used only here.
    let raw = unsafe { &mut *ctx.sock_addr };
    if raw.protocol != IPPROTO_UDP {
        return ALLOW;
    }
    let key = Ipv4RevnatTuple {
        cookie: cookie(ctx),
        address: Be32(raw.user_ip4.to_ne_bytes()),
        port: Be16(port_bytes(raw)),
        pad: 0,
    };
    // SAFETY: LRU value copied at once, never written through.
    if let Some(front) = unsafe { LB4_REVERSE_SK.get(&key).copied() } {
        raw.user_ip4 = u32::from_ne_bytes(front.address.0);
        raw.user_port = port_value(front.port.0);
    }
    ALLOW
}

#[inline(always)]
fn reverse6(ctx: &SockAddrContext) -> i32 {
    // SAFETY: kernel-supplied context for this attach type, used only here.
    let raw = unsafe { &mut *ctx.sock_addr };
    if raw.protocol != IPPROTO_UDP {
        return ALLOW;
    }
    let words = raw.user_ip6;
    let port = port_bytes(raw);
    if let Some(address) = mapped(words) {
        let key = Ipv4RevnatTuple {
            cookie: cookie(ctx),
            address: Be32(address),
            port: Be16(port),
            pad: 0,
        };
        // SAFETY: LRU value copied at once, never written through.
        if let Some(front) = unsafe { LB4_REVERSE_SK.get(&key).copied() } {
            raw.user_ip6 = [0, 0, MAPPED, u32::from_ne_bytes(front.address.0)];
            raw.user_port = port_value(front.port.0);
        }
        return ALLOW;
    }
    let key = Ipv6RevnatTuple {
        cookie: cookie(ctx),
        address: ip6_bytes(words),
        port: Be16(port),
        pad: 0,
        pad2: 0,
    };
    // SAFETY: LRU value copied at once, never written through.
    if let Some(front) = unsafe { LB6_REVERSE_SK.get(&key).copied() } {
        raw.user_ip6 = ip6_words(front.address);
        raw.user_port = port_value(front.port.0);
    }
    ALLOW
}

#[cgroup_sock_addr(connect4)]
pub fn sock4_connect(ctx: SockAddrContext) -> i32 {
    forward4(&ctx)
}
#[cgroup_sock_addr(sendmsg4)]
pub fn sock4_sendmsg(ctx: SockAddrContext) -> i32 {
    forward4(&ctx)
}
#[cgroup_sock_addr(recvmsg4)]
pub fn sock4_recvmsg(ctx: SockAddrContext) -> i32 {
    reverse4(&ctx)
}
#[cgroup_sock_addr(getpeername4)]
pub fn sock4_getpeername(ctx: SockAddrContext) -> i32 {
    reverse4(&ctx)
}
#[cgroup_sock_addr(connect6)]
pub fn sock6_connect(ctx: SockAddrContext) -> i32 {
    forward6(&ctx)
}
#[cgroup_sock_addr(sendmsg6)]
pub fn sock6_sendmsg(ctx: SockAddrContext) -> i32 {
    forward6(&ctx)
}
#[cgroup_sock_addr(recvmsg6)]
pub fn sock6_recvmsg(ctx: SockAddrContext) -> i32 {
    reverse6(&ctx)
}
#[cgroup_sock_addr(getpeername6)]
pub fn sock6_getpeername(ctx: SockAddrContext) -> i32 {
    reverse6(&ctx)
}

// SAFETY: unique immutable ELF license declaration, required by the loader.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
