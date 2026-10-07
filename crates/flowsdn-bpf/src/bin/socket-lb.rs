//! Socket-level service load balancing (spec 05 §3.8, spec 02 socket hooks):
//! cgroup v2 `connect`/`sendmsg` rewrite a ClusterIP frontend to a backend,
//! `recvmsg`/`getpeername` rewrite a UDP backend back to its frontend. The
//! translation happens before routing, for the host and every pod netns, so
//! no packet DNAT or conntrack entry is needed. IPv4-mapped IPv6 addresses
//! use the IPv4 maps. Map layouts follow spec 01 §4.3; the agent
//! owns their contents. A frontend with the session-affinity flag keeps each
//! client (its network namespace cookie, as the reference's socket LB does)
//! on the backend it last got, while that is within the master's timeout and
//! the agent's affinity-match map still pairs the backend with the service.
//! Maglev, NodePort surrogates, skip-LB and socket termination are not
//! implemented here.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_NO_PREALLOC, bpf_sock_addr},
    helpers::{bpf_get_netns_cookie, bpf_get_prandom_u32, bpf_get_socket_cookie, bpf_ktime_get_ns},
    macros::{cgroup_sock_addr, map},
    maps::{HashMap, LruHashMap},
    programs::SockAddrContext,
};
use flowsdn_bpf_abi::{
    Be16, Be32,
    affinity::{LbAffinityMatch, LbAffinityVal, Lb4AffinityKey, Lb6AffinityKey, NETNS_COOKIE},
    lb::{
        Ipv4RevnatEntry, Ipv4RevnatTuple, Ipv6RevnatEntry, Ipv6RevnatTuple, Lb4Backend, Lb4Key,
        Lb6Backend, Lb6Key, LbService, service_flags,
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

#[map(name = "flowsdn_lb4_affinity")]
static LB4_AFFINITY: LruHashMap<Lb4AffinityKey, LbAffinityVal> =
    LruHashMap::with_max_entries(65536, 0);
#[map(name = "flowsdn_lb6_affinity")]
static LB6_AFFINITY: LruHashMap<Lb6AffinityKey, LbAffinityVal> =
    LruHashMap::with_max_entries(65536, 0);
#[map(name = "flowsdn_lb_affinity_match")]
static LB_AFFINITY_MATCH: HashMap<LbAffinityMatch, u8> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);

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

/// Monotonic seconds, the unit of the affinity timeout.
#[inline(always)]
fn now() -> u64 {
    // SAFETY: no arguments; returns the monotonic clock.
    unsafe { bpf_ktime_get_ns() } / 1_000_000_000
}
/// The client of a socket for affinity: its network namespace.
#[inline(always)]
fn netns(ctx: &SockAddrContext) -> u64 {
    // SAFETY: the kernel-supplied sock_addr context of this invocation.
    unsafe { bpf_get_netns_cookie(ctx.as_ptr()) }
}
/// The remembered backend, if it is within the timeout and the agent still
/// pairs it with service `rev`.
#[inline(always)]
fn affine(remembered: Option<LbAffinityVal>, rev: u16, timeout: u32, now: u64) -> Option<u32> {
    let value = remembered?;
    let (last_used, backend_id) = (value.last_used, value.backend_id);
    if now.saturating_sub(last_used) > u64::from(timeout) {
        return None;
    }
    let pair = LbAffinityMatch {
        backend_id,
        rev_nat_id: rev,
        pad: 0,
    };
    // SAFETY: presence check only; the value is never read.
    unsafe { LB_AFFINITY_MATCH.get(&pair) }?;
    Some(backend_id)
}

#[inline(always)]
fn lookup4(ctx: &SockAddrContext, address: [u8; 4], port: [u8; 2], proto: u8) -> Lookup<Lb4Backend> {
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
    let rev = service.rev_nat_index;
    let sticky = service.service_flags() & service_flags::SESSION_AFFINITY != 0;
    let affinity = Lb4AffinityKey {
        client_id: netns(ctx).to_ne_bytes(),
        rev_nat_id: rev,
        flags: NETNS_COOKIE,
        pad1: 0,
        pad2: 0,
    };
    let time = now();
    let remembered = if sticky {
        // SAFETY: LRU value copied at once, never written through.
        affine(unsafe { LB4_AFFINITY.get(&affinity).copied() }, rev, service.affinity_seconds(), time)
    } else {
        None
    };
    let id = match remembered {
        Some(id) => id,
        None => {
            let Some(index) = slot(service.count) else {
                return Lookup::Reject;
            };
            key.backend_slot = index;
            // SAFETY: as above.
            let Some(entry) = (unsafe { LB4_SERVICES.get(&key).copied() }) else {
                return Lookup::Reject;
            };
            entry.backend_id()
        }
    };
    // SAFETY: as above.
    let Some(backend) = (unsafe { LB4_BACKENDS.get(&id).copied() }) else {
        return Lookup::Reject;
    };
    if sticky {
        let value = LbAffinityVal {
            last_used: time,
            backend_id: id,
            pad: 0,
        };
        // A full LRU evicts an old client; failing only forgets this one.
        let _ = LB4_AFFINITY.insert(&affinity, &value, 0);
    }
    Lookup::Backend(backend, rev)
}

#[inline(always)]
fn lookup6(ctx: &SockAddrContext, address: [u8; 16], port: [u8; 2], proto: u8) -> Lookup<Lb6Backend> {
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
    let rev = service.rev_nat_index;
    let sticky = service.service_flags() & service_flags::SESSION_AFFINITY != 0;
    let [c0, c1, c2, c3, c4, c5, c6, c7] = netns(ctx).to_ne_bytes();
    let affinity = Lb6AffinityKey {
        client_id: [c0, c1, c2, c3, c4, c5, c6, c7, 0, 0, 0, 0, 0, 0, 0, 0],
        rev_nat_id: rev,
        flags: NETNS_COOKIE,
        pad1: 0,
        pad2: 0,
    };
    let time = now();
    let remembered = if sticky {
        // SAFETY: LRU value copied at once, never written through.
        affine(unsafe { LB6_AFFINITY.get(&affinity).copied() }, rev, service.affinity_seconds(), time)
    } else {
        None
    };
    let id = match remembered {
        Some(id) => id,
        None => {
            let Some(index) = slot(service.count) else {
                return Lookup::Reject;
            };
            key.backend_slot = index;
            // SAFETY: see lookup4.
            let Some(entry) = (unsafe { LB6_SERVICES.get(&key).copied() }) else {
                return Lookup::Reject;
            };
            entry.backend_id()
        }
    };
    // SAFETY: see lookup4.
    let Some(backend) = (unsafe { LB6_BACKENDS.get(&id).copied() }) else {
        return Lookup::Reject;
    };
    if sticky {
        let value = LbAffinityVal {
            last_used: time,
            backend_id: id,
            pad: 0,
        };
        // See lookup4.
        let _ = LB6_AFFINITY.insert(&affinity, &value, 0);
    }
    Lookup::Backend(backend, rev)
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
    match lookup4(ctx, address, port, proto) {
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
        return match lookup4(ctx, address, port, proto) {
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
    match lookup6(ctx, address, port, proto) {
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
