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
//! The `nodeport_*` tc programs serve NodePort, external and LoadBalancer
//! addresses to clients outside the cluster (IPv4 and IPv6, with SNAT to
//! backends on other nodes). Maglev, DSR, skip-LB and socket termination are not
//! implemented here.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK, __sk_buff, bpf_fib_lookup, bpf_sock_addr},
    helpers::{
        bpf_fib_lookup as fib_lookup, bpf_get_netns_cookie, bpf_get_prandom_u32,
        bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh,
    },
    macros::{cgroup_sock_addr, classifier, map},
    maps::{HashMap, LruHashMap},
    programs::{SockAddrContext, TcContext},
};
use flowsdn_bpf_abi::{
    Be16, Be32,
    affinity::{Lb4AffinityKey, Lb6AffinityKey, LbAffinityMatch, LbAffinityVal, NETNS_COOKIE},
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
static LB4_BACKENDS: HashMap<u32, Lb4Backend> = HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb4_reverse_sk")]
static LB4_REVERSE_SK: LruHashMap<Ipv4RevnatTuple, Ipv4RevnatEntry> =
    LruHashMap::with_max_entries(65536, 0);
#[map(name = "flowsdn_lb6_services")]
static LB6_SERVICES: HashMap<Lb6Key, LbService> =
    HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_lb6_backends")]
static LB6_BACKENDS: HashMap<u32, Lb6Backend> = HashMap::with_max_entries(65536, BPF_F_NO_PREALLOC);
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
    let nanoseconds = unsafe { bpf_ktime_get_ns() };
    nanoseconds / 1_000_000_000
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
fn lookup4(
    ctx: &SockAddrContext,
    address: [u8; 4],
    port: [u8; 2],
    proto: u8,
) -> Lookup<Lb4Backend> {
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
        affine(
            unsafe { LB4_AFFINITY.get(&affinity).copied() },
            rev,
            service.affinity_seconds(),
            time,
        )
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
fn lookup6(
    ctx: &SockAddrContext,
    address: [u8; 16],
    port: [u8; 2],
    proto: u8,
) -> Lookup<Lb6Backend> {
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
        affine(
            unsafe { LB6_AFFINITY.get(&affinity).copied() },
            rev,
            service.affinity_seconds(),
            time,
        )
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
    let [
        a0,
        a1,
        a2,
        a3,
        b0,
        b1,
        b2,
        b3,
        c0,
        c1,
        c2,
        c3,
        d0,
        d1,
        d2,
        d3,
    ] = bytes;
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

// ---------------------------------------------------------------------------
// NodePort, external and LoadBalancer addresses from outside the cluster
// (#292), IPv4 (IPv6 below): tc programs on the node's uplink. A packet to a frontend of
// the node-local scope (scope 1: this node's backends, or every backend
// unless externalTrafficPolicy is Local) is sent to a backend.
//
// The FIB decides where the backend is. Reached through another device (a
// pod's veth) or on this node: the destination is rewritten and the host
// stack routes it to the pod; the reply's source is rewritten back on the
// uplink's egress. Reached back out of the uplink it arrived on (a pod on
// another node): the packet is also source-NATed to this node's address
// toward that backend (the FIB's source, `BPF_FIB_LOOKUP_SRC`, Linux 6.7) on
// a port in 61000-65535, outside the kernel's default ephemeral range, and
// redirected straight back out (the stack would drop a packet from its own
// address as martian). The other node's reply to that port is reverse-NATed
// on this uplink's ingress and redirected to the client. The remote node
// must not masquerade it: it is the reply of a connection its conntrack saw
// arrive, which iptables/nftables masquerade leaves alone.
//
// Every direction of a flow is remembered in one LRU map, so a connection
// keeps its backend and NAT port. Neither program ever drops a packet:
// anything it does not handle passes untouched.

/// One direction of a translated flow: `a:ap -> b:bp`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nodeport4Key {
    a: [u8; 4],
    b: [u8; 4],
    ap: [u8; 2],
    bp: [u8; 2],
    proto: u8,
    direction: u8,
    pad: [u8; 2],
}
/// Client to frontend; the value is the backend (and with [`FLOW_SNAT`]
/// the NAT address and port in `other`).
const FORWARD: u8 = 0;
/// Local backend to client, at the uplink's egress; the value is the frontend.
const REPLY: u8 = 1;
/// Remote backend to the NAT address and port, at the uplink's ingress; the
/// value is the frontend, and the client in `other`.
const SNAT_REPLY: u8 = 2;
/// A forward flow to a backend on another node.
const FLOW_SNAT: u8 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nodeport4Value {
    address: [u8; 4],
    port: [u8; 2],
    flags: u8,
    pad: u8,
    other: [u8; 4],
    other_port: [u8; 2],
    pad2: [u8; 2],
}
#[map(name = "flowsdn_nodeport4_nat")]
static NODEPORT4: LruHashMap<Nodeport4Key, Nodeport4Value> = LruHashMap::with_max_entries(65536, 0);

const ETH_P_IPV4: [u8; 2] = [0x08, 0x00];
const BPF_F_PSEUDO_HDR: u64 = 1 << 4;
const BPF_F_MARK_MANGLED_0: u64 = 1 << 5;
const BPF_NOEXIST: u64 = 1;
const BPF_FIB_LOOKUP_SRC: u32 = 1 << 4;
const FIB_SUCCESS: i64 = 0;
const FIB_NO_NEIGH: i64 = 7;
const NAT_PORT_MIN: u32 = 61000;
const NAT_PORTS: u32 = 65536 - NAT_PORT_MIN;
/// NAT ports tried for a new flow before it is left untranslated.
const NAT_TRIES: u32 = 8;

/// The IPv4 TCP/UDP 5-tuple of a frame: (L4 offset, proto, src, dst,
/// sport, dport). Fragments other than the first carry no ports: skipped.
#[inline(always)]
fn tuple4(ctx: &TcContext) -> Option<(usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2])> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV4 {
        return None;
    }
    let version_ihl = ctx.load::<u8>(14).ok()?;
    if version_ihl >> 4 != 4 || version_ihl & 15 < 5 {
        return None;
    }
    let fragment = u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?);
    if fragment & 0x1fff != 0 {
        return None;
    }
    let proto = ctx.load::<u8>(23).ok()?;
    if proto != 6 && proto != 17 {
        return None;
    }
    let l4 = usize::from(version_ihl & 15)
        .checked_mul(4)?
        .checked_add(14)?;
    let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(l4).ok()?;
    Some((
        l4,
        proto,
        ctx.load::<[u8; 4]>(26).ok()?,
        ctx.load::<[u8; 4]>(30).ok()?,
        [s0, s1],
        [d0, d1],
    ))
}

/// Rewrite the address at `ip_offset` (26 source, 30 destination) and the
/// port at `port_offset`, keeping the IPv4 and TCP/UDP checksums right. A
/// UDP checksum of zero (none) stays zero.
#[inline(always)]
fn rewrite4(
    ctx: &TcContext,
    l4: usize,
    proto: u8,
    ip_offset: usize,
    port_offset: usize,
    old: ([u8; 4], [u8; 2]),
    new: ([u8; 4], [u8; 2]),
) -> Option<()> {
    let (old_ip, new_ip) = (u32::from_ne_bytes(old.0), u32::from_ne_bytes(new.0));
    let (old_port, new_port) = (u16::from_ne_bytes(old.1), u16::from_ne_bytes(new.1));
    let (checksum, mangled) = if proto == 6 {
        (l4.checked_add(16)?, 0)
    } else {
        (l4.checked_add(6)?, BPF_F_MARK_MANGLED_0)
    };
    let udp_without_checksum = proto == 17 && ctx.load::<u16>(checksum).ok()? == 0;
    if !udp_without_checksum {
        ctx.l4_csum_replace(
            checksum,
            u64::from(old_ip),
            u64::from(new_ip),
            BPF_F_PSEUDO_HDR | mangled | 4,
        )
        .ok()?;
        ctx.l4_csum_replace(
            checksum,
            u64::from(old_port),
            u64::from(new_port),
            mangled | 2,
        )
        .ok()?;
    }
    ctx.l3_csum_replace(24, u64::from(old_ip), u64::from(new_ip), 4)
        .ok()?;
    ctx.store(ip_offset, &new.0, 0).ok()?;
    ctx.store(port_offset, &new.1, 0).ok()?;
    Some(())
}

/// The device the program runs on: the uplink the packet arrived on.
#[inline(always)]
fn uplink(ctx: &TcContext) -> u32 {
    // SAFETY: a kernel-created TC context points at a live __sk_buff for the
    // duration of this program; ifindex is an allowed scalar context access.
    unsafe { (*ctx.skb.skb).ifindex }
}

/// An ingress FIB lookup from `src` to `dst` as if the packet arrived on
/// the uplink: (result, parameters with the output device, MACs and, with
/// [`BPF_FIB_LOOKUP_SRC`], the source address). Negative results are errors
/// (an unknown flag on a kernel before 6.7).
#[inline(always)]
fn fib4(
    ctx: &TcContext,
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    flags: u32,
) -> (i64, bpf_fib_lookup) {
    // SAFETY: the generated C struct contains only integers, integer arrays
    // and unions of those types; all-zero is a valid value of each, and the
    // inactive union bytes are initialized before the helper reads them.
    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    fib.family = 2; // AF_INET
    fib.l4_protocol = proto;
    fib.ifindex = uplink(ctx);
    fib.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes(src);
    fib.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes(dst);
    // SAFETY: `fib` is a live, aligned stack value of the helper's ABI type
    // and its real size; the helper does not keep the pointer.
    let result = unsafe {
        fib_lookup(
            ctx.as_ptr(),
            core::ptr::from_mut(&mut fib),
            core::mem::size_of::<bpf_fib_lookup>() as i32,
            flags,
        )
    };
    (result, fib)
}

/// Whether the FIB sends the packet out of a device (with or without a
/// resolved neighbour).
#[inline(always)]
fn forwarded(result: i64) -> bool {
    result == FIB_SUCCESS || result == FIB_NO_NEIGH
}

/// Send the (already translated) frame out of the FIB's device: with its
/// MACs when the neighbour is resolved, else through the neighbour
/// subsystem. TTL is decremented, as forwarding would.
#[inline(always)]
fn redirect(ctx: &TcContext, result: i64, fib: &bpf_fib_lookup) -> Option<i32> {
    let [ttl, proto] = ctx.load::<[u8; 2]>(22).ok()?;
    let lower = [ttl.checked_sub(1)?, proto];
    ctx.l3_csum_replace(
        24,
        u64::from(u16::from_ne_bytes([ttl, proto])),
        u64::from(u16::from_ne_bytes(lower)),
        2,
    )
    .ok()?;
    ctx.store(22, &lower, 0).ok()?;
    if result == FIB_SUCCESS {
        ctx.store(0, &fib.dmac, 0).ok()?;
        ctx.store(6, &fib.smac, 0).ok()?;
        // SAFETY: plain helper call with scalar arguments.
        Some(unsafe { bpf_redirect(fib.ifindex, 0) } as i32)
    } else {
        // SAFETY: no nexthop parameters (NULL, length 0): the kernel routes
        // the translated destination itself.
        Some(unsafe { bpf_redirect_neigh(fib.ifindex, core::ptr::null_mut(), 0, 0) } as i32)
    }
}

/// TTL that forwarding may still decrement.
#[inline(always)]
fn ttl_ok(ctx: &TcContext) -> Option<()> {
    (ctx.load::<u8>(22).ok()? > 1).then_some(())
}

/// A free NAT port toward `backend` from `nat`, claimed for `reply`
/// (keyed backend -> nat:port, so ports are per backend and protocol).
#[inline(always)]
fn claim_port(
    backend: ([u8; 4], [u8; 2]),
    nat: [u8; 4],
    proto: u8,
    reply: &Nodeport4Value,
) -> Option<[u8; 2]> {
    // SAFETY: no arguments; returns a pseudo-random scalar.
    let start = unsafe { bpf_get_prandom_u32() };
    for i in 0..NAT_TRIES {
        let offset = start.wrapping_add(i).checked_rem(NAT_PORTS)?;
        let port = u16::try_from(NAT_PORT_MIN.checked_add(offset)?)
            .ok()?
            .to_be_bytes();
        let key = Nodeport4Key {
            a: backend.0,
            b: nat,
            ap: backend.1,
            bp: port,
            proto,
            direction: SNAT_REPLY,
            pad: [0; 2],
        };
        if NODEPORT4.insert(&key, reply, BPF_NOEXIST).is_ok() {
            return Some(port);
        }
    }
    None
}

/// A remote backend's reply to a NAT port: back to the client, from the
/// frontend.
#[inline(always)]
fn snat_reply4(
    ctx: &TcContext,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
    flow: Nodeport4Value,
) -> Option<i32> {
    let (l4, proto, backend, nat, backend_port, nat_port) = tuple;
    ttl_ok(ctx)?;
    let (result, fib) = fib4(ctx, proto, flow.address, flow.other, 0);
    if !forwarded(result) {
        return None;
    }
    rewrite4(
        ctx,
        l4,
        proto,
        26,
        l4,
        (backend, backend_port),
        (flow.address, flow.port),
    )?;
    rewrite4(
        ctx,
        l4,
        proto,
        30,
        l4.checked_add(2)?,
        (nat, nat_port),
        (flow.other, flow.other_port),
    )?;
    redirect(ctx, result, &fib)
}

/// The client's packet to a remote backend: destination to the backend,
/// source to the NAT address and port, out of the uplink.
#[inline(always)]
fn snat_forward4(
    ctx: &TcContext,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
    flow: Nodeport4Value,
    route: Option<(i64, bpf_fib_lookup)>,
) -> Option<i32> {
    let (l4, proto, client, front, client_port, front_port) = tuple;
    ttl_ok(ctx)?;
    let (result, fib) = match route {
        Some(route) => route,
        None => fib4(ctx, proto, flow.other, flow.address, 0),
    };
    if !forwarded(result) {
        return None;
    }
    rewrite4(
        ctx,
        l4,
        proto,
        30,
        l4.checked_add(2)?,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    rewrite4(
        ctx,
        l4,
        proto,
        26,
        l4,
        (client, client_port),
        (flow.other, flow.other_port),
    )?;
    redirect(ctx, result, &fib)
}

#[inline(always)]
fn nodeport4_in(ctx: &TcContext) -> Option<i32> {
    let tuple = tuple4(ctx)?;
    let (l4, proto, client, front, client_port, front_port) = tuple;
    let mut key = Nodeport4Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    if let Some(flow) = unsafe { NODEPORT4.get(&key).copied() } {
        return snat_reply4(ctx, tuple, flow);
    }
    key.direction = FORWARD;
    let mut route = None;
    // SAFETY: LRU value copied at once, never written through.
    let flow = match unsafe { NODEPORT4.get(&key).copied() } {
        Some(known) => known,
        None => {
            let mut service_key = Lb4Key {
                address: Be32(front),
                dport: Be16(front_port),
                backend_slot: 0,
                proto,
                scope: 1,
                pad: [0; 2],
            };
            // SAFETY: see lookup4.
            let service = unsafe { LB4_SERVICES.get(&service_key).copied() }?;
            service_key.backend_slot = slot(service.count)?;
            // SAFETY: see lookup4.
            let entry = unsafe { LB4_SERVICES.get(&service_key).copied() }?;
            // SAFETY: see lookup4.
            let chosen = unsafe { LB4_BACKENDS.get(&entry.backend_id()).copied() }?;
            let backend = (chosen.address.0, chosen.port.0);
            let (result, fib) = fib4(ctx, proto, client, backend.0, 0);
            let mut flow = Nodeport4Value {
                address: backend.0,
                port: backend.1,
                flags: 0,
                pad: 0,
                other: [0; 4],
                other_port: [0; 2],
                pad2: [0; 2],
            };
            if forwarded(result) && fib.ifindex == uplink(ctx) {
                // Another node's backend: SNAT to this node's address there.
                ttl_ok(ctx)?;
                let (result, fib) = fib4(ctx, proto, [0; 4], backend.0, BPF_FIB_LOOKUP_SRC);
                if !forwarded(result) {
                    return None;
                }
                // SAFETY: the active member after an IPv4 lookup.
                let nat = unsafe { fib.__bindgen_anon_3.ipv4_src }.to_ne_bytes();
                let reply = Nodeport4Value {
                    address: front,
                    port: front_port,
                    flags: 0,
                    pad: 0,
                    other: client,
                    other_port: client_port,
                    pad2: [0; 2],
                };
                // The reply entry first: a reply must never find a flow it
                // cannot undo.
                flow.other_port = claim_port(backend, nat, proto, &reply)?;
                flow.other = nat;
                flow.flags = FLOW_SNAT;
                route = Some((result, fib));
            } else {
                let reverse = Nodeport4Key {
                    a: backend.0,
                    b: client,
                    ap: backend.1,
                    bp: client_port,
                    proto,
                    direction: REPLY,
                    pad: [0; 2],
                };
                let front_value = Nodeport4Value {
                    address: front,
                    port: front_port,
                    flags: 0,
                    pad: 0,
                    other: [0; 4],
                    other_port: [0; 2],
                    pad2: [0; 2],
                };
                NODEPORT4.insert(&reverse, &front_value, 0).ok()?;
            }
            NODEPORT4.insert(&key, &flow, 0).ok()?;
            flow
        }
    };
    if flow.flags & FLOW_SNAT != 0 {
        return snat_forward4(ctx, tuple, flow, route);
    }
    rewrite4(
        ctx,
        l4,
        proto,
        30,
        l4.checked_add(2)?,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    Some(TC_ACT_OK)
}

#[inline(always)]
fn nodeport4_out(ctx: &TcContext) -> Option<()> {
    let (l4, proto, backend, client, backend_port, client_port) = tuple4(ctx)?;
    let reverse = Nodeport4Key {
        a: backend,
        b: client,
        ap: backend_port,
        bp: client_port,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let front = unsafe { NODEPORT4.get(&reverse).copied() }?;
    rewrite4(
        ctx,
        l4,
        proto,
        26,
        l4,
        (backend, backend_port),
        (front.address, front.port),
    )
}

// IPv6: the same flows, keyed and translated the same way. There is no
// IPv6 header checksum; the TCP/UDP checksum covers the addresses through the
// pseudo-header, so each 32-bit word of a rewritten address is replaced in
// it. Only TCP/UDP directly after the fixed header is handled: a packet with
// extension headers (a fragment among them) passes untouched.

/// One direction of a translated IPv6 flow (see [`Nodeport4Key`]).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nodeport6Key {
    a: [u8; 16],
    b: [u8; 16],
    ap: [u8; 2],
    bp: [u8; 2],
    proto: u8,
    direction: u8,
    pad: [u8; 2],
}
/// See [`Nodeport4Value`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Nodeport6Value {
    address: [u8; 16],
    port: [u8; 2],
    flags: u8,
    pad: u8,
    other: [u8; 16],
    other_port: [u8; 2],
    pad2: [u8; 2],
}
#[map(name = "flowsdn_nodeport6_nat")]
static NODEPORT6: LruHashMap<Nodeport6Key, Nodeport6Value> = LruHashMap::with_max_entries(65536, 0);

const ETH_P_IPV6: [u8; 2] = [0x86, 0xdd];
/// Offsets in the frame: next header, hop limit, source, destination, then
/// the L4 source port, destination port and UDP/TCP checksum.
const IP6_NEXT: usize = 20;
const IP6_HOPS: usize = 21;
const IP6_SRC: usize = 22;
const IP6_DST: usize = 38;
const IP6_SPORT: usize = 54;
const IP6_DPORT: usize = 56;
const IP6_UDP_CHECK: usize = 60;
const IP6_TCP_CHECK: usize = 70;

/// The IPv6 TCP/UDP 5-tuple of a frame: (proto, src, dst, sport, dport).
#[inline(always)]
fn tuple6(ctx: &TcContext) -> Option<(u8, [u8; 16], [u8; 16], [u8; 2], [u8; 2])> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV6 {
        return None;
    }
    if ctx.load::<u8>(14).ok()? >> 4 != 6 {
        return None;
    }
    let proto = ctx.load::<u8>(IP6_NEXT).ok()?;
    if proto != 6 && proto != 17 {
        return None;
    }
    let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(IP6_SPORT).ok()?;
    Some((
        proto,
        ctx.load::<[u8; 16]>(IP6_SRC).ok()?,
        ctx.load::<[u8; 16]>(IP6_DST).ok()?,
        [s0, s1],
        [d0, d1],
    ))
}

/// Rewrite the address at `ip_offset` ([`IP6_SRC`] or [`IP6_DST`]) and the
/// port at `port_offset`, keeping the TCP/UDP checksum right. A UDP checksum
/// of zero (none) stays zero.
#[inline(always)]
fn rewrite6(
    ctx: &TcContext,
    proto: u8,
    ip_offset: usize,
    port_offset: usize,
    old: ([u8; 16], [u8; 2]),
    new: ([u8; 16], [u8; 2]),
) -> Option<()> {
    let (checksum, mangled) = if proto == 6 {
        (IP6_TCP_CHECK, 0)
    } else {
        (IP6_UDP_CHECK, BPF_F_MARK_MANGLED_0)
    };
    let udp_without_checksum = proto == 17 && ctx.load::<u16>(checksum).ok()? == 0;
    if !udp_without_checksum {
        let [o0, o1, o2, o3] = ip6_words(old.0);
        let [n0, n1, n2, n3] = ip6_words(new.0);
        for (from, to) in [(o0, n0), (o1, n1), (o2, n2), (o3, n3)] {
            ctx.l4_csum_replace(
                checksum,
                u64::from(from),
                u64::from(to),
                BPF_F_PSEUDO_HDR | mangled | 4,
            )
            .ok()?;
        }
        ctx.l4_csum_replace(
            checksum,
            u64::from(u16::from_ne_bytes(old.1)),
            u64::from(u16::from_ne_bytes(new.1)),
            mangled | 2,
        )
        .ok()?;
    }
    ctx.store(ip_offset, &new.0, 0).ok()?;
    ctx.store(port_offset, &new.1, 0).ok()?;
    Some(())
}

/// [`fib4`] for IPv6.
#[inline(always)]
fn fib6(
    ctx: &TcContext,
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
    flags: u32,
) -> (i64, bpf_fib_lookup) {
    // SAFETY: as in fib4.
    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    fib.family = 10; // AF_INET6
    fib.l4_protocol = proto;
    fib.ifindex = uplink(ctx);
    fib.__bindgen_anon_3.ipv6_src = ip6_words(src);
    fib.__bindgen_anon_4.ipv6_dst = ip6_words(dst);
    // SAFETY: as in fib4.
    let result = unsafe {
        fib_lookup(
            ctx.as_ptr(),
            core::ptr::from_mut(&mut fib),
            core::mem::size_of::<bpf_fib_lookup>() as i32,
            flags,
        )
    };
    (result, fib)
}

/// [`redirect`] for IPv6: the hop limit is decremented (no header checksum).
#[inline(always)]
fn redirect6(ctx: &TcContext, result: i64, fib: &bpf_fib_lookup) -> Option<i32> {
    let hops = ctx.load::<u8>(IP6_HOPS).ok()?.checked_sub(1)?;
    ctx.store(IP6_HOPS, &hops, 0).ok()?;
    if result == FIB_SUCCESS {
        ctx.store(0, &fib.dmac, 0).ok()?;
        ctx.store(6, &fib.smac, 0).ok()?;
        // SAFETY: plain helper call with scalar arguments.
        Some(unsafe { bpf_redirect(fib.ifindex, 0) } as i32)
    } else {
        // SAFETY: as in redirect.
        Some(unsafe { bpf_redirect_neigh(fib.ifindex, core::ptr::null_mut(), 0, 0) } as i32)
    }
}

/// A hop limit that forwarding may still decrement.
#[inline(always)]
fn hops_ok(ctx: &TcContext) -> Option<()> {
    (ctx.load::<u8>(IP6_HOPS).ok()? > 1).then_some(())
}

/// [`claim_port`] for IPv6.
#[inline(always)]
fn claim_port6(
    backend: ([u8; 16], [u8; 2]),
    nat: [u8; 16],
    proto: u8,
    reply: &Nodeport6Value,
) -> Option<[u8; 2]> {
    // SAFETY: no arguments; returns a pseudo-random scalar.
    let start = unsafe { bpf_get_prandom_u32() };
    for i in 0..NAT_TRIES {
        let offset = start.wrapping_add(i).checked_rem(NAT_PORTS)?;
        let port = u16::try_from(NAT_PORT_MIN.checked_add(offset)?)
            .ok()?
            .to_be_bytes();
        let key = Nodeport6Key {
            a: backend.0,
            b: nat,
            ap: backend.1,
            bp: port,
            proto,
            direction: SNAT_REPLY,
            pad: [0; 2],
        };
        if NODEPORT6.insert(&key, reply, BPF_NOEXIST).is_ok() {
            return Some(port);
        }
    }
    None
}

/// [`snat_reply4`] for IPv6.
#[inline(always)]
fn snat_reply6(
    ctx: &TcContext,
    tuple: (u8, [u8; 16], [u8; 16], [u8; 2], [u8; 2]),
    flow: Nodeport6Value,
) -> Option<i32> {
    let (proto, backend, nat, backend_port, nat_port) = tuple;
    hops_ok(ctx)?;
    let (result, fib) = fib6(ctx, proto, flow.address, flow.other, 0);
    if !forwarded(result) {
        return None;
    }
    rewrite6(
        ctx,
        proto,
        IP6_SRC,
        IP6_SPORT,
        (backend, backend_port),
        (flow.address, flow.port),
    )?;
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (nat, nat_port),
        (flow.other, flow.other_port),
    )?;
    redirect6(ctx, result, &fib)
}

/// [`snat_forward4`] for IPv6.
#[inline(always)]
fn snat_forward6(
    ctx: &TcContext,
    tuple: (u8, [u8; 16], [u8; 16], [u8; 2], [u8; 2]),
    flow: Nodeport6Value,
) -> Option<i32> {
    let (proto, client, front, client_port, front_port) = tuple;
    hops_ok(ctx)?;
    // Looked up again rather than kept from the first packet's lookup: a
    // second 64-byte lookup result would not fit the stack.
    let (result, fib) = fib6(ctx, proto, flow.other, flow.address, 0);
    if !forwarded(result) {
        return None;
    }
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    rewrite6(
        ctx,
        proto,
        IP6_SRC,
        IP6_SPORT,
        (client, client_port),
        (flow.other, flow.other_port),
    )?;
    redirect6(ctx, result, &fib)
}

/// [`nodeport4_in`] for IPv6.
#[inline(always)]
fn nodeport6_in(ctx: &TcContext) -> Option<i32> {
    let tuple = tuple6(ctx)?;
    let (proto, client, front, client_port, front_port) = tuple;
    let mut key = Nodeport6Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    if let Some(flow) = unsafe { NODEPORT6.get(&key).copied() } {
        return snat_reply6(ctx, tuple, flow);
    }
    key.direction = FORWARD;
    // SAFETY: LRU value copied at once, never written through.
    let flow = match unsafe { NODEPORT6.get(&key).copied() } {
        Some(known) => known,
        None => {
            let mut service_key = Lb6Key {
                address: front,
                dport: Be16(front_port),
                backend_slot: 0,
                proto,
                scope: 1,
                pad: [0; 2],
            };
            // SAFETY: see lookup6.
            let service = unsafe { LB6_SERVICES.get(&service_key).copied() }?;
            service_key.backend_slot = slot(service.count)?;
            // SAFETY: see lookup6.
            let entry = unsafe { LB6_SERVICES.get(&service_key).copied() }?;
            // SAFETY: see lookup6.
            let chosen = unsafe { LB6_BACKENDS.get(&entry.backend_id()).copied() }?;
            let backend = (chosen.address, chosen.port.0);
            let (result, fib) = fib6(ctx, proto, client, backend.0, 0);
            let mut flow = Nodeport6Value {
                address: backend.0,
                port: backend.1,
                flags: 0,
                pad: 0,
                other: [0; 16],
                other_port: [0; 2],
                pad2: [0; 2],
            };
            if forwarded(result) && fib.ifindex == uplink(ctx) {
                // Another node's backend: SNAT to this node's address there.
                hops_ok(ctx)?;
                let (result, source) = fib6(ctx, proto, [0; 16], backend.0, BPF_FIB_LOOKUP_SRC);
                if !forwarded(result) {
                    return None;
                }
                // SAFETY: the active member after an IPv6 lookup.
                let nat = ip6_bytes(unsafe { source.__bindgen_anon_3.ipv6_src });
                let reply = Nodeport6Value {
                    address: front,
                    port: front_port,
                    flags: 0,
                    pad: 0,
                    other: client,
                    other_port: client_port,
                    pad2: [0; 2],
                };
                // The reply entry first: a reply must never find a flow it
                // cannot undo.
                flow.other_port = claim_port6(backend, nat, proto, &reply)?;
                flow.other = nat;
                flow.flags = FLOW_SNAT;
            } else {
                let reverse = Nodeport6Key {
                    a: backend.0,
                    b: client,
                    ap: backend.1,
                    bp: client_port,
                    proto,
                    direction: REPLY,
                    pad: [0; 2],
                };
                let front_value = Nodeport6Value {
                    address: front,
                    port: front_port,
                    flags: 0,
                    pad: 0,
                    other: [0; 16],
                    other_port: [0; 2],
                    pad2: [0; 2],
                };
                NODEPORT6.insert(&reverse, &front_value, 0).ok()?;
            }
            NODEPORT6.insert(&key, &flow, 0).ok()?;
            flow
        }
    };
    if flow.flags & FLOW_SNAT != 0 {
        return snat_forward6(ctx, tuple, flow);
    }
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    Some(TC_ACT_OK)
}

/// [`nodeport4_out`] for IPv6.
#[inline(always)]
fn nodeport6_out(ctx: &TcContext) -> Option<()> {
    let (proto, backend, client, backend_port, client_port) = tuple6(ctx)?;
    let reverse = Nodeport6Key {
        a: backend,
        b: client,
        ap: backend_port,
        bp: client_port,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let front = unsafe { NODEPORT6.get(&reverse).copied() }?;
    rewrite6(
        ctx,
        proto,
        IP6_SRC,
        IP6_SPORT,
        (backend, backend_port),
        (front.address, front.port),
    )
}

// Each family's path is its own BPF function (a BPF-to-BPF call), so each
// gets its own stack frame: inlined together they exceed the 512-byte stack.
#[inline(never)]
fn ingress4(skb: *mut __sk_buff) -> i32 {
    nodeport4_in(&TcContext::new(skb)).unwrap_or(TC_ACT_OK)
}
#[inline(never)]
fn ingress6(skb: *mut __sk_buff) -> i32 {
    nodeport6_in(&TcContext::new(skb)).unwrap_or(TC_ACT_OK)
}
#[inline(never)]
fn egress4(skb: *mut __sk_buff) -> i32 {
    let _ = nodeport4_out(&TcContext::new(skb));
    TC_ACT_OK
}
#[inline(never)]
fn egress6(skb: *mut __sk_buff) -> i32 {
    let _ = nodeport6_out(&TcContext::new(skb));
    TC_ACT_OK
}

#[classifier]
pub fn nodeport_ingress(ctx: TcContext) -> i32 {
    match ctx.load::<[u8; 2]>(12) {
        Ok(ETH_P_IPV6) => ingress6(ctx.skb.skb),
        _ => ingress4(ctx.skb.skb),
    }
}
#[classifier]
pub fn nodeport_egress(ctx: TcContext) -> i32 {
    match ctx.load::<[u8; 2]>(12) {
        Ok(ETH_P_IPV6) => egress6(ctx.skb.skb),
        _ => egress4(ctx.skb.skb),
    }
}

// SAFETY: unique immutable ELF license declaration, required by the loader.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
