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
//! backends on other nodes). A frontend whose master carries the Maglev
//! algorithm picks a new flow's backend from its lookup table in
//! `flowsdn_lb{4,6}_maglev` by the flow hash, so every node sends a flow to
//! the same backend (spec 05 §3.13, §5.1); without a table it picks at
//! random. DSR and skip-LB are not implemented here; the agent terminates
//! sockets.
#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT, __sk_buff, bpf_fib_lookup, bpf_sock_addr},
    helpers::{
        bpf_check_mtu, bpf_csum_diff, bpf_fib_lookup as fib_lookup, bpf_get_netns_cookie,
        bpf_get_prandom_u32, bpf_get_socket_cookie, bpf_ktime_get_ns, bpf_redirect,
        bpf_redirect_neigh, bpf_skb_change_proto,
    },
    btf_maps::{Array as BtfArray, HashOfMaps},
    macros::{btf_map, cgroup_sock_addr, classifier, map},
    maps::{HashMap, LruHashMap, PerCpuArray},
    programs::{SockAddrContext, TcContext},
};
use flowsdn_bpf_abi::{
    Be16, Be32,
    affinity::{Lb4AffinityKey, Lb6AffinityKey, LbAffinityMatch, LbAffinityVal, NETNS_COOKIE},
    lb::{
        Ipv4RevnatEntry, Ipv4RevnatTuple, Ipv6RevnatEntry, Ipv6RevnatTuple, Lb4Backend, Lb4Key,
        Lb6Backend, Lb6Key, LbService, service_flags,
    },
    maglev::{self, ALGORITHM_MAGLEV, TABLE_LEN},
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

/// Each Maglev frontend's lookup table by service ID (`rev_nat_index`):
/// [`TABLE_LEN`] backend IDs in the single entry of an inner array. The agent
/// swaps in a new inner map rather than writing into one.
#[btf_map(name = "flowsdn_lb4_maglev")]
static LB4_MAGLEV: HashOfMaps<u16, BtfArray<[u32; TABLE_LEN], 1>, 65536> = HashOfMaps::new();
#[btf_map(name = "flowsdn_lb6_maglev")]
static LB6_MAGLEV: HashOfMaps<u16, BtfArray<[u32; TABLE_LEN], 1>, 65536> = HashOfMaps::new();

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

/// The client port a Maglev flow hash uses: none with session affinity, so
/// a client keeps its backend.
#[inline(always)]
fn maglev_port(service: &LbService, client_port: [u8; 2]) -> u16 {
    if service.service_flags() & service_flags::SESSION_AFFINITY != 0 {
        0
    } else {
        u16::from_be_bytes(client_port)
    }
}
/// A flow hash's entry of a Maglev table. `% TABLE_SIZE` compiles to a multiply
/// and shifts whose range the verifier cannot follow, and LLVM drops a bounds
/// check it can prove true ("R0 unbounded memory access"). The volatile read
/// hides the proof, so the check stays and is what the verifier sees.
#[inline(always)]
fn table_entry(table: &[u32; TABLE_LEN], hash: u32) -> Option<u32> {
    let reduced = maglev::entry(hash);
    // SAFETY: a read of a local.
    let index = unsafe { core::ptr::read_volatile(&reduced) };
    table.get(usize::try_from(index).ok()?).copied()
}
/// The backend ID a Maglev frontend's table gives a new flow; `None` when
/// the master is not Maglev or has no table (the caller picks at random).
#[inline(always)]
fn maglev4(
    service: &LbService,
    client: [u8; 4],
    client_port: [u8; 2],
    front_port: [u8; 2],
    proto: u8,
) -> Option<u32> {
    if service.algorithm_code() != ALGORITHM_MAGLEV {
        return None;
    }
    let hash = maglev::flow_hash4(
        client,
        maglev_port(service, client_port),
        u16::from_be_bytes(front_port),
        proto,
    );
    // SAFETY: read once; the agent never writes into a published table.
    let table = unsafe { LB4_MAGLEV.get_value(&service.rev_nat_index, &0) }?;
    table_entry(table, hash)
}
/// [`maglev4`] for IPv6.
#[inline(always)]
fn maglev6(
    service: &LbService,
    client: [u8; 16],
    client_port: [u8; 2],
    front_port: [u8; 2],
    proto: u8,
) -> Option<u32> {
    if service.algorithm_code() != ALGORITHM_MAGLEV {
        return None;
    }
    let hash = maglev::flow_hash6(
        client,
        maglev_port(service, client_port),
        u16::from_be_bytes(front_port),
        proto,
    );
    // SAFETY: as in maglev4.
    let table = unsafe { LB6_MAGLEV.get_value(&service.rev_nat_index, &0) }?;
    table_entry(table, hash)
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
    // SAFETY: same size, and every bit pattern is valid for both types. A
    // byte-wise conversion needs 16 values live at once: BPF's ten registers
    // spill them onto the 512-byte stack.
    unsafe { core::mem::transmute::<[u32; 4], [u8; 16]>(words) }
}
#[inline(always)]
fn ip6_words(bytes: [u8; 16]) -> [u32; 4] {
    // SAFETY: as in ip6_bytes.
    unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(bytes) }
}
/// Store an IPv6 address into the context's `user_ip6`: four scalar stores
/// at fixed context offsets. An array assignment from a stack value compiles
/// to a copy through a pointer to `ctx + 8`, which the verifier refuses
/// ("dereference of modified ctx ptr", 7.2, run c61945e336); volatile keeps
/// LLVM from merging the stores back into that copy.
#[inline(always)]
fn set_user_ip6(raw: &mut bpf_sock_addr, words: [u32; 4]) {
    let [a, b, c, d] = words;
    let [ra, rb, rc, rd] = &mut raw.user_ip6;
    // SAFETY: each pointer is a valid, aligned field of the kernel context.
    unsafe {
        core::ptr::write_volatile(ra, a);
        core::ptr::write_volatile(rb, b);
        core::ptr::write_volatile(rc, c);
        core::ptr::write_volatile(rd, d);
    }
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
                set_user_ip6(raw, [0, 0, MAPPED, u32::from_ne_bytes(backend.address.0)]);
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
            set_user_ip6(raw, ip6_words(backend.address));
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
            set_user_ip6(raw, [0, 0, MAPPED, u32::from_ne_bytes(front.address.0)]);
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
        set_user_ip6(raw, ip6_words(front.address));
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
// With `FWD_MODE_DSR` on the frontend (spec 05 §3.12), a backend on another
// node gets the client's own source: the packet is DNATed and redirected with
// the frontend in an IP option (spec 02 §2.5) on a TCP SYN or each UDP packet
// that fits the device's MTU. The backend's node reads the option at its
// uplink's ingress into a reply entry, and its uplink's egress rewrites the
// reply's source to the frontend, so replies skip this node. A too-big UDP
// packet goes without the option: DSR ICMP errors are not implemented.
//
// A frontend whose master carries `NAT46X64` (spec 04 §3.15, spec 05 §3.1) has
// backends of the other family, on other nodes: see "Service NAT46/64" below.
//
// Every direction of a flow is remembered in one LRU map, so a connection
// keeps its backend and NAT port. Neither program drops a packet it has not
// begun to translate: anything it does not handle passes untouched.

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
/// A forward flow to a backend on another node, keeping the client's source.
const FLOW_DSR: u8 = 2;
/// A flow translated between IPv4 and IPv6.
const FLOW_XLATE: u8 = 4;
/// The IPv4 DSR option's type (`IPOPT_COPY | 0x1a`) and length.
const DSR_OPT4: [u8; 2] = [0x9a, 8];
/// The IPv6 DSR Destination Options header's length and its option's type and
/// length (spec 02 §2.5).
const DSR_OPT6_LEN: i32 = 24;
const DSR_OPT6: [u8; 2] = [0x1b, 20];
const IPPROTO_DSTOPTS: u8 = 60;
/// `BPF_ADJ_ROOM_NET`: room after the fixed network header.
const ADJ_ROOM_NET: u32 = 0;
const TCP_FLAGS_SYN_ACK: u8 = 0x12;
const TCP_FLAG_SYN: u8 = 0x02;

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

/// Whether a packet going out of `device` carries the DSR option: a TCP SYN
/// (later packets find the reply entry the SYN left) or a UDP packet that
/// still fits the device's MTU with `room` more bytes.
#[inline(always)]
fn dsr_option_wanted(ctx: &TcContext, l4: usize, proto: u8, device: u32, room: i32) -> Option<bool> {
    if proto == 6 {
        let flags = ctx.load::<u8>(l4.checked_add(13)?).ok()?;
        return Some(flags & TCP_FLAGS_SYN_ACK == TCP_FLAG_SYN);
    }
    let mut mtu: u32 = 0;
    // SAFETY: a live skb; `mtu` is a local the helper writes.
    let fits = unsafe { bpf_check_mtu(ctx.skb.skb.cast(), device, &mut mtu, room, 0) };
    Some(fits == 0)
}

/// Add the frontend as an IP option to a packet with a bare 20-byte header.
/// An option covers neither L4 checksum, only the header's.
#[inline(always)]
fn push_option4(ctx: &TcContext, front: [u8; 4], port: [u8; 2]) -> Option<()> {
    let first = ctx.load::<[u8; 2]>(14).ok()?;
    let total = ctx.load::<[u8; 2]>(16).ok()?;
    ctx.skb.adjust_room(8, ADJ_ROOM_NET, 0).ok()?;
    let new_first = [0x47, first[1]];
    let new_total = u16::from_be_bytes(total).checked_add(8)?.to_be_bytes();
    let head = [DSR_OPT4[0], DSR_OPT4[1], port[0], port[1]];
    ctx.store(14, &new_first, 0).ok()?;
    ctx.store(16, &new_total, 0).ok()?;
    ctx.store(34, &head, 0).ok()?;
    ctx.store(38, &front, 0).ok()?;
    let words = [
        (u16::from_ne_bytes(first), u16::from_ne_bytes(new_first)),
        (u16::from_ne_bytes(total), u16::from_ne_bytes(new_total)),
    ];
    for (old, new) in words {
        ctx.l3_csum_replace(24, u64::from(old), u64::from(new), 2)
            .ok()?;
    }
    for word in [u32::from_ne_bytes(head), u32::from_ne_bytes(front)] {
        ctx.l3_csum_replace(24, 0, u64::from(word), 4).ok()?;
    }
    Some(())
}

/// The client's packet to a backend on another node, keeping its source.
#[inline(always)]
fn dsr_forward4(
    ctx: &TcContext,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
    flow: Nodeport4Value,
    route: Option<(i64, bpf_fib_lookup)>,
) -> Option<i32> {
    let (l4, proto, client, front, _, front_port) = tuple;
    ttl_ok(ctx)?;
    let (result, fib) = match route {
        Some(route) => route,
        None => fib4(ctx, proto, client, flow.address, 0),
    };
    if !forwarded(result) {
        return None;
    }
    // A packet that already has options passes without ours.
    let option = l4 == 34 && dsr_option_wanted(ctx, l4, proto, fib.ifindex, 8)?;
    rewrite4(
        ctx,
        l4,
        proto,
        30,
        l4.checked_add(2)?,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    if option {
        push_option4(ctx, front, front_port)?;
    }
    redirect(ctx, result, &fib)
}

/// On the backend's node: a packet carrying the DSR option leaves the reply
/// entry [`nodeport4_out`] rewrites by. The packet itself goes on to the pod.
#[inline(always)]
fn dsr_backend4(
    ctx: &TcContext,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
) -> Option<()> {
    let (l4, proto, client, backend, client_port, backend_port) = tuple;
    if l4 != 42 || ctx.load::<[u8; 2]>(34).ok()? != DSR_OPT4 {
        return None;
    }
    let reverse = Nodeport4Key {
        a: backend,
        b: client,
        ap: backend_port,
        bp: client_port,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    let front = Nodeport4Value {
        address: ctx.load::<[u8; 4]>(38).ok()?,
        port: ctx.load::<[u8; 2]>(36).ok()?,
        flags: 0,
        pad: 0,
        other: [0; 4],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    NODEPORT4.insert(&reverse, &front, 0).ok()
}

#[inline(always)]
fn nodeport4_in(ctx: &TcContext) -> Option<i32> {
    let tuple = tuple4(ctx)?;
    if dsr_backend4(ctx, tuple).is_some() {
        return Some(TC_ACT_OK);
    }
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
        // A NAT64 flow's port reservation: its reply entry is in XLATE4.
        if flow.flags & FLOW_XLATE != 0 {
            return None;
        }
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
            let id = match maglev4(&service, client, client_port, front_port, proto) {
                Some(id) => id,
                None => {
                    service_key.backend_slot = slot(service.count)?;
                    // SAFETY: see lookup4.
                    let entry = unsafe { LB4_SERVICES.get(&service_key).copied() }?;
                    entry.backend_id()
                }
            };
            // SAFETY: see lookup4.
            let chosen = unsafe { LB4_BACKENDS.get(&id).copied() }?;
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
            let remote = forwarded(result) && fib.ifindex == uplink(ctx);
            if remote && service.service_flags() & service_flags::FWD_MODE_DSR != 0 {
                flow.flags = FLOW_DSR;
                route = Some((result, fib));
            } else if remote {
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
    if flow.flags & FLOW_DSR != 0 {
        return dsr_forward4(ctx, tuple, flow, route);
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
/// The payload-length field, and where an extension header after the fixed
/// header starts.
const IP6_PAYLOAD: usize = 18;
const IP6_OPT: usize = 54;
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
        let flags = BPF_F_PSEUDO_HDR | mangled | 4;
        ctx.l4_csum_replace(checksum, u64::from(o0), u64::from(n0), flags)
            .ok()?;
        ctx.l4_csum_replace(checksum, u64::from(o1), u64::from(n1), flags)
            .ok()?;
        ctx.l4_csum_replace(checksum, u64::from(o2), u64::from(n2), flags)
            .ok()?;
        ctx.l4_csum_replace(checksum, u64::from(o3), u64::from(n3), flags)
            .ok()?;
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

/// The IPv6 FIB lookup's parameters: per CPU rather than on the stack, which
/// the IPv6 path cannot spare 64 bytes of. A tc program runs to completion on
/// its CPU, so one slot serves every lookup of an invocation; each result is
/// read before the next lookup.
#[map(name = "flowsdn_nodeport6_fib")]
static FIB6: PerCpuArray<bpf_fib_lookup> = PerCpuArray::with_max_entries(1, 0);

/// [`fib4`] for IPv6, in the [`FIB6`] slot: (result, the slot). `None` only
/// if the slot is missing.
#[inline(always)]
fn fib6(
    ctx: &TcContext,
    proto: u8,
    src: [u8; 16],
    dst: [u8; 16],
    flags: u32,
) -> Option<(i64, *const bpf_fib_lookup)> {
    let fib = FIB6.get_ptr_mut(0)?;
    // SAFETY: the map value of this CPU, valid for the whole invocation and
    // used by nothing else meanwhile; all-zero is a valid bpf_fib_lookup (see
    // fib4). No reference to it outlives this function.
    unsafe {
        core::ptr::write_bytes(fib, 0, 1);
        (*fib).family = 10; // AF_INET6
        (*fib).l4_protocol = proto;
        (*fib).ifindex = uplink(ctx);
        (*fib).__bindgen_anon_3.ipv6_src = ip6_words(src);
        (*fib).__bindgen_anon_4.ipv6_dst = ip6_words(dst);
    }
    // SAFETY: `fib` is the helper's ABI type at its real size in map memory;
    // the helper does not keep the pointer.
    let result = unsafe {
        fib_lookup(
            ctx.as_ptr(),
            fib,
            core::mem::size_of::<bpf_fib_lookup>() as i32,
            flags,
        )
    };
    Some((result, fib))
}

/// [`redirect`] for IPv6: the hop limit is decremented (no header checksum).
/// `fib` is the [`FIB6`] slot of the lookup that routed the packet.
#[inline(always)]
fn redirect6(ctx: &TcContext, result: i64, fib: *const bpf_fib_lookup) -> Option<i32> {
    let hops = ctx.load::<u8>(IP6_HOPS).ok()?.checked_sub(1)?;
    ctx.store(IP6_HOPS, &hops, 0).ok()?;
    // SAFETY: the per-CPU slot fib6 just filled; plain field reads.
    let (ifindex, dmac, smac) = unsafe { ((*fib).ifindex, (*fib).dmac, (*fib).smac) };
    if result == FIB_SUCCESS {
        ctx.store(0, &dmac, 0).ok()?;
        ctx.store(6, &smac, 0).ok()?;
        // SAFETY: plain helper call with scalar arguments.
        Some(unsafe { bpf_redirect(ifindex, 0) } as i32)
    } else {
        // SAFETY: as in redirect.
        Some(unsafe { bpf_redirect_neigh(ifindex, core::ptr::null_mut(), 0, 0) } as i32)
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

/// An IPv6 frame's TCP/UDP 5-tuple: (proto, src, dst, sport, dport).
type Tuple6 = (u8, [u8; 16], [u8; 16], [u8; 2], [u8; 2]);

// The IPv6 path is split into BPF functions (BPF-to-BPF calls), each with
// its own stack frame: inlined into one, its keys, values and addresses
// exceed the 512-byte frame. The verifier also limits the frames of a call
// chain to 512 bytes combined (#369), so no IPv6 function calls another:
// [`ingress6`] classifies the frame into the [`INGRESS6`] slot and returns a
// step, and the classifier calls the step's function, which reads the slot.

/// The IPv6 ingress path's state between its BPF functions: the frame's
/// tuple and its flow ([`Nodeport6Value`], all zero for a new flow until
/// [`new_flow6`] fills it).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ingress6 {
    tuple: Tuple6,
    flow: Nodeport6Value,
}
/// The [`Ingress6`] slot: per CPU for the reason [`FIB6`] is.
#[map(name = "flowsdn_nodeport6_scratch")]
static INGRESS6: PerCpuArray<Ingress6> = PerCpuArray::with_max_entries(1, 0);

/// [`ingress6`]'s steps: not ours, a reply of an SNAT flow, a new flow, a
/// known forward flow.
const STEP_PASS: i32 = 0;
const STEP_REPLY: i32 = 1;
const STEP_NEW: i32 = 2;
const STEP_FORWARD: i32 = 3;
/// A translated flow's reply and, on the IPv6 side, its forward packet.
const STEP_XLATE_REPLY: i32 = 4;
const STEP_XLATE_FORWARD: i32 = 5;

/// [`dsr_backend4`] for IPv6: the option is a Destination Options header right
/// after the fixed one, its next header the L4 protocol.
#[inline(always)]
fn dsr_backend6(ctx: &TcContext) -> Option<()> {
    if ctx.load::<[u8; 2]>(IP6_OPT.checked_add(2)?).ok()? != DSR_OPT6 {
        return None;
    }
    let proto = ctx.load::<u8>(IP6_OPT).ok()?;
    let l4 = IP6_SPORT.checked_add(usize::try_from(DSR_OPT6_LEN).ok()?)?;
    let reverse = Nodeport6Key {
        a: ctx.load::<[u8; 16]>(IP6_DST).ok()?,
        b: ctx.load::<[u8; 16]>(IP6_SRC).ok()?,
        ap: ctx.load::<[u8; 2]>(l4.checked_add(2)?).ok()?,
        bp: ctx.load::<[u8; 2]>(l4).ok()?,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    let front = Nodeport6Value {
        address: ctx.load::<[u8; 16]>(IP6_OPT.checked_add(4)?).ok()?,
        port: ctx.load::<[u8; 2]>(IP6_OPT.checked_add(20)?).ok()?,
        flags: 0,
        pad: 0,
        other: [0; 16],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    NODEPORT6.insert(&reverse, &front, 0).ok()
}

/// [`nodeport4_in`] for IPv6, up to the flow lookup: fill [`INGRESS6`] and
/// return the step.
#[inline(never)]
fn ingress6(skb: *mut __sk_buff) -> i32 {
    classify6(&TcContext::new(skb)).unwrap_or(STEP_PASS)
}
#[inline(always)]
fn classify6(ctx: &TcContext) -> Option<i32> {
    let state = INGRESS6.get_ptr_mut(0)?;
    if ctx.load::<u8>(IP6_NEXT).ok()? == IPPROTO_DSTOPTS {
        let _ = dsr_backend6(ctx);
        return Some(STEP_PASS);
    }
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
    let (step, flow) = if let Some(flow) = unsafe { NODEPORT6.get(&key).copied() } {
        (STEP_REPLY, flow)
    } else {
        key.direction = FORWARD;
        // SAFETY: as above.
        match unsafe { NODEPORT6.get(&key).copied() } {
            Some(known) => (STEP_FORWARD, known),
            None => (
                STEP_NEW,
                Nodeport6Value {
                    address: [0; 16],
                    port: [0; 2],
                    flags: 0,
                    pad: 0,
                    other: [0; 16],
                    other_port: [0; 2],
                    pad2: [0; 2],
                },
            ),
        }
    };
    let step = match step {
        STEP_REPLY if flow.flags & FLOW_XLATE != 0 => STEP_XLATE_REPLY,
        STEP_FORWARD if flow.flags & FLOW_XLATE != 0 => STEP_XLATE_FORWARD,
        other => other,
    };
    // SAFETY: this CPU's slot, valid for the whole invocation and used by
    // nothing else meanwhile (see fib6).
    unsafe { state.write(Ingress6 { tuple, flow }) };
    Some(step)
}

/// [`snat_reply4`] for IPv6, on the [`INGRESS6`] slot.
#[inline(never)]
fn snat_reply6(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return TC_ACT_OK;
    };
    // SAFETY: the slot ingress6 filled in this invocation; read only.
    let state = unsafe { &*state };
    snat_reply6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
}
#[inline(always)]
fn snat_reply6_in(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<i32> {
    let (proto, backend, nat, backend_port, nat_port) = *tuple;
    hops_ok(ctx)?;
    let (result, fib) = fib6(ctx, proto, flow.address, flow.other, 0)?;
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
    redirect6(ctx, result, fib)
}

/// A forward flow on the [`INGRESS6`] slot: [`snat_forward4`] for IPv6 to
/// another node's backend, else the destination rewrite to a local one.
#[inline(never)]
fn nodeport_forward6(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return TC_ACT_OK;
    };
    // SAFETY: the slot ingress6 (and new_flow6) filled; read only.
    let state = unsafe { &*state };
    if state.flow.flags & FLOW_SNAT != 0 {
        snat_forward6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
    } else if state.flow.flags & FLOW_DSR != 0 {
        dsr_forward6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
    } else {
        let _ = local6(&ctx, &state.tuple, &state.flow);
        TC_ACT_OK
    }
}
/// The route is looked up again rather than kept from a new flow's lookup.
#[inline(always)]
fn snat_forward6_in(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<i32> {
    let (proto, client, front, client_port, front_port) = *tuple;
    hops_ok(ctx)?;
    let (result, fib) = fib6(ctx, proto, flow.other, flow.address, 0)?;
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
    redirect6(ctx, result, fib)
}
/// [`dsr_forward4`] for IPv6. The option is a Destination Options header, which
/// neither the upper-layer length nor the protocol in the L4 checksum counts.
#[inline(always)]
fn dsr_forward6_in(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<i32> {
    let (proto, client, front, _, front_port) = *tuple;
    hops_ok(ctx)?;
    let (result, fib) = fib6(ctx, proto, client, flow.address, 0)?;
    if !forwarded(result) {
        return None;
    }
    // SAFETY: the per-CPU slot fib6 just filled; a plain field read.
    let device = unsafe { (*fib).ifindex };
    let option = dsr_option_wanted(ctx, IP6_SPORT, proto, device, DSR_OPT6_LEN)?;
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    if option {
        let payload = u16::from_be_bytes(ctx.load::<[u8; 2]>(IP6_PAYLOAD).ok()?);
        let grown = payload.checked_add(u16::try_from(DSR_OPT6_LEN).ok()?)?;
        ctx.skb.adjust_room(DSR_OPT6_LEN, ADJ_ROOM_NET, 0).ok()?;
        let head = [proto, 2, DSR_OPT6[0], DSR_OPT6[1]];
        ctx.store(IP6_OPT, &head, 0).ok()?;
        ctx.store(IP6_OPT.checked_add(4)?, &front, 0).ok()?;
        ctx.store(IP6_OPT.checked_add(20)?, &front_port, 0).ok()?;
        ctx.store(IP6_OPT.checked_add(22)?, &[0u8; 2], 0).ok()?;
        ctx.store(IP6_PAYLOAD, &grown.to_be_bytes(), 0).ok()?;
        ctx.store(IP6_NEXT, &IPPROTO_DSTOPTS, 0).ok()?;
    }
    redirect6(ctx, result, fib)
}
/// A node-local backend: rewrite the destination, let the stack deliver it.
#[inline(always)]
fn local6(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<()> {
    let (proto, _, front, _, front_port) = *tuple;
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (flow.address, flow.port),
    )
}

/// A new IPv6 flow to a node-local frontend: pick a backend and, for one on
/// another node, a NAT port; record both directions in [`NODEPORT6`] and
/// leave the forward entry in the [`INGRESS6`] slot. 0 when the frame is not
/// ours, [`NEW_NAT64`] when its frontend's backends are IPv4.
#[inline(never)]
fn new_flow6(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the slot ingress6 filled in this invocation; nothing else
    // refers to it while this function runs.
    let state = unsafe { &mut *state };
    new_flow6_in(&ctx, &state.tuple, &mut state.flow).unwrap_or(0)
}
#[inline(always)]
fn new_flow6_in(ctx: &TcContext, tuple: &Tuple6, flow: &mut Nodeport6Value) -> Option<i32> {
    let (proto, client, front, client_port, front_port) = *tuple;
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
    if service.service_flags() & service_flags::NAT46X64 != 0 {
        return Some(NEW_NAT64);
    }
    let id = match maglev6(&service, client, client_port, front_port, proto) {
        Some(id) => id,
        None => {
            service_key.backend_slot = slot(service.count)?;
            // SAFETY: see lookup6.
            let entry = unsafe { LB6_SERVICES.get(&service_key).copied() }?;
            entry.backend_id()
        }
    };
    // SAFETY: see lookup6.
    let chosen = unsafe { LB6_BACKENDS.get(&id).copied() }?;
    let backend = (chosen.address, chosen.port.0);
    flow.address = backend.0;
    flow.port = backend.1;
    flow.flags = 0;
    let (result, fib) = fib6(ctx, proto, client, backend.0, 0)?;
    // SAFETY: the per-CPU slot fib6 just filled; a plain field read.
    let out_device = unsafe { (*fib).ifindex };
    let key = Nodeport6Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    let mut other = Nodeport6Value {
        address: front,
        port: front_port,
        flags: 0,
        pad: 0,
        other: [0; 16],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    let remote = forwarded(result) && out_device == uplink(ctx);
    if remote && service.service_flags() & service_flags::FWD_MODE_DSR != 0 {
        flow.flags = FLOW_DSR;
    } else if remote {
        // Another node's backend: SNAT to this node's address there.
        hops_ok(ctx)?;
        let (result, source) = fib6(ctx, proto, [0; 16], backend.0, BPF_FIB_LOOKUP_SRC)?;
        if !forwarded(result) {
            return None;
        }
        // SAFETY: the per-CPU slot just filled; the active member after an
        // IPv6 lookup.
        let nat = ip6_bytes(unsafe { (*source).__bindgen_anon_3.ipv6_src });
        other.other = client;
        other.other_port = client_port;
        // The reply entry first: a reply must never find a flow it cannot
        // undo.
        flow.other_port = claim_port6(backend, nat, proto, &other)?;
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
        NODEPORT6.insert(&reverse, &other, 0).ok()?;
    }
    NODEPORT6.insert(&key, flow, 0).ok()?;
    Some(1)
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

// Service NAT46/64 (spec 04 §3.15; ADR-0011 #79; the RFC 6052 gateway is
// milestone 3). A frontend's master with `NAT46X64` means its backend IDs are
// in the other family's backend map. Its flows are always source-NATed to this
// node's address of the backend's family on a NAT port, and leave by the FIB:
// the backend must be on another node, since a local pod's reply to this node's
// address is local input and never reaches the uplink. The agent gives such a
// frontend only other nodes' backends; a route that turns out local passes
// untouched. Never DSR, and only TCP/UDP with a bare header: IPv4 options,
// fragments and UDP without a checksum (IPv6 requires one) pass untouched, as
// does a packet too big for the device once translated.
//
// Entries, one per direction, keyed by the tuple on the wire. IPv6-keyed ones
// are in NODEPORT6 with FLOW_XLATE and IPv4-mapped addresses for the IPv4 side;
// IPv4-keyed ones need room for IPv6 addresses, so they are in XLATE4:
//   NAT46 forward  XLATE4     client4, front4        -> backend6, nat6:port
//   NAT46 reply    NODEPORT6  backend6, nat6:port    -> front4, client4
//   NAT64 forward  NODEPORT6  client6, front6        -> backend4, nat4:port
//   NAT64 reply    XLATE4     backend4, nat4:port    -> front6, client6
// NAT64 also reserves its port in NODEPORT4, so plain SNAT flows do not take it.

/// See above: IPv4-keyed entries of translated flows.
#[map(name = "flowsdn_nodeport4_xlate")]
static XLATE4: LruHashMap<Nodeport4Key, Nodeport6Value> = LruHashMap::with_max_entries(65536, 0);

/// [`new_flow6`]'s answer for a NAT64 frontend.
const NEW_NAT64: i32 = 2;
/// The bytes an IPv6 header adds to an IPv4 one.
const XLATE_GROWTH: i32 = 20;
/// Offsets of the L4 ports and checksums once the frame is IPv4 (bare header).
const IP4_L4: usize = 34;
const IP4_UDP_CHECK: usize = 40;
const IP4_TCP_CHECK: usize = 50;

/// The IPv4 side's state between its BPF functions, as [`Ingress6`] is IPv6's.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Xlate4 {
    src: [u8; 4],
    dst: [u8; 4],
    sport: [u8; 2],
    dport: [u8; 2],
    proto: u8,
    pad: [u8; 3],
    flow: Nodeport6Value,
}
/// The [`Xlate4`] slot: per CPU for the reason [`FIB6`] is.
#[map(name = "flowsdn_nodeport4_xlate_scratch")]
static XLATE4_SLOT: PerCpuArray<Xlate4> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn mapped6(address: [u8; 4]) -> [u8; 16] {
    ip6_bytes([0, 0, MAPPED, u32::from_ne_bytes(address)])
}
#[inline(always)]
fn unmapped(address: [u8; 16]) -> [u8; 4] {
    let [_, _, _, word] = ip6_words(address);
    word.to_ne_bytes()
}
/// The checksum's offset and the replace flags of `proto`.
#[inline(always)]
fn check_of(proto: u8, tcp: usize, udp: usize) -> (usize, u64) {
    if proto == 6 {
        (tcp, 0)
    } else {
        (udp, BPF_F_MARK_MANGLED_0)
    }
}
/// A difference of the pseudo-header's addresses, for `l4_csum_replace` with no
/// size. Length and protocol sum alike in both families' pseudo-headers. `None`
/// on a helper error.
#[inline(always)]
fn address_diff(old: &[u32], new: &[u32]) -> Option<u64> {
    // SAFETY: both are live buffers of the sizes given; the helper only reads
    // them and keeps no pointer.
    let diff = unsafe {
        bpf_csum_diff(
            old.as_ptr().cast_mut(),
            u32::try_from(old.len().checked_mul(4)?).ok()?,
            new.as_ptr().cast_mut(),
            u32::try_from(new.len().checked_mul(4)?).ok()?,
            0,
        )
    };
    u64::try_from(diff).ok()
}
/// Change the frame's L3 protocol. The kernel moves what follows the Ethernet
/// header and leaves the new network header for the program to write.
#[inline(always)]
fn change_proto(ctx: &TcContext, ethertype: [u8; 2]) -> Option<()> {
    // SAFETY: a live skb; the proto is in network order, as the helper wants.
    let result = unsafe { bpf_skb_change_proto(ctx.skb.skb, u16::from_ne_bytes(ethertype), 0) };
    (result == 0).then_some(())
}
/// Replace the L4 ports and write them, once the L3 header is the new one.
#[inline(always)]
fn set_ports(
    ctx: &TcContext,
    at: usize,
    check: (usize, u64),
    diff: u64,
    old: [[u8; 2]; 2],
    new: [[u8; 2]; 2],
) -> Option<()> {
    let (offset, mangled) = check;
    let [old_s, old_d] = old;
    let [new_s, new_d] = new;
    let [a, b] = old_s;
    let [c, d] = old_d;
    let old_ports = u32::from_ne_bytes([a, b, c, d]);
    let [a, b] = new_s;
    let [c, d] = new_d;
    let new_ports = [a, b, c, d];
    ctx.l4_csum_replace(offset, 0, diff, BPF_F_PSEUDO_HDR | mangled)
        .ok()?;
    ctx.l4_csum_replace(
        offset,
        u64::from(old_ports),
        u64::from(u32::from_ne_bytes(new_ports)),
        mangled | 4,
    )
    .ok()?;
    ctx.store(at, &new_ports, 0).ok()
}

/// The IPv4 path's first step, before [`ingress4`]: a reply of a NAT64 flow, or
/// a packet to a NAT46 frontend. Fills [`XLATE4_SLOT`]; anything else is
/// [`STEP_PASS`], at the cost of one service lookup.
#[inline(never)]
fn xlate4(skb: *mut __sk_buff) -> i32 {
    classify4(&TcContext::new(skb)).unwrap_or(STEP_PASS)
}
#[inline(always)]
fn classify4(ctx: &TcContext) -> Option<i32> {
    let state = XLATE4_SLOT.get_ptr_mut(0)?;
    let (l4, proto, src, dst, sport, dport) = tuple4(ctx)?;
    if l4 != IP4_L4 {
        return None;
    }
    let mut key = Nodeport4Key {
        a: src,
        b: dst,
        ap: sport,
        bp: dport,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    let reply = if u32::from(u16::from_be_bytes(dport)) >= NAT_PORT_MIN {
        // SAFETY: LRU value copied at once, never written through.
        unsafe { XLATE4.get(&key).copied() }
    } else {
        None
    };
    let (step, flow) = match reply {
        Some(flow) => (STEP_XLATE_REPLY, flow),
        None => {
            let service_key = Lb4Key {
                address: Be32(dst),
                dport: Be16(dport),
                backend_slot: 0,
                proto,
                scope: 1,
                pad: [0; 2],
            };
            // SAFETY: see lookup4.
            let service = unsafe { LB4_SERVICES.get(&service_key).copied() }?;
            if service.service_flags() & service_flags::NAT46X64 == 0 {
                return None;
            }
            key.direction = FORWARD;
            // SAFETY: LRU value copied at once, never written through.
            match unsafe { XLATE4.get(&key).copied() } {
                Some(known) => (STEP_FORWARD, known),
                None => (
                    STEP_NEW,
                    Nodeport6Value {
                        address: [0; 16],
                        port: [0; 2],
                        flags: 0,
                        pad: 0,
                        other: [0; 16],
                        other_port: [0; 2],
                        pad2: [0; 2],
                    },
                ),
            }
        }
    };
    let slot = Xlate4 {
        src,
        dst,
        sport,
        dport,
        proto,
        pad: [0; 3],
        flow,
    };
    // SAFETY: this CPU's slot, valid for the whole invocation and used by
    // nothing else meanwhile (see fib6).
    unsafe { state.write(slot) };
    Some(step)
}

/// A new flow to a NAT46 frontend: pick an IPv6 backend, claim a NAT port and
/// record both directions. 0 when the frame is not to be translated.
#[inline(never)]
fn new_flow46(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = XLATE4_SLOT.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the slot xlate4 filled in this invocation; nothing else refers
    // to it while this function runs.
    let state = unsafe { &mut *state };
    match new_flow46_in(&ctx, state) {
        Some(()) => 1,
        None => 0,
    }
}
#[inline(always)]
fn new_flow46_in(ctx: &TcContext, state: &mut Xlate4) -> Option<()> {
    let (proto, client, front, client_port, front_port) =
        (state.proto, state.src, state.dst, state.sport, state.dport);
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
    let id = match maglev4(&service, client, client_port, front_port, proto) {
        Some(id) => id,
        None => {
            service_key.backend_slot = slot(service.count)?;
            // SAFETY: see lookup4.
            let entry = unsafe { LB4_SERVICES.get(&service_key).copied() }?;
            entry.backend_id()
        }
    };
    // SAFETY: see lookup6.
    let chosen = unsafe { LB6_BACKENDS.get(&id).copied() }?;
    let (result, source) = fib6(ctx, proto, [0; 16], chosen.address, BPF_FIB_LOOKUP_SRC)?;
    // SAFETY: the per-CPU slot just filled; plain field reads, the source
    // being the active member after an IPv6 lookup.
    let (device, nat) = unsafe { ((*source).ifindex, (*source).__bindgen_anon_3.ipv6_src) };
    if !forwarded(result) || device != uplink(ctx) {
        return None;
    }
    let nat = ip6_bytes(nat);
    let reply = Nodeport6Value {
        address: mapped6(front),
        port: front_port,
        flags: FLOW_XLATE,
        pad: 0,
        other: mapped6(client),
        other_port: client_port,
        pad2: [0; 2],
    };
    // The reply entry first: a reply must never find a flow it cannot undo.
    let nat_port = claim_port6((chosen.address, chosen.port.0), nat, proto, &reply)?;
    state.flow = Nodeport6Value {
        address: chosen.address,
        port: chosen.port.0,
        flags: FLOW_XLATE,
        pad: 0,
        other: nat,
        other_port: nat_port,
        pad2: [0; 2],
    };
    let key = Nodeport4Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    XLATE4.insert(&key, &state.flow, 0).ok()
}

/// [`new_flow46`] for a NAT64 frontend, on the [`INGRESS6`] slot.
#[inline(never)]
fn new_flow64(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the slot ingress6 filled in this invocation; nothing else refers
    // to it while this function runs.
    let state = unsafe { &mut *state };
    match new_flow64_in(&ctx, &state.tuple, &mut state.flow) {
        Some(()) => 1,
        None => 0,
    }
}
#[inline(always)]
fn new_flow64_in(ctx: &TcContext, tuple: &Tuple6, flow: &mut Nodeport6Value) -> Option<()> {
    let (proto, client, front, client_port, front_port) = *tuple;
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
    let id = match maglev6(&service, client, client_port, front_port, proto) {
        Some(id) => id,
        None => {
            service_key.backend_slot = slot(service.count)?;
            // SAFETY: see lookup6.
            let entry = unsafe { LB6_SERVICES.get(&service_key).copied() }?;
            entry.backend_id()
        }
    };
    // SAFETY: see lookup4.
    let chosen = unsafe { LB4_BACKENDS.get(&id).copied() }?;
    let backend = (chosen.address.0, chosen.port.0);
    let (result, fib) = fib4(ctx, proto, [0; 4], backend.0, BPF_FIB_LOOKUP_SRC);
    if !forwarded(result) || fib.ifindex != uplink(ctx) {
        return None;
    }
    // SAFETY: the active member after an IPv4 lookup.
    let nat = unsafe { fib.__bindgen_anon_3.ipv4_src }.to_ne_bytes();
    let reservation = Nodeport4Value {
        address: [0; 4],
        port: [0; 2],
        flags: FLOW_XLATE,
        pad: 0,
        other: [0; 4],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    let nat_port = claim_port(backend, nat, proto, &reservation)?;
    let reply_key = Nodeport4Key {
        a: backend.0,
        b: nat,
        ap: backend.1,
        bp: nat_port,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    let reply = Nodeport6Value {
        address: front,
        port: front_port,
        flags: FLOW_XLATE,
        pad: 0,
        other: client,
        other_port: client_port,
        pad2: [0; 2],
    };
    // The reply entry first: a reply must never find a flow it cannot undo.
    XLATE4.insert(&reply_key, &reply, 0).ok()?;
    flow.address = mapped6(backend.0);
    flow.port = backend.1;
    flow.flags = FLOW_XLATE;
    flow.other = mapped6(nat);
    flow.other_port = nat_port;
    let key = Nodeport6Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    NODEPORT6.insert(&key, flow, 0).ok()
}

/// The [`XLATE4_SLOT`] frame as IPv6: a NAT46 flow's packet to its backend, or
/// (`reply`) a NAT64 flow's reply to its client.
#[inline(never)]
fn to_v6(skb: *mut __sk_buff, reply: bool) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = XLATE4_SLOT.get_ptr_mut(0) else {
        return TC_ACT_OK;
    };
    // SAFETY: the slot xlate4 (and new_flow46) filled; read only.
    let state = unsafe { &*state };
    let flow = &state.flow;
    let (src, dst) = if reply {
        ((flow.address, flow.port), (flow.other, flow.other_port))
    } else {
        ((flow.other, flow.other_port), (flow.address, flow.port))
    };
    to_v6_in(&ctx, state, src, dst).unwrap_or(TC_ACT_OK)
}
/// `None` before anything is changed, so the frame passes untouched. A helper
/// that fails once the frame has begun to change drops it (spec 04 §3.15).
#[inline(always)]
fn to_v6_in(
    ctx: &TcContext,
    state: &Xlate4,
    src: ([u8; 16], [u8; 2]),
    dst: ([u8; 16], [u8; 2]),
) -> Option<i32> {
    let proto = state.proto;
    let (check_old, mangled) = check_of(proto, IP4_TCP_CHECK, IP4_UDP_CHECK);
    let fragment = u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?);
    if fragment & 0x3fff != 0 || (proto == 17 && ctx.load::<u16>(check_old).ok()? == 0) {
        return None;
    }
    ttl_ok(ctx)?;
    let (result, fib) = fib6(ctx, proto, src.0, dst.0, 0)?;
    if !forwarded(result) {
        return None;
    }
    // SAFETY: the per-CPU slot fib6 just filled; a plain field read.
    let device = unsafe { (*fib).ifindex };
    let mut mtu: u32 = 0;
    // SAFETY: a live skb; `mtu` is a local the helper writes.
    let fits = unsafe { bpf_check_mtu(ctx.skb.skb.cast(), device, &mut mtu, XLATE_GROWTH, 0) };
    if fits != 0 {
        return None;
    }
    let [_, tos] = ctx.load::<[u8; 2]>(14).ok()?;
    let total = u16::from_be_bytes(ctx.load::<[u8; 2]>(16).ok()?);
    let ttl = ctx.load::<u8>(22).ok()?;
    let [p0, p1] = total.checked_sub(20)?.to_be_bytes();
    let old = [u32::from_ne_bytes(state.src), u32::from_ne_bytes(state.dst)];
    let [s0, s1, s2, s3] = ip6_words(src.0);
    let [d0, d1, d2, d3] = ip6_words(dst.0);
    let diff = address_diff(&old, &[s0, s1, s2, s3, d0, d1, d2, d3])?;
    let head = [0x60 | (tos >> 4), tos << 4, 0, 0, p0, p1, proto, ttl];
    let done = (|| {
        change_proto(ctx, ETH_P_IPV6)?;
        ctx.store(12, &ETH_P_IPV6, 0).ok()?;
        ctx.store(14, &head, 0).ok()?;
        ctx.store(IP6_SRC, &src.0, 0).ok()?;
        ctx.store(IP6_DST, &dst.0, 0).ok()?;
        set_ports(
            ctx,
            IP6_SPORT,
            (check_of(proto, IP6_TCP_CHECK, IP6_UDP_CHECK).0, mangled),
            diff,
            [state.sport, state.dport],
            [src.1, dst.1],
        )?;
        redirect6(ctx, result, fib)
    })();
    Some(done.unwrap_or(TC_ACT_SHOT))
}

/// The [`INGRESS6`] slot's frame as IPv4: a NAT64 flow's packet to its backend,
/// or (`reply`) a NAT46 flow's reply to its client.
#[inline(never)]
fn to_v4(skb: *mut __sk_buff, reply: bool) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return TC_ACT_OK;
    };
    // SAFETY: the slot ingress6 (and new_flow64) filled; read only.
    let state = unsafe { &*state };
    let flow = &state.flow;
    let (src, dst) = if reply {
        (
            (unmapped(flow.address), flow.port),
            (unmapped(flow.other), flow.other_port),
        )
    } else {
        (
            (unmapped(flow.other), flow.other_port),
            (unmapped(flow.address), flow.port),
        )
    };
    to_v4_in(&ctx, &state.tuple, src, dst).unwrap_or(TC_ACT_OK)
}
/// See [`to_v6_in`]. The IPv4 header says don't fragment, as IPv6 forwarding
/// never would; its checksum is computed here and adjusted by [`redirect`].
#[inline(always)]
fn to_v4_in(
    ctx: &TcContext,
    tuple: &Tuple6,
    src: ([u8; 4], [u8; 2]),
    dst: ([u8; 4], [u8; 2]),
) -> Option<i32> {
    let (proto, old_src, old_dst, old_sport, old_dport) = *tuple;
    let (old_check, mangled) = check_of(proto, IP6_TCP_CHECK, IP6_UDP_CHECK);
    if proto == 17 && ctx.load::<u16>(old_check).ok()? == 0 {
        return None;
    }
    hops_ok(ctx)?;
    let (result, fib) = fib4(ctx, proto, src.0, dst.0, 0);
    if !forwarded(result) {
        return None;
    }
    let [b0, b1] = ctx.load::<[u8; 2]>(14).ok()?;
    let tos = ((b0 & 15) << 4) | (b1 >> 4);
    let payload = u16::from_be_bytes(ctx.load::<[u8; 2]>(IP6_PAYLOAD).ok()?);
    let total = payload.checked_add(20)?;
    let hops = ctx.load::<u8>(IP6_HOPS).ok()?;
    let [o0, o1, o2, o3] = ip6_words(old_src);
    let [o4, o5, o6, o7] = ip6_words(old_dst);
    let new = [u32::from_ne_bytes(src.0), u32::from_ne_bytes(dst.0)];
    let diff = address_diff(&[o0, o1, o2, o3, o4, o5, o6, o7], &new)?;
    let (src_word, dst_word) = (u32::from_be_bytes(src.0), u32::from_be_bytes(dst.0));
    let sum = 0x4500u32
        .wrapping_add(u32::from(tos))
        .wrapping_add(u32::from(total))
        .wrapping_add(0x4000)
        .wrapping_add((u32::from(hops) << 8) | u32::from(proto))
        .wrapping_add(src_word >> 16)
        .wrapping_add(src_word & 0xffff)
        .wrapping_add(dst_word >> 16)
        .wrapping_add(dst_word & 0xffff);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let check = (!(sum as u16)).to_be_bytes();
    let [t0, t1] = total.to_be_bytes();
    let [c0, c1] = check;
    let head = [0x45, tos, t0, t1, 0, 0, 0x40, 0, hops, proto, c0, c1];
    let done = (|| {
        change_proto(ctx, ETH_P_IPV4)?;
        ctx.store(12, &ETH_P_IPV4, 0).ok()?;
        ctx.store(14, &head, 0).ok()?;
        ctx.store(26, &src.0, 0).ok()?;
        ctx.store(30, &dst.0, 0).ok()?;
        set_ports(
            ctx,
            IP4_L4,
            (check_of(proto, IP4_TCP_CHECK, IP4_UDP_CHECK).0, mangled),
            diff,
            [old_sport, old_dport],
            [src.1, dst.1],
        )?;
        redirect(ctx, result, &fib)
    })();
    Some(done.unwrap_or(TC_ACT_SHOT))
}

// Each family's path is its own BPF function (a BPF-to-BPF call), so each
// gets its own stack frame: inlined together they exceed the 512-byte stack.
#[inline(never)]
fn ingress4(skb: *mut __sk_buff) -> i32 {
    nodeport4_in(&TcContext::new(skb)).unwrap_or(TC_ACT_OK)
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
    let skb = ctx.skb.skb;
    match ctx.load::<[u8; 2]>(12) {
        Ok(ETH_P_IPV6) => match ingress6(skb) {
            STEP_REPLY => snat_reply6(skb),
            STEP_NEW => match new_flow6(skb) {
                0 => TC_ACT_OK,
                NEW_NAT64 if new_flow64(skb) != 0 => to_v4(skb, false),
                NEW_NAT64 => TC_ACT_OK,
                _ => nodeport_forward6(skb),
            },
            STEP_FORWARD => nodeport_forward6(skb),
            STEP_XLATE_REPLY => to_v4(skb, true),
            STEP_XLATE_FORWARD => to_v4(skb, false),
            _ => TC_ACT_OK,
        },
        _ => match xlate4(skb) {
            STEP_XLATE_REPLY => to_v6(skb, true),
            STEP_NEW if new_flow46(skb) != 0 => to_v6(skb, false),
            STEP_NEW => TC_ACT_OK,
            STEP_FORWARD => to_v6(skb, false),
            _ => ingress4(skb),
        },
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
