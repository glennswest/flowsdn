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
//! backends on other nodes); what they neither redirect nor drop goes on to
//! the next TCX program (`TCX_NEXT`), the host firewall. A frontend whose master carries the Maglev
//! algorithm picks a new flow's backend from its lookup table in
//! `flowsdn_lb{4,6}_maglev` by the flow hash, so every node sends a flow to
//! the same backend (spec 05 §3.13, §5.1); without a table it picks at
//! random. DSR and skip-LB are not done here; the agent terminates
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
    maps::{HashMap, LpmTrie, LruHashMap, PerCpuArray, lpm_trie::Key},
    programs::{SockAddrContext, TcContext},
};
use flowsdn_bpf_abi::{
    Be16, Be32,
    affinity::{Lb4AffinityKey, Lb6AffinityKey, LbAffinityMatch, LbAffinityVal, NETNS_COOKIE},
    lb::{
        Ipv4RevnatEntry, Ipv4RevnatTuple, Ipv6RevnatEntry, Ipv6RevnatTuple, Lb4Backend, Lb4Key,
        DsrDispatch, Lb6Backend, Lb6Key, LbService, service_flags,
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
// packet of a known flow goes without the option. With `flowsdn_dsr_config`
// set to IPIP or Geneve (#447) the same packets carry the frontend by
// encapsulation instead (see `encap4`/`encap6`); the backend's node strips
// it at its uplink's ingress, whichever mode it is set to itself. ICMP errors about the
// flow are translated both ways (#449, "ICMP errors of Service flows").
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
/// A masqueraded flow (#460): a local Pod's to outside the cluster.
const FLOW_MASQ: u8 = 16;
/// The IPv4 DSR option's type (`IPOPT_COPY | 0x1a`) and length.
const DSR_OPT4: [u8; 2] = [0x9a, 8];
/// The IPv6 DSR Destination Options header's length and its option's type and
/// length (spec 02 §2.5).
const DSR_OPT6_LEN: i32 = 24;
const DSR_OPT6: [u8; 2] = [0x1b, 20];
const IPPROTO_DSTOPTS: u8 = 60;
/// `BPF_ADJ_ROOM_NET`: room after the fixed network header.
const ADJ_ROOM_NET: u32 = 0;
/// `BPF_ADJ_ROOM_MAC`: room right after the Ethernet header.
const ADJ_ROOM_MAC: u32 = 1;
/// `bpf_skb_adjust_room` flags for an added tunnel header: its outer L3
/// family, a UDP header, an inner Ethernet header of `ENCAP_L2(14)`.
const ENCAP_L3_IPV4: u64 = 1 << 1;
const ENCAP_L3_IPV6: u64 = 1 << 2;
const ENCAP_L4_UDP: u64 = 1 << 4;
const ENCAP_L2_ETH: u64 = 1 << 6;
const ENCAP_INNER_ETH: u64 = 14 << 56;

// How a DSR packet carries its frontend (#447, the reference's
// `bpf-lb-dsr-dispatch`, spec 02 §2.5): an IP option / IPv6 Destination
// Options header, IPIP / IP6IP6 (the client's packet unchanged inside an
// outer header to the backend), or Geneve (the DNATed packet in Ethernet,
// with the DSR option, to the backend's node). Set by the agent in
// `flowsdn_dsr_config`; absent is `opt`. Receiving accepts all three.
const DISPATCH_OPT: u8 = DsrDispatch::Opt.byte();
const DISPATCH_IPIP: u8 = DsrDispatch::Ipip.byte();
const DISPATCH_GENEVE: u8 = DsrDispatch::Geneve.byte();
#[map(name = "flowsdn_dsr_config")]
static DSR_CONFIG: HashMap<u32, [u8; 4]> = HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);
/// This node's dispatch mode.
#[inline(always)]
fn dispatch() -> u8 {
    // SAFETY: a fixed-size array value copied at once.
    unsafe { DSR_CONFIG.get(&0).copied() }.map_or(DISPATCH_OPT, |v| v[0])
}
/// Geneve's UDP port.
const GENEVE_PORT: [u8; 2] = 6081u16.to_be_bytes();
/// The Geneve DSR option's header: class 0x014b, type 0x81 (critical), its
/// length in 4-byte words (2: an IPv4 address and port, 5: IPv6).
const GENEVE_OPT4: [u8; 4] = [0x01, 0x4b, 0x81, 2];
const GENEVE_OPT6: [u8; 4] = [0x01, 0x4b, 0x81, 5];
/// The Geneve base header: version 0, the option words (3 or 6), the
/// critical-options flag, Ethernet (0x6558), VNI 2 (WORLD: the client is
/// outside the cluster), a reserved byte.
const GENEVE4_BASE: [u8; 8] = [3, 0x40, 0x65, 0x58, 0, 0, 2, 0];
const GENEVE6_BASE: [u8; 8] = [6, 0x40, 0x65, 0x58, 0, 0, 2, 0];
/// Bytes a mode adds in front of an IPv4 / IPv6 packet: the option; an outer
/// header; outer IP + UDP 8 + Geneve 8 + option 12 or 24 + Ethernet 14.
const IPIP4_ROOM: i32 = 20;
const GENEVE4_ROOM: i32 = 62;
const IPIP6_ROOM: i32 = 40;
const GENEVE6_ROOM: i32 = 94;
/// The same, removed on the backend's node.
const IPIP4_STRIP: i32 = -20;
const GENEVE4_STRIP: i32 = -62;
const IPIP6_STRIP: i32 = -40;
const GENEVE6_STRIP: i32 = -94;
#[inline(always)]
fn room4(mode: u8) -> i32 {
    match mode {
        DISPATCH_IPIP => IPIP4_ROOM,
        DISPATCH_GENEVE => GENEVE4_ROOM,
        _ => 8,
    }
}
#[inline(always)]
fn room6(mode: u8) -> i32 {
    match mode {
        DISPATCH_IPIP => IPIP6_ROOM,
        DISPATCH_GENEVE => GENEVE6_ROOM,
        _ => DSR_OPT6_LEN,
    }
}
/// A tunnel source port from the flow's ports, so a flow keeps one path.
#[inline(always)]
fn tunnel_port(client_port: [u8; 2], front_port: [u8; 2]) -> [u8; 2] {
    let mixed = u16::from_be_bytes(client_port) ^ u16::from_be_bytes(front_port).rotate_left(7);
    (0xc000 | (mixed & 0x3fff)).to_be_bytes()
}
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

/// An IPv4 datagram being fragmented (#458, the reference's
/// `ENABLE_IPV4_FRAGMENTS`): source, destination, IP ID and protocol.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frag4Key {
    src: [u8; 4],
    dst: [u8; 4],
    id: [u8; 2],
    proto: u8,
    pad: u8,
}
/// The ports the datagram's first fragment carried.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frag4Ports {
    sport: [u8; 2],
    dport: [u8; 2],
}
/// Filled from each first fragment (offset 0, more fragments) the uplink
/// programs see, in either direction; later fragments take their ports
/// from it.
#[map(name = "flowsdn_nodeport4_frags")]
static FRAGS4: LruHashMap<Frag4Key, Frag4Ports> = LruHashMap::with_max_entries(8192, 0);
/// [`tuple4`]'s L4 offset for a fragment after the first: it has no L4
/// header, so only its IP header is rewritten.
const NO_L4: usize = 0;

/// BPF masquerade (#460, the reference's `enable-bpf-masquerade`), IPv4:
/// sources masqueraded (this node's pod CIDRs) and destinations never
/// masqueraded (the cluster's pod CIDRs and `non-masquerade-cidrs`). Both
/// empty (the agent's default) masquerade nothing.
#[map(name = "flowsdn_masq4_sources")]
static MASQ4_SOURCES: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(256, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_masq4_exclude")]
static MASQ4_EXCLUDE: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, BPF_F_NO_PREALLOC);
const ICMP4: u8 = 1;

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
/// A NAT reservation whose TCP flow saw a FIN or RST (finding 1cb155baca89).
const FLOW_CLOSING: u8 = 8;
/// Seconds a NAT reservation lives without traffic: TCP, TCP after a FIN or
/// RST, everything else. Its last-seen second is kept in the value's `pad2`
/// (16 bits, compared with wrapping arithmetic, so the pinned map's layout is
/// unchanged); every lifetime is far below 2^15 s.
const LIFE_TCP: u16 = 21600;
const LIFE_CLOSING: u16 = 10;
const LIFE_OTHER: u16 = 60;

/// Seconds since boot, modulo 2^16.
#[inline(always)]
fn now16() -> u16 {
    // SAFETY: no arguments; returns the monotonic clock in nanoseconds.
    let ns = unsafe { bpf_ktime_get_ns() };
    (ns.checked_div(1_000_000_000).unwrap_or(0) & 0xffff) as u16
}
/// Whether a reservation with `flags`, last seen at `seen`, has outlived its
/// flow. NAT46/64 reservations (their traffic does not refresh them) never
/// expire.
#[inline(always)]
fn expired(flags: u8, seen: [u8; 2], proto: u8, now: u16) -> bool {
    if flags & FLOW_XLATE != 0 {
        return false;
    }
    let life = if flags & FLOW_CLOSING != 0 {
        LIFE_CLOSING
    } else if proto == 6 {
        LIFE_TCP
    } else {
        LIFE_OTHER
    };
    now.wrapping_sub(u16::from_ne_bytes(seen)) > life
}
/// A TCP segment with FIN or RST at `l4`.
#[inline(always)]
fn closes(ctx: &TcContext, l4: usize, proto: u8) -> bool {
    proto == 6
        && l4 != NO_L4
        && l4
            .checked_add(13)
            .and_then(|at| ctx.load::<u8>(at).ok())
            .is_some_and(|flags| flags & 0x05 != 0)
}

/// The IPv4 TCP/UDP 5-tuple of a frame: (L4 offset, proto, src, dst,
/// sport, dport). A first fragment records its ports in [`FRAGS4`]; a later
/// fragment takes them from there with L4 offset [`NO_L4`] (#458), or is
/// skipped when its first fragment was not seen.
#[inline(always)]
fn tuple4(ctx: &TcContext) -> Option<(usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2])> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV4 {
        return None;
    }
    let version_ihl = ctx.load::<u8>(14).ok()?;
    if version_ihl >> 4 != 4 || version_ihl & 15 < 5 {
        return None;
    }
    let proto = ctx.load::<u8>(23).ok()?;
    if proto != 6 && proto != 17 {
        return None;
    }
    let src = ctx.load::<[u8; 4]>(26).ok()?;
    let dst = ctx.load::<[u8; 4]>(30).ok()?;
    let fragment = u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?);
    let key = Frag4Key {
        src,
        dst,
        id: ctx.load::<[u8; 2]>(18).ok()?,
        proto,
        pad: 0,
    };
    if fragment & 0x1fff != 0 {
        // SAFETY: LRU value copied at once, never written through.
        let ports = unsafe { FRAGS4.get(&key).copied() }?;
        return Some((NO_L4, proto, src, dst, ports.sport, ports.dport));
    }
    let l4 = usize::from(version_ihl & 15)
        .checked_mul(4)?
        .checked_add(14)?;
    let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(l4).ok()?;
    if fragment & 0x2000 != 0 {
        let ports = Frag4Ports {
            sport: [s0, s1],
            dport: [d0, d1],
        };
        // A full table only leaves this datagram's later fragments untouched.
        let _ = FRAGS4.insert(&key, &ports, 0);
    }
    Some((l4, proto, src, dst, [s0, s1], [d0, d1]))
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
    // A fragment after the first (#458): no ports, no L4 checksum (the
    // first fragment's covers the whole datagram), only the IP header.
    if l4 == NO_L4 {
        ctx.l3_csum_replace(24, u64::from(old_ip), u64::from(new_ip), 4)
            .ok()?;
        return ctx.store(ip_offset, &new.0, 0).ok();
    }
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
    lower_ttl(ctx)?;
    send(ctx, result, fib)
}
/// [`redirect`] without the TTL: an encapsulated packet's outer header is
/// new.
#[inline(always)]
fn send(ctx: &TcContext, result: i64, fib: &bpf_fib_lookup) -> Option<i32> {
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

/// A fresh outer IPv4 header at offset 14: DF, TTL 64, no options.
#[inline(always)]
fn outer4(ctx: &TcContext, tos: u8, total: u16, proto: u8, src: [u8; 4], dst: [u8; 4]) -> Option<()> {
    let (src_word, dst_word) = (u32::from_be_bytes(src), u32::from_be_bytes(dst));
    let sum = 0x4500u32
        .wrapping_add(u32::from(tos))
        .wrapping_add(u32::from(total))
        .wrapping_add(0x4000)
        .wrapping_add((64u32 << 8) | u32::from(proto))
        .wrapping_add(src_word >> 16)
        .wrapping_add(src_word & 0xffff)
        .wrapping_add(dst_word >> 16)
        .wrapping_add(dst_word & 0xffff);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let sum = (sum & 0xffff).wrapping_add(sum >> 16);
    let [c0, c1] = (!(sum as u16)).to_be_bytes();
    let [t0, t1] = total.to_be_bytes();
    let head = [0x45, tos, t0, t1, 0, 0, 0x40, 0, 64, proto, c0, c1];
    ctx.store(14, &head, 0).ok()?;
    ctx.store(26, &src, 0).ok()?;
    ctx.store(30, &dst, 0).ok()
}

/// Decrement the TTL of the IPv4 header at offset 14, as forwarding does.
#[inline(always)]
fn lower_ttl(ctx: &TcContext) -> Option<()> {
    let [ttl, proto] = ctx.load::<[u8; 2]>(22).ok()?;
    let lower = [ttl.checked_sub(1)?, proto];
    ctx.l3_csum_replace(
        24,
        u64::from(u16::from_ne_bytes([ttl, proto])),
        u64::from(u16::from_ne_bytes(lower)),
        2,
    )
    .ok()?;
    ctx.store(22, &lower, 0).ok()
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
    let keys = NAT_KEYS.get_ptr_mut(0)?;
    // SAFETY: no arguments; returns a pseudo-random scalar.
    let start = unsafe { bpf_get_prandom_u32() };
    for i in 0..NAT_TRIES {
        let offset = start.wrapping_add(i).checked_rem(NAT_PORTS)?;
        let port = u16::try_from(NAT_PORT_MIN.checked_add(offset)?)
            .ok()?
            .to_be_bytes();
        // SAFETY: this CPU's scratch slot, used by nothing else meanwhile;
        // the keys live there, not on the stack (#369).
        let keys = unsafe { &mut *keys };
        keys.k4.a = backend.0;
        keys.k4.b = nat;
        keys.k4.ap = backend.1;
        keys.k4.bp = port;
        keys.k4.proto = proto;
        keys.k4.direction = SNAT_REPLY;
        keys.k4.pad = [0; 2];
        if NODEPORT4.insert(&keys.k4, reply, BPF_NOEXIST).is_ok() {
            return Some(port);
        }
        // Taken: reclaim it if its flow is over, dropping that flow's forward
        // entry when it still points at this port (finding 1cb155baca89).
        // SAFETY: an LRU value read in place.
        let Some(held) = (unsafe { NODEPORT4.get(&keys.k4) }) else {
            continue;
        };
        if !expired(held.flags, held.pad2, proto, now16()) {
            continue;
        }
        keys.s4.a = held.other;
        keys.s4.b = held.address;
        keys.s4.ap = held.other_port;
        keys.s4.bp = held.port;
        keys.s4.proto = proto;
        keys.s4.direction = FORWARD;
        keys.s4.pad = [0; 2];
        // SAFETY: as above.
        if unsafe { NODEPORT4.get(&keys.s4) }
            .is_some_and(|f| f.other == nat && f.other_port == port)
        {
            let _ = NODEPORT4.remove(&keys.s4);
        }
        if NODEPORT4.insert(&keys.k4, reply, 0).is_ok() {
            return Some(port);
        }
    }
    None
}

/// The reservation behind SNAT flow `flow` of `client`: renewed (and marked
/// closing on a FIN or RST) while it still names this client; false when it
/// is gone or another flow reclaimed it.
#[inline(always)]
fn live4(
    flow: &Nodeport4Value,
    client: ([u8; 4], [u8; 2]),
    proto: u8,
    fin: bool,
) -> bool {
    let Some(keys) = NAT_KEYS.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: this CPU's scratch slot, used by nothing else meanwhile.
    let keys = unsafe { &mut *keys };
    keys.k4.a = flow.address;
    keys.k4.b = flow.other;
    keys.k4.ap = flow.port;
    keys.k4.bp = flow.other_port;
    keys.k4.proto = proto;
    keys.k4.direction = SNAT_REPLY;
    keys.k4.pad = [0; 2];
    let Some(value) = NODEPORT4.get_ptr_mut(&keys.k4) else {
        return false;
    };
    // SAFETY: an LRU value of this map, read and written in place; a racing
    // writer only costs one renewal.
    unsafe {
        if (*value).other != client.0 || (*value).other_port != client.1 {
            return false;
        }
        (*value).pad2 = now16().to_ne_bytes();
        if fin {
            (*value).flags |= FLOW_CLOSING;
        }
    }
    true
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
    let mode = dispatch();
    let option = l4 == 34 && dsr_option_wanted(ctx, l4, proto, fib.ifindex, room4(mode))?;
    if option && mode != DISPATCH_OPT {
        return encap4(ctx, mode, tuple, flow);
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
    if option {
        push_option4(ctx, front, front_port)?;
    }
    redirect(ctx, result, &fib)
}

/// [`dsr_forward4`] by encapsulation (#447): IPIP keeps the client's packet
/// as it came (to the frontend) inside an outer header from this node's
/// address to the backend; Geneve DNATs it and sends it, in Ethernet, with
/// the frontend in the DSR option, to the FIB's next hop (the backend's
/// node). The inner TTL is decremented, as forwarding does.
#[inline(always)]
fn encap4(
    ctx: &TcContext,
    mode: u8,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
    flow: Nodeport4Value,
) -> Option<i32> {
    let (l4, proto, _, front, client_port, front_port) = tuple;
    let (result, fib) = fib4(ctx, proto, [0; 4], flow.address, BPF_FIB_LOOKUP_SRC);
    if !forwarded(result) {
        return None;
    }
    // SAFETY: the active members after an IPv4 lookup.
    let (source, hop) = unsafe {
        (
            fib.__bindgen_anon_3.ipv4_src.to_ne_bytes(),
            fib.__bindgen_anon_4.ipv4_dst.to_ne_bytes(),
        )
    };
    lower_ttl(ctx)?;
    let tos = ctx.load::<u8>(15).ok()?;
    if mode == DISPATCH_IPIP {
        let total = u16::from_be_bytes(ctx.load::<[u8; 2]>(16).ok()?);
        ctx.skb
            .adjust_room(IPIP4_ROOM, ADJ_ROOM_MAC, ENCAP_L3_IPV4)
            .ok()?;
        outer4(ctx, tos, total.checked_add(20)?, 4, source, flow.address)?;
        return send(ctx, result, &fib);
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
    let total = u16::from_be_bytes(ctx.load::<[u8; 2]>(16).ok()?);
    ctx.skb
        .adjust_room(
            GENEVE4_ROOM,
            ADJ_ROOM_MAC,
            ENCAP_L3_IPV4 | ENCAP_L4_UDP | ENCAP_L2_ETH | ENCAP_INNER_ETH,
        )
        .ok()?;
    let udp = total.checked_add(42)?;
    outer4(ctx, tos, udp.checked_add(20)?, 17, source, hop)?;
    let [s0, s1] = tunnel_port(client_port, front_port);
    let [l0, l1] = udp.to_be_bytes();
    ctx.store(34, &[s0, s1, GENEVE_PORT[0], GENEVE_PORT[1], l0, l1, 0, 0], 0)
        .ok()?;
    ctx.store(42, &GENEVE4_BASE, 0).ok()?;
    ctx.store(50, &GENEVE_OPT4, 0).ok()?;
    ctx.store(54, &front, 0).ok()?;
    ctx.store(58, &[front_port[0], front_port[1], 0, 0], 0).ok()?;
    ctx.store(62, &fib.dmac, 0).ok()?;
    ctx.store(68, &fib.smac, 0).ok()?;
    ctx.store(74, &ETH_P_IPV4, 0).ok()?;
    send(ctx, result, &fib)
}

/// Backend slots a DSR frontend is checked against (finding 0252b1736f32);
/// a frontend with more backends than this cannot vouch for a DSR packet.
const DSR_CHECK_SLOTS: u16 = 256;
/// [`dsr4`]'s answers: no DSR option, an option accepted (the packet goes on
/// to the pod), an option refused (dropped).
const DSR_NONE: i32 = 0;
const DSR_ACCEPT: i32 = 1;
const DSR_REJECT: i32 = 2;

/// Whether `front` is a frontend in DSR mode (its node-local master carries
/// `FWD_MODE_DSR`) and `backend` one of its backends. A forged option cannot
/// then make a reply leave from an address the service does not have.
#[inline(always)]
fn dsr_valid4(front: ([u8; 4], [u8; 2]), proto: u8, backend: ([u8; 4], [u8; 2])) -> bool {
    matches!(dsr_match4(front, proto, backend.0, Some(backend.1)), Some(Some(_)))
}
/// [`dsr_valid4`] with the backend's port unknown (IPIP carries none): None
/// when `front` is not a DSR frontend, `Some(None)` when `address` is not
/// one of its backends (with `port`, when given), else the backend's port.
#[inline(always)]
fn dsr_match4(
    front: ([u8; 4], [u8; 2]),
    proto: u8,
    address: [u8; 4],
    port: Option<[u8; 2]>,
) -> Option<Option<[u8; 2]>> {
    let mut key = Lb4Key {
        address: Be32(front.0),
        dport: Be16(front.1),
        backend_slot: 0,
        proto,
        scope: 1,
        pad: [0; 2],
    };
    // SAFETY: see lookup4.
    let service = unsafe { LB4_SERVICES.get(&key).copied() }?;
    if service.service_flags() & service_flags::FWD_MODE_DSR == 0 {
        return None;
    }
    for slot in 1..=DSR_CHECK_SLOTS {
        if slot > service.count {
            break;
        }
        key.backend_slot = slot;
        // SAFETY: see lookup4.
        let Some(entry) = (unsafe { LB4_SERVICES.get(&key).copied() }) else {
            continue;
        };
        // SAFETY: see lookup4.
        let Some(chosen) = (unsafe { LB4_BACKENDS.get(&entry.backend_id()).copied() }) else {
            continue;
        };
        if chosen.address.0 == address && port.is_none_or(|p| p == chosen.port.0) {
            return Some(Some(chosen.port.0));
        }
    }
    Some(None)
}

/// On the backend's node: a packet carrying the DSR option, from the
/// classifier on its own stack frame.
#[inline(never)]
fn dsr4(skb: *mut __sk_buff) -> i32 {
    dsr_backend4(&TcContext::new(skb)).unwrap_or(DSR_NONE)
}
/// A valid option leaves the reply entry [`nodeport4_out`] rewrites by, and
/// the packet goes on to the pod; an option naming a frontend that is not in
/// DSR mode, or a destination that is not one of its backends, is refused.
#[inline(always)]
fn dsr_backend4(ctx: &TcContext) -> Option<i32> {
    // An encapsulated DSR packet (#447), outer header without options.
    if ctx.load::<[u8; 2]>(12).ok()? == ETH_P_IPV4 && ctx.load::<u8>(14).ok()? == 0x45 {
        match ctx.load::<u8>(23).ok()? {
            4 => return decap_ipip4(ctx),
            17 if ctx.load::<[u8; 2]>(36).ok() == Some(GENEVE_PORT) => return decap_geneve4(ctx),
            _ => {}
        }
    }
    let (l4, proto, client, backend, client_port, backend_port) = tuple4(ctx)?;
    if l4 != 42 || ctx.load::<[u8; 2]>(34).ok()? != DSR_OPT4 {
        return Some(DSR_NONE);
    }
    let advertised = (ctx.load::<[u8; 4]>(38).ok()?, ctx.load::<[u8; 2]>(36).ok()?);
    if !dsr_valid4(advertised, proto, (backend, backend_port)) {
        return Some(DSR_REJECT);
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
        address: advertised.0,
        port: advertised.1,
        flags: 0,
        pad: 0,
        other: [0; 4],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    // A full table only costs this reply its rewrite; the packet is valid.
    let _ = NODEPORT4.insert(&reverse, &front, 0);
    Some(DSR_ACCEPT)
}
/// The reply entry of a DSR flow on the backend's node: the backend's reply
/// to the client leaves from the frontend.
#[inline(always)]
fn dsr_reply4(
    backend: ([u8; 4], [u8; 2]),
    client: ([u8; 4], [u8; 2]),
    front: ([u8; 4], [u8; 2]),
    proto: u8,
) {
    let reverse = Nodeport4Key {
        a: backend.0,
        b: client.0,
        ap: backend.1,
        bp: client.1,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    let value = Nodeport4Value {
        address: front.0,
        port: front.1,
        flags: 0,
        pad: 0,
        other: [0; 4],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    // A full table only costs this reply its rewrite; the packet is valid.
    let _ = NODEPORT4.insert(&reverse, &value, 0);
}
/// IPIP (#447): the inner packet goes to a DSR frontend and the outer
/// destination is one of its backends. Strip the outer header, DNAT the
/// packet to that backend (its port from the service), leave the reply
/// entry. An inner destination that is not a DSR frontend is not ours; a
/// DSR frontend whose backends do not include the outer destination drops.
#[inline(always)]
fn decap_ipip4(ctx: &TcContext) -> Option<i32> {
    if ctx.load::<u8>(34).ok()? != 0x45 {
        return Some(DSR_NONE);
    }
    let proto = ctx.load::<u8>(43).ok()?;
    if proto != 6 && proto != 17 {
        return Some(DSR_NONE);
    }
    let backend = ctx.load::<[u8; 4]>(30).ok()?;
    let client = ctx.load::<[u8; 4]>(46).ok()?;
    let front = ctx.load::<[u8; 4]>(50).ok()?;
    let [c0, c1, f0, f1] = ctx.load::<[u8; 4]>(54).ok()?;
    let (client_port, front_port) = ([c0, c1], [f0, f1]);
    let port = match dsr_match4((front, front_port), proto, backend, None) {
        None => return Some(DSR_NONE),
        Some(None) => return Some(DSR_REJECT),
        Some(Some(port)) => port,
    };
    ctx.skb.adjust_room(IPIP4_STRIP, ADJ_ROOM_MAC, 0).ok()?;
    rewrite4(ctx, 34, proto, 30, 36, (front, front_port), (backend, port))?;
    dsr_reply4((backend, port), (client, client_port), (front, front_port), proto);
    Some(DSR_ACCEPT)
}
/// Geneve (#447): a UDP 6081 packet with the DSR option, carrying the
/// already DNATed packet in Ethernet. The frontend must be a DSR frontend
/// and the inner destination one of its backends; strip everything before
/// the inner IPv4 header and leave the reply entry. Geneve without the DSR
/// option is not ours.
#[inline(always)]
fn decap_geneve4(ctx: &TcContext) -> Option<i32> {
    if ctx.load::<[u8; 4]>(42).ok()? != [3, 0x40, 0x65, 0x58]
        || ctx.load::<[u8; 4]>(50).ok()? != GENEVE_OPT4
    {
        return Some(DSR_NONE);
    }
    if ctx.load::<[u8; 2]>(74).ok()? != ETH_P_IPV4 || ctx.load::<u8>(76).ok()? != 0x45 {
        return Some(DSR_REJECT);
    }
    let front = (ctx.load::<[u8; 4]>(54).ok()?, ctx.load::<[u8; 2]>(58).ok()?);
    let proto = ctx.load::<u8>(85).ok()?;
    let client = ctx.load::<[u8; 4]>(88).ok()?;
    let backend = ctx.load::<[u8; 4]>(92).ok()?;
    let [c0, c1, b0, b1] = ctx.load::<[u8; 4]>(96).ok()?;
    if !dsr_valid4(front, proto, (backend, [b0, b1])) {
        return Some(DSR_REJECT);
    }
    ctx.skb.adjust_room(GENEVE4_STRIP, ADJ_ROOM_MAC, 0).ok()?;
    dsr_reply4((backend, [b0, b1]), (client, [c0, c1]), front, proto);
    Some(DSR_ACCEPT)
}

#[inline(always)]
fn nodeport4_in(ctx: &TcContext) -> Option<i32> {
    let tuple = tuple4(ctx)?;
    let (l4, proto, client, front, client_port, front_port) = tuple;
    let fin = closes(ctx, l4, proto);
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
        if let Some(value) = NODEPORT4.get_ptr_mut(&key) {
            // SAFETY: an LRU value of this map, written in place.
            unsafe {
                (*value).pad2 = now16().to_ne_bytes();
                if fin {
                    (*value).flags |= FLOW_CLOSING;
                }
            }
        }
        if flow.flags & FLOW_MASQ != 0 {
            return masq_reply4(ctx, tuple, flow);
        }
        return snat_reply4(ctx, tuple, flow);
    }
    key.direction = FORWARD;
    let mut route = None;
    // A known SNAT flow whose reservation expired and went to another flow
    // starts again as a new flow.
    // SAFETY: LRU value copied at once, never written through.
    let known = unsafe { NODEPORT4.get(&key).copied() }
        .filter(|f| f.flags & FLOW_SNAT == 0 || live4(f, (client, client_port), proto, fin));
    let flow = match known {
        Some(known) => known,
        // A later fragment follows its datagram's flow; it never starts one.
        None if l4 == NO_L4 => return None,
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
            // DSR only when this first packet can carry the option (a bare
            // header; a TCP SYN, or UDP that fits with it): otherwise the
            // backend's node would never learn the frontend (finding
            // 08ad0c4a7dca), so the flow is source-NATed instead.
            let dsr = remote
                && service.service_flags() & service_flags::FWD_MODE_DSR != 0
                && l4 == 34
                && dsr_option_wanted(ctx, l4, proto, fib.ifindex, room4(dispatch()))
                    .unwrap_or(false);
            if dsr {
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
                    flags: if fin { FLOW_CLOSING } else { 0 },
                    pad: 0,
                    other: client,
                    other_port: client_port,
                    pad2: now16().to_ne_bytes(),
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

// ---------------------------------------------------------------------------
// BPF masquerade (#460), IPv4. At the uplink's egress, a local Pod's TCP, UDP
// or ICMP echo packet to a destination outside the cluster ([`MASQ4_SOURCES`],
// [`MASQ4_EXCLUDE`]) leaves from this node's address on that uplink (the FIB's
// source) and a NAT port (an echo: a NAT identifier) from the NodePort SNAT
// range, claimed and expired as NodePort's SNAT ports are, in the same map.
// At the ingress, the reply (and an ICMP error about the flow) is reverse
// translated to the Pod and handed to the host stack, so the Pod's own
// programs judge it. Netfilter's conntrack saw the Pod's address on the way
// out and sees it on the way back.

/// Whether `src -> dst` is masqueraded.
#[inline(always)]
fn masqueraded4(src: [u8; 4], dst: [u8; 4]) -> bool {
    MASQ4_SOURCES.get(Key::new(32, src)).is_some() && MASQ4_EXCLUDE.get(Key::new(32, dst)).is_none()
}

/// The masqueraded flow `src:sport -> dst:dport`: its NAT address and port,
/// claimed by its first packet. A later fragment never starts one.
#[inline(always)]
fn masq_flow4(
    ctx: &TcContext,
    l4: usize,
    proto: u8,
    from: ([u8; 4], [u8; 2]),
    to: ([u8; 4], [u8; 2]),
    fin: bool,
) -> Option<([u8; 4], [u8; 2])> {
    let key = Nodeport4Key {
        a: from.0,
        b: to.0,
        ap: from.1,
        bp: to.1,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    if let Some(flow) = unsafe { NODEPORT4.get(&key).copied() }
        .filter(|f| f.flags & FLOW_MASQ != 0 && live4(f, from, proto, fin))
    {
        return Some((flow.other, flow.other_port));
    }
    if l4 == NO_L4 {
        return None;
    }
    let (result, fib) = fib4(ctx, proto, [0; 4], to.0, BPF_FIB_LOOKUP_SRC);
    // Only out of the uplink it leaves by, from that uplink's address.
    if !forwarded(result) || fib.ifindex != uplink(ctx) {
        return None;
    }
    // SAFETY: the active member after an IPv4 lookup.
    let nat = unsafe { fib.__bindgen_anon_3.ipv4_src }.to_ne_bytes();
    let reply = Nodeport4Value {
        address: to.0,
        port: to.1,
        flags: FLOW_MASQ | if fin { FLOW_CLOSING } else { 0 },
        pad: 0,
        other: from.0,
        other_port: from.1,
        pad2: now16().to_ne_bytes(),
    };
    let port = claim_port(to, nat, proto, &reply)?;
    let flow = Nodeport4Value {
        address: to.0,
        port: to.1,
        flags: FLOW_SNAT | FLOW_MASQ,
        pad: 0,
        other: nat,
        other_port: port,
        pad2: [0; 2],
    };
    NODEPORT4.insert(&key, &flow, 0).ok()?;
    Some((nat, port))
}

/// An IPv4 ICMP message that is not a fragment: (L4 offset, src, dst, type,
/// echo identifier).
#[inline(always)]
fn icmp4(ctx: &TcContext) -> Option<(usize, [u8; 4], [u8; 4], u8, [u8; 2])> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV4 {
        return None;
    }
    let version_ihl = ctx.load::<u8>(14).ok()?;
    if version_ihl >> 4 != 4 || version_ihl & 15 < 5 || ctx.load::<u8>(23).ok()? != ICMP4 {
        return None;
    }
    if u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?) & 0x3fff != 0 {
        return None;
    }
    let l4 = usize::from(version_ihl & 15)
        .checked_mul(4)?
        .checked_add(14)?;
    Some((
        l4,
        ctx.load::<[u8; 4]>(26).ok()?,
        ctx.load::<[u8; 4]>(30).ok()?,
        ctx.load::<u8>(l4).ok()?,
        ctx.load::<[u8; 2]>(l4.checked_add(4)?).ok()?,
    ))
}

/// Replace IPv4 address `old` at `at` by `new`, with the header checksum.
#[inline(always)]
fn set_address4(ctx: &TcContext, at: usize, old: [u8; 4], new: [u8; 4]) -> Option<()> {
    ctx.l3_csum_replace(
        24,
        u64::from(u32::from_ne_bytes(old)),
        u64::from(u32::from_ne_bytes(new)),
        4,
    )
    .ok()?;
    ctx.store(at, &new, 0).ok()
}
/// Replace the echo identifier at `l4 + 4`, with the ICMP checksum (no
/// pseudo-header).
#[inline(always)]
fn set_echo_id(ctx: &TcContext, l4: usize, old: [u8; 2], new: [u8; 2]) -> Option<()> {
    ctx.l4_csum_replace(
        l4.checked_add(2)?,
        u64::from(u16::from_ne_bytes(old)),
        u64::from(u16::from_ne_bytes(new)),
        2,
    )
    .ok()?;
    ctx.store(l4.checked_add(4)?, &new, 0).ok()
}

/// The packet an ICMP error at `l4` quotes, TCP or UDP with its ports:
/// (inner header offset, its L4 offset, protocol, source, destination,
/// source port, destination port).
#[inline(always)]
fn icmp4_inner(
    ctx: &TcContext,
    l4: usize,
) -> Option<(usize, usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2])> {
    let inner = l4.checked_add(8)?;
    let version_ihl = ctx.load::<u8>(inner).ok()?;
    if version_ihl >> 4 != 4 || version_ihl & 15 < 5 {
        return None;
    }
    let proto = ctx.load::<u8>(inner.checked_add(9)?).ok()?;
    if proto != 6 && proto != 17 {
        return None;
    }
    let inner_l4 = usize::from(version_ihl & 15)
        .checked_mul(4)?
        .checked_add(inner)?;
    let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(inner_l4).ok()?;
    Some((
        inner,
        inner_l4,
        proto,
        ctx.load::<[u8; 4]>(inner.checked_add(12)?).ok()?,
        ctx.load::<[u8; 4]>(inner.checked_add(16)?).ok()?,
        [s0, s1],
        [d0, d1],
    ))
}

/// Rewrite the address `offset` bytes into the quoted header at `inner` (12
/// its source, 16 its destination) and the port at `port_at` from `old` to
/// `new`, with the quoted header's checksum and the ICMP checksum at
/// `l4 + 2`, which covers both. The quoted TCP/UDP checksum is left: the
/// quote may be cut short, and receivers do not check it.
#[inline(always)]
fn set_inner4(
    ctx: &TcContext,
    l4: usize,
    inner: usize,
    offset: usize,
    port_at: usize,
    old: ([u8; 4], [u8; 2]),
    new: ([u8; 4], [u8; 2]),
) -> Option<()> {
    let (old_ip, new_ip) = (
        u64::from(u32::from_ne_bytes(old.0)),
        u64::from(u32::from_ne_bytes(new.0)),
    );
    let check_at = inner.checked_add(10)?;
    let before = ctx.load::<[u8; 2]>(check_at).ok()?;
    ctx.l3_csum_replace(check_at, old_ip, new_ip, 4).ok()?;
    let after = ctx.load::<[u8; 2]>(check_at).ok()?;
    let icmp_check = l4.checked_add(2)?;
    for (old, new, size) in [
        (old_ip, new_ip, 4),
        (
            u64::from(u16::from_ne_bytes(before)),
            u64::from(u16::from_ne_bytes(after)),
            2,
        ),
        (
            u64::from(u16::from_ne_bytes(old.1)),
            u64::from(u16::from_ne_bytes(new.1)),
            2,
        ),
    ] {
        ctx.l4_csum_replace(icmp_check, old, new, size).ok()?;
    }
    ctx.store(inner.checked_add(offset)?, &new.0, 0).ok()?;
    ctx.store(port_at, &new.1, 0).ok()
}

#[inline(always)]
fn masquerade4(ctx: &TcContext) -> Option<()> {
    let Some((l4, proto, src, dst, sport, dport)) = tuple4(ctx) else {
        // An echo request: its identifier is the port.
        let (l4, src, dst, kind, id) = icmp4(ctx)?;
        if kind != 8 || !masqueraded4(src, dst) {
            return None;
        }
        let (nat, nat_id) = masq_flow4(ctx, l4, ICMP4, (src, id), (dst, [0; 2]), false)?;
        set_address4(ctx, 26, src, nat)?;
        return set_echo_id(ctx, l4, id, nat_id);
    };
    if !masqueraded4(src, dst) {
        return None;
    }
    let fin = closes(ctx, l4, proto);
    let nat = masq_flow4(ctx, l4, proto, (src, sport), (dst, dport), fin)?;
    rewrite4(ctx, l4, proto, 26, l4, (src, sport), nat)
}

/// The reply of a masqueraded TCP/UDP flow: to the Pod, through the stack.
#[inline(always)]
fn masq_reply4(
    ctx: &TcContext,
    tuple: (usize, u8, [u8; 4], [u8; 4], [u8; 2], [u8; 2]),
    flow: Nodeport4Value,
) -> Option<i32> {
    let (l4, proto, _, nat, _, nat_port) = tuple;
    rewrite4(
        ctx,
        l4,
        proto,
        30,
        l4.checked_add(2)?,
        (nat, nat_port),
        (flow.other, flow.other_port),
    )?;
    Some(TC_ACT_OK)
}

/// A masqueraded flow's reservation `server:server_port -> nat:nat_port`.
#[inline(always)]
fn masq_reservation4(
    server: ([u8; 4], [u8; 2]),
    nat: ([u8; 4], [u8; 2]),
    proto: u8,
) -> Option<Nodeport4Value> {
    let key = Nodeport4Key {
        a: server.0,
        b: nat.0,
        ap: server.1,
        bp: nat.1,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    unsafe { NODEPORT4.get(&key).copied() }.filter(|f| f.flags & FLOW_MASQ != 0)
}

/// At the uplink's ingress: an echo reply to a masqueraded echo, or an ICMP
/// error (destination unreachable, time exceeded, parameter problem) about a
/// masqueraded TCP/UDP flow, to the Pod. For an error, the embedded packet's
/// source (address, port and header checksum) is translated too, with the
/// ICMP checksum.
#[inline(always)]
fn masq_icmp4_in(ctx: &TcContext) -> Option<i32> {
    let (l4, src, dst, kind, id) = icmp4(ctx)?;
    if kind == 0 {
        let flow = masq_reservation4((src, [0; 2]), (dst, id), ICMP4)?;
        set_address4(ctx, 30, dst, flow.other)?;
        set_echo_id(ctx, l4, id, flow.other_port)?;
        return Some(TC_ACT_OK);
    }
    if !matches!(kind, 3 | 11 | 12) {
        return None;
    }
    let (inner, inner_l4, proto, inner_src, server, sport, dport) = icmp4_inner(ctx, l4)?;
    if inner_src != dst {
        return None;
    }
    let flow = masq_reservation4((server, dport), (dst, sport), proto)?;
    set_address4(ctx, 30, dst, flow.other)?;
    set_inner4(
        ctx,
        l4,
        inner,
        12,
        inner_l4,
        (dst, sport),
        (flow.other, flow.other_port),
    )?;
    Some(TC_ACT_OK)
}

// ICMP errors of Service flows (#449). A client matches an ICMP error to its
// connection by the packet it quotes, so the quote must name the frontend it
// talks to, never the backend.
//
// On the backend's node, at the uplink's egress: an error about a packet of
// a flow whose replies are rewritten there (a REPLY entry: a DSR flow, or a
// node-local backend's) has the quote's destination (and the error's source,
// when the backend sent it) rewritten from the backend to the frontend.
//
// On the frontend's node, at the uplink's ingress: an error about a reply
// (the quote's source, and the error's destination, is the frontend) of a
// DSR or node-local flow goes to the backend: the error's destination and
// the quote's source become the backend. A DSR flow's is redirected toward
// the backend's node as the flow's packets are; a local one goes to the
// stack. Errors about source-NATed flows pass untouched.

/// Whether ICMP `kind` is an error that quotes the packet it is about:
/// destination unreachable (fragmentation needed among them), time exceeded
/// or parameter problem.
#[inline(always)]
fn icmp4_error(kind: u8) -> bool {
    matches!(kind, 3 | 11 | 12)
}

/// On the backend's node: an ICMP error about a packet a client sent to a
/// frontend, leaving toward the client.
#[inline(always)]
fn icmp_error4_out(ctx: &TcContext) -> Option<()> {
    let (l4, src, _, kind, _) = icmp4(ctx)?;
    if !icmp4_error(kind) {
        return None;
    }
    let (inner, inner_l4, proto, client, backend, client_port, backend_port) =
        icmp4_inner(ctx, l4)?;
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
    if src == backend {
        set_address4(ctx, 26, backend, front.address)?;
    }
    set_inner4(
        ctx,
        l4,
        inner,
        16,
        inner_l4.checked_add(2)?,
        (backend, backend_port),
        (front.address, front.port),
    )
}

/// On the frontend's node: an ICMP error about a reply the frontend sent,
/// to the flow's backend.
#[inline(always)]
fn icmp_error4_in(ctx: &TcContext) -> Option<i32> {
    let (l4, src, dst, kind, _) = icmp4(ctx)?;
    if !icmp4_error(kind) {
        return None;
    }
    let (inner, inner_l4, proto, front, client, front_port, client_port) = icmp4_inner(ctx, l4)?;
    if front != dst {
        return None;
    }
    let key = Nodeport4Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let flow = unsafe { NODEPORT4.get(&key).copied() }?;
    if flow.flags & !(FLOW_DSR | FLOW_CLOSING) != 0 {
        return None;
    }
    let backend = (flow.address, flow.port);
    let route = if flow.flags & FLOW_DSR != 0 {
        ttl_ok(ctx)?;
        let (result, fib) = fib4(ctx, ICMP4, src, backend.0, 0);
        if !forwarded(result) {
            return None;
        }
        Some((result, fib))
    } else {
        None
    };
    set_address4(ctx, 30, front, backend.0)?;
    set_inner4(ctx, l4, inner, 12, inner_l4, (front, front_port), backend)?;
    match route {
        Some((result, fib)) => redirect(ctx, result, &fib),
        None => Some(TC_ACT_OK),
    }
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

/// Keys a NAT port claim or renewal builds (finding 1cb155baca89), kept in
/// per-CPU map memory: on the stack they would push the ingress paths over
/// the 512-byte frame (#369).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NatKeys {
    k4: Nodeport4Key,
    s4: Nodeport4Key,
    k6: Nodeport6Key,
    s6: Nodeport6Key,
}
#[map(name = "flowsdn_nodeport_natkeys")]
static NAT_KEYS: PerCpuArray<NatKeys> = PerCpuArray::with_max_entries(1, 0);

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
    send6(ctx, result, fib)
}
/// [`redirect6`] without the hop limit: an encapsulated packet's outer header
/// is new.
#[inline(always)]
fn send6(ctx: &TcContext, result: i64, fib: *const bpf_fib_lookup) -> Option<i32> {
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
    let keys = NAT_KEYS.get_ptr_mut(0)?;
    // SAFETY: no arguments; returns a pseudo-random scalar.
    let start = unsafe { bpf_get_prandom_u32() };
    for i in 0..NAT_TRIES {
        let offset = start.wrapping_add(i).checked_rem(NAT_PORTS)?;
        let port = u16::try_from(NAT_PORT_MIN.checked_add(offset)?)
            .ok()?
            .to_be_bytes();
        // SAFETY: this CPU's scratch slot (see claim_port).
        let keys = unsafe { &mut *keys };
        keys.k6.a = backend.0;
        keys.k6.b = nat;
        keys.k6.ap = backend.1;
        keys.k6.bp = port;
        keys.k6.proto = proto;
        keys.k6.direction = SNAT_REPLY;
        keys.k6.pad = [0; 2];
        if NODEPORT6.insert(&keys.k6, reply, BPF_NOEXIST).is_ok() {
            return Some(port);
        }
        // SAFETY: an LRU value read in place.
        let Some(held) = (unsafe { NODEPORT6.get(&keys.k6) }) else {
            continue;
        };
        if !expired(held.flags, held.pad2, proto, now16()) {
            continue;
        }
        keys.s6.a = held.other;
        keys.s6.b = held.address;
        keys.s6.ap = held.other_port;
        keys.s6.bp = held.port;
        keys.s6.proto = proto;
        keys.s6.direction = FORWARD;
        keys.s6.pad = [0; 2];
        // SAFETY: as above.
        if unsafe { NODEPORT6.get(&keys.s6) }
            .is_some_and(|f| f.other == nat && f.other_port == port)
        {
            let _ = NODEPORT6.remove(&keys.s6);
        }
        if NODEPORT6.insert(&keys.k6, reply, 0).is_ok() {
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

/// The RFC 6052 NAT46/64 gateway (#454, the reference's
/// `enable-nat46x64-gateway`): its /96 prefix, when on.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Gateway64 {
    enabled: u8,
    pad: [u8; 3],
    prefix: [u8; 12],
}
#[map(name = "flowsdn_gw64_config")]
static GW64_CONFIG: HashMap<u32, Gateway64> = HashMap::with_max_entries(1, BPF_F_NO_PREALLOC);
/// The IPv6 sources the gateway translates: this node's pod CIDRs.
#[map(name = "flowsdn_gw64_sources")]
static GW64_SOURCES: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(256, BPF_F_NO_PREALLOC);

/// [`ingress6`]'s steps: not ours, a reply of an SNAT flow, a new flow, a
/// known forward flow.
const STEP_PASS: i32 = 0;
const STEP_REPLY: i32 = 1;
const STEP_NEW: i32 = 2;
const STEP_FORWARD: i32 = 3;
/// A translated flow's reply and, on the IPv6 side, its forward packet.
const STEP_XLATE_REPLY: i32 = 4;
const STEP_XLATE_FORWARD: i32 = 5;
/// A frame with a Destination Options header: [`dsr6`] judges it.
const STEP_DSR: i32 = 6;
/// The reply of a masqueraded flow (#513): [`masq_reply6`].
const STEP_MASQ_REPLY: i32 = 7;

/// [`dsr_valid4`] for IPv6.
#[inline(always)]
fn dsr_valid6(front: ([u8; 16], [u8; 2]), proto: u8, backend: ([u8; 16], [u8; 2])) -> bool {
    matches!(dsr_match6(front, proto, backend.0, Some(backend.1)), Some(Some(_)))
}
/// [`dsr_match4`] for IPv6.
#[inline(always)]
fn dsr_match6(
    front: ([u8; 16], [u8; 2]),
    proto: u8,
    address: [u8; 16],
    port: Option<[u8; 2]>,
) -> Option<Option<[u8; 2]>> {
    let mut key = Lb6Key {
        address: front.0,
        dport: Be16(front.1),
        backend_slot: 0,
        proto,
        scope: 1,
        pad: [0; 2],
    };
    // SAFETY: see lookup6.
    let service = unsafe { LB6_SERVICES.get(&key).copied() }?;
    if service.service_flags() & service_flags::FWD_MODE_DSR == 0 {
        return None;
    }
    for slot in 1..=DSR_CHECK_SLOTS {
        if slot > service.count {
            break;
        }
        key.backend_slot = slot;
        // SAFETY: see lookup6.
        let Some(entry) = (unsafe { LB6_SERVICES.get(&key).copied() }) else {
            continue;
        };
        // SAFETY: see lookup6.
        let Some(chosen) = (unsafe { LB6_BACKENDS.get(&entry.backend_id()).copied() }) else {
            continue;
        };
        if chosen.address == address && port.is_none_or(|p| p == chosen.port.0) {
            return Some(Some(chosen.port.0));
        }
    }
    Some(None)
}
/// [`dsr4`] for IPv6, from the classifier on its own stack frame.
#[inline(never)]
fn dsr6(skb: *mut __sk_buff) -> i32 {
    dsr_backend6(&TcContext::new(skb)).unwrap_or(DSR_NONE)
}
/// [`dsr_backend4`] for IPv6: the option is a Destination Options header right
/// after the fixed one, its next header the L4 protocol.
#[inline(always)]
fn dsr_backend6(ctx: &TcContext) -> Option<i32> {
    match ctx.load::<u8>(IP6_NEXT).ok()? {
        41 => return decap_ipip6(ctx),
        17 => return decap_geneve6(ctx),
        _ => {}
    }
    if ctx.load::<[u8; 2]>(IP6_OPT.checked_add(2)?).ok()? != DSR_OPT6 {
        return Some(DSR_NONE);
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
    // The destination (`reverse.a`, `.ap`) must be one of its backends.
    if !dsr_valid6((front.address, front.port), proto, (reverse.a, reverse.ap)) {
        return Some(DSR_REJECT);
    }
    let _ = NODEPORT6.insert(&reverse, &front, 0);
    Some(DSR_ACCEPT)
}
/// [`dsr_reply4`] for IPv6.
#[inline(always)]
fn dsr_reply6(
    backend: ([u8; 16], [u8; 2]),
    client: ([u8; 16], [u8; 2]),
    front: ([u8; 16], [u8; 2]),
    proto: u8,
) {
    let reverse = Nodeport6Key {
        a: backend.0,
        b: client.0,
        ap: backend.1,
        bp: client.1,
        proto,
        direction: REPLY,
        pad: [0; 2],
    };
    let value = Nodeport6Value {
        address: front.0,
        port: front.1,
        flags: 0,
        pad: 0,
        other: [0; 16],
        other_port: [0; 2],
        pad2: [0; 2],
    };
    let _ = NODEPORT6.insert(&reverse, &value, 0);
}
/// [`decap_ipip4`] for IP6IP6: the inner header (no extension headers) at 54.
#[inline(always)]
fn decap_ipip6(ctx: &TcContext) -> Option<i32> {
    if ctx.load::<u8>(54).ok()? >> 4 != 6 {
        return Some(DSR_NONE);
    }
    let proto = ctx.load::<u8>(60).ok()?;
    if proto != 6 && proto != 17 {
        return Some(DSR_NONE);
    }
    let backend = ctx.load::<[u8; 16]>(IP6_DST).ok()?;
    let client = ctx.load::<[u8; 16]>(62).ok()?;
    let front = ctx.load::<[u8; 16]>(78).ok()?;
    let [c0, c1, f0, f1] = ctx.load::<[u8; 4]>(94).ok()?;
    let (client_port, front_port) = ([c0, c1], [f0, f1]);
    let port = match dsr_match6((front, front_port), proto, backend, None) {
        None => return Some(DSR_NONE),
        Some(None) => return Some(DSR_REJECT),
        Some(Some(port)) => port,
    };
    ctx.skb.adjust_room(IPIP6_STRIP, ADJ_ROOM_MAC, 0).ok()?;
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (backend, port),
    )?;
    dsr_reply6((backend, port), (client, client_port), (front, front_port), proto);
    Some(DSR_ACCEPT)
}
/// [`decap_geneve4`] for IPv6: the option at 70, the inner IPv6 header at 108.
#[inline(always)]
fn decap_geneve6(ctx: &TcContext) -> Option<i32> {
    if ctx.load::<[u8; 4]>(62).ok()? != [6, 0x40, 0x65, 0x58]
        || ctx.load::<[u8; 4]>(70).ok()? != GENEVE_OPT6
    {
        return Some(DSR_NONE);
    }
    if ctx.load::<[u8; 2]>(106).ok()? != ETH_P_IPV6 || ctx.load::<u8>(108).ok()? >> 4 != 6 {
        return Some(DSR_REJECT);
    }
    let front = (ctx.load::<[u8; 16]>(74).ok()?, ctx.load::<[u8; 2]>(90).ok()?);
    let proto = ctx.load::<u8>(114).ok()?;
    let client = ctx.load::<[u8; 16]>(116).ok()?;
    let backend = ctx.load::<[u8; 16]>(132).ok()?;
    let [c0, c1, b0, b1] = ctx.load::<[u8; 4]>(148).ok()?;
    if !dsr_valid6(front, proto, (backend, [b0, b1])) {
        return Some(DSR_REJECT);
    }
    ctx.skb.adjust_room(GENEVE6_STRIP, ADJ_ROOM_MAC, 0).ok()?;
    dsr_reply6((backend, [b0, b1]), (client, [c0, c1]), front, proto);
    Some(DSR_ACCEPT)
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
    // The DSR option, IP6IP6, or Geneve with the DSR option (#447).
    let next = ctx.load::<u8>(IP6_NEXT).ok()?;
    if next == IPPROTO_DSTOPTS
        || next == 41
        || (next == 17
            && ctx.load::<[u8; 2]>(IP6_DPORT).ok() == Some(GENEVE_PORT)
            && ctx.load::<[u8; 4]>(70).ok() == Some(GENEVE_OPT6))
    {
        return Some(STEP_DSR);
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
        STEP_REPLY if flow.flags & FLOW_MASQ != 0 => STEP_MASQ_REPLY,
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
    let key = Nodeport6Key {
        a: backend,
        b: nat,
        ap: backend_port,
        bp: nat_port,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    if let Some(value) = NODEPORT6.get_ptr_mut(&key) {
        // SAFETY: an LRU value of this map, written in place.
        unsafe {
            (*value).pad2 = now16().to_ne_bytes();
            if closes(ctx, IP6_SPORT, proto) {
                (*value).flags |= FLOW_CLOSING;
            }
        }
    }
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
        if !live6(&ctx, &state.tuple, &state.flow) {
            return STALE6;
        }
        snat_forward6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
    } else if state.flow.flags & FLOW_DSR != 0 {
        dsr_forward6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
    } else {
        let _ = local6(&ctx, &state.tuple, &state.flow);
        TC_ACT_OK
    }
}
/// [`nodeport_forward6`]'s answer for an SNAT flow whose reservation expired
/// and went to another flow: the classifier starts it again as a new flow.
const STALE6: i32 = 1000;
/// [`live4`] for IPv6.
#[inline(always)]
fn live6(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> bool {
    let (proto, client, _, client_port, _) = *tuple;
    let Some(keys) = NAT_KEYS.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: this CPU's scratch slot, used by nothing else meanwhile.
    let keys = unsafe { &mut *keys };
    keys.k6.a = flow.address;
    keys.k6.b = flow.other;
    keys.k6.ap = flow.port;
    keys.k6.bp = flow.other_port;
    keys.k6.proto = proto;
    keys.k6.direction = SNAT_REPLY;
    keys.k6.pad = [0; 2];
    let Some(value) = NODEPORT6.get_ptr_mut(&keys.k6) else {
        return false;
    };
    // SAFETY: an LRU value of this map, read and written in place.
    unsafe {
        if (*value).other != client || (*value).other_port != client_port {
            return false;
        }
        (*value).pad2 = now16().to_ne_bytes();
        if closes(ctx, IP6_SPORT, proto) {
            (*value).flags |= FLOW_CLOSING;
        }
    }
    true
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
    let mode = dispatch();
    let option = dsr_option_wanted(ctx, IP6_SPORT, proto, device, room6(mode))?;
    if option && mode != DISPATCH_OPT {
        return encap6(ctx, mode, tuple, flow);
    }
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
/// A fresh outer IPv6 header at offset 14: `first` (version, traffic class,
/// flow label) from the inner one, hop limit 64.
#[inline(always)]
fn outer6(
    ctx: &TcContext,
    first: [u8; 4],
    payload: u16,
    next: u8,
    src: [u8; 16],
    dst: [u8; 16],
) -> Option<()> {
    let [p0, p1] = payload.to_be_bytes();
    ctx.store(14, &first, 0).ok()?;
    ctx.store(IP6_PAYLOAD, &[p0, p1, next, 64], 0).ok()?;
    ctx.store(IP6_SRC, &src, 0).ok()?;
    ctx.store(IP6_DST, &dst, 0).ok()
}
/// [`encap4`] for IPv6: IP6IP6 to the backend, or Geneve to the FIB's next
/// hop with the IPv6 DSR option. The inner hop limit is decremented.
#[inline(always)]
fn encap6(ctx: &TcContext, mode: u8, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<i32> {
    let (proto, _, front, client_port, front_port) = *tuple;
    let (result, fib) = fib6(ctx, proto, [0; 16], flow.address, BPF_FIB_LOOKUP_SRC)?;
    if !forwarded(result) {
        return None;
    }
    // SAFETY: the per-CPU slot fib6 just filled; the active members after an
    // IPv6 lookup.
    let (source, hop, dmac, smac) = unsafe {
        (
            ip6_bytes((*fib).__bindgen_anon_3.ipv6_src),
            ip6_bytes((*fib).__bindgen_anon_4.ipv6_dst),
            (*fib).dmac,
            (*fib).smac,
        )
    };
    let hops = ctx.load::<u8>(IP6_HOPS).ok()?.checked_sub(1)?;
    ctx.store(IP6_HOPS, &hops, 0).ok()?;
    let first = ctx.load::<[u8; 4]>(14).ok()?;
    if mode == DISPATCH_IPIP {
        let payload = u16::from_be_bytes(ctx.load::<[u8; 2]>(IP6_PAYLOAD).ok()?);
        ctx.skb
            .adjust_room(IPIP6_ROOM, ADJ_ROOM_MAC, ENCAP_L3_IPV6)
            .ok()?;
        outer6(ctx, first, payload.checked_add(40)?, 41, source, flow.address)?;
        return send6(ctx, result, fib);
    }
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    let payload = u16::from_be_bytes(ctx.load::<[u8; 2]>(IP6_PAYLOAD).ok()?);
    ctx.skb
        .adjust_room(
            GENEVE6_ROOM,
            ADJ_ROOM_MAC,
            ENCAP_L3_IPV6 | ENCAP_L4_UDP | ENCAP_L2_ETH | ENCAP_INNER_ETH,
        )
        .ok()?;
    // UDP 8 + Geneve 8 + option 24 + Ethernet 14 + the inner IPv6 packet.
    let udp = payload.checked_add(94)?;
    outer6(ctx, first, udp, 17, source, hop)?;
    let [s0, s1] = tunnel_port(client_port, front_port);
    let [l0, l1] = udp.to_be_bytes();
    // A zero UDP checksum: the backend's node's program takes the packet
    // before the stack, and the inner packet's own checksum stays valid.
    ctx.store(54, &[s0, s1, GENEVE_PORT[0], GENEVE_PORT[1], l0, l1, 0, 0], 0)
        .ok()?;
    ctx.store(62, &GENEVE6_BASE, 0).ok()?;
    ctx.store(70, &GENEVE_OPT6, 0).ok()?;
    ctx.store(74, &front, 0).ok()?;
    ctx.store(90, &[front_port[0], front_port[1], 0, 0], 0).ok()?;
    ctx.store(94, &dmac, 0).ok()?;
    ctx.store(100, &smac, 0).ok()?;
    ctx.store(106, &ETH_P_IPV6, 0).ok()?;
    send6(ctx, result, fib)
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
        flags: if closes(ctx, IP6_SPORT, proto) {
            FLOW_CLOSING
        } else {
            0
        },
        pad: 0,
        other: [0; 16],
        other_port: [0; 2],
        pad2: now16().to_ne_bytes(),
    };
    let remote = forwarded(result) && out_device == uplink(ctx);
    // As for IPv4: DSR only when this first packet can carry the option.
    let dsr = remote
        && service.service_flags() & service_flags::FWD_MODE_DSR != 0
        && dsr_option_wanted(ctx, IP6_SPORT, proto, out_device, room6(dispatch()))
            .unwrap_or(false);
    if dsr {
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

// ICMPv6 errors of Service flows (#449): see "ICMP errors of Service flows"
// for IPv4. The ICMPv6 checksum covers a pseudo-header: a rewrite of the
// outer header's address is a pseudo-header change, one of the quoted
// packet's is not. Only a message right after the fixed header, quoting a
// TCP/UDP packet right after its fixed header, is translated.
const ICMP6: u8 = 58;
const ICMP6_CHECK: usize = 56;
/// The quoted packet: its next header, source, destination, and what
/// follows its fixed header.
const INNER6_NEXT: usize = 68;
const INNER6_SRC: usize = 70;
const INNER6_DST: usize = 86;
const INNER6_L4: usize = 102;

/// An ICMPv6 error (destination unreachable, packet too big, time exceeded,
/// parameter problem) quoting a TCP/UDP packet: (protocol, its source,
/// destination, the quoted L4 offset, source port, destination port). The
/// quote may carry one Destination Options header (a DSR packet's, as the
/// backend received it).
#[inline(always)]
fn icmp6_error(ctx: &TcContext) -> Option<(u8, [u8; 16], [u8; 16], usize, [u8; 2], [u8; 2])> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV6
        || ctx.load::<u8>(14).ok()? >> 4 != 6
        || ctx.load::<u8>(IP6_NEXT).ok()? != ICMP6
    {
        return None;
    }
    if !matches!(ctx.load::<u8>(IP6_SPORT).ok()?, 1..=4) {
        return None;
    }
    if ctx.load::<u8>(INNER6_NEXT.checked_sub(6)?).ok()? >> 4 != 6 {
        return None;
    }
    let (proto, inner_l4) = match ctx.load::<u8>(INNER6_NEXT).ok()? {
        IPPROTO_DSTOPTS => {
            let [next, length] = ctx.load::<[u8; 2]>(INNER6_L4).ok()?;
            let size = usize::from(length).checked_add(1)?.checked_mul(8)?;
            (next, INNER6_L4.checked_add(size)?)
        }
        next => (next, INNER6_L4),
    };
    if proto != 6 && proto != 17 {
        return None;
    }
    let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(inner_l4).ok()?;
    Some((
        proto,
        ctx.load::<[u8; 16]>(INNER6_SRC).ok()?,
        ctx.load::<[u8; 16]>(INNER6_DST).ok()?,
        inner_l4,
        [s0, s1],
        [d0, d1],
    ))
}

/// Replace the address at `at` and the port at `port_at` (none when
/// `port_at` is 0) in an ICMPv6 message, with its checksum; `outer` when the
/// address is the outer header's (a pseudo-header word).
#[inline(always)]
fn set_icmp6(
    ctx: &TcContext,
    at: usize,
    port_at: usize,
    outer: bool,
    old: ([u8; 16], [u8; 2]),
    new: ([u8; 16], [u8; 2]),
) -> Option<()> {
    let flags = if outer { BPF_F_PSEUDO_HDR | 4 } else { 4 };
    let [o0, o1, o2, o3] = ip6_words(old.0);
    let [n0, n1, n2, n3] = ip6_words(new.0);
    for (o, n) in [(o0, n0), (o1, n1), (o2, n2), (o3, n3)] {
        ctx.l4_csum_replace(ICMP6_CHECK, u64::from(o), u64::from(n), flags)
            .ok()?;
    }
    ctx.store(at, &new.0, 0).ok()?;
    if port_at != 0 {
        ctx.l4_csum_replace(
            ICMP6_CHECK,
            u64::from(u16::from_ne_bytes(old.1)),
            u64::from(u16::from_ne_bytes(new.1)),
            2,
        )
        .ok()?;
        ctx.store(port_at, &new.1, 0).ok()?;
    }
    Some(())
}

/// [`icmp_error4_out`] for IPv6.
#[inline(always)]
fn icmp_error6_out(ctx: &TcContext) -> Option<()> {
    let (proto, client, backend, inner_l4, client_port, backend_port) = icmp6_error(ctx)?;
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
    if ctx.load::<[u8; 16]>(IP6_SRC).ok()? == backend {
        set_icmp6(ctx, IP6_SRC, 0, true, (backend, [0; 2]), (front.address, [0; 2]))?;
    }
    set_icmp6(
        ctx,
        INNER6_DST,
        inner_l4.checked_add(2)?,
        false,
        (backend, backend_port),
        (front.address, front.port),
    )
}

/// [`icmp_error4_in`] for IPv6.
#[inline(always)]
fn icmp_error6_in(ctx: &TcContext) -> Option<i32> {
    let (proto, front, client, inner_l4, front_port, client_port) = icmp6_error(ctx)?;
    if ctx.load::<[u8; 16]>(IP6_DST).ok()? != front {
        return None;
    }
    let key = Nodeport6Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let flow = unsafe { NODEPORT6.get(&key).copied() }?;
    if flow.flags & !(FLOW_DSR | FLOW_CLOSING) != 0 {
        return None;
    }
    let route = if flow.flags & FLOW_DSR != 0 {
        hops_ok(ctx)?;
        let src = ctx.load::<[u8; 16]>(IP6_SRC).ok()?;
        let (result, fib) = fib6(ctx, ICMP6, src, flow.address, 0)?;
        if !forwarded(result) {
            return None;
        }
        Some((result, fib))
    } else {
        None
    };
    set_icmp6(ctx, IP6_DST, 0, true, (front, [0; 2]), (flow.address, [0; 2]))?;
    set_icmp6(
        ctx,
        INNER6_SRC,
        inner_l4,
        false,
        (front, front_port),
        (flow.address, flow.port),
    )?;
    match route {
        Some((result, fib)) => redirect6(ctx, result, fib),
        None => Some(TC_ACT_OK),
    }
}

// BPF masquerade (#513), IPv6: the counterpart of the IPv4 one (#460). At
// the uplink's egress a local Pod's TCP, UDP or ICMPv6 echo packet to a
// destination outside the cluster ([`MASQ6_SOURCES`], [`MASQ6_EXCLUDE`])
// leaves from this node's IPv6 address on that uplink (the FIB's source) and
// a NAT port (an echo: identifier) claimed by [`claim_port6`] in
// [`NODEPORT6`]. At the ingress the reply, an echo reply and an ICMPv6 error
// about the flow (destination unreachable, packet too big, time exceeded,
// parameter problem) go back to the Pod through the host stack. Only TCP/UDP
// right after the fixed header: a packet with extension headers passes
// untouched. Each step is its own BPF function, called from the classifier.

#[map(name = "flowsdn_masq6_sources")]
static MASQ6_SOURCES: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(256, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_masq6_exclude")]
static MASQ6_EXCLUDE: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, BPF_F_NO_PREALLOC);
/// The ICMPv6 echo identifier's offset in the frame.
const ICMP6_ID: usize = 58;

/// Whether `src -> dst` is masqueraded.
#[inline(always)]
fn masqueraded6(src: [u8; 16], dst: [u8; 16]) -> bool {
    MASQ6_SOURCES.get(Key::new(128, src)).is_some()
        && MASQ6_EXCLUDE.get(Key::new(128, dst)).is_none()
}

/// At the uplink's egress: whether the frame is a Pod's packet leaving the
/// cluster. Its tuple goes into the [`INGRESS6`] slot (an echo request's
/// identifier as the source port, protocol [`ICMP6`]) with its known flow:
/// [`STEP_FORWARD`], [`STEP_NEW`] for [`masq_new6`], or [`STEP_PASS`].
#[inline(always)]
fn masq_classify6(ctx: &TcContext) -> Option<i32> {
    let state = INGRESS6.get_ptr_mut(0)?;
    let tuple = match tuple6(ctx) {
        Some(tuple) => tuple,
        None => {
            // An echo request: its identifier is the port.
            if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV6
                || ctx.load::<u8>(14).ok()? >> 4 != 6
                || ctx.load::<u8>(IP6_NEXT).ok()? != ICMP6
                || ctx.load::<u8>(IP6_SPORT).ok()? != 128
            {
                return None;
            }
            (
                ICMP6,
                ctx.load::<[u8; 16]>(IP6_SRC).ok()?,
                ctx.load::<[u8; 16]>(IP6_DST).ok()?,
                ctx.load::<[u8; 2]>(ICMP6_ID).ok()?,
                [0; 2],
            )
        }
    };
    let (proto, src, dst, sport, dport) = tuple;
    if !masqueraded6(src, dst) {
        return None;
    }
    let key = Nodeport6Key {
        a: src,
        b: dst,
        ap: sport,
        bp: dport,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let known = unsafe { NODEPORT6.get(&key).copied() }
        .filter(|f| f.flags & FLOW_MASQ != 0 && live6(ctx, &tuple, f));
    let step = if known.is_some() {
        STEP_FORWARD
    } else {
        STEP_NEW
    };
    let flow = known.unwrap_or(Nodeport6Value {
        address: [0; 16],
        port: [0; 2],
        flags: 0,
        pad: 0,
        other: [0; 16],
        other_port: [0; 2],
        pad2: [0; 2],
    });
    // SAFETY: this CPU's slot, valid for the whole invocation and used by
    // nothing else meanwhile (see fib6).
    unsafe { state.write(Ingress6 { tuple, flow }) };
    Some(step)
}

/// [`masq_flow4`] for IPv6, on the [`INGRESS6`] slot: claim the new flow's
/// NAT address and port, into the slot's flow.
#[inline(always)]
fn masq_new6_in(ctx: &TcContext, state: *mut Ingress6) -> Option<()> {
    // SAFETY: the slot masq_classify6 filled; read here, written below.
    let (proto, src, dst, sport, dport) = unsafe { (*state).tuple };
    let (result, fib) = fib6(ctx, proto, [0; 16], dst, BPF_FIB_LOOKUP_SRC)?;
    // SAFETY: the per-CPU slot fib6 just filled; plain field reads.
    let (ifindex, source) = unsafe { ((*fib).ifindex, (*fib).__bindgen_anon_3.ipv6_src) };
    // Only out of the uplink it leaves by, from that uplink's address.
    if !forwarded(result) || ifindex != uplink(ctx) {
        return None;
    }
    let nat = ip6_bytes(source);
    let fin = closes(ctx, IP6_SPORT, proto);
    let reply = Nodeport6Value {
        address: dst,
        port: dport,
        flags: FLOW_MASQ | if fin { FLOW_CLOSING } else { 0 },
        pad: 0,
        other: src,
        other_port: sport,
        pad2: now16().to_ne_bytes(),
    };
    let port = claim_port6((dst, dport), nat, proto, &reply)?;
    let key = Nodeport6Key {
        a: src,
        b: dst,
        ap: sport,
        bp: dport,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: as above; the flow is written in place.
    let flow = unsafe { &mut (*state).flow };
    flow.address = dst;
    flow.port = dport;
    flow.flags = FLOW_SNAT | FLOW_MASQ;
    flow.other = nat;
    flow.other_port = port;
    NODEPORT6.insert(&key, flow, 0).ok()?;
    Some(())
}

/// On the [`INGRESS6`] slot: the packet leaves from the flow's NAT address
/// and port (an echo: identifier).
#[inline(always)]
fn masquerade6_in(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<()> {
    let (proto, src, _, sport, _) = *tuple;
    let nat = (flow.other, flow.other_port);
    if proto == ICMP6 {
        return set_icmp6(ctx, IP6_SRC, ICMP6_ID, true, (src, sport), nat);
    }
    rewrite6(ctx, proto, IP6_SRC, IP6_SPORT, (src, sport), nat)
}

/// A masqueraded flow's reservation `server:server_port -> nat:nat_port`.
#[inline(always)]
fn masq_reservation6(
    server: ([u8; 16], [u8; 2]),
    nat: ([u8; 16], [u8; 2]),
    proto: u8,
) -> Option<Nodeport6Value> {
    let key = Nodeport6Key {
        a: server.0,
        b: nat.0,
        ap: server.1,
        bp: nat.1,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    unsafe { NODEPORT6.get(&key).copied() }.filter(|f| f.flags & FLOW_MASQ != 0)
}

/// At the uplink's ingress, on the [`INGRESS6`] slot: the reply of a
/// masqueraded TCP/UDP flow, to the Pod through the stack.
#[inline(always)]
fn masq_reply6_in(ctx: &TcContext, tuple: &Tuple6, flow: &Nodeport6Value) -> Option<i32> {
    let (proto, server, nat, server_port, nat_port) = *tuple;
    let key = Nodeport6Key {
        a: server,
        b: nat,
        ap: server_port,
        bp: nat_port,
        proto,
        direction: SNAT_REPLY,
        pad: [0; 2],
    };
    if let Some(value) = NODEPORT6.get_ptr_mut(&key) {
        // SAFETY: an LRU value of this map, written in place.
        unsafe {
            (*value).pad2 = now16().to_ne_bytes();
            if closes(ctx, IP6_SPORT, proto) {
                (*value).flags |= FLOW_CLOSING;
            }
        }
    }
    rewrite6(
        ctx,
        proto,
        IP6_DST,
        IP6_DPORT,
        (nat, nat_port),
        (flow.other, flow.other_port),
    )?;
    Some(TC_ACT_OK)
}

/// At the uplink's ingress: an echo reply to a masqueraded echo, or an
/// ICMPv6 error about a masqueraded TCP/UDP flow, to the Pod. For an error
/// the quote's source (address and port) is translated too.
#[inline(always)]
fn masq_icmp6_in(ctx: &TcContext) -> Option<i32> {
    if ctx.load::<[u8; 2]>(12).ok()? != ETH_P_IPV6
        || ctx.load::<u8>(14).ok()? >> 4 != 6
        || ctx.load::<u8>(IP6_NEXT).ok()? != ICMP6
    {
        return None;
    }
    let dst = ctx.load::<[u8; 16]>(IP6_DST).ok()?;
    if ctx.load::<u8>(IP6_SPORT).ok()? == 129 {
        let src = ctx.load::<[u8; 16]>(IP6_SRC).ok()?;
        let id = ctx.load::<[u8; 2]>(ICMP6_ID).ok()?;
        let flow = masq_reservation6((src, [0; 2]), (dst, id), ICMP6)?;
        set_icmp6(ctx, IP6_DST, ICMP6_ID, true, (dst, id), (flow.other, flow.other_port))?;
        return Some(TC_ACT_OK);
    }
    let (proto, nat, server, inner_l4, nat_port, server_port) = icmp6_error(ctx)?;
    if nat != dst {
        return None;
    }
    let flow = masq_reservation6((server, server_port), (nat, nat_port), proto)?;
    set_icmp6(ctx, IP6_DST, 0, true, (nat, [0; 2]), (flow.other, [0; 2]))?;
    set_icmp6(
        ctx,
        INNER6_SRC,
        inner_l4,
        false,
        (nat, nat_port),
        (flow.other, flow.other_port),
    )?;
    Some(TC_ACT_OK)
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
/// [`ingress4`]/[`egress4`]: not a NodePort packet, so the caller tries the
/// masquerade (#460) from its own frame (nested, the stacks exceed 512 bytes).
const NOT_NODEPORT: i32 = -2;
#[inline(never)]
fn ingress4(skb: *mut __sk_buff) -> i32 {
    nodeport4_in(&TcContext::new(skb)).unwrap_or(NOT_NODEPORT)
}
#[inline(never)]
fn egress4(skb: *mut __sk_buff) -> i32 {
    match nodeport4_out(&TcContext::new(skb)) {
        Some(()) => TC_ACT_OK,
        None => NOT_NODEPORT,
    }
}
#[inline(never)]
fn masq_out(skb: *mut __sk_buff) -> i32 {
    let _ = masquerade4(&TcContext::new(skb));
    TC_ACT_OK
}
/// [`icmp_error4_out`] on its own frame; [`NOT_NODEPORT`] when not ours.
#[inline(never)]
fn icmp_out4(skb: *mut __sk_buff) -> i32 {
    match icmp_error4_out(&TcContext::new(skb)) {
        Some(()) => TC_ACT_OK,
        None => NOT_NODEPORT,
    }
}
/// [`icmp_error4_in`] on its own frame; [`NOT_NODEPORT`] when not ours.
#[inline(never)]
fn icmp_in4(skb: *mut __sk_buff) -> i32 {
    icmp_error4_in(&TcContext::new(skb)).unwrap_or(NOT_NODEPORT)
}
#[inline(never)]
fn masq_icmp_in(skb: *mut __sk_buff) -> i32 {
    masq_icmp4_in(&TcContext::new(skb)).unwrap_or(TC_ACT_OK)
}
/// [`icmp_error6_out`] on its own frame; [`NOT_NODEPORT`] when not ours.
#[inline(never)]
fn icmp_out6(skb: *mut __sk_buff) -> i32 {
    match icmp_error6_out(&TcContext::new(skb)) {
        Some(()) => TC_ACT_OK,
        None => NOT_NODEPORT,
    }
}
/// [`icmp_error6_in`] on its own frame; [`NOT_NODEPORT`] when not ours.
#[inline(never)]
fn icmp_in6(skb: *mut __sk_buff) -> i32 {
    icmp_error6_in(&TcContext::new(skb)).unwrap_or(NOT_NODEPORT)
}
/// [`masq_classify6`] on its own frame.
#[inline(never)]
fn masq6(skb: *mut __sk_buff) -> i32 {
    masq_classify6(&TcContext::new(skb)).unwrap_or(STEP_PASS)
}
/// [`masq_new6_in`] on its own frame: 1 when the flow was claimed.
#[inline(never)]
fn masq_new6(skb: *mut __sk_buff) -> i32 {
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return 0;
    };
    i32::from(masq_new6_in(&TcContext::new(skb), state).is_some())
}
/// [`masquerade6_in`] on the [`INGRESS6`] slot, on its own frame.
#[inline(never)]
fn masq_out6(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    if let Some(state) = INGRESS6.get_ptr_mut(0) {
        // SAFETY: the slot masq6 (and masq_new6) filled; read only.
        let state = unsafe { &*state };
        let _ = masquerade6_in(&ctx, &state.tuple, &state.flow);
    }
    TC_ACT_OK
}
/// [`masq_icmp6_in`] on its own frame; anything else passes.
#[inline(never)]
fn masq_icmp_in6(skb: *mut __sk_buff) -> i32 {
    masq_icmp6_in(&TcContext::new(skb)).unwrap_or(TC_ACT_OK)
}
/// [`masq_reply6_in`] on the [`INGRESS6`] slot, on its own frame.
#[inline(never)]
fn masq_reply6(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return TC_ACT_OK;
    };
    // SAFETY: the slot ingress6 filled in this invocation; read only.
    let state = unsafe { &*state };
    masq_reply6_in(&ctx, &state.tuple, &state.flow).unwrap_or(TC_ACT_OK)
}
#[inline(never)]
fn egress6(skb: *mut __sk_buff) -> i32 {
    match nodeport6_out(&TcContext::new(skb)) {
        Some(()) => TC_ACT_OK,
        None => NOT_NODEPORT,
    }
}
/// At the uplink's egress, a local Pod's IPv6 TCP/UDP packet to the RFC 6052
/// prefix (#454): the frame's tuple and known flow in the [`INGRESS6`] slot
/// and [`STEP_XLATE_FORWARD`], or [`STEP_NEW`] for [`gateway64_new`] to make
/// the flow; the caller translates it ([`to_v4`]). Each runs from the
/// caller's frame: together their stacks exceed 512 bytes. Anything else is
/// [`STEP_PASS`].
#[inline(never)]
fn gateway64(skb: *mut __sk_buff) -> i32 {
    gateway64_classify(&TcContext::new(skb)).unwrap_or(STEP_PASS)
}
#[inline(always)]
fn gateway64_classify(ctx: &TcContext) -> Option<i32> {
    // SAFETY: NO_PREALLOC hash; the value is copied at once.
    let config = unsafe { GW64_CONFIG.get(&0).copied() }?;
    if config.enabled == 0 {
        return None;
    }
    let tuple = tuple6(ctx)?;
    let (proto, client, front, client_port, front_port) = tuple;
    let [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, _, _, _, _] = front;
    if [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11] != config.prefix
        || GW64_SOURCES.get(Key::new(128, client)).is_none()
    {
        return None;
    }
    let state = INGRESS6.get_ptr_mut(0)?;
    let key = Nodeport6Key {
        a: client,
        b: front,
        ap: client_port,
        bp: front_port,
        proto,
        direction: FORWARD,
        pad: [0; 2],
    };
    // SAFETY: LRU value copied at once, never written through.
    let known = unsafe { NODEPORT6.get(&key).copied() }.filter(|f| f.flags & FLOW_XLATE != 0);
    let (step, flow) = match known {
        Some(flow) => (STEP_XLATE_FORWARD, flow),
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
    };
    // SAFETY: this CPU's slot, valid for the whole invocation and used by
    // nothing else meanwhile (see fib6).
    unsafe { state.write(Ingress6 { tuple, flow }) };
    Some(step)
}
/// A new gateway flow for the [`INGRESS6`] slot's frame (#454): a NAT port
/// on this node's IPv4 address toward the server the prefix embeds, claimed
/// and recorded as a Service NAT64 flow's. 1 when made.
#[inline(never)]
fn gateway64_new(skb: *mut __sk_buff) -> i32 {
    let ctx = TcContext::new(skb);
    let Some(state) = INGRESS6.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: the slot gateway64 filled in this invocation; nothing else
    // refers to it while this function runs.
    let state = unsafe { &mut *state };
    match gateway64_new_in(&ctx, &state.tuple, &mut state.flow) {
        Some(()) => 1,
        None => 0,
    }
}
#[inline(always)]
fn gateway64_new_in(ctx: &TcContext, tuple: &Tuple6, flow: &mut Nodeport6Value) -> Option<()> {
    let (proto, client, front, client_port, front_port) = *tuple;
    let [_, _, _, _, _, _, _, _, _, _, _, _, a, b, c, d] = front;
    // The IPv4 server the prefix embeds, on the same port.
    let server = ([a, b, c, d], front_port);
    let (result, fib) = fib4(ctx, proto, [0; 4], server.0, BPF_FIB_LOOKUP_SRC);
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
    let nat_port = claim_port(server, nat, proto, &reservation)?;
    let reply_key = Nodeport4Key {
        a: server.0,
        b: nat,
        ap: server.1,
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
    flow.address = mapped6(server.0);
    flow.port = server.1;
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

/// TCX's "run the next program on this hook" (`TCX_NEXT`). TCX ends the
/// chain on any other verdict, `TC_ACT_OK` (`TCX_PASS`) included, and the host
/// firewall (`from_netdev`/`to_netdev`, #379) is attached after these
/// programs: a pass here must hand the packet on to it (finding
/// 9353481628e3, #484). Redirects and drops stay final.
const TCX_NEXT: i32 = -1;
#[inline(always)]
fn next(verdict: i32) -> i32 {
    if verdict == TC_ACT_OK {
        TCX_NEXT
    } else {
        verdict
    }
}

#[classifier]
pub fn nodeport_ingress(ctx: TcContext) -> i32 {
    next(ingress(&ctx))
}
#[inline(always)]
fn ingress(ctx: &TcContext) -> i32 {
    let skb = ctx.skb.skb;
    match ctx.load::<[u8; 2]>(12) {
        Ok(ETH_P_IPV6) => match ingress6(skb) {
            STEP_REPLY => snat_reply6(skb),
            STEP_NEW => match new_flow6(skb) {
                0 => TC_ACT_OK,
                NEW_NAT64 if new_flow64(skb) != 0 => to_v4(skb, false),
                NEW_NAT64 => TC_ACT_OK,
                _ => match nodeport_forward6(skb) {
                    STALE6 => TC_ACT_OK,
                    verdict => verdict,
                },
            },
            STEP_FORWARD => match nodeport_forward6(skb) {
                STALE6 => match new_flow6(skb) {
                    0 | NEW_NAT64 => TC_ACT_OK,
                    _ => match nodeport_forward6(skb) {
                        STALE6 => TC_ACT_OK,
                        verdict => verdict,
                    },
                },
                verdict => verdict,
            },
            STEP_XLATE_REPLY => to_v4(skb, true),
            STEP_XLATE_FORWARD => to_v4(skb, false),
            STEP_DSR => match dsr6(skb) {
                DSR_REJECT => TC_ACT_SHOT,
                _ => TC_ACT_OK,
            },
            STEP_PASS => match icmp_in6(skb) {
                NOT_NODEPORT => masq_icmp_in6(skb),
                verdict => verdict,
            },
            STEP_MASQ_REPLY => masq_reply6(skb),
            _ => TC_ACT_OK,
        },
        _ => match xlate4(skb) {
            STEP_XLATE_REPLY => to_v6(skb, true),
            STEP_NEW if new_flow46(skb) != 0 => to_v6(skb, false),
            STEP_NEW => TC_ACT_OK,
            STEP_FORWARD => to_v6(skb, false),
            _ => match dsr4(skb) {
                DSR_NONE => match ingress4(skb) {
                    NOT_NODEPORT => match icmp_in4(skb) {
                        NOT_NODEPORT => masq_icmp_in(skb),
                        verdict => verdict,
                    },
                    verdict => verdict,
                },
                DSR_ACCEPT => TC_ACT_OK,
                _ => TC_ACT_SHOT,
            },
        },
    }
}
#[classifier]
pub fn nodeport_egress(ctx: TcContext) -> i32 {
    next(match ctx.load::<[u8; 2]>(12) {
        Ok(ETH_P_IPV6) => match egress6(ctx.skb.skb) {
            NOT_NODEPORT => match icmp_out6(ctx.skb.skb) {
                NOT_NODEPORT => match gateway64(ctx.skb.skb) {
                    STEP_XLATE_FORWARD => to_v4(ctx.skb.skb, false),
                    STEP_NEW if gateway64_new(ctx.skb.skb) != 0 => to_v4(ctx.skb.skb, false),
                    STEP_NEW => TC_ACT_OK,
                    _ => match masq6(ctx.skb.skb) {
                        STEP_FORWARD => masq_out6(ctx.skb.skb),
                        STEP_NEW if masq_new6(ctx.skb.skb) != 0 => masq_out6(ctx.skb.skb),
                        _ => TC_ACT_OK,
                    },
                },
                verdict => verdict,
            },
            verdict => verdict,
        },
        _ => match egress4(ctx.skb.skb) {
            NOT_NODEPORT => match icmp_out4(ctx.skb.skb) {
                NOT_NODEPORT => masq_out(ctx.skb.skb),
                verdict => verdict,
            },
            verdict => verdict,
        },
    })
}

// SAFETY: unique immutable ELF license declaration, required by the loader.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
