//! Endpoint network policy (spec 06 §3.8, spec 02 §3.10/§3.11; ADR-0021).
//! `local_delivery` (host veth ingress) enforces the endpoint's egress,
//! `to_container` (host veth egress) its ingress. The endpoint is the
//! interface the program runs on, looked up in `flowsdn_policy_ep`; an
//! interface without an entry is neither enforced nor tracked. The remote
//! identity comes from `flowsdn_ipcache` (a miss is world). Allowed flows are
//! remembered in `flowsdn_policy_ct`, keyed by the flow and the direction it
//! was allowed in, so a reply in the other direction passes without a policy
//! lookup. Not implemented: authentication (an entry that requires it
//! drops), proxy redirects, audit mode, verdict events, ICMP error
//! classification as related, and fragments other than the first (dropped
//! where enforced).
use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{HashMap, LpmTrie, LruHashMap, lpm_trie::Key},
    programs::TcContext,
};
use flowsdn_bpf_abi::{
    Be16, FAMILY_V4, FAMILY_V6, RemoteEndpointInfo,
    policy::{
        ENDPOINT_POLICY_FULL_PREFIX, POLICY_CT_CLOSING, PolicyCtKey, PolicyCtValue,
        PolicyEndpoint, PolicyEntry, enforce,
    },
};

#[map(name = "flowsdn_policy_ep")]
static POLICY_EP: HashMap<u32, PolicyEndpoint> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// The endpoint policy key after its LPM prefix length (`EndpointPolicyKey`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyData {
    endpoint: u32,
    sec_label: u32,
    egress: u8,
    protocol: u8,
    dport: [u8; 2],
}
#[map(name = "flowsdn_policy")]
static POLICY: LpmTrie<PolicyData, PolicyEntry> = LpmTrie::with_max_entries(65536, 0);

/// The ipcache key after its LPM prefix length (`IpCacheKey`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpcacheData {
    cluster_id: u16,
    pad: u8,
    family: u8,
    address: [u8; 16],
}
#[map(name = "flowsdn_ipcache")]
static IPCACHE: LpmTrie<IpcacheData, RemoteEndpointInfo> = LpmTrie::with_max_entries(65536, 0);

#[map(name = "flowsdn_policy_ct")]
static POLICY_CT: LruHashMap<PolicyCtKey, PolicyCtValue> = LruHashMap::with_max_entries(65536, 0);

/// This cluster's ID (0 without cluster mesh) for the aggregate identity.
// SAFETY: unique immutable symbol in the loader configuration datasec.
#[unsafe(link_section = ".rodata.config")]
#[unsafe(no_mangle)]
static __config_cluster_id: u32 = 0;

const HOST: u32 = 1;
const WORLD: u32 = 2;
const AGGREGATE_CLUSTER: u32 = 11;
const AGGREGATE_CLUSTER_MESH: u32 = 12;
const AGGREGATE_WORLD: u32 = 13;
const AGGREGATE_REMOTE_NODE: u32 = 14;
const MAX_PRECEDENCE: u32 = u32::MAX;

const TCP: u8 = 6;
const UDP: u8 = 17;
const SCTP: u8 = 132;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;
const TCP_FIN: u8 = 1;
const TCP_RST: u8 = 4;
/// Seconds a flow lives without traffic: TCP until closed, anything else,
/// and TCP after a FIN or RST.
const LIFETIME_TCP: u64 = 21600;
const LIFETIME_OTHER: u64 = 60;
const LIFETIME_CLOSING: u64 = 10;
/// An entry's expiry is rewritten only when it moves by more than this.
const REFRESH_SLACK: u64 = 5;

/// A parsed IP packet as the policy sees it.
pub struct Flow {
    key: PolicyCtKey,
    /// The policy key's port: the L4 destination port, 0 for other protocols.
    port: [u8; 2],
    tcp_flags: u8,
    /// A fragment other than the first: no L4 header.
    fragment: bool,
}

enum Parsed {
    /// Not IP, or traffic the network needs whatever the policy says
    /// (neighbour discovery, fragmentation-needed/packet-too-big).
    Pass,
    Malformed,
    Flow,
}

#[inline(always)]
fn now() -> u64 {
    // SAFETY: no arguments; returns the monotonic clock.
    let nanoseconds = unsafe { bpf_ktime_get_ns() };
    nanoseconds / 1_000_000_000
}

/// The ifindex the program runs on: the endpoint's host-side veth.
#[inline(always)]
fn ifindex(ctx: &TcContext) -> u32 {
    // SAFETY: a kernel-created TC context points at a live __sk_buff for the
    // duration of this program; ifindex is an allowed scalar context access.
    unsafe { (*ctx.skb.skb).ifindex }
}

#[inline(always)]
fn parse(ctx: &TcContext, flow: &mut Flow) -> Option<Parsed> {
    match ctx.load::<[u8; 2]>(12).ok()? {
        [0x08, 0x00] => parse4(ctx, flow),
        [0x86, 0xdd] => parse6(ctx, flow),
        _ => Some(Parsed::Pass),
    }
}

#[inline(always)]
fn parse4(ctx: &TcContext, flow: &mut Flow) -> Option<Parsed> {
    let version_ihl = ctx.load::<u8>(14).ok()?;
    if version_ihl >> 4 != 4 || version_ihl & 15 < 5 {
        return Some(Parsed::Malformed);
    }
    flow.key.family = FAMILY_V4;
    flow.key.protocol = ctx.load::<u8>(23).ok()?;
    let [a, b, c, d] = ctx.load::<[u8; 4]>(26).ok()?;
    flow.key.saddr = [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let [a, b, c, d] = ctx.load::<[u8; 4]>(30).ok()?;
    flow.key.daddr = [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?) & 0x1fff != 0 {
        flow.fragment = true;
        return Some(Parsed::Flow);
    }
    let l4 = usize::from(version_ihl & 15)
        .checked_mul(4)?
        .checked_add(14)?;
    if flow.key.protocol == ICMP {
        let [kind, code] = ctx.load::<[u8; 2]>(l4).ok()?;
        // Fragmentation needed: path MTU discovery must always work.
        if kind == 3 && code == 4 {
            return Some(Parsed::Pass);
        }
        return icmp_echo(ctx, flow, l4, kind, 8, 0);
    }
    l4_ports(ctx, flow, l4)
}

#[inline(always)]
fn parse6(ctx: &TcContext, flow: &mut Flow) -> Option<Parsed> {
    if ctx.load::<u8>(14).ok()? >> 4 != 6 {
        return Some(Parsed::Malformed);
    }
    flow.key.family = FAMILY_V6;
    flow.key.protocol = ctx.load::<u8>(20).ok()?;
    flow.key.saddr = ctx.load::<[u8; 16]>(22).ok()?;
    flow.key.daddr = ctx.load::<[u8; 16]>(38).ok()?;
    const L4: usize = 54;
    match flow.key.protocol {
        ICMPV6 => {
            let kind = ctx.load::<u8>(L4).ok()?;
            // Packet too big (2) and neighbour/router discovery (133-137).
            if kind == 2 || (133..=137).contains(&kind) {
                return Some(Parsed::Pass);
            }
            icmp_echo(ctx, flow, L4, kind, 128, 129)
        }
        // A fragment header: the first fragment's ports are not parsed either.
        44 => {
            flow.fragment = true;
            Some(Parsed::Flow)
        }
        // Other extension headers are not walked: protocol is the next header, port 0.
        _ => l4_ports(ctx, flow, L4),
    }
}

/// ICMP: the echo identifier keeps request and reply in one flow; the
/// policy port is 0 (spec 06 ICMP type rules are not enabled).
#[inline(always)]
fn icmp_echo(
    ctx: &TcContext,
    flow: &mut Flow,
    l4: usize,
    kind: u8,
    request: u8,
    reply: u8,
) -> Option<Parsed> {
    if kind == request || kind == reply {
        let id = ctx.load::<[u8; 2]>(l4.checked_add(4)?).ok()?;
        if kind == request {
            flow.key.sport = Be16(id);
        } else {
            flow.key.dport = Be16(id);
        }
    }
    Some(Parsed::Flow)
}

#[inline(always)]
fn l4_ports(ctx: &TcContext, flow: &mut Flow, l4: usize) -> Option<Parsed> {
    if matches!(flow.key.protocol, TCP | UDP | SCTP) {
        let [s0, s1, d0, d1] = ctx.load::<[u8; 4]>(l4).ok()?;
        flow.key.sport = Be16([s0, s1]);
        flow.key.dport = Be16([d0, d1]);
        flow.port = [d0, d1];
        if flow.key.protocol == TCP {
            flow.tcp_flags = ctx.load::<u8>(l4.checked_add(13)?).ok()?;
        }
    }
    Some(Parsed::Flow)
}

/// The remote's security identity; an address the ipcache lacks is world.
#[inline(always)]
fn identity(family: u8, address: [u8; 16]) -> u32 {
    let bits = if family == FAMILY_V4 { 64 } else { 160 };
    let key = Key::new(
        bits,
        IpcacheData {
            cluster_id: 0,
            pad: 0,
            family,
            address,
        },
    );
    IPCACHE.get(key).map_or(WORLD, |info| info.sec_identity)
}

/// spec 03 `aggregate_for` with the default cluster encoding (255 clusters,
/// cluster ID in bits 16-23 of a global identity).
#[inline(always)]
fn aggregate(identity: u32) -> u32 {
    match identity {
        0 | AGGREGATE_CLUSTER..=AGGREGATE_REMOTE_NODE => identity,
        _ => match identity >> 24 {
            1 => AGGREGATE_WORLD,
            2 => AGGREGATE_REMOTE_NODE,
            _ if identity < 100 => 0,
            // SAFETY: valid immutable global; volatile so the loader's value is read.
            _ if (identity >> 16) & 0xff
                == unsafe { core::ptr::read_volatile(&raw const __config_cluster_id) } =>
            {
                AGGREGATE_CLUSTER
            }
            _ => AGGREGATE_CLUSTER_MESH,
        },
    }
}

/// One policy lookup: `found` and the entry (zeroed on a miss). Not an
/// `Option`: LLVM spills a `None`'s undefined fields, and the verifier
/// refuses to read an uninitialized register ("R4 !read_ok" on 7.2).
#[derive(Clone, Copy)]
struct Hit {
    found: bool,
    entry: PolicyEntry,
}

#[inline(always)]
fn entry(endpoint: u32, identity: u32, egress: u8, flow: &Flow) -> Hit {
    let key = Key::new(
        ENDPOINT_POLICY_FULL_PREFIX,
        PolicyData {
            endpoint,
            sec_label: identity,
            egress,
            protocol: flow.key.protocol,
            dport: flow.port,
        },
    );
    match POLICY.get(key) {
        Some(found) => Hit {
            found: true,
            entry: *found,
        },
        None => Hit {
            found: false,
            entry: PolicyEntry::default(),
        },
    }
}

/// spec 02 §3.10: the specific entry, the aggregate's, then the wildcard
/// identity; the winner by precedence, then L4 prefix length.
#[inline(always)]
fn allowed(endpoint: u32, remote: u32, egress: u8, flow: &Flow) -> bool {
    let specific = entry(endpoint, remote, egress, flow);
    if specific.found && specific.entry.precedence == MAX_PRECEDENCE {
        return !specific.entry.denies();
    }
    let group = aggregate(remote);
    let mut broader = Hit {
        found: false,
        entry: PolicyEntry::default(),
    };
    if group != remote {
        broader = entry(endpoint, group, egress, flow);
    }
    if !broader.found && !specific.found && group != 0 {
        broader = entry(endpoint, 0, egress, flow);
    }
    if !specific.found && !broader.found {
        return false;
    }
    let (chosen, other) = if !specific.found
        || (broader.found
            && (broader.entry.precedence > specific.entry.precedence
                || (broader.entry.precedence == specific.entry.precedence
                    && broader.entry.lpm_prefix_length() > specific.entry.lpm_prefix_length())))
    {
        (broader.entry, specific)
    } else {
        (specific.entry, broader)
    };
    if chosen.denies() {
        return false;
    }
    let mut auth = chosen.auth_type();
    if other.found
        && other.entry.precedence == chosen.precedence
        && !chosen.has_explicit_auth_type()
        && other.entry.auth_type() > auth
    {
        auth = other.entry.auth_type();
    }
    // No authentication map: an entry that requires it is not satisfied.
    auth == 0
}

#[inline(always)]
fn lifetime(flow: &Flow) -> u64 {
    if flow.key.protocol != TCP {
        LIFETIME_OTHER
    } else if flow.tcp_flags & (TCP_FIN | TCP_RST) != 0 {
        LIFETIME_CLOSING
    } else {
        LIFETIME_TCP
    }
}

/// A live entry for `key`: refresh it and say so.
#[inline(always)]
fn tracked(key: &PolicyCtKey, flow: &Flow, now: u64) -> bool {
    let Some(value) = POLICY_CT.get_ptr_mut(key) else {
        return false;
    };
    // SAFETY: an LRU value pointer is valid for this program run; the fields
    // are plain integers, and concurrent writers only move the expiry.
    unsafe {
        let expires = (*value).expires;
        if expires < now {
            return false;
        }
        let closing = flow.tcp_flags & (TCP_FIN | TCP_RST) != 0;
        if closing {
            (*value).flags |= POLICY_CT_CLOSING;
        }
        let life = if (*value).flags & POLICY_CT_CLOSING != 0 {
            LIFETIME_CLOSING
        } else {
            lifetime(flow)
        };
        let next = now.saturating_add(life);
        if closing || next > expires.saturating_add(REFRESH_SLACK) {
            (*value).expires = next;
        }
    }
    true
}

/// Enforce the endpoint behind this interface for one packet in `egress`
/// (1: leaving the endpoint) or ingress (0). TC_ACT_OK lets it continue.
#[inline(always)]
pub fn enforce(ctx: &TcContext, egress: u8) -> i32 {
    // SAFETY: NO_PREALLOC hash; the value is copied at once.
    let Some(endpoint) = (unsafe { POLICY_EP.get(ifindex(ctx)).copied() }) else {
        return TC_ACT_OK;
    };
    let mut flow = Flow {
        key: PolicyCtKey::default(),
        port: [0, 0],
        tcp_flags: 0,
        fragment: false,
    };
    let enforced = endpoint.flags
        & if egress != 0 {
            enforce::EGRESS
        } else {
            enforce::INGRESS
        }
        != 0;
    match parse(ctx, &mut flow) {
        Some(Parsed::Pass) => return TC_ACT_OK,
        Some(Parsed::Flow) => {}
        Some(Parsed::Malformed) | None => {
            return if enforced { TC_ACT_SHOT } else { TC_ACT_OK };
        }
    }
    if flow.fragment {
        return if enforced { TC_ACT_SHOT } else { TC_ACT_OK };
    }
    let now = now();
    flow.key.egress = egress;
    if tracked(&flow.key, &flow, now) {
        return TC_ACT_OK;
    }
    let mut reply = flow.key;
    reply.saddr = flow.key.daddr;
    reply.daddr = flow.key.saddr;
    reply.sport = flow.key.dport;
    reply.dport = flow.key.sport;
    reply.egress = egress ^ 1;
    if tracked(&reply, &flow, now) {
        return TC_ACT_OK;
    }
    if enforced {
        let remote = if egress != 0 {
            identity(flow.key.family, flow.key.daddr)
        } else {
            identity(flow.key.family, flow.key.saddr)
        };
        // The node itself (kubelet probes) always reaches its pods.
        if !(egress == 0 && remote == HOST) && !allowed(endpoint.endpoint, remote, egress, &flow) {
            return TC_ACT_SHOT;
        }
    }
    let value = PolicyCtValue {
        expires: now.saturating_add(lifetime(&flow)),
        flags: 0,
        pad: 0,
    };
    // A full table or a racing insert only costs a policy lookup later.
    let _ = POLICY_CT.insert(&flow.key, &value, 0);
    TC_ACT_OK
}
