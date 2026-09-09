//! Native Ethernet forwarding from specification 02 §3.8 and §5.5.
//! This initial path requires forwarding and an already resolved neighbour.
//! The caller validates the IP destination and performs policy checks.

use aya_ebpf::{
    EbpfContext,
    bindings::{TC_ACT_SHOT, bpf_fib_lookup},
    helpers::bpf_fib_lookup as fib_lookup,
    programs::TcContext,
};
use flowsdn_bpf_abi::endpoint::EndpointInfo;

/// Route a validated Ethernet IP packet using the ingress device's FIB.
/// Unresolved neighbours, unsupported protocols, fragments, IPv6 extension
/// headers and every unsuccessful FIB result fail closed. No NAT is applied.
#[inline(always)]
pub fn route(ctx: &TcContext) -> i32 {
    let Some(mut fib) = parameters(ctx) else {
        return TC_ACT_SHOT;
    };
    // SAFETY: the TC context is supplied by the kernel. `fib` is a fully
    // initialized, correctly aligned stack value of the exact helper ABI type;
    // the helper receives its real size and cannot retain its pointer. Flags=0
    // selects the ordinary ingress FIB lookup including neighbour resolution.
    let result = unsafe {
        fib_lookup(
            ctx.as_ptr(),
            core::ptr::from_mut(&mut fib),
            core::mem::size_of::<bpf_fib_lookup>() as i32,
            0,
        )
    };
    // BPF_FIB_LKUP_RET_SUCCESS is zero. In particular, NO_NEIGH does not
    // supply usable MAC addresses and cannot use this redirect fallback.
    if result != 0 {
        return TC_ACT_SHOT;
    }
    crate::local_delivery::deliver(
        ctx,
        EndpointInfo {
            ifindex: fib.ifindex,
            mac: mac_value(fib.dmac),
            node_mac: mac_value(fib.smac),
            flags: 0,
            ..EndpointInfo::default()
        },
    )
}

#[inline(always)]
fn parameters(ctx: &TcContext) -> Option<bpf_fib_lookup> {
    // SAFETY: the generated C struct contains only integers, integer arrays
    // and unions of those types. Every all-zero field representation is valid.
    // Initialize inactive union bytes too before passing the stack to a helper.
    let mut fib: bpf_fib_lookup = unsafe { core::mem::zeroed() };
    // SAFETY: a kernel-created TC context points at a live __sk_buff for the
    // duration of this program; ifindex is an allowed scalar context access.
    fib.ifindex = unsafe { (*ctx.skb.skb).ifindex };
    if fib.ifindex == 0 {
        return None;
    }
    let (transport, end) = match ctx.load::<[u8; 2]>(12).ok()? {
        [0x08, 0x00] => {
            fib.family = 2; // AF_INET
            fib.l4_protocol = ctx.load::<u8>(23).ok()?;
            if !matches!(fib.l4_protocol, 1 | 6 | 17) {
                return None;
            }
            let fragment = u16::from_be_bytes(ctx.load::<[u8; 2]>(20).ok()?);
            if fragment & 0x3fff != 0 {
                return None;
            }
            let total = u16::from_be_bytes(ctx.load::<[u8; 2]>(16).ok()?);
            fib.__bindgen_anon_1.tot_len = total;
            fib.__bindgen_anon_2.tos = ctx.load::<u8>(15).ok()?;
            // Direct native integer loads preserve the network-order bytes
            // expected by the kernel's __be32 fields on either architecture.
            fib.__bindgen_anon_3.ipv4_src = ctx.load::<u32>(26).ok()?;
            fib.__bindgen_anon_4.ipv4_dst = ctx.load::<u32>(30).ok()?;
            let ihl = ctx.load::<u8>(14).ok()? & 15;
            let transport = usize::from(ihl).checked_mul(4)?.checked_add(14)?;
            (transport, usize::from(total).checked_add(14)?)
        }
        [0x86, 0xdd] => {
            fib.family = 10; // AF_INET6
            fib.l4_protocol = ctx.load::<u8>(20).ok()?;
            if !matches!(fib.l4_protocol, 6 | 17 | 58) {
                return None;
            }
            let payload = u16::from_be_bytes(ctx.load::<[u8; 2]>(18).ok()?);
            fib.__bindgen_anon_1.tot_len = payload.checked_add(40)?;
            let flow = u32::from_be_bytes(ctx.load::<[u8; 4]>(14).ok()?);
            fib.__bindgen_anon_2.flowinfo = (flow & 0x0fff_ffff).to_be();
            fib.__bindgen_anon_3.ipv6_src = ctx.load::<[u32; 4]>(22).ok()?;
            fib.__bindgen_anon_4.ipv6_dst = ctx.load::<[u32; 4]>(38).ok()?;
            (54, usize::from(payload).checked_add(54)?)
        }
        _ => return None,
    };
    if matches!(fib.l4_protocol, 6 | 17) {
        // Read ports only within the declared IP length, never Ethernet padding.
        if transport.checked_add(4)? > end {
            return None;
        }
        fib.sport = ctx.load::<u16>(transport).ok()?;
        fib.dport = ctx.load::<u16>(transport.checked_add(2)?).ok()?;
    }
    Some(fib)
}

#[inline(always)]
fn mac_value(bytes: [u8; 6]) -> u64 {
    let [a, b, c, d, e, f] = bytes;
    u64::from_le_bytes([a, b, c, d, e, f, 0, 0])
}
