//! Ethernet local delivery from specification 02 §3.9 and §5.5.
//! This primitive assumes its caller has performed identity and policy checks.
use aya_ebpf::{bindings::TC_ACT_SHOT, helpers::bpf_redirect, programs::TcContext};
use flowsdn_bpf_abi::endpoint::{EndpointInfo, EndpointKey};

/// Validate the fixed IP header and return its local-cluster destination key.
/// VLAN, non-IP frames and IPv6 jumbograms are not supported by this primitive.
#[inline(always)]
pub fn destination(ctx: &TcContext) -> Option<EndpointKey> {
    match ctx.load::<[u8; 2]>(12).ok()? {
        [0x08, 0x00] => {
            let version_ihl = ctx.load::<u8>(14).ok()?;
            if version_ihl >> 4 != 4 || version_ihl & 15 < 5 {
                return None;
            }
            let header_len = u32::from(version_ihl & 15).checked_mul(4)?;
            let total = u32::from(u16::from_be_bytes(ctx.load::<[u8; 2]>(16).ok()?));
            if total < header_len || total.checked_add(14)? > ctx.len() {
                return None;
            }
            Some(EndpointKey::v4(ctx.load::<[u8; 4]>(30).ok()?, 0, 0))
        }
        [0x86, 0xdd] => {
            if ctx.load::<u8>(14).ok()? >> 4 != 6 {
                return None;
            }
            let payload = u32::from(u16::from_be_bytes(ctx.load::<[u8; 2]>(18).ok()?));
            if payload == 0 || payload.checked_add(54)? > ctx.len() {
                return None;
            }
            Some(EndpointKey::v6(ctx.load::<[u8; 16]>(38).ok()?, 0, 0))
        }
        _ => None,
    }
}

#[inline(always)]
fn mac(value: u64) -> [u8; 6] {
    let [a, b, c, d, e, f, _, _] = value.to_le_bytes();
    [a, b, c, d, e, f]
}

/// Rewrite L2 addresses, reduce hop count and redirect to an endpoint veth.
/// Unsupported endpoint flags and expired hop counts fail closed. ICMP error
/// generation and redirect_peer selection belong to the eventual caller.
#[inline(always)]
pub fn deliver(ctx: &TcContext, ep: EndpointInfo) -> i32 {
    if ep.ifindex == 0 || ep.flags != 0 || rewrite(ctx, ep).is_none() {
        return TC_ACT_SHOT;
    }
    // SAFETY: scalar ifindex was checked; flags=0 selects egress. The helper
    // validates the interface, and takes no pointer or borrowed map storage.
    unsafe { bpf_redirect(ep.ifindex, 0) as i32 }
}

#[inline(always)]
fn rewrite(ctx: &TcContext, ep: EndpointInfo) -> Option<()> {
    match ctx.load::<[u8; 2]>(12).ok()? {
        [0x08, 0x00] => {
            let [ttl, protocol] = ctx.load::<[u8; 2]>(22).ok()?;
            if ttl <= 1 { return None; }
            let next = ttl.checked_sub(1)?;
            let old_word = u16::from_ne_bytes([ttl, protocol]);
            let new_word = u16::from_ne_bytes([next, protocol]);
            ctx.l3_csum_replace(24, u64::from(old_word), u64::from(new_word), 2).ok()?;
            ctx.store(22, &next, 0).ok()?;
        }
        [0x86, 0xdd] => {
            let hop = ctx.load::<u8>(21).ok()?;
            if hop <= 1 { return None; }
            ctx.store(21, &hop.checked_sub(1)?, 0).ok()?;
        }
        _ => return None,
    }
    ctx.store(0, &mac(ep.mac), 0).ok()?;
    ctx.store(6, &mac(ep.node_mac), 0).ok()?;
    Some(())
}
