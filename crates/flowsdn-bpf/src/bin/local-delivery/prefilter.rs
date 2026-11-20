//! The XDP prefilter (#467; the reference's `enable-xdp-prefilter`): frames
//! on an uplink whose IPv4 or IPv6 source is in the deny list are dropped
//! at XDP, before the stack sees them. Host prefixes (/32, /128) are in the
//! `_fix` hash maps, every other prefix in the `_dyn` LPM tries; the agent
//! writes both (`/v1/prefilter`). Anything else (ARP, VLAN-tagged, short or
//! non-IP frames) passes.
use aya_ebpf::{
    bindings::{BPF_F_NO_PREALLOC, xdp_action},
    macros::map,
    maps::{HashMap, LpmTrie, lpm_trie::Key},
    programs::XdpContext,
};

#[map(name = "flowsdn_cidr_v4_fix")]
static CIDR_V4_FIX: HashMap<[u8; 4], u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_cidr_v4_dyn")]
static CIDR_V4_DYN: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_cidr_v6_fix")]
static CIDR_V6_FIX: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);
#[map(name = "flowsdn_cidr_v6_dyn")]
static CIDR_V6_DYN: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(1024, BPF_F_NO_PREALLOC);

const ETH_HLEN: usize = 14;
const ETH_P_IP: [u8; 2] = [0x08, 0x00];
const ETH_P_IPV6: [u8; 2] = [0x86, 0xdd];
/// The source address's offset in an IPv4 and an IPv6 header.
const IP4_SRC: usize = 12;
const IP6_SRC: usize = 8;

/// `N` bytes at `offset` of the frame, bounds-checked for the verifier.
#[inline(always)]
fn bytes<const N: usize>(ctx: &XdpContext, offset: usize) -> Option<[u8; N]> {
    let start = ctx.data();
    let at = start.checked_add(offset)?;
    if at.checked_add(N)? > ctx.data_end() {
        return None;
    }
    // SAFETY: [at, at + N) is inside the packet, checked just above.
    Some(unsafe { core::ptr::read_unaligned(at as *const [u8; N]) })
}

#[inline(always)]
fn denied(ctx: &XdpContext) -> Option<bool> {
    let kind = bytes::<2>(ctx, 12)?;
    if kind == ETH_P_IP {
        let source = bytes::<4>(ctx, ETH_HLEN.checked_add(IP4_SRC)?)?;
        // SAFETY: NO_PREALLOC hash; only presence is read.
        if unsafe { CIDR_V4_FIX.get(&source) }.is_some() {
            return Some(true);
        }
        return Some(CIDR_V4_DYN.get(&Key::new(32, source)).is_some());
    }
    if kind == ETH_P_IPV6 {
        let source = bytes::<16>(ctx, ETH_HLEN.checked_add(IP6_SRC)?)?;
        // SAFETY: as above.
        if unsafe { CIDR_V6_FIX.get(&source) }.is_some() {
            return Some(true);
        }
        return Some(CIDR_V6_DYN.get(&Key::new(128, source)).is_some());
    }
    Some(false)
}

/// Drop a frame whose source is denied; pass everything else.
#[inline(always)]
pub fn filter(ctx: &XdpContext) -> u32 {
    if denied(ctx) == Some(true) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}
