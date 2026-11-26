//! Egress gateway policy map layouts (spec 14 §3.4.5, spec 01 §4.3): IPv4,
//! the reference's `_v4_v2` layout under flowsdn's name
//! `flowsdn_egress_gw_policy_v4` (#564), and IPv6,
//! `flowsdn_egress_gw_policy_v6` (#580), whose `gateway_ip` is still the
//! gateway node's IPv4. `flowsdn_egress_gw_nexthop6` maps that IPv4 to the
//! gateway's IPv6 InternalIP, the next hop of an IPv6 packet in native
//! routing (flowsdn's deviation, spec 14's #580 amendment).
//!
//! The LPM key is `{prefixlen u32, saddr be32, daddr be32}` with prefixlen =
//! 32 + the destination prefix's length: the source is matched exactly, the
//! destination by longest prefix. The value carries the egress address (set
//! only on the gateway node), the gateway node's IPv4, and the egress
//! interface (0: the FIB decides).

use crate::{MapBytes, put, take};

/// `gateway_ip` sentinel: no gateway resolved; matching traffic is dropped.
pub const GATEWAY_NONE: [u8; 4] = [0, 0, 0, 0];
/// `gateway_ip` sentinel: an excluded CIDR; the packet goes on as if no
/// policy matched.
pub const GATEWAY_EXCLUDED: [u8; 4] = [0, 0, 0, 1];
/// The LPM key's fixed source part: 32 bits of exact source address.
pub const SOURCE_BITS: u32 = 32;
/// The IPv6 key's fixed source part: 128 bits.
pub const SOURCE_BITS6: u32 = 128;

/// `EgressGw4Key`: 12-byte LPM key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressGw4Key {
    /// Byte offset 0: 32 + destination prefix length.
    pub prefixlen: u32,
    /// Byte offset 4.
    pub saddr: [u8; 4],
    /// Byte offset 8.
    pub daddr: [u8; 4],
}
impl MapBytes<12> for EgressGw4Key {
    fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, self.prefixlen.to_le_bytes());
        put(&mut bytes, 4, self.saddr);
        put(&mut bytes, 8, self.daddr);
        bytes
    }
    fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&bytes, 0)),
            saddr: take(&bytes, 4),
            daddr: take(&bytes, 8),
        }
    }
}

/// `EgressGw4Value`: 28-byte value (the reference's `egress_gw_policy_entry_v2`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressGw4Value {
    /// Byte offset 0: the SNAT address, on the gateway node only.
    pub egress_ip: [u8; 4],
    /// Byte offset 4: the gateway node's IPv4, or a sentinel.
    pub gateway_ip: [u8; 4],
    /// Byte offset 8: room for an IPv6 gateway address.
    pub reserved: [u32; 3],
    /// Byte offset 20: the egress interface, 0 when the FIB chooses.
    pub egress_ifindex: u32,
    /// Byte offset 24.
    pub reserved2: u32,
}
impl MapBytes<28> for EgressGw4Value {
    fn to_bytes(self) -> [u8; 28] {
        let mut bytes = [0; 28];
        put(&mut bytes, 0, self.egress_ip);
        put(&mut bytes, 4, self.gateway_ip);
        for (index, word) in self.reserved.iter().enumerate() {
            put(
                &mut bytes,
                8usize.saturating_add(index.saturating_mul(4)),
                word.to_le_bytes(),
            );
        }
        put(&mut bytes, 20, self.egress_ifindex.to_le_bytes());
        put(&mut bytes, 24, self.reserved2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 28]) -> Self {
        Self {
            egress_ip: take(&bytes, 0),
            gateway_ip: take(&bytes, 4),
            reserved: [
                u32::from_le_bytes(take(&bytes, 8)),
                u32::from_le_bytes(take(&bytes, 12)),
                u32::from_le_bytes(take(&bytes, 16)),
            ],
            egress_ifindex: u32::from_le_bytes(take(&bytes, 20)),
            reserved2: u32::from_le_bytes(take(&bytes, 24)),
        }
    }
}

/// `EgressGw6Key`: 36-byte LPM key, prefixlen = 128 + destination prefix length.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressGw6Key {
    /// Byte offset 0.
    pub prefixlen: u32,
    /// Byte offset 4.
    pub saddr: [u8; 16],
    /// Byte offset 20.
    pub daddr: [u8; 16],
}
impl MapBytes<36> for EgressGw6Key {
    fn to_bytes(self) -> [u8; 36] {
        let mut bytes = [0; 36];
        put(&mut bytes, 0, self.prefixlen.to_le_bytes());
        put(&mut bytes, 4, self.saddr);
        put(&mut bytes, 20, self.daddr);
        bytes
    }
    fn from_bytes(bytes: [u8; 36]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&bytes, 0)),
            saddr: take(&bytes, 4),
            daddr: take(&bytes, 20),
        }
    }
}

/// `EgressGw6Value`: 40-byte value (the reference's `egress_gw_policy_entry6`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EgressGw6Value {
    /// Byte offset 0: the IPv6 SNAT address, on the gateway node only.
    pub egress_ip: [u8; 16],
    /// Byte offset 16: the gateway node's IPv4, or a sentinel.
    pub gateway_ip: [u8; 4],
    /// Byte offset 20.
    pub reserved: [u32; 3],
    /// Byte offset 32: the egress interface, 0 when the FIB chooses.
    pub egress_ifindex: u32,
    /// Byte offset 36.
    pub reserved2: u32,
}
impl MapBytes<40> for EgressGw6Value {
    fn to_bytes(self) -> [u8; 40] {
        let mut bytes = [0; 40];
        put(&mut bytes, 0, self.egress_ip);
        put(&mut bytes, 16, self.gateway_ip);
        for (index, word) in self.reserved.iter().enumerate() {
            put(
                &mut bytes,
                20usize.saturating_add(index.saturating_mul(4)),
                word.to_le_bytes(),
            );
        }
        put(&mut bytes, 32, self.egress_ifindex.to_le_bytes());
        put(&mut bytes, 36, self.reserved2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 40]) -> Self {
        Self {
            egress_ip: take(&bytes, 0),
            gateway_ip: take(&bytes, 16),
            reserved: [
                u32::from_le_bytes(take(&bytes, 20)),
                u32::from_le_bytes(take(&bytes, 24)),
                u32::from_le_bytes(take(&bytes, 28)),
            ],
            egress_ifindex: u32::from_le_bytes(take(&bytes, 32)),
            reserved2: u32::from_le_bytes(take(&bytes, 36)),
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<EgressGw6Key>() == 36);
    assert!(core::mem::offset_of!(EgressGw6Key, daddr) == 20);
    assert!(core::mem::size_of::<EgressGw6Value>() == 40);
    assert!(core::mem::offset_of!(EgressGw6Value, gateway_ip) == 16);
    assert!(core::mem::offset_of!(EgressGw6Value, egress_ifindex) == 32);
};

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<EgressGw4Key>() == 12);
    assert!(offset_of!(EgressGw4Key, saddr) == 4);
    assert!(offset_of!(EgressGw4Key, daddr) == 8);
    assert!(size_of::<EgressGw4Value>() == 28);
    assert!(offset_of!(EgressGw4Value, gateway_ip) == 4);
    assert!(offset_of!(EgressGw4Value, egress_ifindex) == 20);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_layouts_round_trip_at_their_offsets() {
        let key = EgressGw6Key {
            prefixlen: SOURCE_BITS6.saturating_add(64),
            saddr: [0xfd; 16],
            daddr: [0x20; 16],
        };
        let bytes = key.to_bytes();
        assert_eq!(bytes.get(0..4), Some(&192u32.to_le_bytes()[..]));
        assert_eq!(bytes.get(4..20), Some(&[0xfd; 16][..]));
        assert_eq!(bytes.get(20..36), Some(&[0x20; 16][..]));
        assert_eq!(EgressGw6Key::from_bytes(bytes), key);
        let value = EgressGw6Value {
            egress_ip: [0x2a; 16],
            gateway_ip: [192, 0, 2, 30],
            egress_ifindex: 7,
            ..EgressGw6Value::default()
        };
        let bytes = value.to_bytes();
        assert_eq!(bytes.get(16..20), Some(&[192, 0, 2, 30][..]));
        assert_eq!(bytes.get(32..36), Some(&7u32.to_le_bytes()[..]));
        assert_eq!(EgressGw6Value::from_bytes(bytes), value);
    }
}
