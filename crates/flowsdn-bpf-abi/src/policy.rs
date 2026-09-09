//! Policy map keys, values and counters from map ABI §4.4 and policy §4.4.
//! Raw codecs preserve reserved bits; constructors create canonical new data.
use crate::{Be16, InvalidPrefix, MapBytes, put, take};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyKey {
    pub prefixlen: u32,
    pub sec_label: u32,
    pub egress: u8,
    pub protocol: u8,
    pub dport: Be16,
}
impl PolicyKey {
    /// Mask port host bits and derive the prefix from its declared length,
    /// including ranges starting at port zero. Protocol zero wildcards all L4
    /// fields and therefore cannot be combined with a port constraint.
    pub fn new(identity: u32, egress: bool, protocol: u8, port: u16, port_prefix: u8) -> Result<Self, InvalidPrefix> {
        if port_prefix > 16 || (protocol == 0 && (port_prefix != 0 || port != 0)) {
            return Err(InvalidPrefix);
        }
        let prefixlen = if protocol == 0 { 40 } else { 48u32.saturating_add(u32::from(port_prefix)) };
        let mask = u16::MAX.checked_shl(u32::from(16u8.saturating_sub(port_prefix))).unwrap_or(0);
        Ok(Self { prefixlen, sec_label: identity, egress: u8::from(egress), protocol, dport: Be16::new(port & mask) })
    }
}
impl MapBytes<12> for PolicyKey {
    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0; 12];
        put(&mut out, 0, self.prefixlen.to_le_bytes());
        put(&mut out, 4, self.sec_label.to_le_bytes());
        put(&mut out, 8, [self.egress, self.protocol]);
        put(&mut out, 10, self.dport.0);
        out
    }
    fn from_bytes(b: [u8; 12]) -> Self {
        Self { prefixlen: u32::from_le_bytes(take(&b, 0)), sec_label: u32::from_le_bytes(take(&b, 4)),
            egress: take::<1, 12>(&b, 8)[0], protocol: take::<1, 12>(&b, 9)[0], dport: Be16(take(&b, 10)) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPolicyFields;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyEntry {
    pub proxy_port: Be16,
    /// Bit 0 deny; bits 1–2 reserved; bits 3–7 protocol/port prefix length.
    pub flags: u8,
    /// Low seven bits auth type; high bit explicit auth type.
    pub auth: u8,
    pub precedence: u32,
    pub cookie: u32,
}
impl PolicyEntry {
    /// `lpm_prefix_length` excludes the static 40 bits: zero for wildcard L4,
    /// or 8 protocol bits plus 0–16 port bits. Reserved flag bits start at zero.
    pub fn new(proxy_port: u16, deny: bool, lpm_prefix_length: u8, auth_type: u8, explicit_auth: bool, precedence: u32, cookie: u32) -> Result<Self, InvalidPolicyFields> {
        if !(lpm_prefix_length == 0 || (8..=24).contains(&lpm_prefix_length)) || auth_type > 127 {
            return Err(InvalidPolicyFields);
        }
        Ok(Self { proxy_port: Be16::new(proxy_port), flags: u8::from(deny) | (lpm_prefix_length << 3), auth: auth_type | (u8::from(explicit_auth) << 7), precedence, cookie })
    }
    pub const fn denies(self) -> bool { self.flags & 1 != 0 }
    pub const fn lpm_prefix_length(self) -> u8 { self.flags >> 3 }
    pub const fn auth_type(self) -> u8 { self.auth & 0x7f }
    pub const fn has_explicit_auth_type(self) -> bool { self.auth & 0x80 != 0 }
}
impl MapBytes<12> for PolicyEntry {
    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0; 12];
        put(&mut out, 0, self.proxy_port.0);
        put(&mut out, 2, [self.flags, self.auth]);
        put(&mut out, 4, self.precedence.to_le_bytes());
        put(&mut out, 8, self.cookie.to_le_bytes());
        out
    }
    fn from_bytes(b: [u8; 12]) -> Self {
        Self { proxy_port: Be16(take(&b, 0)), flags: take::<1, 12>(&b, 2)[0], auth: take::<1, 12>(&b, 3)[0],
            precedence: u32::from_le_bytes(take(&b, 4)), cookie: u32::from_le_bytes(take(&b, 8)) }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyStatsKey {
    pub endpoint_id: u16,
    pub pad1: u8,
    pub prefix_len: u8,
    pub sec_label: u32,
    pub egress: u8,
    pub protocol: u8,
    pub dport: Be16,
}
impl MapBytes<12> for PolicyStatsKey {
    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0; 12];
        put(&mut out, 0, self.endpoint_id.to_le_bytes());
        put(&mut out, 2, [self.pad1, self.prefix_len]);
        put(&mut out, 4, self.sec_label.to_le_bytes());
        put(&mut out, 8, [self.egress, self.protocol]);
        put(&mut out, 10, self.dport.0);
        out
    }
    fn from_bytes(b: [u8; 12]) -> Self {
        Self { endpoint_id: u16::from_le_bytes(take(&b, 0)), pad1: take::<1, 12>(&b, 2)[0], prefix_len: take::<1, 12>(&b, 3)[0],
            sec_label: u32::from_le_bytes(take(&b, 4)), egress: take::<1, 12>(&b, 8)[0], protocol: take::<1, 12>(&b, 9)[0], dport: Be16(take(&b, 10)) }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyStatsValue {
    pub packets: u64,
    pub bytes: u64,
}
impl MapBytes<16> for PolicyStatsValue {
    fn to_bytes(self) -> [u8; 16] {
        let mut out = [0; 16];
        put(&mut out, 0, self.packets.to_le_bytes());
        put(&mut out, 8, self.bytes.to_le_bytes());
        out
    }
    fn from_bytes(b: [u8; 16]) -> Self {
        Self { packets: u64::from_le_bytes(take(&b, 0)), bytes: u64::from_le_bytes(take(&b, 8)) }
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<PolicyKey>() == 12);
    assert!(align_of::<PolicyKey>() == 4);
    assert!(offset_of!(PolicyKey, prefixlen) == 0);
    assert!(offset_of!(PolicyKey, sec_label) == 4);
    assert!(offset_of!(PolicyKey, egress) == 8);
    assert!(offset_of!(PolicyKey, protocol) == 9);
    assert!(offset_of!(PolicyKey, dport) == 10);
    assert!(size_of::<PolicyEntry>() == 12);
    assert!(align_of::<PolicyEntry>() == 4);
    assert!(offset_of!(PolicyEntry, proxy_port) == 0);
    assert!(offset_of!(PolicyEntry, flags) == 2);
    assert!(offset_of!(PolicyEntry, auth) == 3);
    assert!(offset_of!(PolicyEntry, precedence) == 4);
    assert!(offset_of!(PolicyEntry, cookie) == 8);
    assert!(size_of::<PolicyStatsKey>() == 12);
    assert!(align_of::<PolicyStatsKey>() == 4);
    assert!(offset_of!(PolicyStatsKey, endpoint_id) == 0);
    assert!(offset_of!(PolicyStatsKey, pad1) == 2);
    assert!(offset_of!(PolicyStatsKey, prefix_len) == 3);
    assert!(offset_of!(PolicyStatsKey, sec_label) == 4);
    assert!(offset_of!(PolicyStatsKey, egress) == 8);
    assert!(offset_of!(PolicyStatsKey, protocol) == 9);
    assert!(offset_of!(PolicyStatsKey, dport) == 10);
    assert!(size_of::<PolicyStatsValue>() == 16);
    assert!(align_of::<PolicyStatsValue>() == 8);
    assert!(offset_of!(PolicyStatsValue, packets) == 0);
    assert!(offset_of!(PolicyStatsValue, bytes) == 8);
};
