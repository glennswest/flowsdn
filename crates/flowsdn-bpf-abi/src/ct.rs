//! Conntrack and NAT values from map ABI specification §4.2.
use crate::{Be16, Be32, MapBytes, put, take};

/// Named, non-reserved bits in the conntrack value's raw flag word.
pub mod flags {
    pub const RX_CLOSING: u16 = 1 << 0;
    pub const TX_CLOSING: u16 = 1 << 1;
    pub const LB_LOOPBACK: u16 = 1 << 3;
    pub const SEEN_NON_SYN: u16 = 1 << 4;
    pub const NODE_PORT: u16 = 1 << 5;
    pub const PROXY_REDIRECT: u16 = 1 << 6;
    pub const DSR_INTERNAL: u16 = 1 << 7;
    pub const FROM_L7LB: u16 = 1 << 8;
    pub const FROM_TUNNEL: u16 = 1 << 10;
}

/// Raw union storage avoids unsafe casts and preserves either interpretation.
/// The tuple's context determines whether this is a NAT address or service data.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CtEntry {
    pub nat_addr_or_service: [u8; 16],
    pub packets: u64,
    pub bytes: u64,
    /// Absolute expiry in the configured clock's units; no conversion here.
    pub lifetime: u32,
    pub flags: u16,
    pub rev_nat_index: u16,
    pub nat_port: Be16,
    pub tx_flags_seen: u8,
    pub rx_flags_seen: u8,
    /// Frozen at byte 44 for userspace proxy compatibility.
    pub src_sec_id: u32,
    pub last_tx_report: u32,
    pub last_rx_report: u32,
}
impl CtEntry {
    /// Read the full raw service union field, including otherwise unused bits.
    pub fn service_backend_raw(self) -> u64 {
        u64::from_le_bytes(take(&self.nat_addr_or_service, 8))
    }
    /// Select the service interpretation, zeroing reserved union storage.
    pub fn set_service_backend(&mut self, backend_id: u32) {
        self.nat_addr_or_service = [0; 16];
        put(&mut self.nat_addr_or_service, 8, u64::from(backend_id).to_le_bytes());
    }
}
impl MapBytes<56> for CtEntry {
    fn to_bytes(self) -> [u8; 56] {
        let mut out = [0; 56];
        put(&mut out, 0, self.nat_addr_or_service);
        put(&mut out, 16, self.packets.to_le_bytes());
        put(&mut out, 24, self.bytes.to_le_bytes());
        put(&mut out, 32, self.lifetime.to_le_bytes());
        put(&mut out, 36, self.flags.to_le_bytes());
        put(&mut out, 38, self.rev_nat_index.to_le_bytes());
        put(&mut out, 40, self.nat_port.0);
        put(&mut out, 42, [self.tx_flags_seen, self.rx_flags_seen]);
        put(&mut out, 44, self.src_sec_id.to_le_bytes());
        put(&mut out, 48, self.last_tx_report.to_le_bytes());
        put(&mut out, 52, self.last_rx_report.to_le_bytes());
        out
    }
    fn from_bytes(b: [u8; 56]) -> Self {
        Self {
            nat_addr_or_service: take(&b, 0),
            packets: u64::from_le_bytes(take(&b, 16)),
            bytes: u64::from_le_bytes(take(&b, 24)),
            lifetime: u32::from_le_bytes(take(&b, 32)),
            flags: u16::from_le_bytes(take(&b, 36)),
            rev_nat_index: u16::from_le_bytes(take(&b, 38)),
            nat_port: Be16(take(&b, 40)),
            tx_flags_seen: take::<1, 56>(&b, 42)[0],
            rx_flags_seen: take::<1, 56>(&b, 43)[0],
            src_sec_id: u32::from_le_bytes(take(&b, 44)),
            last_tx_report: u32::from_le_bytes(take(&b, 48)),
            last_rx_report: u32::from_le_bytes(take(&b, 52)),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NatEntry {
    pub created: u64,
    pub needs_ct: u64,
    pub pad1: u64,
    pub pad2: u64,
}
impl NatEntry {
    pub const fn requires_conntrack(self) -> bool {
        self.needs_ct & 1 != 0
    }
    /// Change the defined bit without discarding unknown bits from a map read.
    pub fn set_requires_conntrack(&mut self, required: bool) {
        self.needs_ct = (self.needs_ct & !1) | u64::from(required);
    }
}
impl MapBytes<32> for NatEntry {
    fn to_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        put(&mut out, 0, self.created.to_le_bytes());
        put(&mut out, 8, self.needs_ct.to_le_bytes());
        put(&mut out, 16, self.pad1.to_le_bytes());
        put(&mut out, 24, self.pad2.to_le_bytes());
        out
    }
    fn from_bytes(b: [u8; 32]) -> Self {
        Self {
            created: u64::from_le_bytes(take(&b, 0)),
            needs_ct: u64::from_le_bytes(take(&b, 8)),
            pad1: u64::from_le_bytes(take(&b, 16)),
            pad2: u64::from_le_bytes(take(&b, 24)),
        }
    }
}

/// Translation is source for OUT tuples, destination for IN tuples.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4NatEntry {
    pub common: NatEntry,
    pub address: Be32,
    pub port: Be16,
    pub pad: [u8; 2],
}
impl MapBytes<40> for Ipv4NatEntry {
    fn to_bytes(self) -> [u8; 40] {
        let mut out = [0; 40];
        put(&mut out, 0, self.common.to_bytes());
        put(&mut out, 32, self.address.0);
        put(&mut out, 36, self.port.0);
        put(&mut out, 38, self.pad);
        out
    }
    fn from_bytes(b: [u8; 40]) -> Self {
        Self {
            common: NatEntry::from_bytes(take(&b, 0)),
            address: Be32(take(&b, 32)),
            port: Be16(take(&b, 36)),
            pad: take(&b, 38),
        }
    }
}

/// Translation is source for OUT tuples, destination for IN tuples.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv6NatEntry {
    pub common: NatEntry,
    pub address: [u8; 16],
    pub port: Be16,
    pub pad: [u8; 6],
}
impl MapBytes<56> for Ipv6NatEntry {
    fn to_bytes(self) -> [u8; 56] {
        let mut out = [0; 56];
        put(&mut out, 0, self.common.to_bytes());
        put(&mut out, 32, self.address);
        put(&mut out, 48, self.port.0);
        put(&mut out, 50, self.pad);
        out
    }
    fn from_bytes(b: [u8; 56]) -> Self {
        Self {
            common: NatEntry::from_bytes(take(&b, 0)),
            address: take(&b, 32),
            port: Be16(take(&b, 48)),
            pad: take(&b, 50),
        }
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<CtEntry>() == 56);
    assert!(align_of::<CtEntry>() == 8);
    assert!(offset_of!(CtEntry, nat_addr_or_service) == 0);
    assert!(offset_of!(CtEntry, packets) == 16);
    assert!(offset_of!(CtEntry, bytes) == 24);
    assert!(offset_of!(CtEntry, lifetime) == 32);
    assert!(offset_of!(CtEntry, flags) == 36);
    assert!(offset_of!(CtEntry, rev_nat_index) == 38);
    assert!(offset_of!(CtEntry, nat_port) == 40);
    assert!(offset_of!(CtEntry, tx_flags_seen) == 42);
    assert!(offset_of!(CtEntry, rx_flags_seen) == 43);
    assert!(offset_of!(CtEntry, src_sec_id) == 44);
    assert!(offset_of!(CtEntry, last_tx_report) == 48);
    assert!(offset_of!(CtEntry, last_rx_report) == 52);
    assert!(size_of::<NatEntry>() == 32);
    assert!(align_of::<NatEntry>() == 8);
    assert!(offset_of!(NatEntry, created) == 0);
    assert!(offset_of!(NatEntry, needs_ct) == 8);
    assert!(offset_of!(NatEntry, pad1) == 16);
    assert!(offset_of!(NatEntry, pad2) == 24);
    assert!(size_of::<Ipv4NatEntry>() == 40);
    assert!(align_of::<Ipv4NatEntry>() == 8);
    assert!(offset_of!(Ipv4NatEntry, address) == 32);
    assert!(offset_of!(Ipv4NatEntry, port) == 36);
    assert!(offset_of!(Ipv4NatEntry, pad) == 38);
    assert!(size_of::<Ipv6NatEntry>() == 56);
    assert!(align_of::<Ipv6NatEntry>() == 8);
    assert!(offset_of!(Ipv6NatEntry, address) == 32);
    assert!(offset_of!(Ipv6NatEntry, port) == 48);
    assert!(offset_of!(Ipv6NatEntry, pad) == 50);
};
