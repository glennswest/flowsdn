//! Load-balancer map layouts from map ABI specification §4.3.
//! Network fields use byte wrappers; other integer codecs are little endian.
//! Raw decoding preserves padding and unknown flags. This module does not
//! allocate IDs, validate service semantics, or implement map operations.
//!
//! `LbService::union_raw` deliberately has no L7 proxy-port conversion: spec01
//! §4.3 says host order, while spec05 §2 says htons. See LB-COVERAGE.md.

use crate::{Be16, Be32, InvalidPrefix, MapBytes, put, take};

/// `Lb4Key`: 12-byte layout, map ABI specification §4.3.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb4Key {
    /// Byte offset 0.
    pub address: Be32,
    /// Byte offset 4.
    pub dport: Be16,
    /// Byte offset 6.
    pub backend_slot: u16,
    /// Byte offset 8.
    pub proto: u8,
    /// Byte offset 9.
    pub scope: u8,
    /// Byte offset 10.
    pub pad: [u8; 2],
}
impl MapBytes<12> for Lb4Key {
    fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, self.address.0);
        put(&mut bytes, 4, self.dport.0);
        put(&mut bytes, 6, self.backend_slot.to_le_bytes());
        put(&mut bytes, 8, [self.proto]);
        put(&mut bytes, 9, [self.scope]);
        put(&mut bytes, 10, self.pad);
        bytes
    }
    fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            address: Be32(take(&bytes, 0)),
            dport: Be16(take(&bytes, 4)),
            backend_slot: u16::from_le_bytes(take(&bytes, 6)),
            proto: take::<1, 12>(&bytes, 8)[0],
            scope: take::<1, 12>(&bytes, 9)[0],
            pad: take(&bytes, 10),
        }
    }
}

/// `Lb6Key`: 24-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb6Key {
    /// Byte offset 0.
    pub address: [u8; 16],
    /// Byte offset 16.
    pub dport: Be16,
    /// Byte offset 18.
    pub backend_slot: u16,
    /// Byte offset 20.
    pub proto: u8,
    /// Byte offset 21.
    pub scope: u8,
    /// Byte offset 22.
    pub pad: [u8; 2],
}
impl MapBytes<24> for Lb6Key {
    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.address);
        put(&mut bytes, 16, self.dport.0);
        put(&mut bytes, 18, self.backend_slot.to_le_bytes());
        put(&mut bytes, 20, [self.proto]);
        put(&mut bytes, 21, [self.scope]);
        put(&mut bytes, 22, self.pad);
        bytes
    }
    fn from_bytes(bytes: [u8; 24]) -> Self {
        Self {
            address: take(&bytes, 0),
            dport: Be16(take(&bytes, 16)),
            backend_slot: u16::from_le_bytes(take(&bytes, 18)),
            proto: take::<1, 24>(&bytes, 20)[0],
            scope: take::<1, 24>(&bytes, 21)[0],
            pad: take(&bytes, 22),
        }
    }
}

/// `LbService`: 12-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LbService {
    /// Byte offset 0.
    pub union_raw: u32,
    /// Byte offset 4.
    pub count: u16,
    /// Byte offset 6.
    pub rev_nat_index: u16,
    /// Byte offset 8.
    pub flags: u8,
    /// Byte offset 9.
    pub flags2: u8,
    /// Byte offset 10.
    pub qcount: u16,
}
impl MapBytes<12> for LbService {
    fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, self.union_raw.to_le_bytes());
        put(&mut bytes, 4, self.count.to_le_bytes());
        put(&mut bytes, 6, self.rev_nat_index.to_le_bytes());
        put(&mut bytes, 8, [self.flags]);
        put(&mut bytes, 9, [self.flags2]);
        put(&mut bytes, 10, self.qcount.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            union_raw: u32::from_le_bytes(take(&bytes, 0)),
            count: u16::from_le_bytes(take(&bytes, 4)),
            rev_nat_index: u16::from_le_bytes(take(&bytes, 6)),
            flags: take::<1, 12>(&bytes, 8)[0],
            flags2: take::<1, 12>(&bytes, 9)[0],
            qcount: u16::from_le_bytes(take(&bytes, 10)),
        }
    }
}

/// `Lb4Backend`: 12-byte layout, map ABI specification §4.3.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb4Backend {
    /// Byte offset 0.
    pub address: Be32,
    /// Byte offset 4.
    pub port: Be16,
    /// Byte offset 6.
    pub proto: u8,
    /// Byte offset 7.
    pub flags: u8,
    /// Byte offset 8.
    pub cluster_id: u16,
    /// Byte offset 10.
    pub zone: u8,
    /// Byte offset 11.
    pub pad: u8,
}
impl MapBytes<12> for Lb4Backend {
    fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, self.address.0);
        put(&mut bytes, 4, self.port.0);
        put(&mut bytes, 6, [self.proto]);
        put(&mut bytes, 7, [self.flags]);
        put(&mut bytes, 8, self.cluster_id.to_le_bytes());
        put(&mut bytes, 10, [self.zone]);
        put(&mut bytes, 11, [self.pad]);
        bytes
    }
    fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            address: Be32(take(&bytes, 0)),
            port: Be16(take(&bytes, 4)),
            proto: take::<1, 12>(&bytes, 6)[0],
            flags: take::<1, 12>(&bytes, 7)[0],
            cluster_id: u16::from_le_bytes(take(&bytes, 8)),
            zone: take::<1, 12>(&bytes, 10)[0],
            pad: take::<1, 12>(&bytes, 11)[0],
        }
    }
}

/// `Lb6Backend`: 24-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb6Backend {
    /// Byte offset 0.
    pub address: [u8; 16],
    /// Byte offset 16.
    pub port: Be16,
    /// Byte offset 18.
    pub proto: u8,
    /// Byte offset 19.
    pub flags: u8,
    /// Byte offset 20.
    pub cluster_id: u16,
    /// Byte offset 22.
    pub zone: u8,
    /// Byte offset 23.
    pub pad: u8,
}
impl MapBytes<24> for Lb6Backend {
    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.address);
        put(&mut bytes, 16, self.port.0);
        put(&mut bytes, 18, [self.proto]);
        put(&mut bytes, 19, [self.flags]);
        put(&mut bytes, 20, self.cluster_id.to_le_bytes());
        put(&mut bytes, 22, [self.zone]);
        put(&mut bytes, 23, [self.pad]);
        bytes
    }
    fn from_bytes(bytes: [u8; 24]) -> Self {
        Self {
            address: take(&bytes, 0),
            port: Be16(take(&bytes, 16)),
            proto: take::<1, 24>(&bytes, 18)[0],
            flags: take::<1, 24>(&bytes, 19)[0],
            cluster_id: u16::from_le_bytes(take(&bytes, 20)),
            zone: take::<1, 24>(&bytes, 22)[0],
            pad: take::<1, 24>(&bytes, 23)[0],
        }
    }
}

/// `Lb4ReverseNat`: 6-byte layout, map ABI specification §4.3.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb4ReverseNat {
    /// Byte offset 0.
    pub address: Be32,
    /// Byte offset 4.
    pub port: Be16,
}
impl MapBytes<6> for Lb4ReverseNat {
    fn to_bytes(self) -> [u8; 6] {
        let mut bytes = [0; 6];
        put(&mut bytes, 0, self.address.0);
        put(&mut bytes, 4, self.port.0);
        bytes
    }
    fn from_bytes(bytes: [u8; 6]) -> Self {
        Self {
            address: Be32(take(&bytes, 0)),
            port: Be16(take(&bytes, 4)),
        }
    }
}

/// `Lb6ReverseNat`: 18-byte layout, map ABI specification §4.3.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb6ReverseNat {
    /// Byte offset 0.
    pub address: [u8; 16],
    /// Byte offset 16.
    pub port: Be16,
}
impl MapBytes<18> for Lb6ReverseNat {
    fn to_bytes(self) -> [u8; 18] {
        let mut bytes = [0; 18];
        put(&mut bytes, 0, self.address);
        put(&mut bytes, 16, self.port.0);
        bytes
    }
    fn from_bytes(bytes: [u8; 18]) -> Self {
        Self {
            address: take(&bytes, 0),
            port: Be16(take(&bytes, 16)),
        }
    }
}

/// `Lb4SrcRangeKey`: 12-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb4SrcRangeKey {
    /// Byte offset 0.
    pub prefixlen: u32,
    /// Byte offset 4.
    pub rev_nat_id: u16,
    /// Byte offset 6.
    pub pad: u16,
    /// Byte offset 8.
    pub address: Be32,
}
impl MapBytes<12> for Lb4SrcRangeKey {
    fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, self.prefixlen.to_le_bytes());
        put(&mut bytes, 4, self.rev_nat_id.to_le_bytes());
        put(&mut bytes, 6, self.pad.to_le_bytes());
        put(&mut bytes, 8, self.address.0);
        bytes
    }
    fn from_bytes(bytes: [u8; 12]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&bytes, 0)),
            rev_nat_id: u16::from_le_bytes(take(&bytes, 4)),
            pad: u16::from_le_bytes(take(&bytes, 6)),
            address: Be32(take(&bytes, 8)),
        }
    }
}

/// `Lb6SrcRangeKey`: 24-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Lb6SrcRangeKey {
    /// Byte offset 0.
    pub prefixlen: u32,
    /// Byte offset 4.
    pub rev_nat_id: u16,
    /// Byte offset 6.
    pub pad: u16,
    /// Byte offset 8.
    pub address: [u8; 16],
}
impl MapBytes<24> for Lb6SrcRangeKey {
    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.prefixlen.to_le_bytes());
        put(&mut bytes, 4, self.rev_nat_id.to_le_bytes());
        put(&mut bytes, 6, self.pad.to_le_bytes());
        put(&mut bytes, 8, self.address);
        bytes
    }
    fn from_bytes(bytes: [u8; 24]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&bytes, 0)),
            rev_nat_id: u16::from_le_bytes(take(&bytes, 4)),
            pad: u16::from_le_bytes(take(&bytes, 6)),
            address: take(&bytes, 8),
        }
    }
}

/// `Ipv4RevnatTuple`: 16-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4RevnatTuple {
    /// Byte offset 0.
    pub cookie: u64,
    /// Byte offset 8.
    pub address: Be32,
    /// Byte offset 12.
    pub port: Be16,
    /// Byte offset 14.
    pub pad: u16,
}
impl MapBytes<16> for Ipv4RevnatTuple {
    fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        put(&mut bytes, 0, self.cookie.to_le_bytes());
        put(&mut bytes, 8, self.address.0);
        put(&mut bytes, 12, self.port.0);
        put(&mut bytes, 14, self.pad.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            cookie: u64::from_le_bytes(take(&bytes, 0)),
            address: Be32(take(&bytes, 8)),
            port: Be16(take(&bytes, 12)),
            pad: u16::from_le_bytes(take(&bytes, 14)),
        }
    }
}

/// `Ipv4RevnatEntry`: 8-byte layout, map ABI specification §4.3.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4RevnatEntry {
    /// Byte offset 0.
    pub address: Be32,
    /// Byte offset 4.
    pub port: Be16,
    /// Byte offset 6.
    pub rev_nat_index: u16,
}
impl MapBytes<8> for Ipv4RevnatEntry {
    fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        put(&mut bytes, 0, self.address.0);
        put(&mut bytes, 4, self.port.0);
        put(&mut bytes, 6, self.rev_nat_index.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            address: Be32(take(&bytes, 0)),
            port: Be16(take(&bytes, 4)),
            rev_nat_index: u16::from_le_bytes(take(&bytes, 6)),
        }
    }
}

/// `Ipv6RevnatTuple`: 32-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv6RevnatTuple {
    /// Byte offset 0.
    pub cookie: u64,
    /// Byte offset 8.
    pub address: [u8; 16],
    /// Byte offset 24.
    pub port: Be16,
    /// Byte offset 26.
    pub pad: u16,
    /// Byte offset 28.
    pub pad2: u32,
}
impl MapBytes<32> for Ipv6RevnatTuple {
    fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        put(&mut bytes, 0, self.cookie.to_le_bytes());
        put(&mut bytes, 8, self.address);
        put(&mut bytes, 24, self.port.0);
        put(&mut bytes, 26, self.pad.to_le_bytes());
        put(&mut bytes, 28, self.pad2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            cookie: u64::from_le_bytes(take(&bytes, 0)),
            address: take(&bytes, 8),
            port: Be16(take(&bytes, 24)),
            pad: u16::from_le_bytes(take(&bytes, 26)),
            pad2: u32::from_le_bytes(take(&bytes, 28)),
        }
    }
}

/// `Ipv6RevnatEntry`: 20-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv6RevnatEntry {
    /// Byte offset 0.
    pub address: [u8; 16],
    /// Byte offset 16.
    pub port: Be16,
    /// Byte offset 18.
    pub rev_nat_index: u16,
}
impl MapBytes<20> for Ipv6RevnatEntry {
    fn to_bytes(self) -> [u8; 20] {
        let mut bytes = [0; 20];
        put(&mut bytes, 0, self.address);
        put(&mut bytes, 16, self.port.0);
        put(&mut bytes, 18, self.rev_nat_index.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 20]) -> Self {
        Self {
            address: take(&bytes, 0),
            port: Be16(take(&bytes, 16)),
            rev_nat_index: u16::from_le_bytes(take(&bytes, 18)),
        }
    }
}

/// `LbActKey`: 4-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LbActKey {
    /// Byte offset 0.
    pub svc_id: u16,
    /// Byte offset 2.
    pub zone: u8,
    /// Byte offset 3.
    pub pad: u8,
}
impl MapBytes<4> for LbActKey {
    fn to_bytes(self) -> [u8; 4] {
        let mut bytes = [0; 4];
        put(&mut bytes, 0, self.svc_id.to_le_bytes());
        put(&mut bytes, 2, [self.zone]);
        put(&mut bytes, 3, [self.pad]);
        bytes
    }
    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self {
            svc_id: u16::from_le_bytes(take(&bytes, 0)),
            zone: take::<1, 4>(&bytes, 2)[0],
            pad: take::<1, 4>(&bytes, 3)[0],
        }
    }
}

/// `LbActValue`: 8-byte layout, map ABI specification §4.3.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LbActValue {
    /// Byte offset 0.
    pub opened: u32,
    /// Byte offset 4.
    pub closed: u32,
}
impl MapBytes<8> for LbActValue {
    fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        put(&mut bytes, 0, self.opened.to_le_bytes());
        put(&mut bytes, 4, self.closed.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            opened: u32::from_le_bytes(take(&bytes, 0)),
            closed: u32::from_le_bytes(take(&bytes, 4)),
        }
    }
}

/// Health-map values are backend layouts (spec01 §4.3).
pub type Lb4Health = Lb4Backend;
pub type Lb6Health = Lb6Backend;
/// Both service families share the same value layout.
pub type Lb4Service = LbService;
pub type Lb6Service = LbService;

/// Master-slot algorithm codes, spec01 §4.3 and spec05 §4.3.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm { Random = 1, Maglev = 2 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAffinityTimeout;

impl LbService {
    /// Interpret the raw union only when this is a master affinity slot.
    pub fn affinity_seconds(self) -> u32 { self.union_raw & 0x00ff_ffff }
    /// Unknown algorithm bytes remain observable; decoding never coerces them.
    pub fn algorithm_code(self) -> u8 { self.union_raw.to_be_bytes()[0] }
    pub fn set_affinity(&mut self, algorithm: Algorithm, seconds: u32) -> Result<(), InvalidAffinityTimeout> {
        if seconds > 0x00ff_ffff { return Err(InvalidAffinityTimeout); }
        self.union_raw = (u32::from(algorithm as u8) << 24) | seconds;
        Ok(())
    }
    /// Interpret the same raw union as a backend ID only for backend slots.
    pub fn backend_id(self) -> u32 { self.union_raw }
    pub fn service_flags(self) -> u16 { u16::from_le_bytes([self.flags, self.flags2]) }
    pub fn set_service_flags(&mut self, flags: u16) {
        let [low, high] = flags.to_le_bytes();
        self.flags = low;
        self.flags2 = high;
    }
}

impl Lb4SrcRangeKey {
    /// CIDR prefix bits exclude the 32 static service-ID/padding bits. Host
    /// bits are preserved; canonicalization belongs to the IP-prefix owner.
    pub fn new(address: [u8; 4], bits: u32, rev_nat_id: u16) -> Result<Self, InvalidPrefix> {
        if bits > 32 { return Err(InvalidPrefix); }
        Ok(Self { prefixlen: 32_u32.checked_add(bits).ok_or(InvalidPrefix)?, rev_nat_id, pad: 0, address: Be32(address) })
    }
}
impl Lb6SrcRangeKey {
    pub fn new(address: [u8; 16], bits: u32, rev_nat_id: u16) -> Result<Self, InvalidPrefix> {
        if bits > 128 { return Err(InvalidPrefix); }
        Ok(Self { prefixlen: 32_u32.checked_add(bits).ok_or(InvalidPrefix)?, rev_nat_id, pad: 0, address })
    }
}

/// Raw service flag masks, spec05 §4.3. Bit14 is source-range deny, never a
/// backend quarantine flag; backend state is stored in Lb{4,6}Backend.flags.
pub mod service_flags {
    pub const EXTERNAL_IPS: u16 = 0x0001;
    pub const NODE_PORT: u16 = 0x0002;
    pub const EXT_LOCAL_SCOPE: u16 = 0x0004;
    pub const HOST_PORT: u16 = 0x0008;
    pub const SESSION_AFFINITY: u16 = 0x0010;
    pub const LOAD_BALANCER: u16 = 0x0020;
    pub const ROUTABLE: u16 = 0x0040;
    pub const SOURCE_RANGE: u16 = 0x0080;
    pub const LOCAL_REDIRECT: u16 = 0x0100;
    pub const NAT46X64: u16 = 0x0200;
    pub const L7_LOAD_BALANCER: u16 = 0x0400;
    pub const LOOPBACK: u16 = 0x0800;
    pub const INT_LOCAL_SCOPE: u16 = 0x1000;
    pub const TWO_SCOPES: u16 = 0x2000;
    pub const SOURCE_RANGE_DENY: u16 = 0x4000;
    pub const FWD_MODE_DSR: u16 = 0x8000;
}
/// Backend states are enum-like byte values, not independent bit masks.
pub mod backend_state {
    pub const ACTIVE: u8 = 0;
    pub const TERMINATING: u8 = 1;
    pub const QUARANTINED: u8 = 2;
    pub const MAINTENANCE: u8 = 3;
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Lb4Key>() == 12);
    assert!(offset_of!(Lb4Key, address) == 0);
    assert!(offset_of!(Lb4Key, dport) == 4);
    assert!(offset_of!(Lb4Key, backend_slot) == 6);
    assert!(offset_of!(Lb4Key, proto) == 8);
    assert!(offset_of!(Lb4Key, scope) == 9);
    assert!(offset_of!(Lb4Key, pad) == 10);
    assert!(size_of::<Lb6Key>() == 24);
    assert!(offset_of!(Lb6Key, address) == 0);
    assert!(offset_of!(Lb6Key, dport) == 16);
    assert!(offset_of!(Lb6Key, backend_slot) == 18);
    assert!(offset_of!(Lb6Key, proto) == 20);
    assert!(offset_of!(Lb6Key, scope) == 21);
    assert!(offset_of!(Lb6Key, pad) == 22);
    assert!(size_of::<LbService>() == 12);
    assert!(offset_of!(LbService, union_raw) == 0);
    assert!(offset_of!(LbService, count) == 4);
    assert!(offset_of!(LbService, rev_nat_index) == 6);
    assert!(offset_of!(LbService, flags) == 8);
    assert!(offset_of!(LbService, flags2) == 9);
    assert!(offset_of!(LbService, qcount) == 10);
    assert!(size_of::<Lb4Backend>() == 12);
    assert!(offset_of!(Lb4Backend, address) == 0);
    assert!(offset_of!(Lb4Backend, port) == 4);
    assert!(offset_of!(Lb4Backend, proto) == 6);
    assert!(offset_of!(Lb4Backend, flags) == 7);
    assert!(offset_of!(Lb4Backend, cluster_id) == 8);
    assert!(offset_of!(Lb4Backend, zone) == 10);
    assert!(offset_of!(Lb4Backend, pad) == 11);
    assert!(size_of::<Lb6Backend>() == 24);
    assert!(offset_of!(Lb6Backend, address) == 0);
    assert!(offset_of!(Lb6Backend, port) == 16);
    assert!(offset_of!(Lb6Backend, proto) == 18);
    assert!(offset_of!(Lb6Backend, flags) == 19);
    assert!(offset_of!(Lb6Backend, cluster_id) == 20);
    assert!(offset_of!(Lb6Backend, zone) == 22);
    assert!(offset_of!(Lb6Backend, pad) == 23);
    assert!(size_of::<Lb4ReverseNat>() == 6);
    assert!(offset_of!(Lb4ReverseNat, address) == 0);
    assert!(offset_of!(Lb4ReverseNat, port) == 4);
    assert!(size_of::<Lb6ReverseNat>() == 18);
    assert!(offset_of!(Lb6ReverseNat, address) == 0);
    assert!(offset_of!(Lb6ReverseNat, port) == 16);
    assert!(size_of::<Lb4SrcRangeKey>() == 12);
    assert!(offset_of!(Lb4SrcRangeKey, prefixlen) == 0);
    assert!(offset_of!(Lb4SrcRangeKey, rev_nat_id) == 4);
    assert!(offset_of!(Lb4SrcRangeKey, pad) == 6);
    assert!(offset_of!(Lb4SrcRangeKey, address) == 8);
    assert!(size_of::<Lb6SrcRangeKey>() == 24);
    assert!(offset_of!(Lb6SrcRangeKey, prefixlen) == 0);
    assert!(offset_of!(Lb6SrcRangeKey, rev_nat_id) == 4);
    assert!(offset_of!(Lb6SrcRangeKey, pad) == 6);
    assert!(offset_of!(Lb6SrcRangeKey, address) == 8);
    assert!(size_of::<Ipv4RevnatTuple>() == 16);
    assert!(offset_of!(Ipv4RevnatTuple, cookie) == 0);
    assert!(offset_of!(Ipv4RevnatTuple, address) == 8);
    assert!(offset_of!(Ipv4RevnatTuple, port) == 12);
    assert!(offset_of!(Ipv4RevnatTuple, pad) == 14);
    assert!(size_of::<Ipv4RevnatEntry>() == 8);
    assert!(offset_of!(Ipv4RevnatEntry, address) == 0);
    assert!(offset_of!(Ipv4RevnatEntry, port) == 4);
    assert!(offset_of!(Ipv4RevnatEntry, rev_nat_index) == 6);
    assert!(size_of::<Ipv6RevnatTuple>() == 32);
    assert!(offset_of!(Ipv6RevnatTuple, cookie) == 0);
    assert!(offset_of!(Ipv6RevnatTuple, address) == 8);
    assert!(offset_of!(Ipv6RevnatTuple, port) == 24);
    assert!(offset_of!(Ipv6RevnatTuple, pad) == 26);
    assert!(offset_of!(Ipv6RevnatTuple, pad2) == 28);
    assert!(size_of::<Ipv6RevnatEntry>() == 20);
    assert!(offset_of!(Ipv6RevnatEntry, address) == 0);
    assert!(offset_of!(Ipv6RevnatEntry, port) == 16);
    assert!(offset_of!(Ipv6RevnatEntry, rev_nat_index) == 18);
    assert!(size_of::<LbActKey>() == 4);
    assert!(offset_of!(LbActKey, svc_id) == 0);
    assert!(offset_of!(LbActKey, zone) == 2);
    assert!(offset_of!(LbActKey, pad) == 3);
    assert!(size_of::<LbActValue>() == 8);
    assert!(offset_of!(LbActValue, opened) == 0);
    assert!(offset_of!(LbActValue, closed) == 4);
    assert!(align_of::<Lb4ReverseNat>() == 1);
    assert!(align_of::<Lb6ReverseNat>() == 1);
};
