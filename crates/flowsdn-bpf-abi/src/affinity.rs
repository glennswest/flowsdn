//! Fixed affinity and skip-LB map layouts, map ABI specification §4.3.
//! Raw decoding preserves every union, reserved flag, and padding byte.
//! Unmarked integer fields use the specification's little-endian host order;
//! IPv6 addresses remain network bytes. No map operations or clock-unit
//! conversion are implemented. See LB-COVERAGE.md for the precise scope.

use crate::{MapBytes, put, take};

/// Bit zero selects the network-namespace cookie union member. Higher bits
/// are reserved and are preserved by raw decoding and the bit setter.
pub const NETNS_COOKIE: u8 = 1;

/// `Lb4AffinityKey`: 16-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Lb4AffinityKey {
    /// Byte offset 0.
    pub client_id: [u8; 8],
    /// Byte offset 8.
    pub rev_nat_id: u16,
    /// Byte offset 10.
    pub flags: u8,
    /// Byte offset 11.
    pub pad1: u8,
    /// Byte offset 12.
    pub pad2: u32,
}
impl MapBytes<16> for Lb4AffinityKey {
    fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        put(&mut bytes, 0, self.client_id);
        put(&mut bytes, 8, self.rev_nat_id.to_le_bytes());
        put(&mut bytes, 10, [self.flags]);
        put(&mut bytes, 11, [self.pad1]);
        put(&mut bytes, 12, self.pad2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            client_id: take(&bytes, 0),
            rev_nat_id: u16::from_le_bytes(take(&bytes, 8)),
            flags: take::<1, 16>(&bytes, 10)[0],
            pad1: take::<1, 16>(&bytes, 11)[0],
            pad2: u32::from_le_bytes(take(&bytes, 12)),
        }
    }
}

/// `Lb6AffinityKey`: 24-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct Lb6AffinityKey {
    /// Byte offset 0.
    pub client_id: [u8; 16],
    /// Byte offset 16.
    pub rev_nat_id: u16,
    /// Byte offset 18.
    pub flags: u8,
    /// Byte offset 19.
    pub pad1: u8,
    /// Byte offset 20.
    pub pad2: u32,
}
impl MapBytes<24> for Lb6AffinityKey {
    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.client_id);
        put(&mut bytes, 16, self.rev_nat_id.to_le_bytes());
        put(&mut bytes, 18, [self.flags]);
        put(&mut bytes, 19, [self.pad1]);
        put(&mut bytes, 20, self.pad2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 24]) -> Self {
        Self {
            client_id: take(&bytes, 0),
            rev_nat_id: u16::from_le_bytes(take(&bytes, 16)),
            flags: take::<1, 24>(&bytes, 18)[0],
            pad1: take::<1, 24>(&bytes, 19)[0],
            pad2: u32::from_le_bytes(take(&bytes, 20)),
        }
    }
}

/// `LbAffinityVal`: 16-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct LbAffinityVal {
    /// Byte offset 0.
    pub last_used: u64,
    /// Byte offset 8.
    pub backend_id: u32,
    /// Byte offset 12.
    pub pad: u32,
}
impl MapBytes<16> for LbAffinityVal {
    fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        put(&mut bytes, 0, self.last_used.to_le_bytes());
        put(&mut bytes, 8, self.backend_id.to_le_bytes());
        put(&mut bytes, 12, self.pad.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            last_used: u64::from_le_bytes(take(&bytes, 0)),
            backend_id: u32::from_le_bytes(take(&bytes, 8)),
            pad: u32::from_le_bytes(take(&bytes, 12)),
        }
    }
}

/// `LbAffinityMatch`: 8-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct LbAffinityMatch {
    /// Byte offset 0.
    pub backend_id: u32,
    /// Byte offset 4.
    pub rev_nat_id: u16,
    /// Byte offset 6.
    pub pad: u16,
}
impl MapBytes<8> for LbAffinityMatch {
    fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        put(&mut bytes, 0, self.backend_id.to_le_bytes());
        put(&mut bytes, 4, self.rev_nat_id.to_le_bytes());
        put(&mut bytes, 6, self.pad.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self {
            backend_id: u32::from_le_bytes(take(&bytes, 0)),
            rev_nat_id: u16::from_le_bytes(take(&bytes, 4)),
            pad: u16::from_le_bytes(take(&bytes, 6)),
        }
    }
}

/// `SkipLb4Key`: 16-byte map ABI layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SkipLb4Key {
    /// Byte offset 0.
    pub netns_cookie: u64,
    /// Byte offset 8.
    pub address: u32,
    /// Byte offset 12.
    pub port: u16,
    /// Byte offset 14.
    pub pad: u16,
}
impl MapBytes<16> for SkipLb4Key {
    fn to_bytes(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        put(&mut bytes, 0, self.netns_cookie.to_le_bytes());
        put(&mut bytes, 8, self.address.to_le_bytes());
        put(&mut bytes, 12, self.port.to_le_bytes());
        put(&mut bytes, 14, self.pad.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 16]) -> Self {
        Self {
            netns_cookie: u64::from_le_bytes(take(&bytes, 0)),
            address: u32::from_le_bytes(take(&bytes, 8)),
            port: u16::from_le_bytes(take(&bytes, 12)),
            pad: u16::from_le_bytes(take(&bytes, 14)),
        }
    }
}

/// `SkipLb6Key`: 32-byte map ABI layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SkipLb6Key {
    /// Byte offset 0.
    pub netns_cookie: u64,
    /// Byte offset 8.
    pub address: [u8; 16],
    /// Byte offset 24.
    pub pad: u32,
    /// Byte offset 28.
    pub port: u16,
    /// Byte offset 30.
    pub pad2: u16,
}
impl MapBytes<32> for SkipLb6Key {
    fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        put(&mut bytes, 0, self.netns_cookie.to_le_bytes());
        put(&mut bytes, 8, self.address);
        put(&mut bytes, 24, self.pad.to_le_bytes());
        put(&mut bytes, 28, self.port.to_le_bytes());
        put(&mut bytes, 30, self.pad2.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            netns_cookie: u64::from_le_bytes(take(&bytes, 0)),
            address: take(&bytes, 8),
            pad: u32::from_le_bytes(take(&bytes, 24)),
            port: u16::from_le_bytes(take(&bytes, 28)),
            pad2: u16::from_le_bytes(take(&bytes, 30)),
        }
    }
}

impl Lb4AffinityKey {
    /// Construct the cookie member; all padding and reserved flag bits are zero.
    pub fn with_cookie(cookie: u64, rev_nat_id: u16) -> Self {
        Self {
            client_id: cookie.to_le_bytes(),
            rev_nat_id,
            flags: NETNS_COOKIE,
            ..Default::default()
        }
    }
    /// Raw cookie view. The caller must first check `uses_netns_cookie()`.
    pub fn cookie(self) -> u64 {
        u64::from_le_bytes(self.client_id)
    }
    pub fn rev_nat_id(self) -> u16 {
        self.rev_nat_id
    }
    pub fn uses_netns_cookie(self) -> bool {
        self.flags & NETNS_COOKIE != 0
    }
    /// Change only the discriminator bit; the union and reserved bits stay intact.
    pub fn set_netns_cookie(&mut self, enabled: bool) {
        self.flags = (self.flags & !NETNS_COOKIE) | u8::from(enabled);
    }
}
impl Lb6AffinityKey {
    /// Construct the cookie member; unused upper union bytes and padding are zero.
    pub fn with_cookie(cookie: u64, rev_nat_id: u16) -> Self {
        let mut client_id = [0; 16];
        put(&mut client_id, 0, cookie.to_le_bytes());
        Self {
            client_id,
            rev_nat_id,
            flags: NETNS_COOKIE,
            ..Default::default()
        }
    }
    /// Construct the IPv6 member from network bytes with no cookie flag.
    pub fn with_address(address: [u8; 16], rev_nat_id: u16) -> Self {
        Self {
            client_id: address,
            rev_nat_id,
            ..Default::default()
        }
    }
    /// Raw cookie view. The upper eight union bytes remain available in client_id.
    pub fn cookie(self) -> u64 {
        u64::from_le_bytes(take(&self.client_id, 0))
    }
    pub fn rev_nat_id(self) -> u16 {
        self.rev_nat_id
    }
    pub fn uses_netns_cookie(self) -> bool {
        self.flags & NETNS_COOKIE != 0
    }
    pub fn set_netns_cookie(&mut self, enabled: bool) {
        self.flags = (self.flags & !NETNS_COOKIE) | u8::from(enabled);
    }
}
impl LbAffinityVal {
    /// Packed numeric fields are returned by value, never by unaligned reference.
    pub fn last_used(self) -> u64 {
        self.last_used
    }
    pub fn backend_id(self) -> u32 {
        self.backend_id
    }
}
impl LbAffinityMatch {
    pub fn backend_id(self) -> u32 {
        self.backend_id
    }
    pub fn rev_nat_id(self) -> u16 {
        self.rev_nat_id
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Lb4AffinityKey>() == 16);
    assert!(align_of::<Lb4AffinityKey>() == 1);
    assert!(offset_of!(Lb4AffinityKey, client_id) == 0);
    assert!(offset_of!(Lb4AffinityKey, rev_nat_id) == 8);
    assert!(offset_of!(Lb4AffinityKey, flags) == 10);
    assert!(offset_of!(Lb4AffinityKey, pad1) == 11);
    assert!(offset_of!(Lb4AffinityKey, pad2) == 12);
    assert!(size_of::<Lb6AffinityKey>() == 24);
    assert!(align_of::<Lb6AffinityKey>() == 1);
    assert!(offset_of!(Lb6AffinityKey, client_id) == 0);
    assert!(offset_of!(Lb6AffinityKey, rev_nat_id) == 16);
    assert!(offset_of!(Lb6AffinityKey, flags) == 18);
    assert!(offset_of!(Lb6AffinityKey, pad1) == 19);
    assert!(offset_of!(Lb6AffinityKey, pad2) == 20);
    assert!(size_of::<LbAffinityVal>() == 16);
    assert!(align_of::<LbAffinityVal>() == 1);
    assert!(offset_of!(LbAffinityVal, last_used) == 0);
    assert!(offset_of!(LbAffinityVal, backend_id) == 8);
    assert!(offset_of!(LbAffinityVal, pad) == 12);
    assert!(size_of::<LbAffinityMatch>() == 8);
    assert!(align_of::<LbAffinityMatch>() == 1);
    assert!(offset_of!(LbAffinityMatch, backend_id) == 0);
    assert!(offset_of!(LbAffinityMatch, rev_nat_id) == 4);
    assert!(offset_of!(LbAffinityMatch, pad) == 6);
    assert!(size_of::<SkipLb4Key>() == 16);
    assert!(offset_of!(SkipLb4Key, netns_cookie) == 0);
    assert!(offset_of!(SkipLb4Key, address) == 8);
    assert!(offset_of!(SkipLb4Key, port) == 12);
    assert!(offset_of!(SkipLb4Key, pad) == 14);
    assert!(size_of::<SkipLb6Key>() == 32);
    assert!(offset_of!(SkipLb6Key, netns_cookie) == 0);
    assert!(offset_of!(SkipLb6Key, address) == 8);
    assert!(offset_of!(SkipLb6Key, pad) == 24);
    assert!(offset_of!(SkipLb6Key, port) == 28);
    assert!(offset_of!(SkipLb6Key, pad2) == 30);
};
