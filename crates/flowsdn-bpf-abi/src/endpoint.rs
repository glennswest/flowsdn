//! Endpoint, node and subnet map layouts from map ABI specification §4.4.
//! Addresses are raw network bytes, while unmarked integers are little endian.
//! Raw decoding preserves unknown families, flags, union tails and padding;
//! family-specific constructors produce canonical padding, not masked addresses.
//! MAC fields remain raw u64 values: no byte-order interpretation is invented.

use crate::{FAMILY_V4, FAMILY_V6, InvalidPrefix, MapBytes, put, take};

pub mod endpoint_flags {
    pub const HOST: u32 = 1;
    pub const AT_HOST_NS: u32 = 2;
    pub const NO_SNAT_V4: u32 = 4;
    pub const NO_SNAT_V6: u32 = 8;
}

/// `EndpointKey`: 20-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct EndpointKey {
    /// Byte offset 0.
    pub address: [u8; 16],
    /// Byte offset 16.
    pub family: u8,
    /// Byte offset 17.
    pub key: u8,
    /// Byte offset 18.
    pub cluster_id: u16,
}
impl MapBytes<20> for EndpointKey {
    fn to_bytes(self) -> [u8; 20] {
        let mut bytes = [0; 20];
        put(&mut bytes, 0, self.address);
        put(&mut bytes, 16, [self.family]);
        put(&mut bytes, 17, [self.key]);
        put(&mut bytes, 18, self.cluster_id.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 20]) -> Self {
        Self {
            address: take(&bytes, 0),
            family: take::<1, 20>(&bytes, 16)[0],
            key: take::<1, 20>(&bytes, 17)[0],
            cluster_id: u16::from_le_bytes(take(&bytes, 18)),
        }
    }
}

/// `EndpointInfo`: 48-byte map ABI layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct EndpointInfo {
    /// Byte offset 0.
    pub ifindex: u32,
    /// Byte offset 4.
    pub unused: u16,
    /// Byte offset 6.
    pub lxc_id: u16,
    /// Byte offset 8.
    pub flags: u32,
    /// Byte offset 12.
    pub rt_info: u32,
    /// Byte offset 16.
    pub mac: u64,
    /// Byte offset 24.
    pub node_mac: u64,
    /// Byte offset 32.
    pub sec_id: u32,
    /// Byte offset 36.
    pub parent_ifindex: u32,
    /// Byte offset 40.
    pub pad: [u32; 2],
}
impl MapBytes<48> for EndpointInfo {
    fn to_bytes(self) -> [u8; 48] {
        let mut bytes = [0; 48];
        put(&mut bytes, 0, self.ifindex.to_le_bytes());
        put(&mut bytes, 4, self.unused.to_le_bytes());
        put(&mut bytes, 6, self.lxc_id.to_le_bytes());
        put(&mut bytes, 8, self.flags.to_le_bytes());
        put(&mut bytes, 12, self.rt_info.to_le_bytes());
        put(&mut bytes, 16, self.mac.to_le_bytes());
        put(&mut bytes, 24, self.node_mac.to_le_bytes());
        put(&mut bytes, 32, self.sec_id.to_le_bytes());
        put(&mut bytes, 36, self.parent_ifindex.to_le_bytes());
        let [first, second] = self.pad;
        put(&mut bytes, 40, first.to_le_bytes());
        put(&mut bytes, 44, second.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 48]) -> Self {
        Self {
            ifindex: u32::from_le_bytes(take(&bytes, 0)),
            unused: u16::from_le_bytes(take(&bytes, 4)),
            lxc_id: u16::from_le_bytes(take(&bytes, 6)),
            flags: u32::from_le_bytes(take(&bytes, 8)),
            rt_info: u32::from_le_bytes(take(&bytes, 12)),
            mac: u64::from_le_bytes(take(&bytes, 16)),
            node_mac: u64::from_le_bytes(take(&bytes, 24)),
            sec_id: u32::from_le_bytes(take(&bytes, 32)),
            parent_ifindex: u32::from_le_bytes(take(&bytes, 36)),
            pad: [u32::from_le_bytes(take(&bytes, 40)), u32::from_le_bytes(take(&bytes, 44))],
        }
    }
}

/// `NodeKey`: 20-byte map ABI layout.
#[repr(C, align(4))]
#[derive(Clone, Copy, Default)]
pub struct NodeKey {
    /// Byte offset 0.
    pub pad1: u16,
    /// Byte offset 2.
    pub pad2: u8,
    /// Byte offset 3.
    pub family: u8,
    /// Byte offset 4.
    pub address: [u8; 16],
}
impl MapBytes<20> for NodeKey {
    fn to_bytes(self) -> [u8; 20] {
        let mut bytes = [0; 20];
        put(&mut bytes, 0, self.pad1.to_le_bytes());
        put(&mut bytes, 2, [self.pad2]);
        put(&mut bytes, 3, [self.family]);
        put(&mut bytes, 4, self.address);
        bytes
    }
    fn from_bytes(bytes: [u8; 20]) -> Self {
        Self {
            pad1: u16::from_le_bytes(take(&bytes, 0)),
            pad2: take::<1, 20>(&bytes, 2)[0],
            family: take::<1, 20>(&bytes, 3)[0],
            address: take(&bytes, 4),
        }
    }
}

/// `NodeValue`: 4-byte map ABI layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NodeValue {
    /// Byte offset 0.
    pub id: u16,
    /// Byte offset 2.
    pub spi: u8,
    /// Byte offset 3.
    pub pad: u8,
}
impl MapBytes<4> for NodeValue {
    fn to_bytes(self) -> [u8; 4] {
        let mut bytes = [0; 4];
        put(&mut bytes, 0, self.id.to_le_bytes());
        put(&mut bytes, 2, [self.spi]);
        put(&mut bytes, 3, [self.pad]);
        bytes
    }
    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self {
            id: u16::from_le_bytes(take(&bytes, 0)),
            spi: take::<1, 4>(&bytes, 2)[0],
            pad: take::<1, 4>(&bytes, 3)[0],
        }
    }
}

/// `SubnetKey`: 24-byte map ABI layout.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct SubnetKey {
    /// Byte offset 0.
    pub prefixlen: u32,
    /// Byte offset 4.
    pub pad0: u16,
    /// Byte offset 6.
    pub pad1: u8,
    /// Byte offset 7.
    pub family: u8,
    /// Byte offset 8.
    pub address: [u8; 16],
}
impl MapBytes<24> for SubnetKey {
    fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, self.prefixlen.to_le_bytes());
        put(&mut bytes, 4, self.pad0.to_le_bytes());
        put(&mut bytes, 6, [self.pad1]);
        put(&mut bytes, 7, [self.family]);
        put(&mut bytes, 8, self.address);
        bytes
    }
    fn from_bytes(bytes: [u8; 24]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&bytes, 0)),
            pad0: u16::from_le_bytes(take(&bytes, 4)),
            pad1: take::<1, 24>(&bytes, 6)[0],
            family: take::<1, 24>(&bytes, 7)[0],
            address: take(&bytes, 8),
        }
    }
}

/// `SubnetValue`: 4-byte map ABI layout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SubnetValue {
    /// Byte offset 0.
    pub identity: u32,
}
impl MapBytes<4> for SubnetValue {
    fn to_bytes(self) -> [u8; 4] {
        let mut bytes = [0; 4];
        put(&mut bytes, 0, self.identity.to_le_bytes());
        bytes
    }
    fn from_bytes(bytes: [u8; 4]) -> Self {
        Self {
            identity: u32::from_le_bytes(take(&bytes, 0)),
        }
    }
}

impl EndpointKey {
    /// IPv4 uses the first four union bytes; the remaining twelve are zero.
    pub fn v4(address: [u8; 4], key: u8, cluster_id: u16) -> Self {
        let mut full = [0; 16];
        put(&mut full, 0, address);
        Self { address: full, family: FAMILY_V4, key, cluster_id }
    }
    pub fn v6(address: [u8; 16], key: u8, cluster_id: u16) -> Self {
        Self { address, family: FAMILY_V6, key, cluster_id }
    }
    /// Packed multi-byte fields are exposed by value, never unaligned reference.
    pub fn cluster_id(self) -> u16 { self.cluster_id }
}
impl NodeKey {
    pub fn v4(address: [u8; 4]) -> Self {
        let mut full = [0; 16];
        put(&mut full, 0, address);
        Self { address: full, family: FAMILY_V4, ..Default::default() }
    }
    pub fn v6(address: [u8; 16]) -> Self {
        Self { address, family: FAMILY_V6, ..Default::default() }
    }
}
impl SubnetKey {
    /// Prefix counts 32 static padding/family bits plus CIDR bits. Host bits
    /// remain unchanged; address masking belongs to the IP-prefix owner.
    pub fn v4(address: [u8; 4], bits: u32) -> Result<Self, InvalidPrefix> {
        if bits > 32 { return Err(InvalidPrefix); }
        let mut full = [0; 16];
        put(&mut full, 0, address);
        Ok(Self { prefixlen: 32_u32.checked_add(bits).ok_or(InvalidPrefix)?, family: FAMILY_V4, address: full, ..Default::default() })
    }
    pub fn v6(address: [u8; 16], bits: u32) -> Result<Self, InvalidPrefix> {
        if bits > 128 { return Err(InvalidPrefix); }
        Ok(Self { prefixlen: 32_u32.checked_add(bits).ok_or(InvalidPrefix)?, family: FAMILY_V6, address, ..Default::default() })
    }
    pub fn prefixlen(self) -> u32 { self.prefixlen }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<EndpointKey>() == 20);
    assert!(align_of::<EndpointKey>() == 1);
    assert!(offset_of!(EndpointKey, address) == 0);
    assert!(offset_of!(EndpointKey, family) == 16);
    assert!(offset_of!(EndpointKey, key) == 17);
    assert!(offset_of!(EndpointKey, cluster_id) == 18);
    assert!(size_of::<EndpointInfo>() == 48);
    assert!(offset_of!(EndpointInfo, ifindex) == 0);
    assert!(offset_of!(EndpointInfo, unused) == 4);
    assert!(offset_of!(EndpointInfo, lxc_id) == 6);
    assert!(offset_of!(EndpointInfo, flags) == 8);
    assert!(offset_of!(EndpointInfo, rt_info) == 12);
    assert!(offset_of!(EndpointInfo, mac) == 16);
    assert!(offset_of!(EndpointInfo, node_mac) == 24);
    assert!(offset_of!(EndpointInfo, sec_id) == 32);
    assert!(offset_of!(EndpointInfo, parent_ifindex) == 36);
    assert!(offset_of!(EndpointInfo, pad) == 40);
    assert!(size_of::<NodeKey>() == 20);
    assert!(offset_of!(NodeKey, pad1) == 0);
    assert!(offset_of!(NodeKey, pad2) == 2);
    assert!(offset_of!(NodeKey, family) == 3);
    assert!(offset_of!(NodeKey, address) == 4);
    assert!(size_of::<NodeValue>() == 4);
    assert!(offset_of!(NodeValue, id) == 0);
    assert!(offset_of!(NodeValue, spi) == 2);
    assert!(offset_of!(NodeValue, pad) == 3);
    assert!(size_of::<SubnetKey>() == 24);
    assert!(align_of::<SubnetKey>() == 1);
    assert!(offset_of!(SubnetKey, prefixlen) == 0);
    assert!(offset_of!(SubnetKey, pad0) == 4);
    assert!(offset_of!(SubnetKey, pad1) == 6);
    assert!(offset_of!(SubnetKey, family) == 7);
    assert!(offset_of!(SubnetKey, address) == 8);
    assert!(size_of::<SubnetValue>() == 4);
    assert!(offset_of!(SubnetValue, identity) == 0);
    assert!(align_of::<EndpointInfo>() == 8);
    assert!(align_of::<NodeKey>() == 4);
};
