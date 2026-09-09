//! Map data layouts from map ABI specification §4.
//! No allocation, system calls, loader, or unsafe memory casts. Byte codecs are
//! explicit; integration with the future Aya loader remains separate.
#![no_std]

#[cfg(not(target_endian = "little"))]
compile_error!("the map ABI currently supports little-endian targets only");

/// Network-order port; array storage avoids unaligned integer references.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Be16(pub [u8; 2]);
impl Be16 {
    pub const fn new(value: u16) -> Self {
        Self(value.to_be_bytes())
    }
    pub const fn get(self) -> u16 {
        u16::from_be_bytes(self.0)
    }
}

/// Network-order IPv4 address or other 32-bit field.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Be32(pub [u8; 4]);
impl Be32 {
    pub const fn new(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
    pub const fn get(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

/// Lossless byte codec for one fixed-size map key or value. Decoding preserves
/// reserved bits and padding; constructors initialize their own reserved bytes.
pub trait MapBytes<const N: usize>: Sized {
    fn to_bytes(self) -> [u8; N];
    fn from_bytes(bytes: [u8; N]) -> Self;
}

pub mod affinity;
pub mod ct;
pub mod endpoint;
pub mod lb;
pub mod policy;

pub mod ct_flags {
    pub const OUT: u8 = 0;
    pub const IN: u8 = 1;
    pub const RELATED: u8 = 2;
    pub const SERVICE: u8 = 4;
}

/// Names follow the reference's mixed direction convention: addresses describe
/// the reply direction, while ports describe the original direction.
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv4CtTuple {
    pub daddr: Be32,
    pub saddr: Be32,
    pub dport: Be16,
    pub sport: Be16,
    pub nexthdr: u8,
    pub flags: u8,
}
impl MapBytes<14> for Ipv4CtTuple {
    fn to_bytes(self) -> [u8; 14] {
        let mut out = [0; 14];
        put(&mut out, 0, self.daddr.0);
        put(&mut out, 4, self.saddr.0);
        put(&mut out, 8, self.dport.0);
        put(&mut out, 10, self.sport.0);
        put(&mut out, 12, [self.nexthdr, self.flags]);
        out
    }
    fn from_bytes(b: [u8; 14]) -> Self {
        Self {
            daddr: Be32(take(&b, 0)),
            saddr: Be32(take(&b, 4)),
            dport: Be16(take(&b, 8)),
            sport: Be16(take(&b, 10)),
            nexthdr: take::<1, 14>(&b, 12)[0],
            flags: take::<1, 14>(&b, 13)[0],
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Ipv6CtTuple {
    pub daddr: [u8; 16],
    pub saddr: [u8; 16],
    pub dport: Be16,
    pub sport: Be16,
    pub nexthdr: u8,
    pub flags: u8,
}
impl MapBytes<38> for Ipv6CtTuple {
    fn to_bytes(self) -> [u8; 38] {
        let mut out = [0; 38];
        put(&mut out, 0, self.daddr);
        put(&mut out, 16, self.saddr);
        put(&mut out, 32, self.dport.0);
        put(&mut out, 34, self.sport.0);
        put(&mut out, 36, [self.nexthdr, self.flags]);
        out
    }
    fn from_bytes(b: [u8; 38]) -> Self {
        Self {
            daddr: take(&b, 0),
            saddr: take(&b, 16),
            dport: Be16(take(&b, 32)),
            sport: Be16(take(&b, 34)),
            nexthdr: take::<1, 38>(&b, 36)[0],
            flags: take::<1, 38>(&b, 37)[0],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidPrefix;

macro_rules! lpm_key {
    ($name:ident, $addr:literal, $size:literal, $bits:literal) => {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
        pub struct $name {
            pub prefixlen: u32,
            pub address: [u8; $addr],
        }
        impl $name {
            /// Prefix bits count only the address. Callers supply canonical
            /// prefix addresses; this raw ABI layer does not mask host bits.
            pub fn new(address: [u8; $addr], prefixlen: u32) -> Result<Self, InvalidPrefix> {
                if prefixlen > $bits {
                    return Err(InvalidPrefix);
                }
                Ok(Self { prefixlen, address })
            }
        }
        impl MapBytes<$size> for $name {
            fn to_bytes(self) -> [u8; $size] {
                let mut out = [0; $size];
                put(&mut out, 0, self.prefixlen.to_le_bytes());
                put(&mut out, 4, self.address);
                out
            }
            fn from_bytes(b: [u8; $size]) -> Self {
                Self {
                    prefixlen: u32::from_le_bytes(take(&b, 0)),
                    address: take(&b, 4),
                }
            }
        }
    };
}
lpm_key!(LpmV4Key, 4, 8, 32);
lpm_key!(LpmV6Key, 16, 20, 128);

pub const FAMILY_V4: u8 = 1;
pub const FAMILY_V6: u8 = 2;

/// Frozen ipcache key, including 32 static prefix bits before the address.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct IpCacheKey {
    pub prefixlen: u32,
    pub cluster_id: u16,
    pub pad: u8,
    pub family: u8,
    pub address: [u8; 16],
}
impl IpCacheKey {
    pub fn v4(address: [u8; 4], bits: u32, cluster_id: u16) -> Result<Self, InvalidPrefix> {
        if bits > 32 {
            return Err(InvalidPrefix);
        }
        let mut full = [0; 16];
        put(&mut full, 0, address);
        Self::make(full, bits, cluster_id, FAMILY_V4)
    }
    pub fn v6(address: [u8; 16], bits: u32, cluster_id: u16) -> Result<Self, InvalidPrefix> {
        if bits > 128 {
            return Err(InvalidPrefix);
        }
        Self::make(address, bits, cluster_id, FAMILY_V6)
    }
    fn make(
        address: [u8; 16],
        bits: u32,
        cluster_id: u16,
        family: u8,
    ) -> Result<Self, InvalidPrefix> {
        Ok(Self {
            prefixlen: 32u32.checked_add(bits).ok_or(InvalidPrefix)?,
            cluster_id,
            pad: 0,
            family,
            address,
        })
    }
    pub fn prefixlen(self) -> u32 {
        self.prefixlen
    }
    pub fn cluster_id(self) -> u16 {
        self.cluster_id
    }
}
impl MapBytes<24> for IpCacheKey {
    fn to_bytes(self) -> [u8; 24] {
        let mut out = [0; 24];
        put(&mut out, 0, self.prefixlen.to_le_bytes());
        put(&mut out, 4, self.cluster_id.to_le_bytes());
        put(&mut out, 6, [self.pad, self.family]);
        put(&mut out, 8, self.address);
        out
    }
    fn from_bytes(b: [u8; 24]) -> Self {
        Self {
            prefixlen: u32::from_le_bytes(take(&b, 0)),
            cluster_id: u16::from_le_bytes(take(&b, 4)),
            pad: take::<1, 24>(&b, 6)[0],
            family: take::<1, 24>(&b, 7)[0],
            address: take(&b, 8),
        }
    }
}

pub mod remote_flags {
    pub const SKIP_TUNNEL: u8 = 1;
    pub const HAS_TUNNEL_ENDPOINT: u8 = 2;
    pub const IPV6_TUNNEL_ENDPOINT: u8 = 4;
    pub const REMOTE_CLUSTER: u8 = 8;
}

/// Frozen ipcache value. Tunnel addresses are network bytes; identity is LE.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteEndpointInfo {
    pub sec_identity: u32,
    pub tunnel_endpoint: [u8; 16],
    pub pad: u16,
    pub key: u8,
    pub flags: u8,
}
impl MapBytes<24> for RemoteEndpointInfo {
    fn to_bytes(self) -> [u8; 24] {
        let mut out = [0; 24];
        put(&mut out, 0, self.sec_identity.to_le_bytes());
        put(&mut out, 4, self.tunnel_endpoint);
        put(&mut out, 20, self.pad.to_le_bytes());
        put(&mut out, 22, [self.key, self.flags]);
        out
    }
    fn from_bytes(b: [u8; 24]) -> Self {
        Self {
            sec_identity: u32::from_le_bytes(take(&b, 0)),
            tunnel_endpoint: take(&b, 4),
            pad: u16::from_le_bytes(take(&b, 20)),
            key: take::<1, 24>(&b, 22)[0],
            flags: take::<1, 24>(&b, 23)[0],
        }
    }
}

fn put<const N: usize, const M: usize>(out: &mut [u8; N], offset: usize, bytes: [u8; M]) {
    let end = offset.checked_add(M).expect("fixed ABI field offset");
    out.get_mut(offset..end)
        .expect("fixed ABI field fits")
        .copy_from_slice(&bytes);
}
fn take<const M: usize, const N: usize>(input: &[u8; N], offset: usize) -> [u8; M] {
    let end = offset.checked_add(M).expect("fixed ABI field offset");
    input
        .get(offset..end)
        .expect("fixed ABI field fits")
        .try_into()
        .expect("fixed ABI field length")
}

// These assertions compile for every target, including cross-target checks.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<Ipv4CtTuple>() == 14 && align_of::<Ipv4CtTuple>() == 1);
    assert!(size_of::<Ipv6CtTuple>() == 38 && align_of::<Ipv6CtTuple>() == 1);
    assert!(offset_of!(Ipv4CtTuple, dport) == 8 && offset_of!(Ipv4CtTuple, flags) == 13);
    assert!(offset_of!(Ipv6CtTuple, dport) == 32 && offset_of!(Ipv6CtTuple, flags) == 37);
    assert!(size_of::<LpmV4Key>() == 8 && size_of::<LpmV6Key>() == 20);
    assert!(offset_of!(LpmV4Key, address) == 4 && offset_of!(LpmV6Key, address) == 4);
    assert!(size_of::<IpCacheKey>() == 24 && align_of::<IpCacheKey>() == 1);
    assert!(
        offset_of!(IpCacheKey, cluster_id) == 4
            && offset_of!(IpCacheKey, family) == 7
            && offset_of!(IpCacheKey, address) == 8
    );
    assert!(size_of::<RemoteEndpointInfo>() == 24 && align_of::<RemoteEndpointInfo>() == 4);
    assert!(
        offset_of!(RemoteEndpointInfo, tunnel_endpoint) == 4
            && offset_of!(RemoteEndpointInfo, key) == 22
    );
};
