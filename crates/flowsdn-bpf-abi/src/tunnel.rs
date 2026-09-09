//! Fixed overlay wire codecs from datapath specification §2.5.
//! These validate individual headers/options, not packets, option chains, or
//! peer authorization. No IP/UDP parsing or checksum calculation is performed.
use crate::{put, take};

pub const VXLAN_PORT: u16 = 8472;
pub const GENEVE_PORT: u16 = 6081;
pub const ETHERNET_PROTOCOL: u16 = 0x6558;
pub const DSR_CLASS: u16 = 0x014b;
pub const DSR_TYPE: u8 = 0x81;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Length,
    IdentityTooWide,
    HostIdentity,
    Reserved,
    Unsupported,
}

/// Validated 24-bit wire identity. Reserved numeric values retain their ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TunnelIdentity(u32);
impl TunnelIdentity {
    /// Apply the required HOST and WORLD rewrites before encapsulation.
    pub fn for_encapsulation(identity: u32) -> Result<Self, WireError> {
        let identity = match identity {
            1 => 6,
            9 | 10 => 2,
            other => other,
        };
        Self::from_wire(identity)
    }
    /// Received HOST is invalid; this does not authorize the received identity.
    pub fn from_wire(identity: u32) -> Result<Self, WireError> {
        if identity > 0x00ff_ffff {
            return Err(WireError::IdentityTooWide);
        }
        if identity == 1 {
            return Err(WireError::HostIdentity);
        }
        Ok(Self(identity))
    }
    pub const fn get(self) -> u32 {
        self.0
    }
    /// Re-split WORLD on dual-stack decapsulation using the inner IP family.
    pub const fn for_decapsulation(self, family: IpFamily, dual_stack: bool) -> u32 {
        if self.0 == 2 && dual_stack {
            match family {
                IpFamily::V4 => 9,
                IpFamily::V6 => 10,
            }
        } else {
            self.0
        }
    }
    fn word(self) -> [u8; 4] {
        (self.0 << 8).to_be_bytes()
    }
    fn decode(word: [u8; 4]) -> Result<Self, WireError> {
        let [_, _, _, reserved] = word;
        if reserved != 0 {
            return Err(WireError::Reserved);
        }
        Self::from_wire(u32::from_be_bytes(word) >> 8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Ordinary VXLAN with the I flag set; extensions are outside this codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VxlanHeader {
    pub identity: TunnelIdentity,
}
impl VxlanHeader {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        put(&mut bytes, 0, [8, 0, 0, 0]);
        put(&mut bytes, 4, self.identity.word());
        bytes
    }
    pub fn from_bytes(bytes: [u8; 8]) -> Result<Self, WireError> {
        if take::<4, 8>(&bytes, 0) != [8, 0, 0, 0] {
            return Err(WireError::Unsupported);
        }
        Ok(Self {
            identity: TunnelIdentity::decode(take(&bytes, 4))?,
        })
    }
}

/// Version-zero Ethernet Geneve base header, excluding its option bytes.
/// The caller must validate that the packet contains `option_words * 4` bytes
/// of valid options. Both settings of the base critical flag are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneveHeader {
    pub identity: TunnelIdentity,
    option_words: u8,
    pub critical: bool,
}
impl GeneveHeader {
    pub fn new(
        identity: TunnelIdentity,
        option_words: u8,
        critical: bool,
    ) -> Result<Self, WireError> {
        if option_words > 63 {
            return Err(WireError::Length);
        }
        Ok(Self {
            identity,
            option_words,
            critical,
        })
    }
    pub const fn option_words(self) -> u8 {
        self.option_words
    }
    pub fn to_bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        put(
            &mut bytes,
            0,
            [self.option_words, u8::from(self.critical) << 6],
        );
        put(&mut bytes, 2, ETHERNET_PROTOCOL.to_be_bytes());
        put(&mut bytes, 4, self.identity.word());
        bytes
    }
    pub fn from_bytes(bytes: [u8; 8]) -> Result<Self, WireError> {
        let [version_length, flags] = take(&bytes, 0);
        if version_length & 0xc0 != 0
            || flags & 0x80 != 0
            || u16::from_be_bytes(take(&bytes, 2)) != ETHERNET_PROTOCOL
        {
            return Err(WireError::Unsupported);
        }
        if flags & 0x3f != 0 {
            return Err(WireError::Reserved);
        }
        Self::new(
            TunnelIdentity::decode(take(&bytes, 4))?,
            version_length,
            flags & 0x40 != 0,
        )
    }
}

/// The single known DSR option payload for IPv4 (header included: 12 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DsrIpv4 {
    pub address: [u8; 4],
    pub port: u16,
}
impl DsrIpv4 {
    pub fn to_bytes(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        put(&mut bytes, 0, [0x01, 0x4b, DSR_TYPE, 2]);
        put(&mut bytes, 4, self.address);
        put(&mut bytes, 8, self.port.to_be_bytes());
        bytes
    }
    pub fn from_bytes(bytes: [u8; 12]) -> Result<Self, WireError> {
        validate_option(take(&bytes, 0), 2, take(&bytes, 10))?;
        Ok(Self {
            address: take(&bytes, 4),
            port: u16::from_be_bytes(take(&bytes, 8)),
        })
    }
}

/// The single known DSR option payload for IPv6 (header included: 24 bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DsrIpv6 {
    pub address: [u8; 16],
    pub port: u16,
}
impl DsrIpv6 {
    pub fn to_bytes(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, [0x01, 0x4b, DSR_TYPE, 5]);
        put(&mut bytes, 4, self.address);
        put(&mut bytes, 20, self.port.to_be_bytes());
        bytes
    }
    pub fn from_bytes(bytes: [u8; 24]) -> Result<Self, WireError> {
        validate_option(take(&bytes, 0), 5, take(&bytes, 22))?;
        Ok(Self {
            address: take(&bytes, 4),
            port: u16::from_be_bytes(take(&bytes, 20)),
        })
    }
}
fn validate_option(header: [u8; 4], words: u8, padding: [u8; 2]) -> Result<(), WireError> {
    let [class_hi, class_lo, kind, length] = header;
    if u16::from_be_bytes([class_hi, class_lo]) != DSR_CLASS || kind != DSR_TYPE {
        return Err(WireError::Unsupported);
    }
    if length & 0xe0 != 0 || padding != [0; 2] {
        return Err(WireError::Reserved);
    }
    if length != words {
        return Err(WireError::Length);
    }
    Ok(())
}
