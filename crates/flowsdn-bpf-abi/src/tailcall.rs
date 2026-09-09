//! Frozen tail program slots from datapath specification §2.6.
//! Slots zero and three are reserved. Aliases for different hook families share
//! one numeric value; policy arrays indexed by endpoint ID are separate.
use core::fmt;

pub const CALL_SIZE: u32 = 50;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTailSlot(pub u32);
impl fmt::Display for InvalidTailSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported or reserved tail-call slot {}", self.0)
    }
}
impl core::error::Error for InvalidTailSlot {}

macro_rules! slots {
    ($($name:ident = $number:literal),+ $(,)?) => {
        #[repr(u32)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum TailSlot { $($name = $number),+ }
        pub const SLOTS: &[TailSlot] = &[$(TailSlot::$name),+];
        impl TailSlot {
            pub const fn number(self) -> u32 { self as u32 }
            pub const fn from_number(number: u32) -> Result<Self, InvalidTailSlot> {
                match number { $($number => Ok(Self::$name)),+, _ => Err(InvalidTailSlot(number)) }
            }
        }
        impl TryFrom<u32> for TailSlot {
            type Error = InvalidTailSlot;
            fn try_from(number: u32) -> Result<Self, Self::Error> { Self::from_number(number) }
        }
    };
}
slots! {
    DropNotify = 1, ErrorNotify = 2,
    HandleIcmp6Ns = 4, SendIcmp6TimeExceeded = 5, Arp = 6,
    Ipv4FromLxc = 7, Ipv46Rfc6052 = 8, Ipv64Rfc6052 = 9,
    Ipv6FromLxc = 10, Ipv4ToLxcPolicyOnly = 11, Ipv6ToLxcPolicyOnly = 12,
    Ipv4ToEndpoint = 13, Ipv6ToEndpoint = 14,
    Ipv4NodeportNatEgress = 15, Ipv6NodeportNatEgress = 16,
    Ipv4NodeportRevnat = 17, Ipv6NodeportRevnatIngress = 18,
    Ipv6NodeportRevnatEgress = 19, Ipv4NodeportNatFwd = 20,
    Ipv4NodeportDsr = 21, Ipv6NodeportDsr = 22,
    Ipv4FromHost = 23, Ipv6FromHost = 24, Ipv6NodeportNatFwd = 25,
    Ipv4FromLxcCont = 26, Ipv6FromLxcCont = 27,
    Ipv4CtIngress = 28, Ipv4CtIngressPolicyOnly = 29, Ipv4CtEgress = 30,
    Ipv6CtIngress = 31, Ipv6CtIngressPolicyOnly = 32, Ipv6CtEgress = 33,
    Srv6Encap = 34, Srv6Decap = 35,
    Ipv4NodeportNatIngress = 36, Ipv6NodeportNatIngress = 37,
    Ipv4NodeportSnatFwd = 38, Ipv6NodeportSnatFwd = 39,
    Ipv4InterClusterRevsnat = 40, Ipv4ContFromHost = 41,
    Ipv4ContFromNetdev = 42, Ipv6ContFromHost = 43, Ipv6ContFromNetdev = 44,
    Ipv4NoService = 45, Ipv6NoService = 46, MulticastEpDelivery = 47,
    Ipv4PolicyDenied = 48, Ipv6PolicyDenied = 49,
}
