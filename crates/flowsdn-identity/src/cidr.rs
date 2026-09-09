//! Canonical CIDR label keys and CIDR-only selector containment (spec 03 §4.1).
//! World-label selection, general label matching and allocation belong to callers.
use crate::labels::Label;
use alloc::string::{String, ToString};
use core::{fmt, net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CidrError {
    InvalidPrefix,
    InvalidAddress,
    InvalidLength,
    InvalidLabel,
    EncodedKeyTooLong,
}
impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPrefix => "CIDR prefix must contain an address and decimal prefix length",
            Self::InvalidAddress => "invalid CIDR IP address",
            Self::InvalidLength => "CIDR prefix length exceeds its address family",
            Self::InvalidLabel => "CIDR matching requires source cidr and an empty label value",
            Self::EncodedKeyTooLong => "encoded CIDR key exceeds 64 bytes",
        })
    }
}
impl core::error::Error for CidrError {}

/// A family-preserving network prefix, with all host bits cleared.
/// IPv4-mapped IPv6 remains IPv6 and never matches an IPv4 prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CidrPrefix { network: IpAddr, length: u8 }
impl CidrPrefix {
    pub fn new(address: IpAddr, length: u8) -> Result<Self, CidrError> {
        let network = match address {
            IpAddr::V4(address) => {
                if length > 32 { return Err(CidrError::InvalidLength); }
                let mask = u32::MAX.checked_shl(32_u32.saturating_sub(u32::from(length))).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) => {
                if length > 128 { return Err(CidrError::InvalidLength); }
                let mask = u128::MAX.checked_shl(128_u32.saturating_sub(u32::from(length))).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
        };
        Ok(Self { network, length })
    }
    pub const fn network(self) -> IpAddr { self.network }
    pub const fn prefix_len(self) -> u8 { self.length }
    pub const fn is_world(self) -> bool { self.length == 0 }

    /// Canonical encoded key without the `cidr:` source prefix. A /0 key can
    /// be decoded for selector use; `to_label` omits it from identity labels.
    pub fn encoded_key(self) -> String {
        let address = self.network.to_string();
        let mut key = String::new();
        if address.starts_with(':') { key.push('0'); }
        for ch in address.chars() { key.push(if ch == ':' { '-' } else { ch }); }
        if address.ends_with(':') { key.push('0'); }
        key.push('/');
        key.push_str(&self.length.to_string());
        key
    }

    /// Decode a label key, then mask host bits and normalize the prefix.
    /// Both encoded IPv6 keys and decoded textual prefixes are accepted.
    pub fn decode_key(key: &str) -> Result<Self, CidrError> {
        if key.len() > 64 { return Err(CidrError::EncodedKeyTooLong); }
        key.replace('-', ":").parse()
    }

    pub fn from_label(label: &Label) -> Result<Self, CidrError> {
        if label.source() != "cidr" || !label.value().is_empty() { return Err(CidrError::InvalidLabel); }
        Self::decode_key(label.key())
    }

    /// /0 contributes only a caller-selected world label, never a CIDR label.
    /// This method therefore returns None for either family's /0.
    pub fn to_label(self) -> Option<Label> {
        if self.is_world() { None }
        else { Some(Label::new("cidr", &self.encoded_key(), "").expect("canonical CIDR key is nonempty")) }
    }

    pub fn contains_address(self, address: IpAddr) -> bool {
        if self.network.is_ipv4() != address.is_ipv4() { return false; }
        Self::new(address, self.length).is_ok_and(|prefix| prefix.network == self.network)
    }

    /// Match a CIDR selector against another CIDR prefix, preserving family.
    pub fn contains_prefix(self, candidate: Self) -> bool {
        self.length <= candidate.length && self.contains_address(candidate.network)
    }
}
impl FromStr for CidrPrefix {
    type Err = CidrError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, length) = text.split_once('/').ok_or(CidrError::InvalidPrefix)?;
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CidrError::InvalidPrefix);
        }
        let length = length.parse::<u8>().map_err(|_| CidrError::InvalidLength)?;
        let address = address.parse::<IpAddr>().map_err(|_| CidrError::InvalidAddress)?;
        Self::new(address, length)
    }
}
impl fmt::Display for CidrPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}/{}", self.network, self.length) }
}

/// CIDR-specific label relation only. Non-CIDR labels return an error instead
/// of acquiring generic source wildcard or label-selector semantics.
pub fn cidr_selector_matches(selector: &Label, candidate: &Label) -> Result<bool, CidrError> {
    Ok(CidrPrefix::from_label(selector)?.contains_prefix(CidrPrefix::from_label(candidate)?))
}
