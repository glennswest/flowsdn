//! Parsed IP filtering: alternate IPv6 spellings identify the same address.
use std::{fmt, net::IpAddr, str::FromStr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidArgument(pub String);
impl fmt::Display for InvalidArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for InvalidArgument {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IpMatch {
    Address(IpAddr),
    Prefix { network: IpAddr, bits: u8 },
}

/// OR across entries. An explicitly empty list matches no addresses; absence
/// of an IP field is represented by None in FlowFilter, not by an empty set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpSet(Vec<IpMatch>);
impl IpSet {
    pub fn compile(entries: &[impl AsRef<str>]) -> Result<Self, InvalidArgument> {
        let mut output = Vec::with_capacity(entries.len());
        for entry in entries {
            let raw = entry.as_ref();
            let invalid = || InvalidArgument(format!("invalid IP address or prefix: {raw}"));
            let rule = if let Some((address, prefix)) = raw.split_once('/') {
                let address = IpAddr::from_str(address).map_err(|_| invalid())?;
                let bits = prefix.parse::<u8>().map_err(|_| invalid())?;
                if bits > if address.is_ipv4() { 32 } else { 128 } {
                    return Err(invalid());
                }
                IpMatch::Prefix {
                    network: address,
                    bits,
                }
            } else {
                IpMatch::Address(raw.parse().map_err(|_| invalid())?)
            };
            output.push(rule);
        }
        Ok(Self(output))
    }
    pub fn matches(&self, rendered: &str) -> bool {
        let Ok(address) = rendered.parse::<IpAddr>() else {
            return false;
        };
        self.0.iter().any(|rule| match rule {
            IpMatch::Address(expected) => *expected == address,
            IpMatch::Prefix { network, bits } => match (*network, address) {
                (IpAddr::V4(a), IpAddr::V4(b)) => {
                    let shift = 32u32.saturating_sub(u32::from(*bits));
                    u32::from(a).checked_shr(shift).unwrap_or(0)
                        == u32::from(b).checked_shr(shift).unwrap_or(0)
                }
                (IpAddr::V6(a), IpAddr::V6(b)) => {
                    let shift = 128u32.saturating_sub(u32::from(*bits));
                    u128::from(a).checked_shr(shift).unwrap_or(0)
                        == u128::from(b).checked_shr(shift).unwrap_or(0)
                }
                _ => false,
            },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Addresses<'a> {
    pub source: &'a str,
    pub destination: &'a str,
    pub translated_source: &'a str,
}
#[derive(Clone, Debug, Default)]
pub struct FlowFilter {
    pub source: Option<IpSet>,
    pub destination: Option<IpSet>,
    pub translated_source: Option<IpSet>,
}
impl FlowFilter {
    pub fn matches(&self, addresses: Addresses<'_>) -> bool {
        self.source
            .as_ref()
            .is_none_or(|f| f.matches(addresses.source))
            && self
                .destination
                .as_ref()
                .is_none_or(|f| f.matches(addresses.destination))
            && self
                .translated_source
                .as_ref()
                .is_none_or(|f| f.matches(addresses.translated_source))
    }
}
#[derive(Clone, Debug, Default)]
pub struct FilterSet {
    pub allow: Vec<FlowFilter>,
    pub deny: Vec<FlowFilter>,
}
impl FilterSet {
    /// None represents an in-band loss event, which cannot be filtered out.
    pub fn matches(&self, event: Option<Addresses<'_>>) -> bool {
        let Some(addresses) = event else {
            return true;
        };
        (self.allow.is_empty() || self.allow.iter().any(|f| f.matches(addresses)))
            && !self.deny.iter().any(|f| f.matches(addresses))
    }
}
/// An adapter must map this error to gRPC InvalidArgument before starting a
/// stream. No expression is silently ignored, including an empty expression.
pub fn validate_cel(expressions: &[impl AsRef<str>]) -> Result<(), InvalidArgument> {
    if expressions.is_empty() {
        Ok(())
    } else {
        Err(InvalidArgument(
            "unsupported filter: experimental.cel_expression".into(),
        ))
    }
}
