//! UPDATE structural validation for the supported unicast receive subset.
//! Successful validation is not permission to install a route.
use crate::{ErrorScope, ProtocolError};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
fn error(subcode: u8, structural: bool) -> ProtocolError {
    ProtocolError {
        code: 3,
        subcode,
        scope: if structural {
            ErrorScope::AttributeStructure
        } else {
            ErrorScope::UpdateContent
        },
    }
}
fn take<'a>(
    input: &mut &'a [u8],
    length: usize,
    subcode: u8,
    structural: bool,
) -> Result<&'a [u8], ProtocolError> {
    let (value, rest) = input
        .split_at_checked(length)
        .ok_or_else(|| error(subcode, structural))?;
    *input = rest;
    Ok(value)
}
fn byte(input: &mut &[u8], subcode: u8, structural: bool) -> Result<u8, ProtocolError> {
    Ok(*take(input, 1, subcode, structural)?
        .first()
        .ok_or_else(|| error(subcode, structural))?)
}
fn short(input: &mut &[u8], subcode: u8, structural: bool) -> Result<u16, ProtocolError> {
    Ok(u16::from_be_bytes(
        take(input, 2, subcode, structural)?
            .try_into()
            .map_err(|_| error(subcode, structural))?,
    ))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Prefix {
    address: IpAddr,
    bits: u8,
}
impl Prefix {
    pub fn new(address: IpAddr, bits: u8) -> Result<Self, ProtocolError> {
        let width = if address.is_ipv4() { 32 } else { 128 };
        if bits > width {
            return Err(error(10, false));
        }
        let shift = u32::from(width.saturating_sub(bits));
        let address = match address {
            IpAddr::V4(ip) => Ipv4Addr::from(
                u32::from(ip)
                    .checked_shr(shift)
                    .unwrap_or(0)
                    .checked_shl(shift)
                    .unwrap_or(0),
            )
            .into(),
            IpAddr::V6(ip) => Ipv6Addr::from(
                u128::from(ip)
                    .checked_shr(shift)
                    .unwrap_or(0)
                    .checked_shl(shift)
                    .unwrap_or(0),
            )
            .into(),
        };
        Ok(Self { address, bits })
    }
    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn bits(self) -> u8 {
        self.bits
    }
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = vec![self.bits];
        let length = usize::from(self.bits).div_ceil(8);
        match self.address {
            IpAddr::V4(ip) => {
                bytes.extend_from_slice(ip.octets().get(..length).expect("validated prefix"))
            }
            IpAddr::V6(ip) => {
                bytes.extend_from_slice(ip.octets().get(..length).expect("validated prefix"))
            }
        }
        bytes
    }
}
pub fn prefixes(mut bytes: &[u8], ipv6: bool) -> Result<Vec<Prefix>, ProtocolError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let bits = byte(&mut bytes, 10, false)?;
        if bits > if ipv6 { 128 } else { 32 } {
            return Err(error(10, false));
        }
        let payload = take(&mut bytes, usize::from(bits).div_ceil(8), 10, false)?;
        let address = if ipv6 {
            let mut ip = [0; 16];
            ip.get_mut(..payload.len())
                .expect("prefix bound")
                .copy_from_slice(payload);
            IpAddr::V6(Ipv6Addr::from(ip))
        } else {
            let mut ip = [0; 4];
            ip.get_mut(..payload.len())
                .expect("prefix bound")
                .copy_from_slice(payload);
            IpAddr::V4(Ipv4Addr::from(ip))
        };
        result.push(Prefix::new(address, bits)?);
    }
    Ok(result)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownTransitive {
    pub flags: u8,
    pub code: u8,
    pub value: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub withdrawn: Vec<Prefix>,
    pub announced: Vec<Prefix>,
    pub mp_announced: Vec<Prefix>,
    pub mp_withdrawn: Vec<Prefix>,
    pub unknown_transitive: Vec<UnknownTransitive>,
}
fn as_path(mut value: &[u8], width: usize) -> Result<(), ProtocolError> {
    while !value.is_empty() {
        let segment = byte(&mut value, 11, false)?;
        let count = byte(&mut value, 11, false)?;
        if !matches!(segment, 1 | 2) || count == 0 {
            return Err(error(11, false));
        }
        take(
            &mut value,
            usize::from(count)
                .checked_mul(width)
                .ok_or_else(|| error(11, false))?,
            11,
            false,
        )?;
    }
    Ok(())
}
fn mp(value: &[u8], reach: bool) -> Result<Vec<Prefix>, ProtocolError> {
    let mut bytes = value;
    let afi = short(&mut bytes, 9, false)?;
    let safi = byte(&mut bytes, 9, false)?;
    if !matches!(afi, 1 | 2) || safi != 1 {
        return Err(error(9, false));
    }
    if reach {
        let length = usize::from(byte(&mut bytes, 9, false)?);
        if !matches!(length, 4 | 16 | 32) || (afi == 2 && length == 4) {
            return Err(error(9, false));
        }
        take(&mut bytes, length, 9, false)?;
        byte(&mut bytes, 9, false)?;
    }
    prefixes(bytes, afi == 2)
}
/// `four_octet_asn` is the negotiated AS_PATH width, not a guess from the bytes.
/// Outer lengths and attribute TLVs are always fatal when malformed; bounded
/// semantic errors follow the strict/lenient policy in error_action.
pub fn validate(body: &[u8], four_octet_asn: bool) -> Result<Summary, ProtocolError> {
    if body.len() > crate::MAX_MESSAGE_LENGTH.saturating_sub(crate::HEADER_LENGTH) {
        return Err(crate::framing(2));
    }
    let mut bytes = body;
    let withdrawn_length = usize::from(short(&mut bytes, 1, true)?);
    let withdrawn_bytes = take(&mut bytes, withdrawn_length, 1, true)?;
    let attribute_length = usize::from(short(&mut bytes, 1, true)?);
    let mut attributes = take(&mut bytes, attribute_length, 1, true)?;
    // Validate every enclosing length/TLV before interpreting any prefix or
    // attribute. An early content error must not mask a later fatal boundary
    // failure in lenient mode. Allocation is bounded by the message-size cap.
    let mut fields = Vec::new();
    while !attributes.is_empty() {
        let flags = byte(&mut attributes, 1, true)?;
        let code = byte(&mut attributes, 1, true)?;
        let length = if flags & 0x10 != 0 {
            usize::from(short(&mut attributes, 5, true)?)
        } else {
            usize::from(byte(&mut attributes, 5, true)?)
        };
        fields.push((flags, code, take(&mut attributes, length, 5, true)?));
    }
    let withdrawn = prefixes(withdrawn_bytes, false)?;
    let announced = prefixes(bytes, false)?;
    let mut result = Summary {
        withdrawn,
        announced,
        mp_announced: Vec::new(),
        mp_withdrawn: Vec::new(),
        unknown_transitive: Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for (flags, code, value) in fields {
        if !seen.insert(code) {
            return Err(error(1, false));
        }
        if flags & 0x20 != 0 && flags & 0xc0 != 0xc0 {
            return Err(error(4, false));
        }
        let expected = match code {
            1 | 2 | 3 | 5 | 6 => Some(0x40),
            4 | 14 | 15 => Some(0x80),
            7 | 8 | 17 | 18 | 32 => Some(0xc0),
            _ => None,
        };
        if let Some(expected) = expected {
            if flags & 0xc0 != expected || (flags & 0x20 != 0 && expected != 0xc0) {
                return Err(error(4, false));
            }
        } else {
            if flags & 0x80 == 0 {
                return Err(error(2, false));
            }
            if flags & 0x40 != 0 {
                result.unknown_transitive.push(UnknownTransitive {
                    flags: flags | 0x20,
                    code,
                    value: value.to_vec(),
                });
            }
            continue;
        }
        match code {
            1 => {
                if value.len() != 1 {
                    return Err(error(5, false));
                }
                if value.first().is_none_or(|v| *v > 2) {
                    return Err(error(6, false));
                }
            }
            2 => as_path(value, if four_octet_asn { 4 } else { 2 })?,
            17 => as_path(value, 4)?,
            3 => {
                let ip = Ipv4Addr::from(<[u8; 4]>::try_from(value).map_err(|_| error(5, false))?);
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                    return Err(error(8, false));
                }
            }
            4 | 5 if value.len() != 4 => {
                return Err(error(5, false));
            }
            6 if !value.is_empty() => {
                return Err(error(5, false));
            }
            7 if value.len() != if four_octet_asn { 8 } else { 6 } => {
                return Err(error(5, false));
            }
            18 if value.len() != 8 => {
                return Err(error(5, false));
            }
            8 if !value.len().is_multiple_of(4) => {
                return Err(error(5, false));
            }
            32 if !value.len().is_multiple_of(12) => {
                return Err(error(5, false));
            }
            14 => result.mp_announced = mp(value, true)?,
            15 => result.mp_withdrawn = mp(value, false)?,
            _ => {}
        }
    }
    if (!result.announced.is_empty() || !result.mp_announced.is_empty())
        && (!seen.contains(&1) || !seen.contains(&2))
    {
        return Err(error(3, false));
    }
    if !result.announced.is_empty() && !seen.contains(&3) {
        return Err(error(3, false));
    }
    Ok(result)
}
