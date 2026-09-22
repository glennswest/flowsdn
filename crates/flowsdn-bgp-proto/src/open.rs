//! OPEN body codec and peer checks; family negotiation remains the caller's job.
use crate::{ErrorScope, ProtocolError};
use std::net::Ipv4Addr;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub code: u8,
    pub value: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Open {
    pub asn: u16,
    pub hold_time: u16,
    pub router_id: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}
fn error(subcode: u8) -> ProtocolError {
    ProtocolError {
        code: 2,
        subcode,
        scope: ErrorScope::Open,
    }
}
fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], ProtocolError> {
    let (value, rest) = bytes.split_at_checked(length).ok_or_else(|| error(4))?;
    *bytes = rest;
    Ok(value)
}
fn capability(code: u8, value: &[u8]) -> Result<(), ProtocolError> {
    let valid = match code {
        1 => value.len() == 4,
        2 => value.is_empty(),
        5 => !value.is_empty() && value.len().is_multiple_of(6),
        64 => value.len() >= 2 && value.len().saturating_sub(2).is_multiple_of(4),
        65 => value.len() == 4,
        _ => true,
    };
    if valid { Ok(()) } else { Err(error(4)) }
}
impl Open {
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        if body.len() < 10 {
            return Err(error(4));
        }
        if body.first() != Some(&4) {
            return Err(error(1));
        }
        let mut bytes = body.get(1..).ok_or_else(|| error(4))?;
        let asn = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().map_err(|_| error(4))?);
        let hold_time = u16::from_be_bytes(take(&mut bytes, 2)?.try_into().map_err(|_| error(4))?);
        if matches!(hold_time, 1 | 2) {
            return Err(error(6));
        }
        let router_id =
            Ipv4Addr::from(<[u8; 4]>::try_from(take(&mut bytes, 4)?).map_err(|_| error(4))?);
        let length = usize::from(*take(&mut bytes, 1)?.first().ok_or_else(|| error(4))?);
        if bytes.len() != length {
            return Err(error(4));
        }
        let mut capabilities = Vec::new();
        while !bytes.is_empty() {
            let kind = *take(&mut bytes, 1)?.first().ok_or_else(|| error(4))?;
            let length = usize::from(*take(&mut bytes, 1)?.first().ok_or_else(|| error(4))?);
            let mut parameter = take(&mut bytes, length)?;
            if kind != 2 {
                return Err(error(4));
            }
            while !parameter.is_empty() {
                let code = *take(&mut parameter, 1)?.first().ok_or_else(|| error(4))?;
                let length =
                    usize::from(*take(&mut parameter, 1)?.first().ok_or_else(|| error(4))?);
                let value = take(&mut parameter, length)?;
                capability(code, value)?;
                capabilities.push(Capability {
                    code,
                    value: value.to_vec(),
                });
            }
        }
        let result = Self {
            asn,
            hold_time,
            router_id,
            capabilities,
        };
        result.effective_asn()?;
        Ok(result)
    }
    pub fn effective_asn(&self) -> Result<u32, ProtocolError> {
        let mut four = None;
        for cap in self.capabilities.iter().filter(|cap| cap.code == 65) {
            let value = u32::from_be_bytes(cap.value.as_slice().try_into().map_err(|_| error(4))?);
            if four.is_some_and(|old| old != value) {
                return Err(error(4));
            }
            four = Some(value);
        }
        Ok(four.unwrap_or(u32::from(self.asn)))
    }
    pub fn validate_peer(
        &self,
        expected_asn: u32,
        local_router_id: Ipv4Addr,
        local_hold: u16,
    ) -> Result<u16, ProtocolError> {
        if expected_asn != 0 && self.effective_asn()? != expected_asn {
            return Err(error(2));
        }
        if self.router_id.is_unspecified() || self.router_id == local_router_id {
            return Err(error(3));
        }
        if matches!(self.hold_time, 1 | 2) || matches!(local_hold, 1 | 2) {
            return Err(error(6));
        }
        Ok(self.hold_time.min(local_hold))
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.effective_asn()?;
        if matches!(self.hold_time, 1 | 2) {
            return Err(error(6));
        }
        let mut params = Vec::new();
        for cap in &self.capabilities {
            capability(cap.code, &cap.value)?;
            let size = cap
                .value
                .len()
                .checked_add(2)
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| error(4))?;
            params.extend_from_slice(&[
                2,
                size,
                cap.code,
                u8::try_from(cap.value.len()).map_err(|_| error(4))?,
            ]);
            params.extend_from_slice(&cap.value);
        }
        let mut out = vec![4];
        out.extend_from_slice(&self.asn.to_be_bytes());
        out.extend_from_slice(&self.hold_time.to_be_bytes());
        out.extend_from_slice(&self.router_id.octets());
        out.push(u8::try_from(params.len()).map_err(|_| error(4))?);
        out.extend(params);
        Ok(out)
    }
}
