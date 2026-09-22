//! Typed auxiliary codecs. Message framing remains in the crate root.
use crate::{ErrorScope, ProtocolError, capabilities::Family};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Notification {
    pub code: u8,
    pub subcode: u8,
    pub data: Vec<u8>,
}
impl Notification {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut body = vec![self.code, self.subcode];
        body.extend_from_slice(&self.data);
        crate::encode(crate::Kind::Notification, &body)?;
        Ok(body)
    }
    pub fn decode(body: &[u8]) -> Result<Self, ProtocolError> {
        let Some((&code, rest)) = body.split_first() else {
            return Err(crate::framing(2));
        };
        let Some((&subcode, data)) = rest.split_first() else {
            return Err(crate::framing(2));
        };
        if body.len() > 4077 {
            return Err(crate::framing(2));
        }
        Ok(Self {
            code,
            subcode,
            data: data.to_vec(),
        })
    }
}
pub fn route_refresh(family: Family) -> Result<Vec<u8>, ProtocolError> {
    family.validate()?;
    let [a, b] = family.afi.to_be_bytes();
    Ok(vec![a, b, 0, family.safi])
}
pub fn decode_refresh(body: &[u8]) -> Result<Family, ProtocolError> {
    let [a, b, _, safi]: [u8; 4] = body.try_into().map_err(|_| ProtocolError {
        code: 7,
        subcode: 1,
        scope: ErrorScope::Framing,
    })?;
    let family = Family {
        afi: u16::from_be_bytes([a, b]),
        safi,
    };
    family.validate()?;
    Ok(family)
}
pub fn end_of_rib(family: Family) -> Result<Vec<u8>, ProtocolError> {
    family.validate()?;
    if family == Family::IPV4 {
        Ok(vec![0, 0, 0, 0])
    } else {
        let [a, b] = family.afi.to_be_bytes();
        Ok(vec![0, 0, 0, 6, 0x80, 15, 3, a, b, family.safi])
    }
}
impl Notification {
    /// RFC 8538 wraps the original cause, including its data, in Cease/9.
    /// Without bilateral N support retain the original legacy notification.
    pub fn hard_reset(self, notifications: bool) -> Result<Self, ProtocolError> {
        if !notifications {
            return Ok(self);
        }
        let data = self.encode()?;
        let wrapped = Self {
            code: 6,
            subcode: 9,
            data,
        };
        wrapped.encode()?;
        Ok(wrapped)
    }
    pub fn permits_graceful_restart(&self, notifications: bool) -> bool {
        notifications && !(self.code == 6 && self.subcode == 9)
    }
    pub fn unsupported_version() -> Self {
        Self {
            code: 2,
            subcode: 1,
            data: vec![0, 4],
        }
    }
}
