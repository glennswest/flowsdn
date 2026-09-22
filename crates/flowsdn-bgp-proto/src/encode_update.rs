//! Export encoding for resolved unicast paths. This does not select routes,
//! implement AS_SET/confederation aggregation or reconstruct inbound AS4 paths.
use crate::{
    ErrorScope, ProtocolError,
    capabilities::Family,
    update::{self, Prefix},
};
use std::net::IpAddr;
fn error() -> ProtocolError {
    ProtocolError {
        code: 3,
        subcode: 9,
        scope: ErrorScope::UpdateContent,
    }
}
#[derive(Clone, Debug)]
pub struct Export {
    pub family: Family,
    pub next_hop: IpAddr,
    pub local_asn: u32,
    pub external: bool,
    pub four_octet_asn: bool,
    pub as_sequence: Vec<u32>,
    pub local_preference: u32,
    pub origin: u8,
}
fn attribute(out: &mut Vec<u8>, flags: u8, code: u8, value: &[u8]) -> Result<(), ProtocolError> {
    if value.len() > 255 {
        out.extend_from_slice(&[flags | 0x10, code]);
        out.extend_from_slice(
            &u16::try_from(value.len())
                .map_err(|_| error())?
                .to_be_bytes(),
        );
    } else {
        out.extend_from_slice(&[
            flags & !0x10,
            code,
            u8::try_from(value.len()).map_err(|_| error())?,
        ]);
    }
    out.extend_from_slice(value);
    Ok(())
}
fn path(sequence: &[u32], four: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for segment in sequence.chunks(255) {
        out.extend_from_slice(&[2, u8::try_from(segment.len()).expect("segment bounded")]);
        for asn in segment {
            if four {
                out.extend_from_slice(&asn.to_be_bytes());
            } else {
                out.extend_from_slice(&u16::try_from(*asn).unwrap_or(23456).to_be_bytes());
            }
        }
    }
    out
}
impl Export {
    fn attributes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.family.validate()?;
        if self.local_asn == 0
            || self.origin > 2
            || self.as_sequence.contains(&0)
            || self.as_sequence.len() > 1024
        {
            return Err(error());
        }
        let mut sequence = self.as_sequence.clone();
        if self.external {
            sequence.insert(0, self.local_asn);
        }
        let mut attrs = Vec::new();
        attribute(&mut attrs, 0x40, 1, &[self.origin])?;
        attribute(&mut attrs, 0x40, 2, &path(&sequence, self.four_octet_asn))?;
        if !self.four_octet_asn && sequence.iter().any(|asn| *asn > 65535) {
            attribute(&mut attrs, 0xc0, 17, &path(&sequence, true))?;
        }
        if !self.external {
            attribute(&mut attrs, 0x40, 5, &self.local_preference.to_be_bytes())?;
        }
        if let IpAddr::V4(ip) = self.next_hop {
            if self.family != Family::IPV4
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
            {
                return Err(error());
            }
            attribute(&mut attrs, 0x40, 3, &ip.octets())?;
        } else if self.next_hop.is_unspecified() || self.next_hop.is_multicast() {
            return Err(error());
        }
        Ok(attrs)
    }
    fn body(&self, base: &[u8], prefixes: &[Prefix]) -> Result<Vec<u8>, ProtocolError> {
        let mut nlri = Vec::new();
        for prefix in prefixes {
            nlri.extend(prefix.encode());
        }
        let mut attrs = base.to_vec();
        let legacy = self.family == Family::IPV4 && self.next_hop.is_ipv4();
        if !legacy {
            let IpAddr::V6(ip) = self.next_hop else {
                return Err(error());
            };
            let mut reach = self.family.afi.to_be_bytes().to_vec();
            reach.extend_from_slice(&[self.family.safi, 16]);
            reach.extend_from_slice(&ip.octets());
            reach.push(0);
            reach.extend_from_slice(&nlri);
            attribute(&mut attrs, 0x80, 14, &reach)?;
        }
        let mut body = vec![0, 0];
        body.extend_from_slice(
            &u16::try_from(attrs.len())
                .map_err(|_| error())?
                .to_be_bytes(),
        );
        body.extend(attrs);
        if legacy {
            body.extend(nlri);
        }
        Ok(body)
    }
    /// Split only at NLRI boundaries; each frame receives a complete attribute
    /// set. IPv4-over-IPv6 callers must first negotiate Extended Next Hop.
    pub fn announcements(&self, prefixes: &[Prefix]) -> Result<Vec<Vec<u8>>, ProtocolError> {
        let base = self.attributes()?;
        if self.body(&base, &[])?.len() > 4077 {
            return Err(crate::framing(2));
        }
        if prefixes
            .iter()
            .any(|p| p.address().is_ipv4() != (self.family == Family::IPV4))
        {
            return Err(error());
        }
        let mut output = Vec::new();
        let mut batch = Vec::new();
        for prefix in prefixes {
            batch.push(*prefix);
            if self.body(&base, &batch)?.len() > 4077 {
                batch.pop();
                if batch.is_empty() {
                    return Err(crate::framing(2));
                }
                output.push(self.checked(&base, &batch)?);
                batch.clear();
                batch.push(*prefix);
            }
        }
        if !batch.is_empty() {
            output.push(self.checked(&base, &batch)?);
        }
        Ok(output)
    }
    fn checked(&self, base: &[u8], batch: &[Prefix]) -> Result<Vec<u8>, ProtocolError> {
        let body = self.body(base, batch)?;
        update::validate(&body, self.four_octet_asn)?;
        crate::encode(crate::Kind::Update, &body)
    }
}
pub fn withdrawals(family: Family, prefixes: &[Prefix]) -> Result<Vec<Vec<u8>>, ProtocolError> {
    family.validate()?;
    let mut out = Vec::new();
    let mut nlri = Vec::new();
    for prefix in prefixes {
        if prefix.address().is_ipv4() != (family == Family::IPV4) {
            return Err(error());
        }
        let encoded = prefix.encode();
        if nlri.len().saturating_add(encoded.len()) > 4000 {
            out.push(withdraw_body(family, &nlri)?);
            nlri.clear();
        }
        nlri.extend(encoded);
    }
    if !nlri.is_empty() {
        out.push(withdraw_body(family, &nlri)?);
    }
    Ok(out)
}
fn withdraw_body(family: Family, nlri: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::new();
    if family == Family::IPV4 {
        body.extend_from_slice(
            &u16::try_from(nlri.len())
                .map_err(|_| error())?
                .to_be_bytes(),
        );
        body.extend_from_slice(nlri);
        body.extend_from_slice(&[0, 0]);
    } else {
        let mut value = family.afi.to_be_bytes().to_vec();
        value.push(family.safi);
        value.extend_from_slice(nlri);
        let mut attrs = Vec::new();
        attribute(&mut attrs, 0x80, 15, &value)?;
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(
            &u16::try_from(attrs.len())
                .map_err(|_| error())?
                .to_be_bytes(),
        );
        body.extend(attrs);
    }
    update::validate(&body, true)?;
    crate::encode(crate::Kind::Update, &body)
}
