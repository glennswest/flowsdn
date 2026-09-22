//! Typed supported-family capability construction and negotiation.
use crate::{
    ErrorScope, ProtocolError,
    open::{Capability, Open},
};
use std::{collections::BTreeSet, net::Ipv4Addr};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Family {
    pub afi: u16,
    pub safi: u8,
}
impl Family {
    pub const IPV4: Self = Self { afi: 1, safi: 1 };
    pub const IPV6: Self = Self { afi: 2, safi: 1 };
    pub fn validate(self) -> Result<(), ProtocolError> {
        if matches!(self.afi, 1 | 2) && self.safi == 1 {
            Ok(())
        } else {
            Err(error(7))
        }
    }
}
fn error(subcode: u8) -> ProtocolError {
    ProtocolError {
        code: 2,
        subcode,
        scope: ErrorScope::Open,
    }
}
pub fn multiprotocol(family: Family) -> Result<Capability, ProtocolError> {
    family.validate()?;
    let [hi, lo] = family.afi.to_be_bytes();
    Ok(Capability {
        code: 1,
        value: vec![hi, lo, 0, family.safi],
    })
}
pub fn graceful_restart(
    seconds: u16,
    restarting: bool,
    families: &BTreeSet<Family>,
) -> Result<Capability, ProtocolError> {
    let flags = seconds.min(4095) | 0x4000 | if restarting { 0x8000 } else { 0 };
    let mut value = flags.to_be_bytes().to_vec();
    for family in families {
        family.validate()?;
        value.extend_from_slice(&family.afi.to_be_bytes());
        value.extend_from_slice(&[family.safi, 0]);
    }
    Ok(Capability { code: 64, value })
}
pub fn local_open(
    asn: u32,
    hold_time: u16,
    router_id: Ipv4Addr,
    families: &BTreeSet<Family>,
) -> Result<Open, ProtocolError> {
    if asn == 0 || router_id.is_unspecified() || families.is_empty() {
        return Err(error(4));
    }
    let mut capabilities = vec![
        Capability {
            code: 65,
            value: asn.to_be_bytes().to_vec(),
        },
        Capability {
            code: 2,
            value: vec![],
        },
    ];
    for family in families {
        capabilities.push(multiprotocol(*family)?);
    }
    let open = Open {
        asn: u16::try_from(asn).unwrap_or(23456),
        hold_time,
        router_id,
        capabilities,
    };
    open.encode()?;
    Ok(open)
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    pub graceful: Option<Graceful>,
    pub hold_time: u16,
    pub four_octet_asn: bool,
    pub route_refresh: bool,
    pub families: BTreeSet<Family>,
}
pub fn negotiate(
    local: &Open,
    peer: &Open,
    expected_asn: u32,
) -> Result<Negotiated, ProtocolError> {
    // Revalidate typed input too; constructing Open directly must not bypass
    // the wire capability length checks.
    local.encode()?;
    peer.encode()?;
    let hold_time = peer.validate_peer(expected_asn, local.router_id, local.hold_time)?;
    fn families(open: &Open) -> BTreeSet<Family> {
        open.capabilities
            .iter()
            .filter(|cap| cap.code == 1)
            .filter_map(|cap| {
                let [a, b, _, safi]: [u8; 4] = cap.value.as_slice().try_into().ok()?;
                Some(Family {
                    afi: u16::from_be_bytes([a, b]),
                    safi,
                })
            })
            .filter(|family| family.validate().is_ok())
            .collect()
    }
    let common = families(local)
        .intersection(&families(peer))
        .copied()
        .collect::<BTreeSet<_>>();
    if common.is_empty() {
        return Err(error(7));
    }
    let both = |code| {
        local.capabilities.iter().any(|c| c.code == code)
            && peer.capabilities.iter().any(|c| c.code == code)
    };
    Ok(Negotiated {
        graceful: graceful(local, peer),
        hold_time,
        four_octet_asn: both(65),
        route_refresh: both(2),
        families: common,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Restart {
    pub seconds: u16,
    pub restarting: bool,
    pub notifications: bool,
    pub forwarding: BTreeSet<Family>,
}
/// RFC 4724: when repeated, only the last GR capability is used.
pub fn restart(open: &Open) -> Option<Restart> {
    let capability = open.capabilities.iter().rev().find(|cap| cap.code == 64)?;
    let (header, tuples) = capability.value.split_at_checked(2)?;
    if !tuples.len().is_multiple_of(4) {
        return None;
    }
    let field = u16::from_be_bytes(header.try_into().ok()?);
    let forwarding = tuples
        .chunks_exact(4)
        .filter_map(|tuple| {
            let [a, b, safi, flags]: [u8; 4] = tuple.try_into().ok()?;
            let family = Family {
                afi: u16::from_be_bytes([a, b]),
                safi,
            };
            (flags & 0x80 != 0 && family.validate().is_ok()).then_some(family)
        })
        .collect();
    Some(Restart {
        seconds: field & 0x0fff,
        restarting: field & 0x8000 != 0,
        notifications: field & 0x4000 != 0,
        forwarding,
    })
}
/// The exporter does not retain learned forwarding state. These negotiated
/// facts determine whether the *peer* can retain this exporter's local routes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Graceful {
    pub notifications: bool,
    pub local_restart_seconds: u16,
    pub peer: Restart,
}
pub fn graceful(local: &Open, peer: &Open) -> Option<Graceful> {
    let local = restart(local)?;
    let peer = restart(peer)?;
    Some(Graceful {
        notifications: local.notifications && peer.notifications,
        local_restart_seconds: local.seconds,
        peer,
    })
}
