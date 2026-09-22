//! Encryption/routing validation and plans; no kernel state or key handling.
#![forbid(unsafe_code)]
pub mod gateway;
pub mod validation;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
}
pub fn underlay(request: &str, ipv4: bool, ipv6: bool) -> Result<Family, Error> {
    match request {
        "auto" if ipv4 => Ok(Family::Ipv4),
        "auto" if ipv6 => Ok(Family::Ipv6),
        "ipv4" if ipv4 => Ok(Family::Ipv4),
        "ipv6" if ipv6 => Ok(Family::Ipv6),
        _ => Err(Error(
            "underlay requires a configured enabled address family",
        )),
    }
}
pub fn tunnel_endpoint(
    family: Family,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<IpAddr, Error> {
    match family {
        Family::Ipv4 => ipv4.map(IpAddr::V4),
        Family::Ipv6 => ipv6.map(IpAddr::V6),
    }
    .ok_or(Error(
        "peer lacks the selected underlay address; no cross-family fallback",
    ))
}
/// WireGuard uses its distinct reference fallback ordering (§3.1.4), not the
/// strict tunnel-address selector. Addresses are prevalidated node addresses.
pub fn wireguard_endpoint(
    tunnel: bool,
    underlay: Family,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<SocketAddr, Error> {
    let address = if tunnel && underlay == Family::Ipv6 {
        ipv6.map(IpAddr::V6).or_else(|| ipv4.map(IpAddr::V4))
    } else {
        ipv4.map(IpAddr::V4).or_else(|| ipv6.map(IpAddr::V6))
    };
    address
        .map(|address| SocketAddr::new(address, 51871))
        .ok_or(Error("no enabled peer address for WireGuard"))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpsecLayering {
    NativeIpsec,
    OverlayInsideIpsec,
}
pub fn ipsec_layering(tunnel: bool, legacy_pre_118: bool) -> Result<IpsecLayering, Error> {
    if legacy_pre_118 {
        return Err(Error(
            "pre-1.18 IPsec-inside-overlay is unsupported; drain and migrate first",
        ));
    }
    Ok(if tunnel {
        IpsecLayering::OverlayInsideIpsec
    } else {
        IpsecLayering::NativeIpsec
    })
}
pub fn ipsec_interface_warning(value: &str) -> Option<&'static str> {
    (!value.is_empty()).then_some(
        "encryption.ipsec.interface is ignored; interface selection follows node/device discovery",
    )
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostDelivery {
    BpfHostRouting,
    BpfEndpointRoute,
}
pub fn host_delivery(legacy: bool, endpoint_routes: bool) -> Result<HostDelivery, Error> {
    if legacy {
        return Err(Error(
            "legacy host routing is unsupported; configure BPF host routing",
        ));
    }
    Ok(if endpoint_routes {
        HostDelivery::BpfEndpointRoute
    } else {
        HostDelivery::BpfHostRouting
    })
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObjectBuild {
    pub debug_events: bool,
    pub test_hooks: bool,
}
impl ObjectBuild {
    pub fn validate_release(self) -> Result<(), Error> {
        if self.debug_events || self.test_hooks {
            Err(Error(
                "release objects must exclude debug-events and test-hooks",
            ))
        } else {
            Ok(())
        }
    }
    pub fn cargo_features(self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if self.debug_events {
            features.push("debug-events");
        }
        if self.test_hooks {
            features.push("test-hooks");
        }
        features
    }
}
