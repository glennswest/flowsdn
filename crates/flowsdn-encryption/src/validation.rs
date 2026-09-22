use crate::Error;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Encryption {
    pub wireguard: bool,
    pub ipsec: bool,
    pub strict_ingress: bool,
    pub host_firewall: bool,
    pub pinned_router_ip: bool,
    pub l7_proxy: bool,
    pub dns_transparent: bool,
    pub insecure_ipsec_proxy_override: bool,
    pub ciliumnode_crd: bool,
    pub tunnel: bool,
    pub xfrm_output_mark_mask: bool,
    pub vtep: bool,
    pub srv6: bool,
}
impl Default for Encryption {
    fn default() -> Self {
        Self {
            wireguard: false,
            ipsec: false,
            strict_ingress: false,
            host_firewall: false,
            pinned_router_ip: false,
            l7_proxy: false,
            dns_transparent: false,
            insecure_ipsec_proxy_override: false,
            ciliumnode_crd: true,
            tunnel: false,
            xfrm_output_mark_mask: false,
            vtep: false,
            srv6: false,
        }
    }
}
impl Encryption {
    /// Validates this explicit subset of §6.7; not all encryption/egress inputs.
    pub fn validate(self) -> Result<Vec<&'static str>, Error> {
        if self.vtep || self.srv6 {
            return Err(Error(
                "VTEP and SRv6 are not implemented; configuration cannot enable them",
            ));
        }
        if self.wireguard && self.ipsec {
            return Err(Error("WireGuard and IPsec are mutually exclusive"));
        }
        if (self.wireguard || self.ipsec) && !self.ciliumnode_crd {
            return Err(Error("encryption requires CiliumNode CRD"));
        }
        if self.ipsec && self.strict_ingress {
            return Err(Error("IPsec strict ingress awaits dedicated leak tests"));
        }
        if self.ipsec && self.host_firewall {
            return Err(Error("IPsec with host firewall is unsupported"));
        }
        if self.ipsec && self.pinned_router_ip {
            return Err(Error("IPsec with pinned local router IP is unsupported"));
        }
        if self.ipsec && self.tunnel && !self.xfrm_output_mark_mask {
            return Err(Error(
                "encrypted overlay requires XFRM output-mark mask support",
            ));
        }
        let mut warnings = Vec::new();
        if self.ipsec && self.l7_proxy && !self.dns_transparent {
            if !self.insecure_ipsec_proxy_override {
                return Err(Error("IPsec L7 proxy requires transparent DNS proxy mode"));
            }
            warnings.push("insecure IPsec proxy override permits unencrypted proxy traffic");
        }
        Ok(warnings)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyReaders {
    None,
    Present,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressMaps {
    pub ipv4_v2: bool,
    pub ipv6: bool,
    pub legacy_ipv4: bool,
}
/// Caller inspects actual loaded programs, not merely current configuration.
/// Apply/prune both enabled IPv4 maps before reporting a completed reconciliation.
pub fn egress_maps(
    ipv4: bool,
    ipv6: bool,
    legacy_flag: bool,
    readers: LegacyReaders,
) -> Result<EgressMaps, Error> {
    if readers == LegacyReaders::Unknown {
        return Err(Error(
            "cannot determine whether loaded programs still read the legacy egress map",
        ));
    }
    if readers == LegacyReaders::Present && (!legacy_flag || !ipv4) {
        return Err(Error(
            "loaded legacy reader requires legacy IPv4 map synchronization or explicit drain/detach",
        ));
    }
    Ok(EgressMaps {
        ipv4_v2: ipv4,
        ipv6,
        legacy_ipv4: legacy_flag && ipv4,
    })
}
