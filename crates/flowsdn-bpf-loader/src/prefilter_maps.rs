//! The XDP prefilter's deny maps (#467): `flowsdn_cidr_v4_fix` /
//! `flowsdn_cidr_v6_fix` (hash, host prefixes /32 and /128) and
//! `flowsdn_cidr_v4_dyn` / `flowsdn_cidr_v6_dyn` (LPM, every other prefix),
//! as the reference splits them. Contents are the agent's.
use super::KernelResult;
use aya::{
    Ebpf,
    maps::{HashMap, LpmTrie, MapData, lpm_trie::Key},
};
use std::net::IpAddr;

pub const NAMES: [&str; 4] = [
    "flowsdn_cidr_v4_fix",
    "flowsdn_cidr_v4_dyn",
    "flowsdn_cidr_v6_fix",
    "flowsdn_cidr_v6_dyn",
];

/// Handles on the four deny maps.
pub struct PrefilterMaps {
    v4_fix: HashMap<MapData, [u8; 4], u8>,
    v4_dyn: LpmTrie<MapData, [u8; 4], u8>,
    v6_fix: HashMap<MapData, [u8; 16], u8>,
    v6_dyn: LpmTrie<MapData, [u8; 16], u8>,
}

/// A prefix as the maps hold it: the network address (host bits cleared)
/// and its length; None for a length past the family's width.
fn masked(address: IpAddr, prefix: u8) -> Option<IpAddr> {
    match address {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = u32::MAX.checked_shl(32u32.checked_sub(u32::from(prefix))?).unwrap_or(0);
            (prefix <= 32).then(|| IpAddr::from(std::net::Ipv4Addr::from(bits & mask)))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = u128::MAX
                .checked_shl(128u32.checked_sub(u32::from(prefix))?)
                .unwrap_or(0);
            (prefix <= 128).then(|| IpAddr::from(std::net::Ipv6Addr::from(bits & mask)))
        }
    }
}

impl PrefilterMaps {
    pub(super) fn take(bpf: &mut Ebpf) -> KernelResult<Self> {
        let mut take = |name: &str| bpf.take_map(name).ok_or(format!("missing map {name}"));
        let v4_fix = take("flowsdn_cidr_v4_fix")?;
        let v4_dyn = take("flowsdn_cidr_v4_dyn")?;
        let v6_fix = take("flowsdn_cidr_v6_fix")?;
        let v6_dyn = take("flowsdn_cidr_v6_dyn")?;
        Ok(Self {
            v4_fix: HashMap::try_from(v4_fix)?,
            v4_dyn: LpmTrie::try_from(v4_dyn)?,
            v6_fix: HashMap::try_from(v6_fix)?,
            v6_dyn: LpmTrie::try_from(v6_dyn)?,
        })
    }

    /// Deny sources in `address/prefix` (host bits are cleared first).
    pub fn insert(&mut self, address: IpAddr, prefix: u8) -> KernelResult<()> {
        match masked(address, prefix).ok_or("prefix length too long")? {
            IpAddr::V4(v4) if prefix == 32 => self.v4_fix.insert(v4.octets(), 1, 0)?,
            IpAddr::V4(v4) => self
                .v4_dyn
                .insert(&Key::new(u32::from(prefix), v4.octets()), 1, 0)?,
            IpAddr::V6(v6) if prefix == 128 => self.v6_fix.insert(v6.octets(), 1, 0)?,
            IpAddr::V6(v6) => self
                .v6_dyn
                .insert(&Key::new(u32::from(prefix), v6.octets()), 1, 0)?,
        }
        Ok(())
    }

    /// Stop denying `address/prefix`.
    pub fn remove(&mut self, address: IpAddr, prefix: u8) -> KernelResult<()> {
        match masked(address, prefix).ok_or("prefix length too long")? {
            IpAddr::V4(v4) if prefix == 32 => self.v4_fix.remove(&v4.octets())?,
            IpAddr::V4(v4) => self.v4_dyn.remove(&Key::new(u32::from(prefix), v4.octets()))?,
            IpAddr::V6(v6) if prefix == 128 => self.v6_fix.remove(&v6.octets())?,
            IpAddr::V6(v6) => self.v6_dyn.remove(&Key::new(u32::from(prefix), v6.octets()))?,
        }
        Ok(())
    }

    /// Every denied prefix, as (network address, length).
    pub fn entries(&self) -> KernelResult<Vec<(IpAddr, u8)>> {
        let mut out = Vec::new();
        for key in self.v4_fix.keys() {
            out.push((IpAddr::from(key?), 32));
        }
        for key in self.v4_dyn.keys() {
            let key = key?;
            out.push((IpAddr::from(key.data()), u8::try_from(key.prefix_len())?));
        }
        for key in self.v6_fix.keys() {
            out.push((IpAddr::from(key?), 128));
        }
        for key in self.v6_dyn.keys() {
            let key = key?;
            out.push((IpAddr::from(key.data()), u8::try_from(key.prefix_len())?));
        }
        out.sort();
        Ok(out)
    }

    /// Remove every entry (a pinned map may hold an earlier agent's).
    pub fn clear(&mut self) -> KernelResult<()> {
        for (address, prefix) in self.entries()? {
            self.remove(address, prefix)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_bits_are_cleared_and_lengths_bounded() {
        let ip = |t: &str| t.parse::<IpAddr>().expect("ip");
        assert_eq!(masked(ip("192.0.2.77"), 24), Some(ip("192.0.2.0")));
        assert_eq!(masked(ip("192.0.2.77"), 32), Some(ip("192.0.2.77")));
        assert_eq!(masked(ip("192.0.2.77"), 0), Some(ip("0.0.0.0")));
        assert_eq!(masked(ip("192.0.2.77"), 33), None);
        assert_eq!(masked(ip("2001:db8::1"), 32), Some(ip("2001:db8::")));
        assert_eq!(masked(ip("2001:db8::1"), 129), None);
    }
}
