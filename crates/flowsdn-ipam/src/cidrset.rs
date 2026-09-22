//! Fixed node-prefix allocator; spec07§5.4. No cloud or API operations.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    address: IpAddr,
    bits: u8,
}
impl Prefix {
    pub fn new(address: IpAddr, bits: u8) -> Result<Self, &'static str> {
        let width = if address.is_ipv4() { 32u8 } else { 128 };
        if bits > width {
            return Err("invalid prefix");
        }
        let shift = u32::from(width.saturating_sub(bits));
        let value = number(address)
            .checked_shr(shift)
            .unwrap_or(0)
            .checked_shl(shift)
            .unwrap_or(0);
        Ok(Self {
            address: ip(value, address.is_ipv6()),
            bits,
        })
    }
    pub fn address(self) -> IpAddr {
        self.address
    }
    pub fn bits(self) -> u8 {
        self.bits
    }
    fn last(self) -> u128 {
        let width = if self.address.is_ipv4() { 32u8 } else { 128 };
        number(self.address)
            | u128::MAX
                .checked_shr(u32::from(
                    128u8.saturating_sub(width.saturating_sub(self.bits)),
                ))
                .unwrap_or(0)
    }
}
impl std::str::FromStr for Prefix {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, bits) = s.split_once('/').ok_or("missing mask")?;
        Self::new(
            ip.parse().map_err(|_| "address")?,
            bits.parse().map_err(|_| "mask")?,
        )
    }
}
fn number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v) => u128::from(u32::from(v)),
        IpAddr::V6(v) => u128::from(v),
    }
}
fn ip(n: u128, v6: bool) -> IpAddr {
    if v6 {
        Ipv6Addr::from(n).into()
    } else {
        Ipv4Addr::from(u32::try_from(n).expect("IPv4 bounded")).into()
    }
}
pub struct CidrSet {
    cluster: Prefix,
    node_mask: u8,
    used: Vec<bool>,
    next: usize,
}
impl CidrSet {
    pub fn new(cluster: Prefix, node_mask: u8) -> Result<Self, &'static str> {
        let width = if cluster.address.is_ipv4() { 32 } else { 128 };
        let diff = node_mask
            .checked_sub(cluster.bits)
            .ok_or("node mask smaller than cluster")?;
        if node_mask > width || diff > 16 {
            return Err("subnet mask size too big");
        }
        Ok(Self {
            cluster,
            node_mask,
            used: vec![false; 1usize << diff],
            next: 0,
        })
    }
    pub fn capacity(&self) -> usize {
        self.used.len()
    }
    pub fn is_full(&self) -> bool {
        self.used.iter().all(|v| *v)
    }
    pub fn is_cluster(&self, p: Prefix) -> bool {
        self.cluster == p
    }
    pub fn in_range(&self, p: Prefix) -> bool {
        self.interval(p).is_ok()
    }
    pub fn block(&self, index: usize) -> Result<Prefix, &'static str> {
        if index >= self.used.len() {
            return Err("block index out of range");
        }
        let width = if self.cluster.address.is_ipv4() {
            32u8
        } else {
            128
        };
        let offset = (index as u128)
            .checked_shl(u32::from(width.saturating_sub(self.node_mask)))
            .unwrap_or(0);
        Prefix::new(
            ip(
                number(self.cluster.address) | offset,
                self.cluster.address.is_ipv6(),
            ),
            self.node_mask,
        )
    }
    fn interval(&self, p: Prefix) -> Result<std::ops::RangeInclusive<usize>, &'static str> {
        if p.address.is_ipv4() != self.cluster.address.is_ipv4()
            || number(p.address) > self.cluster.last()
            || p.last() < number(self.cluster.address)
        {
            return Err("CIDR allocation failed; not in range");
        }
        let width = if self.cluster.address.is_ipv4() {
            32u8
        } else {
            128
        };
        let shift = u32::from(width.saturating_sub(self.node_mask));
        let base = number(self.cluster.address);
        let first = number(p.address)
            .max(base)
            .saturating_sub(base)
            .checked_shr(shift)
            .unwrap_or(0);
        let last = p
            .last()
            .min(self.cluster.last())
            .saturating_sub(base)
            .checked_shr(shift)
            .unwrap_or(0);
        Ok(usize::try_from(first).map_err(|_| "index")?
            ..=usize::try_from(last).map_err(|_| "index")?)
    }
    pub fn occupy(&mut self, p: Prefix) -> Result<(), &'static str> {
        for i in self.interval(p)? {
            *self.used.get_mut(i).ok_or("index")? = true;
        }
        Ok(())
    }
    pub fn release(&mut self, p: Prefix) -> Result<(), &'static str> {
        for i in self.interval(p)? {
            *self.used.get_mut(i).ok_or("index")? = false;
        }
        Ok(())
    }
    pub fn is_allocated(&self, p: Prefix) -> Result<bool, &'static str> {
        Ok(self.interval(p)?.all(|i| self.used.get(i) == Some(&true)))
    }
    #[allow(clippy::arithmetic_side_effects)] // vector capacity is a nonzero power of two, at most65536
    pub fn allocate_next(&mut self) -> Result<Prefix, &'static str> {
        for step in 0..self.used.len() {
            let i = self.next.saturating_add(step) % self.used.len();
            if self.used.get(i) == Some(&false) {
                *self.used.get_mut(i).ok_or("index")? = true;
                self.next = i.saturating_add(1) % self.used.len();
                return self.block(i);
            }
        }
        Err("there are no remaining CIDRs left to allocate")
    }
}
