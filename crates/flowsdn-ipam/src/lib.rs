//! Host-scope allocation from spec 07 §§3.1, 3.4 and 5.5.
//! Callers serialize access through exclusive mutable borrows or their own lock.

pub mod cidrset;

use std::collections::{BTreeMap, hash_map::RandomState};
use std::fmt;
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DEFAULT_POOL: &str = "default";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidPrefix,
    CapacityOverflow,
    NotInRange,
    Allocated,
    Excluded { owner: String },
    Full,
    FamilyMismatch,
    FamilyDisabled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => f.write_str("invalid IP prefix"),
            Self::CapacityOverflow => f.write_str("address capacity exceeds u128"),
            Self::NotInRange => f.write_str("IP is not in the allocatable range"),
            Self::Allocated => f.write_str("IP is already allocated"),
            Self::Excluded { owner } => write!(f, "IP is excluded, owned by {owner}"),
            Self::Full => f.write_str("IP range is full"),
            Self::FamilyMismatch => f.write_str("IP address family does not match"),
            Self::FamilyDisabled => f.write_str("IP address family is disabled"),
        }
    }
}

impl std::error::Error for Error {}

/// Endpoint reservations. Host-scope defaults reserve both endpoints when
/// the prefix contains more than two addresses, for both address families.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RangeOptions {
    pub allow_first_ip: bool,
    pub allow_last_ip: bool,
}

/// A single prefix, backed by sparse bitmap words. Memory is proportional to
/// allocated addresses, even for IPv6 /64 or /0 ranges. Capacity includes
/// excluded addresses and does not decrease as addresses are allocated.
#[derive(Debug)]
pub struct HostScope {
    network: IpAddr,
    prefix_len: u8,
    first: u128,
    last: u128,
    capacity: u128,
    words: BTreeMap<u128, u64>,
    owners: BTreeMap<IpAddr, String>,
    excluded: BTreeMap<IpAddr, String>,
    random: RandomState,
    sequence: u128,
}

impl HostScope {
    /// Host bits in `address` are normalized to the prefix network address.
    pub fn new(address: IpAddr, prefix_len: u8, options: RangeOptions) -> Result<Self, Error> {
        let width: u8 = if address.is_ipv4() { 32 } else { 128 };
        let host_bits = width.checked_sub(prefix_len).ok_or(Error::InvalidPrefix)?;
        let host_mask = if host_bits == 128 {
            u128::MAX
        } else {
            1u128.wrapping_shl(u32::from(host_bits)).wrapping_sub(1)
        };
        let network_number = number(address) & !host_mask;
        let network = from_number(network_number, address.is_ipv4());
        let reserve_first = host_bits > 1 && !options.allow_first_ip;
        let reserve_last = host_bits > 1 && !options.allow_last_ip;
        let first = network_number.wrapping_add(u128::from(reserve_first));
        let last = (network_number | host_mask).wrapping_sub(u128::from(reserve_last));
        let capacity = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::CapacityOverflow)?;
        Ok(Self {
            network,
            prefix_len,
            first,
            last,
            capacity,
            words: BTreeMap::new(),
            owners: BTreeMap::new(),
            excluded: BTreeMap::new(),
            random: RandomState::new(),
            sequence: 0,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn capacity(&self) -> u128 {
        self.capacity
    }

    pub fn allocated(&self) -> usize {
        self.owners.len()
    }

    pub fn dump(&self) -> &BTreeMap<IpAddr, String> {
        &self.owners
    }

    /// Restore uses the same collision and exclusion checks as a static
    /// allocation. Host scope has no upstream synchronization to defer.
    pub fn allocate_without_sync(&mut self, address: IpAddr, owner: &str) -> Result<(), Error> {
        self.allocate(address, owner)
    }

    pub fn restore_finished(&mut self) {}

    pub fn allocate(&mut self, address: IpAddr, owner: &str) -> Result<(), Error> {
        let offset = self.offset(address).ok_or(Error::NotInRange)?;
        if let Some(owner) = self.excluded.get(&address) {
            return Err(Error::Excluded {
                owner: owner.clone(),
            });
        }
        if self.is_set(offset) {
            return Err(Error::Allocated);
        }
        self.reserve(offset, address, owner.to_owned());
        Ok(())
    }

    pub fn allocate_next_without_sync(&mut self, owner: &str) -> Result<IpAddr, Error> {
        self.allocate_next(owner)
    }

    /// Start at a process-randomized offset, then scan linearly with wraparound.
    /// Scanning is bounded by occupied addresses plus exclusions, rather than
    /// the potentially enormous address space, unless that space is full.
    pub fn allocate_next(&mut self, owner: &str) -> Result<IpAddr, Error> {
        if self.owners.len() as u128 == self.capacity {
            return Err(Error::Full);
        }
        self.sequence = self.sequence.wrapping_add(1);
        let high = u128::from(self.random.hash_one((self.sequence, 0u8)));
        let low = u128::from(self.random.hash_one((self.sequence, 1u8)));
        let start = ((high << 64) | low)
            .checked_rem(self.capacity)
            .ok_or(Error::Full)?;
        let mut offset = start;
        loop {
            if !self.is_set(offset) {
                let address = from_number(self.first.wrapping_add(offset), self.network.is_ipv4());
                if let Some(excluded_owner) = self.excluded.get(&address) {
                    let excluded_owner = format!("{excluded_owner} (excluded)");
                    self.reserve(offset, address, excluded_owner);
                } else {
                    self.reserve(offset, address, owner.to_owned());
                    return Ok(address);
                }
            }
            offset = if offset == self.capacity.wrapping_sub(1) {
                0
            } else {
                offset.wrapping_add(1)
            };
            if offset == start || self.owners.len() as u128 == self.capacity {
                return Err(Error::Full);
            }
        }
    }

    /// Record an infrastructure exclusion. Existing allocations retain their
    /// owner until release; the exclusion remains after release. Out-of-range
    /// exclusions are accepted because infrastructure IPs may be external.
    pub fn exclude_ip(&mut self, address: IpAddr, owner: &str) {
        self.excluded.insert(address, owner.to_owned());
    }

    /// Releasing a free, reserved-endpoint or foreign address is a no-op.
    /// Exclusions are persistent: release never makes an excluded IP usable.
    pub fn release(&mut self, address: IpAddr) {
        let Some(offset) = self.offset(address) else {
            return;
        };
        let word = offset >> 6;
        let mask = 1u64 << (offset & 63);
        if let Some(bits) = self.words.get_mut(&word) {
            *bits &= !mask;
            if *bits == 0 {
                self.words.remove(&word);
            }
        }
        self.owners.remove(&address);
    }

    fn offset(&self, address: IpAddr) -> Option<u128> {
        if address.is_ipv4() != self.network.is_ipv4() {
            return None;
        }
        let value = number(address);
        if value < self.first || value > self.last {
            return None;
        }
        value.checked_sub(self.first)
    }

    fn is_set(&self, offset: u128) -> bool {
        self.words
            .get(&(offset >> 6))
            .is_some_and(|bits| bits & (1u64 << (offset & 63)) != 0)
    }

    fn reserve(&mut self, offset: u128, address: IpAddr, owner: String) {
        *self.words.entry(offset >> 6).or_default() |= 1u64 << (offset & 63);
        self.owners.insert(address, owner);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddressPair {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// Host-scope dual-stack coordinator. Both families belong to `default`.
/// Exclusive mutable access covers both families for rollback and bookkeeping.
#[derive(Debug)]
pub struct Ipam {
    ipv4: Option<HostScope>,
    ipv6: Option<HostScope>,
}

impl Ipam {
    pub fn new(ipv4: Option<HostScope>, ipv6: Option<HostScope>) -> Result<Self, Error> {
        if ipv4.as_ref().is_some_and(|p| !p.network.is_ipv4())
            || ipv6.as_ref().is_some_and(|p| !p.network.is_ipv6())
        {
            return Err(Error::FamilyMismatch);
        }
        Ok(Self { ipv4, ipv6 })
    }

    pub fn ipv4(&self) -> Option<&HostScope> {
        self.ipv4.as_ref()
    }

    pub fn ipv6(&self) -> Option<&HostScope> {
        self.ipv6.as_ref()
    }

    pub fn allocate(&mut self, address: IpAddr, owner: &str) -> Result<(), Error> {
        self.family_mut(address)?.allocate(address, owner)
    }

    /// An explicit API family request must not depend on the other pool.
    pub fn allocate_next_family(&mut self, ipv6: bool, owner: &str) -> Result<IpAddr, Error> {
        let pool = if ipv6 {
            self.ipv6.as_mut()
        } else {
            self.ipv4.as_mut()
        };
        pool.ok_or(Error::FamilyDisabled)?.allocate_next(owner)
    }

    pub fn exclude_ip(&mut self, address: IpAddr, owner: &str) -> Result<(), Error> {
        self.family_mut(address)?.exclude_ip(address, owner);
        Ok(())
    }

    pub fn release(&mut self, address: IpAddr) -> Result<(), Error> {
        self.family_mut(address)?.release(address);
        Ok(())
    }

    /// Allocate all enabled families, IPv6 first. IPv4 failure releases the
    /// newly allocated IPv6 IP, while preserving pre-existing allocations and
    /// any infrastructure exclusions discovered during the scan.
    pub fn allocate_next(&mut self, owner: &str) -> Result<AddressPair, Error> {
        if self.ipv4.is_none() && self.ipv6.is_none() {
            return Err(Error::FamilyDisabled);
        }
        let ipv6 = match self.ipv6.as_mut() {
            Some(pool) => match pool.allocate_next(owner)? {
                IpAddr::V6(ip) => Some(ip),
                IpAddr::V4(_) => return Err(Error::FamilyMismatch),
            },
            None => None,
        };
        let ipv4 = match self.ipv4.as_mut() {
            Some(pool) => match pool.allocate_next(owner) {
                Ok(IpAddr::V4(ip)) => Some(ip),
                result => {
                    if let (Some(pool), Some(ip)) = (self.ipv6.as_mut(), ipv6) {
                        pool.release(IpAddr::V6(ip));
                    }
                    return Err(result.err().unwrap_or(Error::FamilyMismatch));
                }
            },
            None => None,
        };
        Ok(AddressPair { ipv4, ipv6 })
    }

    fn family_mut(&mut self, address: IpAddr) -> Result<&mut HostScope, Error> {
        if address.is_ipv4() {
            self.ipv4.as_mut()
        } else {
            self.ipv6.as_mut()
        }
        .ok_or(Error::FamilyDisabled)
    }
}

fn number(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(ip) => u128::from(u32::from(ip)),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn from_number(value: u128, ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}
