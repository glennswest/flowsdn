//! Socket-LB map planning (spec 05 §3.4, spec 01 §4.3): desired ClusterIP
//! frontends and their backends become the contents of
//! `cilium_lb{4,6}_services_v2` and `_backends_v3`, and the difference from the
//! kernel's current contents becomes an ordered list of map writes.
//!
//! Stateless by design: service IDs (`rev_nat_index`) and backend IDs are
//! recovered from the current maps, so a restarted agent keeps them and a
//! failed write is retried by planning again from what the kernel holds.
use flowsdn_bpf_abi::{
    Be16, Be32, MapBytes,
    lb::{Lb4Backend, Lb4Key, Lb6Backend, Lb6Key, LbService, service_flags},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// A service address: `address:port/proto`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Address {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: u8,
}
impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = match self.proto {
            PROTO_TCP => "TCP",
            PROTO_UDP => "UDP",
            _ => "ANY",
        };
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}/{proto}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}/{proto}", self.port),
        }
    }
}

/// One frontend and the backends it balances over. Backends of the other
/// family are ignored; duplicates collapse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Service {
    pub frontend: Address,
    pub backends: Vec<Address>,
}

/// The four maps' contents as raw map bytes, keyed as the kernel keys them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Maps {
    pub services4: BTreeMap<[u8; 12], [u8; 12]>,
    pub backends4: BTreeMap<u32, [u8; 12]>,
    pub services6: BTreeMap<[u8; 24], [u8; 12]>,
    pub backends6: BTreeMap<u32, [u8; 24]>,
}

/// One map write. [`plan`] orders them so a concurrent lookup never reads a
/// slot beyond its master's count or a backend ID with no backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Op {
    Backend4(u32, [u8; 12]),
    Backend6(u32, [u8; 24]),
    Service4([u8; 12], [u8; 12]),
    Service6([u8; 24], [u8; 12]),
    DeleteService4([u8; 12]),
    DeleteService6([u8; 24]),
    DeleteBackend4(u32),
    DeleteBackend6(u32),
}

/// What [`desired`] chose: the map contents, and the service ID of each frontend.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Desired {
    pub maps: Maps,
    pub ids: BTreeMap<Address, u16>,
}

fn key4(frontend: Address, slot: u16) -> Option<[u8; 12]> {
    let IpAddr::V4(ip) = frontend.ip else {
        return None;
    };
    Some(
        Lb4Key {
            address: Be32(ip.octets()),
            dport: Be16::new(frontend.port),
            backend_slot: slot,
            proto: frontend.proto,
            scope: 0,
            pad: [0; 2],
        }
        .to_bytes(),
    )
}
fn key6(frontend: Address, slot: u16) -> Option<[u8; 24]> {
    let IpAddr::V6(ip) = frontend.ip else {
        return None;
    };
    Some(
        Lb6Key {
            address: ip.octets(),
            dport: Be16::new(frontend.port),
            backend_slot: slot,
            proto: frontend.proto,
            scope: 0,
            pad: [0; 2],
        }
        .to_bytes(),
    )
}
fn backend_bytes4(backend: Address) -> Option<[u8; 12]> {
    let IpAddr::V4(ip) = backend.ip else {
        return None;
    };
    Some(
        Lb4Backend {
            address: Be32(ip.octets()),
            port: Be16::new(backend.port),
            proto: backend.proto,
            ..Lb4Backend::default()
        }
        .to_bytes(),
    )
}
fn backend_bytes6(backend: Address) -> Option<[u8; 24]> {
    let IpAddr::V6(ip) = backend.ip else {
        return None;
    };
    Some(
        Lb6Backend {
            address: ip.octets(),
            port: Be16::new(backend.port),
            proto: backend.proto,
            ..Lb6Backend::default()
        }
        .to_bytes(),
    )
}

/// The frontend and slot of a service-map key.
fn frontend4(key: [u8; 12]) -> (Address, u16) {
    let key = Lb4Key::from_bytes(key);
    let address = Address {
        ip: IpAddr::V4(Ipv4Addr::from(key.address.0)),
        port: key.dport.get(),
        proto: key.proto,
    };
    (address, key.backend_slot)
}
fn frontend6(key: [u8; 24]) -> (Address, u16) {
    let key = Lb6Key::from_bytes(key);
    let address = Address {
        ip: IpAddr::V6(Ipv6Addr::from(key.address)),
        port: key.dport.get(),
        proto: key.proto,
    };
    (address, key.backend_slot)
}
fn backend4(value: [u8; 12]) -> Address {
    let backend = Lb4Backend::from_bytes(value);
    Address {
        ip: IpAddr::V4(Ipv4Addr::from(backend.address.0)),
        port: backend.port.get(),
        proto: backend.proto,
    }
}
fn backend6(value: [u8; 24]) -> Address {
    let backend = Lb6Backend::from_bytes(value);
    Address {
        ip: IpAddr::V6(Ipv6Addr::from(backend.address)),
        port: backend.port.get(),
        proto: backend.proto,
    }
}

/// Hands out the smallest IDs in `1..=max` not in `used`, in increasing
/// order; IDs only join `used` during one planning pass, so a cursor suffices.
struct Ids {
    used: BTreeSet<u32>,
    next: u32,
    max: u32,
}
impl Ids {
    fn new(used: BTreeSet<u32>, max: u32) -> Self {
        Self { used, next: 1, max }
    }
    fn allocate(&mut self) -> Option<u32> {
        while self.used.contains(&self.next) {
            self.next = self.next.checked_add(1)?;
        }
        if self.next > self.max {
            return None;
        }
        self.used.insert(self.next);
        Some(self.next)
    }
}

/// Compute the map contents for `services`, keeping the service and backend
/// IDs that `current` already holds. A new ID never reuses one still present
/// in `current`, because a live slot may reference it until [`plan`]'s
/// writes replace that slot.
pub fn desired(current: &Maps, services: &[Service]) -> Result<Desired, String> {
    // Recover IDs. A duplicate backend value keeps its lowest ID.
    let mut backend_ids: BTreeMap<Address, u32> = BTreeMap::new();
    for (id, value) in &current.backends4 {
        backend_ids.entry(backend4(*value)).or_insert(*id);
    }
    for (id, value) in &current.backends6 {
        backend_ids.entry(backend6(*value)).or_insert(*id);
    }
    let mut backend_pool = Ids::new(
        current
            .backends4
            .keys()
            .chain(current.backends6.keys())
            .copied()
            .collect(),
        u32::MAX,
    );
    let mut service_ids: BTreeMap<Address, u16> = BTreeMap::new();
    let masters4 = current.services4.iter().map(|(k, v)| (frontend4(*k), *v));
    let masters6 = current.services6.iter().map(|(k, v)| (frontend6(*k), *v));
    let mut used_services: BTreeSet<u32> = BTreeSet::new();
    for ((frontend, slot), value) in masters4.chain(masters6) {
        let rev = LbService::from_bytes(value).rev_nat_index;
        used_services.insert(u32::from(rev));
        if slot == 0 && rev != 0 {
            service_ids.entry(frontend).or_insert(rev);
        }
    }

    let mut service_pool = Ids::new(used_services, u32::from(u16::MAX));
    let mut out = Desired::default();
    let mut frontends = BTreeSet::new();
    let mut sorted: Vec<&Service> = services.iter().collect();
    sorted.sort_by_key(|s| s.frontend);
    for service in sorted {
        let frontend = service.frontend;
        if !frontends.insert(frontend) {
            return Err(format!("duplicate frontend {frontend}"));
        }
        let backends: BTreeSet<Address> = service
            .backends
            .iter()
            .filter(|b| b.ip.is_ipv4() == frontend.ip.is_ipv4())
            .copied()
            .collect();
        let count = u16::try_from(backends.len())
            .map_err(|_| format!("{frontend}: more than 65535 backends"))?;
        let id = match service_ids.get(&frontend) {
            Some(id) => *id,
            None => {
                let id = service_pool.allocate().ok_or("service IDs exhausted")?;
                u16::try_from(id).map_err(|_| "service ID overflow")?
            }
        };
        out.ids.insert(frontend, id);
        let mut master = LbService {
            count,
            rev_nat_index: id,
            ..LbService::default()
        };
        master.set_service_flags(service_flags::ROUTABLE);
        let mut slots = vec![(0u16, master)];
        for (index, backend) in backends.into_iter().enumerate() {
            let backend_id = match backend_ids.get(&backend) {
                Some(id) => *id,
                None => {
                    let id = backend_pool.allocate().ok_or("backend IDs exhausted")?;
                    backend_ids.insert(backend, id);
                    id
                }
            };
            match backend.ip {
                IpAddr::V4(_) => {
                    let value = backend_bytes4(backend).ok_or("backend family")?;
                    out.maps.backends4.insert(backend_id, value);
                }
                IpAddr::V6(_) => {
                    let value = backend_bytes6(backend).ok_or("backend family")?;
                    out.maps.backends6.insert(backend_id, value);
                }
            }
            let slot = u16::try_from(index)
                .ok()
                .and_then(|i| i.checked_add(1))
                .ok_or("slot overflow")?;
            slots.push((
                slot,
                LbService {
                    union_raw: backend_id,
                    rev_nat_index: id,
                    ..LbService::default()
                },
            ));
        }
        for (slot, value) in slots {
            match frontend.ip {
                IpAddr::V4(_) => {
                    let key = key4(frontend, slot).ok_or("frontend family")?;
                    out.maps.services4.insert(key, value.to_bytes());
                }
                IpAddr::V6(_) => {
                    let key = key6(frontend, slot).ok_or("frontend family")?;
                    out.maps.services6.insert(key, value.to_bytes());
                }
            }
        }
    }
    Ok(out)
}

/// The writes that turn `current` into `desired`, in the order spec 05 §3.4
/// requires: backends, then slots, then masters (the publish point); then
/// stale masters, stale slots and stale backends.
pub fn plan(current: &Maps, desired: &Maps) -> Vec<Op> {
    let mut ops = Vec::new();
    let changed4 = |key: &u32, value: &[u8; 12]| current.backends4.get(key) != Some(value);
    let changed6 = |key: &u32, value: &[u8; 24]| current.backends6.get(key) != Some(value);
    for (id, value) in &desired.backends4 {
        if changed4(id, value) {
            ops.push(Op::Backend4(*id, *value));
        }
    }
    for (id, value) in &desired.backends6 {
        if changed6(id, value) {
            ops.push(Op::Backend6(*id, *value));
        }
    }
    for master in [false, true] {
        for (key, value) in &desired.services4 {
            let (_, slot) = frontend4(*key);
            if (slot == 0) == master && current.services4.get(key) != Some(value) {
                ops.push(Op::Service4(*key, *value));
            }
        }
        for (key, value) in &desired.services6 {
            let (_, slot) = frontend6(*key);
            if (slot == 0) == master && current.services6.get(key) != Some(value) {
                ops.push(Op::Service6(*key, *value));
            }
        }
    }
    for master in [true, false] {
        for key in current.services4.keys() {
            let (_, slot) = frontend4(*key);
            if (slot == 0) == master && !desired.services4.contains_key(key) {
                ops.push(Op::DeleteService4(*key));
            }
        }
        for key in current.services6.keys() {
            let (_, slot) = frontend6(*key);
            if (slot == 0) == master && !desired.services6.contains_key(key) {
                ops.push(Op::DeleteService6(*key));
            }
        }
    }
    for id in current.backends4.keys() {
        if !desired.backends4.contains_key(id) {
            ops.push(Op::DeleteBackend4(*id));
        }
    }
    for id in current.backends6.keys() {
        if !desired.backends6.contains_key(id) {
            ops.push(Op::DeleteBackend6(*id));
        }
    }
    ops
}

/// Apply `ops` to an in-memory copy (tests, and what the kernel should hold
/// after a successful apply).
pub fn apply(maps: &mut Maps, ops: &[Op]) {
    for op in ops {
        match *op {
            Op::Backend4(id, value) => {
                maps.backends4.insert(id, value);
            }
            Op::Backend6(id, value) => {
                maps.backends6.insert(id, value);
            }
            Op::Service4(key, value) => {
                maps.services4.insert(key, value);
            }
            Op::Service6(key, value) => {
                maps.services6.insert(key, value);
            }
            Op::DeleteService4(key) => {
                maps.services4.remove(&key);
            }
            Op::DeleteService6(key) => {
                maps.services6.remove(&key);
            }
            Op::DeleteBackend4(id) => {
                maps.backends4.remove(&id);
            }
            Op::DeleteBackend6(id) => {
                maps.backends6.remove(&id);
            }
        }
    }
}

/// The backends a lookup of `frontend` can reach in `maps`, the way the BPF
/// program resolves them: master count, then each slot's backend ID. `None`
/// when the frontend is absent; an unresolvable slot is an error.
pub fn resolve(maps: &Maps, frontend: Address) -> Option<Result<Vec<Address>, String>> {
    let service = |slot| -> Option<LbService> {
        match frontend.ip {
            IpAddr::V4(_) => maps.services4.get(&key4(frontend, slot)?).copied(),
            IpAddr::V6(_) => maps.services6.get(&key6(frontend, slot)?).copied(),
        }
        .map(LbService::from_bytes)
    };
    let master = service(0)?;
    let mut out = Vec::new();
    for slot in 1..=master.count {
        let Some(entry) = service(slot) else {
            return Some(Err(format!("{frontend}: slot {slot} missing")));
        };
        let id = entry.backend_id();
        let backend = match frontend.ip {
            IpAddr::V4(_) => maps.backends4.get(&id).map(|v| backend4(*v)),
            IpAddr::V6(_) => maps.backends6.get(&id).map(|v| backend6(*v)),
        };
        match backend {
            Some(backend) => out.push(backend),
            None => return Some(Err(format!("{frontend}: backend {id} missing"))),
        }
    }
    Some(Ok(out))
}

#[cfg(test)]
#[path = "socket_tests.rs"]
mod tests;
