//! The names the DNS proxy has seen answered and their addresses, until
//! their TTLs run out (spec 16 §3.6.7), and the local identity of each such
//! address while any name holds it.
//!
//! flowsdn keeps one cache for the node, not one per endpoint: an FQDN
//! selector selects the addresses its names were answered with, whichever
//! endpoint asked (the reference's identities and ipcache labels are
//! node-wide too; its per-endpoint caches decide when an address is
//! released). A connection already open to an address that expired keeps
//! working through the endpoint's flow entry, the reference's zombies'
//! purpose; a new one is judged without it.
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// The local identity scope (spec 03 §3.1: `1 << 24`), upper half: CIDR
/// identities of the agent's policy compiler number up from the scope's
/// base, these from here.
pub const IDENTITY_BASE: u32 = (1 << 24) | (1 << 23);
/// Identities above [`IDENTITY_BASE`].
pub const IDENTITY_COUNT: u32 = (1 << 23) - 1;

/// The cache's limits (spec 16 §3.6.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `tofqdns-min-ttl`: the smallest TTL kept, in seconds.
    pub min_ttl: u32,
    /// `tofqdns-endpoint-max-ip-per-hostname`: addresses kept per name.
    pub max_ips_per_name: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            min_ttl: 0,
            max_ips_per_name: 1000,
        }
    }
}

/// Name -> address -> when it expires (seconds, the caller's clock).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cache {
    names: BTreeMap<String, BTreeMap<IpAddr, u64>>,
    identities: BTreeMap<IpAddr, u32>,
    pub limits: Limits,
}

impl Cache {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }
    /// An answer: each of `names` holds each of `ips` for the effective TTL
    /// (`max(ttl, min-ttl)`) from `now`. Whether anything changed.
    pub fn insert(&mut self, names: &[String], ips: &[IpAddr], ttl: u32, now: u64) -> bool {
        let expires = now.saturating_add(u64::from(ttl.max(self.limits.min_ttl)));
        let mut changed = false;
        for name in names {
            let held = self.names.entry(name.clone()).or_default();
            for ip in ips {
                let slot = held.entry(*ip).or_insert(0);
                if *slot < expires {
                    changed |= *slot == 0;
                    *slot = expires;
                }
            }
            // Over the limit: the soonest to expire go first.
            while held.len() > self.limits.max_ips_per_name {
                let Some(oldest) = held.iter().min_by_key(|(_, e)| **e).map(|(ip, _)| *ip) else {
                    break;
                };
                held.remove(&oldest);
                changed = true;
            }
        }
        self.number();
        changed
    }
    /// Forget what expired by `now`. Whether anything did.
    pub fn expire(&mut self, now: u64) -> bool {
        let mut changed = false;
        for held in self.names.values_mut() {
            let before = held.len();
            held.retain(|_, expires| *expires > now);
            changed |= held.len() != before;
        }
        self.names.retain(|_, held| !held.is_empty());
        self.number();
        changed
    }
    /// Give each held address an identity, keep those still held, free the
    /// rest. An address keeps its number while any name holds it.
    fn number(&mut self) {
        let held: BTreeSet<IpAddr> = self
            .names
            .values()
            .flat_map(|h| h.keys().copied())
            .collect();
        self.identities.retain(|ip, _| held.contains(ip));
        let mut used: BTreeSet<u32> = self.identities.values().copied().collect();
        let mut next = 1u32;
        for ip in held {
            if self.identities.contains_key(&ip) {
                continue;
            }
            while used.contains(&IDENTITY_BASE.saturating_add(next)) && next < IDENTITY_COUNT {
                next = next.saturating_add(1);
            }
            if next >= IDENTITY_COUNT {
                break;
            }
            let id = IDENTITY_BASE.saturating_add(next);
            used.insert(id);
            self.identities.insert(ip, id);
        }
    }
    /// The addresses of the names `selects` accepts.
    pub fn ips(&self, selects: impl Fn(&str) -> bool) -> BTreeSet<IpAddr> {
        self.names
            .iter()
            .filter(|(name, _)| selects(name))
            .flat_map(|(_, held)| held.keys().copied())
            .collect()
    }
    /// An address's identity, while a name holds it.
    pub fn identity(&self, ip: &IpAddr) -> Option<u32> {
        self.identities.get(ip).copied()
    }
    pub fn identities(&self) -> &BTreeMap<IpAddr, u32> {
        &self.identities
    }
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
    /// `{name: {address: expires}}`.
    pub fn json(&self) -> Value {
        Value::Object(
            self.names
                .iter()
                .map(|(name, held)| {
                    (
                        name.clone(),
                        Value::Object(
                            held.iter()
                                .map(|(ip, expires)| (ip.to_string(), json!(expires)))
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }
}
