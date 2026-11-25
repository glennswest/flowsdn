//! Proxy ports (spec 16 §3.3.1): a `(name, kind, direction)` with an
//! allocated port and a reference count.
//!
//! - **Allocation:** the requested port when it is free. Otherwise the first
//!   free one in a permutation of the range (default 10000–20000), skipping
//!   ports already allocated and ports open locally (read from the kernel's
//!   socket tables, [`open_ports`], never by binding). Ports released before
//!   are tried only on a second pass, and only after [`REUSE_DELAY`] seconds,
//!   so a connection to an old listener is never misrouted.
//! - **Release:** at a reference count of 0 the port is free again after the
//!   delay. A static port (the DNS listener's) is never released.
//! - **Persistence:** [`Ports::json`] / [`Ports::restore`] keep the
//!   allocations across agent restarts; a file older than
//!   [`RESTORE_AGE_LIMIT`] seconds is ignored.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const RANGE: (u16, u16) = (10000, 20000);
/// Seconds before a released port may be allocated again.
pub const REUSE_DELAY: u64 = 300;
/// Seconds after which a persisted file is ignored.
pub const RESTORE_AGE_LIMIT: u64 = 900;

/// One proxy port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyPort {
    /// `http`, `tls`, `dns` or `crd`.
    pub kind: String,
    pub ingress: bool,
    pub port: u16,
    /// Never released while the agent runs (the DNS listener's).
    pub is_static: bool,
    pub references: u32,
}

/// The proxy ports of this agent.
#[derive(Clone, Debug)]
pub struct Ports {
    range: (u16, u16),
    ports: BTreeMap<String, ProxyPort>,
    /// Released port -> the second it was released.
    released: BTreeMap<u16, u64>,
}
impl Default for Ports {
    fn default() -> Self {
        Self::new(RANGE)
    }
}

impl Ports {
    pub fn new(range: (u16, u16)) -> Self {
        Self {
            range,
            ports: BTreeMap::new(),
            released: BTreeMap::new(),
        }
    }
    pub fn get(&self, name: &str) -> Option<&ProxyPort> {
        self.ports.get(name)
    }
    fn taken(&self, port: u16) -> bool {
        self.ports.values().any(|p| p.port == port)
    }
    /// Take a reference on `name`'s port, allocating it on first use.
    /// `open` are the locally open ports, `now` seconds, `seed` picks where
    /// the permutation starts.
    #[allow(clippy::too_many_arguments)]
    pub fn acquire(
        &mut self,
        name: &str,
        kind: &str,
        ingress: bool,
        requested: Option<u16>,
        is_static: bool,
        open: &BTreeSet<u16>,
        now: u64,
        seed: u64,
    ) -> Result<u16, String> {
        if let Some(existing) = self.ports.get_mut(name) {
            existing.references = existing.references.saturating_add(1);
            return Ok(existing.port);
        }
        let fresh = |ports: &Self, port: u16| {
            port != 0 && !ports.taken(port) && !open.contains(&port) && !ports.released.contains_key(&port)
        };
        let port = match requested.filter(|p| fresh(self, *p)) {
            Some(port) => port,
            None => self.pick(open, now, seed).ok_or("no free proxy port in the range")?,
        };
        self.released.remove(&port);
        self.ports.insert(
            name.to_owned(),
            ProxyPort {
                kind: kind.to_owned(),
                ingress,
                port,
                is_static,
                references: 1,
            },
        );
        Ok(port)
    }
    /// The first free port of a permutation of the range: unused ports, then
    /// released ones past the delay.
    fn pick(&self, open: &BTreeSet<u16>, now: u64, seed: u64) -> Option<u16> {
        let (low, high) = self.range;
        let span = u64::from(high.checked_sub(low)?).checked_add(1)?;
        // A stride coprime with the span visits every port once.
        let mut stride = 7919u64.checked_rem(span)?;
        while stride == 0 || gcd(stride, span) != 1 {
            stride = stride.checked_add(1)?;
        }
        let start = seed.checked_rem(span)?;
        for second in [false, true] {
            for step in 0..span {
                let offset = start
                    .checked_add(step.checked_mul(stride)?.checked_rem(span)?)?
                    .checked_rem(span)?;
                let port = u16::try_from(u64::from(low).checked_add(offset)?).ok()?;
                if self.taken(port) || open.contains(&port) {
                    continue;
                }
                match (second, self.released.get(&port)) {
                    (false, None) => return Some(port),
                    (true, Some(at)) if now.saturating_sub(*at) >= REUSE_DELAY => return Some(port),
                    _ => {}
                }
            }
        }
        None
    }
    /// Drop a reference on `name`'s port; at 0 a non-static port is released.
    pub fn release(&mut self, name: &str, now: u64) {
        let Some(port) = self.ports.get_mut(name) else {
            return;
        };
        port.references = port.references.saturating_sub(1);
        if port.references == 0 && !port.is_static {
            let number = port.port;
            self.ports.remove(name);
            self.released.insert(number, now);
        }
    }
    /// The persisted form (`<state-dir>/proxy-ports.json`).
    pub fn json(&self) -> Value {
        let ports: Vec<Value> = self
            .ports
            .iter()
            .map(|(name, p)| {
                json!({"name": name, "kind": p.kind, "ingress": p.ingress, "port": p.port,
                       "static": p.is_static})
            })
            .collect();
        json!({"ports": ports})
    }
    /// Pre-allocate the persisted ports (with no references yet), unless the
    /// file is older than [`RESTORE_AGE_LIMIT`] seconds.
    pub fn restore(&mut self, persisted: &Value, age: u64) -> usize {
        if age > RESTORE_AGE_LIMIT {
            return 0;
        }
        let mut restored = 0usize;
        for entry in persisted
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let port = entry
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0);
            if name.is_empty() || port == 0 || self.taken(port) || self.ports.contains_key(name) {
                continue;
            }
            self.ports.insert(
                name.to_owned(),
                ProxyPort {
                    kind: entry.get("kind").and_then(Value::as_str).unwrap_or("").to_owned(),
                    ingress: entry.get("ingress").and_then(Value::as_bool).unwrap_or(false),
                    port,
                    is_static: entry.get("static").and_then(Value::as_bool).unwrap_or(false),
                    references: 0,
                },
            );
            restored = restored.saturating_add(1);
        }
        restored
    }
}

fn gcd(a: u64, b: u64) -> u64 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        let r = a.checked_rem(b).unwrap_or(0);
        a = b;
        b = r;
    }
    a
}

/// The local ports of every TCP and UDP socket, IPv4 and IPv6, from
/// `/proc/net/{tcp,tcp6,udp,udp6}` (field 2, `address:PORT` in hex).
pub fn open_ports() -> BTreeSet<u16> {
    let mut out = BTreeSet::new();
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/net/{table}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            if let Some(port) = line
                .split_whitespace()
                .nth(1)
                .and_then(|local| local.rsplit_once(':'))
                .and_then(|(_, port)| u16::from_str_radix(port, 16).ok())
            {
                out.insert(port);
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "ports_tests.rs"]
mod tests;
