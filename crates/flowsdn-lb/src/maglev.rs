//! Deterministic Maglev table, spec05§5.1. Arithmetic hashes wrap by definition.
use std::{collections::BTreeSet, net::IpAddr};
#[derive(Clone, Debug)]
pub struct Backend {
    pub id: u32,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: &'static str,
    pub cluster: u32,
    pub internal: bool,
    pub weight: u16,
}
impl Backend {
    pub fn hash_string(&self) -> String {
        let mut address = match self.address {
            IpAddr::V4(v) => v.to_string(),
            IpAddr::V6(v) => format!("[{v}]"),
        };
        if self.cluster != 0 {
            address.push_str(&format!("@{}", self.cluster));
        }
        format!(
            "[{}:{}/{}{},State:active]",
            address,
            self.port,
            self.protocol,
            if self.internal { "/i" } else { "" }
        )
    }
}
fn mix(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^ (k >> 33)
}
/// MurmurHash3 x64 128-bit variant. Lanes use little-endian input words.
pub fn hash(bytes: &[u8], seed: u32) -> (u64, u64) {
    const C1: u64 = 0x87c37b91114253d5;
    const C2: u64 = 0x4cf5ad432745937f;
    let (mut h1, mut h2) = (u64::from(seed), u64::from(seed));
    let mut chunks = bytes.chunks_exact(16);
    for chunk in &mut chunks {
        let (a, b) = chunk.split_at(8);
        let k1 = u64::from_le_bytes(a.try_into().expect("8"));
        let k2 = u64::from_le_bytes(b.try_into().expect("8"));
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dce729);
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x38495ab5);
    }
    let tail = chunks.remainder();
    let (mut k1, mut k2) = (0u64, 0u64);
    for (i, b) in tail.iter().enumerate() {
        let shift = u32::try_from(i % 8).expect("bounded").wrapping_mul(8);
        if i < 8 {
            k1 |= u64::from(*b) << shift;
        } else {
            k2 |= u64::from(*b) << shift;
        }
    }
    if tail.len() > 8 {
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
    }
    if !tail.is_empty() {
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    }
    h1 ^= bytes.len() as u64;
    h2 ^= bytes.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = mix(h1);
    h2 = mix(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}
struct Work {
    id: u32,
    weight: u64,
    counter: f64,
    offset: u64,
    skip: u64,
    next: u64,
}
/// Sizes are the supported primes. Zero weights are rejected: callers must
/// remove disabled backends before table computation. Empty input yields no LUT.
#[allow(clippy::arithmetic_side_effects)] // validated nonzero primes and bounded table/backend sizes; floating arithmetic matches spec
pub fn table(backends: &[Backend], size: usize, seed: u32) -> Result<Vec<u32>, &'static str> {
    if ![
        251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071,
    ]
    .contains(&size)
        || backends.len() > 65535
    {
        return Err("invalid Maglev size");
    }
    if backends.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = BTreeSet::new();
    let mut sorted = Vec::new();
    for b in backends {
        if b.weight == 0 || !matches!(b.protocol, "TCP" | "UDP" | "SCTP") || !ids.insert(b.id) {
            return Err("invalid backend");
        }
        sorted.push((b.hash_string(), b));
    }
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted
        .windows(2)
        .any(|p| p.first().map(|v| &v.0) == p.last().map(|v| &v.0))
    {
        return Err("duplicate backend address");
    }
    let count = sorted.len() as u64;
    let sum = sorted.iter().map(|(_, b)| u64::from(b.weight)).sum::<u64>();
    let weighted = sum / count > 1;
    let m = size as u64;
    let mut work = sorted
        .into_iter()
        .map(|(s, b)| {
            let (a, c) = hash(s.as_bytes(), seed);
            Work {
                id: b.id,
                weight: u64::from(b.weight),
                counter: f64::from(b.weight) / count as f64,
                offset: a % m,
                skip: c % (m - 1) + 1,
                next: 0,
            }
        })
        .collect::<Vec<_>>();
    let mut entries = vec![None; size];
    for n in 0..size {
        let mut i = n % work.len();
        loop {
            let w = work.get_mut(i).ok_or("backend index")?;
            if weighted && (n as u64 + 1) * w.weight < (w.counter as u64) {
                i = (i + 1) % backends.len();
                continue;
            }
            if weighted {
                w.counter += sum as f64;
            }
            loop {
                let slot = ((w.offset + w.next * w.skip) % m) as usize;
                w.next += 1;
                let entry = entries.get_mut(slot).ok_or("slot")?;
                if entry.is_none() {
                    *entry = Some(w.id);
                    break;
                }
            }
            break;
        }
    }
    entries
        .into_iter()
        .map(|v| v.ok_or("unfilled table"))
        .collect()
}
