//! Canonical kernel-entry lookup and same-identity authentication preparation.
//! This is not the full Rule-to-LPM compiler: Pass reranking, origins and
//! cross-identity covering-rule insertion must precede this layer.
use crate::oracle::Packet;
use flowsdn_bpf_abi::policy::{PolicyEntry, PolicyKey};
use flowsdn_identity::numeric::{ClusterEncoding, NumericIdentity};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub key: PolicyKey,
    pub entry: PolicyEntry,
    pub origin: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Miss,
    Deny,
    Allow {
        proxy_port: u16,
        authentication: u8,
        cookie: u32,
    },
}
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub encoding: ClusterEncoding,
    pub local_cluster: u16,
}
impl Context {
    fn aggregate(self, id: u32) -> Result<u32, &'static str> {
        let id = NumericIdentity::new(id).map_err(|_| "invalid identity")?;
        self.encoding
            .aggregate_for(id, self.local_cluster)
            .map(|a| a as u32)
            .map_err(|_| "invalid cluster context")
    }
}
fn canonical(record: &Record) -> Result<(), &'static str> {
    let k = record.key;
    let v = record.entry;
    NumericIdentity::new(k.sec_label).map_err(|_| "invalid key identity")?;
    let prefix = if k.protocol == 0 {
        0
    } else {
        u8::try_from(k.prefixlen.checked_sub(48).ok_or("key prefix")?).map_err(|_| "key prefix")?
    };
    let reconstructed = PolicyKey::new(
        k.sec_label,
        k.egress == 1,
        k.protocol,
        k.dport.get(),
        prefix,
    )
    .map_err(|_| "key prefix")?;
    if k.egress > 1
        || reconstructed != k
        || u32::from(v.lpm_prefix_length()) != k.prefixlen.saturating_sub(40)
        || v.flags & 6 != 0
    {
        return Err("noncanonical key/value");
    }
    if v.precedence & 255 == 0 {
        return Err("Pass must be resolved before kernel insertion");
    }
    if v.denies() && (v.auth != 0 || v.proxy_port.get() != 0 || v.precedence & 255 != 255) {
        return Err("noncanonical deny");
    }
    if !v.denies() && ((v.precedence & 255 == 1) != (v.proxy_port.get() == 0)) {
        return Err("redirect precedence and proxy port disagree");
    }
    if !v.denies() && v.precedence & 255 == 255 {
        return Err("deny precedence on allow");
    }
    Ok(())
}
fn matches(record: &Record, packet: Packet, id: u32) -> bool {
    let k = record.key;
    if k.sec_label != id || k.egress != u8::from(packet.egress) {
        return false;
    }
    if k.protocol == 0 {
        return true;
    }
    if k.protocol != packet.protocol {
        return false;
    }
    let bits = k.prefixlen.saturating_sub(48);
    let mask = u16::MAX
        .checked_shl(16u32.saturating_sub(bits))
        .unwrap_or(0);
    packet.port & mask == k.dport.get()
}
/// Brute-force ABI oracle. It scans records three separate times, then applies
/// the datapath comparison directly; no indexed lookup helper is called.
pub fn scan(records: &[Record], context: Context, packet: Packet) -> Result<Outcome, &'static str> {
    for (position, record) in records.iter().enumerate() {
        canonical(record)?;
        if records.iter().take(position).any(|r| r.key == record.key) {
            return Err("duplicate policy key");
        }
    }
    let aggregate = context.aggregate(packet.identity)?;
    let exact = records
        .iter()
        .filter(|r| matches(r, packet, packet.identity))
        .max_by_key(|r| r.key.prefixlen);
    let mut other = if aggregate == packet.identity {
        None
    } else {
        records
            .iter()
            .filter(|r| matches(r, packet, aggregate))
            .max_by_key(|r| r.key.prefixlen)
    };
    if exact.is_none() && other.is_none() && aggregate != 0 {
        other = records
            .iter()
            .filter(|r| matches(r, packet, 0))
            .max_by_key(|r| r.key.prefixlen);
    }
    let (chosen, alternate) = match (exact, other) {
        (Some(s), Some(a))
            if s.entry.precedence != u32::MAX
                && (a.entry.precedence > s.entry.precedence
                    || (a.entry.precedence == s.entry.precedence
                        && a.key.prefixlen > s.key.prefixlen)) =>
        {
            (a, Some(s))
        }
        (Some(s), a) => (
            s,
            if s.entry.precedence == u32::MAX {
                None
            } else {
                a
            },
        ),
        (None, Some(a)) => (a, None),
        (None, None) => return Ok(Outcome::Miss),
    };
    if chosen.entry.denies() {
        return Ok(Outcome::Deny);
    }
    let mut auth = chosen.entry.auth_type();
    if !chosen.entry.has_explicit_auth_type()
        && let Some(other) = alternate.filter(|r| r.entry.precedence == chosen.entry.precedence)
    {
        auth = auth.max(other.entry.auth_type());
    }
    Ok(Outcome::Allow {
        proxy_port: chosen.entry.proxy_port.get(),
        authentication: auth,
        cookie: chosen.entry.cookie,
    })
}
type Key = (u32, bool, u8, u8, u16);
#[derive(Clone, Debug)]
pub struct Index {
    entries: BTreeMap<Key, PolicyEntry>,
}
impl Index {
    pub fn new(records: &[Record]) -> Result<Self, &'static str> {
        let mut entries = BTreeMap::new();
        for record in records {
            canonical(record)?;
            let k = record.key;
            let prefix = u8::try_from(k.prefixlen.saturating_sub(48)).map_err(|_| "prefix")?;
            if entries
                .insert(
                    (
                        k.sec_label,
                        k.egress == 1,
                        k.protocol,
                        prefix,
                        k.dport.get(),
                    ),
                    record.entry,
                )
                .is_some()
            {
                return Err("duplicate policy key");
            }
        }
        Ok(Self { entries })
    }
    fn find(&self, id: u32, p: Packet) -> Option<PolicyEntry> {
        if p.protocol != 0 {
            for bits in (0..=16u8).rev() {
                let mask = u16::MAX
                    .checked_shl(u32::from(16u8.saturating_sub(bits)))
                    .unwrap_or(0);
                if let Some(entry) =
                    self.entries
                        .get(&(id, p.egress, p.protocol, bits, p.port & mask))
                {
                    return Some(*entry);
                }
            }
        }
        self.entries.get(&(id, p.egress, 0, 0, 0)).copied()
    }
    pub fn lookup(&self, context: Context, p: Packet) -> Result<Outcome, &'static str> {
        let agg = context.aggregate(p.identity)?;
        let specific = self.find(p.identity, p);
        let aggregate = if agg != p.identity {
            self.find(agg, p)
        } else {
            None
        };
        let mut candidates = Vec::new();
        if let Some(entry) = aggregate {
            candidates.push((entry, false));
        }
        if let Some(entry) = specific {
            candidates.push((entry, true));
        }
        if candidates.is_empty()
            && agg != 0
            && let Some(entry) = self.find(0, p)
        {
            candidates.push((entry, false));
        }
        candidates.sort_by_key(|(e, s)| (e.precedence, e.lpm_prefix_length(), *s));
        let Some((chosen, _)) = candidates.last() else {
            return Ok(Outcome::Miss);
        };
        if chosen.denies() {
            return Ok(Outcome::Deny);
        }
        let authentication = if chosen.has_explicit_auth_type() {
            chosen.auth_type()
        } else {
            candidates
                .iter()
                .filter(|(e, _)| e.precedence == chosen.precedence)
                .map(|(e, _)| e.auth_type())
                .max()
                .unwrap_or(0)
        };
        Ok(Outcome::Allow {
            proxy_port: chosen.proxy_port.get(),
            authentication,
            cookie: chosen.cookie,
        })
    }
}
fn covers(parent: &Record, child: &Record) -> bool {
    parent.key.prefixlen < child.key.prefixlen
        && matches(
            parent,
            Packet {
                identity: child.key.sec_label,
                egress: child.key.egress == 1,
                protocol: child.key.protocol,
                port: child.key.dport.get(),
            },
            child.key.sec_label,
        )
}
/// Inherit explicit auth through same-identity covering keys, independent of
/// redirect rank within one allow priority. Input is already precedence-normalized:
/// a stronger covering entry must have been propagated/pruned by the compiler.
/// Reject such unprepared input rather than silently changing security policy.
pub fn inherit_auth(records: &[Record]) -> Result<Vec<Record>, &'static str> {
    Index::new(records)?;
    let mut result = records.to_vec();
    for target in &mut result {
        if target.entry.denies() {
            continue;
        }
        let parents = records
            .iter()
            .filter(|p| covers(p, target))
            .collect::<Vec<_>>();
        if parents
            .iter()
            .any(|p| p.entry.precedence > target.entry.precedence)
        {
            return Err("covering precedence must be normalized before auth propagation");
        }
        if target.entry.has_explicit_auth_type() {
            continue;
        }
        let applicable = parents
            .into_iter()
            .filter(|p| {
                !p.entry.denies()
                    && p.entry.has_explicit_auth_type()
                    && (p.entry.precedence & !255) >= (target.entry.precedence & !255)
            })
            .max_by_key(|p| p.key.prefixlen);
        if let Some(parent) = applicable {
            target.entry.auth = parent.entry.auth_type();
        }
    }
    Ok(result)
}
/// Remove only identical same-prefix category aggregate duplicates. Origin and
/// cookie must also match. This never prunes across wildcard/aggregate boundaries.
pub fn prune_aggregate_duplicates(
    records: &[Record],
    context: Context,
) -> Result<Vec<Record>, &'static str> {
    Index::new(records)?;
    let mut out = Vec::new();
    for record in records {
        let agg = context.aggregate(record.key.sec_label)?;
        // Without full covering-rule normalization, another entry in either
        // identity bucket may become visible after pruning. Keep that case.
        let isolated = records
            .iter()
            .filter(|r| {
                r.key.sec_label == record.key.sec_label && r.key.egress == record.key.egress
            })
            .count()
            == 1
            && records
                .iter()
                .filter(|r| r.key.sec_label == agg && r.key.egress == record.key.egress)
                .count()
                == 1;
        let equivalent = isolated
            && agg != record.key.sec_label
            && records.iter().any(|other| {
                let mut key = record.key;
                key.sec_label = agg;
                other.key == key && other.entry == record.entry && other.origin == record.origin
            });
        if !equivalent {
            out.push(record.clone());
        }
    }
    Ok(out)
}
