//! Forwardable IPs and desired neighbors (spec 10 §3.4, §4.1): owners name
//! the addresses whose neighbors flowsdn keeps (`forwardable-ips`); the
//! next hops of each on each selected device are `desired-neighbors`, which
//! [`NeighborTarget`] reconciles into kernel-managed entries through
//! [`NeighborOps`]. Prune deletes learned entries no row wants; an entry
//! without `NTF_EXT_LEARNED` (an administrator's) is never the target's.
use crate::rows::{DesiredNeighbor, ForwardableIp};
use flowsdn_reconcile::Target;
use flowsdn_table::{Key, Snapshot};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

/// `forwardable-ips` rows from `(address, owner)` pairs: one row per
/// address with its owners, sorted.
pub fn forwardable(pairs: impl IntoIterator<Item = (IpAddr, String)>) -> Vec<ForwardableIp> {
    let mut owners: BTreeMap<IpAddr, BTreeSet<String>> = BTreeMap::new();
    for (addr, owner) in pairs {
        owners.entry(addr).or_default().insert(owner);
    }
    owners
        .into_iter()
        .map(|(addr, owners)| ForwardableIp {
            addr,
            owners: owners.into_iter().collect(),
        })
        .collect()
}

/// The kernel side of the neighbors.
pub trait NeighborOps: Send {
    /// Add (or refresh) a managed entry.
    fn add(&mut self, neighbor: &DesiredNeighbor) -> Result<(), String>;
    /// Delete an entry; absent is success.
    fn delete(&mut self, neighbor: &DesiredNeighbor) -> Result<(), String>;
    /// The learned entries on the selected devices.
    fn learned(&mut self) -> Result<Vec<DesiredNeighbor>, String>;
}

/// The `flowsdn-reconcile` target of `desired-neighbors`. `removed` lists the
/// entries prune deleted.
pub struct NeighborTarget<O: NeighborOps> {
    pub ops: O,
    pub removed: Vec<DesiredNeighbor>,
    seen: BTreeMap<Key, DesiredNeighbor>,
}
impl<O: NeighborOps> NeighborTarget<O> {
    pub fn new(ops: O) -> Self {
        Self {
            ops,
            removed: Vec::new(),
            seen: BTreeMap::new(),
        }
    }
}
impl<O: NeighborOps> Target<DesiredNeighbor> for NeighborTarget<O> {
    type Error = String;
    async fn update(&mut self, row: Arc<DesiredNeighbor>) -> Result<(), String> {
        self.seen
            .insert(flowsdn_table::Keyed::primary_key(&*row), (*row).clone());
        self.ops.add(&row)
    }
    async fn delete(&mut self, key: Key) -> Result<(), String> {
        match self.seen.remove(&key) {
            Some(neighbor) => {
                self.ops.delete(&neighbor)?;
                self.removed.push(neighbor);
                Ok(())
            }
            None => Ok(()),
        }
    }
    async fn prune(&mut self, desired: Snapshot<DesiredNeighbor>) -> Result<(), String> {
        let wanted: BTreeSet<Key> = desired
            .all()
            .map(|(r, _)| flowsdn_table::Keyed::primary_key(&*r))
            .collect();
        let mut failures = Vec::new();
        for neighbor in self.ops.learned()? {
            if wanted.contains(&flowsdn_table::Keyed::primary_key(&neighbor)) {
                continue;
            }
            match self.ops.delete(&neighbor) {
                Ok(()) => self.removed.push(neighbor),
                Err(error) => failures.push(error),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use flowsdn_reconcile::{Options, Reconciler};
    use flowsdn_table::Table;
    use std::sync::Mutex;

    struct Fake(Arc<Mutex<BTreeSet<(u32, IpAddr, bool)>>>);
    impl NeighborOps for Fake {
        fn add(&mut self, n: &DesiredNeighbor) -> Result<(), String> {
            self.0.lock().unwrap().insert((n.link_index, n.addr, true));
            Ok(())
        }
        fn delete(&mut self, n: &DesiredNeighbor) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .retain(|(i, a, _)| !(*i == n.link_index && *a == n.addr));
            Ok(())
        }
        fn learned(&mut self) -> Result<Vec<DesiredNeighbor>, String> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, _, learned)| *learned)
                .map(|(link_index, addr, _)| DesiredNeighbor {
                    addr: *addr,
                    link_index: *link_index,
                })
                .collect())
        }
    }
    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }
    fn n(index: u32, addr: &str) -> DesiredNeighbor {
        DesiredNeighbor {
            addr: ip(addr),
            link_index: index,
        }
    }

    #[test]
    fn forwardable_ips_merge_owners() {
        let rows = forwardable([
            (ip("192.0.2.2"), "node:b".to_owned()),
            (ip("192.0.2.1"), "node:a".to_owned()),
            (ip("192.0.2.2"), "node:a".to_owned()),
        ]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].owners, ["node:a", "node:b"]);
    }

    #[tokio::test]
    async fn neighbors_are_kept_and_stale_learned_ones_pruned() {
        let table = Table::new(Vec::new()).unwrap();
        let init = table.register_initializer("test").unwrap();
        table.seal_initializers();
        let kernel = Arc::new(Mutex::new(BTreeSet::from([
            (3, ip("192.0.2.9"), true),
            (3, ip("192.0.2.254"), false),
        ])));
        let mut reconciler = Reconciler::new(
            &table,
            NeighborTarget::new(Fake(Arc::clone(&kernel))),
            Options::default(),
        )
        .unwrap();
        crate::set_all(&table, [n(3, "192.0.2.1"), n(4, "192.0.2.1")])
            .await
            .unwrap();
        init.complete();
        reconciler.prune_now();
        for _ in 0..5 {
            reconciler.run_round(std::time::Instant::now()).await.ok();
        }
        assert_eq!(
            *kernel.lock().unwrap(),
            BTreeSet::from([
                (3, ip("192.0.2.1"), true),
                (3, ip("192.0.2.254"), false),
                (4, ip("192.0.2.1"), true),
            ]),
            "the stale learned entry goes; an administrator's stays"
        );
        assert_eq!(reconciler.target().removed, [n(3, "192.0.2.9")]);
        crate::set_all(&table, [n(3, "192.0.2.1")]).await.unwrap();
        for _ in 0..5 {
            reconciler.run_round(std::time::Instant::now()).await.ok();
        }
        assert!(!kernel.lock().unwrap().contains(&(4, ip("192.0.2.1"), true)));
    }
}
