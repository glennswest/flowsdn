//! Desired rules (spec 10 §4.1): the `ip rule`s flowsdn wants, reconciled
//! into the kernel by [`RuleTarget`] through [`RuleOps`]. Rules have no
//! owners: the table is the whole set.
use crate::rows::DesiredRule;
use flowsdn_reconcile::Target;
use flowsdn_table::{Key, Keyed, Snapshot, Table, TableError};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The kernel side of the rules.
pub trait RuleOps: Send {
    fn add(&mut self, rule: &DesiredRule) -> Result<(), String>;
    fn delete(&mut self, rule: &DesiredRule) -> Result<(), String>;
    /// The rules flowsdn owns (its priority span).
    fn owned(&mut self) -> Result<Vec<DesiredRule>, String>;
}

/// Make `table` hold exactly `rules`.
pub async fn set_rules(
    table: &Table<DesiredRule>,
    rules: &BTreeSet<DesiredRule>,
) -> Result<(), TableError> {
    let snapshot = table.snapshot();
    let wanted: BTreeMap<Key, &DesiredRule> = rules.iter().map(|r| (r.primary_key(), r)).collect();
    table
        .batch(|write| -> Result<(), TableError> {
            for (row, _) in snapshot.all() {
                if !wanted.contains_key(&row.primary_key()) {
                    write.delete(&row.primary_key())?;
                }
            }
            for (key, rule) in &wanted {
                if snapshot.get("primary", key).ok().flatten().is_none() {
                    write.insert((*rule).clone())?;
                }
            }
            Ok(())
        })
        .await
}

/// The `flowsdn-reconcile` target of `desired-rules`: a row is added when
/// the kernel lacks it; prune deletes owned rules no row wants.
pub struct RuleTarget<O: RuleOps> {
    pub ops: O,
    /// The rows seen, so a deleted key can be turned back into its rule.
    seen: BTreeMap<Key, DesiredRule>,
}
impl<O: RuleOps> RuleTarget<O> {
    pub fn new(ops: O) -> Self {
        Self {
            ops,
            seen: BTreeMap::new(),
        }
    }
}
impl<O: RuleOps> Target<DesiredRule> for RuleTarget<O> {
    type Error = String;
    async fn update(&mut self, row: Arc<DesiredRule>) -> Result<(), String> {
        self.seen.insert(row.primary_key(), (*row).clone());
        if self.ops.owned()?.contains(&row) {
            return Ok(());
        }
        self.ops.add(&row)
    }
    async fn delete(&mut self, key: Key) -> Result<(), String> {
        match self.seen.remove(&key) {
            Some(rule) if self.ops.owned()?.contains(&rule) => self.ops.delete(&rule),
            // Not one this target wrote: prune finds it if it is there.
            _ => Ok(()),
        }
    }
    async fn prune(&mut self, desired: Snapshot<DesiredRule>) -> Result<(), String> {
        let wanted: BTreeSet<DesiredRule> = desired.all().map(|(r, _)| (*r).clone()).collect();
        let mut failures = Vec::new();
        for rule in self.ops.owned()? {
            if !wanted.contains(&rule)
                && let Err(error) = self.ops.delete(&rule)
            {
                failures.push(error);
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
    #![allow(clippy::unwrap_used)]
    use super::*;
    use flowsdn_reconcile::{Options, Reconciler};
    use std::sync::Mutex;

    struct Fake(Arc<Mutex<BTreeSet<DesiredRule>>>);
    impl RuleOps for Fake {
        fn add(&mut self, rule: &DesiredRule) -> Result<(), String> {
            if !self.0.lock().unwrap().insert(rule.clone()) {
                return Err("EEXIST".into());
            }
            Ok(())
        }
        fn delete(&mut self, rule: &DesiredRule) -> Result<(), String> {
            self.0.lock().unwrap().remove(rule);
            Ok(())
        }
        fn owned(&mut self) -> Result<Vec<DesiredRule>, String> {
            Ok(self.0.lock().unwrap().iter().cloned().collect())
        }
    }
    fn rule(priority: u32, table: u32) -> DesiredRule {
        DesiredRule {
            v6: false,
            priority,
            table,
            from: Some(("192.0.2.20".parse().unwrap(), 32)),
            to: None,
            suppress_prefix: None,
        }
    }

    #[tokio::test]
    async fn rules_are_added_once_and_stale_ones_pruned() {
        let table = Table::new(Vec::new()).unwrap();
        let init = table.register_initializer("test").unwrap();
        table.seal_initializers();
        let kernel = Arc::new(Mutex::new(BTreeSet::from([rule(2099, 9)])));
        let mut reconciler = Reconciler::new(
            &table,
            RuleTarget::new(Fake(Arc::clone(&kernel))),
            Options::default(),
        )
        .unwrap();
        set_rules(
            &table,
            &BTreeSet::from([rule(2080, 2081), rule(2081, 2082)]),
        )
        .await
        .unwrap();
        init.complete();
        reconciler.prune_now();
        for _ in 0..5 {
            reconciler.run_round(std::time::Instant::now()).await.ok();
        }
        assert_eq!(
            *kernel.lock().unwrap(),
            BTreeSet::from([rule(2080, 2081), rule(2081, 2082)]),
            "added, the stale one pruned"
        );
        // A rule already there is not added again (no EEXIST); one removed
        // from the set is deleted.
        set_rules(&table, &BTreeSet::from([rule(2080, 2081)]))
            .await
            .unwrap();
        for _ in 0..5 {
            reconciler.run_round(std::time::Instant::now()).await.ok();
        }
        assert_eq!(*kernel.lock().unwrap(), BTreeSet::from([rule(2080, 2081)]));
        let cells = flowsdn_table::TableRender::cells(&rule(2080, 2081));
        assert_eq!(
            cells,
            ["ipv4", "2080", "192.0.2.20/32", "all", "2081", "none"]
        );
    }
}
