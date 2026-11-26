//! Desired routes (spec 10 §4.1): owners write the routes they want into
//! `desired-routes` through a [`RouteManager`]; for each `(table, prefix,
//! priority)` the lowest admin distance (then owner name) is `selected`. The
//! [`RouteTarget`] puts the selected routes into the kernel through
//! [`RouteOps`] under `flowsdn-reconcile` (ADR-0009 statuses, prune after
//! initialization).
use crate::rows::{DesiredRoute, desired_route_indexes, group_key, parse_group};
use flowsdn_reconcile::Target;
use flowsdn_table::{Key, Table, TableError};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Mark the selected route of every group in `rows` (lowest admin distance,
/// then owner name); every other row is not selected.
pub fn select(rows: &mut [DesiredRoute]) {
    let mut best: BTreeMap<Vec<u8>, (u8, String)> = BTreeMap::new();
    for row in rows.iter() {
        let candidate = (row.admin_distance, row.owner.clone());
        best.entry(row.group_key())
            .and_modify(|b| {
                if candidate < *b {
                    *b = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    for row in rows.iter_mut() {
        row.selected = best
            .get(&row.group_key())
            .is_some_and(|(ad, owner)| *ad == row.admin_distance && *owner == row.owner);
    }
}

/// The only writer of `desired-routes`: owners replace their rows, and the
/// selection of every group they touch is recomputed, under one lock.
pub struct RouteManager {
    table: Arc<Table<DesiredRoute>>,
    lock: tokio::sync::Mutex<()>,
}
impl RouteManager {
    pub fn new() -> Result<Self, TableError> {
        Ok(Self {
            table: Arc::new(Table::new(desired_route_indexes())?),
            lock: tokio::sync::Mutex::new(()),
        })
    }
    pub fn table(&self) -> Arc<Table<DesiredRoute>> {
        Arc::clone(&self.table)
    }
    /// Make `owner`'s rows exactly `rows` (their `owner` is set to it and
    /// `selected` computed), and re-select every group either touches.
    pub async fn set_owner(&self, owner: &str, rows: Vec<DesiredRoute>) -> Result<(), TableError> {
        let _guard = self.lock.lock().await;
        let snapshot = self.table.snapshot();
        let mut current: Vec<DesiredRoute> = snapshot.all().map(|(r, _)| (*r).clone()).collect();
        let mut groups: BTreeSet<Vec<u8>> = current
            .iter()
            .filter(|r| r.owner == owner)
            .map(DesiredRoute::group_key)
            .collect();
        current.retain(|r| r.owner != owner);
        for mut row in rows {
            row.owner = owner.to_owned();
            groups.insert(row.group_key());
            current.push(row);
        }
        select(&mut current);
        let wanted: BTreeMap<Key, DesiredRoute> = current
            .into_iter()
            .filter(|r| groups.contains(&r.group_key()))
            .map(|r| (flowsdn_table::Keyed::primary_key(&r), r))
            .collect();
        let stale: Vec<Key> = snapshot
            .all()
            .filter(|(r, _)| groups.contains(&r.group_key()))
            .map(|(r, _)| flowsdn_table::Keyed::primary_key(&*r))
            .filter(|k| !wanted.contains_key(k))
            .collect();
        self.table
            .batch(|write| -> Result<(), TableError> {
                for key in &stale {
                    write.delete(key)?;
                }
                for (key, row) in wanted {
                    let unchanged = snapshot
                        .get("primary", &key)
                        .ok()
                        .flatten()
                        .is_some_and(|(old, _)| *old == row);
                    if !unchanged {
                        write.insert(row)?;
                    }
                }
                Ok(())
            })
            .await
    }
}

/// The kernel side of the routes: replace one route, delete one, and list the
/// routes flowsdn owns in the tables it manages (for prune).
pub trait RouteOps: Send {
    /// Install `route` with replace semantics.
    fn replace(&mut self, route: &DesiredRoute) -> Result<(), String>;
    /// Delete the route `(table, prefix, priority)`, if flowsdn's; absent is
    /// success.
    fn delete(&mut self, table: u32, prefix: (std::net::IpAddr, u8), priority: u32) -> Result<(), String>;
    /// The `(table, prefix, priority)` of every route flowsdn owns.
    fn owned(&mut self) -> Result<Vec<(u32, (std::net::IpAddr, u8), u32)>, String>;
}

/// The `flowsdn-reconcile` target of `desired-routes`: a selected row is
/// installed; deleting a row deletes its kernel route only when no other row
/// of its group is selected; prune deletes owned routes no selected row wants.
pub struct RouteTarget<O: RouteOps> {
    pub ops: O,
    table: Arc<Table<DesiredRoute>>,
}
impl<O: RouteOps> RouteTarget<O> {
    pub fn new(ops: O, table: Arc<Table<DesiredRoute>>) -> Self {
        Self { ops, table }
    }
}
impl<O: RouteOps> Target<DesiredRoute> for RouteTarget<O> {
    type Error = String;
    async fn update(&mut self, row: Arc<DesiredRoute>) -> Result<(), String> {
        if row.selected {
            self.ops.replace(&row)
        } else {
            Ok(())
        }
    }
    async fn delete(&mut self, key: Key) -> Result<(), String> {
        let (table, prefix, priority) = parse_group(&key).ok_or("malformed desired-route key")?;
        let group = group_key(table, &prefix, Some(priority));
        let still = self
            .table
            .snapshot()
            .list("group", &group)
            .map_err(|e| e.to_string())?
            .into_iter()
            .any(|(r, _)| r.selected);
        if still {
            return Ok(());
        }
        self.ops.delete(table, prefix, priority)
    }
    async fn prune(&mut self, desired: flowsdn_table::Snapshot<DesiredRoute>) -> Result<(), String> {
        let wanted: BTreeSet<Vec<u8>> = desired
            .all()
            .filter(|(r, _)| r.selected)
            .map(|(r, _)| r.group_key())
            .collect();
        let mut failures = Vec::new();
        for (table, prefix, priority) in self.ops.owned()? {
            if !wanted.contains(&group_key(table, &prefix, Some(priority)))
                && let Err(error) = self.ops.delete(table, prefix, priority)
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
#[path = "routes_tests.rs"]
mod tests;
