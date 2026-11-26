//! The agent's node model in spec 10's tables (§3.1.1, §4.1; #576, ADR-0004:
//! devices, routes and node addresses share one mechanism).
//!
//! - [`rows`]: the realized views (`devices`, `routes`, `neighbors`,
//!   `node-addresses`) and the desired ones (`desired-routes`,
//!   `forwardable-ips`, `desired-neighbors`). Each row renders the columns
//!   of the harvested `.table` files (spec 00 §4.3a).
//! - [`addresses`]: `node-addresses` derived from `devices` and the local
//!   table (§3.1.6).
//! - [`routes`]: the route manager (owners write their desired routes; the
//!   lowest admin distance of a `(table, prefix, priority)` is selected) and
//!   the `flowsdn-reconcile` target that puts the selected routes into the
//!   kernel through [`routes::RouteOps`].
//!
//! Kernel access is the caller's (the agent implements the ops over
//! `flowsdn-connector`), so everything here is tested without a kernel.
#![forbid(unsafe_code)]

pub mod addresses;
pub mod neighbors;
pub mod routes;
pub mod rows;
pub mod rules;

/// Make `table` hold exactly `rows`: rows not given are deleted, changed or
/// new ones written, unchanged ones left alone (no revision, no reconcile).
pub async fn set_all<T>(
    table: &flowsdn_table::Table<T>,
    rows: impl IntoIterator<Item = T>,
) -> Result<(), flowsdn_table::TableError>
where
    T: flowsdn_table::Keyed + Clone + PartialEq + Send + Sync + 'static,
{
    use flowsdn_table::Keyed;
    let snapshot = table.snapshot();
    let wanted: std::collections::BTreeMap<Vec<u8>, T> =
        rows.into_iter().map(|r| (r.primary_key(), r)).collect();
    table
        .batch(|write| -> Result<(), flowsdn_table::TableError> {
            for (row, _) in snapshot.all() {
                if !wanted.contains_key(&row.primary_key()) {
                    write.delete(&row.primary_key())?;
                }
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
