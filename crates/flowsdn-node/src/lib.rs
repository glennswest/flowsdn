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
pub mod rows;
pub mod routes;
