//! The agent side of the scripttest harness (spec 17 §3.5, §3.6, §11.1;
//! ADR-0004): the per-script `Fixture` that replaces the reference's hive,
//! the fakes it holds, and one builder per corpus area. The engine crate
//! (`flowsdn-scripttest`) stays free of agent dependencies; this crate is where
//! they enter.
pub mod areas;
pub mod fixture;
pub mod health;
pub mod k8s;
pub mod time;
