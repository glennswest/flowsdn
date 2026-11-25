//! The L7 proxy core in the agent (ADR-0024 step 1, #577).
//!
//! Traffic reaches the proxy through the datapath. An allowed endpoint egress
//! TCP flow whose policy entry carries a proxy port is marked
//! `TO_PROXY | port << 16` and its first packet is assigned to the proxy's
//! transparent listener (`bpf_sk_assign`). The ip rule and table of [`route`]
//! deliver its packets locally, so the listener accepts a connection whose
//! local address is the flow's original destination. This crate holds:
//!
//! - [`listener`]: transparent listeners, and the accepted connection's
//!   original destination, source and source identity;
//! - [`ports`]: proxy ports (spec 16 §3.3.1): allocation from the range,
//!   reference counts, the reuse delay, and persistence across restarts;
//! - [`route`]: the ip rule and local route the redirect needs;
//! - [`record`]: the L7 record a listener emits into the agent's flow
//!   pipeline (spec 16 §4.3).
//!
//! What the proxy does with a connection (DNS, #536; HTTP policy, #537;
//! Ingress and Gateway API) builds on this and is not here.
pub mod listener;
pub mod ports;
pub mod record;
pub mod route;
