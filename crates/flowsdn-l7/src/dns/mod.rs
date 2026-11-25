//! The DNS proxy (spec 16 §3.6; ADR-0024 step 2, #536): the agent's DNS
//! listener. The datapath redirects an endpoint's DNS traffic to it (the
//! static proxy port, §3.6.1). Each query is checked against the endpoint's
//! DNS rules (§3.6.3) and refused, or forwarded to the server the endpoint
//! asked over the same protocol with the endpoint's identity in the
//! upstream socket's mark (§3.6.2). An answer's names and addresses go to
//! [`Policy::learned`] before the response is released (the response hold
//! of §3.6.5): that is where `toFQDNs` learns what to allow. The reply
//! comes from the address the endpoint queried.
//!
//! Not built here: the restore of DNS rules and the cache across restarts
//! (§3.6.9; the cache is rebuilt by new lookups), the per-name lock striping
//! (the agent serialises [`Policy::learned`]), transparent upstream mode
//! (the server sees the node, the reference's default), and the
//! standalone DNS proxy (§3.7, not built by ADR-0024).
pub mod cache;
pub mod message;
pub mod pattern;
pub mod proxy;

use std::{net::IpAddr, time::Duration};

/// The proxy's view of the agent: who an address is, and what its rules
/// allow.
pub trait Policy: Send + Sync {
    /// The endpoint (its numeric ID and identity) whose address `source` is;
    /// `None` refuses the query with SERVFAIL (§3.6.4 step 3).
    fn endpoint(&self, source: IpAddr) -> Option<(u16, u32)>;
    /// An address's identity (world when it has none, §3.6.4 step 4).
    fn identity(&self, address: IpAddr) -> u32;
    /// Whether `endpoint`'s DNS rules allow asking the server of identity
    /// `server` on (`protocol`, `port`) for `name` (lower-case, trailing dot).
    fn allowed(&self, endpoint: u16, server: u32, protocol: u8, port: u16, name: &str) -> bool;
    /// An allowed answer (§3.6.5): `names` resolved to `ips` for `ttl`
    /// seconds. Returns once the datapath allows them, or after the
    /// response's longest hold.
    fn learned(&self, endpoint: u16, names: &[String], ips: &[IpAddr], ttl: u32);
    /// One finished query, for the flow pipeline and the counters.
    fn record(&self, _record: crate::record::Record) {}
}

/// The proxy's settings (spec 16 §6 names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// `tofqdns-dns-reject-response-code`: REFUSED or NXDOMAIN.
    pub reject: u8,
    /// How long an upstream answer is waited for; past it the client gets
    /// nothing and retries (§3.6.3).
    pub upstream_timeout: Duration,
    /// `dnsproxy-concurrency-limit`: queries in flight (0: the proxy's own
    /// ceiling, [`proxy::MAX_IN_FLIGHT`]); past it SERVFAIL.
    pub concurrency: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            reject: message::rcode::REFUSED,
            upstream_timeout: Duration::from_secs(10),
            concurrency: 0,
        }
    }
}

#[cfg(test)]
mod tests;
