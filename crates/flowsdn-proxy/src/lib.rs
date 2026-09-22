//! Proxy integration plans, not a DNS server, xDS transport or L7 proxy.
pub mod accesslog;
pub mod ack;
pub mod fqdn;
/// Explicit effective configuration wins; only an unset key inherits the SDP
/// topology default. Caller resolves file/environment/flag precedence first.
pub const fn transparent_dns(standalone_dns_proxy: bool, explicit: Option<bool>) -> bool {
    match explicit {
        Some(value) => value,
        None => standalone_dns_proxy,
    }
}
