//! Observer building blocks from specification 11. No server or perf reader.
pub mod correlation;
pub mod filters;
pub mod monitor;
pub mod ring;

/// Producer identity, never the name of the compatibility target.
pub const EMITTER_NAME: &str = "flowsdn";
pub const EMITTER_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Preserve the reference low-latency reader policy until measured otherwise.
pub const PERF_WAKEUP_WATERMARK_BYTES: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressPreference {
    pub prefer_ipv6: bool,
    pub warn_deprecated: bool,
}
/// Explicit global configuration wins, including false. An absent global
/// setting falls back to the deprecated setting, then to false. Call before
/// collapsing configuration provenance into defaulted booleans.
pub const fn address_preference(global: Option<bool>, legacy: Option<bool>) -> AddressPreference {
    AddressPreference {
        prefer_ipv6: match global {
            Some(value) => value,
            None => match legacy {
                Some(value) => value,
                None => false,
            },
        },
        warn_deprecated: legacy.is_some(),
    }
}
pub mod drop_events;
pub mod export;
