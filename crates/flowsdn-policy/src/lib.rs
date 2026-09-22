//! Policy building blocks from spec 06. This library is not a Kubernetes
//! importer, BPF map writer, or a complete selector/authentication/L7 compiler.
use std::fmt;

pub mod cidr;
pub mod named_ports;
pub mod mapstate;
pub mod oracle;
pub mod ports;
pub mod repository;

/// Frozen reference target; availability is a watcher responsibility.
pub const KCNP_API_VERSION: &str = "policy.networking.k8s.io/v1alpha2";
pub const KCNP_ENABLED_BY_DEFAULT: bool = false;
pub const LOCKDOWN_ENABLED_BY_DEFAULT: bool = false;
/// The current verdict wire contract does not resolve log strings to cookies.
pub const POLICY_LOG_COOKIE: u32 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    PassWithAuthentication,
    InvalidPriority,
    InvalidPortRange,
    ZeroStartRange,
    InvalidProtocol,
    InvalidRedirect,
    InvalidCapacity,
    InvalidException,
    InvalidName,
    RevisionExhausted,
    OracleAuthenticationUnsupported,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PassWithAuthentication => {
                "Pass and authentication cannot coexist for one subject"
            }
            Self::InvalidPriority => "policy priority must be finite and nonnegative",
            Self::InvalidPortRange => "port range must be ordered",
            Self::ZeroStartRange => "an explicit port range may not start at zero",
            Self::InvalidProtocol => "protocol wildcard cannot constrain ports",
            Self::InvalidRedirect => {
                "listener priority requires a redirect port and must be at most 126"
            }
            Self::InvalidCapacity => "policy map capacity must be between 256 and 65536",
            Self::InvalidException => "CIDR exception must be contained in its allow prefix",
            Self::InvalidName => "policy resource or named-port selector name is empty",
            Self::RevisionExhausted => "policy repository revision exhausted",
            Self::OracleAuthenticationUnsupported => {
                "oracle does not yet evaluate authentication inheritance"
            }
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverflowAction {
    /// Attempt normal reconciliation; never report incomplete enforcement as success.
    Reconcile,
    Lockdown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pressure {
    pub alarm: bool,
    pub overflow: bool,
    pub action: OverflowAction,
}
/// Pure planning only. The caller must publish the alarm and implement the
/// lock-down/reconciliation transaction and its failure reporting (spec §3.7.8).
pub fn pressure(desired: u64, capacity: u32, lockdown: bool) -> Result<Pressure, Error> {
    if !(256..=65536).contains(&capacity) {
        return Err(Error::InvalidCapacity);
    }
    let maximum = u64::from(capacity);
    // ceil(9 * maximum / 10) is exact, avoiding float rounding at 90%.
    let threshold = maximum.saturating_mul(9).div_ceil(10);
    let overflow = desired > maximum;
    Ok(Pressure {
        alarm: desired >= threshold,
        overflow,
        action: if overflow && lockdown {
            OverflowAction::Lockdown
        } else {
            OverflowAction::Reconcile
        },
    })
}
