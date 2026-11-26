//! FlowsdnBGPNodeConfig status from the BGP control plane's state (#334,
//! spec 15 §3.8). The agent's reconcilers and speaker (#570, #571) report
//! per-instance peer state and reconcile errors; this module turns them into
//! the node config's `status` and decides when it is written:
//!
//! - **Instances and peers**: name, local ASN; per peer its address, ASN
//!   (the session's when configured as 0), state string, negotiated hold and
//!   keepalive, established time (RFC 3339 from the session's uptime) and
//!   per-family route counts. A peer with no address or no ASN is left out.
//! - **`flowsdn.io/BGPReconcileError`**: at most five errors per instance;
//!   True (`ReconcileFailed`) with one `<instance>: <error>` line each,
//!   sorted by instance then error, cut at 32 KiB; else False
//!   (`ReconcileSucceeded`), empty.
//! - **Cadence** ([`Flusher`]): a write at most every 5 s (±500 ms), only
//!   when the status differs from the last one written; a failed write backs
//!   off (5 s, ×1.2, jitter 0.5, 10 steps) and then falls back to the plain
//!   ticker; `NotFound` (the node config went) forgets the last write and is
//!   not an error.
//!
//! Nothing calls it yet: the BGP control plane it reports on is #570.
use flowsdn_k8s::kinds::{
    BgpAppliedTimers, BgpInstanceStatus, BgpPeerStatus, BgpRouteCount, Condition,
    FlowsdnBGPNodeConfigStatus,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime};

pub const CONDITION_RECONCILE_ERROR: &str = "flowsdn.io/BGPReconcileError";
/// Errors kept per instance.
pub const MAX_ERRORS: usize = 5;
/// The longest condition message, in bytes.
pub const MAX_MESSAGE: usize = 32 * 1024;
/// The write ticker and its jitter.
pub const TICK: Duration = Duration::from_secs(5);
pub const TICK_JITTER: Duration = Duration::from_millis(500);
/// A failed write's backoff: initial delay, factor, jitter, steps.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(5);
pub const BACKOFF_FACTOR: f64 = 1.2;
pub const BACKOFF_JITTER: f64 = 0.5;
pub const BACKOFF_STEPS: u32 = 10;
/// With status reporting off the agent clears the status once at start,
/// retried at this interval this many times (`NotFound` is success).
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(3);
pub const CLEANUP_ATTEMPTS: u32 = 20;

/// A BGP session's state (RFC 4271 §8.2.2), reported in the reference's
/// strings (`open_sent`, `open_confirm`: spec 15 §4.4 DEVIATION).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SessionState {
    #[default]
    Unknown,
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}
impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Idle => "idle",
            Self::Connect => "connect",
            Self::Active => "active",
            Self::OpenSent => "open_sent",
            Self::OpenConfirm => "open_confirm",
            Self::Established => "established",
        }
    }
}

/// Routes in one family of a session.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FamilyCount {
    pub afi: String,
    pub safi: String,
    pub received: u32,
    pub advertised: u32,
}

/// One peer as the control plane sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerState {
    pub name: String,
    /// None: not known yet (default-gateway discovery found nothing).
    pub address: Option<String>,
    /// The configured ASN; 0 accepts the one the peer's OPEN carries.
    pub configured_asn: u32,
    /// The ASN the session learned.
    pub session_asn: Option<u32>,
    pub state: SessionState,
    /// How long the session has been established.
    pub uptime: Option<Duration>,
    pub applied_hold: Option<u16>,
    pub applied_keepalive: Option<u16>,
    pub families: Vec<FamilyCount>,
}

/// One BGP instance's state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstanceState {
    pub name: String,
    pub local_asn: Option<u32>,
    pub peers: Vec<PeerState>,
}

fn saturate(n: u32) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// The `status.bgpInstances` of these instances at `now`, sorted by name.
pub fn instances_status(instances: &[InstanceState], now: SystemTime) -> Vec<BgpInstanceStatus> {
    let mut out: Vec<BgpInstanceStatus> = instances
        .iter()
        .map(|instance| {
            let mut peers: Vec<BgpPeerStatus> = instance
                .peers
                .iter()
                .filter_map(|peer| {
                    let address = peer.address.clone().filter(|a| !a.is_empty())?;
                    let asn = match peer.configured_asn {
                        0 => peer.session_asn.filter(|a| *a != 0)?,
                        configured => configured,
                    };
                    let established_time = (peer.state == SessionState::Established)
                        .then_some(peer.uptime)
                        .flatten()
                        .and_then(|up| now.checked_sub(up))
                        .map(crate::events::rfc3339);
                    let timers = (peer.applied_hold.is_some() || peer.applied_keepalive.is_some())
                        .then(|| BgpAppliedTimers {
                            applied_hold_time_seconds: peer.applied_hold.map(i32::from),
                            applied_keepalive_seconds: peer.applied_keepalive.map(i32::from),
                        });
                    let route_count = (!peer.families.is_empty()).then(|| {
                        peer.families
                            .iter()
                            .map(|f| BgpRouteCount {
                                advertised: Some(saturate(f.advertised)),
                                afi: f.afi.clone(),
                                received: Some(saturate(f.received)),
                                safi: f.safi.clone(),
                            })
                            .collect()
                    });
                    Some(BgpPeerStatus {
                        established_time,
                        name: peer.name.clone(),
                        peer_asn: Some(i64::from(asn)),
                        peer_address: address,
                        peering_state: Some(peer.state.as_str().into()),
                        route_count,
                        timers,
                    })
                })
                .collect();
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            BgpInstanceStatus {
                local_asn: instance.local_asn.map(i64::from),
                name: instance.name.clone(),
                peers: (!peers.is_empty()).then_some(peers),
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The reconcile error table: at most [`MAX_ERRORS`] per instance.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileErrors {
    by_instance: BTreeMap<String, Vec<String>>,
}
impl ReconcileErrors {
    /// Replace an instance's errors (the first five kept); whether the
    /// table changed.
    pub fn set(&mut self, instance: &str, mut errors: Vec<String>) -> bool {
        errors.truncate(MAX_ERRORS);
        let before = self.by_instance.get(instance).cloned().unwrap_or_default();
        if errors.is_empty() {
            self.by_instance.remove(instance);
        } else {
            self.by_instance.insert(instance.to_owned(), errors.clone());
        }
        before != errors
    }
    /// Forget a removed instance; whether the table changed.
    pub fn remove(&mut self, instance: &str) -> bool {
        self.by_instance.remove(instance).is_some()
    }
    /// The condition's status, reason and message.
    fn summary(&self) -> (bool, &'static str, String) {
        if self.by_instance.is_empty() {
            return (false, "ReconcileSucceeded", String::new());
        }
        let mut message = String::new();
        'all: for (instance, errors) in &self.by_instance {
            for error in errors {
                let line = format!("{instance}: {error}\n");
                if message.len().saturating_add(line.len()) > MAX_MESSAGE {
                    let room = MAX_MESSAGE.saturating_sub(message.len());
                    let mut cut = room.min(line.len());
                    while cut > 0 && !line.is_char_boundary(cut) {
                        cut = cut.saturating_sub(1);
                    }
                    message.push_str(line.get(..cut).unwrap_or(""));
                    break 'all;
                }
                message.push_str(&line);
            }
        }
        (true, "ReconcileFailed", message)
    }
}

/// The status to write: the instances, and the existing conditions with
/// `BGPReconcileError` set (its lastTransitionTime kept while its status
/// holds), sorted by type.
pub fn desired_status(
    instances: &[InstanceState],
    errors: &ReconcileErrors,
    existing: Option<&FlowsdnBGPNodeConfigStatus>,
    generation: Option<i64>,
    now: SystemTime,
) -> FlowsdnBGPNodeConfigStatus {
    let (failed, reason, message) = errors.summary();
    let status = if failed { "True" } else { "False" };
    let old = existing
        .and_then(|s| s.conditions.clone())
        .unwrap_or_default();
    let since = old
        .iter()
        .find(|c| c.type_ == CONDITION_RECONCILE_ERROR && c.status == status)
        .map_or_else(
            || crate::events::rfc3339(now),
            |c| c.last_transition_time.clone(),
        );
    let mut conditions: Vec<Condition> = old
        .into_iter()
        .filter(|c| c.type_ != CONDITION_RECONCILE_ERROR)
        .collect();
    conditions.push(Condition {
        last_transition_time: since,
        message,
        observed_generation: generation,
        reason: reason.into(),
        status: status.into(),
        type_: CONDITION_RECONCILE_ERROR.into(),
    });
    conditions.sort_by(|a, b| a.type_.cmp(&b.type_));
    let instances = instances_status(instances, now);
    FlowsdnBGPNodeConfigStatus {
        bgp_instances: (!instances.is_empty()).then_some(instances),
        conditions: Some(conditions),
    }
}

/// The merge patch body that writes `status` to `/status`.
pub fn status_patch(status: &FlowsdnBGPNodeConfigStatus) -> Value {
    json!({"status": status})
}

/// The JSON patch that clears a stale status when reporting is off.
pub fn cleanup_patch() -> Value {
    json!([{"op": "replace", "path": "/status", "value": {}}])
}

/// How a status write ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Written,
    /// 404: the node config is gone.
    NotFound,
    Failed,
}

/// When the status is written (§3.8).
#[derive(Clone, Debug)]
pub struct Flusher {
    last_written: Option<FlowsdnBGPNodeConfigStatus>,
    next: Instant,
    /// Failed writes since the last success or exhaustion.
    failures: u32,
    rng: u64,
}
impl Flusher {
    pub fn new(now: Instant, seed: u64) -> Self {
        Self {
            last_written: None,
            next: now,
            failures: 0,
            rng: seed | 1,
        }
    }
    /// A number in [0, 1).
    fn unit(&mut self) -> f64 {
        self.rng ^= self.rng.wrapping_shl(13);
        self.rng ^= self.rng.wrapping_shr(7);
        self.rng ^= self.rng.wrapping_shl(17);
        #[allow(clippy::cast_precision_loss)]
        let unit = (self.rng >> 11) as f64 / (1u64 << 53) as f64;
        unit
    }
    fn tick(&mut self) -> Duration {
        // 5 s ± up to 500 ms (uniform; the reference's is normal).
        let offset = TICK_JITTER.mul_f64(self.unit());
        if self.unit() < 0.5 {
            TICK.saturating_sub(offset)
        } else {
            TICK.saturating_add(offset)
        }
    }
    /// Whether `desired` is to be written at `now`.
    pub fn due(&self, now: Instant, desired: &FlowsdnBGPNodeConfigStatus) -> bool {
        now >= self.next && self.last_written.as_ref() != Some(desired)
    }
    /// Record a write's outcome; true when the backoff was just exhausted
    /// (logged once per exhaustion).
    pub fn record(
        &mut self,
        now: Instant,
        desired: &FlowsdnBGPNodeConfigStatus,
        outcome: Outcome,
    ) -> bool {
        let mut exhausted = false;
        let delay = match outcome {
            Outcome::Written => {
                self.last_written = Some(desired.clone());
                self.failures = 0;
                self.tick()
            }
            Outcome::NotFound => {
                self.last_written = None;
                self.failures = 0;
                self.tick()
            }
            Outcome::Failed => {
                if self.failures >= BACKOFF_STEPS {
                    self.failures = 0;
                    exhausted = true;
                    self.tick()
                } else {
                    let steps = i32::try_from(self.failures).unwrap_or(i32::MAX);
                    self.failures = self.failures.saturating_add(1);
                    let base = BACKOFF_INITIAL.mul_f64(BACKOFF_FACTOR.powi(steps));
                    base.saturating_add(base.mul_f64(BACKOFF_JITTER * self.unit()))
                }
            }
        };
        self.next = now.checked_add(delay).unwrap_or(now);
        exhausted
    }
    /// When the next write may happen.
    pub fn next(&self) -> Instant {
        self.next
    }
}

#[cfg(test)]
#[path = "bgp_status_tests.rs"]
mod tests;
