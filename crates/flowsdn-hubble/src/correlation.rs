//! Contract for correlation against one immutable realized-policy snapshot.
//! Desired policy or repository head must never be substituted by the adapter.
use std::collections::BTreeSet;
use flowsdn_bpf_abi::notify::{DROP_POLICY_DENIED, DROP_POLICY_DENY};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction { Ingress, Egress }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key {
    pub remote_identity: u32,
    /// Host-order destination port, or ICMP type.
    pub destination_port: u16,
    pub protocol: u8,
    pub direction: Direction,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rule {
    pub labels: Vec<(String, String)>,
    pub log: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMatch { pub revision: u64, pub rules: Vec<Rule> }
/// Owns lookup specificity and rule-origin resolution for the *realized* map.
/// None means no endpoint, no realized snapshot, or no matching map key. It
/// must not synthesize a rule from pending desired state or from a CIDR guess.
pub trait PolicySnapshot {
    fn correlation_info(&self, endpoint_id: u16, key: Key) -> Option<PolicyMatch>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict { Forwarded, Redirected, Dropped { reason: u32 }, Audit, Other }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Field { IngressAllowedBy, EgressAllowedBy, IngressDeniedBy, EgressDeniedBy }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Correlation {
    pub field: Field,
    pub policy: PolicyMatch,
    pub policy_log: Vec<String>,
}
/// Call only for policy-verdict events with packet-derived L4 key and local
/// endpoint selection. Zero L4/port, endpoint or unknown verdict yields no data.
/// Reference compatibility also excludes valid ICMP type 0 (echo reply); this
/// is an inherited correlation limitation, not packet validation.
pub fn correlate(snapshot: &impl PolicySnapshot, endpoint_id: u16, key: Key, verdict: Verdict) -> Option<Correlation> {
    if endpoint_id == 0 || key.protocol == 0 || key.destination_port == 0 { return None; }
    let allowed = match verdict {
        Verdict::Forwarded | Verdict::Redirected => true,
        Verdict::Audit | Verdict::Dropped { reason: DROP_POLICY_DENIED | DROP_POLICY_DENY } => false,
        _ => return None,
    };
    let policy = snapshot.correlation_info(endpoint_id, key)?;
    let policy_log = policy.rules.iter().filter_map(|r| r.log.clone()).collect::<BTreeSet<_>>().into_iter().collect();
    let field = match (key.direction, allowed) {
        (Direction::Ingress, true) => Field::IngressAllowedBy,
        (Direction::Egress, true) => Field::EgressAllowedBy,
        (Direction::Ingress, false) => Field::IngressDeniedBy,
        (Direction::Egress, false) => Field::EgressDeniedBy,
    };
    Some(Correlation { field, policy, policy_log })
}
