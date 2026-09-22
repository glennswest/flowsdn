//! Compiled resolved-policy lookup index. Build once, then binary-search port
//! intervals instead of scanning source rules per packet. Adjacent equivalent
//! answers are coalesced. This is not the complete kernel LPM mapstate compiler:
//! authentication, aggregate identities and cookies remain explicit future work.
//!
//! Semantics are implemented independently of oracle::evaluate: no oracle
//! evaluation or matching/ranking helper is called during build or lookup.
use crate::{
    Error,
    oracle::{Decision, Packet, Peer, Rule, Tier, Verdict, validate_subject},
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Bucket {
    identity: Option<u32>,
    egress: bool,
    protocol: Option<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interval {
    pub first: u16,
    pub last: u16,
    pub decision: Decision,
}
#[derive(Clone, Debug, Default)]
pub struct MapState {
    buckets: BTreeMap<Bucket, Vec<Interval>>,
    identities: BTreeSet<u32>,
    protocols: BTreeSet<u8>,
}
fn rank(rule: &Rule) -> u16 {
    match rule.verdict {
        Verdict::Deny => 255,
        Verdict::Pass => 0,
        Verdict::Allow if rule.proxy_port == 0 => 1,
        Verdict::Allow if rule.listener_priority == 0 => 127,
        Verdict::Allow => 255u16.saturating_sub(u16::from(rule.listener_priority)),
    }
}
fn compare(left: &Rule, right: &Rule) -> std::cmp::Ordering {
    left.tier
        .cmp(&right.tier)
        .then_with(|| {
            if left.priority == right.priority {
                std::cmp::Ordering::Equal
            } else {
                left.priority.total_cmp(&right.priority)
            }
        })
        .then_with(|| rank(right).cmp(&rank(left)))
}
fn decide(ordered: &[&Rule], port: u16) -> Decision {
    let mut passed: Option<Tier> = None;
    let mut winner: Option<&Rule> = None;
    let mut proxy_ports = BTreeSet::new();
    for rule in ordered {
        let (first, last) = rule.ports.bounds();
        if port < first || port > last || passed == Some(rule.tier) {
            continue;
        }
        if let Some(chosen) = winner {
            if compare(chosen, rule) != std::cmp::Ordering::Equal {
                break;
            }
            proxy_ports.insert(rule.proxy_port);
            continue;
        }
        match rule.verdict {
            Verdict::Deny => return Decision::Deny,
            Verdict::Pass => passed = Some(rule.tier),
            Verdict::Allow => {
                winner = Some(rule);
                proxy_ports.insert(rule.proxy_port);
            }
        }
    }
    if winner.is_some() {
        Decision::Allow { proxy_ports }
    } else {
        Decision::Deny
    }
}
impl MapState {
    pub fn compile(rules: &[Rule]) -> Result<Self, Error> {
        validate_subject(rules)?;
        if rules.iter().any(|rule| rule.authentication.is_some()) {
            return Err(Error::OracleAuthenticationUnsupported);
        }
        let identities = rules
            .iter()
            .filter_map(|rule| match rule.peer {
                Peer::Any => None,
                Peer::Identity(id) => Some(id),
            })
            .collect::<BTreeSet<_>>();
        let protocols = rules
            .iter()
            .map(|rule| rule.protocol)
            .filter(|protocol| *protocol != 0)
            .collect::<BTreeSet<_>>();
        let mut buckets = BTreeMap::new();
        for identity in std::iter::once(None).chain(identities.iter().copied().map(Some)) {
            for egress in [false, true] {
                for protocol in std::iter::once(None).chain(protocols.iter().copied().map(Some)) {
                    let mut candidates = rules
                        .iter()
                        .filter(|rule| {
                            rule.egress == egress
                                && (match rule.peer {
                                    Peer::Any => true,
                                    Peer::Identity(id) => identity == Some(id),
                                })
                                && (rule.protocol == 0 || protocol == Some(rule.protocol))
                        })
                        .collect::<Vec<_>>();
                    candidates.sort_by(|a, b| compare(a, b));
                    let mut edges = BTreeSet::from([0u32, 65536]);
                    for rule in &candidates {
                        let (first, last) = rule.ports.bounds();
                        edges.insert(u32::from(first));
                        edges.insert(u32::from(last).saturating_add(1));
                    }
                    let edges = edges.into_iter().collect::<Vec<_>>();
                    let mut intervals: Vec<Interval> = Vec::new();
                    for window in edges.windows(2) {
                        let Some((&first, &end)) = window.first().zip(window.get(1)) else {
                            continue;
                        };
                        let first = u16::try_from(first).map_err(|_| Error::InvalidPortRange)?;
                        let last = u16::try_from(end.saturating_sub(1))
                            .map_err(|_| Error::InvalidPortRange)?;
                        let decision = decide(&candidates, first);
                        if let Some(previous) = intervals
                            .last_mut()
                            .filter(|previous| previous.decision == decision)
                        {
                            previous.last = last;
                        } else {
                            intervals.push(Interval {
                                first,
                                last,
                                decision,
                            });
                        }
                    }
                    buckets.insert(
                        Bucket {
                            identity,
                            egress,
                            protocol,
                        },
                        intervals,
                    );
                }
            }
        }
        Ok(Self {
            buckets,
            identities,
            protocols,
        })
    }
    pub fn lookup(&self, packet: Packet) -> Decision {
        let bucket = Bucket {
            identity: self
                .identities
                .contains(&packet.identity)
                .then_some(packet.identity),
            egress: packet.egress,
            protocol: self
                .protocols
                .contains(&packet.protocol)
                .then_some(packet.protocol),
        };
        let Some(intervals) = self.buckets.get(&bucket) else {
            return Decision::Deny;
        };
        let index = intervals.partition_point(|interval| interval.last < packet.port);
        intervals
            .get(index)
            .filter(|interval| interval.first <= packet.port)
            .map_or(Decision::Deny, |interval| interval.decision.clone())
    }
    /// Validate the complete candidate before replacing the current index.
    pub fn replace(&mut self, rules: &[Rule]) -> Result<(), Error> {
        *self = Self::compile(rules)?;
        Ok(())
    }
    pub fn interval_count(&self) -> usize {
        self.buckets
            .values()
            .map(Vec::len)
            .fold(0, usize::saturating_add)
    }
}
