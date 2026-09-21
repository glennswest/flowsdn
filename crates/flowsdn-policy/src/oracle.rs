//! Independent brute-force oracle over already-selected L3/L4 policy rules.
//! This intentionally has no trie, map-state insertion, aggregate pruning or
//! datapath precedence encoder. Auth inheritance/L7 content need later oracles.
use crate::{Error, ports::PortRange};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Tier {
    Admin = 100,
    Normal = 200,
    Baseline = 250,
    Default = 255,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Allow,
    Deny,
    Pass,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer {
    Any,
    Identity(u32),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    Disabled,
    Required,
    TestAlwaysFail,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub tier: Tier,
    pub priority: f64,
    pub verdict: Verdict,
    pub egress: bool,
    pub peer: Peer,
    pub protocol: u8,
    pub ports: PortRange,
    pub authentication: Option<Authentication>,
    pub proxy_port: u16,
    pub listener_priority: u8,
}
impl Rule {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.priority.is_finite() || self.priority < 0.0 {
            return Err(Error::InvalidPriority);
        }
        if self.protocol == 0 && !self.ports.is_any() {
            return Err(Error::InvalidProtocol);
        }
        if self.listener_priority > 126
            || (self.proxy_port == 0 && self.listener_priority != 0)
            || (self.verdict != Verdict::Allow
                && (self.proxy_port != 0 || self.authentication.is_some()))
        {
            return Err(Error::InvalidRedirect);
        }
        Ok(())
    }
    fn matches(&self, packet: Packet) -> bool {
        self.egress == packet.egress
            && (self.peer == Peer::Any || self.peer == Peer::Identity(packet.identity))
            && (self.protocol == 0 || self.protocol == packet.protocol)
            && self.ports.contains(packet.port)
    }
    // Ranking within a tier/priority directly expresses §3.5.3; it is not the
    // BPF packed precedence representation the oracle is meant to check.
    fn verdict_rank(&self) -> (u8, u8) {
        match self.verdict {
            Verdict::Deny => (3, 0),
            Verdict::Pass => (0, 0),
            Verdict::Allow if self.proxy_port == 0 => (1, 0),
            Verdict::Allow if self.listener_priority == 0 => (2, 0),
            Verdict::Allow => (2, 127u8.saturating_sub(self.listener_priority)),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet {
    pub identity: u32,
    pub egress: bool,
    pub protocol: u8,
    pub port: u16,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decision {
    Deny,
    /// Equal-rank rules may contain different equivalent redirect instances.
    /// Return all candidate ports instead of inventing an ordering guarantee.
    Allow {
        proxy_ports: std::collections::BTreeSet<u16>,
    },
}
/// Reject unsupported Pass/auth combinations before a repository update is
/// published, across all resources selecting this one subject/direction set.
pub fn validate_subject<'a>(rules: impl IntoIterator<Item = &'a Rule>) -> Result<(), Error> {
    let mut pass = false;
    let mut auth = false;
    for rule in rules {
        rule.validate()?;
        pass |= rule.verdict == Verdict::Pass;
        auth |= rule.authentication.is_some();
    }
    if pass && auth {
        return Err(Error::PassWithAuthentication);
    }
    Ok(())
}
/// Rules must already include any synthesized default policy. Absence of a
/// match is deny. Explicit Pass ignores the rest of its tier and resumes below.
pub fn evaluate(rules: &[Rule], packet: Packet) -> Result<Decision, Error> {
    validate_subject(rules)?;
    if rules.iter().any(|r| r.authentication.is_some()) {
        return Err(Error::OracleAuthenticationUnsupported);
    }
    for tier in [Tier::Admin, Tier::Normal, Tier::Baseline, Tier::Default] {
        let matches: Vec<_> = rules
            .iter()
            .filter(|rule| rule.tier == tier && rule.matches(packet))
            .collect();
        let Some(priority) = matches
            .iter()
            .map(|rule| rule.priority)
            .min_by(f64::total_cmp)
        else {
            continue;
        };
        let peers: Vec<_> = matches
            .into_iter()
            .filter(|rule| rule.priority == priority)
            .collect();
        let Some(rank) = peers.iter().map(|rule| rule.verdict_rank()).max() else {
            continue;
        };
        let winners: Vec<_> = peers
            .into_iter()
            .filter(|rule| rule.verdict_rank() == rank)
            .collect();
        match winners.first().map(|rule| rule.verdict) {
            Some(Verdict::Pass) => continue,
            Some(Verdict::Deny) => return Ok(Decision::Deny),
            Some(Verdict::Allow) => {
                return Ok(Decision::Allow {
                    proxy_ports: winners.iter().map(|r| r.proxy_port).collect(),
                });
            }
            None => continue,
        }
    }
    Ok(Decision::Deny)
}
