//! Subject/peer/port frontend and independent direct-flow simulator. Selectors
//! here are equality conjunctions, not a complete Kubernetes selector parser.
use crate::{
    Error,
    mapstate::MapState,
    oracle::{self, Decision, Packet, Peer, Rule, Verdict},
    ports::PortRange,
};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    None,
    Any,
    Labels(BTreeMap<String, String>),
}
impl Selector {
    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        match self {
            Self::None => false,
            Self::Any => true,
            Self::Labels(labels) => labels
                .iter()
                .all(|(k, v)| endpoint.labels.get(k) == Some(v)),
        }
    }
}
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub identity: u32,
    pub labels: BTreeMap<String, String>,
    pub named_ports: BTreeMap<(u8, String), u16>,
}
#[derive(Clone, Debug)]
pub enum Port {
    Numeric(PortRange),
    Named(String),
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub subject: Selector,
    pub peers: Selector,
    pub default_deny: bool,
    pub rule: Rule,
    pub port: Port,
}
fn resolve_port(entry: &Entry, destination: &Endpoint) -> Result<Option<PortRange>, Error> {
    match &entry.port {
        Port::Numeric(range) => Ok(Some(*range)),
        Port::Named(name) => {
            if !matches!(entry.rule.protocol, 6 | 17) {
                return Err(Error::InvalidProtocol);
            }
            destination
                .named_ports
                .get(&(entry.rule.protocol, name.clone()))
                .filter(|p| **p != 0)
                .map(|p| PortRange::from_api(*p, None))
                .transpose()
        }
    }
}
/// Direct evaluation examines only the current flow; it never expands identity
/// sets or calls the compiled frontend. Named ports belong to the destination.
pub fn evaluate(
    entries: &[Entry],
    source: &Endpoint,
    destination: &Endpoint,
    egress: bool,
    protocol: u8,
    port: u16,
) -> Result<Decision, Error> {
    let (subject, peer) = if egress {
        (source, destination)
    } else {
        (destination, source)
    };
    let selected = entries
        .iter()
        .filter(|e| e.rule.egress == egress && e.subject.matches(subject))
        .collect::<Vec<_>>();
    oracle::validate_subject(selected.iter().map(|e| &e.rule))?;
    let default_deny = selected.iter().any(|e| e.default_deny);
    let mut matching = Vec::new();
    for entry in selected {
        if !entry.peers.matches(peer)
            || (entry.rule.protocol != 0 && entry.rule.protocol != protocol)
        {
            continue;
        }
        let Some(range) = resolve_port(entry, destination)? else {
            continue;
        };
        if !range.contains(port) {
            continue;
        }
        let mut rule = entry.rule.clone();
        rule.peer = Peer::Any;
        rule.ports = range;
        matching.push(rule);
    }
    if matching.is_empty() && !default_deny {
        return Ok(Decision::Allow {
            proxy_ports: BTreeSet::from([0]),
        });
    }
    oracle::evaluate(
        &matching,
        Packet {
            identity: peer.identity,
            egress,
            protocol,
            port,
        },
    )
}
/// Compile one selected subject/direction over a complete endpoint snapshot.
/// Recompile on endpoint label or named-port changes; no watcher is supplied.
pub struct SubjectMap {
    index: MapState,
    egress: bool,
}
impl SubjectMap {
    pub fn lookup(&self, packet: Packet) -> Decision {
        if packet.egress != self.egress {
            return Decision::Deny;
        }
        self.index.lookup(packet)
    }
}
pub fn compile(
    entries: &[Entry],
    subject: &Endpoint,
    endpoints: &[Endpoint],
    egress: bool,
) -> Result<SubjectMap, Error> {
    let ids = endpoints
        .iter()
        .map(|e| e.identity)
        .collect::<BTreeSet<_>>();
    if ids.len() != endpoints.len() {
        return Err(Error::InvalidName);
    }
    let selected = entries
        .iter()
        .filter(|e| e.rule.egress == egress && e.subject.matches(subject))
        .collect::<Vec<_>>();
    oracle::validate_subject(selected.iter().map(|e| &e.rule))?;
    let default_allow = !selected.iter().any(|e| e.default_deny);
    let mut rules = Vec::new();
    for entry in selected {
        if entry.peers == Selector::Any && matches!(entry.port, Port::Numeric(_)) {
            let mut r = entry.rule.clone();
            r.peer = Peer::Any;
            if let Port::Numeric(p) = entry.port {
                r.ports = p;
            }
            rules.push(r);
            continue;
        }
        for peer in endpoints.iter().filter(|p| entry.peers.matches(p)) {
            let dest = if egress { peer } else { subject };
            let Some(port) = resolve_port(entry, dest)? else {
                continue;
            };
            let mut r = entry.rule.clone();
            r.peer = Peer::Identity(peer.identity);
            r.ports = port;
            rules.push(r);
        }
    }
    Ok(SubjectMap {
        index: MapState::compile_with_default(&rules, default_allow)?,
        egress,
    })
}
/// The pinned FuzzDistillPolicy byte format, described in spec06. Endpoint
/// identities and labels are owned by the caller; no reference code is linked.
pub fn decode_seed(bytes: &[u8]) -> Result<Vec<Entry>, Error> {
    let mut entries = Vec::new();
    for pair in bytes.chunks_exact(2) {
        let b = *pair.first().ok_or(Error::InvalidPriority)?;
        let priority = *pair.get(1).ok_or(Error::InvalidPriority)?;
        let tier = match priority & 3 {
            0 => oracle::Tier::Admin,
            2 => oracle::Tier::Baseline,
            _ => oracle::Tier::Normal,
        };
        let peers = match b & 3 {
            0 => Selector::Any,
            1 => Selector::Labels(BTreeMap::from([("name".into(), "b".into())])),
            2 => Selector::Labels(BTreeMap::from([("name".into(), "c".into())])),
            _ => Selector::Labels(BTreeMap::from([("namespace".into(), "default".into())])),
        };
        let ports = match (b >> 2) & 7 {
            0 => PortRange::any(),
            1 => PortRange::from_api(4, Some(7))?,
            2 => PortRange::from_api(4, Some(5))?,
            3 => PortRange::from_api(6, Some(7))?,
            n => PortRange::from_api(u16::from(n), None)?,
        };
        let verdict = match (b >> 5) & 3 {
            0 => Verdict::Allow,
            1 => Verdict::Deny,
            _ => Verdict::Pass,
        };
        entries.push(Entry {
            subject: Selector::Labels(BTreeMap::from([("name".into(), "a".into())])),
            peers,
            default_deny: true,
            port: Port::Numeric(ports),
            rule: Rule {
                tier,
                priority: f64::from(priority >> 2),
                verdict,
                egress: true,
                peer: Peer::Any,
                protocol: if ports.is_any() { 0 } else { 6 },
                ports,
                authentication: None,
                proxy_port: 0,
                listener_priority: 0,
            },
        });
    }
    Ok(entries)
}
