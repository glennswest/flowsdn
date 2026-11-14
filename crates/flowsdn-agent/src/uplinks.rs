//! Both NICs (#408; owner's choice B, 2026-11-13: routed, two addresses).
//! Every port that holds a node address, or an address on a node address's
//! subnet, is an uplink. That set is found from the kernel, never configured.
//! A monitor watches every uplink's carrier for the node's whole life:
//!
//! * every uplink with carrier carries traffic (`active-active`, the default):
//!   other nodes' pod CIDRs are per-flow ECMP routes with one path per live
//!   port (L4 hash), the default route has an ECMP copy in flowsdn's table,
//!   and each node address is pinned to its own port by source rules;
//! * a port that loses carrier leaves at once: the kernel skips its paths
//!   (`ignore_routes_with_linkdown`), its addresses are added as host
//!   addresses (/32, /128) on a live port with a gratuitous ARP, and its
//!   source rules point at that port;
//! * a port whose carrier returns rejoins at once: the host addresses go,
//!   its own addresses are announced from it again and the paths spread
//!   over both.
//!
//! Only carrier decides. Traffic, thresholds and tests never enable a port.
//! This file is the pure plan. `uplinks_monitor.rs` applies it.
use crate::kubernetes::{Cidr, cidr_text, overlaps};
use crate::state::Result;
use flowsdn_connector::multihome::{NextHop, Rule};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::IpAddr,
};

/// flowsdn's routing tables: `table` holds the ECMP default, `table + 1 + i`
/// pins the i-th node address.
pub const DEFAULT_TABLE: u32 = 2080;
/// flowsdn's rule priorities: `priority + 10 + i` (address to its subnet),
/// `priority + 50` (main without its default), `priority + 100 + i` (address
/// to anywhere), `priority + 200` (the ECMP default).
pub const DEFAULT_PRIORITY: u32 = 9100;
/// The most node addresses pinned to their ports.
pub const MAX_PINNED: usize = 32;
/// The span of priorities flowsdn owns from `priority`.
pub const PRIORITY_SPAN: u32 = 300;
/// The join/leave history kept for `GET /v1/uplinks`.
pub const HISTORY: usize = 64;

/// `kubernetes.uplinks.mode`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mode {
    /// Every uplink with carrier carries traffic.
    #[default]
    ActiveActive,
    /// Only the preferred uplink with carrier carries the balanced routes;
    /// failover of addresses is the same.
    ActiveBackup,
    /// Nothing is balanced or moved (the behaviour before #408).
    Single,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActiveActive => "active-active",
            Self::ActiveBackup => "active-backup",
            Self::Single => "single",
        }
    }
}

/// `kubernetes.uplinks`: all optional; nothing names a port except weights.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Settings {
    pub mode: Mode,
    /// Interface name -> relative weight (1-255, default 1). A higher weight
    /// is also preferred for active-backup and as a failover target.
    pub weights: BTreeMap<String, u8>,
    pub table: u32,
    pub priority: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            weights: BTreeMap::new(),
            table: DEFAULT_TABLE,
            priority: DEFAULT_PRIORITY,
        }
    }
}
impl Settings {
    pub fn parse(value: Option<&Value>) -> Result<Self> {
        let mut settings = Self::default();
        let object = match value {
            None | Some(Value::Null) => return Ok(settings),
            Some(Value::Object(object)) => object,
            Some(_) => return Err("kubernetes.uplinks must be an object".into()),
        };
        for (key, value) in object {
            match key.as_str() {
                "mode" => {
                    settings.mode = match value.as_str() {
                        Some("active-active") => Mode::ActiveActive,
                        Some("active-backup") => Mode::ActiveBackup,
                        Some("single") => Mode::Single,
                        _ => {
                            return Err("kubernetes.uplinks.mode must be active-active, \
                                        active-backup or single"
                                .into());
                        }
                    }
                }
                "weights" => {
                    let weights = value
                        .as_object()
                        .ok_or("kubernetes.uplinks.weights must be an object")?;
                    for (name, weight) in weights {
                        let weight = weight
                            .as_u64()
                            .and_then(|w| u8::try_from(w).ok())
                            .filter(|w| *w >= 1)
                            .ok_or("kubernetes.uplinks.weights values must be 1-255")?;
                        if name.is_empty() || name.len() >= 16 {
                            return Err(
                                "kubernetes.uplinks.weights keys must be interface names".into()
                            );
                        }
                        settings.weights.insert(name.clone(), weight);
                    }
                }
                "table" => {
                    settings.table = value
                        .as_u64()
                        .and_then(|t| u32::try_from(t).ok())
                        .filter(|t| (1..=250).contains(t) || (256..=0x7fff_0000).contains(t))
                        .ok_or("kubernetes.uplinks.table must be 1-250 or 256-2147418112")?;
                    if settings.table <= 250
                        && settings.table.saturating_add(MAX_PINNED as u32) > 250
                    {
                        return Err("kubernetes.uplinks.table leaves no room below 251".into());
                    }
                }
                "rule-priority" => {
                    settings.priority = value
                        .as_u64()
                        .and_then(|p| u32::try_from(p).ok())
                        .filter(|p| (1..=32_000u32.saturating_sub(PRIORITY_SPAN)).contains(p))
                        .ok_or("kubernetes.uplinks.rule-priority must be 1-31700")?;
                }
                _ => return Err(format!("unknown kubernetes.uplinks.{key}").into()),
            }
        }
        Ok(settings)
    }
    fn weight(&self, name: &str) -> u8 {
        self.weights.get(name).copied().unwrap_or(1)
    }
    /// Whether `priority` is one of flowsdn's rules.
    pub fn owns_priority(&self, priority: u32) -> bool {
        (self.priority..self.priority.saturating_add(PRIORITY_SPAN)).contains(&priority)
    }
    /// flowsdn's tables, the ECMP default's first.
    pub fn tables(&self) -> std::ops::RangeInclusive<u32> {
        self.table..=self.table.saturating_add(MAX_PINNED as u32)
    }
}

/// One interface as the monitor read it: its global addresses (without the
/// host addresses flowsdn added) and whether it has carrier.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Port {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub carrier: bool,
    pub addresses: Vec<Cidr>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Uplink {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
    pub up: bool,
    pub addresses: Vec<Cidr>,
    pub weight: u8,
    /// It holds the node's first InternalIP.
    pub primary: bool,
}
impl Uplink {
    /// Whether `ip` is on one of this uplink's subnets (or is an IPv6
    /// link-local gateway, reachable on every port of the segment).
    pub fn reaches(&self, ip: IpAddr) -> bool {
        link_local(ip)
            || self
                .addresses
                .iter()
                .any(|a| a.1 < host(ip) && overlaps(*a, (ip, host(ip))))
    }
}

fn host(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 32 } else { 128 }
}
fn link_local(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V6(v6) if v6.segments().first().is_some_and(|s| s & 0xffc0 == 0xfe80))
}
fn global(ip: IpAddr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local(ip))
}
/// The network address of `ip/prefix`.
pub fn network((ip, prefix): Cidr) -> Cidr {
    match ip {
        IpAddr::V4(v4) => {
            let mask = u32::MAX
                .checked_shl(32u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            (IpAddr::V4((u32::from(v4) & mask).into()), prefix)
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX
                .checked_shl(128u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            (IpAddr::V6((u128::from(v6) & mask).into()), prefix)
        }
    }
}

/// The uplinks among `ports`: those holding one of `node_ips`, or a global
/// address on the subnet of one. Ordered by preference: weight, then the
/// node's primary address, then interface index.
pub fn select(ports: &[Port], node_ips: &[IpAddr], settings: &Settings) -> Vec<Uplink> {
    let mut uplinks: Vec<Uplink> = ports
        .iter()
        .filter_map(|port| {
            let addresses: Vec<Cidr> = port
                .addresses
                .iter()
                .copied()
                .filter(|(ip, _)| global(*ip))
                .collect();
            let member = addresses.iter().any(|(ip, prefix)| {
                node_ips.contains(ip)
                    || node_ips.iter().any(|node| {
                        node.is_ipv4() == ip.is_ipv4()
                            && *prefix < host(*ip)
                            && overlaps((*ip, *prefix), (*node, host(*node)))
                    })
            });
            member.then(|| Uplink {
                name: port.name.clone(),
                index: port.index,
                mac: port.mac,
                up: port.carrier,
                primary: node_ips
                    .first()
                    .is_some_and(|first| addresses.iter().any(|(ip, _)| ip == first)),
                addresses,
                weight: settings.weight(&port.name),
            })
        })
        .collect();
    uplinks.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then(b.primary.cmp(&a.primary))
            .then(a.index.cmp(&b.index))
    });
    uplinks
}

/// Several uplinks, and a mode that uses them.
pub fn balancing(uplinks: &[Uplink], mode: Mode) -> bool {
    mode != Mode::Single && uplinks.len() >= 2
}

/// The uplinks that carry the balanced routes, in preference order.
pub fn carriers(uplinks: &[Uplink], mode: Mode) -> Vec<&Uplink> {
    if !balancing(uplinks, mode) {
        return Vec::new();
    }
    let up = uplinks.iter().filter(|u| u.up);
    match mode {
        Mode::ActiveBackup => up.take(1).collect(),
        _ => up.collect(),
    }
}

/// A down uplink's address, held as a host address by a live one.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct Move {
    pub address: IpAddr,
    pub from: String,
    pub to: String,
    pub to_index: u32,
    pub to_mac: [u8; 6],
}
impl Move {
    pub fn prefix(&self) -> u8 {
        host(self.address)
    }
}

/// Every address of a down uplink moves to the most preferred live uplink on
/// its subnet; with no such uplink it stays where it is.
pub fn moves(uplinks: &[Uplink], mode: Mode) -> Vec<Move> {
    if !balancing(uplinks, mode) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for down in uplinks.iter().filter(|u| !u.up) {
        for (address, _) in &down.addresses {
            if let Some(to) = uplinks.iter().find(|u| u.up && u.reaches(*address)) {
                out.push(Move {
                    address: *address,
                    from: down.name.clone(),
                    to: to.name.clone(),
                    to_index: to.index,
                    to_mac: to.mac,
                });
            }
        }
    }
    out
}

/// The paths of a route to a node with `gateways` (its InternalIPs of the
/// family, primary first) over `carriers`: path k pairs gateway k and
/// carrier k (cycling the shorter list), so two addresses on each side use
/// both ports at both ends. A pair whose carrier is not on the gateway's
/// subnet is dropped; if none is left, every reachable pair is used.
pub fn nexthops(gateways: &[IpAddr], carriers: &[&Uplink]) -> Vec<NextHop> {
    let mut out: Vec<NextHop> = Vec::new();
    let push = |out: &mut Vec<NextHop>, gateway: IpAddr, uplink: &Uplink| {
        let hop = NextHop {
            gateway: Some(gateway),
            index: uplink.index,
            weight: uplink.weight,
        };
        if !out.contains(&hop) {
            out.push(hop);
        }
    };
    let (Some(count_g), Some(count_c)) = (
        std::num::NonZeroUsize::new(gateways.len()),
        std::num::NonZeroUsize::new(carriers.len()),
    ) else {
        return Vec::new();
    };
    for k in 0..count_g.get().max(count_c.get()) {
        if let (Some(gateway), Some(uplink)) = (
            gateways.get(k.checked_rem(count_g.get()).unwrap_or(0)),
            carriers.get(k.checked_rem(count_c.get()).unwrap_or(0)),
        ) && uplink.reaches(*gateway)
        {
            push(&mut out, *gateway, uplink);
        }
    }
    if out.is_empty() {
        for gateway in gateways {
            for uplink in carriers.iter().filter(|u| u.reaches(*gateway)) {
                push(&mut out, *gateway, uplink);
            }
        }
    }
    out
}

/// One route of a flowsdn table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableEntry {
    pub destination: Cidr,
    pub hops: Vec<NextHop>,
    pub source: Option<IpAddr>,
}

/// The rules and table routes flowsdn wants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Desired {
    pub rules: BTreeSet<Rule>,
    pub tables: BTreeMap<u32, Vec<TableEntry>>,
}

/// Source rules, the ECMP default and the pinned tables. `defaults` are the
/// main table's default gateways (one per family). Nothing while there are
/// fewer than two uplinks or the mode is `single`.
pub fn desired(
    uplinks: &[Uplink],
    moves: &[Move],
    settings: &Settings,
    defaults: &[IpAddr],
) -> Desired {
    let mut out = Desired::default();
    if !balancing(uplinks, settings.mode) {
        return out;
    }
    let mut families = BTreeSet::new();
    let pinned = uplinks
        .iter()
        .flat_map(|u| u.addresses.iter().map(move |a| (u, *a)))
        .take(MAX_PINNED);
    for (offset, (owner, (address, prefix))) in (0u32..).zip(pinned) {
        let hosting = if owner.up {
            Some(owner)
        } else {
            moves
                .iter()
                .find(|m| m.address == address)
                .and_then(|m| uplinks.iter().find(|u| u.index == m.to_index))
        };
        let Some(hosting) = hosting else { continue };
        let v6 = address.is_ipv6();
        families.insert(v6);
        let table = settings.table.saturating_add(1).saturating_add(offset);
        let subnet = network((address, prefix));
        let source = Some((address, host(address)));
        out.rules.insert(Rule {
            v6,
            priority: settings.priority.saturating_add(10).saturating_add(offset),
            table,
            source,
            destination: Some(subnet),
            suppress_prefix: None,
        });
        out.rules.insert(Rule {
            v6,
            priority: settings.priority.saturating_add(100).saturating_add(offset),
            table,
            source,
            destination: None,
            suppress_prefix: None,
        });
        let mut entries = vec![TableEntry {
            destination: subnet,
            hops: vec![NextHop {
                gateway: None,
                index: hosting.index,
                weight: 1,
            }],
            source: Some(address),
        }];
        if let Some(gateway) = defaults
            .iter()
            .find(|g| g.is_ipv6() == v6 && (link_local(**g) || overlaps(subnet, (**g, host(**g)))))
        {
            entries.push(TableEntry {
                destination: (unspecified(v6), 0),
                hops: vec![NextHop {
                    gateway: Some(*gateway),
                    index: hosting.index,
                    weight: 1,
                }],
                source: Some(address),
            });
        }
        out.tables.insert(table, entries);
    }
    let live = carriers(uplinks, settings.mode);
    for v6 in families {
        out.rules.insert(Rule {
            v6,
            priority: settings.priority.saturating_add(50),
            table: 254,
            source: None,
            destination: None,
            suppress_prefix: Some(0),
        });
        let Some(gateway) = defaults.iter().find(|g| g.is_ipv6() == v6) else {
            continue;
        };
        let hops = nexthops(&[*gateway], &live);
        if hops.is_empty() {
            continue;
        }
        out.rules.insert(Rule {
            v6,
            priority: settings.priority.saturating_add(200),
            table: settings.table,
            source: None,
            destination: None,
            suppress_prefix: None,
        });
        out.tables
            .entry(settings.table)
            .or_default()
            .push(TableEntry {
                destination: (unspecified(v6), 0),
                hops,
                source: None,
            });
    }
    out
}

fn unspecified(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    }
}

/// A port joining or leaving, as the history and the log say it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Change {
    pub at: String,
    pub port: String,
    pub joined: bool,
    pub message: String,
}

/// The joins and leaves between two uplink sets: a port that gained carrier
/// or appeared up joins; one that lost carrier or disappeared while up
/// leaves.
pub fn changes(before: &[Uplink], after: &[Uplink], at: &str) -> Vec<Change> {
    let was: BTreeMap<&str, bool> = before.iter().map(|u| (u.name.as_str(), u.up)).collect();
    let now: BTreeMap<&str, &Uplink> = after.iter().map(|u| (u.name.as_str(), u)).collect();
    let live = after.iter().filter(|u| u.up).count();
    let mut out = Vec::new();
    for uplink in after {
        let addresses = addresses_text(&uplink.addresses);
        match (was.get(uplink.name.as_str()), uplink.up) {
            (Some(false) | None, true) => out.push(Change {
                at: at.into(),
                port: uplink.name.clone(),
                joined: true,
                message: format!(
                    "uplink {} joined: carrier up ({addresses}); {live} of {} carrying",
                    uplink.name,
                    after.len()
                ),
            }),
            (Some(true), false) => out.push(Change {
                at: at.into(),
                port: uplink.name.clone(),
                joined: false,
                message: format!(
                    "uplink {} left: no carrier ({addresses}); {live} of {} carrying",
                    uplink.name,
                    after.len()
                ),
            }),
            _ => {}
        }
    }
    for uplink in before
        .iter()
        .filter(|u| u.up && !now.contains_key(u.name.as_str()))
    {
        out.push(Change {
            at: at.into(),
            port: uplink.name.clone(),
            joined: false,
            message: format!(
                "uplink {} left: it no longer holds a node address; {live} of {} carrying",
                uplink.name,
                after.len()
            ),
        });
    }
    out
}

fn addresses_text(addresses: &[Cidr]) -> String {
    addresses
        .iter()
        .map(|(ip, prefix)| cidr_text(*ip, *prefix))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A physical port's link as sysfs and ethtool report it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortStats {
    pub name: String,
    pub carrier: bool,
    /// Mb/s; None while the kernel does not know.
    pub speed: Option<u32>,
    pub fec_configured: Vec<&'static str>,
    pub fec_active: Vec<&'static str>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// What `GET /v1/uplinks` serves and the route thread reads.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub started: bool,
    pub mode: Mode,
    pub uplinks: Vec<Uplink>,
    /// Uplink name -> its physical ports (itself, or a bridge's members).
    pub ports: BTreeMap<String, Vec<PortStats>>,
    pub moves: Vec<Move>,
    pub history: VecDeque<Change>,
    /// Bumped when the uplinks' carrier, addresses or moves change.
    pub generation: u64,
}
impl View {
    pub fn record(&mut self, change: Change) {
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(change);
    }
    /// The paths for a route to a node with `gateways`, or None to keep the
    /// plain route (one uplink, `single`, or no carrier on any).
    pub fn hops(&self, gateways: &[IpAddr]) -> Option<Vec<NextHop>> {
        let live = carriers(&self.uplinks, self.mode);
        let hops = nexthops(gateways, &live);
        (!hops.is_empty()).then_some(hops)
    }
    pub fn json(&self) -> Value {
        let mac = |m: &[u8; 6]| {
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        let live = carriers(&self.uplinks, self.mode);
        json!({
            "mode": self.mode.as_str(),
            "monitoring": self.started,
            "balancing": balancing(&self.uplinks, self.mode),
            "carrying": live.iter().map(|u| u.name.clone()).collect::<Vec<_>>(),
            "uplinks": self.uplinks.iter().map(|u| json!({
                "name": u.name,
                "ifindex": u.index,
                "mac": mac(&u.mac),
                "carrier": u.up,
                "primary": u.primary,
                "weight": u.weight,
                "addresses": u.addresses.iter().map(|(ip, p)| cidr_text(*ip, *p)).collect::<Vec<_>>(),
                "ports": self.ports.get(&u.name).map(|ports| ports.iter().map(|p| json!({
                    "name": p.name,
                    "carrier": p.carrier,
                    "speed-mbps": p.speed,
                    "fec": {"configured": p.fec_configured, "active": p.fec_active},
                    "rx-bytes": p.rx_bytes,
                    "tx-bytes": p.tx_bytes,
                })).collect::<Vec<_>>()).unwrap_or_default(),
            })).collect::<Vec<_>>(),
            "failover": self.moves.iter().map(|m| json!({
                "address": m.address.to_string(),
                "from": m.from,
                "on": m.to,
            })).collect::<Vec<_>>(),
            "history": self.history.iter().map(|c| json!({
                "at": c.at,
                "port": c.port,
                "event": if c.joined { "joined" } else { "left" },
                "message": c.message,
            })).collect::<Vec<_>>(),
        })
    }
    /// One line for `/v1/healthz`.
    pub fn summary(&self) -> String {
        let live = carriers(&self.uplinks, self.mode);
        if !balancing(&self.uplinks, self.mode) {
            return format!("{} uplink(s), {}", self.uplinks.len(), self.mode.as_str());
        }
        format!(
            "{} of {} uplinks carrying ({}), {}{}",
            live.len(),
            self.uplinks.len(),
            live.iter()
                .map(|u| u.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            self.mode.as_str(),
            if self.moves.is_empty() {
                String::new()
            } else {
                format!(", {} address(es) failed over", self.moves.len())
            }
        )
    }
}

#[cfg(test)]
#[path = "uplinks_tests.rs"]
mod tests;
