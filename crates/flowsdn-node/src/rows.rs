//! Spec 10's table rows (§3.1.1, §4.1). Columns follow the harvested `.table`
//! files of the `device`, `route-reconciler` and `neighbor` areas.
use flowsdn_table::{Index, Keyed, TableRender, key};
use std::net::IpAddr;

/// A prefix: address and length.
pub type Prefix = (IpAddr, u8);

/// `a.b.c.d/n` or `x::/n`.
pub fn prefix_text(prefix: &Prefix) -> String {
    format!("{}/{}", prefix.0, prefix.1)
}
fn opt<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "none".to_owned(), |v| v.to_string())
}
fn prefix_key(prefix: &Prefix) -> Vec<u8> {
    let mut out = key::addr(prefix.0);
    out.push(prefix.1);
    out
}

/// One address of a device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceAddress {
    pub addr: IpAddr,
    pub prefix: u8,
    /// `RT_SCOPE_*`: 0 universe, 200 site, 253 link, 254 host.
    pub scope: u8,
    pub secondary: bool,
}

/// `devices`: one network device (§3.1.1).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Device {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub hw_addr: Option<[u8; 6]>,
    /// The link kind (`veth`, `vxlan`, `bridge`, …); `device` when it has none.
    pub kind: String,
    pub up: bool,
    /// `up`, `down`, `unknown`, …
    pub oper_status: String,
    pub master_index: Option<u32>,
    pub addresses: Vec<DeviceAddress>,
    pub selected: bool,
    pub not_selected_reason: String,
}
impl Keyed for Device {
    fn primary_key(&self) -> Vec<u8> {
        key::u32be(self.index)
    }
}
impl TableRender for Device {
    fn headers() -> &'static [&'static str] {
        &[
            "Name",
            "Index",
            "Selected",
            "Type",
            "MTU",
            "HWAddr",
            "Flags",
            "Addresses",
            "OperStatus",
        ]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.name.clone(),
            self.index.to_string(),
            self.selected.to_string(),
            self.kind.clone(),
            self.mtu.to_string(),
            self.hw_addr.map_or_else(String::new, |m| {
                m.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            }),
            if self.up { "up" } else { "" }.to_owned(),
            self.addresses
                .iter()
                .map(|a| a.addr.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            self.oper_status.clone(),
        ]
    }
}
/// The `devices` indexes: unique `name`, and `selected`.
pub fn device_indexes() -> Vec<Index<Device>> {
    vec![
        Index::new("name", true, |d: &Device| vec![d.name.clone().into_bytes()]),
        Index::new("selected", false, |d: &Device| {
            vec![vec![u8::from(d.selected)]]
        }),
    ]
}

/// `routes`: a route as the kernel holds it (§3.1.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    pub table: u32,
    pub link_index: u32,
    pub dst: Prefix,
    pub src: Option<IpAddr>,
    pub gw: Option<IpAddr>,
    pub scope: u8,
    pub priority: u32,
    pub proto: u8,
    /// `RTN_*`: 1 unicast, 2 local.
    pub kind: u8,
}
impl Keyed for Route {
    fn primary_key(&self) -> Vec<u8> {
        let mut out = key::u32be(self.table);
        out.extend(key::u32be(self.link_index));
        out.extend(prefix_key(&self.dst));
        out
    }
}
impl TableRender for Route {
    fn headers() -> &'static [&'static str] {
        &["Table", "LinkIndex", "Destination", "Source", "Gateway"]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.table.to_string(),
            self.link_index.to_string(),
            prefix_text(&self.dst),
            opt(self.src),
            opt(self.gw),
        ]
    }
}
/// The `routes` index: `link_index`.
pub fn route_indexes() -> Vec<Index<Route>> {
    vec![Index::new("link", false, |r: &Route| {
        vec![key::u32be(r.link_index)]
    })]
}

/// `neighbors`: a neighbor entry (§3.1.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neighbor {
    pub link_index: u32,
    pub addr: IpAddr,
    pub hw_addr: Option<[u8; 6]>,
    /// `DST` (unicast) and the reference's other type names.
    pub kind: String,
    /// `REACHABLE`, `STALE`, … (`NUD_*`).
    pub state: String,
    /// `EXT_LEARNED`, …, or `NONE`.
    pub flags: String,
    /// `EXT_MANAGED` or `NONE`.
    pub flags_ext: String,
}
impl Keyed for Neighbor {
    fn primary_key(&self) -> Vec<u8> {
        let mut out = key::u32be(self.link_index);
        out.extend(key::addr(self.addr));
        out
    }
}
impl TableRender for Neighbor {
    fn headers() -> &'static [&'static str] {
        &[
            "LinkIndex",
            "IPAddr",
            "HardwareAddr",
            "Type",
            "State",
            "Flags",
            "FlagsExt",
        ]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.link_index.to_string(),
            self.addr.to_string(),
            self.hw_addr.map_or_else(String::new, |m| {
                m.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            }),
            self.kind.clone(),
            self.state.clone(),
            self.flags.clone(),
            self.flags_ext.clone(),
        ]
    }
}

/// `node-addresses` (§3.1.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeAddress {
    pub addr: IpAddr,
    pub device: String,
    pub node_port: bool,
    pub primary: bool,
}
impl Keyed for NodeAddress {
    fn primary_key(&self) -> Vec<u8> {
        let mut out = key::addr(self.addr);
        out.extend(self.device.as_bytes());
        out
    }
}
impl TableRender for NodeAddress {
    fn headers() -> &'static [&'static str] {
        &["Address", "NodePort", "Primary", "DeviceName"]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.addr.to_string(),
            self.node_port.to_string(),
            self.primary.to_string(),
            self.device.clone(),
        ]
    }
}

/// One path of a multipath route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NextHop {
    pub gateway: IpAddr,
    pub device_index: u32,
    /// The kernel's weight minus one (`rtnh_hops`).
    pub weight: u8,
}

/// `desired-routes` (§4.1): a route an owner wants. Several owners may want
/// the same `(table, prefix, priority)`; the lowest admin distance is
/// `selected` and reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredRoute {
    pub owner: String,
    pub table: u32,
    pub prefix: Prefix,
    pub priority: Option<u32>,
    pub nexthop: Option<IpAddr>,
    pub src: Option<IpAddr>,
    /// The device: name and index.
    pub device: Option<(String, u32)>,
    pub multipath: Vec<NextHop>,
    pub mtu: Option<u32>,
    /// `universe`, `link`, `host`.
    pub scope: String,
    /// `unicast`, `local`, or `unspec` (the kernel's default).
    pub kind: String,
    pub admin_distance: u8,
    pub selected: bool,
}
impl DesiredRoute {
    /// The kernel route's identity: `(table, prefix, priority)`.
    pub fn group_key(&self) -> Vec<u8> {
        group_key(self.table, &self.prefix, self.priority)
    }
}
/// `(table, prefix, priority)` encoded; a route without a priority sorts as 0.
pub fn group_key(table: u32, prefix: &Prefix, priority: Option<u32>) -> Vec<u8> {
    let mut out = key::u32be(table);
    out.extend(prefix_key(prefix));
    out.extend(key::u32be(priority.unwrap_or(0)));
    out
}
/// The group key's parts back, from a group key or a primary key (which
/// starts with it).
pub fn parse_group(bytes: &[u8]) -> Option<(u32, Prefix, u32)> {
    let table = u32::from_be_bytes(bytes.get(0..4)?.try_into().ok()?);
    let addr: [u8; 16] = bytes.get(4..20)?.try_into().ok()?;
    let length = *bytes.get(20)?;
    let priority = u32::from_be_bytes(bytes.get(21..25)?.try_into().ok()?);
    let v6 = std::net::Ipv6Addr::from(addr);
    let addr = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    Some((table, (addr, length), priority))
}
impl Keyed for DesiredRoute {
    fn primary_key(&self) -> Vec<u8> {
        let mut out = self.group_key();
        out.extend(self.owner.as_bytes());
        out
    }
}
impl TableRender for DesiredRoute {
    fn headers() -> &'static [&'static str] {
        &[
            "Owner",
            "Table",
            "Prefix",
            "Priority",
            "AD",
            "Selected",
            "Nexthop",
            "Src",
            "Device",
            "MultiPath",
            "MTU",
            "Scope",
            "Type",
        ]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.owner.clone(),
            self.table.to_string(),
            prefix_text(&self.prefix),
            opt(self.priority),
            self.admin_distance.to_string(),
            self.selected.to_string(),
            opt(self.nexthop),
            opt(self.src),
            self.device.as_ref().map_or_else(
                || "none".to_owned(),
                |(name, index)| format!("{name} ({index})"),
            ),
            if self.multipath.is_empty() {
                "none".to_owned()
            } else {
                self.multipath
                    .iter()
                    .map(|h| format!("{} ({}, {})", h.gateway, h.device_index, h.weight))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            opt(self.mtu),
            self.scope.clone(),
            self.kind.clone(),
        ]
    }
}
/// The `desired-routes` indexes: `group` (`(table, prefix, priority)`) and
/// `owner`.
pub fn desired_route_indexes() -> Vec<Index<DesiredRoute>> {
    vec![
        Index::new("group", false, |r: &DesiredRoute| vec![r.group_key()]),
        Index::new("owner", false, |r: &DesiredRoute| {
            vec![r.owner.clone().into_bytes()]
        }),
    ]
}

/// `forwardable-ips` (§4.1): an address whose neighbor flowsdn keeps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForwardableIp {
    pub addr: IpAddr,
    /// `node:<name>` or `service:<namespace>/<name>`.
    pub owners: Vec<String>,
}
impl Keyed for ForwardableIp {
    fn primary_key(&self) -> Vec<u8> {
        key::addr(self.addr)
    }
}
impl TableRender for ForwardableIp {
    fn headers() -> &'static [&'static str] {
        &["IP", "Owners"]
    }
    fn cells(&self) -> Vec<String> {
        vec![self.addr.to_string(), self.owners.join(", ")]
    }
}

/// `desired-neighbors` (§4.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesiredNeighbor {
    pub addr: IpAddr,
    pub link_index: u32,
}
impl Keyed for DesiredNeighbor {
    fn primary_key(&self) -> Vec<u8> {
        let mut out = key::u32be(self.link_index);
        out.extend(key::addr(self.addr));
        out
    }
}
impl TableRender for DesiredNeighbor {
    fn headers() -> &'static [&'static str] {
        &["IP", "Link"]
    }
    fn cells(&self) -> Vec<String> {
        vec![self.addr.to_string(), self.link_index.to_string()]
    }
}
