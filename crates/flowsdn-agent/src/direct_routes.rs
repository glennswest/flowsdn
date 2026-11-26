//! Direct node routes through spec 10's `desired-routes` (#576 stage 2).
//!
//! The route thread is the `direct-routes` owner: from the desired routes (one
//! per other node's pod CIDR, #292) it plans `flowsdn_node` rows, which the
//! [`RouteManager`](flowsdn_node::routes::RouteManager) selects and the
//! reconciler puts into the kernel through [`ConnectorOps`]:
//!
//! - **Plan** ([`plan`]): with several uplinks, an ECMP route over the paths
//!   whose gateway is directly reachable (#498); else the plain route via the
//!   node's first InternalIP, which must be directly reachable (spec 10
//!   §3.2.3 step 1; skipped instead with `direct-routing-skip-unreachable`).
//! - **Install** ([`ConnectorOps::replace`]): never over a route of another
//!   protocol to the prefix (§5.2). The route's key is persisted before it is
//!   installed, so one left by a crash is still pruned.
//! - **Delete** and **prune**: by destination, flowsdn's own route only.
//!   Prune runs once the first complete Node list is planned (the table's
//!   initializer), and removes persisted routes nobody wants.
//! - **Repair**: every row is refreshed every 30 s (the reconciler's refresh),
//!   as the 30 s repair did.
//! - **Held**: a desired route that plans no row this round (an error, or
//!   skipped) keeps whatever is installed for it ([`Holding`]): only a route
//!   no longer desired is deleted (#498).
use crate::kubernetes::DesiredRoute;
use flowsdn_connector::Connector;
use flowsdn_connector::multihome::NextHop;
use flowsdn_node::routes::{RouteId, RouteOps};
use flowsdn_node::rows;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const OWNER: &str = "direct-routes";
/// The reference's default admin distance.
pub const ADMIN_DISTANCE: u8 = 100;
/// The main table.
pub const MAIN: u32 = 254;
/// `RTPROT_KERNEL`, the protocol direct routes are installed with.
pub const RTPROT_KERNEL: u8 = 2;

/// A persisted route: destination, prefix, gateway.
pub type Key = (IpAddr, u8, IpAddr);

/// One desired route, planned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Planned {
    /// Reconciled into the kernel.
    Row(Box<rows::DesiredRoute>),
    /// Not installed, with why (direct-routing-skip-unreachable).
    Skipped(String),
    /// Not installed: an error.
    Failed(String),
}

/// `a.b.c.d/n`.
pub fn cidr_text(ip: IpAddr, prefix: u8) -> String {
    format!("{ip}/{prefix}")
}

/// The hops whose gateway is directly reachable (#498; spec 10 §3.2.3 step
/// 1 per path): `direct` says whether the main table reaches an address
/// without a router. A hop without a gateway is on-link.
pub fn reachable_hops(
    hops: &[NextHop],
    mut direct: impl FnMut(IpAddr) -> Result<bool, String>,
) -> Result<Vec<NextHop>, String> {
    let mut out = Vec::new();
    for hop in hops {
        let ok = match hop.gateway {
            Some(gateway) => direct(gateway)?,
            None => true,
        };
        if ok {
            out.push(*hop);
        }
    }
    Ok(out)
}

/// Plan one route. `hops`: the ECMP paths over this node's uplinks (#408),
/// when there are several; `direct`: whether an address is reached without a
/// router; `router`: the gateway the main table uses for an address.
pub fn plan(
    route: &DesiredRoute,
    hops: Option<&[NextHop]>,
    mut direct: impl FnMut(IpAddr) -> Result<bool, String>,
    mut router: impl FnMut(IpAddr) -> Result<Option<IpAddr>, String>,
    skip_unreachable: bool,
) -> Planned {
    let base = |nexthop: Option<IpAddr>, multipath: Vec<rows::NextHop>| {
        Planned::Row(Box::new(rows::DesiredRoute {
            owner: OWNER.into(),
            table: MAIN,
            prefix: (route.destination, route.prefix),
            priority: None,
            nexthop,
            src: None,
            device: None,
            multipath,
            mtu: None,
            scope: "universe".into(),
            kind: "unicast".into(),
            admin_distance: ADMIN_DISTANCE,
            selected: false,
        }))
    };
    if let Some(hops) = hops {
        match reachable_hops(hops, &mut direct) {
            Ok(usable) if !usable.is_empty() => {
                return base(
                    None,
                    usable
                        .iter()
                        .map(|h| rows::NextHop {
                            gateway: h.gateway,
                            device_index: h.index,
                            weight: h.weight,
                        })
                        .collect(),
                );
            }
            Ok(_) => {}
            Err(error) => return Planned::Failed(error),
        }
    }
    match router(route.gateway) {
        Err(error) => Planned::Failed(error),
        Ok(Some(gateway)) if !gateway.is_unspecified() && gateway != route.gateway => {
            if skip_unreachable {
                Planned::Skipped(format!(
                    "skipped: route to {} uses gateway {gateway}",
                    route.gateway
                ))
            } else {
                Planned::Failed(format!(
                    "route to destination {} contains gateway {gateway}, must be directly reachable. \
                     Add direct-routing-skip-unreachable to skip unreachable routes",
                    route.gateway
                ))
            }
        }
        Ok(_) => base(Some(route.gateway), Vec::new()),
    }
}

/// The state text of a planned row once reconciled.
pub fn installed_text(row: &rows::DesiredRoute) -> String {
    if row.multipath.len() > 1 {
        format!("installed: {} paths", row.multipath.len())
    } else {
        "installed".into()
    }
}

/// The persisted route set: `[{destination, gateway}]`.
pub fn load(file: &Path) -> Result<BTreeSet<Key>, String> {
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error.to_string()),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut routes = BTreeSet::new();
    for row in value.as_array().ok_or("routes file must be an array")? {
        let text = |key: &str| -> Result<&str, String> {
            row.get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("route without {key}"))
        };
        let (ip, prefix) = text("destination")?
            .split_once('/')
            .ok_or("route destination must be a CIDR")?;
        let parse = |what: &str, text: &str| format!("bad {what} {text:?}");
        routes.insert((
            ip.parse().map_err(|_| parse("address", ip))?,
            prefix.parse().map_err(|_| parse("prefix", prefix))?,
            text("gateway")?
                .parse()
                .map_err(|_| parse("gateway", "gateway"))?,
        ));
    }
    Ok(routes)
}
/// Write the persisted route set.
pub fn save(file: &Path, routes: &BTreeSet<Key>) -> Result<(), String> {
    let rows: Vec<_> = routes
        .iter()
        .map(|(ip, prefix, gateway)| {
            json!({"destination": cidr_text(*ip, *prefix), "gateway": gateway.to_string()})
        })
        .collect();
    use std::io::Write as _;
    let text = serde_json::to_vec(&rows).map_err(|e| e.to_string())?;
    let temporary = file.with_extension("json.tmp");
    let mut output = fs::File::create(&temporary).map_err(|e| e.to_string())?;
    output.write_all(&text).map_err(|e| e.to_string())?;
    output.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temporary, file).map_err(|e| e.to_string())
}

/// The kernel side of the direct routes over netlink.
pub struct ConnectorOps {
    pub connector: Connector,
    file: PathBuf,
    installed: BTreeSet<Key>,
}
impl ConnectorOps {
    /// Open with the persisted set (unreadable: empty, said once).
    pub fn new(connector: Connector, file: PathBuf) -> Self {
        let installed = match load(&file) {
            Ok(routes) => routes,
            Err(error) => {
                crate::log::logln!("ignoring unreadable {}: {error}", file.display());
                BTreeSet::new()
            }
        };
        Self {
            connector,
            file,
            installed,
        }
    }
    /// Whether the main table reaches `address` without a router.
    pub fn direct(&self, address: IpAddr) -> Result<bool, String> {
        self.router(address)
            .map(|gateway| gateway.is_none_or(|g| g.is_unspecified() || g == address))
    }
    /// The gateway the main table uses for `address`.
    pub fn router(&self, address: IpAddr) -> Result<Option<IpAddr>, String> {
        self.connector
            .lookup(address)
            .map(|(gateway, _)| gateway)
            .map_err(|e| e.to_string())
    }
}
impl RouteOps for ConnectorOps {
    fn replace(&mut self, route: &rows::DesiredRoute) -> Result<(), String> {
        let (destination, prefix) = route.prefix;
        // Spec 10 §5.2: never clobber a static/boot/dhcp/ra route to the prefix.
        let existing = self
            .connector
            .main_routes_to(destination, prefix)
            .map_err(|e| e.to_string())?;
        if let Some(other) = existing.iter().find(|r| r.protocol != RTPROT_KERNEL) {
            return Err(format!("route conflict with proto {}", other.protocol));
        }
        let gateway = route
            .nexthop
            .or_else(|| route.multipath.iter().find_map(|h| h.gateway))
            .unwrap_or(destination);
        // Persisted before it is installed; another gateway's key for the
        // same destination is replaced.
        let before = self.installed.len();
        self.installed
            .retain(|(d, p, g)| !(*d == destination && *p == prefix && *g != gateway));
        if self.installed.insert((destination, prefix, gateway)) || self.installed.len() != before {
            save(&self.file, &self.installed)?;
        }
        if route.multipath.is_empty() {
            self.connector
                .replace_gateway_route(destination, prefix, gateway)
                .map_err(|e| e.to_string())
        } else {
            let hops: Vec<NextHop> = route
                .multipath
                .iter()
                .map(|h| NextHop {
                    gateway: h.gateway,
                    index: h.device_index,
                    weight: h.weight,
                })
                .collect();
            self.connector
                .replace_multipath_route(destination, prefix, &hops, MAIN, None, None)
                .map_err(|e| e.to_string())
        }
    }
    fn delete(
        &mut self,
        table: u32,
        (destination, prefix): (IpAddr, u8),
        _: u32,
    ) -> Result<(), String> {
        if table != MAIN {
            return Ok(());
        }
        // flowsdn's route for the destination (protocol kernel, with a
        // gateway or paths), whatever gateway it uses (#498); a route of
        // another protocol, or a connected one, is never touched.
        let owned = self
            .connector
            .table_routes(MAIN, destination.is_ipv6())
            .map_err(|e| e.to_string())?
            .into_iter()
            .any(|r| {
                r.destination == destination
                    && r.prefix == prefix
                    && flowsdn_connector::multihome::owned(&r)
            });
        if owned {
            self.connector
                .delete_owned_route(destination, prefix, MAIN, None)
                .map_err(|e| e.to_string())?;
        }
        let before = self.installed.len();
        self.installed
            .retain(|(d, p, _)| !(*d == destination && *p == prefix));
        if self.installed.len() != before {
            save(&self.file, &self.installed)?;
        }
        Ok(())
    }
    fn owned(&mut self) -> Result<Vec<RouteId>, String> {
        let routes: BTreeSet<RouteId> = self
            .installed
            .iter()
            .map(|(d, p, _)| (MAIN, (*d, *p), 0))
            .collect();
        Ok(routes.into_iter().collect())
    }
}

/// The prefixes of desired routes that planned no row this round (an
/// error, or skipped as unreachable), whose installed route stays as it is:
/// a route is deleted only when it is no longer desired (#498, as before
/// #576), never because one lookup failed.
pub fn held(planned: &[(DesiredRoute, Planned)]) -> BTreeSet<(IpAddr, u8)> {
    planned
        .iter()
        .filter(|(_, p)| !matches!(p, Planned::Row(_)))
        .map(|(route, _)| (route.destination, route.prefix))
        .collect()
}

/// [`RouteOps`] that neither deletes nor prunes a held prefix (see
/// [`held`]); the loop sets the shared set before each round.
pub struct Holding<O: RouteOps> {
    pub inner: O,
    pub held: Arc<Mutex<BTreeSet<(IpAddr, u8)>>>,
}
impl<O: RouteOps> Holding<O> {
    fn holds(&self, prefix: (IpAddr, u8)) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&prefix)
    }
}
impl<O: RouteOps> RouteOps for Holding<O> {
    fn replace(&mut self, route: &rows::DesiredRoute) -> Result<(), String> {
        self.inner.replace(route)
    }
    fn delete(&mut self, table: u32, prefix: (IpAddr, u8), priority: u32) -> Result<(), String> {
        if self.holds(prefix) {
            return Ok(());
        }
        self.inner.delete(table, prefix, priority)
    }
    fn owned(&mut self) -> Result<Vec<RouteId>, String> {
        let owned = self.inner.owned()?;
        Ok(owned
            .into_iter()
            .filter(|(_, prefix, _)| !self.holds(*prefix))
            .collect())
    }
}

#[cfg(test)]
#[path = "direct_routes_tests.rs"]
mod tests;
