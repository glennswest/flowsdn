//! Applying the uplink plan to the kernel (#408): read the ports, write the
//! sysctls balancing needs, keep flowsdn's rules and tables, read each port's
//! counters and FEC, and keep the failover addresses on disk. The monitor
//! thread (Kubernetes mode) and the `uplinks-live` kernel fixture both use
//! these, so the fixture checks the agent's own code on a real kernel.
use super::{Desired, Move, Port, PortStats, Settings, TableEntry, Uplink};
use crate::kubernetes::cidr_text;
use crate::state::Result;
use flowsdn_connector::{
    Connector,
    multihome::{self, Rule},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

/// FEC is read this often (an ioctl per physical port).
pub const FEC_INTERVAL: Duration = Duration::from_secs(5);
/// Each physical port's last FEC read (configured, active) and when.
pub type FecCache = BTreeMap<String, (Option<(u32, u32)>, Instant)>;
/// The failover addresses, under the agent's state directory.
pub const MOVES_FILE: &str = "uplink-moves.json";

pub fn global(ip: IpAddr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || matches!(ip, IpAddr::V6(v6) if v6.segments().first().is_some_and(|s| s & 0xffc0 == 0xfe80)))
}

/// Every interface with its carrier and addresses, minus the host addresses
/// flowsdn added for failover.
pub fn read_ports(connector: &Connector, moved: &[Move]) -> std::result::Result<Vec<Port>, String> {
    let addresses = connector
        .all_addresses()
        .map_err(|e| format!("netlink addresses: {e}"))?;
    let mut ports = Vec::new();
    for entry in fs::read_dir("/sys/class/net").map_err(|e| format!("/sys/class/net: {e}"))? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name().to_string_lossy().into_owned();
        let read = |key: &str| fs::read_to_string(entry.path().join(key)).ok();
        let Some(index) = read("ifindex").and_then(|i| i.trim().parse::<u32>().ok()) else {
            continue;
        };
        let carrier = read("carrier").is_some_and(|c| c.trim() == "1");
        let mac = read("address").map(|m| parse_mac(&m)).unwrap_or_default();
        let held = addresses
            .iter()
            .filter(|(i, ip, _)| {
                *i == index
                    && !moved
                        .iter()
                        .any(|m| m.to_index == index && m.address == *ip)
            })
            .map(|(_, ip, prefix)| (*ip, *prefix))
            .collect();
        ports.push(Port {
            name,
            index,
            mac,
            carrier,
            addresses: held,
        });
    }
    ports.sort_by_key(|p| p.index);
    Ok(ports)
}

pub fn parse_mac(text: &str) -> [u8; 6] {
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(text.trim().split(':')) {
        *slot = u8::from_str_radix(part, 16).unwrap_or(0);
    }
    mac
}

/// What balancing needs of the kernel (spec: docs/runtime.md, #408): per-flow
/// L4 hashing, no paths over a port without carrier, each address answered
/// only on the port that holds it, no strict reverse-path check (replies may
/// arrive on the other port) and unsolicited NA for moved IPv6 addresses.
pub fn tune(root: &Path, uplink: &str, node_ips: &[IpAddr]) -> Vec<String> {
    let v6 = node_ips.iter().any(IpAddr::is_ipv6) || root.join("net/ipv6/conf/all").exists();
    let mut keys: Vec<(String, &str)> = vec![
        ("net/ipv4/fib_multipath_hash_policy".into(), "1"),
        // A path whose gateway does not answer ARP (a port on another
        // segment with the same subnet) is skipped, not blackholed.
        ("net/ipv4/fib_multipath_use_neigh".into(), "1"),
        ("net/ipv4/conf/all/ignore_routes_with_linkdown".into(), "1"),
        (
            format!("net/ipv4/conf/{uplink}/ignore_routes_with_linkdown"),
            "1",
        ),
        (format!("net/ipv4/conf/{uplink}/arp_ignore"), "1"),
        (format!("net/ipv4/conf/{uplink}/arp_announce"), "2"),
        (format!("net/ipv4/conf/{uplink}/rp_filter"), "0"),
    ];
    if v6 {
        keys.extend([
            ("net/ipv6/fib_multipath_hash_policy".into(), "1"),
            ("net/ipv6/conf/all/ignore_routes_with_linkdown".into(), "1"),
            (
                format!("net/ipv6/conf/{uplink}/ignore_routes_with_linkdown"),
                "1",
            ),
            (format!("net/ipv6/conf/{uplink}/ndisc_notify"), "1"),
        ]);
    }
    let mut failed = Vec::new();
    for (key, value) in keys {
        if let Err(error) = fs::write(root.join(&key), value) {
            failed.push(format!("{}={value}: {error}", key.replace('/', ".")));
        }
    }
    failed
}

/// [`tune`] every uplink in `names` not yet in `tuned` (#497). An uplink
/// joins `tuned` only once all its writes succeeded; one that failed is
/// tried again on the next call, and its failures are returned each time
/// until then.
pub fn tune_pending<'a>(
    root: &Path,
    names: impl IntoIterator<Item = &'a str>,
    node_ips: &[IpAddr],
    tuned: &mut BTreeSet<String>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for name in names {
        if tuned.contains(name) {
            continue;
        }
        let failed = tune(root, name, node_ips);
        if failed.is_empty() {
            tuned.insert(name.to_owned());
        } else {
            failures.extend(failed.into_iter().map(|f| format!("{name}: {f}")));
        }
    }
    failures
}

/// The main table's default gateways, one per family.
pub fn default_gateways(connector: &Connector) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for any in [
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    ] {
        if let Some(gateway) = connector
            .main_routes_to(any, 0)
            .ok()
            .and_then(|routes| routes.into_iter().find_map(|r| r.gateway))
        {
            out.push(gateway);
        }
    }
    out
}

/// Make flowsdn's rules and tables what `desired` says (#576 stage 3): the
/// table routes are the `uplinks` owner of spec 10's `desired-routes` and the
/// rules are `desired-rules`, each reconciled into the kernel through
/// `flowsdn-reconcile`. Rules in flowsdn's priority span and routes in its
/// tables that are not wanted are pruned; every wanted one is (re)written.
/// Nothing outside the span and the tables is touched.
pub fn reconcile_kernel(
    connector: &Connector,
    settings: &Settings,
    desired: &Desired,
) -> std::result::Result<(), String> {
    use flowsdn_node::routes::{RouteManager, RouteTarget};
    use flowsdn_node::rules::{RuleTarget, set_rules};
    use flowsdn_reconcile::{Kind, Options, Reconciler};
    use futures::executor::block_on;
    let mut failures = Vec::new();
    // Rules.
    let rules = flowsdn_table::Table::new(Vec::new()).map_err(|e| e.to_string())?;
    let init = rules
        .register_initializer(OWNER)
        .map_err(|e| e.to_string())?;
    rules.seal_initializers();
    let wanted: BTreeSet<flowsdn_node::rows::DesiredRule> = desired.rules.iter().map(to_row).collect();
    block_on(set_rules(&rules, &wanted)).map_err(|e| e.to_string())?;
    init.complete();
    let mut reconciler = Reconciler::new(
        &rules,
        RuleTarget::new(RuleOps { connector, settings }),
        Options::default(),
    )
    .map_err(|e| e.to_string())?;
    reconciler.prune_now();
    drive(&mut reconciler, &mut failures, "rule");
    for (row, _) in rules.snapshot().all() {
        if let Some(status) = reconciler.status(&flowsdn_table::Keyed::primary_key(&*row))
            && status.kind == Kind::Error
        {
            failures.push(format!(
                "rule {}: {}",
                row.priority,
                status.error.unwrap_or_default()
            ));
        }
    }
    // Table routes.
    let manager = RouteManager::new().map_err(|e| e.to_string())?;
    let table = manager.table();
    let init = table
        .register_initializer(OWNER)
        .map_err(|e| e.to_string())?;
    table.seal_initializers();
    let rows: Vec<flowsdn_node::rows::DesiredRoute> = desired
        .tables
        .iter()
        .flat_map(|(table, entries)| entries.iter().map(move |e| route_row(*table, e)))
        .collect();
    block_on(manager.set_owner(OWNER, rows)).map_err(|e| e.to_string())?;
    init.complete();
    let mut reconciler = Reconciler::new(
        &table,
        RouteTarget::new(TableOps { connector, settings }, std::sync::Arc::clone(&table)),
        Options::default(),
    )
    .map_err(|e| e.to_string())?;
    reconciler.prune_now();
    drive(&mut reconciler, &mut failures, "route");
    for (row, _) in table.snapshot().all() {
        if let Some(status) = reconciler.status(&flowsdn_table::Keyed::primary_key(&*row))
            && status.kind == Kind::Error
        {
            failures.push(format!(
                "table {} {}: {}",
                row.table,
                cidr_text(row.prefix.0, row.prefix.1),
                status.error.unwrap_or_default()
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// The owner of the uplink table routes in `desired-routes`.
pub const OWNER: &str = "uplinks";

/// Run rounds until nothing is pending (bounded); a prune error is a failure.
fn drive<T: flowsdn_table::Keyed, U: flowsdn_reconcile::Target<T>>(
    reconciler: &mut flowsdn_reconcile::Reconciler<'_, T, U>,
    failures: &mut Vec<String>,
    what: &str,
) {
    // The connector runs its own runtime, so this is driven without one.
    for _ in 0..16 {
        let _ = futures::executor::block_on(reconciler.run_round(std::time::Instant::now()));
        if !reconciler.has_pending_work() {
            break;
        }
    }
    if let Some(error) = reconciler.prune_status().and_then(|p| p.error.clone()) {
        failures.push(format!("{what} prune: {error}"));
    }
}

fn to_row(rule: &Rule) -> flowsdn_node::rows::DesiredRule {
    flowsdn_node::rows::DesiredRule {
        v6: rule.v6,
        priority: rule.priority,
        table: rule.table,
        from: rule.source,
        to: rule.destination,
        suppress_prefix: rule.suppress_prefix,
    }
}
fn from_row(row: &flowsdn_node::rows::DesiredRule) -> Rule {
    Rule {
        v6: row.v6,
        priority: row.priority,
        table: row.table,
        source: row.from,
        destination: row.to,
        suppress_prefix: row.suppress_prefix,
    }
}
fn route_row(table: u32, entry: &TableEntry) -> flowsdn_node::rows::DesiredRoute {
    flowsdn_node::rows::DesiredRoute {
        owner: OWNER.into(),
        table,
        prefix: entry.destination,
        priority: None,
        nexthop: None,
        src: entry.source,
        device: None,
        multipath: entry
            .hops
            .iter()
            .map(|h| flowsdn_node::rows::NextHop {
                gateway: h.gateway,
                device_index: h.index,
                weight: h.weight,
            })
            .collect(),
        mtu: None,
        scope: "universe".into(),
        kind: "unicast".into(),
        admin_distance: 100,
        selected: false,
    }
}

/// `desired-rules` over netlink: flowsdn's priority span only.
struct RuleOps<'a> {
    connector: &'a Connector,
    settings: &'a Settings,
}
impl flowsdn_node::rules::RuleOps for RuleOps<'_> {
    fn add(&mut self, rule: &flowsdn_node::rows::DesiredRule) -> std::result::Result<(), String> {
        self.connector
            .add_rule(&from_row(rule))
            .map_err(|e| e.to_string())
    }
    fn delete(&mut self, rule: &flowsdn_node::rows::DesiredRule) -> std::result::Result<(), String> {
        self.connector
            .delete_rule(&from_row(rule))
            .map_err(|e| e.to_string())
    }
    fn owned(&mut self) -> std::result::Result<Vec<flowsdn_node::rows::DesiredRule>, String> {
        let mut out = Vec::new();
        for v6 in [false, true] {
            for rule in self.connector.rules(v6).map_err(|e| format!("list rules: {e}"))? {
                if self.settings.owns_priority(rule.priority) {
                    out.push(to_row(&rule));
                }
            }
        }
        Ok(out)
    }
}

/// `desired-routes` in flowsdn's uplink tables over netlink.
struct TableOps<'a> {
    connector: &'a Connector,
    settings: &'a Settings,
}
impl flowsdn_node::routes::RouteOps for TableOps<'_> {
    fn replace(&mut self, route: &flowsdn_node::rows::DesiredRoute) -> std::result::Result<(), String> {
        let hops: Vec<multihome::NextHop> = route
            .multipath
            .iter()
            .map(|h| multihome::NextHop {
                gateway: h.gateway,
                index: h.device_index,
                weight: h.weight,
            })
            .collect();
        self.connector
            .replace_multipath_route(route.prefix.0, route.prefix.1, &hops, route.table, None, route.src)
            .map_err(|e| e.to_string())
    }
    fn delete(
        &mut self,
        table: u32,
        (destination, prefix): (IpAddr, u8),
        _: u32,
    ) -> std::result::Result<(), String> {
        if !self.settings.tables().contains(&table) {
            return Ok(());
        }
        self.connector
            .delete_owned_route(destination, prefix, table, None)
            .map_err(|e| e.to_string())
    }
    fn owned(&mut self) -> std::result::Result<Vec<flowsdn_node::routes::RouteId>, String> {
        let mut out = Vec::new();
        for table in self.settings.tables() {
            for v6 in [false, true] {
                for route in self
                    .connector
                    .table_routes(table, v6)
                    .map_err(|e| format!("list table {table}: {e}"))?
                {
                    out.push((table, (route.destination, route.prefix), 0));
                }
            }
        }
        Ok(out)
    }
}

/// Each uplink's physical ports (a bridge's members, else itself) with
/// carrier, speed, FEC and byte counters.
pub fn port_stats(uplinks: &[Uplink], fec: &mut FecCache) -> BTreeMap<String, Vec<PortStats>> {
    let net = Path::new("/sys/class/net");
    let mut out = BTreeMap::new();
    for uplink in uplinks {
        let mut members: Vec<String> = fs::read_dir(net.join(&uplink.name).join("brif"))
            .or_else(|_| fs::read_dir(net.join(&uplink.name).join("lower_dev")))
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|name| net.join(name).join("device").exists())
                    .collect()
            })
            .unwrap_or_default();
        if members.is_empty() {
            members.push(uplink.name.clone());
        }
        members.sort();
        let stats = members
            .into_iter()
            .map(|name| {
                let read = |key: &str| fs::read_to_string(net.join(&name).join(key)).ok();
                let number = |key: &str| {
                    read(key)
                        .and_then(|v| v.trim().parse::<u64>().ok())
                        .unwrap_or(0)
                };
                let modes = match fec.get(&name) {
                    Some((modes, at)) if at.elapsed() < FEC_INTERVAL => *modes,
                    _ => {
                        let modes = multihome::fec(&name).ok().flatten();
                        fec.insert(name.clone(), (modes, Instant::now()));
                        modes
                    }
                };
                PortStats {
                    carrier: read("carrier").is_some_and(|c| c.trim() == "1"),
                    speed: read("speed")
                        .and_then(|s| s.trim().parse::<i64>().ok())
                        .and_then(|s| u32::try_from(s).ok())
                        .filter(|s| *s > 0),
                    fec_configured: modes
                        .map(|(c, _)| multihome::fec_names(c))
                        .unwrap_or_default(),
                    fec_active: modes
                        .map(|(_, a)| multihome::fec_names(a))
                        .unwrap_or_default(),
                    rx_bytes: number("statistics/rx_bytes"),
                    tx_bytes: number("statistics/tx_bytes"),
                    name,
                }
            })
            .collect();
        out.insert(uplink.name.clone(), stats);
    }
    out
}

pub fn load_moves(file: &Path) -> Result<Vec<Move>> {
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let value: Value = serde_json::from_slice(&bytes)?;
    let mut moves = Vec::new();
    for row in value.as_array().ok_or("uplink moves must be an array")? {
        let text = |key: &str| -> Result<String> {
            row.get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("uplink move without {key}").into())
        };
        let index = row
            .get("to-index")
            .and_then(Value::as_u64)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or("uplink move without to-index")?;
        moves.push(Move {
            address: text("address")?.parse()?,
            from: text("from")?,
            to: text("to")?,
            to_index: index,
            to_mac: parse_mac(&text("to-mac")?),
        });
    }
    Ok(moves)
}

pub fn save_moves(file: &Path, moves: &[Move]) -> Result<()> {
    let rows: Vec<_> = moves
        .iter()
        .map(|m| {
            json!({"address":m.address.to_string(),"from":m.from,"to":m.to,"to-index":m.to_index,
                "to-mac":m.to_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")})
        })
        .collect();
    let temporary = file.with_extension("json.tmp");
    let mut output = fs::File::create(&temporary)?;
    output.write_all(&serde_json::to_vec(&rows)?)?;
    output.sync_all()?;
    fs::rename(&temporary, file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_persist_and_sysctls_are_written() {
        let dir = std::env::temp_dir().join(format!("flowsdn-uplinks-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join(MOVES_FILE);
        assert!(load_moves(&file).expect("absent").is_empty());
        let moves = vec![Move {
            address: "192.168.16.204".parse().expect("ip"),
            from: "enp65s0f1np1".into(),
            to: "stormbr0".into(),
            to_index: 4,
            to_mac: [0xe8, 0xeb, 0xd3, 0x94, 0xa2, 0x80],
        }];
        save_moves(&file, &moves).expect("save");
        assert_eq!(load_moves(&file).expect("load"), moves);
        fs::write(&file, b"{}").expect("corrupt");
        assert!(load_moves(&file).is_err());
        for d in ["net/ipv4/conf/all", "net/ipv4/conf/stormbr0"] {
            fs::create_dir_all(dir.join(d)).expect("dir");
        }
        let failed = tune(&dir, "stormbr0", &["192.168.16.203".parse().expect("ip")]);
        assert!(failed.is_empty(), "{failed:?}");
        let read = |k: &str| fs::read_to_string(dir.join(k)).ok();
        assert_eq!(
            read("net/ipv4/fib_multipath_hash_policy").as_deref(),
            Some("1")
        );
        assert_eq!(
            read("net/ipv4/conf/stormbr0/arp_ignore").as_deref(),
            Some("1")
        );
        assert_eq!(
            read("net/ipv4/conf/stormbr0/arp_announce").as_deref(),
            Some("2")
        );
        assert_eq!(
            read("net/ipv4/conf/stormbr0/rp_filter").as_deref(),
            Some("0")
        );
        assert_eq!(
            read("net/ipv4/conf/all/ignore_routes_with_linkdown").as_deref(),
            Some("1")
        );
        assert_eq!(
            parse_mac("e8:eb:d3:94:a2:81\n"),
            [0xe8, 0xeb, 0xd3, 0x94, 0xa2, 0x81]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// #497 (finding 19c970eb0774): an uplink whose sysctls could not be
    /// written is not marked tuned, so the next tick writes them again and
    /// reports the failure until they succeed.
    #[test]
    fn failed_sysctl_writes_are_retried() {
        let dir = std::env::temp_dir().join(format!("flowsdn-tune-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("net/ipv4/conf/all")).expect("dir");
        let node: Vec<IpAddr> = vec!["192.168.16.203".parse().expect("ip")];
        let mut tuned = BTreeSet::new();
        // u1's conf directory is missing: its per-port writes fail.
        let failed = tune_pending(&dir, ["u1"], &node, &mut tuned);
        assert!(tuned.is_empty(), "a failed port is not tuned");
        assert!(
            failed
                .iter()
                .any(|f| f.starts_with("u1: net.ipv4.conf.u1.rp_filter=0")),
            "{failed:?}"
        );
        let again = tune_pending(&dir, ["u1"], &node, &mut tuned);
        assert!(!again.is_empty(), "still failing, still reported");
        assert!(tuned.is_empty());
        fs::create_dir_all(dir.join("net/ipv4/conf/u1")).expect("dir");
        let ok = tune_pending(&dir, ["u1"], &node, &mut tuned);
        assert!(ok.is_empty(), "{ok:?}");
        assert!(tuned.contains("u1"));
        assert_eq!(
            fs::read_to_string(dir.join("net/ipv4/conf/u1/rp_filter"))
                .ok()
                .as_deref(),
            Some("0")
        );
        // Tuned once: no further writes (the file is not rewritten).
        fs::write(dir.join("net/ipv4/conf/u1/rp_filter"), "1").expect("write");
        assert!(tune_pending(&dir, ["u1"], &node, &mut tuned).is_empty());
        assert_eq!(
            fs::read_to_string(dir.join("net/ipv4/conf/u1/rp_filter"))
                .ok()
                .as_deref(),
            Some("1")
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
