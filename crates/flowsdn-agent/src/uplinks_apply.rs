//! Applying the uplink plan to the kernel (#408): read the ports, write the
//! sysctls balancing needs, keep flowsdn's rules and tables, read each port's
//! counters and FEC, and keep the failover addresses on disk. The monitor
//! thread (Kubernetes mode) and the `uplinks-live` kernel fixture both use
//! these, so the fixture checks the agent's own code on a real kernel.
use super::{Desired, Move, Port, PortStats, Settings, TableEntry, Uplink};
use crate::kubernetes::{Cidr, cidr_text};
use crate::state::Result;
use flowsdn_connector::{
    Connector,
    multihome::{self, Rule},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
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

/// Make flowsdn's rules and tables what `desired` says: rules in its priority
/// span and routes in its tables that are not wanted go; every wanted one is
/// (re)written. Nothing outside the span and the tables is touched.
pub fn reconcile_kernel(
    connector: &Connector,
    settings: &Settings,
    desired: &Desired,
) -> std::result::Result<(), String> {
    let mut failures = Vec::new();
    for v6 in [false, true] {
        let present: Vec<Rule> = match connector.rules(v6) {
            Ok(rules) => rules
                .into_iter()
                .filter(|r| settings.owns_priority(r.priority))
                .collect(),
            Err(error) => {
                failures.push(format!("list rules: {error}"));
                continue;
            }
        };
        for rule in present.iter().filter(|r| !desired.rules.contains(*r)) {
            if let Err(error) = connector.delete_rule(rule) {
                failures.push(format!("delete rule {}: {error}", rule.priority));
            }
        }
        for rule in desired
            .rules
            .iter()
            .filter(|r| r.v6 == v6 && !present.contains(*r))
        {
            if let Err(error) = connector.add_rule(rule) {
                failures.push(format!("add rule {}: {error}", rule.priority));
            }
        }
        for table in settings.tables() {
            let wanted: Vec<&TableEntry> = desired
                .tables
                .get(&table)
                .map(|entries| {
                    entries
                        .iter()
                        .filter(|e| e.destination.0.is_ipv6() == v6)
                        .collect()
                })
                .unwrap_or_default();
            let routes = match connector.table_routes(table, v6) {
                Ok(routes) => routes,
                Err(error) => {
                    failures.push(format!("list table {table}: {error}"));
                    continue;
                }
            };
            for route in routes.iter().filter(|r| {
                !wanted
                    .iter()
                    .any(|e| e.destination == (r.destination, r.prefix))
            }) {
                if let Err(error) =
                    connector.delete_owned_route(route.destination, route.prefix, table, None)
                {
                    failures.push(format!(
                        "delete {} from table {table}: {error}",
                        cidr_text(route.destination, route.prefix)
                    ));
                }
            }
            for entry in wanted {
                let (destination, prefix) = entry.destination;
                if let Err(error) = connector.replace_multipath_route(
                    destination,
                    prefix,
                    &entry.hops,
                    table,
                    None,
                    entry.source,
                ) {
                    failures.push(format!(
                        "table {table} {}: {error}",
                        cidr_text(destination, prefix)
                    ));
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Each uplink's physical ports (a bridge's members, else itself) with
/// carrier, speed, FEC and byte counters.
pub fn port_stats(
    uplinks: &[Uplink],
    fec: &mut FecCache,
) -> BTreeMap<String, Vec<PortStats>> {
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
}
