use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}
fn port(name: &str, index: u32, carrier: bool, addresses: &[(&str, u8)]) -> Port {
    Port {
        name: name.into(),
        index,
        mac: [2, 0, 0, 0, 0, u8::try_from(index).expect("small")],
        carrier,
        addresses: addresses.iter().map(|(a, p)| (ip(a), *p)).collect(),
    }
}
/// forge1 (#408): the boot port bridged as stormbr0 (.203) and the second
/// 25G port with its own lease (.204), both on g16; plus a pod veth and lo.
fn forge1(bridge_up: bool, second_up: bool) -> Vec<Port> {
    vec![
        port("lo", 1, true, &[("127.0.0.1", 8)]),
        port(
            "stormbr0",
            4,
            bridge_up,
            &[("192.168.16.203", 20), ("fe80::1", 64)],
        ),
        port("enp65s0f1np1", 3, second_up, &[("192.168.16.204", 20)]),
        port("lxc1234", 9, true, &[("10.203.0.1", 32)]),
        port("storage0", 5, true, &[("172.16.0.9", 24)]),
    ]
}
const NODE: &[&str] = &["192.168.16.203"];
fn node() -> Vec<IpAddr> {
    NODE.iter().map(|a| ip(a)).collect()
}

#[test]
fn uplinks_are_the_ports_on_a_node_address_subnet_found_not_configured() {
    let uplinks = select(&forge1(true, true), &node(), &Settings::default());
    let names: Vec<_> = uplinks.iter().map(|u| u.name.as_str()).collect();
    // The primary (.203) first; the storage VLAN and pod devices are not uplinks.
    assert_eq!(names, ["stormbr0", "enp65s0f1np1"]);
    assert!(uplinks.first().is_some_and(|u| u.primary));
    // Only global addresses are kept.
    assert_eq!(
        uplinks.first().map(|u| u.addresses.clone()),
        Some(vec![(ip("192.168.16.203"), 20)])
    );
    // A weight reorders them.
    let mut settings = Settings::default();
    settings.weights.insert("enp65s0f1np1".into(), 3);
    let uplinks = select(&forge1(true, true), &node(), &settings);
    assert_eq!(uplinks.first().map(|u| u.weight), Some(3));
    assert_eq!(
        uplinks.first().map(|u| u.name.as_str()),
        Some("enp65s0f1np1")
    );
}

#[test]
fn a_single_nic_node_is_not_balanced_and_changes_nothing() {
    let ports = vec![port("eth0", 2, true, &[("192.168.31.172", 20)])];
    let uplinks = select(&ports, &[ip("192.168.31.172")], &Settings::default());
    assert_eq!(uplinks.len(), 1);
    assert!(!balancing(&uplinks, Mode::ActiveActive));
    assert!(carriers(&uplinks, Mode::ActiveActive).is_empty());
    assert!(moves(&uplinks, Mode::ActiveActive).is_empty());
    let plan = desired(&uplinks, &[], &Settings::default(), &[ip("192.168.16.1")]);
    assert_eq!(plan, Desired::default());
}

#[test]
fn both_up_carry_traffic_one_down_moves_its_address_and_it_comes_back() {
    let settings = Settings::default();
    // Both up: both carry, nothing moved.
    let both = select(&forge1(true, true), &node(), &settings);
    assert_eq!(carriers(&both, settings.mode).len(), 2);
    assert!(moves(&both, settings.mode).is_empty());
    // The second port goes down: one carries, .204 is held by stormbr0.
    let one = select(&forge1(true, false), &node(), &settings);
    let live: Vec<_> = carriers(&one, settings.mode)
        .iter()
        .map(|u| u.name.clone())
        .collect();
    assert_eq!(live, ["stormbr0"]);
    let moved = moves(&one, settings.mode);
    assert_eq!(
        moved,
        [Move {
            address: ip("192.168.16.204"),
            from: "enp65s0f1np1".into(),
            to: "stormbr0".into(),
            to_index: 4,
            to_mac: [2, 0, 0, 0, 0, 4],
        }]
    );
    assert_eq!(moved.first().map(Move::prefix), Some(32));
    // The bridge goes down instead: .203 moves to the second port.
    let other = select(&forge1(false, true), &node(), &settings);
    let moved = moves(&other, settings.mode);
    assert_eq!(moved.len(), 1);
    assert_eq!(moved.first().map(|m| m.to.as_str()), Some("enp65s0f1np1"));
    // Both down: nowhere to move to.
    let none = select(&forge1(false, false), &node(), &settings);
    assert!(moves(&none, settings.mode).is_empty());
    assert!(carriers(&none, settings.mode).is_empty());
    // Every move goes both ways, any number of times.
    for _ in 0..3 {
        let down = select(&forge1(true, false), &node(), &settings);
        let up = select(&forge1(true, true), &node(), &settings);
        let left = changes(&up, &down, "t");
        assert_eq!(left.len(), 1);
        assert!(
            left.first()
                .is_some_and(|c| !c.joined && c.port == "enp65s0f1np1")
        );
        assert!(
            left.first()
                .is_some_and(|c| c.message.contains("1 of 2 carrying"))
        );
        let back = changes(&down, &up, "t");
        assert!(
            back.first()
                .is_some_and(|c| c.joined && c.port == "enp65s0f1np1")
        );
        assert!(changes(&up, &up, "t").is_empty());
    }
}

#[test]
fn routes_pair_each_remote_address_with_a_local_port() {
    let settings = Settings::default();
    let both = select(&forge1(true, true), &node(), &settings);
    let live = carriers(&both, settings.mode);
    // Today a peer publishes one InternalIP: both local ports send to it.
    let one = nexthops(&[ip("192.168.16.21")], &live);
    assert_eq!(
        one.iter().map(|h| (h.gateway, h.index)).collect::<Vec<_>>(),
        [
            (Some(ip("192.168.16.21")), 4),
            (Some(ip("192.168.16.21")), 3)
        ]
    );
    // A peer with both addresses (rustkube-node#366): port k to address k.
    let two = nexthops(&[ip("192.168.16.21"), ip("192.168.16.22")], &live);
    assert_eq!(
        two.iter().map(|h| (h.gateway, h.index)).collect::<Vec<_>>(),
        [
            (Some(ip("192.168.16.21")), 4),
            (Some(ip("192.168.16.22")), 3)
        ]
    );
    // One port down: everything leaves through the other.
    let down = select(&forge1(true, false), &node(), &settings);
    let live = carriers(&down, settings.mode);
    let hops = nexthops(&[ip("192.168.16.21"), ip("192.168.16.22")], &live);
    assert_eq!(
        hops.iter().map(|h| h.index).collect::<Vec<_>>(),
        [4, 4],
        "both remote addresses through the live port"
    );
    // A gateway on no uplink's subnet gets no path (the plain route stays).
    assert!(nexthops(&[ip("10.0.0.1")], &live).is_empty());
    // Active-backup carries on the preferred port only.
    let backup = carriers(&both, Mode::ActiveBackup);
    assert_eq!(backup.len(), 1);
    assert_eq!(backup.first().map(|u| u.name.as_str()), Some("stormbr0"));
}

#[test]
fn each_address_is_pinned_to_the_port_that_holds_it() {
    let settings = Settings::default();
    let gateway = ip("192.168.16.1");
    let both = select(&forge1(true, true), &node(), &settings);
    let plan = desired(&both, &[], &settings, &[gateway]);
    let priorities: Vec<_> = plan.rules.iter().map(|r| (r.priority, r.table)).collect();
    // .203 then .204 pinned (to its subnet, then anywhere), main without its
    // default between them, the ECMP default after.
    assert_eq!(
        {
            let mut p = priorities.clone();
            p.sort_unstable();
            p
        },
        [
            (9110, 2081),
            (9111, 2082),
            (9150, 254),
            (9200, 2081),
            (9201, 2082),
            (9300, 2080)
        ]
    );
    let table = |t: u32| plan.tables.get(&t).cloned().unwrap_or_default();
    let devices = |t: u32| {
        table(t)
            .iter()
            .flat_map(|e| e.hops.iter().map(|h| h.index))
            .collect::<Vec<_>>()
    };
    assert_eq!(devices(2081), [4, 4]);
    assert_eq!(devices(2082), [3, 3]);
    assert_eq!(devices(2080), [4, 3], "the default spreads over both ports");
    assert_eq!(
        table(2082).first().map(|e| (e.destination, e.source)),
        Some(((ip("192.168.16.0"), 20), Some(ip("192.168.16.204"))))
    );
    // The second port down: .204's table follows its address to stormbr0.
    let down = select(&forge1(true, false), &node(), &settings);
    let moved = moves(&down, settings.mode);
    let plan = desired(&down, &moved, &settings, &[gateway]);
    let table = |t: u32| plan.tables.get(&t).cloned().unwrap_or_default();
    assert_eq!(
        table(2082)
            .iter()
            .flat_map(|e| e.hops.iter().map(|h| h.index))
            .collect::<Vec<_>>(),
        [4, 4]
    );
    assert_eq!(
        table(2080)
            .iter()
            .flat_map(|e| e.hops.iter().map(|h| h.index))
            .collect::<Vec<_>>(),
        [4]
    );
    // single turns it all off.
    let single = Settings {
        mode: Mode::Single,
        ..Settings::default()
    };
    assert_eq!(desired(&both, &[], &single, &[gateway]), Desired::default());
}

#[test]
fn settings_parse_and_refuse() {
    assert_eq!(Settings::parse(None).expect("default"), Settings::default());
    let parsed = Settings::parse(Some(&serde_json::json!({
        "mode": "active-backup",
        "weights": {"enp65s0f1np1": 2},
        "table": 3000,
        "rule-priority": 8000
    })))
    .expect("parse");
    assert_eq!(parsed.mode, Mode::ActiveBackup);
    assert_eq!(parsed.weights.get("enp65s0f1np1"), Some(&2));
    assert_eq!((parsed.table, parsed.priority), (3000, 8000));
    assert!(parsed.owns_priority(8299) && !parsed.owns_priority(8300));
    assert_eq!(parsed.tables(), 3000..=3032);
    for bad in [
        serde_json::json!({"mode": "lacp"}),
        serde_json::json!({"weights": {"eth0": 0}}),
        serde_json::json!({"table": 254}),
        serde_json::json!({"table": 240}),
        serde_json::json!({"rule-priority": 32000}),
        serde_json::json!({"ports": ["eth0"]}),
        serde_json::json!("eth0"),
    ] {
        assert!(Settings::parse(Some(&bad)).is_err(), "{bad}");
    }
}

#[test]
fn the_view_reports_ports_failover_and_history() {
    let mut view = View {
        started: true,
        uplinks: select(&forge1(true, false), &node(), &Settings::default()),
        ..View::default()
    };
    view.moves = moves(&view.uplinks, view.mode);
    view.ports.insert(
        "enp65s0f1np1".into(),
        vec![PortStats {
            name: "enp65s0f1np1".into(),
            carrier: false,
            speed: None,
            fec_configured: vec!["rs"],
            fec_active: vec![],
            rx_bytes: 7,
            tx_bytes: 9,
        }],
    );
    for n in 0..HISTORY.saturating_add(3) {
        view.record(Change {
            at: format!("t{n}"),
            port: "enp65s0f1np1".into(),
            joined: n.is_multiple_of(2),
            message: String::new(),
        });
    }
    assert_eq!(view.history.len(), HISTORY);
    let json = view.json();
    assert_eq!(
        json.pointer("/carrying"),
        Some(&serde_json::json!(["stormbr0"]))
    );
    assert_eq!(
        json.pointer("/failover/0/address"),
        Some(&serde_json::json!("192.168.16.204"))
    );
    assert_eq!(
        json.pointer("/failover/0/on"),
        Some(&serde_json::json!("stormbr0"))
    );
    assert_eq!(
        json.pointer("/uplinks/1/ports/0/fec/configured/0"),
        Some(&serde_json::json!("rs"))
    );
    assert_eq!(
        json.pointer("/uplinks/1/ports/0/tx-bytes"),
        Some(&serde_json::json!(9))
    );
    assert_eq!(
        json.pointer("/history/0/at"),
        Some(&serde_json::json!("t3"))
    );
    assert!(
        view.summary()
            .contains("1 of 2 uplinks carrying (stormbr0)")
    );
    assert!(view.summary().contains("1 address(es) failed over"));
    assert_eq!(
        view.hops(&[ip("192.168.16.21")])
            .map(|h| h.iter().map(|h| h.index).collect::<Vec<_>>()),
        Some(vec![4])
    );
}
