use super::*;
use crate::kubernetes::NodeInfo;
use crate::uplinks::Uplink;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("ip")
}
fn node(name: &str, ips: &[&str]) -> NodeInfo {
    NodeInfo {
        name: name.into(),
        internal_ips: ips.iter().map(|i| ip(i)).collect(),
        ..NodeInfo::default()
    }
}
fn uplink(name: &str, index: u32, mac: [u8; 6]) -> Uplink {
    Uplink {
        name: name.into(),
        index,
        mac,
        ..Uplink::default()
    }
}
fn after(at: Instant, seconds: u64) -> Instant {
    at.checked_add(Duration::from_secs(seconds)).expect("time")
}

#[test]
fn forwardable_ips_are_other_nodes_and_devices_are_uplinks_with_a_mac() {
    let mut view = View {
        local_node: "n1".into(),
        nodes: vec![
            node("n1", &["192.0.2.1"]),
            node("n2", &["192.0.2.2", "2001:db8::2"]),
            node("n3", &["198.51.100.3"]),
        ],
        ..View::default()
    };
    view.uplinks.uplinks = vec![
        uplink("eth0", 2, [2, 0, 0, 0, 0, 1]),
        uplink("wg0", 3, [0; 6]),
        uplink("eth1", 4, [2, 0, 0, 0, 0, 2]),
    ];
    let got = inputs(&view);
    assert_eq!(
        got.forwardable,
        [ip("192.0.2.2"), ip("2001:db8::2"), ip("198.51.100.3")]
            .into_iter()
            .collect()
    );
    assert_eq!(
        got.devices,
        BTreeMap::from([(2, "eth0".to_owned()), (4, "eth1".to_owned())])
    );
}

#[test]
fn the_calculator_resyncs_first_then_rate_limits_changes_and_resyncs_every_five_minutes() {
    let start = Instant::now();
    let a = Inputs {
        forwardable: [ip("192.0.2.2")].into_iter().collect(),
        devices: BTreeMap::from([(2, "eth0".to_owned())]),
    };
    let mut b = a.clone();
    b.forwardable.insert(ip("192.0.2.3"));
    let mut calc = Calculator::default();
    assert_eq!(calc.due(start, &a), Some(true), "start: resync");
    calc.done(start, a.clone(), true);
    assert_eq!(calc.due(after(start, 1), &a), None, "nothing changed");
    assert_eq!(
        calc.due(after(start, 5), &b),
        None,
        "changed, but within 15 s"
    );
    assert_eq!(
        calc.due(after(start, 15), &b),
        Some(false),
        "changed, 15 s on"
    );
    calc.done(after(start, 15), b.clone(), false);
    assert_eq!(calc.due(after(start, 20), &b), None);
    assert_eq!(calc.due(after(start, 299), &b), None);
    assert_eq!(calc.due(after(start, 300), &b), Some(true), "5 min: resync");
}

#[test]
fn only_learned_entries_on_selected_devices_that_are_not_desired_are_stale() {
    let devices = BTreeMap::from([(2, "eth0".to_owned())]);
    let desired: BTreeSet<(u32, IpAddr)> = [(2, ip("192.0.2.9"))].into_iter().collect();
    let learned = vec![
        (2, ip("192.0.2.9")),
        (2, ip("192.0.2.77")),
        (7, ip("10.0.0.1")),
    ];
    assert_eq!(
        stale(&desired, &learned, &devices),
        vec![(2, ip("192.0.2.77"))]
    );
}

#[test]
fn status_reports_the_reconcile() {
    let inputs = Inputs {
        forwardable: [ip("192.0.2.2")].into_iter().collect(),
        devices: BTreeMap::from([(2, "eth0".to_owned())]),
    };
    let outcome = Outcome {
        desired: [(2, ip("192.0.2.9"))].into_iter().collect(),
        removed: vec![(2, ip("192.0.2.77"))],
        unreachable: 1,
        errors: Vec::new(),
    };
    let got = status(&inputs, &outcome, true, 1);
    assert_eq!(
        got,
        json!({"enabled": true, "devices": ["eth0"], "forwardable": 1, "desired": 1,
               "unreachable": 1, "pruned": 1, "last": "resync", "errors": []})
    );
}
