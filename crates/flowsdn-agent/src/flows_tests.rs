use super::*;
use crate::kubernetes::{NodeInfo, PodInfo, Workload};
use flowsdn_bpf_abi::{Be16, FAMILY_V4, FAMILY_V6};

fn v4(a: [u8; 4]) -> [u8; 16] {
    let mut bytes = [0; 16];
    if let Some(head) = bytes.get_mut(..4) {
        head.copy_from_slice(&a);
    }
    bytes
}

fn event(egress: bool, saddr: [u8; 4], daddr: [u8; 4], protocol: u8, kind: u8) -> PolicyEvent {
    PolicyEvent {
        time_ns: 1,
        endpoint: 7,
        remote: 2,
        ifindex: 9,
        saddr: v4(saddr),
        daddr: v4(daddr),
        sport: Be16::new(40000),
        dport: Be16::new(80),
        protocol,
        family: FAMILY_V4,
        egress: u8::from(egress),
        verdict: kind,
        reason: 0,
        pad: [0; 3],
    }
}

fn view() -> View {
    let mut view = View {
        local_node: "n1".into(),
        ..View::default()
    };
    view.nodes = vec![
        NodeInfo {
            name: "n1".into(),
            internal_ips: vec![
                "192.0.2.1"
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ],
            ..NodeInfo::default()
        },
        NodeInfo {
            name: "n2".into(),
            internal_ips: vec![
                "192.0.2.2"
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ],
            ..NodeInfo::default()
        },
    ];
    view.pods = vec![
        PodInfo {
            namespace: "shop".into(),
            name: "web-1".into(),
            node: "n1".into(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))],
            workload: Some(Workload {
                kind: "Deployment".into(),
                name: "web".into(),
            }),
            ..PodInfo::default()
        },
        PodInfo {
            namespace: "data".into(),
            name: "db-0".into(),
            node: "n2".into(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 9))],
            ..PodInfo::default()
        },
    ];
    view.pod_identities
        .insert(("shop".into(), "web-1".into()), 300);
    view
}

#[test]
fn records_name_both_sides_and_say_the_verdict() {
    let view = view();
    let time = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_795_000_000))
        .unwrap_or(UNIX_EPOCH);
    // A world client's TCP 80 to the local web Pod, allowed.
    let allowed = record(
        Some(&view),
        time,
        &event(false, [198, 51, 100, 9], [10, 1, 0, 5], 6, verdict::ALLOWED),
    );
    assert_eq!(
        allowed,
        json!({
            "time": "2026-11-18T11:06:40Z",
            "verdict": "FORWARDED",
            "traffic_direction": "INGRESS",
            "protocol": "TCP",
            "source": {"reserved": "world", "identity": 2, "ip": "198.51.100.9", "port": 40000},
            "destination": {"ID": 7, "identity": 300, "namespace": "shop", "pod_name": "web-1",
                "node_name": "n1", "labels": ["k8s:io.kubernetes.pod.namespace=shop"],
                "workloads": [{"name": "web", "kind": "Deployment"}],
                "ip": "10.1.0.5", "port": 80},
        })
    );
    // The web Pod's UDP to the remote db Pod, dropped: namespace on both sides.
    let mut dropped = event(true, [10, 1, 0, 5], [10, 2, 0, 9], 17, verdict::DENIED);
    dropped.remote = 400;
    dropped.reason = flowsdn_bpf_abi::policy::drop_reason::POLICY_DENIED;
    let dropped = record(Some(&view), time, &dropped);
    assert_eq!(dropped.get("verdict"), Some(&json!("DROPPED")));
    assert_eq!(dropped.get("drop_reason"), Some(&json!("POLICY_DENIED")));
    assert_eq!(dropped.get("traffic_direction"), Some(&json!("EGRESS")));
    assert_eq!(dropped.pointer("/source/namespace"), Some(&json!("shop")));
    assert_eq!(dropped.pointer("/source/ID"), Some(&json!(7)));
    assert_eq!(
        dropped.pointer("/destination/namespace"),
        Some(&json!("data"))
    );
    assert_eq!(
        dropped.pointer("/destination/pod_name"),
        Some(&json!("db-0"))
    );
    assert_eq!(dropped.pointer("/destination/identity"), Some(&json!(400)));
    assert_eq!(dropped.pointer("/destination/ID"), None);
    // Node addresses are host or remote-node; ICMP has no ports; audit.
    let mut icmp = event(false, [192, 0, 2, 2], [192, 0, 2, 1], 1, verdict::AUDIT);
    icmp.endpoint = HOST_ENDPOINT;
    icmp.remote = 6;
    let icmp = record(Some(&view), time, &icmp);
    assert_eq!(icmp.get("verdict"), Some(&json!("AUDIT")));
    assert_eq!(icmp.get("protocol"), Some(&json!("ICMPv4")));
    assert_eq!(
        icmp.get("source"),
        Some(&json!({"reserved": "remote-node", "node_name": "n2", "ip": "192.0.2.2"}))
    );
    assert_eq!(
        icmp.get("destination"),
        Some(&json!({"reserved": "host", "ip": "192.0.2.1"}))
    );
    // Without a Kubernetes view: the identity only.
    let mut v6 = event(false, [0; 4], [0; 4], 58, verdict::ALLOWED);
    v6.family = FAMILY_V6;
    v6.saddr = "2001:db8::9"
        .parse::<Ipv6Addr>()
        .map(|a| a.octets())
        .unwrap_or([0; 16]);
    v6.daddr = "fd00::7"
        .parse::<Ipv6Addr>()
        .map(|a| a.octets())
        .unwrap_or([0; 16]);
    v6.remote = 1234;
    let v6 = record(None, time, &v6);
    assert_eq!(v6.get("protocol"), Some(&json!("ICMPv6")));
    assert_eq!(
        v6.get("source"),
        Some(&json!({"identity": 1234, "ip": "2001:db8::9"}))
    );
    assert_eq!(v6.get("destination"), Some(&json!({"ip": "fd00::7"})));
}

#[test]
fn flows_are_newest_first_bounded_and_since() {
    let events = Events::default();
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_795_000_100))
        .unwrap_or(UNIX_EPOCH);
    // Stamped 100, 60 and 10 s before `now` (monotonic 100 s).
    let stamps = [0u64, 40, 90];
    let batch = stamps
        .iter()
        .map(|s| {
            let mut e = event(false, [198, 51, 100, 9], [10, 1, 0, 5], 6, verdict::ALLOWED);
            e.time_ns = s.saturating_mul(1_000_000_000);
            e.sport = Be16::new(u16::try_from(*s).unwrap_or(0));
            e
        })
        .collect();
    events.push(batch, now, 100_000_000_000);
    let all = json(&events, None, 10, None);
    assert_eq!(all.get("seen"), Some(&json!(3)));
    assert_eq!(all.get("kept"), Some(&json!(3)));
    let ports: Vec<_> = all
        .get("flows")
        .and_then(Value::as_array)
        .map(|flows| {
            flows
                .iter()
                .filter_map(|f| f.pointer("/source/port").cloned())
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(ports, vec![json!(90), json!(40), json!(0)]);
    let one = json(&events, None, 1, None);
    assert_eq!(
        one.get("flows").and_then(Value::as_array).map(Vec::len),
        Some(1)
    );
    // Since 2026-11-18T11:07:20Z (now - 60 s): the two newest.
    let since = parse_time("2026-11-18T11:07:20Z");
    let recent = json(&events, None, 10, since);
    assert_eq!(
        recent.get("flows").and_then(Value::as_array).map(Vec::len),
        Some(2)
    );
}

/// #552 (finding 8fb1b606e6dc): events kept out of time order (CPUs stamp
/// after reserving their ring entries) are all filtered by `since` and
/// returned newest first by time, not cut at the first older one.
#[test]
fn flows_since_does_not_stop_at_an_out_of_order_event() {
    let events = Events::default();
    let now = UNIX_EPOCH
        .checked_add(Duration::from_secs(1_795_000_100))
        .unwrap_or(UNIX_EPOCH);
    // Kept in this order, stamped 10, 100 (old) and 40 s before `now`.
    let stamps = [90u64, 0, 60];
    let batch = stamps
        .iter()
        .map(|s| {
            let mut e = event(false, [198, 51, 100, 9], [10, 1, 0, 5], 6, verdict::ALLOWED);
            e.time_ns = s.saturating_mul(1_000_000_000);
            e.sport = Be16::new(u16::try_from(*s).unwrap_or(0));
            e
        })
        .collect();
    events.push(batch, now, 100_000_000_000);
    let ports = |value: &Value| -> Vec<Value> {
        value
            .get("flows")
            .and_then(Value::as_array)
            .map(|flows| {
                flows
                    .iter()
                    .filter_map(|f| f.pointer("/source/port").cloned())
                    .collect()
            })
            .unwrap_or_default()
    };
    // Since now - 60 s: both recent ones, past the old one between them.
    let since = parse_time("2026-11-18T11:07:20Z");
    assert_eq!(
        ports(&json(&events, None, 10, since)),
        vec![json!(90), json!(60)]
    );
    // All, newest first by time; the limit takes the newest.
    assert_eq!(
        ports(&json(&events, None, 10, None)),
        vec![json!(90), json!(60), json!(0)]
    );
    assert_eq!(ports(&json(&events, None, 1, None)), vec![json!(90)]);
}

#[test]
fn rfc3339_times_parse() {
    let at = |s: u64, n: u32| UNIX_EPOCH.checked_add(Duration::new(s, n));
    assert_eq!(parse_time("1970-01-01T00:00:00Z"), at(0, 0));
    assert_eq!(parse_time("2026-11-18T11:06:40Z"), at(1_795_000_000, 0));
    assert_eq!(
        parse_time("2026-11-18T12:06:40.5+01:00"),
        at(1_795_000_000, 500_000_000)
    );
    assert_eq!(
        parse_time("2026-11-18t06:06:40-05:00"),
        at(1_795_000_000, 0)
    );
    assert_eq!(parse_time("2024-02-29T00:00:00Z"), at(1_709_164_800, 0));
    assert_eq!(parse_time("2000-02-29T00:00:00Z"), at(951_782_400, 0));
    assert_eq!(parse_time("2026-12-31T00:00:00Z"), at(1_798_675_200, 0));
    for bad in [
        "",
        "2026-11-18",
        "2026-11-18T07:06:40",
        "2026-13-01T00:00:00Z",
        "2026-11-18T25:00:00Z",
        "2026-11-18T07:06:40.Z",
        "2026-11-18T07:06:40+0100",
        "1969-12-31T23:59:59Z",
        "2026-11-18T07:06:4xZ",
        // #552 (finding 3c7298844c45): days the month does not have.
        "2026-02-29T00:00:00Z",
        "2026-02-30T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "2026-11-31T00:00:00Z",
        "2026-11-00T00:00:00Z",
    ] {
        assert_eq!(parse_time(bad), None, "{bad}");
    }
}
