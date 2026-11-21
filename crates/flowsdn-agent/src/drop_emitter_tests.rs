use super::*;
use crate::kubernetes::{LocalEndpoint, PodInfo};
use flowsdn_bpf_abi::{Be16, FAMILY_V4, policy::drop_reason};

fn v4(a: [u8; 4]) -> [u8; 16] {
    let mut bytes = [0; 16];
    if let Some(head) = bytes.get_mut(..4) {
        head.copy_from_slice(&a);
    }
    bytes
}

/// A decision of endpoint 7 (shop/web-1, 10.1.0.5): ingress from `peer`, or
/// egress to it, protocol and destination port.
fn event(egress: bool, peer: [u8; 4], protocol: u8, dport: u16, reason: u8) -> PolicyEvent {
    let (saddr, daddr) = if egress {
        ([10, 1, 0, 5], peer)
    } else {
        (peer, [10, 1, 0, 5])
    };
    PolicyEvent {
        time_ns: 1,
        endpoint: 7,
        remote: 2,
        ifindex: 9,
        saddr: v4(saddr),
        daddr: v4(daddr),
        sport: Be16::new(40000),
        dport: Be16::new(dport),
        protocol,
        family: FAMILY_V4,
        egress: u8::from(egress),
        verdict: verdict::DENIED,
        reason,
        pad: [0; 3],
    }
}

fn view() -> View {
    let mut view = View {
        local_node: "n1".into(),
        ..View::default()
    };
    view.endpoints = vec![LocalEndpoint {
        id: 7,
        namespace: "shop".into(),
        name: "web-1".into(),
        uid: "uid-web".into(),
        ..LocalEndpoint::default()
    }];
    view.pods = vec![
        PodInfo {
            namespace: "shop".into(),
            name: "web-1".into(),
            uid: "uid-web".into(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 5))],
            ..PodInfo::default()
        },
        PodInfo {
            namespace: "shop".into(),
            name: "client".into(),
            ips: vec![IpAddr::V4(Ipv4Addr::new(10, 1, 0, 9))],
            ..PodInfo::default()
        },
    ];
    view
}

fn settings(extended: bool) -> DropEvents {
    DropEvents {
        interval: Duration::from_secs(120),
        reasons: vec![drop_reason::AUTH_REQUIRED, drop_reason::POLICY_DENIED],
        extended,
        rate_limit: 1,
    }
}

fn messages(drops: &[Drop]) -> Vec<&str> {
    drops.iter().map(|d| d.message.as_str()).collect()
}

/// A policy-denied flow is one `PacketDrop` Event on its Pod, in the
/// reference's words; its repeats within the interval, and a second Event
/// in the same second, are not written.
#[test]
fn a_policy_denied_flow_is_one_rate_limited_event() {
    let view = view();
    let mut emitter = Emitter::new(settings(false)).unwrap_or_else(|e| panic!("{e}"));
    let denied = event(false, [10, 1, 0, 9], 6, 80, drop_reason::POLICY_DENIED);
    let at = Duration::from_secs(100);
    let first = emitter.process(at, &[denied, denied], &view);
    assert_eq!(
        first,
        vec![Drop {
            namespace: "shop".into(),
            name: "web-1".into(),
            uid: "uid-web".into(),
            message: "Incoming packet dropped (policy_denied) from shop/client (10.1.0.9) TCP/80."
                .into(),
        }]
    );
    // The same drop again within the interval: deduplicated.
    assert!(emitter.process(at.saturating_add(Duration::from_secs(5)), &[denied], &view).is_empty());
    // An egress drop to the world in the same second as another: the
    // one-a-second limit holds the second back; a second later it goes.
    let mut egress = event(true, [198, 51, 100, 9], 17, 53, drop_reason::POLICY_DENIED);
    egress.remote = 2;
    let other = event(false, [10, 1, 0, 9], 6, 81, drop_reason::POLICY_DENIED);
    let now = at.saturating_add(Duration::from_secs(10));
    assert_eq!(
        messages(&emitter.process(now, &[egress, other], &view)),
        vec!["Outgoing packet dropped (policy_denied) to world (198.51.100.9) UDP/53."]
    );
    assert_eq!(
        messages(&emitter.process(now.saturating_add(Duration::from_secs(1)), &[other], &view)),
        vec!["Incoming packet dropped (policy_denied) from shop/client (10.1.0.9) TCP/81."]
    );
    // After the interval the first drop is written again.
    assert_eq!(
        emitter
            .process(at.saturating_add(Duration::from_secs(121)), &[denied], &view)
            .len(),
        1
    );
}

/// Only listed reasons of dropped Pod traffic: not a deny-rule drop by
/// default, not an audit pass, an allowed flow, the host firewall's drops or
/// an endpoint the view does not know.
#[test]
fn only_listed_drops_of_known_pods() {
    let view = view();
    let mut emitter = Emitter::new(settings(false)).unwrap_or_else(|e| panic!("{e}"));
    let deny_rule = event(false, [10, 1, 0, 9], 6, 22, drop_reason::POLICY_DENY);
    let mut audit = event(false, [10, 1, 0, 9], 6, 23, drop_reason::POLICY_DENIED);
    audit.verdict = verdict::AUDIT;
    let mut allowed = event(false, [10, 1, 0, 9], 6, 24, 0);
    allowed.verdict = verdict::ALLOWED;
    let mut host = event(false, [10, 1, 0, 9], 6, 25, drop_reason::POLICY_DENIED);
    host.endpoint = HOST_ENDPOINT;
    let mut unknown = event(false, [10, 1, 0, 9], 6, 26, drop_reason::POLICY_DENIED);
    unknown.endpoint = 8;
    let unjudged = event(false, [10, 1, 0, 9], 6, 27, 0);
    let mut at = Duration::from_secs(1);
    for (what, event) in [
        ("deny rule", deny_rule),
        ("audit", audit),
        ("allowed", allowed),
        ("host", host),
        ("unknown endpoint", unknown),
        ("not judged", unjudged),
    ] {
        at = at.saturating_add(Duration::from_secs(2));
        assert!(emitter.process(at, &[event], &view).is_empty(), "{what}");
    }
    // Listed, a deny-rule drop and an auth-required one are written.
    let mut emitter = Emitter::new(DropEvents {
        reasons: vec![drop_reason::POLICY_DENY, drop_reason::AUTH_REQUIRED],
        ..settings(false)
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let mut world = event(false, [198, 51, 100, 9], 1, 0, drop_reason::AUTH_REQUIRED);
    world.remote = 9;
    assert_eq!(
        messages(&emitter.process(at, &[deny_rule], &view)),
        vec!["Incoming packet dropped (policy_deny) from shop/client (10.1.0.9) TCP/22."]
    );
    assert_eq!(
        messages(&emitter.process(at.saturating_add(Duration::from_secs(2)), &[world], &view)),
        vec!["Incoming packet dropped (auth_required) from world-ipv4 (198.51.100.9) ICMPv4."]
    );
}

/// `-extended`: the policies applied to the Pod in the drop's direction.
#[test]
fn extended_names_the_applied_policies() {
    let mut view = view();
    view.applied_policies.insert(
        (7, true),
        [
            (false, "NetworkPolicy/allow-web".to_owned()),
            (false, "FlowsdnNetworkPolicy/fp".to_owned()),
            (true, "FlowsdnClusterwideNetworkPolicy/base".to_owned()),
        ]
        .into_iter()
        .collect(),
    );
    let mut emitter = Emitter::new(settings(true)).unwrap_or_else(|e| panic!("{e}"));
    let denied = event(false, [8, 8, 8, 8], 6, 80, drop_reason::POLICY_DENIED);
    assert_eq!(
        messages(&emitter.process(Duration::from_secs(1), &[denied], &view)),
        vec![
            "Incoming packet dropped (policy_denied) from world (8.8.8.8) TCP/80. Applied policies: FlowsdnNetworkPolicy/fp,NetworkPolicy/allow-web. Applied clusterwide policies: FlowsdnClusterwideNetworkPolicy/base."
        ]
    );
    // No policy recorded for egress: the plain message.
    let egress = event(true, [8, 8, 8, 8], 6, 443, drop_reason::POLICY_DENIED);
    assert_eq!(
        messages(&emitter.process(Duration::from_secs(3), &[egress], &view)),
        vec!["Outgoing packet dropped (policy_denied) to world (8.8.8.8) TCP/443."]
    );
}
