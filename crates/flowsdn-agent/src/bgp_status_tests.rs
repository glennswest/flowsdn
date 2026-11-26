use super::*;
use flowsdn_k8s::kinds::FlowsdnBGPNodeConfig;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn peer(name: &str, address: Option<&str>, configured: u32, learned: Option<u32>) -> PeerState {
    PeerState {
        name: name.into(),
        address: address.map(str::to_owned),
        configured_asn: configured,
        session_asn: learned,
        ..PeerState::default()
    }
}

#[test]
fn peers_report_state_timers_counts_and_established_time() {
    let mut up = peer("tor-a", Some("10.0.0.1"), 0, Some(65000));
    up.state = SessionState::Established;
    up.uptime = Some(Duration::from_secs(60));
    up.applied_hold = Some(9);
    up.applied_keepalive = Some(3);
    up.families = vec![FamilyCount {
        afi: "ipv4".into(),
        safi: "unicast".into(),
        received: 1,
        advertised: u32::MAX,
    }];
    let mut connecting = peer("tor-b", Some("10.0.0.2"), 65000, None);
    connecting.state = SessionState::OpenSent;
    connecting.uptime = Some(Duration::from_secs(5));
    let instances = vec![
        InstanceState {
            name: "z".into(),
            local_asn: None,
            peers: vec![],
        },
        InstanceState {
            name: "i65001".into(),
            local_asn: Some(65001),
            peers: vec![
                connecting,
                up,
                // No address yet, and no ASN learned: both left out.
                peer("gw", None, 65000, None),
                peer("learning", Some("10.0.0.3"), 0, None),
            ],
        },
    ];
    let status = instances_status(&instances, at(1_791_302_693));
    assert_eq!(
        serde_json::to_value(&status).expect("serialize"),
        json!([
            {"name": "i65001", "localASN": 65001, "peers": [
                {"name": "tor-a", "peerAddress": "10.0.0.1", "peerASN": 65000,
                 "peeringState": "established", "establishedTime": "2026-10-06T16:03:53Z",
                 "timers": {"appliedHoldTimeSeconds": 9, "appliedKeepaliveSeconds": 3},
                 "routeCount": [{"afi": "ipv4", "safi": "unicast", "received": 1, "advertised": i32::MAX}]},
                {"name": "tor-b", "peerAddress": "10.0.0.2", "peerASN": 65000, "peeringState": "open_sent"}
            ]},
            {"name": "z"}
        ])
    );
    let states: Vec<&str> = [
        SessionState::Unknown,
        SessionState::Idle,
        SessionState::Connect,
        SessionState::Active,
        SessionState::OpenSent,
        SessionState::OpenConfirm,
        SessionState::Established,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(
        states,
        ["unknown", "idle", "connect", "active", "open_sent", "open_confirm", "established"]
    );
}

#[test]
fn the_written_status_is_admitted_by_the_schema() {
    let mut up = peer("tor-a", Some("10.0.0.1"), 65000, None);
    up.state = SessionState::Established;
    up.uptime = Some(Duration::from_secs(1));
    let mut errors = ReconcileErrors::default();
    errors.set("i65001", vec!["peer tor-a: no route".into()]);
    let status = desired_status(
        &[InstanceState {
            name: "i65001".into(),
            local_asn: Some(65001),
            peers: vec![up],
        }],
        &errors,
        None,
        Some(4),
        at(1_791_302_693),
    );
    let mut object = FlowsdnBGPNodeConfig::named("w1");
    object.spec.bgp_instances = vec![flowsdn_k8s::kinds::BgpNodeInstance {
        name: "i65001".into(),
        ..Default::default()
    }];
    object.status = Some(status);
    let schema = flowsdn_k8s::crd::owned_crds()
        .expect("CRDs")
        .into_iter()
        .find(|c| c.document.pointer("/spec/names/plural") == Some(&json!("flowsdnbgpnodeconfigs")))
        .and_then(|c| c.document.pointer("/spec/versions/0/schema/openAPIV3Schema").cloned())
        .expect("schema");
    let value = serde_json::to_value(&object).expect("serialize");
    let problems = flowsdn_k8s::schema::validate(&schema, &value);
    assert!(problems.is_empty(), "{problems:?}\n{value:#}");
}

#[test]
fn reconcile_errors_are_capped_sorted_and_truncated() {
    let mut errors = ReconcileErrors::default();
    let none = desired_status(&[], &errors, None, None, at(0));
    let condition = &none.conditions.as_ref().expect("conditions")[0];
    assert_eq!(
        (condition.status.as_str(), condition.reason.as_str(), condition.message.as_str()),
        ("False", "ReconcileSucceeded", "")
    );
    assert_eq!(none.bgp_instances, None);

    assert!(errors.set("b", (0..8).map(|i| format!("e{i}")).collect()));
    assert!(errors.set("a", vec!["first".into()]));
    assert!(!errors.set("a", vec!["first".into()]), "unchanged");
    let failed = desired_status(&[], &errors, Some(&none), Some(3), at(100));
    let condition = &failed.conditions.as_ref().expect("conditions")[0];
    assert_eq!(condition.status, "True");
    assert_eq!(condition.reason, "ReconcileFailed");
    assert_eq!(condition.message, "a: first\nb: e0\nb: e1\nb: e2\nb: e3\nb: e4\n");
    assert_eq!(condition.last_transition_time, "1970-01-01T00:01:40Z");
    assert_eq!(condition.observed_generation, Some(3));

    // Unchanged status keeps its time; a foreign condition stays.
    let mut existing = failed.clone();
    if let Some(list) = existing.conditions.as_mut() {
        list.push(Condition {
            last_transition_time: "1970-01-01T00:00:00Z".into(),
            message: String::new(),
            observed_generation: None,
            reason: "Other".into(),
            status: "True".into(),
            type_: "example.com/Other".into(),
        });
    }
    let later = desired_status(&[], &errors, Some(&existing), Some(3), at(500));
    let list = later.conditions.expect("conditions");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].type_, "example.com/Other");
    assert_eq!(list[1].last_transition_time, "1970-01-01T00:01:40Z");

    // 32 KiB at most, cut on a character boundary.
    let mut big = ReconcileErrors::default();
    for i in 0..20 {
        big.set(&format!("instance-{i:02}"), vec!["é".repeat(2000); 5]);
    }
    let (_, _, message) = big.summary();
    assert!(message.len() <= MAX_MESSAGE && message.len() > MAX_MESSAGE - 8);
    assert!(message.starts_with("instance-00: é"));
    assert!(errors.remove("a") && !errors.remove("a"));
}

#[test]
fn the_flusher_writes_on_change_at_the_tick_and_backs_off() {
    let start = Instant::now();
    let mut flusher = Flusher::new(start, 7);
    let one = FlowsdnBGPNodeConfigStatus::default();
    let mut two = FlowsdnBGPNodeConfigStatus::default();
    two.bgp_instances = Some(vec![]);
    assert!(flusher.due(start, &one), "the first write is due at once");
    assert!(!flusher.record(start, &one, Outcome::Written));
    let next = flusher.next().duration_since(start);
    assert!(next >= TICK - TICK_JITTER && next <= TICK + TICK_JITTER, "{next:?}");
    assert!(!flusher.due(start + Duration::from_secs(60), &one), "unchanged: no write");
    assert!(!flusher.due(start + Duration::from_secs(1), &two), "changed, before the tick");
    let t = start + Duration::from_secs(6);
    assert!(flusher.due(t, &two));
    // Failures back off from 5 s by 1.2, with up to half again of jitter.
    let mut now = t;
    for step in 0..BACKOFF_STEPS {
        assert!(!flusher.record(now, &two, Outcome::Failed));
        let delay = flusher.next().duration_since(now).as_secs_f64();
        let base = 5.0 * 1.2f64.powi(i32::try_from(step).expect("step"));
        assert!(delay >= base && delay <= base * 1.5 + 1e-9, "step {step}: {delay}");
        now = flusher.next();
        assert!(flusher.due(now, &two));
    }
    // Exhausted: reported once, back to the plain ticker.
    assert!(flusher.record(now, &two, Outcome::Failed));
    let delay = flusher.next().duration_since(now);
    assert!(delay <= TICK + TICK_JITTER, "{delay:?}");
    assert!(!flusher.record(flusher.next(), &two, Outcome::Failed), "a new round");
    // NotFound forgets the last write: the same status is due again.
    let mut flusher = Flusher::new(start, 9);
    flusher.record(start, &one, Outcome::Written);
    let later = start + Duration::from_secs(10);
    assert!(!flusher.due(later, &one));
    flusher.record(later, &one, Outcome::NotFound);
    assert!(flusher.due(later + Duration::from_secs(10), &one));
}

#[test]
fn patches() {
    let status = FlowsdnBGPNodeConfigStatus {
        bgp_instances: None,
        conditions: Some(vec![]),
    };
    assert_eq!(status_patch(&status), json!({"status": {"conditions": []}}));
    assert_eq!(
        cleanup_patch(),
        json!([{"op": "replace", "path": "/status", "value": {}}])
    );
}
