use flowsdn_hubble::{
    drop_events::{Gate, Key, Rejected},
    export::{EventNode, node_name},
};
use std::time::Duration;
fn key(uid: &str) -> Key {
    Key {
        pod_uid: uid.into(),
        reason: "PacketDrop".into(),
        message: "Incoming packet dropped from 192.0.2.1 TCP port 80".into(),
    }
}
#[test]
fn export_node_shape_is_event_specific_and_preserves_flow_value() {
    assert_eq!(
        node_name(EventNode::Flow("mesh/worker"), "worker"),
        "mesh/worker"
    );
    assert_eq!(node_name(EventNode::Flow(""), "worker"), "");
    for kind in [EventNode::Lost, EventNode::Agent, EventNode::Debug] {
        assert_eq!(node_name(kind, "worker"), "worker");
    }
}
#[test]
fn dedupe_rate_boundaries_and_failed_write_retry_are_separate() {
    let mut gate = Gate::new(Duration::from_secs(120), 2, 1).expect("gate");
    let first = gate.admit(Duration::ZERO, key("uid1")).expect("first");
    assert_eq!(
        gate.admit(Duration::ZERO, key("uid1"))
            .expect_err("duplicate"),
        Rejected::Duplicate
    );
    assert_eq!(
        gate.admit(Duration::from_millis(999), key("uid2"))
            .expect_err("rate"),
        Rejected::RateLimited
    );
    gate.finish(first, false);
    assert_eq!(
        gate.admit(Duration::from_millis(999), key("uid1"))
            .expect_err("no refund"),
        Rejected::RateLimited
    );
    gate.admit(Duration::from_secs(1), key("uid1"))
        .expect("retry");
    gate.admit(Duration::from_secs(2), key("uid2"))
        .expect("different UID");
    assert_eq!(
        gate.admit(Duration::from_secs(3), key("uid3"))
            .expect_err("bounded"),
        Rejected::Capacity
    );
    assert_eq!(
        gate.admit(Duration::from_secs(120), key("uid1"))
            .expect_err("not yet expired"),
        Rejected::Duplicate
    );
    gate.admit(Duration::from_secs(121), key("uid1"))
        .expect("exact expiry");
    assert_eq!(
        gate.admit(Duration::ZERO, key("uid3"))
            .expect_err("monotonic"),
        Rejected::ClockReversed
    );
    assert_eq!(gate.retained_keys(), 2);
}
#[test]
fn stale_failure_does_not_remove_a_new_reservation() {
    let mut gate = Gate::new(Duration::from_secs(1), 1, 0).expect("unlimited rate");
    let stale = gate.admit(Duration::ZERO, key("uid")).expect("old");
    let current = gate.admit(Duration::from_secs(1), key("uid")).expect("new");
    gate.finish(stale, false);
    assert_eq!(
        gate.admit(Duration::from_secs(1), key("uid"))
            .expect_err("still reserved"),
        Rejected::Duplicate
    );
    gate.finish(current, true);
    assert_eq!(gate.retained_keys(), 1);
    assert!(Gate::new(Duration::ZERO, 1, 0).is_err());
    assert!(Gate::new(Duration::from_secs(1), 0, 0).is_err());
}

#[test]
fn old_gate_completion_cannot_erase_replacement_gate_reservation() {
    let mut old = Gate::new(Duration::from_secs(120), 1, 0).expect("old gate");
    let stale = old.admit(Duration::ZERO, key("uid")).expect("old admission");
    drop(old);
    let mut replacement = Gate::new(Duration::from_secs(120), 1, 0).expect("replacement");
    let current = replacement.admit(Duration::ZERO, key("uid")).expect("new admission");
    replacement.finish(stale, false);
    assert_eq!(replacement.retained_keys(), 1);
    assert_eq!(replacement.admit(Duration::ZERO, key("uid")).expect_err("reserved"), Rejected::Duplicate);
    replacement.finish(current, false);
    assert_eq!(replacement.retained_keys(), 0);
}
