use flowsdn_operator::{
    ces::{Error, RateTable, Selection},
    lifecycle::{Action, Event, Lifecycle, State},
    readiness::{Observation, crd_plan, probes},
    taints::{self, Taint},
};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn leadership_loss_is_terminal_even_during_startup() {
    for started in [false, true] {
        let mut lifecycle = Lifecycle::default();
        assert!(!lifecycle.is_leader());
        assert_eq!(
            lifecycle.transition(Event::LeaseAcquired),
            Ok(Action::StartLeaderScope)
        );
        if started {
            assert_eq!(
                lifecycle.transition(Event::DutiesStarted),
                Ok(Action::PublishLeadership)
            );
        }
        assert_eq!(lifecycle.is_leader(), started);
        assert_eq!(
            lifecycle.transition(Event::LeadershipLost),
            Ok(Action::CancelAndExit)
        );
        assert_eq!(lifecycle.state(), State::Terminated);
        assert!(!lifecycle.is_leader());
        for event in [
            Event::LeaseAcquired,
            Event::DutiesStarted,
            Event::LeadershipLost,
        ] {
            assert!(lifecycle.transition(event).is_err());
            assert_eq!(lifecycle.state(), State::Terminated);
        }
    }
}
#[test]
fn partial_duty_start_failure_requires_release_and_exit() {
    let mut lifecycle = Lifecycle::default();
    assert!(lifecycle.transition(Event::DutiesStarted).is_err());
    assert_eq!(lifecycle.state(), State::Follower);
    lifecycle.transition(Event::LeaseAcquired).expect("acquire");
    assert_eq!(
        lifecycle.transition(Event::DutyStartFailed),
        Ok(Action::CancelReleaseAndExit)
    );
    assert!(!lifecycle.is_leader());
    assert!(lifecycle.transition(Event::LeaseAcquired).is_err());
}
#[test]
fn missing_crd_blocks_readiness_but_keeps_process_health() {
    let required = BTreeSet::from(["a".into(), "b".into()]);
    let mut observed = BTreeMap::from([("a".into(), Observation::Established)]);
    let missing = crd_plan(true, true, &required, &observed);
    assert!(!missing.register);
    assert!(!missing.release_fence);
    assert_eq!(missing.blockers.get("b"), Some(&Observation::Missing));
    assert_eq!(probes(true, true, &missing).health_status, 200);
    assert_eq!(probes(true, true, &missing).readiness_status, 503);
    for state in [Observation::NotEstablished, Observation::ReadFailed] {
        observed.insert("b".into(), state);
        assert!(!crd_plan(true, true, &required, &observed).release_fence);
    }
    observed.insert("b".into(), Observation::Established);
    let ready = crd_plan(true, true, &required, &observed);
    assert!(ready.release_fence);
    assert_eq!(probes(true, true, &ready).readiness_status, 200);
    assert_eq!(probes(true, false, &ready).health_status, 500);
    assert_eq!(probes(true, false, &ready).readiness_status, 500);
    observed.remove("a");
    assert!(!crd_plan(true, true, &required, &observed).release_fence);
}
#[test]
fn crd_registration_and_disabled_kubernetes_are_distinct() {
    let required = BTreeSet::from(["a".into()]);
    let observed = BTreeMap::new();
    let create = crd_plan(true, false, &required, &observed);
    assert!(create.register);
    assert!(!create.release_fence);
    let disabled = crd_plan(false, false, &required, &observed);
    assert!(!disabled.register);
    assert!(disabled.release_fence);
    assert_eq!(probes(false, true, &disabled).readiness_status, 501);
}
#[test]
fn ces_unsorted_thresholds_select_boundaries_in_both_directions() {
    let table = RateTable::parse(r#"[{"nodes":25,"limit":16,"burst":32},{"nodes":5,"limit":5,"burst":10},{"nodes":15,"limit":11.5,"burst":22}]"#).expect("table");
    for (count, expected) in [
        (0, 5),
        (4, 5),
        (5, 5),
        (14, 5),
        (15, 15),
        (24, 15),
        (25, 25),
        (u64::MAX, 25),
    ] {
        assert_eq!(table.select(count).nodes, expected);
    }
    let mut current = Selection::new(table);
    assert_eq!(current.current().nodes, 5);
    assert!(current.update(10).is_none());
    assert_eq!(current.update(25).expect("increase").burst, 32);
    assert_eq!(current.update(15).expect("decrease").limit, 11.5);
    assert!(current.update(24).is_none());
    assert_eq!(current.update(0).expect("back to first").nodes, 5);
}
#[test]
fn ces_single_step_and_reference_field_spelling() {
    let table =
        RateTable::parse(r#"[{"Nodes":5,"Limit":15.5,"Burst":30}]"#).expect("reference spelling");
    assert_eq!(table.select(0), table.select(u64::MAX));
    assert_eq!(table.select(0).limit, 15.5);
    assert_eq!(RateTable::default().select(0).burst, 20);
    assert_eq!(RateTable::default().select(u64::MAX).limit, 10.0);
}
#[test]
fn ces_rejects_invalid_tables_before_selection() {
    for bad in [
        "",
        "null",
        "{}",
        "[]",
        "[null]",
        r#"[{"nodes":0,"limit":10,"burst":20,"unknown":1}]"#,
        r#"[{"nodes":-1,"limit":10,"burst":20}]"#,
        r#"[{"nodes":0.5,"limit":10,"burst":20}]"#,
        r#"[{"nodes":0,"limit":0,"burst":20}]"#,
        r#"[{"nodes":0,"limit":-2,"burst":20}]"#,
        r#"[{"nodes":0,"limit":1e999,"burst":20}]"#,
        r#"[{"nodes":0,"limit":10,"burst":0}]"#,
        r#"[{"nodes":0,"limit":10,"burst":4294967296}]"#,
        r#"[{"nodes":0,"limit":10}]"#,
        r#"[{"nodes":0,"limit":10,"burst":20}] {}"#,
        r#"[{"nodes":0,"Nodes":1,"limit":10,"burst":20}]"#,
        r#"[{"nodes":0,"nodes":1,"limit":10,"burst":20}]"#,
        r#"[{"nodes":0,"limit":10,"limit":20,"burst":20}]"#,
        r#"[{"nodes":0,"limit":10,"burst":20,"burst":30}]"#,
    ] {
        assert!(RateTable::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(
        RateTable::parse(
            r#"[{"nodes":0,"limit":10,"burst":20},{"nodes":0,"limit":20,"burst":40}]"#
        )
        .expect_err("duplicate threshold"),
        Error::DuplicateThreshold
    );
}
#[test]
fn taint_removal_matches_key_and_preserves_every_other_field() {
    let make = |key: &str, effect: &str| Taint {
        key: key.into(),
        value: "true".into(),
        effect: effect.into(),
    };
    let other = make("other", "PreferNoSchedule");
    let observed = vec![
        make(taints::AGENT_NOT_READY_KEY, "NoExecute"),
        other.clone(),
        make(taints::AGENT_NOT_READY_KEY, "NoSchedule"),
    ];
    assert_eq!(
        taints::remove_not_ready(&observed, taints::AGENT_NOT_READY_KEY),
        vec![other]
    );
    assert_eq!(taints::remove_not_ready(&observed, "custom"), observed);
    assert_eq!(
        taints::add_not_ready(&observed, taints::AGENT_NOT_READY_KEY),
        observed
    );
    let custom = taints::add_not_ready(&observed, "custom");
    assert_eq!(
        custom.last(),
        Some(&Taint {
            key: "custom".into(),
            value: String::new(),
            effect: "NoSchedule".into()
        })
    );
    assert_eq!(taints::remove_not_ready(&custom, "custom"), observed);
}
