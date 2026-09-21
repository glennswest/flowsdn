use flowsdn_policy::{
    Error, OverflowAction,
    cidr::{CidrRule, PrefixUpdate},
    named_ports::{Contribution, Key, NamedPortState},
    oracle::{Authentication, Peer, Rule, Tier, Verdict},
    ports::PortRange,
    pressure,
    repository::SubjectRepository,
};
use std::collections::BTreeSet;

fn allow() -> Rule {
    Rule {
        tier: Tier::Normal,
        priority: 0.0,
        verdict: Verdict::Allow,
        egress: true,
        peer: Peer::Identity(123),
        protocol: 6,
        ports: PortRange::from_api(443, None).expect("port"),
        authentication: None,
        proxy_port: 0,
        listener_priority: 0,
    }
}
#[test]
fn import_rejects_cross_resource_pass_auth_without_replacing_old_policy() {
    let mut repository = SubjectRepository::default();
    let authenticated = Rule {
        authentication: Some(Authentication::Required),
        ..allow()
    };
    repository
        .replace("cnp/a", vec![authenticated])
        .expect("auth policy");
    repository
        .replace("kcnp/b", vec![allow()])
        .expect("old rule");
    let before = repository.clone();
    let pass = Rule {
        tier: Tier::Admin,
        verdict: Verdict::Pass,
        ..allow()
    };
    assert_eq!(
        repository.replace("kcnp/b", vec![pass.clone()]),
        Err(Error::PassWithAuthentication)
    );
    assert_eq!(repository, before);
    repository.replace("cnp/a", vec![]).expect("remove auth");
    repository
        .replace("kcnp/b", vec![pass])
        .expect("pass accepted after auth gone");
    let before = repository.clone();
    assert_eq!(
        repository.replace(
            "cnp/c",
            vec![Rule {
                authentication: Some(Authentication::Disabled),
                ..allow()
            }]
        ),
        Err(Error::PassWithAuthentication)
    );
    assert_eq!(repository, before);
}
#[test]
fn rejected_numeric_and_protocol_inputs_preserve_repository_revision() {
    let mut repository = SubjectRepository::default();
    repository.replace("cnp/a", vec![allow()]).expect("initial");
    let original = repository.clone();
    for priority in [f64::NAN, f64::INFINITY, -1.0] {
        assert_eq!(
            repository.replace(
                "cnp/a",
                vec![Rule {
                    priority,
                    ..allow()
                }]
            ),
            Err(Error::InvalidPriority)
        );
        assert_eq!(repository, original);
    }
    assert_eq!(
        repository.replace(
            "cnp/a",
            vec![Rule {
                protocol: 0,
                ..allow()
            }]
        ),
        Err(Error::InvalidProtocol)
    );
    assert_eq!(repository, original);
}
#[test]
fn policy_read_status_tracks_last_rule_deletion() {
    let mut repository = SubjectRepository::default();
    assert_eq!(repository.read_status(), 404);
    repository.replace("cnp/a", vec![allow()]).expect("first");
    repository.replace("cnp/b", vec![allow()]).expect("second");
    repository.replace("cnp/a", vec![]).expect("remove first");
    assert_eq!(repository.read_status(), 200);
    repository.replace("cnp/b", vec![]).expect("remove last");
    assert_eq!(repository.read_status(), 404);
    assert_eq!(repository.revision(), 4);
}
#[test]
fn named_port_deletion_preserves_other_selector_and_restores_shadowed_precedence() {
    let mut state = NamedPortState::default();
    let key = Key {
        identity: 123,
        protocol: 6,
        port: 443,
    };
    state
        .replace(
            "a",
            vec![Contribution {
                key,
                precedence: 10,
            }],
        )
        .expect("a");
    state
        .replace(
            "b",
            vec![Contribution {
                key,
                precedence: 20,
            }],
        )
        .expect("b");
    let change = state.replace("b", vec![]).expect("remove b");
    assert!(change.deletes.is_empty());
    assert_eq!(change.upserts.get(&key), Some(&10));
    assert_eq!(state.desired().get(&key), Some(&10));
    let change = state.replace("a", vec![]).expect("last owner removed");
    assert_eq!(change.deletes, vec![key]);
    assert!(state.desired().is_empty());
}
#[test]
fn named_port_reresolution_removes_old_key_and_keeps_unrelated_identity() {
    let mut state = NamedPortState::default();
    let old = Key {
        identity: 123,
        protocol: 6,
        port: 80,
    };
    let new = Key { port: 8080, ..old };
    let other = Key {
        identity: 456,
        ..old
    };
    state
        .replace(
            "a",
            vec![Contribution {
                key: old,
                precedence: 5,
            }],
        )
        .expect("old");
    state
        .replace(
            "b",
            vec![Contribution {
                key: other,
                precedence: 7,
            }],
        )
        .expect("other");
    let change = state
        .replace(
            "a",
            vec![Contribution {
                key: new,
                precedence: 5,
            }],
        )
        .expect("new");
    assert_eq!(change.deletes, vec![old]);
    assert_eq!(change.upserts.get(&new), Some(&5));
    assert_eq!(state.desired().get(&other), Some(&7));
    let original = state.clone();
    assert!(
        state
            .replace(
                "a",
                vec![Contribution {
                    key: Key { protocol: 0, ..new },
                    precedence: 2
                }]
            )
            .is_err()
    );
    assert_eq!(state, original);
}
#[test]
fn exceptions_are_allocated_before_publish_and_removed_afterwards() {
    let allow = "10.0.0.0/8".parse().expect("allow");
    let exception = "10.1.0.0/16".parse().expect("except");
    let rule = CidrRule::new(allow, [exception, exception]).expect("CIDR rule");
    assert_eq!(rule.import_prefixes(), BTreeSet::from([allow, exception]));
    // A straddling identity still matches the selector. The separate /16
    // ipcache identity is what prevents its addresses using that /9 identity.
    assert!(rule.selects("10.0.0.0/9".parse().expect("straddling")));
    assert!(!rule.selects(exception));
    assert!(!rule.selects("10.1.2.0/24".parse().expect("excluded child")));
    assert!(rule.selects("10.2.0.0/16".parse().expect("allowed child")));
    let initial = PrefixUpdate::between(&[], std::slice::from_ref(&rule));
    assert_eq!(initial.allocate_before_publish, rule.import_prefixes());
    assert!(initial.release_after_publish.is_empty());
    let replacement = CidrRule::new(allow, []).expect("remove except");
    let delta = PrefixUpdate::between(&[rule], &[replacement]);
    assert!(delta.allocate_before_publish.is_empty());
    assert_eq!(delta.release_after_publish, BTreeSet::from([exception]));
}
#[test]
fn cidr_exception_validation_preserves_family_and_containment() {
    let v6 = "2001:db8::/32".parse().expect("v6");
    let inner = "2001:db8:1::/48".parse().expect("inner");
    assert_eq!(
        CidrRule::new(v6, [inner])
            .expect("valid")
            .import_prefixes()
            .len(),
        2
    );
    for invalid in ["2001:db9::/32", "0.0.0.0/0", "2001::/16"] {
        assert_eq!(
            CidrRule::new(v6, [invalid.parse().expect("prefix")]),
            Err(Error::InvalidException)
        );
    }
}
#[test]
fn api_range_regression_seeds_reject_zero_start_without_wildcarding() {
    for line in include_str!("corpus/port-ranges.tsv")
        .lines()
        .filter(|s| !s.starts_with('#'))
    {
        let mut fields = line.split_whitespace();
        let start = fields.next().expect("start").parse().expect("start number");
        let end = fields.next().expect("end").parse().expect("end number");
        let accepted: bool = fields.next().expect("accepted").parse().expect("bool");
        assert_eq!(
            PortRange::from_api(start, Some(end)).is_ok(),
            accepted,
            "{line}"
        );
    }
    assert!(
        PortRange::from_api(0, None)
            .expect("wildcard without endPort")
            .is_any()
    );
}
#[test]
fn port_blocks_cover_exactly_the_inclusive_input_without_overlap() {
    for (start, end) in [
        (1, 65535),
        (80, 80),
        (1024, 2047),
        (1001, 9876),
        (65535, 65535),
    ] {
        let range = PortRange::from_api(start, Some(end)).expect("range");
        let blocks = range.blocks();
        for packet_port in 0..=u16::MAX {
            let matches = blocks.iter().filter(|b| b.matches(packet_port)).count();
            assert_eq!(
                matches,
                usize::from(start <= packet_port && packet_port <= end)
            );
        }
        for block in &blocks {
            let key = block.policy_key(123, true, 6).expect("ABI key");
            assert_eq!(key.prefixlen, 48u32.saturating_add(u32::from(block.prefix)));
        }
        if (start, end) == (1, 65535) {
            assert_eq!(blocks.len(), 16);
        }
    }
    let blocks = PortRange::any().blocks();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks.first().expect("wildcard").prefix, 0);
}
#[test]
fn pressure_alarm_is_exact_at_ninety_percent_and_lockdown_is_explicit() {
    assert!(!pressure(230, 256, false).expect("capacity").alarm);
    assert!(pressure(231, 256, false).expect("capacity").alarm);
    assert!(!pressure(899, 1000, false).expect("capacity").alarm);
    assert!(pressure(900, 1000, false).expect("capacity").alarm);
    assert!(!pressure(1000, 1000, true).expect("full fits").overflow);
    assert_eq!(
        pressure(1001, 1000, false).expect("compatibility").action,
        OverflowAction::Reconcile
    );
    assert_eq!(
        pressure(1001, 1000, true).expect("lockdown").action,
        OverflowAction::Lockdown
    );
    assert!(
        pressure(u64::MAX, 65536, true)
            .expect("large desired")
            .alarm
    );
    for capacity in [0, 255, 65537, u32::MAX] {
        assert_eq!(pressure(0, capacity, true), Err(Error::InvalidCapacity));
    }
}
