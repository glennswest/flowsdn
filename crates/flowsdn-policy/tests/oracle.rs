use flowsdn_policy::{Error, oracle::*, ports::PortRange};
use std::collections::BTreeSet;
fn rule(tier: Tier, priority: f64, verdict: Verdict) -> Rule {
    Rule {
        tier,
        priority,
        verdict,
        egress: true,
        peer: Peer::Any,
        protocol: 0,
        ports: PortRange::any(),
        authentication: None,
        proxy_port: 0,
        listener_priority: 0,
    }
}
fn packet(port: u16) -> Packet {
    Packet {
        identity: 123,
        egress: true,
        protocol: 6,
        port,
    }
}
fn allow(proxy_port: u16) -> Decision {
    Decision::Allow {
        proxy_ports: BTreeSet::from([proxy_port]),
    }
}
#[test]
fn deny_wins_at_equal_priority_regardless_of_specificity_and_input_order() {
    let broad = rule(Tier::Normal, 0.0, Verdict::Deny);
    let specific = Rule {
        peer: Peer::Identity(123),
        protocol: 6,
        ports: PortRange::from_api(443, None).expect("port"),
        ..rule(Tier::Normal, 0.0, Verdict::Allow)
    };
    for rules in [
        vec![broad.clone(), specific.clone()],
        vec![specific.clone(), broad.clone()],
    ] {
        assert_eq!(evaluate(&rules, packet(443)), Ok(Decision::Deny));
    }
    let mut higher = specific;
    higher.tier = Tier::Admin;
    assert_eq!(evaluate(&[broad, higher], packet(443)), Ok(allow(0)));
}
#[test]
fn pass_skips_lower_priority_rules_in_its_tier_but_not_lower_tiers() {
    let pass = Rule {
        protocol: 6,
        ports: PortRange::from_api(80, Some(90)).expect("range"),
        ..rule(Tier::Admin, 1.0, Verdict::Pass)
    };
    let rules = [
        pass,
        rule(Tier::Admin, 2.0, Verdict::Deny),
        rule(Tier::Normal, 0.0, Verdict::Allow),
    ];
    for port in 0..=u16::MAX {
        assert_eq!(
            evaluate(&rules, packet(port)).expect("oracle"),
            if (80..=90).contains(&port) {
                allow(0)
            } else {
                Decision::Deny
            }
        );
    }
    assert_eq!(
        evaluate(&[rule(Tier::Admin, 0.0, Verdict::Pass)], packet(80)),
        Ok(Decision::Deny)
    );
}
#[test]
fn equal_priority_deny_beats_pass_and_redirect_beats_plain_allow() {
    assert_eq!(
        evaluate(
            &[
                rule(Tier::Admin, 0.0, Verdict::Pass),
                rule(Tier::Admin, 0.0, Verdict::Deny),
                rule(Tier::Normal, 0.0, Verdict::Allow)
            ],
            packet(443)
        ),
        Ok(Decision::Deny)
    );
    let redirect = Rule {
        proxy_port: 15000,
        listener_priority: 1,
        ..rule(Tier::Normal, 0.0, Verdict::Allow)
    };
    assert_eq!(
        evaluate(
            &[rule(Tier::Normal, 0.0, Verdict::Allow), redirect.clone()],
            packet(443)
        ),
        Ok(allow(15000))
    );
    let weaker = Rule {
        proxy_port: 15001,
        listener_priority: 0,
        ..redirect.clone()
    };
    assert_eq!(evaluate(&[weaker, redirect], packet(443)), Ok(allow(15000)));
}
#[test]
fn direction_identity_protocol_and_default_deny_are_independent() {
    let constrained = Rule {
        peer: Peer::Identity(123),
        protocol: 6,
        ..rule(Tier::Normal, 0.0, Verdict::Allow)
    };
    for bad in [
        Packet {
            identity: 124,
            ..packet(80)
        },
        Packet {
            egress: false,
            ..packet(80)
        },
        Packet {
            protocol: 17,
            ..packet(80)
        },
    ] {
        assert_eq!(
            evaluate(std::slice::from_ref(&constrained), bad),
            Ok(Decision::Deny)
        );
    }
    assert_eq!(evaluate(&[], packet(80)), Ok(Decision::Deny));
}
#[test]
fn unsupported_auth_is_explicit_rather_than_a_false_oracle_success() {
    let authenticated = Rule {
        authentication: Some(Authentication::Required),
        ..rule(Tier::Normal, 0.0, Verdict::Allow)
    };
    assert_eq!(
        evaluate(&[authenticated], packet(80)),
        Err(Error::OracleAuthenticationUnsupported)
    );
}
