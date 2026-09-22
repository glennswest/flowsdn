use flowsdn_hubble::correlation::*;
use std::cell::Cell;
struct Snapshot {
    calls: Cell<u32>,
    present: bool,
}
impl PolicySnapshot for Snapshot {
    fn correlation_info(&self, endpoint_id: u16, key: Key) -> Option<PolicyMatch> {
        assert_eq!(endpoint_id, 42);
        assert_eq!(key.remote_identity, 1234);
        self.calls.set(self.calls.get().saturating_add(1));
        self.present.then(|| PolicyMatch {
            revision: 17,
            rules: vec![
                Rule {
                    labels: vec![("io.cilium.k8s.policy.name".into(), "ingress".into())],
                    log: Some("audit".into()),
                },
                Rule {
                    labels: vec![],
                    log: Some("audit".into()),
                },
            ],
        })
    }
}
fn key(direction: Direction) -> Key {
    Key {
        direction,
        remote_identity: 1234,
        destination_port: 443,
        protocol: 6,
    }
}
#[test]
fn realized_revision_labels_and_logs_follow_direction_and_verdict() {
    let snapshot = Snapshot {
        calls: Cell::new(0),
        present: true,
    };
    for (direction, verdict, field) in [
        (
            Direction::Ingress,
            Verdict::Forwarded,
            Field::IngressAllowedBy,
        ),
        (
            Direction::Egress,
            Verdict::Redirected,
            Field::EgressAllowedBy,
        ),
        (
            Direction::Ingress,
            Verdict::Dropped { reason: 133 },
            Field::IngressDeniedBy,
        ),
        (
            Direction::Egress,
            Verdict::Dropped { reason: 181 },
            Field::EgressDeniedBy,
        ),
        (Direction::Ingress, Verdict::Audit, Field::IngressDeniedBy),
        (Direction::Egress, Verdict::Audit, Field::EgressDeniedBy),
    ] {
        let result = correlate(&snapshot, 42, key(direction), verdict).expect("match");
        assert_eq!(result.field, field);
        assert_eq!(result.policy.revision, 17);
        assert_eq!(result.policy_log, vec!["audit"]);
        assert_eq!(
            result
                .policy
                .rules
                .first()
                .expect("rule")
                .labels
                .first()
                .expect("label")
                .1,
            "ingress"
        );
    }
}
#[test]
fn missing_policy_and_irrelevant_packets_never_invent_provenance() {
    let snapshot = Snapshot {
        calls: Cell::new(0),
        present: false,
    };
    let base = key(Direction::Ingress);
    for (endpoint, key, verdict) in [
        (0, base, Verdict::Forwarded),
        (
            42,
            Key {
                protocol: 0,
                ..base
            },
            Verdict::Forwarded,
        ),
        (
            42,
            Key {
                destination_port: 0,
                ..base
            },
            Verdict::Forwarded,
        ),
        (42, base, Verdict::Dropped { reason: 196 }),
        (42, base, Verdict::Other),
    ] {
        assert!(correlate(&snapshot, endpoint, key, verdict).is_none());
    }
    assert_eq!(snapshot.calls.get(), 0);
    assert!(correlate(&snapshot, 42, base, Verdict::Forwarded).is_none());
    assert_eq!(snapshot.calls.get(), 1);
}

#[test]
fn icmp_type_zero_preserves_reference_correlation_omission() {
    let snapshot = Snapshot {
        calls: Cell::new(0),
        present: true,
    };
    for protocol in [1, 58] {
        let zero_type = Key {
            protocol,
            destination_port: 0,
            ..key(Direction::Ingress)
        };
        assert!(correlate(&snapshot, 42, zero_type, Verdict::Forwarded).is_none());
    }
    assert_eq!(snapshot.calls.get(), 0);
    let echo_request = Key {
        protocol: 1,
        destination_port: 8,
        ..key(Direction::Ingress)
    };
    assert!(correlate(&snapshot, 42, echo_request, Verdict::Forwarded).is_some());
    assert_eq!(snapshot.calls.get(), 1);
}
