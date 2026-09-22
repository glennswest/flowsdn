use flowsdn_bgp_proto::{
    capabilities::{Family, local_open},
    session::*,
    *,
};
use std::{collections::BTreeSet, net::Ipv4Addr};
fn local() -> open::Open {
    local_open(
        65000,
        30,
        Ipv4Addr::new(192, 0, 2, 1),
        &BTreeSet::from([Family::IPV4]),
    )
    .expect("local")
}
fn peer(hold: u16) -> Vec<u8> {
    local_open(
        65001,
        hold,
        Ipv4Addr::new(192, 0, 2, 2),
        &BTreeSet::from([Family::IPV4]),
    )
    .expect("peer")
    .encode()
    .expect("wire")
}
fn config() -> Config {
    Config {
        local: local(),
        peer_asn: 65001,
        listen: true,
        passive: false,
        retry_ms: 1000,
        keepalive_ms: 4000,
        strict_update_errors: false,
        graceful_shutdown: false,
    }
}
fn message(session: &mut Session, kind: Kind, body: &[u8], now: u64) -> Vec<Action> {
    let generation = session.generation();
    session
        .handle(
            Event::Message {
                generation,
                frame: Frame { kind, body },
            },
            now,
            0,
        )
        .expect("event")
}
fn established(config: Config, hold: u16) -> Session {
    let mut s = Session::new(config).expect("session");
    s.handle(Event::Start, 0, 0).expect("start");
    s.handle(
        Event::TcpEstablished {
            generation: s.generation(),
            inbound: false,
        },
        1,
        0,
    )
    .expect("TCP");
    message(&mut s, Kind::Open, &peer(hold), 2);
    message(&mut s, Kind::Keepalive, &[], 3);
    assert_eq!(s.state(), State::Established);
    s
}
fn notification(actions: &[Action], code: u8, subcode: u8) -> bool {
    actions.iter().any(|a| matches!(a,Action::Send {kind:Kind::Notification,body} if body.starts_with(&[code,subcode])))
}
#[test]
fn active_handshake_transcript_and_each_timer() {
    let mut s = Session::new(config()).expect("session");
    assert_eq!(
        s.handle(Event::Start, 0, 10).expect("start"),
        vec![Action::Connect { generation: 1 }]
    );
    assert_eq!(s.deadlines().retry, Some(1010));
    s.handle(Event::TcpFailed { generation: 1 }, 100, 0)
        .expect("failure");
    assert_eq!(s.state(), State::Active);
    assert!(s.poll(1099, 0).expect("not due").is_empty());
    assert_eq!(
        s.poll(1100, 0).expect("retry"),
        vec![Action::Close, Action::Connect { generation: 3 }]
    );
    let sent = s
        .handle(
            Event::TcpEstablished {
                generation: 3,
                inbound: false,
            },
            1101,
            0,
        )
        .expect("TCP");
    assert!(matches!(
        sent.as_slice(),
        [Action::Send {
            kind: Kind::Open,
            ..
        }]
    ));
    assert_eq!(s.deadlines().hold, Some(241101));
    assert_eq!(
        message(&mut s, Kind::Open, &peer(9), 1102),
        vec![Action::Send {
            kind: Kind::Keepalive,
            body: vec![]
        }]
    );
    assert_eq!(s.state(), State::OpenConfirm);
    assert_eq!(s.deadlines().hold, Some(10102));
    assert_eq!(s.deadlines().keepalive, Some(4102));
    let export = message(&mut s, Kind::Keepalive, &[], 1103);
    assert_eq!(
        export,
        vec![Action::Export {
            families: BTreeSet::from([Family::IPV4]),
            end_of_rib: true
        }]
    );
    assert!(message(&mut s, Kind::Keepalive, &[], 1104).is_empty());
    assert_eq!(
        s.poll(4102, 0).expect("keepalive"),
        vec![Action::Send {
            kind: Kind::Keepalive,
            body: vec![]
        }]
    );
    let expired = s.poll(10104, 0).expect("hold expired");
    assert!(notification(&expired, 4, 0));
    assert_eq!(s.state(), State::Idle);
    assert!(
        s.handle(Event::Start, 10105, 0)
            .expect("manual start respects hold")
            .is_empty()
    );
    assert!(s.poll(15103, 0).expect("idle wait").is_empty());
    assert!(
        s.poll(15104, 0)
            .expect("idle expiry")
            .iter()
            .any(|a| matches!(a, Action::Connect { .. }))
    );
}
#[test]
fn open_sent_timeout_invalid_open_and_unexpected_messages_notify() {
    let mut s = Session::new(config()).expect("session");
    s.handle(Event::Start, 0, 0).expect("start");
    s.handle(
        Event::TcpEstablished {
            generation: 1,
            inbound: false,
        },
        1,
        0,
    )
    .expect("TCP");
    assert!(notification(&s.poll(240001, 0).expect("timeout"), 4, 0));
    for (kind, body, code, subcode) in [
        (Kind::Open, vec![3, 0, 0, 0, 0, 192, 0, 2, 2, 0], 2, 1),
        (Kind::Keepalive, vec![], 5, 1),
    ] {
        let mut s = Session::new(config()).expect("session");
        s.handle(Event::Start, 0, 0).expect("start");
        s.handle(
            Event::TcpEstablished {
                generation: 1,
                inbound: false,
            },
            1,
            0,
        )
        .expect("TCP");
        assert!(notification(
            &message(&mut s, kind, &body, 2),
            code,
            subcode
        ));
        assert_eq!(s.state(), State::Idle);
    }
    let mut s = established(config(), 9);
    assert!(notification(
        &message(&mut s, Kind::Open, &peer(9), 4),
        5,
        3
    ));
}
#[test]
fn zero_hold_disables_liveness_timers_and_shutdown_wins_expiry() {
    let mut s = established(config(), 0);
    assert_eq!(s.deadlines().hold, None);
    assert_eq!(s.deadlines().keepalive, None);
    assert!(s.poll(1_000_000, 0).expect("no timers").is_empty());
    let closed = s.handle(Event::Shutdown, 1_000_001, 0).expect("shutdown");
    assert!(notification(&closed, 6, 2));
    assert!(
        s.poll(2_000_000, 0)
            .expect("no automatic restart")
            .is_empty()
    );
    let mut s = established(config(), 9);
    let expired = s.deadlines().hold.expect("hold");
    s.handle(Event::Shutdown, expired, 0)
        .expect("shutdown at expiry");
    assert_eq!(s.deadlines().idle, None);
    assert!(
        s.poll(expired.saturating_add(5000), 0)
            .expect("stopped")
            .is_empty()
    );
}
#[test]
fn passive_never_dials_and_stale_transport_generation_is_ignored() {
    let mut cfg = config();
    cfg.passive = true;
    let mut s = Session::new(cfg).expect("passive");
    assert!(s.handle(Event::Start, 0, 0).expect("start").is_empty());
    assert_eq!(s.state(), State::Active);
    assert_eq!(s.poll(1000, 0).expect("retry"), vec![Action::Close]);
    assert_eq!(
        s.handle(
            Event::TcpEstablished {
                generation: 1,
                inbound: true
            },
            1001,
            0
        )
        .expect("stale"),
        vec![Action::DropConnection]
    );
    assert_eq!(
        s.handle(
            Event::TcpEstablished {
                generation: 2,
                inbound: false
            },
            1002,
            0
        )
        .expect("outbound forbidden"),
        vec![Action::DropConnection]
    );
    assert!(matches!(
        s.handle(
            Event::TcpEstablished {
                generation: 2,
                inbound: true
            },
            1003,
            0
        )
        .expect("inbound")
        .as_slice(),
        [Action::Send {
            kind: Kind::Open,
            ..
        }]
    ));
    s.handle(Event::TcpClosed { generation: 2 }, 1004, 0)
        .expect("closed");
    assert_eq!(s.state(), State::Active);
    assert!(
        s.handle(
            Event::Message {
                generation: 2,
                frame: Frame {
                    kind: Kind::Open,
                    body: &peer(9)
                }
            },
            1005,
            0
        )
        .expect("old read callback")
        .is_empty()
    );
    assert_eq!(s.state(), State::Active);
}
#[test]
fn strict_and_lenient_update_paths_do_not_install_routes_or_hide_structure() {
    let invalid_origin = [0, 0, 0, 4, 0x40, 1, 1, 3];
    for strict in [false, true] {
        let mut cfg = config();
        cfg.strict_update_errors = strict;
        let mut s = established(cfg, 9);
        let actions = message(&mut s, Kind::Update, &invalid_origin, 4);
        if strict {
            assert!(notification(&actions, 3, 6));
            assert_eq!(s.state(), State::Idle);
        } else {
            assert!(matches!(actions.as_slice(), [Action::DiscardUpdate(_)]));
            assert_eq!(s.state(), State::Established);
        }
    }
    let mut s = established(config(), 9);
    assert!(matches!(
        message(&mut s, Kind::Update, &[0, 0, 0, 0], 4).as_slice(),
        [Action::ObserveUpdate(_)]
    ));
    assert!(
        notification(
            &message(&mut s, Kind::Update, &[0, 0, 0, 1, 0x40, 33], 5),
            3,
            5
        ) || s.state() == State::Idle
    );
    assert_eq!(s.state(), State::Idle);
}
#[test]
fn soft_reset_refresh_graceful_shutdown_collision_and_clock_bounds() {
    let mut cfg = config();
    cfg.graceful_shutdown = true;
    let mut s = established(cfg, 30);
    assert!(matches!(
        s.handle(Event::SoftResetOut, 4, 0)
            .expect("soft")
            .as_slice(),
        [Action::Export {
            end_of_rib: false,
            ..
        }]
    ));
    assert!(matches!(
        message(&mut s, Kind::RouteRefresh, &[0, 1, 0, 1], 5).as_slice(),
        [Action::Export {
            end_of_rib: false,
            ..
        }]
    ));
    assert_eq!(
        s.handle(Event::Shutdown, 6, 0).expect("GR shutdown"),
        vec![Action::Close]
    );
    let before = s.state();
    assert_eq!(s.poll(5, 0), Err(Error::ClockReversed));
    assert_eq!(s.state(), before);
    for entropy in [0, 1, 999, u64::MAX] {
        let value = retry_delay(1000, entropy).expect("jitter");
        assert!((1000..2000).contains(&value));
    }
    assert_eq!(retry_delay(0, 0), Err(Error::InvalidConfig));
    assert_eq!(
        retain_outbound(Ipv4Addr::new(192, 0, 2, 2), Ipv4Addr::new(192, 0, 2, 1)),
        Some(true)
    );
    assert_eq!(
        retain_outbound(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST),
        None
    );
}
fn established_gr() -> Session {
    let families = BTreeSet::from([Family::IPV4]);
    let mut cfg = config();
    cfg.local
        .capabilities
        .push(capabilities::graceful_restart(120, false, &families).expect("GR"));
    let mut remote = local_open(65001, 30, Ipv4Addr::new(192, 0, 2, 2), &families).expect("peer");
    remote
        .capabilities
        .push(capabilities::graceful_restart(30, false, &families).expect("GR"));
    let mut s = Session::new(cfg).expect("session");
    s.handle(Event::Start, 0, 0).expect("start");
    s.handle(
        Event::TcpEstablished {
            generation: 1,
            inbound: false,
        },
        1,
        0,
    )
    .expect("TCP");
    message(&mut s, Kind::Open, &remote.encode().expect("OPEN"), 2);
    message(&mut s, Kind::Keepalive, &[], 3);
    s
}
#[test]
fn graceful_notifications_and_hard_resets_have_distinct_wire_and_close_semantics() {
    let mut s = established_gr();
    message(&mut s, Kind::Notification, &[4, 0], 4);
    assert_eq!(s.last_close(), CloseDisposition::PeerMayRetainExports);
    let mut s = established_gr();
    message(&mut s, Kind::Notification, &[6, 9, 6, 2], 4);
    assert_eq!(s.last_close(), CloseDisposition::Hard);
    let mut s = established_gr();
    let actions = s.handle(Event::HardReset, 4, 0).expect("reset");
    assert!(actions.contains(&Action::Send {
        kind: Kind::Notification,
        body: vec![6, 9, 6, 4]
    }));
    assert_eq!(s.last_close(), CloseDisposition::Hard);
    let mut s = established_gr();
    let actions = s.poll(30003, 0).expect("hold");
    assert!(notification(&actions, 4, 0));
    assert_eq!(s.last_close(), CloseDisposition::PeerMayRetainExports);
    let mut s = established(config(), 30);
    message(&mut s, Kind::Notification, &[4, 0], 4);
    assert_eq!(s.last_close(), CloseDisposition::Hard);
}
#[test]
fn received_table_over_cap_survives_without_local_origin_or_export_changes() {
    use flowsdn_bgp_proto::{
        encode_update::Export,
        rib::{LocalRib, ObservedRib},
        update::Prefix,
    };
    let mut local_rib = LocalRib::default();
    local_rib.advertise(Prefix::new("203.0.113.0".parse().expect("IP"), 24).expect("prefix"));
    let snapshot = local_rib.prefixes().clone();
    let mut observed = ObservedRib::new(100);
    let mut s = established(config(), 30);
    let export = Export {
        family: Family::IPV4,
        next_hop: "192.0.2.2".parse().expect("IP"),
        local_asn: 65001,
        external: true,
        four_octet_asn: true,
        as_sequence: vec![],
        local_preference: 100,
        origin: 0,
    };
    let prefixes = (0..100001)
        .map(|n| Prefix::new(Ipv4Addr::from(n).into(), 32).expect("prefix"))
        .collect::<Vec<_>>();
    let frames = export.announcements(&prefixes).expect("table");
    for (index, frame) in frames.iter().enumerate() {
        let (frame, _) = decode(frame).expect("frame");
        let actions = message(
            &mut s,
            frame.kind,
            frame.body,
            4 + u64::try_from(index).expect("index"),
        );
        assert!(matches!(actions.as_slice(), [Action::ObserveUpdate(_)]));
        for action in actions {
            if let Action::ObserveUpdate(summary) = action {
                observed.observe(&summary);
            }
        }
    }
    assert_eq!(s.state(), State::Established);
    assert_eq!(observed.prefixes(false).len(), 100);
    assert_eq!(observed.counters().announcements, 100001);
    assert_eq!(local_rib.prefixes(), &snapshot);
}
#[test]
fn terminal_connect_callback_revokes_attempt_before_late_success_or_failure() {
    for closed in [false, true] {
        let mut s = Session::new(config()).expect("session");
        s.handle(Event::Start, 0, 0).expect("start");
        let terminal = if closed {
            Event::TcpClosed { generation: 1 }
        } else {
            Event::TcpFailed { generation: 1 }
        };
        s.handle(terminal, 10, 0).expect("terminal");
        let deadlines = s.deadlines();
        assert_eq!(
            s.handle(
                Event::TcpEstablished {
                    generation: 1,
                    inbound: false
                },
                11,
                0
            )
            .expect("late success"),
            vec![Action::DropConnection]
        );
        s.handle(terminal, 12, 0).expect("duplicate terminal");
        assert_eq!(s.deadlines(), deadlines);
        assert_eq!(s.state(), State::Active);
    }
}
