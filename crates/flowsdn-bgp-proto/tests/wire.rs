use flowsdn_bgp_proto::{
    open::{Capability, Open},
    planning::*,
    update::{self, Prefix},
    *,
};
use std::net::{IpAddr, Ipv4Addr};
#[test]
fn independent_keepalive_frame_partial_and_coalesced_messages() {
    let mut golden = vec![255; 16];
    golden.extend_from_slice(&[0, 19, 4]);
    assert_eq!(encode(Kind::Keepalive, &[]).expect("encode"), golden);
    for length in 0..golden.len() {
        assert_eq!(
            decode(golden.get(..length).expect("prefix")),
            Err(DecodeError::NeedMore)
        );
    }
    let mut two = golden.clone();
    two.extend_from_slice(&golden);
    let (frame, used) = decode(&two).expect("first");
    assert_eq!(used, 19);
    assert_eq!(frame.kind, Kind::Keepalive);
    assert!(frame.body.is_empty());
    assert_eq!(
        decode(two.get(used..).expect("second")).expect("second").1,
        19
    );
    *golden.first_mut().expect("marker") = 0;
    assert!(decode(&golden).is_ok());
    for (tail, subcode) in [
        ([0, 18, 4], 2),
        ([16, 1, 2], 2),
        ([0, 19, 6], 3),
        ([0, 20, 4], 2),
        ([0, 22, 5], 2),
    ] {
        let mut packet = vec![255; 16];
        packet.extend_from_slice(&tail);
        assert!(
            matches!(decode(&packet),Err(DecodeError::Protocol(ProtocolError {code:1,subcode:s,..})) if s==subcode)
        );
    }
    assert!(encode(Kind::Notification, &vec![0; 4077]).is_ok());
    assert!(encode(Kind::Notification, &vec![0; 4078]).is_err());
}
#[test]
fn open_golden_unknown_capability_four_octet_as_and_validation() {
    // Independent OPEN body: v4, AS_TRANS, hold90, 192.0.2.1, one AS4 cap65001.
    let wire = [
        4, 91, 160, 0, 90, 192, 0, 2, 1, 8, 2, 6, 65, 4, 0, 0, 253, 233,
    ];
    let open = Open::decode(&wire).expect("OPEN");
    assert_eq!(open.asn, 23456);
    assert_eq!(open.effective_asn().expect("AS4"), 65001);
    assert_eq!(open.encode().expect("encode"), wire);
    assert_eq!(
        open.validate_peer(65001, Ipv4Addr::new(192, 0, 2, 2), 30),
        Ok(30)
    );
    assert_eq!(
        open.validate_peer(65001, Ipv4Addr::new(192, 0, 2, 2), 0),
        Ok(0)
    );
    assert_eq!(
        open.validate_peer(65002, Ipv4Addr::new(192, 0, 2, 2), 30)
            .expect_err("AS")
            .subcode,
        2
    );
    assert_eq!(
        open.validate_peer(65001, open.router_id, 30)
            .expect_err("ID")
            .subcode,
        3
    );
    for length in 0..wire.len() {
        assert!(Open::decode(wire.get(..length).expect("prefix")).is_err());
    }
    let unknown = Open {
        capabilities: vec![Capability {
            code: 250,
            value: vec![1, 2, 3],
        }],
        ..open.clone()
    };
    assert_eq!(
        Open::decode(&unknown.encode().expect("unknown")).expect("decode"),
        unknown
    );
    for (offset, value, code) in [(0, 3, 1), (4, 2, 6), (9, 7, 4), (10, 1, 4), (13, 5, 4)] {
        let mut bad = wire;
        *bad.get_mut(offset).expect("fixture") = value;
        assert_eq!(Open::decode(&bad).expect_err("invalid").subcode, code);
    }
    let conflict = Open {
        capabilities: vec![
            Capability {
                code: 65,
                value: 65001u32.to_be_bytes().to_vec(),
            },
            Capability {
                code: 65,
                value: 65002u32.to_be_bytes().to_vec(),
            },
        ],
        ..open
    };
    assert!(conflict.encode().is_err());
}
fn update_body(attributes: &[u8], nlri: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(
        &u16::try_from(attributes.len())
            .expect("fixture")
            .to_be_bytes(),
    );
    body.extend_from_slice(attributes);
    body.extend_from_slice(nlri);
    body
}
fn valid_attributes() -> Vec<u8> {
    vec![
        0x40, 1, 1, 0, 0x40, 2, 4, 2, 1, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 1,
    ]
}
#[test]
fn update_vectors_prefix_masking_unknowns_and_end_of_rib() {
    let body = update_body(&valid_attributes(), &[25, 203, 0, 113, 255]);
    let decoded = update::validate(&body, false).expect("UPDATE");
    let route = decoded.announced.first().expect("NLRI");
    assert_eq!(
        route.address(),
        "203.0.113.128".parse::<IpAddr>().expect("IP")
    );
    assert_eq!(route.encode(), [25, 203, 0, 113, 128]);
    assert!(
        update::validate(&[0, 0, 0, 0], false)
            .expect("EOR")
            .announced
            .is_empty()
    );
    let mut attrs = valid_attributes();
    attrs.extend_from_slice(&[0xc0, 99, 2, 8, 9, 0x80, 100, 1, 7]);
    let result = update::validate(&update_body(&attrs, &[0]), false).expect("unknown optional");
    assert_eq!(result.unknown_transitive.len(), 1);
    assert_eq!(
        result.unknown_transitive.first().expect("retained").flags,
        0xe0
    );
    let ipv6 = Prefix::new("2001:db8:abcd:ffff::1".parse().expect("v6"), 48).expect("prefix");
    assert_eq!(ipv6.encode(), [48, 0x20, 1, 0xd, 0xb8, 0xab, 0xcd]);
    assert_eq!(
        update::prefixes(&ipv6.encode(), true).expect("NLRI"),
        vec![ipv6]
    );
    assert_eq!(
        Prefix::new("192.0.2.1".parse().expect("v4"), 0)
            .expect("default")
            .encode(),
        [0]
    );
}
#[test]
fn malformed_update_error_policy_separates_structure_and_content() {
    let malformed = [
        (&[0, 0, 0, 5, 0x40, 1, 5, 0][..], true),
        (&[0, 0, 0, 1, 0x40][..], true),
        (&[0, 8, 1][..], true),
    ];
    for (body, _) in malformed {
        let error = update::validate(body, false).expect_err("structural");
        assert_eq!(error_action(error, false), ErrorAction::NotifyAndClose);
    }
    let mut origin = valid_attributes();
    *origin.get_mut(3).expect("origin") = 3;
    let content =
        update::validate(&update_body(&origin, &[24, 203, 0, 113]), false).expect_err("ORIGIN");
    assert_eq!(content.subcode, 6);
    assert_eq!(
        error_action(content, false),
        ErrorAction::CountLogAndDiscard
    );
    assert_eq!(error_action(content, true), ErrorAction::NotifyAndClose);
    for (attrs, nlri, subcode) in [
        (vec![], vec![0], 3),
        (valid_attributes(), vec![33], 10),
        (vec![0x40, 99, 0], vec![], 2),
        (vec![0x80, 1, 1, 0], vec![], 4),
        (vec![0x40, 2, 3, 2, 1, 0], vec![], 11),
    ] {
        assert_eq!(
            update::validate(&update_body(&attrs, &nlri), false)
                .expect_err("invalid")
                .subcode,
            subcode
        );
    }
}
#[test]
fn mp_ipv6_reach_and_unreach_have_bounded_next_hop_and_nlri() {
    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 0];
    let mut reach = vec![0, 2, 1, 16];
    reach.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .expect("next hop")
            .octets(),
    );
    reach.extend_from_slice(&[0, 32, 0x20, 1, 0xd, 0xb8]);
    attrs.extend_from_slice(&[0x80, 14, u8::try_from(reach.len()).expect("length")]);
    attrs.extend(reach);
    let summary = update::validate(&update_body(&attrs, &[]), true).expect("MP_REACH");
    assert_eq!(summary.mp_announced.len(), 1);
    let withdraw = [0x80, 15, 8, 0, 2, 1, 32, 0x20, 1, 0xd, 0xb8];
    assert_eq!(
        update::validate(&update_body(&withdraw, &[]), true)
            .expect("MP_UNREACH")
            .mp_withdrawn,
        summary.mp_announced
    );
    assert!(update::validate(&update_body(&[0x80, 14, 4, 0, 2, 1, 4], &[]), true).is_err());
}
#[test]
fn passive_auth_and_status_plans_fail_closed_and_default_to_omission() {
    let base = Transport {
        local_port: None,
        peer_port: 179,
        passive: false,
        auth: AuthMode::Md5,
    };
    assert!(base.plan().expect("active").initiate);
    assert_eq!(
        Transport {
            passive: true,
            ..base
        }
        .plan(),
        Err(PlanError::PassiveNeedsListener)
    );
    let passive = Transport {
        local_port: Some(179),
        passive: true,
        ..base
    }
    .plan()
    .expect("passive");
    assert!(!passive.initiate);
    assert!(passive.wait_in_active);
    assert_eq!(passive.listen, Some(179));
    assert_eq!(
        Transport {
            auth: AuthMode::TcpAo,
            ..base
        }
        .plan(),
        Err(PlanError::UnsupportedTcpAo)
    );
    assert_eq!(
        Transport {
            peer_port: 0,
            ..base
        }
        .plan(),
        Err(PlanError::InvalidPort)
    );
    let row = Advertisement {
        peer: "upstream".into(),
        prefix: Prefix::new("192.0.2.0".parse().expect("IP"), 24).expect("prefix"),
        policy: "peer-upstream-export".into(),
    };
    assert_eq!(advertised_status(false, [row.clone()], 0), Ok(None));
    assert_eq!(
        advertised_status(true, [row.clone(), row.clone()], 1),
        Ok(Some(vec![row.clone()]))
    );
    assert_eq!(
        advertised_status(true, [row], 0),
        Err(PlanError::StatusTooLarge)
    );
}

#[test]
fn as_path_width_is_negotiated_and_partial_flags_are_validated() {
    let four = [0x40, 2, 6, 2, 1, 0, 1, 0, 2];
    assert!(update::validate(&update_body(&four, &[]), true).is_ok());
    assert_eq!(
        update::validate(&update_body(&four, &[]), false)
            .expect_err("wrong AS width")
            .subcode,
        11
    );
    assert_eq!(
        update::validate(&update_body(&[0xa0, 99, 0], &[]), false)
            .expect_err("partial nontransitive")
            .subcode,
        4
    );
    let oversized = vec![0; 4078];
    assert_eq!(
        update::validate(&oversized, false)
            .expect_err("body limit")
            .scope,
        ErrorScope::Framing
    );
}

#[test]
fn structural_failures_take_precedence_over_earlier_content_errors() {
    for body in [
        vec![0, 0, 0, 1, 0x40, 33], // truncated attribute plus invalid announced prefix
        vec![0, 1, 33],             // invalid withdrawn prefix plus absent attribute length
        vec![0, 0, 0, 5, 0x40, 1, 1, 3, 0x40], // invalid ORIGIN plus truncated next TLV
        vec![0, 0, 0, 7, 0x40, 1, 1, 3, 0x50, 2, 0], // bad ORIGIN plus short extended length
    ] {
        let error = update::validate(&body, false).expect_err("compound malformed UPDATE");
        assert_eq!(error.scope, ErrorScope::AttributeStructure);
        assert_eq!(error_action(error, false), ErrorAction::NotifyAndClose);
    }
}

#[test]
fn update_notification_payload_matrix() {
    for (attribute, code) in [
        (vec![0x40, 99, 1, 9], 2),
        (vec![0x80, 1, 1, 0], 4),
        (vec![0x50, 1, 0, 2, 0, 0], 5),
        (vec![0x40, 1, 1, 9], 6),
        (vec![0x40, 3, 4, 0, 0, 0, 0], 8),
        (vec![0x80, 14, 3, 0, 2, 1], 9),
    ] {
        let failure =
            update::validate_detailed(&update_body(&attribute, &[]), false).expect_err("malformed");
        assert_eq!(failure.error.subcode, code);
        assert_eq!(failure.data, attribute);
    }
    let failure = update::validate_detailed(&[0, 0, 0, 0, 0], false).expect_err("missing ORIGIN");
    assert_eq!(failure.error.subcode, 3);
    assert_eq!(failure.data, [1]);
    let failure = update::validate_detailed(&update_body(&[0x40, 2, 2, 3, 1], &[]), false)
        .expect_err("AS_PATH");
    assert_eq!(failure.error.subcode, 11);
    assert!(failure.data.is_empty());
    let failure = update::validate_detailed(&[0, 0, 0, 0, 33], false).expect_err("NLRI");
    assert_eq!(failure.error.subcode, 10);
    assert!(failure.data.is_empty());
}
#[test]
fn missing_attribute_data_identifies_each_mandatory_code_and_structure_wins() {
    for (attributes, missing) in [
        (vec![], 1),
        (vec![0x40, 1, 1, 0], 2),
        (vec![0x40, 1, 1, 0, 0x40, 2, 0], 3),
    ] {
        let failure = update::validate_detailed(&update_body(&attributes, &[0]), false)
            .expect_err("mandatory");
        assert_eq!((failure.error.code, failure.error.subcode), (3, 3));
        assert_eq!(failure.data, [missing]);
    }
    let failure = update::validate_detailed(&[0, 0, 0, 4, 0x40, 1, 2, 0], false)
        .expect_err("truncated value");
    assert_eq!(failure.error.scope, ErrorScope::AttributeStructure);
    assert_eq!(failure.data, [0x40, 1, 2, 0]);
    let failure = update::validate_detailed(&[0, 9, 33], false).expect_err("bad outer length");
    assert_eq!(failure.error.subcode, 1);
    assert!(failure.data.is_empty());
}
