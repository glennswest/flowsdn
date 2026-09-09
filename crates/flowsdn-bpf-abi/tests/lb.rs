#![allow(clippy::unwrap_used)]

use flowsdn_bpf_abi::{Be16, Be32, MapBytes, lb::*};

#[test]
fn service_keys_keep_network_ports_and_host_slots_distinct() {
    let v4 = Lb4Key {
        address: Be32([192, 0, 2, 9]), dport: Be16::new(443),
        backend_slot: 0x1234, proto: 6, scope: 1, pad: [0xab, 0xcd],
    };
    let fixture = [192, 0, 2, 9, 1, 187, 0x34, 0x12, 6, 1, 0xab, 0xcd];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(Lb4Key::from_bytes(fixture), v4);
    let v6 = Lb6Key {
        address: [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6],
        dport: Be16::new(0x1234), backend_slot: 0x5678, proto: 17, scope: 0,
        pad: [0x98, 0x76],
    };
    let fixture = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6,
        0x12, 0x34, 0x78, 0x56, 17, 0, 0x98, 0x76];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(Lb6Key::from_bytes(fixture), v6);
}

#[test]
fn service_union_and_split_flags_match_master_slot_contract() {
    let mut value = LbService { count: 0x1234, rev_nat_index: 0x5678, qcount: 0x9abc, ..Default::default() };
    value.set_affinity(Algorithm::Maglev, 0x123456).unwrap();
    value.set_service_flags(service_flags::NODE_PORT | service_flags::FWD_MODE_DSR | service_flags::SOURCE_RANGE_DENY);
    let fixture = [0x56, 0x34, 0x12, 2, 0x34, 0x12, 0x78, 0x56, 2, 0xc0, 0xbc, 0x9a];
    assert_eq!(value.to_bytes(), fixture);
    assert_eq!(LbService::from_bytes(fixture), value);
    assert_eq!(value.affinity_seconds(), 0x123456);
    assert_eq!(value.algorithm_code(), 2);
    assert_eq!(value.service_flags(), 0xc002);
    assert_eq!(value.backend_id(), 0x02123456, "backend-slot interpretation preserves the complete raw union");
    let before = value;
    assert!(value.set_affinity(Algorithm::Random, 0x01000000).is_err());
    assert_eq!(value, before);
    value.set_affinity(Algorithm::Random, 0x00ffffff).unwrap();
    assert_eq!(value.union_raw, 0x01ffffff);
    let unknown = LbService { union_raw: 0xfe112233, flags: 0xff, flags2: 0xff, ..Default::default() };
    assert_eq!(unknown.algorithm_code(), 0xfe);
    assert_eq!(LbService::from_bytes(unknown.to_bytes()), unknown);
}

#[test]
fn backend_states_cluster_and_zone_use_independent_bytes() {
    let v4 = Lb4Backend { address: Be32([203, 0, 113, 7]), port: Be16::new(8080), proto: 6,
        flags: backend_state::QUARANTINED, cluster_id: 0x1234, zone: 5, pad: 0xee };
    let fixture = [203, 0, 113, 7, 0x1f, 0x90, 6, 2, 0x34, 0x12, 5, 0xee];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(Lb4Health::from_bytes(fixture), v4);
    let v6 = Lb6Backend { address: [0x12; 16], port: Be16::new(0xabcd), proto: 17,
        flags: backend_state::MAINTENANCE, cluster_id: 0x5678, zone: 9, pad: 0xef };
    let fixture = [0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
        0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0xab, 0xcd, 17, 3, 0x78, 0x56, 9, 0xef];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(Lb6Health::from_bytes(fixture), v6);
    assert_eq!([backend_state::ACTIVE, backend_state::TERMINATING, backend_state::QUARANTINED, backend_state::MAINTENANCE], [0, 1, 2, 3]);
}

#[test]
fn reverse_nat_is_packed_without_trailing_padding() {
    let v4 = Lb4ReverseNat { address: Be32([192, 0, 2, 1]), port: Be16::new(0x1234) };
    let fixture = [192, 0, 2, 1, 0x12, 0x34];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(Lb4ReverseNat::from_bytes(fixture), v4);
    let v6 = Lb6ReverseNat { address: [0xab; 16], port: Be16::new(0x5678) };
    let fixture = [0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x56, 0x78];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(Lb6ReverseNat::from_bytes(fixture), v6);
    assert_eq!(core::mem::align_of::<Lb4ReverseNat>(), 1);
    assert_eq!(core::mem::align_of::<Lb6ReverseNat>(), 1);
}

#[test]
fn source_ranges_add_static_prefix_bits_and_zero_only_constructor_padding() {
    let v4 = Lb4SrcRangeKey::new([192, 0, 2, 99], 24, 0x1234).unwrap();
    assert_eq!(v4.to_bytes(), [56, 0, 0, 0, 0x34, 0x12, 0, 0, 192, 0, 2, 99]);
    assert_eq!(Lb4SrcRangeKey::new([0; 4], 0, 0).unwrap().prefixlen, 32);
    assert_eq!(Lb4SrcRangeKey::new([0; 4], 32, 0).unwrap().prefixlen, 64);
    assert!(Lb4SrcRangeKey::new([0; 4], 33, 0).is_err());
    let v6 = Lb6SrcRangeKey::new([0xcd; 16], 128, 0x5678).unwrap();
    let fixture = [160, 0, 0, 0, 0x78, 0x56, 0, 0, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(Lb6SrcRangeKey::new([0; 16], 0, 0).unwrap().prefixlen, 32);
    assert!(Lb6SrcRangeKey::new([0; 16], u32::MAX, 0).is_err());
}

#[test]
fn socket_revnat_cookie_padding_and_entry_indices_are_host_order() {
    let v4 = Ipv4RevnatTuple { cookie: 0x0807060504030201, address: Be32([192, 0, 2, 8]),
        port: Be16::new(0x1234), pad: 0xabcd };
    let fixture = [1, 2, 3, 4, 5, 6, 7, 8, 192, 0, 2, 8, 0x12, 0x34, 0xcd, 0xab];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(Ipv4RevnatTuple::from_bytes(fixture), v4);
    let value = Ipv4RevnatEntry { address: Be32([203, 0, 113, 8]), port: Be16::new(0x1234), rev_nat_index: 0x5678 };
    assert_eq!(value.to_bytes(), [203, 0, 113, 8, 0x12, 0x34, 0x78, 0x56]);
    let v6 = Ipv6RevnatTuple { cookie: 0x0807060504030201, address: [0x99; 16], port: Be16::new(0x1234), pad: 0x5678, pad2: 0xabcdef01 };
    let fixture = [1, 2, 3, 4, 5, 6, 7, 8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x12, 0x34, 0x78, 0x56, 1, 0xef, 0xcd, 0xab];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(Ipv6RevnatTuple::from_bytes(fixture), v6);
    let value = Ipv6RevnatEntry { address: [0x11; 16], port: Be16::new(0x1234), rev_nat_index: 0x5678 };
    assert_eq!(value.to_bytes(), [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x12, 0x34, 0x78, 0x56]);
}

#[test]
fn activity_layout_preserves_independent_open_close_counters() {
    let key = LbActKey { svc_id: 0x1234, zone: 7, pad: 0xab };
    assert_eq!(key.to_bytes(), [0x34, 0x12, 7, 0xab]);
    assert_eq!(LbActKey::from_bytes(key.to_bytes()), key);
    let value = LbActValue { opened: 0x12345678, closed: 0x9abcdef0 };
    assert_eq!(value.to_bytes(), [0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a]);
    assert_eq!(LbActValue::from_bytes(value.to_bytes()), value);
}

#[test]
fn every_codec_preserves_raw_padding_and_unknown_bits() {
    macro_rules! check {
        ($ty:ty, $size:literal) => {{
            let bytes = [0xa5; $size];
            assert_eq!(<$ty>::from_bytes(bytes).to_bytes(), bytes);
        }};
    }
    check!(Lb4Key, 12); check!(Lb6Key, 24); check!(LbService, 12);
    check!(Lb4Backend, 12); check!(Lb6Backend, 24);
    check!(Lb4ReverseNat, 6); check!(Lb6ReverseNat, 18);
    check!(Lb4SrcRangeKey, 12); check!(Lb6SrcRangeKey, 24);
    check!(Ipv4RevnatTuple, 16); check!(Ipv4RevnatEntry, 8);
    check!(Ipv6RevnatTuple, 32); check!(Ipv6RevnatEntry, 20);
    check!(LbActKey, 4); check!(LbActValue, 8);
}
