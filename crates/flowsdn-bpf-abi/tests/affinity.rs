#![allow(clippy::unwrap_used)]

use flowsdn_bpf_abi::{MapBytes, affinity::*};

#[test]
fn ipv4_cookie_union_discriminator_and_padding_match_frozen_fixture() {
    let key = Lb4AffinityKey::with_cookie(0x0807060504030201, 0x1234);
    let fixture = [1, 2, 3, 4, 5, 6, 7, 8, 0x34, 0x12, 1, 0, 0, 0, 0, 0];
    assert_eq!(key.to_bytes(), fixture);
    let decoded = Lb4AffinityKey::from_bytes(fixture);
    assert_eq!(decoded.cookie(), 0x0807060504030201);
    assert_eq!(decoded.rev_nat_id(), 0x1234);
    assert!(decoded.uses_netns_cookie());
    let raw = Lb4AffinityKey {
        client_id: [1, 2, 3, 4, 0x81, 0x82, 0x83, 0x84],
        rev_nat_id: 0xabcd,
        flags: 0xfe,
        pad1: 0x99,
        pad2: 0x12345678,
    };
    let fixture = [
        1, 2, 3, 4, 0x81, 0x82, 0x83, 0x84, 0xcd, 0xab, 0xfe, 0x99, 0x78, 0x56, 0x34, 0x12,
    ];
    assert_eq!(raw.to_bytes(), fixture);
    assert!(!raw.uses_netns_cookie());
    assert_eq!(Lb4AffinityKey::from_bytes(fixture).to_bytes(), fixture);
}

#[test]
fn ipv6_union_preserves_full_address_and_zeroes_only_cookie_constructor_tail() {
    let cookie = Lb6AffinityKey::with_cookie(0x0807060504030201, 0xabcd);
    assert_eq!(
        cookie.to_bytes(),
        [
            1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0xcd, 0xab, 1, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(cookie.cookie(), 0x0807060504030201);
    let address = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
    let key = Lb6AffinityKey::with_address(address, 0x1234);
    let fixture = [
        0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0x34, 0x12, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(key.to_bytes(), fixture);
    assert!(!key.uses_netns_cookie());
    let decoded = Lb6AffinityKey::from_bytes(fixture);
    assert_eq!(decoded.client_id, address);
    assert_eq!(decoded.rev_nat_id(), 0x1234);
}

#[test]
fn discriminator_setter_preserves_unknown_flags_and_raw_union_bytes() {
    let raw4 = [0xaa; 16];
    let mut key4 = Lb4AffinityKey::from_bytes(raw4);
    key4.set_netns_cookie(true);
    assert_eq!(key4.flags, 0xab);
    assert!(key4.uses_netns_cookie());
    key4.set_netns_cookie(false);
    assert_eq!(key4.to_bytes(), raw4);
    let raw6 = [0xaa; 24];
    let mut key6 = Lb6AffinityKey::from_bytes(raw6);
    key6.set_netns_cookie(true);
    assert_eq!(key6.flags, 0xab);
    assert_eq!(key6.client_id, [0xaa; 16]);
    key6.set_netns_cookie(false);
    assert_eq!(key6.to_bytes(), raw6);
}

#[test]
fn packed_affinity_value_and_match_keep_ids_and_clock_as_raw_host_integers() {
    let value = LbAffinityVal {
        last_used: 0x0807060504030201,
        backend_id: 0x12345678,
        pad: 0x9abcdef0,
    };
    let fixture = [
        1, 2, 3, 4, 5, 6, 7, 8, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a,
    ];
    assert_eq!(value.to_bytes(), fixture);
    let decoded = LbAffinityVal::from_bytes(fixture);
    assert_eq!(decoded.last_used(), 0x0807060504030201);
    assert_eq!(decoded.backend_id(), 0x12345678);
    let value = LbAffinityMatch {
        backend_id: 0x12345678,
        rev_nat_id: 0x9abc,
        pad: 0xdef0,
    };
    let fixture = [0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde];
    assert_eq!(value.to_bytes(), fixture);
    let decoded = LbAffinityMatch::from_bytes(fixture);
    assert_eq!(decoded.backend_id(), 0x12345678);
    assert_eq!(decoded.rev_nat_id(), 0x9abc);
}

#[test]
fn skip_lb_v4_uses_host_order_for_unmarked_address_and_port() {
    let key = SkipLb4Key {
        netns_cookie: 0x0807060504030201,
        address: 0xc0000201,
        port: 0x1234,
        pad: 0xabcd,
    };
    let fixture = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 0, 0xc0, 0x34, 0x12, 0xcd, 0xab,
    ];
    assert_eq!(key.to_bytes(), fixture);
    let decoded = SkipLb4Key::from_bytes(fixture);
    assert_eq!(decoded.netns_cookie, 0x0807060504030201);
    assert_eq!(decoded.address, 0xc0000201);
    assert_eq!(decoded.port, 0x1234);
}

#[test]
fn skip_lb_v6_keeps_network_address_host_port_and_both_padding_fields() {
    let address = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
    let key = SkipLb6Key {
        netns_cookie: 0x0807060504030201,
        address,
        pad: 0x12345678,
        port: 0x9abc,
        pad2: 0xdef0,
    };
    let fixture = [
        1, 2, 3, 4, 5, 6, 7, 8, 0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0x78,
        0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde,
    ];
    assert_eq!(key.to_bytes(), fixture);
    let decoded = SkipLb6Key::from_bytes(fixture);
    assert_eq!(decoded.address, address);
    assert_eq!(decoded.port, 0x9abc);
    assert_eq!(decoded.pad, 0x12345678);
    assert_eq!(decoded.pad2, 0xdef0);
}

#[test]
fn every_raw_codec_roundtrips_reserved_bytes_and_packed_layouts() {
    macro_rules! check {
        ($ty:ty, $size:literal) => {
            assert_eq!(<$ty>::from_bytes([0xff; $size]).to_bytes(), [0xff; $size]);
            assert_eq!(core::mem::size_of::<$ty>(), $size);
        };
    }
    check!(Lb4AffinityKey, 16);
    check!(Lb6AffinityKey, 24);
    check!(LbAffinityVal, 16);
    check!(LbAffinityMatch, 8);
    check!(SkipLb4Key, 16);
    check!(SkipLb6Key, 32);
    assert_eq!(core::mem::align_of::<Lb4AffinityKey>(), 1);
    assert_eq!(core::mem::align_of::<Lb6AffinityKey>(), 1);
    assert_eq!(core::mem::align_of::<LbAffinityVal>(), 1);
    assert_eq!(core::mem::align_of::<LbAffinityMatch>(), 1);
}
