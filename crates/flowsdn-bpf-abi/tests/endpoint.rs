use flowsdn_bpf_abi::{MapBytes, endpoint::*};

#[test]
fn endpoint_keys_use_network_union_and_host_cluster_identity() {
    let v4 = EndpointKey::v4([192, 0, 2, 7], 9, 0x1234);
    let fixture = [192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 9, 0x34, 0x12];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(EndpointKey::from_bytes(fixture).cluster_id(), 0x1234);
    let address = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6];
    let v6 = EndpointKey::v6(address, 0xab, 0xcdef);
    let fixture = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 2, 0xab, 0xef, 0xcd];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(EndpointKey::from_bytes(fixture).address, address);
    assert_eq!(core::mem::align_of::<EndpointKey>(), 1);
}

#[test]
fn endpoint_value_covers_all_offsets_and_preserves_mac_as_raw_integer() {
    let value = EndpointInfo {
        ifindex: 0x04030201, unused: 0x0605, lxc_id: 0x0807,
        flags: 0x0c0b0a09, rt_info: 0x100f0e0d, mac: 0x1817161514131211,
        node_mac: 0x201f1e1d1c1b1a19, sec_id: 0x24232221,
        parent_ifindex: 0x28272625, pad: [0x2c2b2a29, 0x302f2e2d],
    };
    let fixture = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48];
    assert_eq!(value.to_bytes(), fixture);
    let decoded = EndpointInfo::from_bytes(fixture);
    assert_eq!(decoded.mac, 0x1817161514131211);
    assert_eq!(decoded.node_mac, 0x201f1e1d1c1b1a19);
    assert_eq!(decoded.pad, [0x2c2b2a29, 0x302f2e2d]);
    assert_eq!(decoded.to_bytes(), fixture);
    assert_eq!([endpoint_flags::HOST, endpoint_flags::AT_HOST_NS, endpoint_flags::NO_SNAT_V4, endpoint_flags::NO_SNAT_V6], [1, 2, 4, 8]);
}

#[test]
fn node_keys_zero_constructor_padding_and_use_distinct_family_layout() {
    let v4 = NodeKey::v4([203, 0, 113, 7]);
    let fixture = [0, 0, 0, 1, 203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(v4.to_bytes(), fixture);
    let decoded = NodeKey::from_bytes(fixture);
    assert_eq!(decoded.family, 1);
    let v6 = NodeKey::v6([0xab; 16]);
    let fixture = [0, 0, 0, 2, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(NodeKey::from_bytes(fixture).address, [0xab; 16]);
    let raw = NodeKey { pad1: 0x1234, pad2: 0x56, family: 0x78, address: [0x9a; 16] };
    assert_eq!(NodeKey::from_bytes(raw.to_bytes()).to_bytes(), raw.to_bytes());
}

#[test]
fn node_value_and_subnet_identity_are_explicit_host_order() {
    let value = NodeValue { id: 0x1234, spi: 0x56, pad: 0x78 };
    assert_eq!(value.to_bytes(), [0x34, 0x12, 0x56, 0x78]);
    let decoded = NodeValue::from_bytes([0x34, 0x12, 0x56, 0x78]);
    assert_eq!(decoded.id, 0x1234);
    assert_eq!(decoded.spi, 0x56);
    let subnet = SubnetValue { identity: 0x12345678 };
    assert_eq!(subnet.to_bytes(), [0x78, 0x56, 0x34, 0x12]);
    assert_eq!(SubnetValue::from_bytes(subnet.to_bytes()).identity, 0x12345678);
}

#[test]
#[allow(clippy::unwrap_used)]
fn subnet_prefixes_count_static_family_bits_and_preserve_address_host_bits() {
    let v4 = SubnetKey::v4([192, 0, 2, 99], 24).unwrap();
    let fixture = [56, 0, 0, 0, 0, 0, 0, 1, 192, 0, 2, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(v4.to_bytes(), fixture);
    assert_eq!(SubnetKey::from_bytes(fixture).prefixlen(), 56);
    assert_eq!(SubnetKey::v4([0; 4], 0).unwrap().prefixlen(), 32);
    assert_eq!(SubnetKey::v4([0; 4], 32).unwrap().prefixlen(), 64);
    assert!(SubnetKey::v4([0; 4], 33).is_err());
    let v6 = SubnetKey::v6([0xab; 16], 128).unwrap();
    let fixture = [160, 0, 0, 0, 0, 0, 0, 2, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab];
    assert_eq!(v6.to_bytes(), fixture);
    assert_eq!(SubnetKey::v6([0; 16], 0).unwrap().prefixlen(), 32);
    assert!(SubnetKey::v6([0; 16], 129).is_err());
    assert!(SubnetKey::v6([0; 16], u32::MAX).is_err());
    assert_eq!(core::mem::align_of::<SubnetKey>(), 1);
}

#[test]
fn all_raw_codecs_preserve_unknown_flags_families_union_tails_and_padding() {
    macro_rules! check {
        ($ty:ty, $size:literal) => {
            assert_eq!(<$ty>::from_bytes([0xa5; $size]).to_bytes(), [0xa5; $size]);
            assert_eq!(core::mem::size_of::<$ty>(), $size);
        };
    }
    check!(EndpointKey, 20); check!(EndpointInfo, 48);
    check!(NodeKey, 20); check!(NodeValue, 4);
    check!(SubnetKey, 24); check!(SubnetValue, 4);
}
