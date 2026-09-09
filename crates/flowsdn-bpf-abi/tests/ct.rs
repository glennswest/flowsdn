use flowsdn_bpf_abi::{Be16, Be32, MapBytes, ct::*};

#[test]
fn conntrack_fixture_freezes_proxy_offset_and_mixed_byte_order() {
    let bytes = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x24, 0x23, 0x22, 0x21, 0x21, 0x84, 0x34, 0x12,
        0x01, 0xbb, 0x12, 0x18, 0x44, 0x33, 0x22, 0x11,
        0x54, 0x53, 0x52, 0x51, 0x64, 0x63, 0x62, 0x61,
    ];
    let entry = CtEntry::from_bytes(bytes);
    assert_eq!(entry.packets, 0x0102_0304_0506_0708);
    assert_eq!(entry.bytes, 0x1112_1314_1516_1718);
    assert_eq!(entry.lifetime, 0x2122_2324);
    assert_eq!(entry.flags, 0x8421);
    assert_eq!(entry.rev_nat_index, 0x1234);
    assert_eq!(entry.nat_port.get(), 443);
    assert_eq!(entry.tx_flags_seen, 0x12);
    assert_eq!(entry.rx_flags_seen, 0x18);
    assert_eq!(entry.src_sec_id, 0x1122_3344);
    assert_eq!(entry.last_tx_report, 0x5152_5354);
    assert_eq!(entry.last_rx_report, 0x6162_6364);
    assert_eq!(entry.service_backend_raw(), 0x0f0e_0d0c_0b0a_0908);
    assert_eq!(entry.to_bytes(), bytes);
}

#[test]
fn service_union_setter_clears_reserved_storage_only() {
    let mut entry = CtEntry::from_bytes([0xff; 56]);
    entry.set_service_backend(0x1234_5678);
    assert_eq!(entry.nat_addr_or_service, [0,0,0,0,0,0,0,0,0x78,0x56,0x34,0x12,0,0,0,0]);
    assert_eq!(entry.service_backend_raw(), 0x1234_5678);
    assert_eq!(entry.src_sec_id, u32::MAX);
    assert_eq!(entry.flags, u16::MAX);
}

#[test]
fn flag_masks_leave_reserved_positions_unnamed() {
    assert_eq!(flags::RX_CLOSING | flags::TX_CLOSING | flags::LB_LOOPBACK
        | flags::SEEN_NON_SYN | flags::NODE_PORT | flags::PROXY_REDIRECT
        | flags::DSR_INTERNAL | flags::FROM_L7LB | flags::FROM_TUNNEL, 0x05fb);
}

#[test]
fn nat_common_retains_unknown_bits_and_padding() {
    let bytes = [
        8,7,6,5,4,3,2,1, 0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        1,2,3,4,5,6,7,8, 9,10,11,12,13,14,15,16,
    ];
    let mut entry = NatEntry::from_bytes(bytes);
    assert_eq!(entry.created, 0x0102_0304_0506_0708);
    assert!(!entry.requires_conntrack());
    assert_eq!(entry.to_bytes(), bytes);
    entry.set_requires_conntrack(true);
    assert!(entry.requires_conntrack());
    assert_eq!(entry.needs_ct, u64::MAX);
    entry.set_requires_conntrack(false);
    assert_eq!(entry.to_bytes(), bytes);
}

#[test]
fn ipv4_translation_fixture_is_network_order_with_explicit_padding() {
    let expected = [
        1,0,0,0,0,0,0,0, 1,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        192,0,2,9, 0x1f,0x90, 0xa5,0x5a,
    ];
    let entry = Ipv4NatEntry {
        common: NatEntry { created: 1, needs_ct: 1, ..Default::default() },
        address: Be32::new(0xc000_0209), port: Be16::new(8080), pad: [0xa5, 0x5a],
    };
    assert_eq!(entry.to_bytes(), expected);
    assert_eq!(Ipv4NatEntry::from_bytes(expected), entry);
}

#[test]
fn ipv6_translation_fixture_preserves_full_address_and_tail() {
    let expected = [
        1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,
        0x01,0xbb, 1,2,3,4,5,6,
    ];
    let entry = Ipv6NatEntry::from_bytes(expected);
    assert_eq!(entry.common.created, 1);
    assert_eq!(entry.address, [0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1]);
    assert_eq!(entry.port.get(), 443);
    assert_eq!(entry.pad, [1,2,3,4,5,6]);
    assert_eq!(entry.to_bytes(), expected);
}
