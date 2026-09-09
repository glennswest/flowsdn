#![allow(clippy::unwrap_used)]
use flowsdn_bpf_abi::tunnel::*;

#[test]
fn identities_fold_before_encoding_and_host_is_rejected_on_receive() {
    for (input, wire) in [(0, 0), (1, 6), (2, 2), (9, 2), (10, 2), (0xffffff, 0xffffff)] {
        assert_eq!(TunnelIdentity::for_encapsulation(input).unwrap().get(), wire);
    }
    for identity in [0x1000000, 0x80000001, u32::MAX] {
        assert_eq!(TunnelIdentity::for_encapsulation(identity), Err(WireError::IdentityTooWide));
    }
    assert_eq!(TunnelIdentity::from_wire(1), Err(WireError::HostIdentity));
    let world = TunnelIdentity::from_wire(2).unwrap();
    assert_eq!(world.for_decapsulation(IpFamily::V4, true), 9);
    assert_eq!(world.for_decapsulation(IpFamily::V6, true), 10);
    assert_eq!(world.for_decapsulation(IpFamily::V6, false), 2);
    assert_eq!(TunnelIdentity::from_wire(6).unwrap().for_decapsulation(IpFamily::V4, true), 6);
}

#[test]
fn vxlan_identity_network_word_and_flags_are_exact() {
    let header = VxlanHeader { identity: TunnelIdentity::for_encapsulation(0x123456).unwrap() };
    let wire = [8, 0, 0, 0, 0x12, 0x34, 0x56, 0];
    assert_eq!(header.to_bytes(), wire);
    assert_eq!(VxlanHeader::from_bytes(wire), Ok(header));
    assert_eq!(VxlanHeader::from_bytes([8, 0, 0, 0, 0, 0, 1, 0]), Err(WireError::HostIdentity));
    assert_eq!(VxlanHeader::from_bytes([8, 0, 0, 0, 0, 0, 2, 1]), Err(WireError::Reserved));
    for offset in 0..4 {
        let mut altered = wire;
        *altered.get_mut(offset).unwrap() ^= 1;
        assert_eq!(VxlanHeader::from_bytes(altered), Err(WireError::Unsupported));
    }
}

#[test]
fn geneve_header_preserves_critical_flag_and_option_word_units() {
    let identity = TunnelIdentity::for_encapsulation(0xabcdef).unwrap();
    for (words, flags) in [(0, 0), (3, 0), (3, 0x40), (6, 0x40), (63, 0x40)] {
        let header = GeneveHeader::new(identity, words, flags != 0).unwrap();
        let wire = [words, flags, 0x65, 0x58, 0xab, 0xcd, 0xef, 0];
        assert_eq!(header.to_bytes(), wire);
        assert_eq!(GeneveHeader::from_bytes(wire), Ok(header));
        assert_eq!(header.option_words(), words);
    }
    assert_eq!(GeneveHeader::new(identity, 64, false), Err(WireError::Length));
    for wire in [
        [0x40, 0, 0x65, 0x58, 0, 0, 2, 0],
        [0, 0x80, 0x65, 0x58, 0, 0, 2, 0],
        [0, 0, 8, 0, 0, 0, 2, 0],
    ] { assert_eq!(GeneveHeader::from_bytes(wire), Err(WireError::Unsupported)); }
    assert_eq!(GeneveHeader::from_bytes([0, 1, 0x65, 0x58, 0, 0, 2, 0]), Err(WireError::Reserved));
    assert_eq!(GeneveHeader::from_bytes([0, 0, 0x65, 0x58, 0, 0, 1, 0]), Err(WireError::HostIdentity));
}

#[test]
fn dsr_known_vectors_include_header_but_length_counts_only_payload_words() {
    let v4 = DsrIpv4 { address: [192, 0, 2, 7], port: 0x1234 };
    let bytes4 = [1, 0x4b, 0x81, 2, 192, 0, 2, 7, 0x12, 0x34, 0, 0];
    assert_eq!(v4.to_bytes(), bytes4);
    assert_eq!(DsrIpv4::from_bytes(bytes4), Ok(v4));
    let v6 = DsrIpv6 { address: [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6], port: 0xabcd };
    let bytes6 = [1, 0x4b, 0x81, 5, 0x20, 1, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0xab, 0xcd, 0, 0];
    assert_eq!(v6.to_bytes(), bytes6);
    assert_eq!(DsrIpv6::from_bytes(bytes6), Ok(v6));
    for (offset, value, error) in [(0, 0, WireError::Unsupported), (2, 1, WireError::Unsupported), (3, 3, WireError::Length), (3, 0x22, WireError::Reserved), (10, 1, WireError::Reserved), (11, 1, WireError::Reserved)] {
        let mut altered = bytes4;
        *altered.get_mut(offset).unwrap() = value;
        assert_eq!(DsrIpv4::from_bytes(altered), Err(error));
    }
    for (offset, value, error) in [(1, 0, WireError::Unsupported), (2, 0, WireError::Unsupported), (3, 6, WireError::Length), (3, 0x25, WireError::Reserved), (22, 1, WireError::Reserved), (23, 1, WireError::Reserved)] {
        let mut altered = bytes6;
        *altered.get_mut(offset).unwrap() = value;
        assert_eq!(DsrIpv6::from_bytes(altered), Err(error));
    }
}
