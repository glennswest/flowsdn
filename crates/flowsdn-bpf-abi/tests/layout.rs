#![allow(clippy::unwrap_used)]
use flowsdn_bpf_abi::*;

#[test]
fn network_fields_are_distinct_from_host_order_fields() {
    assert_eq!(Be16::new(0x1234).0,[0x12,0x34]);
    assert_eq!(Be32::new(0x12345678).0,[0x12,0x34,0x56,0x78]);
    assert_eq!(Be16([0xab,0xcd]).get(),0xabcd);
    assert_eq!(Be32([1,2,3,4]).get(),0x01020304);
}

#[test]
fn ipv4_connection_tuple_matches_network_byte_fixture_without_direction_swaps() {
    let tuple=Ipv4CtTuple{daddr:Be32([192,0,2,1]),saddr:Be32([198,51,100,2]),dport:Be16::new(443),sport:Be16::new(12345),nexthdr:6,flags:ct_flags::IN|ct_flags::RELATED};
    let fixture=[192,0,2,1,198,51,100,2,1,187,48,57,6,3];
    assert_eq!(tuple.to_bytes(),fixture);assert_eq!(Ipv4CtTuple::from_bytes(fixture),tuple);
}

#[test]
fn ipv6_tuple_preserves_full_addresses_ports_and_unknown_flag_bits() {
    let mut bytes=[0xff;38]; bytes.get_mut(32..36).unwrap().copy_from_slice(&[0x12,0x34,0x56,0x78]);
    let tuple=Ipv6CtTuple::from_bytes(bytes);assert_eq!(tuple.dport.get(),0x1234);assert_eq!(tuple.sport.get(),0x5678);assert_eq!(tuple.to_bytes(),bytes);
}

#[test]
fn lpm_prefix_bounds_and_host_order_header_match_fixtures() {
    assert_eq!(LpmV4Key::new([192,0,2,0],24).unwrap().to_bytes(),[24,0,0,0,192,0,2,0]);
    assert!(LpmV4Key::new([0;4],33).is_err());assert!(LpmV6Key::new([0;16],129).is_err());
    let key=LpmV6Key::new([0;16],128).unwrap();assert_eq!(key.to_bytes().get(..4),Some([128,0,0,0].as_slice()));assert_eq!(LpmV6Key::from_bytes(key.to_bytes()),key);
}

#[test]
fn ipcache_static_prefix_family_cluster_and_padding_are_exact() {
    let key=IpCacheKey::v4([192,0,2,0],24,0x1234).unwrap();
    assert_eq!(key.to_bytes(),[56,0,0,0,0x34,0x12,0,1,192,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    let key=IpCacheKey::v6([0xff;16],128,0).unwrap();assert_eq!(key.prefixlen(),160);assert_eq!(key.family,FAMILY_V6);
    assert!(IpCacheKey::v4([0;4],33,0).is_err());assert!(IpCacheKey::v6([0;16],u32::MAX,0).is_err());
}

#[test]
fn raw_decoding_preserves_padding_and_future_flags() {
    let bytes=[0xa5;24];assert_eq!(IpCacheKey::from_bytes(bytes).to_bytes(),bytes);
    assert_eq!(RemoteEndpointInfo::from_bytes(bytes).to_bytes(),bytes);
    let value=RemoteEndpointInfo{sec_identity:0x12345678,tunnel_endpoint:[1;16],key:7,flags:remote_flags::HAS_TUNNEL_ENDPOINT|remote_flags::IPV6_TUNNEL_ENDPOINT,..Default::default()};
    assert_eq!(value.to_bytes().get(..4),Some([0x78,0x56,0x34,0x12].as_slice()));
    assert_eq!(value.to_bytes().get(20..),Some([0,0,7,6].as_slice()));
}
