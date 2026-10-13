#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
use flowsdn_bpf_abi::{MapBytes, policy::*};

#[test]
fn key_fixture_has_host_identity_and_network_port() {
    let key = PolicyKey::new(0x1234_5678, true, 6, 443, 16).unwrap();
    let bytes = [64, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 1, 6, 1, 0xbb];
    assert_eq!(key.to_bytes(), bytes);
    assert_eq!(PolicyKey::from_bytes(bytes), key);
}

#[test]
fn zero_based_port_ranges_retain_their_declared_prefix() {
    let key = PolicyKey::new(42, false, 6, 0, 6).unwrap();
    assert_eq!(key.prefixlen, 54);
    assert_eq!(key.dport.get(), 0);
    assert_eq!(PolicyKey::new(42, false, 6, 1023, 6).unwrap(), key);
    assert_eq!(
        PolicyKey::new(42, false, 6, 1024, 6).unwrap().dport.get(),
        1024
    );
    assert_eq!(PolicyKey::new(42, false, 6, 0, 16).unwrap().prefixlen, 64);
}

#[test]
fn wildcard_and_port_prefix_bounds_are_explicit() {
    assert_eq!(PolicyKey::new(0, false, 0, 0, 0).unwrap().prefixlen, 40);
    let all_ports = PolicyKey::new(1, false, 17, u16::MAX, 0).unwrap();
    assert_eq!(all_ports.prefixlen, 48);
    assert_eq!(all_ports.dport.get(), 0);
    assert!(PolicyKey::new(1, true, 0, 80, 16).is_err());
    assert!(PolicyKey::new(1, true, 0, 0, 6).is_err());
    assert!(PolicyKey::new(1, true, 6, 80, 17).is_err());
    let raw = [255; 12];
    assert_eq!(PolicyKey::from_bytes(raw).to_bytes(), raw);
}

#[test]
fn entry_fixture_and_constructors_keep_reserved_bits_zero() {
    let entry = PolicyEntry::new(15000, true, 24, 5, true, 0x1234_5678, 0xaabb_ccdd).unwrap();
    let bytes = [
        0x3a, 0x98, 0xc1, 0x85, 0x78, 0x56, 0x34, 0x12, 0xdd, 0xcc, 0xbb, 0xaa,
    ];
    assert_eq!(entry.to_bytes(), bytes);
    assert_eq!(PolicyEntry::from_bytes(bytes), entry);
    assert_eq!(entry.flags & 6, 0);
    for prefix in [0, 8, 16, 24] {
        assert!(PolicyEntry::new(0, false, prefix, 127, false, 0, 0).is_ok());
    }
    for prefix in [1, 7, 25, 31, 255] {
        assert!(PolicyEntry::new(0, false, prefix, 0, false, 0, 0).is_err());
    }
    assert!(PolicyEntry::new(0, false, 0, 128, false, 0, 0).is_err());
}

#[test]
fn all_flag_bytes_ignore_reserved_bits_without_losing_them() {
    for flags in 0..=u8::MAX {
        let bytes = [0, 0, flags, flags, 0, 0, 0, 0, 0, 0, 0, 0];
        let entry = PolicyEntry::from_bytes(bytes);
        assert_eq!(entry.denies(), flags & 1 == 1);
        assert_eq!(entry.lpm_prefix_length(), flags >> 3);
        assert_eq!(entry.auth_type(), flags & 127);
        assert_eq!(entry.has_explicit_auth_type(), flags & 128 != 0);
        assert_eq!(entry.to_bytes(), bytes);
        let with_reserved_flipped = PolicyEntry {
            flags: flags ^ 6,
            ..entry
        };
        assert_eq!(with_reserved_flipped.denies(), entry.denies());
        assert_eq!(
            with_reserved_flipped.lpm_prefix_length(),
            entry.lpm_prefix_length()
        );
    }
}

#[test]
fn stats_fixtures_preserve_padding_and_full_width_counters() {
    let bytes = [
        0x34, 0x12, 0xa5, 24, 0x78, 0x56, 0x34, 0x12, 0xfd, 17, 0x1f, 0x90,
    ];
    let key = PolicyStatsKey::from_bytes(bytes);
    assert_eq!(key.endpoint_id, 0x1234);
    assert_eq!(key.pad1, 0xa5);
    assert_eq!(key.sec_label, 0x1234_5678);
    assert_eq!(key.egress, 0xfd);
    assert_eq!(key.dport.get(), 8080);
    assert_eq!(key.to_bytes(), bytes);
    let counters = [
        8, 7, 6, 5, 4, 3, 2, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];
    let value = PolicyStatsValue::from_bytes(counters);
    assert_eq!(value.packets, 0x0102_0304_0506_0708);
    assert_eq!(value.bytes, u64::MAX);
    assert_eq!(value.to_bytes(), counters);
}

#[test]
fn endpoint_policy_key_leads_with_the_endpoint() {
    let inner = PolicyKey::new(0x1234_5678, true, 6, 443, 16).unwrap();
    let key = EndpointPolicyKey::new(7, inner);
    assert_eq!(key.prefixlen, ENDPOINT_POLICY_FULL_PREFIX);
    let bytes = [
        96, 0, 0, 0, 7, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 1, 6, 1, 0xbb,
    ];
    assert_eq!(key.to_bytes(), bytes);
    assert_eq!(EndpointPolicyKey::from_bytes(bytes), key);
    assert_eq!(key.policy_key(), inner);
    let wildcard = EndpointPolicyKey::new(7, PolicyKey::new(0, false, 0, 0, 0).unwrap());
    assert_eq!(wildcard.prefixlen, 72);
}

#[test]
fn policy_endpoint_and_flow_round_trip() {
    let endpoint = PolicyEndpoint {
        endpoint: 7,
        flags: enforce::INGRESS | enforce::EGRESS,
    };
    assert_eq!(endpoint.to_bytes(), [7, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(PolicyEndpoint::from_bytes(endpoint.to_bytes()), endpoint);
    let mut flow = PolicyCtKey {
        sport: flowsdn_bpf_abi::Be16::new(40000),
        dport: flowsdn_bpf_abi::Be16::new(80),
        protocol: 6,
        family: flowsdn_bpf_abi::FAMILY_V4,
        egress: 1,
        ..Default::default()
    };
    flow.saddr[..4].copy_from_slice(&[10, 0, 0, 7]);
    flow.daddr[..4].copy_from_slice(&[10, 0, 1, 5]);
    let bytes = flow.to_bytes();
    assert_eq!(bytes[32..40], [0x9c, 0x40, 0, 80, 6, 1, 1, 0]);
    assert_eq!(PolicyCtKey::from_bytes(bytes), flow);
    let value = PolicyCtValue {
        expires: 99,
        flags: POLICY_CT_CLOSING,
        pad: 0,
    };
    assert_eq!(PolicyCtValue::from_bytes(value.to_bytes()), value);
}
