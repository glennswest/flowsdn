use flowsdn_hubble::{address_preference, EMITTER_NAME, EMITTER_VERSION};
use flowsdn_hubble::filters::{Addresses, FilterSet, FlowFilter, IpSet, validate_cel};
use flowsdn_hubble::monitor::{DecodeError, DropNotification};
use flowsdn_hubble::ring::{MemoryRing, Read};
use std::sync::Arc;

#[test]
fn address_spelling_prefix_boundaries_and_families() {
    let exact = IpSet::compile(&["2001:0DB8:0000:0000:0000:0000:0000:0001"]).expect("IPv6");
    assert!(exact.matches("2001:db8::1"));
    assert!(!exact.matches("2001:db8::2"));
    assert!(!exact.matches("not an address"));
    let prefix = IpSet::compile(&["192.0.2.129/25", "2001:db8:7::ffff/48"]).expect("CIDR");
    for ip in ["192.0.2.128", "192.0.2.255", "2001:0db8:0007:ffff::1"] { assert!(prefix.matches(ip), "{ip}"); }
    for ip in ["192.0.2.127", "192.0.3.0", "2001:db8:8::1"] { assert!(!prefix.matches(ip), "{ip}"); }
    let all_v4 = IpSet::compile(&["198.51.100.1/0"]).expect("zero prefix");
    assert!(all_v4.matches("203.0.113.1"));
    assert!(!all_v4.matches("::ffff:203.0.113.1"));
    assert!(IpSet::compile(&["::/0"]).expect("v6").matches("ffff::1"));
    assert!(IpSet::compile(&["192.0.2.1/32"]).expect("host").matches("192.0.2.1"));
    assert!(IpSet::compile(&["2001:db8::1/128"]).expect("host").matches("2001:0db8::1"));
    assert!(!IpSet::compile(&["::ffff:192.0.2.1"]).expect("mapped").matches("192.0.2.1"));
    for bad in ["", "1.2.3", "192.0.2.1/33", "::/129", "::/-1", "::/x", "::/64/64", "fe80::1%eth0"] {
        assert!(IpSet::compile(&[bad]).is_err(), "{bad}");
    }
}
#[test]
fn filtering_has_and_or_deny_and_unfilterable_loss() {
    let source = IpSet::compile(&["2001:db8::1", "192.0.2.1"]).expect("source");
    let destination = IpSet::compile(&["198.51.100.0/24"]).expect("destination");
    let filter = FlowFilter { source: Some(source), destination: Some(destination), translated_source: None };
    let mut set = FilterSet { allow: vec![filter], deny: vec![] };
    let event = Addresses { source: "2001:0db8::1", destination: "198.51.100.9", translated_source: "" };
    assert!(set.matches(Some(event)));
    assert!(!set.matches(Some(Addresses { destination: "203.0.113.1", ..event })));
    set.deny.push(FlowFilter::default());
    assert!(!set.matches(Some(event)));
    assert!(set.matches(None));
    let empty = IpSet::compile(&[] as &[&str]).expect("empty");
    assert!(!empty.matches("192.0.2.1"));
    assert!(FilterSet::default().matches(Some(event)));
}
#[test]
fn cel_rejected_before_stream_and_preference_preserves_explicit_false() {
    assert!(validate_cel(&[] as &[&str]).is_ok());
    for expression in ["", "true", "flow.IP.source == '192.0.2.1'"] {
        assert!(validate_cel(&[expression]).expect_err("unsupported").to_string().contains("experimental.cel_expression"));
    }
    for global in [None, Some(false), Some(true)] {
        for legacy in [None, Some(false), Some(true)] {
            let actual = address_preference(global, legacy);
            assert_eq!(actual.prefer_ipv6, global.or(legacy).unwrap_or(false));
            assert_eq!(actual.warn_deprecated, legacy.is_some());
        }
    }
    assert_eq!(EMITTER_NAME, "flowsdn");
    assert_eq!(EMITTER_VERSION, env!("CARGO_PKG_VERSION"));
}
fn put<const N: usize>(bytes: &mut [u8], offset: usize, value: [u8; N]) {
    let end = offset.checked_add(N).expect("fixture size");
    bytes.get_mut(offset..end).expect("fixture field").copy_from_slice(&value);
}
fn drop_sample(version: u8) -> Vec<u8> {
    let offset: usize = match version { 0 | 1 => 36, 2 => 40, _ => 48 };
    let mut data = vec![0; offset.checked_add(10).expect("sample")];
    put(&mut data, 0, [1, 133]); put(&mut data, 2, 257u16.to_le_bytes());
    put(&mut data, 8, 100u32.to_le_bytes()); put(&mut data, 12, 3u16.to_le_bytes());
    put(&mut data, 14, [version]); put(&mut data, 32, 0x01020304u32.to_le_bytes());
    if version >= 2 { put(&mut data, 36, [0x03]); }
    if version >= 3 { put(&mut data, 40, 0x0102030405060708u64.to_le_bytes()); }
    put(&mut data, offset, [4, 5, 6]);
    data
}
#[test]
fn versioned_drop_decodes_raw_interface_but_preserves_reference_projection() {
    for version in 0..=3 {
        let sample = drop_sample(version);
        let drop = DropNotification::decode(&sample).expect("drop");
        assert_eq!(drop.ifindex, 0x01020304);
        assert_eq!(drop.source, 257);
        assert_eq!(drop.packet, &[4, 5, 6]); // trailing perf alignment bytes excluded
        assert_eq!(drop.flow_interface(), None);
        assert_eq!(drop.flags, if version >= 2 { 3 } else { 0 });
        assert_eq!(drop.ip_trace_id, if version >= 3 { 0x0102030405060708 } else { 0 });
        for size in 0..sample.len().saturating_sub(7) {
            assert!(DropNotification::decode(sample.get(..size).expect("prefix")).is_err());
        }
    }
    let mut sample = drop_sample(3);
    put(&mut sample, 14, [4]);
    assert_eq!(DropNotification::decode(&sample), Err(DecodeError::UnknownVersion));
    put(&mut sample, 14, [3, 1]);
    assert_eq!(DropNotification::decode(&sample), Err(DecodeError::UnknownExtension));
    put(&mut sample, 15, [0]); put(&mut sample, 12, 101u16.to_le_bytes());
    assert_eq!(DropNotification::decode(&sample), Err(DecodeError::InvalidCaptureLength));
    put(&mut sample, 0, [4]);
    assert_eq!(DropNotification::decode(&sample), Err(DecodeError::WrongType));
}
#[test]
fn ring_is_bounded_reserves_newest_and_reports_each_overwritten_position() {
    for invalid in [0, 2, 4, 65536, u32::MAX] { assert!(MemoryRing::<u8>::new(invalid).is_err()); }
    for valid in [1, 3, 4095, 65535] { assert!(MemoryRing::<u8>::new(valid).is_ok()); }
    let mut ring = MemoryRing::new(3).expect("capacity");
    let mut cursor = 0;
    assert_eq!(ring.read_next(&mut cursor), Read::End); assert_eq!(cursor, 0);
    ring.push(10); assert_eq!(ring.read(0), Read::End);
    ring.push(20); assert_eq!(ring.read_next(&mut cursor), Read::Event(Arc::new(10)));
    assert_eq!(cursor, 1); assert_eq!(ring.read_next(&mut cursor), Read::End);
    for value in 30..=35 { ring.push(value); }
    assert_eq!(ring.capacity(), 3); assert_eq!(ring.len(), 3); assert_eq!(ring.oldest(), 4);
    for expected_cursor in 2..=4 { assert_eq!(ring.read_next(&mut cursor), Read::Lost { count: 1 }); assert_eq!(cursor, expected_cursor); }
    assert_eq!(ring.read_next(&mut cursor), Read::Event(Arc::new(32)));
    assert_eq!(ring.read(ring.next_sequence()), Read::End);
    let restarted = MemoryRing::<u32>::new(3).expect("restart");
    assert!(restarted.is_empty()); assert_eq!(restarted.next_sequence(), 0); assert_eq!(restarted.read(0), Read::End);
}
