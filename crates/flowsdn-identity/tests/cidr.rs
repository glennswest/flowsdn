use flowsdn_identity::cidr::{CidrError, CidrPrefix, cidr_selector_matches};
use flowsdn_identity::labels::Label;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn prefix(text: &str) -> CidrPrefix { text.parse().expect("valid prefix fixture") }

#[test]
fn ipv4_canonical_masking_and_label_roundtrip() {
    for (input, canonical) in [("10.23.45.67/8", "10.0.0.0/8"), ("192.0.2.129/25", "192.0.2.128/25"), ("192.0.2.3/31", "192.0.2.2/31"), ("192.0.2.3/32", "192.0.2.3/32")] {
        let value = prefix(input);
        assert_eq!(value.to_string(), canonical);
        assert_eq!(value.encoded_key(), canonical);
        let label = value.to_label().expect("non-world");
        assert_eq!(label.source(), "cidr");
        assert!(label.value().is_empty());
        assert_eq!(CidrPrefix::from_label(&label), Ok(value));
    }
}

#[test]
fn ipv6_leading_trailing_colons_and_canonical_compression() {
    for (input, canonical, key) in [
        ("::1/128", "::1/128", "0--1/128"),
        ("fd00::beef/64", "fd00::/64", "fd00--0/64"),
        ("2001:0DB8:0:0:0:0:0:1/128", "2001:db8::1/128", "2001-db8--1/128"),
        ("::/64", "::/64", "0--0/64"),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/127", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", "ffff-ffff-ffff-ffff-ffff-ffff-ffff-fffe/127"),
    ] {
        let value = prefix(input);
        assert_eq!(value.to_string(), canonical);
        assert_eq!(value.encoded_key(), key);
        assert_eq!(CidrPrefix::decode_key(key), Ok(value));
        assert_eq!(CidrPrefix::from_label(&value.to_label().expect("non-world")), Ok(value));
    }
}

#[test]
fn zero_prefix_omits_cidr_identity_label_but_retains_family_for_selectors() {
    let v4 = prefix("192.0.2.1/0");
    let v6 = prefix("2001:db8::1/0");
    assert_eq!(v4.to_string(), "0.0.0.0/0");
    assert_eq!(v6.to_string(), "::/0");
    assert!(v4.is_world() && v6.is_world());
    assert!(v4.to_label().is_none() && v6.to_label().is_none());
    assert!(v4.contains_prefix(prefix("203.0.113.4/32")));
    assert!(v6.contains_prefix(prefix("ffff::/16")));
    assert!(!v4.contains_prefix(v6));
    assert!(!v6.contains_prefix(v4));
    assert_eq!(CidrPrefix::decode_key("0--0/0"), Ok(v6));
    assert_eq!(CidrPrefix::from_label(&Label::parse("reserved:world").expect("label")), Err(CidrError::InvalidLabel));
}

#[test]
fn prefix_boundaries_and_invalid_text_are_rejected() {
    for text in ["10.0.0.1/33", "::1/129", "::/256"] { assert_eq!(text.parse::<CidrPrefix>(), Err(CidrError::InvalidLength)); }
    for text in ["10.0.0.1", "10.0.0.1/", "10.0.0.1/-1", "10.0.0.1/+1", "::/1/2", "::/ 1", "::/１"] { assert_eq!(text.parse::<CidrPrefix>(), Err(CidrError::InvalidPrefix)); }
    for text in ["300.0.0.1/24", "192.168.001.1/24", "fe80::1%eth0/64", "[::1]/128", " ::1/128"] { assert_eq!(text.parse::<CidrPrefix>(), Err(CidrError::InvalidAddress)); }
    for key in ["0---1/128", "fffff--0/64", "192.0.2.1/33"] { assert!(CidrPrefix::decode_key(key).is_err()); }
    assert_eq!(CidrPrefix::decode_key(&"a".repeat(65)), Err(CidrError::EncodedKeyTooLong));
}

#[test]
fn containment_observes_prefix_length_and_both_network_edges() {
    let selector = prefix("192.0.2.128/25");
    for address in ["192.0.2.128", "192.0.2.255"] { assert!(selector.contains_address(address.parse().expect("address"))); }
    for address in ["192.0.2.127", "192.0.3.0"] { assert!(!selector.contains_address(address.parse().expect("address"))); }
    assert!(selector.contains_prefix(prefix("192.0.2.255/32")));
    assert!(!selector.contains_prefix(prefix("192.0.2.0/24")));
    assert!(prefix("2001:db8:8000::/33").contains_prefix(prefix("2001:db8:ffff::/48")));
    assert!(!prefix("2001:db8:8000::/33").contains_prefix(prefix("2001:db8:7fff::/48")));
}

#[test]
fn mapped_ipv6_is_not_coerced_to_ipv4() {
    let mapped = prefix("::ffff:192.0.2.1/128");
    assert!(mapped.network().is_ipv6());
    assert_eq!(CidrPrefix::decode_key(&mapped.encoded_key()), Ok(mapped));
    assert!(!prefix("192.0.2.0/24").contains_prefix(mapped));
    assert!(!prefix("::ffff:0:0/96").contains_prefix(prefix("192.0.2.1/32")));
    assert!(prefix("::ffff:0:0/96").contains_prefix(mapped));
}

#[test]
fn all_prefix_lengths_mask_and_roundtrip_without_shift_overflow() {
    for length in 0..=32 {
        let value = CidrPrefix::new(IpAddr::V4(Ipv4Addr::BROADCAST), length).expect("length");
        assert_eq!(value.prefix_len(), length);
        let IpAddr::V4(network) = value.network() else { panic!("family changed"); };
        assert_eq!(u32::from(network).count_ones(), u32::from(length));
        assert_eq!(CidrPrefix::decode_key(&value.encoded_key()), Ok(value));
    }
    for length in 0..=128 {
        let value = CidrPrefix::new(IpAddr::V6(Ipv6Addr::from(u128::MAX)), length).expect("length");
        let IpAddr::V6(network) = value.network() else { panic!("family changed"); };
        assert_eq!(u128::from(network).count_ones(), u32::from(length));
        assert_eq!(CidrPrefix::decode_key(&value.encoded_key()), Ok(value));
    }
}

#[test]
fn cidr_labels_match_by_containment_without_general_source_rules() {
    let selector = Label::parse("cidr:2001-db8--0/32").expect("label");
    let candidate = Label::parse("cidr:2001-db8-1--1234/64").expect("label");
    assert_eq!(cidr_selector_matches(&selector, &candidate), Ok(true));
    assert_eq!(cidr_selector_matches(&candidate, &selector), Ok(false));
    let other = Label::parse("cidr:2001-db9--0/32").expect("label");
    assert_eq!(cidr_selector_matches(&selector, &other), Ok(false));
    let any = Label::parse_selector("2001-db8--0/32").expect("selector");
    assert_eq!(cidr_selector_matches(&any, &candidate), Err(CidrError::InvalidLabel));
}
