//! Independent spec07§5.4 cases corresponding to pinned cidrset test categories.
use flowsdn_ipam::cidrset::{CidrSet, Prefix};
fn p(s: &str) -> Prefix {
    s.parse().expect("prefix")
}
#[test]
fn fully_allocated_and_reused() {
    for prefix in ["127.123.234.0/30", "beef:1234::/30"] {
        let cluster = p(prefix);
        let mut set = CidrSet::new(cluster, 30).expect("set");
        assert_eq!(set.allocate_next().expect("block"), cluster);
        assert!(set.allocate_next().is_err());
        set.release(cluster).expect("release");
        assert_eq!(set.allocate_next().expect("reuse"), cluster);
    }
}
#[test]
fn index_mapping() {
    for (cluster, mask, last) in [
        ("10.0.0.0/16", 24, "10.0.255.0/24"),
        ("2001:db8::/48", 64, "2001:db8:0:ffff::/64"),
        ("2001:db8::/120", 128, "2001:db8::ff/128"),
    ] {
        let set = CidrSet::new(p(cluster), mask).expect("set");
        assert_eq!(
            set.block(set.capacity().saturating_sub(1)).expect("last"),
            p(last)
        );
        assert!(set.block(set.capacity()).is_err());
    }
}
#[test]
fn cursor_wrap() {
    let mut set = CidrSet::new(p("10.0.0.0/24"), 26).expect("set");
    let first = set.allocate_next().expect("first");
    set.release(first).expect("release");
    assert_eq!(set.allocate_next().expect("next"), p("10.0.0.64/26"));
    set.allocate_next().expect("next");
    set.allocate_next().expect("next");
    assert_eq!(set.allocate_next().expect("wrap"), first);
}
#[test]
fn skip_occupied() {
    let mut set = CidrSet::new(p("10.0.0.0/24"), 26).expect("set");
    set.occupy(p("10.0.0.0/25")).expect("occupy");
    assert_eq!(set.allocate_next().expect("next"), p("10.0.0.128/26"));
}
#[test]
fn subprefix_maps_to_block() {
    let mut set = CidrSet::new(p("10.0.0.0/24"), 26).expect("set");
    set.occupy(p("10.0.0.70/32")).expect("occupy");
    assert!(set.is_allocated(p("10.0.0.64/26")).expect("allocated"));
    assert!(!set.is_allocated(p("10.0.0.0/24")).expect("partial"));
}
#[test]
fn occupy_supernet_idempotent() {
    let mut set = CidrSet::new(p("127.0.0.0/8"), 16).expect("set");
    for _ in 0..2 {
        set.occupy(p("0.0.0.0/0")).expect("cover");
    }
    assert!(set.is_full());
    for _ in 0..2 {
        set.release(p("127.0.0.0/8")).expect("release");
    }
    assert!(!set.is_full());
    assert!(set.occupy(p("128.0.0.0/8")).is_err());
}
#[test]
fn ipv6_overlap_and_family() {
    let mut set = CidrSet::new(p("2001:db8::/48"), 64).expect("set");
    set.occupy(p("2001:db8::/32")).expect("cover");
    assert!(set.is_full());
    assert!(!set.in_range(p("10.0.0.0/8")));
    set.release(p("2001:db8:0:ffff::1/128")).expect("last");
    assert_eq!(
        set.allocate_next().expect("last"),
        p("2001:db8:0:ffff::/64")
    );
}
#[test]
fn invalid_masks() {
    assert!(CidrSet::new(p("10.0.0.0/8"), 33).is_err());
    assert!(CidrSet::new(p("2001:db8::/32"), 64).is_err());
    assert!(CidrSet::new(p("10.0.0.0/24"), 23).is_err());
    assert!(Prefix::new("::1".parse().expect("ip"), 129).is_err());
}

// Static table data is attributed in cidrset-upstream.txt and NOTICE.
#[test]
fn all_upstream_table_rows() {
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for line in include_str!("cidrset-upstream.txt").lines().filter(|l| !l.starts_with('#')) {
        let fields: Vec<_> = line.split('|').collect();
        let [kind, cluster, mask, input, first, second, error]: [&str; 7] = fields.try_into().expect("seven fields");
        let count = counts.entry(kind).or_default();
        *count = count.saturating_add(1);
        let result = CidrSet::new(p(cluster), mask.parse().expect("mask"));
        if kind == "mask" || kind == "v6" && error == "true" {
            assert_eq!(result.is_err(), error == "true", "{line}");
            continue;
        }
        let mut set = result.expect(line);
        match kind {
            "full" => {
                let expected = p(first);
                assert_eq!(set.allocate_next().expect(line), expected);
                assert!(set.is_full());
                assert!(set.allocate_next().is_err());
                set.release(expected).expect(line);
                assert_eq!(set.allocate_next().expect(line), expected);
                assert!(set.allocate_next().is_err());
            }
            "index" => assert_eq!(set.block(input.parse().expect("index")).expect(line), p(first)),
            "bit" => {
                let index = set.index(p(input).address());
                if error == "true" { assert!(index.is_err(), "{line}"); }
                else { assert_eq!(index.expect(line), first.parse::<usize>().expect("index")); }
            }
            "occupy" => {
                let begin = first.parse::<usize>().expect("begin");
                let end = second.parse::<usize>().expect("end");
                set.occupy(p(input)).expect(line);
                set.occupy(p(input)).expect("idempotent");
                assert_eq!(set.allocated(), end.saturating_sub(begin).saturating_add(1), "{line}");
                for index in begin..=end { assert!(set.is_allocated(set.block(index).expect(line)).expect(line)); }
                set.release(p(input)).expect(line);
                set.release(p(input)).expect("idempotent");
                assert_eq!(set.allocated(), 0);
            }
            "v6" => {
                assert_eq!(set.allocate_next().expect(line), p(first));
                assert_eq!(set.allocate_next().expect(line), p(second));
            }
            _ => panic!("unknown category {kind}"),
        }
    }
    assert_eq!(counts, std::collections::BTreeMap::from([("full",2),("index",15),("bit",14),("occupy",14),("v6",3),("mask",4)]));
}
#[test]
fn upstream_full_roundtrip_and_half_occupied_workflows() {
    for cluster in ["127.123.234.0/16", "beef:1234::/16"] {
        for half_occupied in [false, true] {
            let mut set = CidrSet::new(p(cluster),24).expect("set");
            let original: Vec<_> = (0..256).map(|_|set.allocate_next().expect("allocate")).collect();
            assert!(set.allocate_next().is_err());
            for prefix in &original { set.release(*prefix).expect("release"); }
            if half_occupied { for prefix in original.get(128..).expect("second half") { set.occupy(*prefix).expect("occupy"); } }
            let count = if half_occupied {128} else {256};
            let mut again: Vec<_> = (0..count).map(|_|set.allocate_next().expect("reallocate")).collect();
            assert!(set.allocate_next().is_err());
            if half_occupied { again.extend_from_slice(original.get(128..).expect("second half")); }
            assert_eq!(original, again);
        }
    }
}
