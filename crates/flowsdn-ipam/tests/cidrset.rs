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
