use flowsdn_ipam::{Error, HostScope, Ipam, RangeOptions};
use std::collections::BTreeSet;
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

fn pool(address: &str, prefix: u8) -> HostScope {
    HostScope::new(ip(address), prefix, RangeOptions::default()).expect("test pool")
}

#[test]
fn random_scan_exhausts_each_usable_address_and_reuses_a_hole() {
    let mut pool = pool("10.0.0.7", 24);
    assert_eq!(pool.network(), ip("10.0.0.0"));
    assert_eq!(pool.prefix_len(), 24);
    assert_eq!(pool.capacity(), 254);
    let mut seen = BTreeSet::new();
    for _ in 0..254 {
        let address = pool.allocate_next("ns/pod").expect("free address");
        assert!(seen.insert(address));
        assert_ne!(address, ip("10.0.0.0"));
        assert_ne!(address, ip("10.0.0.255"));
        assert_eq!(
            pool.dump().get(&address).map(String::as_str),
            Some("ns/pod")
        );
    }
    assert_eq!(pool.allocate_next("ns/extra"), Err(Error::Full));
    assert_eq!(pool.capacity(), 254);
    pool.release(ip("10.0.0.42"));
    assert_eq!(pool.allocate_next("ns/replacement"), Ok(ip("10.0.0.42")));
}

#[test]
fn endpoint_options_and_small_prefixes_apply_to_both_families() {
    for (network, prefix) in [("192.0.2.0", 30), ("2001:db8::", 126)] {
        for allow_first_ip in [false, true] {
            for allow_last_ip in [false, true] {
                let mut pool = HostScope::new(
                    ip(network),
                    prefix,
                    RangeOptions {
                        allow_first_ip,
                        allow_last_ip,
                    },
                )
                .expect("range");
                let expected = 2u128
                    .saturating_add(u128::from(allow_first_ip))
                    .saturating_add(u128::from(allow_last_ip));
                assert_eq!(pool.capacity(), expected);
                for _ in 0..expected {
                    pool.allocate_next("pod").expect("free");
                }
                assert_eq!(pool.allocate_next("pod"), Err(Error::Full));
                assert_eq!(pool.dump().contains_key(&ip(network)), allow_first_ip);
                let last = if prefix == 30 {
                    ip("192.0.2.3")
                } else {
                    ip("2001:db8::3")
                };
                assert_eq!(pool.dump().contains_key(&last), allow_last_ip);
            }
        }
    }
    for (network, prefix, count) in [
        ("255.255.255.254", 31, 2),
        ("255.255.255.255", 32, 1),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 127, 2),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 128, 1),
    ] {
        let mut pool = pool(network, prefix);
        assert_eq!(pool.capacity(), count);
        for _ in 0..count {
            pool.allocate_next("pod").expect("free");
        }
        assert_eq!(pool.allocate_next("pod"), Err(Error::Full));
        assert!(pool.dump().contains_key(&ip(network)));
    }
}

#[test]
fn specific_restore_preserves_owners_and_rejects_collisions_and_boundaries() {
    let mut pool = pool("192.0.2.0", 24);
    let address = ip("192.0.2.9");
    pool.allocate_without_sync(address, "restored/pod")
        .expect("restore");
    pool.restore_finished();
    assert_eq!(pool.allocate(address, "new/pod"), Err(Error::Allocated));
    assert_eq!(
        pool.dump().get(&address).map(String::as_str),
        Some("restored/pod")
    );
    for address in ["192.0.2.0", "192.0.2.255", "192.0.3.1", "::ffff:192.0.2.9"] {
        assert_eq!(pool.allocate(ip(address), "pod"), Err(Error::NotInRange));
        pool.release(ip(address));
    }
    assert_eq!(pool.allocated(), 1);
    pool.release(address);
    pool.release(address);
    assert_eq!(pool.allocated(), 0);
    pool.allocate(address, "replacement").expect("reallocate");
}

#[test]
fn excluded_addresses_are_reserved_with_owner_on_scan_and_survive_release() {
    let mut pool = pool("192.0.2.0", 30);
    let excluded = ip("192.0.2.1");
    pool.exclude_ip(excluded, "router");
    pool.exclude_ip(ip("203.0.113.9"), "external");
    assert_eq!(
        pool.allocate(excluded, "pod"),
        Err(Error::Excluded {
            owner: "router".into()
        })
    );
    assert_eq!(pool.allocate_next("pod"), Ok(ip("192.0.2.2")));
    assert_eq!(pool.allocate_next("pod"), Err(Error::Full));
    assert_eq!(
        pool.dump().get(&excluded).map(String::as_str),
        Some("router (excluded)")
    );
    pool.release(excluded);
    assert_eq!(
        pool.allocate_without_sync(excluded, "pod"),
        Err(Error::Excluded {
            owner: "router".into()
        })
    );
    assert_eq!(pool.allocate_next("pod"), Err(Error::Full));
    assert_eq!(pool.allocated(), 2);
    assert_eq!(pool.capacity(), 2);
}

#[test]
fn excluding_an_existing_allocation_preserves_its_owner_until_release() {
    let mut pool = pool("192.0.2.1", 32);
    let address = ip("192.0.2.1");
    pool.allocate(address, "health").expect("infra");
    pool.exclude_ip(address, "router");
    assert_eq!(
        pool.dump().get(&address).map(String::as_str),
        Some("health")
    );
    pool.release(address);
    assert_eq!(pool.allocate_next("pod"), Err(Error::Full));
    assert_eq!(
        pool.dump().get(&address).map(String::as_str),
        Some("router (excluded)")
    );
}

#[test]
fn ipv6_large_prefixes_have_full_capacity_without_dense_storage() {
    for (prefix, capacity) in [
        (96, (1u128 << 32).saturating_sub(2)),
        (64, (1u128 << 64).saturating_sub(2)),
        (0, u128::MAX.saturating_sub(1)),
    ] {
        let mut pool = pool("2001:db8::", prefix);
        assert_eq!(pool.capacity(), capacity);
        for _ in 0..16 {
            pool.allocate_next("pod").expect("sparse allocation");
        }
        assert_eq!(pool.allocated(), 16);
    }
    let all = RangeOptions {
        allow_first_ip: true,
        allow_last_ip: true,
    };
    assert!(matches!(
        HostScope::new(ip("::"), 0, all),
        Err(Error::CapacityOverflow)
    ));
    assert!(matches!(
        HostScope::new(ip("::"), 129, all),
        Err(Error::InvalidPrefix)
    ));
    assert!(matches!(
        HostScope::new(ip("0.0.0.0"), 33, all),
        Err(Error::InvalidPrefix)
    ));
}

#[test]
fn dual_stack_failure_rolls_back_only_the_new_ipv6_allocation() {
    let mut v4 = pool("192.0.2.1", 32);
    v4.allocate(ip("192.0.2.1"), "existing4").expect("v4 full");
    let mut v6 = pool("2001:db8::", 126);
    v6.allocate(ip("2001:db8::1"), "existing6")
        .expect("v6 existing");
    let mut ipam = Ipam::new(Some(v4), Some(v6)).expect("families");
    assert_eq!(ipam.allocate_next("new"), Err(Error::Full));
    let v6 = ipam.ipv6().expect("v6");
    assert_eq!(v6.allocated(), 1);
    assert_eq!(
        v6.dump().get(&ip("2001:db8::1")).map(String::as_str),
        Some("existing6")
    );
    ipam.release(ip("192.0.2.1")).expect("release v4");
    let pair = ipam.allocate_next("new").expect("dual allocation");
    assert_eq!(pair.ipv4.map(IpAddr::V4), Some(ip("192.0.2.1")));
    assert_eq!(pair.ipv6.map(IpAddr::V6), Some(ip("2001:db8::2")));
}

#[test]
fn ipv6_failure_does_not_allocate_ipv4_and_disabled_families_are_explicit() {
    let mut v6 = pool("2001:db8::1", 128);
    v6.allocate(ip("2001:db8::1"), "existing").expect("full v6");
    let mut ipam = Ipam::new(Some(pool("192.0.2.1", 32)), Some(v6)).expect("families");
    assert_eq!(ipam.allocate_next("pod"), Err(Error::Full));
    assert_eq!(ipam.ipv4().expect("v4").allocated(), 0);
    assert!(matches!(
        Ipam::new(Some(pool("::", 128)), None),
        Err(Error::FamilyMismatch)
    ));
    let mut ipam = Ipam::new(None, None).expect("disabled");
    assert_eq!(ipam.allocate_next("pod"), Err(Error::FamilyDisabled));
    assert_eq!(
        ipam.allocate(ip("192.0.2.1"), "pod"),
        Err(Error::FamilyDisabled)
    );
    let mut ipam = Ipam::new(Some(pool("192.0.2.1", 32)), None).expect("v4 only");
    let pair = ipam.allocate_next("pod").expect("v4");
    assert_eq!(pair.ipv4.map(IpAddr::V4), Some(ip("192.0.2.1")));
    assert_eq!(pair.ipv6, None);
}
#[test]
fn explicit_family_allocation_ignores_an_exhausted_other_pool() {
    use flowsdn_ipam::{HostScope, Ipam};
    let mut ipam = Ipam::new(
        Some(
            HostScope::new("198.18.0.1".parse().expect("ip"), 32, Default::default())
                .expect("pool"),
        ),
        Some(
            HostScope::new("2001:db8::1".parse().expect("ip"), 128, Default::default())
                .expect("pool"),
        ),
    )
    .expect("IPAM");
    assert!(
        ipam.allocate_next_family(true, "v6")
            .expect("IPv6")
            .is_ipv6()
    );
    assert!(
        ipam.allocate_next_family(false, "v4")
            .expect("IPv4 independent of full IPv6")
            .is_ipv4()
    );
    assert!(ipam.allocate_next_family(true, "full").is_err());
}

#[test]
fn summaries_distinguish_lazy_exclusions_real_allocations_and_overlap() {
    let mut pool =
        flowsdn_ipam::HostScope::new("10.10.0.0".parse().expect("IP"), 30, Default::default())
            .expect("pool");
    let first = "10.10.0.1".parse().expect("IP");
    let second = "10.10.0.2".parse().expect("IP");
    pool.exclude_ip("10.10.0.0".parse().expect("IP"), "reserved endpoint");
    pool.exclude_ip("192.0.2.1".parse().expect("IP"), "external");
    pool.allocate(first, "real owner (excluded)")
        .expect("allocate");
    pool.exclude_ip(first, "new exclusion");
    pool.exclude_ip(second, "gateway");
    assert_eq!(
        pool.summary(),
        flowsdn_ipam::PoolSummary {
            capacity: 2,
            allocated: 1,
            excluded: 2,
            allocated_excluded: 1,
            available: 0
        }
    );
    assert_eq!(
        pool.allocate_next("pending"),
        Err(flowsdn_ipam::Error::Full)
    );
    assert_eq!(pool.allocated(), 2); // existing raw owner count includes lazy marker
    assert_eq!(pool.summary().allocated, 1);
    assert_eq!(pool.summary().available, 0);
    pool.release(first);
    assert_eq!(pool.summary().allocated, 0);
    assert_eq!(pool.summary().excluded, 2);
    assert_eq!(pool.summary().available, 0);
    pool.release(second);
    assert_eq!(pool.summary().allocated, 0);
    assert_eq!(pool.summary().available, 0);
}
#[test]
fn summaries_account_for_ipv6_capacity_and_reserved_endpoints_without_iteration() {
    let mut pool = flowsdn_ipam::HostScope::new("::".parse().expect("IP"), 0, Default::default())
        .expect("pool");
    assert_eq!(pool.summary().capacity, u128::MAX.saturating_sub(1));
    pool.allocate("::42".parse().expect("IP"), "pending")
        .expect("allocate");
    pool.exclude_ip("::1".parse().expect("IP"), "gateway");
    assert_eq!(pool.summary().available, u128::MAX.saturating_sub(3));
    assert_eq!(pool.summary().allocated, 1);
    let one =
        flowsdn_ipam::HostScope::new("192.0.2.1".parse().expect("IP"), 32, Default::default())
            .expect("single");
    assert_eq!(one.summary().capacity, 1);
}
