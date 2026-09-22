use flowsdn_bgp_proto::{
    collision::{Connections, Direction, Resolution},
    rib::{LocalRib, ObservedRib},
    update::{Prefix, Summary},
};
use std::net::Ipv4Addr;
fn prefix(number: u32) -> Prefix {
    Prefix::new(Ipv4Addr::from(number).into(), 32).expect("prefix")
}
fn summary(announced: Vec<Prefix>, withdrawn: Vec<Prefix>) -> Summary {
    Summary {
        announced,
        withdrawn,
        mp_announced: vec![],
        mp_withdrawn: vec![],
        unknown_transitive: vec![],
    }
}
#[test]
fn received_full_table_cannot_modify_local_exports_and_overflow_is_bounded() {
    let mut local = LocalRib::default();
    let handle = local.advertise(prefix(42));
    let before = local.prefixes().clone();
    let mut observed = ObservedRib::new(100);
    assert!(observed.observe(&summary((0..200000).map(prefix).collect(), vec![])));
    assert_eq!(observed.prefixes(false).len(), 100);
    assert_eq!(observed.counters().announcements, 200000);
    assert_eq!(observed.counters().omitted, 199900);
    assert!(!observed.observe(&summary(vec![prefix(300000)], vec![]))); // log once
    assert_eq!(observed.counters().announcements, 200001);
    let v6 = Prefix::new("2001:db8::".parse().expect("IP"), 32).expect("prefix");
    assert!(!observed.observe(&summary(vec![v6], vec![prefix(0)])));
    assert_eq!(observed.prefixes(true).len(), 1);
    assert_eq!(observed.prefixes(false).len(), 99);
    assert_eq!(local.prefixes(), &before);
    assert!(local.withdraw(&handle));
}
#[test]
fn local_handles_are_idempotent_and_cannot_remove_replaced_or_other_instance_routes() {
    let mut a = LocalRib::default();
    let first = a.advertise(prefix(42));
    let duplicate = a.advertise(prefix(42));
    assert_eq!(a.prefixes().len(), 1);
    assert!(a.withdraw(&duplicate));
    let replacement = a.advertise(prefix(42));
    assert!(!a.withdraw(&first));
    assert!(a.withdraw(&replacement));
    let mut b = LocalRib::default();
    b.advertise(prefix(42));
    assert!(!b.withdraw(&replacement));
    assert_eq!(b.prefixes().len(), 1);
}
#[test]
fn collision_owns_winner_and_stale_callbacks_cannot_close_it() {
    let high = Ipv4Addr::new(192, 0, 2, 2);
    let low = Ipv4Addr::new(192, 0, 2, 1);
    let mut pool = Connections::default();
    let inbound = pool.allocate().expect("token");
    let outbound = pool.allocate().expect("token");
    assert!(matches!(
        pool.consider(inbound.clone(), Direction::Inbound, high, low),
        Resolution::Accepted { displaced: None }
    ));
    assert!(matches!(
        pool.consider(outbound.clone(), Direction::Outbound, high, low),
        Resolution::Accepted { displaced: Some(_) }
    ));
    assert!(!pool.closed(&inbound));
    assert!(pool.is_current(&outbound));
    assert!(pool.established(&outbound));
    let challenger = pool.allocate().expect("token");
    assert!(matches!(
        pool.consider(challenger, Direction::Inbound, low, high),
        Resolution::Rejected
    ));
    let mut other = Connections::default();
    assert!(matches!(
        other.consider(outbound.clone(), Direction::Outbound, high, low),
        Resolution::Rejected
    ));
    assert!(pool.closed(&outbound));
    assert!(!pool.established(&outbound));
    let equal = pool.allocate().expect("token");
    assert!(matches!(
        pool.consider(equal, Direction::Inbound, low, low),
        Resolution::InvalidRouterId
    ));
}
#[test]
fn lower_router_keeps_inbound_independently_of_arrival_order() {
    for inbound_first in [false, true] {
        let mut pool = Connections::default();
        let inbound = pool.allocate().expect("token");
        let outbound = pool.allocate().expect("token");
        let (first, first_direction, second, second_direction) = if inbound_first {
            (
                inbound.clone(),
                Direction::Inbound,
                outbound.clone(),
                Direction::Outbound,
            )
        } else {
            (
                outbound.clone(),
                Direction::Outbound,
                inbound.clone(),
                Direction::Inbound,
            )
        };
        pool.consider(
            first,
            first_direction,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
        );
        pool.consider(
            second,
            second_direction,
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
        );
        assert!(pool.is_current(&inbound));
        assert!(!pool.is_current(&outbound));
    }
}
