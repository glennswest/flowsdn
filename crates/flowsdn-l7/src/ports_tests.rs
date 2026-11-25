#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use super::*;

/// spec 16 §3.3.1 (#577): a requested free port is used; a taken or open one
/// is not; a name's second acquire shares its port.
#[test]
fn allocation_prefers_the_request_and_skips_open_ports() {
    let mut ports = Ports::new((10000, 10009));
    let open = BTreeSet::from([10004u16]);
    assert_eq!(ports.acquire("http-egress", "http", false, Some(10004), false, &open, 0, 0).unwrap() != 10004, true);
    let first = ports.get("http-egress").unwrap().port;
    assert!((10000..=10009).contains(&first) && first != 10004);
    assert_eq!(ports.acquire("http-egress", "http", false, None, false, &open, 0, 0).unwrap(), first);
    assert_eq!(ports.get("http-egress").unwrap().references, 2);
    let dns = ports.acquire("dns-egress", "dns", false, Some(10007), true, &open, 0, 0).unwrap();
    assert_eq!(dns, 10007);
}

/// A released port is not reused within the delay, and is reused after it
/// only once no never-used port is left; a static port is never released.
#[test]
fn released_ports_wait_and_come_last() {
    let mut ports = Ports::new((10000, 10001));
    let open = BTreeSet::new();
    let a = ports.acquire("a", "http", false, None, false, &open, 0, 0).unwrap();
    ports.release("a", 10);
    assert!(ports.get("a").is_none());
    let b = ports.acquire("b", "http", false, None, false, &open, 20, 0).unwrap();
    assert_ne!(a, b, "the never-used port first");
    assert!(ports.acquire("c", "http", false, None, false, &open, 30, 0).is_err(), "a is within its delay");
    assert_eq!(ports.acquire("c", "http", false, None, false, &open, 10 + REUSE_DELAY, 0).unwrap(), a);
    let mut statics = Ports::new((10000, 10001));
    statics.acquire("dns", "dns", false, None, true, &open, 0, 0).unwrap();
    statics.release("dns", 1);
    assert!(statics.get("dns").is_some());
}

/// Persistence round-trips; an old file is ignored; every port is visited
/// by the permutation.
#[test]
fn restore_and_permutation() {
    let mut ports = Ports::default();
    let open = BTreeSet::new();
    let port = ports.acquire("http-egress", "http", false, None, false, &open, 0, 42).unwrap();
    let saved = ports.json();
    let mut again = Ports::default();
    assert_eq!(again.restore(&saved, 60), 1);
    assert_eq!(again.get("http-egress").unwrap().port, port);
    assert_eq!(Ports::default().restore(&saved, RESTORE_AGE_LIMIT + 1), 0);
    let mut small = Ports::new((20000, 20006));
    let mut seen = BTreeSet::new();
    for i in 0..7 {
        seen.insert(small.acquire(&format!("p{i}"), "http", false, None, false, &open, 0, 3).unwrap());
    }
    assert_eq!(seen.len(), 7);
    assert!(small.acquire("p7", "http", false, None, false, &open, 0, 3).is_err());
}
