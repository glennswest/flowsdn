use super::*;

fn addr(ip: &str, port: u16, proto: u8) -> Address {
    Address {
        ip: ip.parse().expect("ip"),
        port,
        proto,
    }
}
fn dns(backends: &[&str]) -> Vec<Service> {
    let front = |proto| addr("10.96.0.10", 53, proto);
    [PROTO_UDP, PROTO_TCP]
        .into_iter()
        .map(|proto| Service {
            frontend: front(proto),
            backends: backends.iter().map(|ip| addr(ip, 53, proto)).collect(),
        })
        .collect()
}
fn sync(current: &mut Maps, services: &[Service]) -> Desired {
    let want = desired(current, services).expect("desired");
    let ops = plan(current, &want.maps);
    // Every intermediate state resolves each frontend of the old or new set
    // without a dangling slot or backend: the property the write order buys.
    let mut step = current.clone();
    for op in &ops {
        apply(&mut step, std::slice::from_ref(op));
        for frontend in step
            .services4
            .keys()
            .map(|k| frontend4(*k).0)
            .chain(step.services6.keys().map(|k| frontend6(*k).0))
        {
            if let Some(result) = resolve(&step, frontend) {
                result.expect("intermediate state resolves");
            }
        }
    }
    apply(current, &ops);
    assert_eq!(*current, want.maps);
    assert!(plan(current, &want.maps).is_empty(), "plan converges");
    want
}

#[test]
fn cluster_ip_resolves_to_each_backend() {
    let mut maps = Maps::default();
    let services = dns(&["10.172.0.5", "10.172.0.9"]);
    let want = sync(&mut maps, &services);
    let udp = addr("10.96.0.10", 53, PROTO_UDP);
    let got = resolve(&maps, udp).expect("present").expect("valid");
    assert_eq!(
        got,
        vec![addr("10.172.0.5", 53, PROTO_UDP), addr("10.172.0.9", 53, PROTO_UDP)]
    );
    // Two frontends (UDP, TCP) x (master + 2 slots); four distinct backends.
    assert_eq!(maps.services4.len(), 6);
    assert_eq!(maps.backends4.len(), 4);
    assert_eq!(want.ids.len(), 2);
    assert!(resolve(&maps, addr("10.96.0.10", 80, PROTO_TCP)).is_none());
    let master = LbService::from_bytes(
        *maps
            .services4
            .get(&key4(udp, 0).expect("key"))
            .expect("master"),
    );
    assert_eq!(master.count, 2);
    assert_eq!(master.service_flags(), service_flags::ROUTABLE);
}

#[test]
fn ids_survive_restart_and_churn() {
    let mut maps = Maps::default();
    let first = sync(&mut maps, &dns(&["10.172.0.5", "10.172.0.9"]));
    let ids4: BTreeMap<u32, [u8; 12]> = maps.backends4.clone();
    // A restarted agent plans from the kernel alone and changes nothing.
    let again = desired(&maps, &dns(&["10.172.0.5", "10.172.0.9"])).expect("desired");
    assert_eq!(again.ids, first.ids);
    assert!(plan(&maps, &again.maps).is_empty());
    // Scale up: existing backends keep their IDs.
    sync(&mut maps, &dns(&["10.172.0.5", "10.172.0.9", "10.172.0.7"]));
    for (id, value) in &ids4 {
        assert_eq!(maps.backends4.get(id), Some(value));
    }
    // Scale down to one, then to none: count 0 is kept (connect fails).
    sync(&mut maps, &dns(&["10.172.0.9"]));
    let udp = addr("10.96.0.10", 53, PROTO_UDP);
    assert_eq!(
        resolve(&maps, udp).expect("present").expect("valid"),
        vec![addr("10.172.0.9", 53, PROTO_UDP)]
    );
    sync(&mut maps, &dns(&[]));
    assert_eq!(resolve(&maps, udp).expect("present").expect("valid"), vec![]);
    assert!(maps.backends4.is_empty());
    // Service removed entirely.
    sync(&mut maps, &[]);
    assert_eq!(maps, Maps::default());
}

#[test]
fn new_ids_never_reuse_live_ones() {
    let mut maps = Maps::default();
    sync(&mut maps, &dns(&["10.172.0.5"]));
    let before: BTreeSet<u32> = maps.backends4.keys().copied().collect();
    // Replace the backend: the new one must get a fresh ID while the old one
    // is still referenced by the live slot.
    let want = desired(&maps, &dns(&["10.172.0.6"])).expect("desired");
    for id in want.maps.backends4.keys() {
        assert!(!before.contains(id));
    }
    sync(&mut maps, &dns(&["10.172.0.6"]));
}

#[test]
fn dual_stack_and_mixed_backends() {
    let mut maps = Maps::default();
    let services = vec![
        Service {
            frontend: addr("10.96.0.1", 443, PROTO_TCP),
            backends: vec![
                addr("192.168.31.172", 6443, PROTO_TCP),
                addr("192.168.31.172", 6443, PROTO_TCP),
                addr("fd00::1", 6443, PROTO_TCP),
            ],
        },
        Service {
            frontend: addr("fd00:10:96::1", 443, PROTO_TCP),
            backends: vec![addr("fd00::1", 6443, PROTO_TCP)],
        },
    ];
    sync(&mut maps, &services);
    assert_eq!(
        resolve(&maps, addr("10.96.0.1", 443, PROTO_TCP))
            .expect("present")
            .expect("valid"),
        vec![addr("192.168.31.172", 6443, PROTO_TCP)]
    );
    assert_eq!(
        resolve(&maps, addr("fd00:10:96::1", 443, PROTO_TCP))
            .expect("present")
            .expect("valid"),
        vec![addr("fd00::1", 6443, PROTO_TCP)]
    );
    assert_eq!(maps.backends6.len(), 1);
    assert!(desired(&maps, &[services[0].clone(), services[0].clone()]).is_err());
}

#[test]
fn foreign_stale_entries_are_pruned() {
    let mut maps = Maps::default();
    // A slot beyond the master's count and an unreferenced backend, as an
    // interrupted earlier agent could leave them.
    let udp = addr("10.96.0.10", 53, PROTO_UDP);
    maps.services4.insert(
        key4(udp, 7).expect("key"),
        LbService {
            union_raw: 99,
            rev_nat_index: 3,
            ..LbService::default()
        }
        .to_bytes(),
    );
    maps.backends4.insert(
        99,
        backend_bytes4(addr("10.1.1.1", 53, PROTO_UDP)).expect("v4"),
    );
    sync(&mut maps, &dns(&["10.172.0.5"]));
    assert!(!maps.backends4.contains_key(&99));
    assert!(!maps.services4.contains_key(&key4(udp, 7).expect("key")));
}

#[test]
fn ids_allocate_upwards_around_holes() {
    let mut ids = Ids::new([1, 2, 4].into_iter().collect(), 5);
    assert_eq!(ids.allocate(), Some(3));
    assert_eq!(ids.allocate(), Some(5));
    assert_eq!(ids.allocate(), None);
}
