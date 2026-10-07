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
            affinity: None,
            scope: SCOPE_CLUSTER,
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
        for (frontend, scope) in step
            .services4
            .keys()
            .map(|k| {
                let (f, scope, _) = frontend4(*k);
                (f, scope)
            })
            .chain(step.services6.keys().map(|k| {
                let (f, scope, _) = frontend6(*k);
                (f, scope)
            }))
        {
            if let Some(result) = resolve_scope(&step, frontend, scope) {
                result.expect("intermediate state resolves");
            }
        }
        // A remembered affinity is only honoured through a match entry, so
        // a match must never name a backend ID that is gone.
        for key in &step.affinity_match {
            let id = flowsdn_bpf_abi::affinity::LbAffinityMatch::from_bytes(*key).backend_id;
            assert!(
                step.backends4.contains_key(&id) || step.backends6.contains_key(&id),
                "affinity match for a deleted backend {id}"
            );
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
        vec![
            addr("10.172.0.5", 53, PROTO_UDP),
            addr("10.172.0.9", 53, PROTO_UDP)
        ]
    );
    // Two frontends (UDP, TCP) x (master + 2 slots); four distinct backends.
    assert_eq!(maps.services4.len(), 6);
    assert_eq!(maps.backends4.len(), 4);
    assert_eq!(want.ids.len(), 2);
    assert!(resolve(&maps, addr("10.96.0.10", 80, PROTO_TCP)).is_none());
    let master = LbService::from_bytes(
        *maps
            .services4
            .get(&key4(udp, 0, 0).expect("key"))
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
    assert_eq!(
        resolve(&maps, udp).expect("present").expect("valid"),
        vec![]
    );
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
            affinity: None,
            scope: SCOPE_CLUSTER,
        },
        Service {
            frontend: addr("fd00:10:96::1", 443, PROTO_TCP),
            backends: vec![addr("fd00::1", 6443, PROTO_TCP)],
            affinity: None,
            scope: SCOPE_CLUSTER,
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
    let twice: Vec<Service> = services.iter().take(1).cycle().take(2).cloned().collect();
    assert!(desired(&maps, &twice).is_err());
}

#[test]
fn foreign_stale_entries_are_pruned() {
    let mut maps = Maps::default();
    // A slot beyond the master's count and an unreferenced backend, as an
    // interrupted earlier agent could leave them.
    let udp = addr("10.96.0.10", 53, PROTO_UDP);
    maps.services4.insert(
        key4(udp, 0, 7).expect("key"),
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
    assert!(!maps.services4.contains_key(&key4(udp, 0, 7).expect("key")));
}

#[test]
fn ids_allocate_upwards_around_holes() {
    let mut ids = Ids::new([1, 2, 4].into_iter().collect(), 5);
    assert_eq!(ids.allocate(), Some(3));
    assert_eq!(ids.allocate(), Some(5));
    assert_eq!(ids.allocate(), None);
}

#[test]
fn session_affinity_sets_the_master_and_tracks_matches() {
    let sticky = |backends: &[&str], affinity: Option<u32>| -> Vec<Service> {
        dns(backends)
            .into_iter()
            .map(|s| Service { affinity, ..s })
            .collect()
    };
    let mut maps = Maps::default();
    let want = sync(
        &mut maps,
        &sticky(&["10.172.0.5", "10.172.0.6"], Some(10800)),
    );
    let master = |maps: &Maps| {
        LbService::from_bytes(
            *maps
                .services4
                .get(&key4(addr("10.96.0.10", 53, PROTO_UDP), 0, 0).expect("key"))
                .expect("master"),
        )
    };
    let m = master(&maps);
    assert_eq!(
        m.service_flags(),
        service_flags::ROUTABLE | service_flags::SESSION_AFFINITY
    );
    assert_eq!(m.affinity_seconds(), 10800);
    assert_eq!(m.algorithm_code(), Algorithm::Random as u8);
    // One match per (backend, service): 2 backends x 2 frontends.
    assert_eq!(maps.affinity_match.len(), 4);
    let ids: BTreeSet<u16> = want.ids.values().copied().collect();
    for key in &maps.affinity_match {
        let matched = LbAffinityMatch::from_bytes(*key);
        let rev = matched.rev_nat_id;
        assert!(ids.contains(&rev));
    }
    // A backend leaves: its matches go before it does (checked in sync).
    sync(&mut maps, &sticky(&["10.172.0.6"], Some(10800)));
    assert_eq!(maps.affinity_match.len(), 2);
    // Affinity off: matches go, the master is plain again.
    sync(&mut maps, &sticky(&["10.172.0.6"], None));
    assert!(maps.affinity_match.is_empty());
    assert_eq!(master(&maps).service_flags(), service_flags::ROUTABLE);
    assert_eq!(master(&maps).union_raw, 0);
    // A timeout beyond 24 bits is refused, not truncated.
    assert!(desired(&maps, &sticky(&["10.172.0.6"], Some(1 << 24))).is_err());
}

#[test]
fn node_local_scope_is_a_separate_service_with_its_own_id() {
    let mut maps = Maps::default();
    let front = addr("192.168.0.1", 30080, PROTO_TCP);
    let cluster = Service {
        frontend: front,
        backends: vec![
            addr("10.1.0.5", 8080, PROTO_TCP),
            addr("10.2.0.5", 8080, PROTO_TCP),
        ],
        affinity: None,
        scope: SCOPE_CLUSTER,
    };
    let local = Service {
        backends: vec![addr("10.1.0.5", 8080, PROTO_TCP)],
        scope: SCOPE_NODE_LOCAL,
        ..cluster.clone()
    };
    let want = sync(&mut maps, &[cluster.clone(), local.clone()]);
    assert_eq!(
        resolve_scope(&maps, front, SCOPE_CLUSTER).map(|r| r.expect("resolves").len()),
        Some(2)
    );
    assert_eq!(
        resolve_scope(&maps, front, SCOPE_NODE_LOCAL).map(|r| r.expect("resolves")),
        Some(vec![addr("10.1.0.5", 8080, PROTO_TCP)])
    );
    // Both scopes share the backend; each scope is its own service ID.
    assert_eq!(maps.backends4.len(), 2);
    assert_eq!(want.ids.len(), 2);
    assert_ne!(
        want.ids.get(&(front, SCOPE_CLUSTER)),
        want.ids.get(&(front, SCOPE_NODE_LOCAL))
    );
    // The same frontend and scope twice is refused; IDs survive a re-plan.
    assert!(desired(&maps, &[cluster.clone(), cluster.clone()]).is_err());
    let again = desired(&maps, &[cluster, local]).expect("desired");
    assert_eq!(again.ids, want.ids);
    assert!(plan(&maps, &again.maps).is_empty());
}
