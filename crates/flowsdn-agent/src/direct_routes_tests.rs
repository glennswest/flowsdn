#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}
fn hop(gateway: Option<&str>, index: u32) -> NextHop {
    NextHop {
        gateway: gateway.map(ip),
        index,
        weight: 1,
    }
}
fn desired() -> DesiredRoute {
    DesiredRoute {
        destination: ip("10.9.0.0"),
        prefix: 16,
        gateway: ip("192.0.2.20"),
        gateways: vec![ip("192.0.2.20"), ip("192.0.2.21")],
        node: "n2".into(),
    }
}

/// #498 (finding 4bc7cb209712): each selected path's gateway is checked;
/// a routed first InternalIP does not reject a later direct one.
#[test]
fn only_reachable_hops_are_installed() {
    let routed = ip("10.0.0.5");
    let hops = [
        hop(Some("10.0.0.5"), 3),
        hop(Some("192.0.2.21"), 4),
        hop(None, 5),
    ];
    let mut asked = Vec::new();
    let usable = reachable_hops(&hops, |g| {
        asked.push(g);
        Ok(g != routed)
    })
    .unwrap();
    assert_eq!(usable, [hops[1], hops[2]]);
    assert_eq!(asked.len(), 2, "a hop without a gateway is on-link");
    assert!(
        reachable_hops(&hops[..1], |_| Ok(false))
            .unwrap()
            .is_empty()
    );
    assert!(reachable_hops(&hops, |_| Err("netlink".into())).is_err());
}

/// #576: a desired route is planned into a `direct-routes` row: ECMP over the
/// reachable paths, else the plain route via the first InternalIP, which
/// must be directly reachable (skipped with direct-routing-skip-unreachable).
#[test]
fn routes_are_planned_into_rows() {
    let route = desired();
    let hops = [hop(Some("192.0.2.20"), 3), hop(Some("192.0.2.21"), 4)];
    let Planned::Row(row) = plan(&route, Some(&hops), |_| Ok(true), |_| Ok(None), false) else {
        panic!("a row");
    };
    assert_eq!(
        (
            row.owner.as_str(),
            row.table,
            row.prefix,
            row.admin_distance
        ),
        (OWNER, MAIN, (ip("10.9.0.0"), 16), ADMIN_DISTANCE)
    );
    assert_eq!(row.nexthop, None);
    assert_eq!(row.multipath.len(), 2);
    assert_eq!(installed_text(&row), "installed: 2 paths");
    // No path reachable: the plain route, via the first InternalIP.
    let Planned::Row(row) = plan(&route, Some(&hops), |_| Ok(false), |_| Ok(None), false) else {
        panic!("a row");
    };
    assert_eq!(
        (row.nexthop, row.multipath.len()),
        (Some(ip("192.0.2.20")), 0)
    );
    assert_eq!(installed_text(&row), "installed");
    // The first InternalIP behind a router: an error, or skipped.
    let router = |_: IpAddr| Ok(Some(ip("192.0.2.1")));
    match plan(&route, None, |_| Ok(true), router, false) {
        Planned::Failed(error) => assert!(error.contains("must be directly reachable"), "{error}"),
        other => panic!("{other:?}"),
    }
    match plan(&route, None, |_| Ok(true), router, true) {
        Planned::Skipped(why) => assert!(why.starts_with("skipped: route to 192.0.2.20"), "{why}"),
        other => panic!("{other:?}"),
    }
    // A gateway equal to the address, or unspecified, is directly reachable.
    assert!(matches!(
        plan(
            &route,
            None,
            |_| Ok(true),
            |_| Ok(Some(ip("192.0.2.20"))),
            false
        ),
        Planned::Row(_)
    ));
    // A netlink failure is an error, not a route.
    assert!(matches!(
        plan(&route, None, |_| Ok(true), |_| Err("netlink".into()), false),
        Planned::Failed(_)
    ));
}

/// #498 (finding 8299a1f6238f) after #576: a route no longer desired is
/// deleted by destination, whatever gateway it was installed with; a desired
/// route whose plan failed or was skipped this round keeps its installed
/// route (neither deleted with its row nor pruned).
#[tokio::test]
async fn stale_routes_go_and_held_ones_stay() {
    use flowsdn_node::routes::{RouteManager, RouteTarget};
    use flowsdn_reconcile::{Options, Reconciler};
    // A fake main table: prefix -> gateway.
    struct Fake(Arc<Mutex<std::collections::BTreeMap<(IpAddr, u8), IpAddr>>>);
    impl RouteOps for Fake {
        fn replace(&mut self, route: &rows::DesiredRoute) -> Result<(), String> {
            let gateway = route
                .nexthop
                .or_else(|| route.multipath.first().and_then(|h| h.gateway))
                .unwrap();
            self.0.lock().unwrap().insert(route.prefix, gateway);
            Ok(())
        }
        fn delete(&mut self, _: u32, prefix: (IpAddr, u8), _: u32) -> Result<(), String> {
            self.0.lock().unwrap().remove(&prefix);
            Ok(())
        }
        fn owned(&mut self) -> Result<Vec<RouteId>, String> {
            Ok(self.0.lock().unwrap().keys().map(|p| (MAIN, *p, 0)).collect())
        }
    }
    let route = |dst: &str, gw: &str| DesiredRoute {
        destination: ip(dst),
        prefix: 16,
        gateway: ip(gw),
        gateways: vec![ip(gw)],
        node: dst.into(),
    };
    let plan_ok = |r: &DesiredRoute| plan(r, None, |_| Ok(true), |_| Ok(None), false);
    // Installed before: a node gone (10.9) via a later InternalIP, and two
    // still-desired nodes.
    let kernel = Arc::new(Mutex::new(std::collections::BTreeMap::from([
        ((ip("10.9.0.0"), 16), ip("192.0.2.21")),
        ((ip("10.8.0.0"), 16), ip("192.0.2.30")),
        ((ip("10.7.0.0"), 16), ip("192.0.2.40")),
    ])));
    let held_set = Arc::new(Mutex::new(BTreeSet::new()));
    let manager = RouteManager::new().unwrap();
    let table = manager.table();
    let init = table.register_initializer(OWNER).unwrap();
    table.seal_initializers();
    let ops = Holding {
        inner: Fake(Arc::clone(&kernel)),
        held: Arc::clone(&held_set),
    };
    let mut reconciler =
        Reconciler::new(&table, RouteTarget::new(ops, Arc::clone(&table)), Options::default()).unwrap();
    let round = |planned: Vec<(DesiredRoute, Planned)>| {
        *held_set.lock().unwrap() = held(&planned);
        planned
            .into_iter()
            .filter_map(|(_, p)| match p {
                Planned::Row(row) => Some(*row),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    // 10.8 moved to another gateway; 10.7's lookup failed this round.
    let a = route("10.8.0.0", "192.0.2.31");
    let b = route("10.7.0.0", "192.0.2.40");
    let rows = round(vec![
        (a.clone(), plan_ok(&a)),
        (b.clone(), Planned::Failed("netlink".into())),
    ]);
    manager.set_owner(OWNER, rows).await.unwrap();
    init.complete();
    reconciler.prune_now();
    for _ in 0..5 {
        reconciler.run_round(std::time::Instant::now()).await.ok();
    }
    assert_eq!(
        *kernel.lock().unwrap(),
        std::collections::BTreeMap::from([
            ((ip("10.8.0.0"), 16), ip("192.0.2.31")),
            ((ip("10.7.0.0"), 16), ip("192.0.2.40")),
        ]),
        "the gone node's route is deleted by destination; the failed one stays"
    );
    // 10.7 planned, then skipped: its row goes but its route stays.
    let rows = round(vec![(a.clone(), plan_ok(&a)), (b.clone(), plan_ok(&b))]);
    manager.set_owner(OWNER, rows).await.unwrap();
    for _ in 0..5 {
        reconciler.run_round(std::time::Instant::now()).await.ok();
    }
    let rows = round(vec![
        (a.clone(), plan_ok(&a)),
        (b.clone(), Planned::Skipped("skipped".into())),
    ]);
    manager.set_owner(OWNER, rows).await.unwrap();
    reconciler.prune_now();
    for _ in 0..5 {
        reconciler.run_round(std::time::Instant::now()).await.ok();
    }
    assert!(kernel.lock().unwrap().contains_key(&(ip("10.7.0.0"), 16)));
    // No longer desired at all: deleted.
    let rows = round(vec![(a.clone(), plan_ok(&a))]);
    manager.set_owner(OWNER, rows).await.unwrap();
    reconciler.prune_now();
    for _ in 0..5 {
        reconciler.run_round(std::time::Instant::now()).await.ok();
    }
    assert_eq!(
        kernel.lock().unwrap().keys().copied().collect::<Vec<_>>(),
        [(ip("10.8.0.0"), 16)]
    );
}
