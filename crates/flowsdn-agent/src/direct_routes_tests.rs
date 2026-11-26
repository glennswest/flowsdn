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
