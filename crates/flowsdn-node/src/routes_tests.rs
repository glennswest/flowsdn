#![allow(clippy::indexing_slicing, clippy::unwrap_used)]
use super::*;
use flowsdn_reconcile::{Options, Reconciler};
use flowsdn_table::TableRender;
use std::net::IpAddr;
use std::sync::Mutex;

fn route(owner: &str, prefix: &str, len: u8, ad: u8, device: (&str, u32)) -> DesiredRoute {
    DesiredRoute {
        owner: owner.into(),
        table: 254,
        prefix: (prefix.parse().unwrap(), len),
        priority: None,
        nexthop: None,
        src: None,
        device: Some((device.0.into(), device.1)),
        multipath: Vec::new(),
        mtu: None,
        scope: "universe".into(),
        kind: "unicast".into(),
        admin_distance: ad,
        selected: false,
    }
}

type Kernel = Arc<Mutex<BTreeMap<(u32, (IpAddr, u8), u32), String>>>;
struct Fake(Kernel);
impl RouteOps for Fake {
    fn replace(&mut self, route: &DesiredRoute) -> Result<(), String> {
        self.0.lock().unwrap().insert(
            (route.table, route.prefix, route.priority.unwrap_or(0)),
            format!(
                "{}:{}",
                route.owner,
                route.device.as_ref().map_or(0, |d| d.1)
            ),
        );
        Ok(())
    }
    fn delete(&mut self, table: u32, prefix: (IpAddr, u8), priority: u32) -> Result<(), String> {
        self.0.lock().unwrap().remove(&(table, prefix, priority));
        Ok(())
    }
    fn owned(&mut self) -> Result<Vec<RouteId>, String> {
        Ok(self.0.lock().unwrap().keys().copied().collect())
    }
}

#[test]
fn the_lowest_admin_distance_is_selected() {
    let mut rows = vec![
        route("b", "10.2.3.4", 32, 100, ("eth1", 3)),
        route("a", "10.2.3.4", 32, 101, ("veth0", 2)),
        route("c", "10.2.3.4", 32, 100, ("eth2", 4)),
        route("a", "10.9.0.0", 16, 200, ("eth1", 3)),
    ];
    select(&mut rows);
    let selected: Vec<(&str, bool)> = rows
        .iter()
        .map(|r| (r.owner.as_str(), r.selected))
        .collect();
    assert_eq!(
        selected,
        [("b", true), ("a", false), ("c", false), ("a", true)],
        "ties go to the owner name"
    );
    let cells = rows[0].cells();
    assert_eq!(cells.len(), DesiredRoute::headers().len());
    assert_eq!(
        &cells[..6],
        ["b", "254", "10.2.3.4/32", "none", "100", "true"]
    );
    assert_eq!(cells[8], "eth1 (3)");
}

async fn settle(reconciler: &mut Reconciler<'_, DesiredRoute, RouteTarget<Fake>>) {
    for _ in 0..10 {
        reconciler.run_round(std::time::Instant::now()).await.ok();
    }
}

#[tokio::test(start_paused = true)]
async fn owners_reconcile_into_the_kernel_by_selection() {
    let manager = RouteManager::new().unwrap();
    let table = manager.table();
    let init = table.register_initializer("test").unwrap();
    table.seal_initializers();
    let kernel: Kernel = Arc::default();
    let mut reconciler = Reconciler::new(
        &table,
        RouteTarget::new(Fake(Arc::clone(&kernel)), Arc::clone(&table)),
        Options::default(),
    )
    .unwrap();
    let key = (254, ("10.2.3.4".parse().unwrap(), 32), 0);
    // owner2 (AD 101) alone: installed.
    manager
        .set_owner("owner2", vec![route("", "10.2.3.4", 32, 101, ("veth0", 2))])
        .await
        .unwrap();
    settle(&mut reconciler).await;
    assert_eq!(
        kernel.lock().unwrap().get(&key).map(String::as_str),
        Some("owner2:2")
    );
    // owner1 (AD 100) comes: it wins, owner2's row stays unselected.
    manager
        .set_owner("owner1", vec![route("", "10.2.3.4", 32, 100, ("eth1", 3))])
        .await
        .unwrap();
    settle(&mut reconciler).await;
    assert_eq!(
        kernel.lock().unwrap().get(&key).map(String::as_str),
        Some("owner1:3")
    );
    let snapshot = table.snapshot();
    let selected: Vec<(String, bool)> = snapshot
        .all()
        .map(|(r, _)| (r.owner.clone(), r.selected))
        .collect();
    assert_eq!(
        selected,
        [("owner1".into(), true), ("owner2".into(), false)]
    );
    // owner1 goes: owner2's route is selected and installed again, never
    // deleted in between.
    manager.set_owner("owner1", vec![]).await.unwrap();
    settle(&mut reconciler).await;
    assert_eq!(
        kernel.lock().unwrap().get(&key).map(String::as_str),
        Some("owner2:2")
    );
    // owner2 goes: the route is deleted.
    manager.set_owner("owner2", vec![]).await.unwrap();
    settle(&mut reconciler).await;
    assert!(kernel.lock().unwrap().is_empty());
    // Prune (after initialization) removes an owned route nobody wants.
    kernel
        .lock()
        .unwrap()
        .insert((254, ("10.66.0.0".parse().unwrap(), 16), 0), "stale".into());
    manager
        .set_owner("owner1", vec![route("", "10.9.0.0", 16, 100, ("eth1", 3))])
        .await
        .unwrap();
    init.complete();
    reconciler.prune_now();
    settle(&mut reconciler).await;
    let left: Vec<_> = kernel.lock().unwrap().keys().copied().collect();
    assert_eq!(left, [(254, ("10.9.0.0".parse().unwrap(), 16), 0)]);
}
