//! L2 neighbor management (spec 10 §3.4, §5.7; #469), with
//! `kubernetes.l2-neigh-discovery` (the reference's `enable-l2-neigh-discovery`,
//! default off). `bpf_redirect_neigh` and `bpf_fib_lookup` need resolved
//! next hops; the kernel would resolve them lazily and drop the first
//! packets of a cold neighbor. So the agent keeps a kernel-managed neighbor
//! entry (`NTF_EXT_LEARNED` + `NTF_EXT_MANAGED`) for every next hop of
//! every forwardable IP on every selected device, and the kernel resolves
//! and refreshes those entries itself.
//!
//! - **Forwardable IPs**: the other nodes' InternalIPs. (The reference also
//!   feeds Service backends, for XDP acceleration only; flowsdn has none.)
//! - **Selected devices**: the node's uplinks (#408) with a hardware address.
//! - **Next hops**: `ip route get <ip> oif <device> fibmatch` per pair
//!   ([`Connector::next_hops`]): the gateway(s) on that device, else the IP
//!   on-link; unreachable on a device means no entry there.
//! - **Reconcile**: add every desired entry; delete `NTF_EXT_LEARNED` entries
//!   on selected devices that are not desired (an administrator's entries,
//!   without that flag, are never touched). Once at start, on every change
//!   of the inputs (at most one per [`RATE`]), and a full resync every
//!   [`RESYNC`].
//!
//! The managed-neighbor probe ([`flowsdn_connector::neighbor::probe_managed`])
//! runs when the setting is on, before this thread starts; a failure stops
//! the agent (no fallback, #132).
use crate::kubernetes::{Shared, View, lock};
use flowsdn_connector::{
    Connector,
    neighbor::{Lookup, probe_managed},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::{Duration, Instant},
};

/// One recalculation per this long after a change (spec 10 §5.7).
pub const RATE: Duration = Duration::from_secs(15);
/// A full resync this often, whatever changed.
pub const RESYNC: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_secs(1);

/// What the desired neighbors are computed from.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Inputs {
    pub forwardable: BTreeSet<IpAddr>,
    /// Selected device index -> name.
    pub devices: BTreeMap<u32, String>,
}

/// The inputs the view gives: other nodes' InternalIPs, and the uplinks
/// with a hardware address.
pub fn inputs(view: &View) -> Inputs {
    Inputs {
        forwardable: view
            .nodes
            .iter()
            .filter(|n| n.name != view.local_node)
            .flat_map(|n| n.internal_ips.iter().copied())
            .collect(),
        devices: view
            .uplinks
            .uplinks
            .iter()
            .filter(|u| u.mac != [0; 6] && u.index != 0)
            .map(|u| (u.index, u.name.clone()))
            .collect(),
    }
}

/// When to recalculate.
#[derive(Clone, Debug, Default)]
pub struct Calculator {
    last: Option<(Instant, Inputs)>,
    resynced: Option<Instant>,
}
impl Calculator {
    /// `Some(true)`: a full resync is due (start, or [`RESYNC`] since the
    /// last); `Some(false)`: the inputs changed and [`RATE`] has passed since
    /// the last calculation; `None`: nothing to do yet.
    pub fn due(&self, now: Instant, inputs: &Inputs) -> Option<bool> {
        let resync = self
            .resynced
            .is_none_or(|at| now.saturating_duration_since(at) >= RESYNC);
        if resync {
            return Some(true);
        }
        match &self.last {
            Some((at, before)) if before != inputs => {
                (now.saturating_duration_since(*at) >= RATE).then_some(false)
            }
            Some(_) => None,
            None => Some(false),
        }
    }
    pub fn done(&mut self, now: Instant, inputs: Inputs, resync: bool) {
        self.last = Some((now, inputs));
        if resync {
            self.resynced = Some(now);
        }
    }
}

/// Learned entries on selected devices that are not desired.
pub fn stale(
    desired: &BTreeSet<(u32, IpAddr)>,
    learned: &[(u32, IpAddr)],
    devices: &BTreeMap<u32, String>,
) -> Vec<(u32, IpAddr)> {
    learned
        .iter()
        .filter(|(index, _)| devices.contains_key(index))
        .filter(|entry| !desired.contains(entry))
        .copied()
        .collect()
}

/// What one reconcile did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Outcome {
    pub desired: BTreeSet<(u32, IpAddr)>,
    pub removed: Vec<(u32, IpAddr)>,
    /// (address, device) pairs with no route on that device.
    pub unreachable: usize,
    pub errors: Vec<String>,
}

/// Compute the desired entries for `inputs` and make the kernel hold them
/// (#576 stage 4): the forwardable IPs (`forwardable-ips`, owner `node`) give,
/// per selected device, the next hops in `desired-neighbors`, which are
/// reconciled into managed entries through `flowsdn-reconcile`; prune
/// deletes learned entries on selected devices that no row wants.
pub fn reconcile(connector: &Connector, inputs: &Inputs) -> Outcome {
    use flowsdn_node::neighbors::{NeighborTarget, forwardable};
    use flowsdn_node::rows::DesiredNeighbor;
    use flowsdn_reconcile::{Kind, Options, Reconciler};
    use futures::executor::block_on;
    let mut outcome = Outcome::default();
    let ips = forwardable(inputs.forwardable.iter().map(|ip| (*ip, "node".to_owned())));
    for row in &ips {
        for (index, name) in &inputs.devices {
            match connector.next_hops(row.addr, *index) {
                Ok(Lookup::Hops(hops)) => {
                    outcome
                        .desired
                        .extend(hops.into_iter().map(|h| (*index, h)));
                }
                Ok(Lookup::Unreachable) => {
                    outcome.unreachable = outcome.unreachable.saturating_add(1);
                }
                Err(error) => outcome
                    .errors
                    .push(format!("route to {} on {name}: {error}", row.addr)),
            }
        }
    }
    let table = match flowsdn_table::Table::new(Vec::new()) {
        Ok(table) => table,
        Err(error) => {
            outcome.errors.push(format!("desired-neighbors: {error}"));
            return outcome;
        }
    };
    let init = match table.register_initializer("neighbors") {
        Ok(init) => init,
        Err(error) => {
            outcome.errors.push(format!("desired-neighbors: {error}"));
            return outcome;
        }
    };
    table.seal_initializers();
    let rows: Vec<DesiredNeighbor> = outcome
        .desired
        .iter()
        .map(|(link_index, addr)| DesiredNeighbor {
            addr: *addr,
            link_index: *link_index,
        })
        .collect();
    if let Err(error) = block_on(flowsdn_node::set_all(&table, rows)) {
        outcome.errors.push(format!("desired-neighbors: {error}"));
        return outcome;
    }
    init.complete();
    let ops = Ops {
        connector,
        devices: &inputs.devices,
    };
    let mut reconciler = match Reconciler::new(&table, NeighborTarget::new(ops), Options::default())
    {
        Ok(reconciler) => reconciler,
        Err(error) => {
            outcome.errors.push(format!("neighbor reconciler: {error}"));
            return outcome;
        }
    };
    reconciler.prune_now();
    // The connector runs its own runtime, so this is driven without one.
    for _ in 0..16 {
        let _ = block_on(reconciler.run_round(Instant::now()));
        if !reconciler.has_pending_work() {
            break;
        }
    }
    for (row, _) in table.snapshot().all() {
        if let Some(status) = reconciler.status(&flowsdn_table::Keyed::primary_key(&*row))
            && status.kind == Kind::Error
        {
            outcome.errors.push(format!(
                "neighbor {} on {}: {}",
                row.addr,
                row.link_index,
                status.error.unwrap_or_default()
            ));
        }
    }
    if let Some(error) = reconciler.prune_status().and_then(|p| p.error.clone()) {
        outcome.errors.push(error);
    }
    outcome.removed = reconciler
        .target()
        .removed
        .iter()
        .map(|n| (n.link_index, n.addr))
        .collect();
    outcome
}

/// `desired-neighbors` over netlink: learned entries on selected devices.
struct Ops<'a> {
    connector: &'a Connector,
    devices: &'a BTreeMap<u32, String>,
}
impl flowsdn_node::neighbors::NeighborOps for Ops<'_> {
    fn add(&mut self, n: &flowsdn_node::rows::DesiredNeighbor) -> Result<(), String> {
        self.connector
            .add_managed(n.link_index, n.addr)
            .map_err(|e| e.to_string())
    }
    fn delete(&mut self, n: &flowsdn_node::rows::DesiredNeighbor) -> Result<(), String> {
        self.connector
            .delete_neighbor(n.link_index, n.addr)
            .map_err(|e| format!("delete neighbor {} on {}: {e}", n.addr, n.link_index))
    }
    fn learned(&mut self) -> Result<Vec<flowsdn_node::rows::DesiredNeighbor>, String> {
        let learned = self
            .connector
            .learned()
            .map_err(|e| format!("list neighbors: {e}"))?;
        Ok(stale(&BTreeSet::new(), &learned, self.devices)
            .into_iter()
            .map(|(link_index, addr)| flowsdn_node::rows::DesiredNeighbor { addr, link_index })
            .collect())
    }
}

/// The `neighbors` part of `/v1/healthz`.
pub fn status(inputs: &Inputs, outcome: &Outcome, resync: bool, pruned: usize) -> Value {
    json!({
        "enabled": true,
        "devices": inputs.devices.values().collect::<Vec<_>>(),
        "forwardable": inputs.forwardable.len(),
        "desired": outcome.desired.len(),
        "unreachable": outcome.unreachable,
        "pruned": pruned,
        "last": if resync { "resync" } else { "change" },
        "errors": outcome.errors,
    })
}

/// The managed-neighbor probe, as the agent's start runs it: an error names
/// what failed and why the agent stops.
pub fn probe() -> Result<(), String> {
    probe_managed().map_err(|error| {
        format!(
            "kubernetes.l2-neigh-discovery is on but this kernel cannot keep managed neighbor \
             entries (NTF_EXT_MANAGED, Linux 5.16+): {error}"
        )
    })
}

/// The `flowsdn-neighbors` thread, for the agent's whole life.
pub fn run(view: &Shared) {
    let connector = match Connector::open() {
        Ok(connector) => connector,
        Err(error) => {
            lock(view)
                .errors
                .insert("neighbors".into(), format!("netlink: {error}"));
            return;
        }
    };
    let mut calculator = Calculator::default();
    let mut pruned = 0usize;
    loop {
        let now = Instant::now();
        let current = inputs(&lock(view));
        if let Some(resync) = calculator.due(now, &current) {
            let outcome = reconcile(&connector, &current);
            pruned = pruned.saturating_add(outcome.removed.len());
            for (index, ip) in &outcome.removed {
                crate::log::logln!(
                    "neighbors: removed learned entry {ip} on {index} (not a next hop)"
                );
            }
            let mut shared = lock(view);
            if outcome.errors.is_empty() {
                shared.errors.remove("neighbors");
            } else {
                shared
                    .errors
                    .insert("neighbors".into(), outcome.errors.join("; "));
            }
            shared.neighbors = status(&current, &outcome, resync, pruned);
            drop(shared);
            calculator.done(now, current, resync);
        }
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
#[path = "neighbors_tests.rs"]
mod tests;
