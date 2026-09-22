//! Connectivity evidence and scenario-group collection primitives, spec 19.
//! No cluster provisioner, Hubble client or end-to-end test executor.
use flowsdn_bpf_abi::ct::CtEntry;
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidCapacity,
    AlreadyActive,
    NotActive,
    StaleGroup,
    UnknownNode,
    Overflow,
    IncompleteEvidence,
}
#[derive(Clone, Debug)]
pub struct Group {
    issuer: Arc<()>,
    generation: u64,
}
impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.issuer, &other.issuer) && self.generation == other.generation
    }
}
impl Eq for Group {}
/// Data is scoped to one active scenario group and explicitly bounded per node.
/// The transport owner must cancel and join streams before finish/begin.
pub struct FlowWindow<T> {
    issuer: Arc<()>,
    capacity: usize,
    generation: u64,
    active: Option<u64>,
    nodes: BTreeMap<String, Vec<T>>,
    incomplete: bool,
}
impl<T> FlowWindow<T> {
    pub fn new(capacity_per_node: usize) -> Result<Self, Error> {
        if capacity_per_node == 0 {
            return Err(Error::InvalidCapacity);
        }
        Ok(Self {
            issuer: Arc::new(()),
            capacity: capacity_per_node,
            generation: 0,
            active: None,
            nodes: BTreeMap::new(),
            incomplete: false,
        })
    }
    pub fn begin(&mut self, nodes: impl IntoIterator<Item = String>) -> Result<Group, Error> {
        if self.active.is_some() {
            return Err(Error::AlreadyActive);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let nodes: BTreeMap<_, _> = nodes.into_iter().map(|node| (node, Vec::new())).collect();
        if nodes.is_empty() || nodes.keys().any(String::is_empty) {
            return Err(Error::UnknownNode);
        }
        self.nodes = nodes;
        self.generation = generation;
        self.incomplete = false;
        let group = Group {
            issuer: Arc::clone(&self.issuer),
            generation,
        };
        self.active = Some(generation);
        Ok(group)
    }
    fn check(&self, group: &Group) -> Result<(), Error> {
        match self.active {
            None => Err(Error::NotActive),
            Some(active)
                if active != group.generation || !Arc::ptr_eq(&self.issuer, &group.issuer) =>
            {
                Err(Error::StaleGroup)
            }
            _ => Ok(()),
        }
    }
    pub fn push(&mut self, group: &Group, node: &str, event: T) -> Result<(), Error> {
        self.check(group)?;
        let entries = self.nodes.get_mut(node).ok_or(Error::UnknownNode)?;
        if entries.len() >= self.capacity {
            self.incomplete = true;
            return Err(Error::Overflow);
        }
        entries.push(event);
        Ok(())
    }
    /// Loss markers, stream termination or decode loss invalidate negative
    /// assertions. The caller may retain the partial sample for diagnostics.
    pub fn mark_incomplete(&mut self, group: &Group) -> Result<(), Error> {
        self.check(group)?;
        self.incomplete = true;
        Ok(())
    }
    pub fn finish(&mut self, group: &Group) -> Result<BTreeMap<String, Vec<T>>, Error> {
        self.check(group)?;
        if self.incomplete {
            return Err(Error::IncompleteEvidence);
        }
        self.active = None;
        Ok(std::mem::take(&mut self.nodes))
    }
    /// Close a failed group while retaining its partial diagnostic sample.
    pub fn abort(&mut self, group: &Group) -> Result<BTreeMap<String, Vec<T>>, Error> {
        self.check(group)?;
        self.active = None;
        Ok(std::mem::take(&mut self.nodes))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CtObservation {
    /// Kernel map ID, not pin path, filename or inode.
    pub map_id: u32,
    pub tuple_key: Vec<u8>,
    pub entry: CtEntry,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseEvidence {
    SameMapAndQuiescedValue,
    ChangedMap,
    ChangedKey,
    ChangedValue,
    InvalidMapId,
}
/// Require a quiesced before/after sample while holding the original map FD
/// open across both observations, preventing kernel map-ID recycling. Exact bytes plus map ID are evidence
/// of map preservation, not proof of entry generation: no creation timestamp
/// exists in the frozen ABI, and delete/reinsert of identical data is invisible.
pub fn quiesced_ct_reuse(before: &CtObservation, after: &CtObservation) -> ReuseEvidence {
    if before.map_id == 0 || after.map_id == 0 {
        return ReuseEvidence::InvalidMapId;
    }
    if before.map_id != after.map_id {
        return ReuseEvidence::ChangedMap;
    }
    if before.tuple_key != after.tuple_key || before.tuple_key.is_empty() {
        return ReuseEvidence::ChangedKey;
    }
    if before.entry != after.entry {
        return ReuseEvidence::ChangedValue;
    }
    ReuseEvidence::SameMapAndQuiescedValue
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    TrustedPrivileged,
    DedicatedArm64,
    UpstreamCrosscheck,
    DatapathScale,
    SimulatedControlPlane,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cadence {
    ReviewedCommit,
    Nightly,
    Weekly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Placement {
    pub cadence: Cadence,
    pub real_datapath: bool,
    pub node_count: Option<u16>,
    pub merge_gate_when_operational: bool,
}
/// Declarative target placements; none is evidence of an installed runner/job.
pub const fn placement(lane: Lane) -> Placement {
    match lane {
        Lane::TrustedPrivileged => Placement {
            cadence: Cadence::ReviewedCommit,
            real_datapath: true,
            node_count: None,
            merge_gate_when_operational: true,
        },
        Lane::DedicatedArm64 => Placement {
            cadence: Cadence::Nightly,
            real_datapath: true,
            node_count: None,
            merge_gate_when_operational: false,
        },
        Lane::UpstreamCrosscheck => Placement {
            cadence: Cadence::Weekly,
            real_datapath: true,
            node_count: None,
            merge_gate_when_operational: false,
        },
        Lane::DatapathScale => Placement {
            cadence: Cadence::Nightly,
            real_datapath: true,
            node_count: Some(5),
            merge_gate_when_operational: false,
        },
        Lane::SimulatedControlPlane => Placement {
            cadence: Cadence::Weekly,
            real_datapath: false,
            node_count: Some(100),
            merge_gate_when_operational: false,
        },
    }
}
