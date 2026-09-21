//! Map lifecycle planning from map ABI/loader specification §3.2.
//! These decisions perform no syscalls, pin mutations, or program attachment.
#![cfg_attr(not(feature = "kernel"), no_std)]

/// Kernel ABI flag: programs may read this map but cannot write it.
pub const RDONLY_PROG: u32 = 1 << 7;
pub const LRU_HASH: u32 = 9;
pub const LRU_PERCPU_HASH: u32 = 10;

/// Attributes relevant to the specified pinned-map compatibility contract.
/// The owner must validate map-type/flag combinations and inner-map schemas;
/// this initial planner does not implement those kernel-specific checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapSpec {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Owner {
    Agent,
    Loader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replacement {
    /// Recreate empty; the caller must report lost contents and changed attributes.
    EmptyAgentMap,
    /// Keep the old map serving until the loader's attachment commit succeeds.
    AtLoaderCommit,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Differences {
    pub map_type: bool,
    pub key_size: bool,
    pub value_size: bool,
    pub max_entries: bool,
    pub flags: bool,
}
impl Differences {
    pub const fn any(self) -> bool {
        self.map_type || self.key_size || self.value_size || self.max_entries || self.flags
    }
}
impl MapSpec {
    pub const fn differences(self, other: Self) -> Differences {
        Differences {
            map_type: self.map_type != other.map_type,
            key_size: self.key_size != other.key_size,
            value_size: self.value_size != other.value_size,
            max_entries: self.max_entries != other.max_entries,
            flags: self.flags != other.flags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapPlan {
    Create {
        spec: MapSpec,
    },
    Reuse {
        effective_spec: MapSpec,
        /// True only for the permitted read-write-map upgrade exception.
        relaxed_program_read_only: bool,
        /// Report this mismatch to the operator; the pinned capacity is used.
        retained_capacity: Option<RetainedCapacity>,
    },
    Replace {
        spec: MapSpec,
        existing: MapSpec,
        changed: Differences,
        replacement: Replacement,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedCapacity {
    pub requested: u32,
    pub pinned: u32,
}

/// Compare kernel-reported pinned attributes with the desired specification.
/// LRU capacity-only changes preserve live contents and report the old capacity.
/// Only the program-read-only upgrade flag mismatch is tolerated. All other flags,
/// including unrecognized bits, participate in exact comparison. A failed
/// relaxation never changes the specification used to create a replacement.
/// Loader replacements are staged for commit, including read-only downgrades.
/// No contents are migrated by this policy.
pub const fn plan_map(spec: MapSpec, existing: Option<MapSpec>, owner: Owner) -> MapPlan {
    let Some(existing) = existing else {
        return MapPlan::Create { spec };
    };
    let relaxed = spec.flags & RDONLY_PROG != 0 && existing.flags & RDONLY_PROG == 0;
    let mut effective_spec = MapSpec {
        flags: if relaxed {
            spec.flags & !RDONLY_PROG
        } else {
            spec.flags
        },
        ..spec
    };
    let changed = effective_spec.differences(existing);
    let retained_capacity = if matches!(spec.map_type, LRU_HASH | LRU_PERCPU_HASH)
        && spec.max_entries != 0
        && existing.max_entries != 0
        && changed.max_entries
        && !changed.map_type
        && !changed.key_size
        && !changed.value_size
        && !changed.flags
    {
        effective_spec.max_entries = existing.max_entries;
        Some(RetainedCapacity {
            requested: spec.max_entries,
            pinned: existing.max_entries,
        })
    } else {
        None
    };
    if !effective_spec.differences(existing).any() {
        MapPlan::Reuse {
            effective_spec,
            relaxed_program_read_only: relaxed,
            retained_capacity,
        }
    } else {
        MapPlan::Replace {
            spec,
            existing,
            changed: spec.differences(existing),
            replacement: match owner {
                Owner::Agent => Replacement::EmptyAgentMap,
                Owner::Loader => Replacement::AtLoaderCommit,
            },
        }
    }
}

/// Refuse a node-ID map replacement until an explicit migration can preserve IDs.
/// Node IDs are encoded into live IPsec marks; empty recreation is not safe.
/// A missing map is a fresh create, not recovery of externally lost pinned state.
pub const fn plan_node_id_map(
    spec: MapSpec,
    existing: Option<MapSpec>,
    owner: Owner,
) -> Result<MapPlan, NodeIdMapMigrationRequired> {
    match plan_map(spec, existing, owner) {
        MapPlan::Replace { changed, .. } => Err(NodeIdMapMigrationRequired { changed }),
        plan => Ok(plan),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeIdMapMigrationRequired {
    pub changed: Differences,
}
impl core::fmt::Display for NodeIdMapMigrationRequired {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("node-ID map replacement requires an explicit ID-preserving migration")
    }
}
impl core::error::Error for NodeIdMapMigrationRequired {}

/// Live local-delivery object ownership, behind an explicit kernel feature.
#[cfg(feature = "kernel")]
pub mod kernel;
pub mod layout;
pub mod nested;
pub mod tails;
