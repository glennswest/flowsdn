//! Map lifecycle planning from map ABI/loader specification §3.2.
//! These decisions perform no syscalls, pin mutations, or program attachment.
#![no_std]

/// Kernel ABI flag: programs may read this map but cannot write it.
pub const RDONLY_PROG: u32 = 1 << 7;

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
    },
    Replace {
        spec: MapSpec,
        existing: MapSpec,
        changed: Differences,
        replacement: Replacement,
    },
}

/// Compare kernel-reported pinned attributes with the desired specification.
/// Only the program-read-only upgrade mismatch is tolerated. All other flags,
/// including unrecognized bits, participate in exact comparison. A failed
/// relaxation never changes the specification used to create a replacement.
/// Loader replacements are staged for commit, including read-only downgrades.
/// No contents are migrated by this policy.
pub const fn plan_map(spec: MapSpec, existing: Option<MapSpec>, owner: Owner) -> MapPlan {
    let Some(existing) = existing else {
        return MapPlan::Create { spec };
    };
    let relaxed = spec.flags & RDONLY_PROG != 0 && existing.flags & RDONLY_PROG == 0;
    let effective_spec = MapSpec {
        flags: if relaxed {
            spec.flags & !RDONLY_PROG
        } else {
            spec.flags
        },
        ..spec
    };
    if !effective_spec.differences(existing).any() {
        MapPlan::Reuse {
            effective_spec,
            relaxed_program_read_only: relaxed,
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

pub mod layout;
pub mod tails;
