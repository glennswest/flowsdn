//! Feature-gated outer-map and inner-template planning from specification §2.2.
//! No map descriptors are created, updated or pinned by these decisions.
use crate::{Differences, MapPlan, MapSpec, Owner, Replacement, plan_map};
use core::fmt;

pub const ARRAY_OF_MAPS: u32 = 12;
pub const HASH_OF_MAPS: u32 = 13;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Features {
    pub clustermesh: bool,
    pub multicast: bool,
    pub maglev: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    PerClusterConntrack,
    PerClusterNat,
    Multicast,
    Maglev,
}
impl Purpose {
    pub const fn enabled(self, features: Features) -> bool {
        match self {
            Self::PerClusterConntrack | Self::PerClusterNat => features.clustermesh,
            Self::Multicast => features.multicast,
            Self::Maglev => features.maglev,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedSpec {
    pub outer: MapSpec,
    pub inner: MapSpec,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidOuterType,
    InvalidOuterLayout,
    UnsupportedInnerType,
    InvalidInnerLayout,
    WrongPurpose,
    InvalidClusterMaximum,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOuterType => "outer map must be ARRAY_OF_MAPS or HASH_OF_MAPS",
            Self::InvalidOuterLayout => "outer map needs a nonempty key, four-byte value and positive capacity; arrays require four-byte keys",
            Self::UnsupportedInnerType => "inner map must use the supported HASH, ARRAY or LRU_HASH layout",
            Self::InvalidInnerLayout => "inner map requires nonempty key/value and positive capacity; arrays require four-byte keys",
            Self::WrongPurpose => "map-in-map layout does not match its feature purpose",
            Self::InvalidClusterMaximum => "connected-cluster maximum must be 255 or 511",
        })
    }
}
impl core::error::Error for Error {}

impl NestedSpec {
    /// Validate the catalogue's supported shapes. Kernel flag legality and
    /// BTF compatibility remain syscall-owner checks; nested inner maps are
    /// deliberately unsupported. Inner capacity is an exact template contract.
    pub const fn validate(self, purpose: Purpose) -> Result<(), Error> {
        if !matches!(self.outer.map_type, ARRAY_OF_MAPS | HASH_OF_MAPS) {
            return Err(Error::InvalidOuterType);
        }
        if self.outer.key_size == 0
            || self.outer.value_size != 4
            || self.outer.max_entries == 0
            || (self.outer.map_type == ARRAY_OF_MAPS && self.outer.key_size != 4)
        {
            return Err(Error::InvalidOuterLayout);
        }
        if !matches!(self.inner.map_type, 1 | 2 | crate::LRU_HASH) {
            return Err(Error::UnsupportedInnerType);
        }
        if self.inner.key_size == 0
            || self.inner.value_size == 0
            || self.inner.max_entries == 0
            || (self.inner.map_type == 2 && self.inner.key_size != 4)
        {
            return Err(Error::InvalidInnerLayout);
        }
        let correct = match purpose {
            Purpose::PerClusterConntrack | Purpose::PerClusterNat => {
                self.outer.map_type == ARRAY_OF_MAPS && self.inner.map_type == crate::LRU_HASH
            }
            Purpose::Multicast => {
                self.outer.map_type == HASH_OF_MAPS
                    && self.outer.key_size == 4
                    && self.inner.map_type == 1
            }
            Purpose::Maglev => {
                self.outer.map_type == HASH_OF_MAPS
                    && self.outer.key_size == 2
                    && self.inner.map_type == 2
                    && self.inner.max_entries == 1
            }
        };
        if !correct {
            return Err(Error::WrongPurpose);
        }
        Ok(())
    }
}

/// Array keys are inclusive cluster IDs, including the cluster-zero slot.
pub const fn cluster_outer_entries(maximum: u32) -> Result<u32, Error> {
    match maximum {
        255 => Ok(256),
        511 => Ok(512),
        _ => Err(Error::InvalidClusterMaximum),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plan {
    /// Do not create/open a map; stale pin removal belongs to the startup sweep.
    Disabled,
    Create {
        spec: NestedSpec,
    },
    Reuse {
        effective_spec: NestedSpec,
        relaxed_program_read_only: bool,
    },
    Replace {
        spec: NestedSpec,
        existing: NestedSpec,
        outer_changes: Differences,
        inner_changes: Differences,
        replacement: Replacement,
    },
}

/// Compare both outer attributes and the original inner template. Looking only
/// at an outer map's four-byte value would miss an incompatible Maglev table.
/// Caller updates outer slots with inner FDs, never the IDs returned by lookup.
pub fn plan(
    spec: NestedSpec,
    existing: Option<NestedSpec>,
    owner: Owner,
    purpose: Purpose,
    features: Features,
) -> Result<Plan, Error> {
    if !purpose.enabled(features) {
        return Ok(Plan::Disabled);
    }
    spec.validate(purpose)?;
    let Some(existing) = existing else {
        return Ok(Plan::Create { spec });
    };
    let outer = plan_map(spec.outer, Some(existing.outer), owner);
    let inner_changes = spec.inner.differences(existing.inner);
    if !inner_changes.any()
        && let MapPlan::Reuse {
            effective_spec,
            relaxed_program_read_only,
            ..
        } = outer
    {
        return Ok(Plan::Reuse {
            effective_spec: NestedSpec {
                outer: effective_spec,
                inner: spec.inner,
            },
            relaxed_program_read_only,
        });
    }
    Ok(Plan::Replace {
        spec,
        existing,
        outer_changes: spec.outer.differences(existing.outer),
        inner_changes,
        replacement: match owner {
            Owner::Agent => Replacement::EmptyAgentMap,
            Owner::Loader => Replacement::AtLoaderCommit,
        },
    })
}
