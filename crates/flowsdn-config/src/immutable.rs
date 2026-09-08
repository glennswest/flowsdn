//! Restart checks over already decoded configuration snapshots (§3.3.9).
//! Runtime file parsing, rotation and endpoint discovery belong to the caller.

use crate::{Class, Resolved, Value};
use std::collections::BTreeSet;
use std::fmt;

pub enum Previous<'a> {
    Absent,
    Parsed(&'a Resolved),
    /// A schema or decoding failure is a warning, never a startup failure.
    Unparseable,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Change {
    pub key: String,
    pub previous: Option<Value>,
    pub current: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Warning {
    PreviousUnparseable,
    ChangedWithoutRestoredEndpoints,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    pub changes: Vec<Change>,
    pub warnings: Vec<Warning>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Incompatible {
    pub changes: Vec<Change>,
}

impl fmt::Display for Incompatible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "immutable configuration changed while restoring endpoints: {}",
            self.changes
                .iter()
                .map(|change| change.key.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for Incompatible {}

/// Compare parsed values, ignoring source attribution and every key outside
/// the immutable set. The union of both snapshots' immutable sets prevents a
/// removed key or changed classification from silently bypassing comparison.
/// Callers must derive `has_endpoint_state` from actual endpoint state files.
/// There is no force bypass: that remains an open specification decision.
pub fn check(
    previous: Previous<'_>,
    current: &Resolved,
    restore: bool,
    has_endpoint_state: bool,
) -> Result<Report, Incompatible> {
    let previous = match previous {
        Previous::Absent => return Ok(Report::default()),
        Previous::Unparseable => {
            return Ok(Report {
                changes: Vec::new(),
                warnings: vec![Warning::PreviousUnparseable],
            });
        }
        Previous::Parsed(previous) => previous,
    };
    let keys: BTreeSet<_> = previous
        .values()
        .iter()
        .chain(current.values())
        .filter(|(_, effective)| effective.class == Class::Immutable)
        .map(|(key, _)| key)
        .collect();
    let changes: Vec<_> = keys
        .into_iter()
        .filter_map(|key| {
            let before = previous.get(key).map(|effective| &effective.value);
            let after = current.get(key).map(|effective| &effective.value);
            (before != after).then(|| Change {
                key: key.clone(),
                previous: before.cloned(),
                current: after.cloned(),
            })
        })
        .collect();
    if !changes.is_empty() && restore && has_endpoint_state {
        return Err(Incompatible { changes });
    }
    let warnings = if changes.is_empty() {
        Vec::new()
    } else {
        vec![Warning::ChangedWithoutRestoredEndpoints]
    };
    Ok(Report { changes, warnings })
}
