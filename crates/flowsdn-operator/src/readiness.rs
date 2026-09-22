//! Pure observation planning. The caller watches required CRDs and re-plans on
//! changes; absence/errors never instruct process exit or CRD creation in skip mode.
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Missing,
    NotEstablished,
    Established,
    ReadFailed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrdPlan {
    pub register: bool,
    pub release_fence: bool,
    pub blockers: BTreeMap<String, Observation>,
}
pub fn crd_plan(
    k8s_enabled: bool,
    skip_creation: bool,
    required: &BTreeSet<String>,
    observations: &BTreeMap<String, Observation>,
) -> CrdPlan {
    if !k8s_enabled {
        return CrdPlan {
            register: false,
            release_fence: true,
            blockers: BTreeMap::new(),
        };
    }
    let blockers = required
        .iter()
        .filter_map(|name| {
            let observed = observations
                .get(name)
                .copied()
                .unwrap_or(Observation::Missing);
            (observed != Observation::Established).then_some((name.clone(), observed))
        })
        .collect::<BTreeMap<_, _>>();
    CrdPlan {
        register: !skip_creation,
        release_fence: blockers.is_empty(),
        blockers,
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbePlan {
    pub health_status: u16,
    pub readiness_status: u16,
}
/// Leadership is intentionally absent: healthy followers remain ready.
pub fn probes(k8s_enabled: bool, dependencies_healthy: bool, crds: &CrdPlan) -> ProbePlan {
    let health_status = if !k8s_enabled {
        501
    } else if !dependencies_healthy {
        500
    } else {
        200
    };
    let readiness_status = if health_status != 200 {
        health_status
    } else if !crds.release_fence {
        503
    } else {
        200
    };
    ProbePlan {
        health_status,
        readiness_status,
    }
}
