use flowsdn_bpf_loader::{MapPlan, MapSpec, Owner, RDONLY_PROG, Replacement, plan_map};

const SPEC: MapSpec = MapSpec {
    map_type: 1,
    key_size: 12,
    value_size: 56,
    max_entries: 1024,
    flags: 0,
};

#[test]
fn missing_pin_creates_exact_desired_specification() {
    for owner in [Owner::Agent, Owner::Loader] {
        assert_eq!(plan_map(SPEC, None, owner), MapPlan::Create { spec: SPEC });
    }
}

#[test]
fn exact_match_reuses_with_unknown_flags_unchanged() {
    for flags in [0, RDONLY_PROG, 0x8000_0001, u32::MAX] {
        let spec = MapSpec { flags, ..SPEC };
        assert_eq!(
            plan_map(spec, Some(spec), Owner::Loader),
            MapPlan::Reuse {
                effective_spec: spec,
                relaxed_program_read_only: false
            }
        );
    }
}

#[test]
fn read_write_pin_satisfies_read_only_spec_without_new_flags() {
    let desired = MapSpec {
        flags: RDONLY_PROG | 1,
        ..SPEC
    };
    let pinned = MapSpec { flags: 1, ..SPEC };
    for owner in [Owner::Agent, Owner::Loader] {
        assert_eq!(
            plan_map(desired, Some(pinned), owner),
            MapPlan::Reuse {
                effective_spec: pinned,
                relaxed_program_read_only: true
            }
        );
    }
}

#[test]
fn read_only_pin_cannot_satisfy_a_writer_and_loader_defers_replacement() {
    let pinned = MapSpec {
        flags: RDONLY_PROG,
        ..SPEC
    };
    for (owner, timing) in [
        (Owner::Agent, Replacement::EmptyAgentMap),
        (Owner::Loader, Replacement::AtLoaderCommit),
    ] {
        match plan_map(SPEC, Some(pinned), owner) {
            MapPlan::Replace {
                spec,
                existing,
                changed,
                replacement,
            } => {
                assert_eq!(spec, SPEC);
                assert_eq!(existing, pinned);
                assert!(changed.flags);
                assert_eq!(replacement, timing);
            }
            other => panic!("expected replacement, got {other:?}"),
        }
    }
}

#[test]
fn every_incompatible_attribute_is_reported() {
    let candidates = [
        MapSpec {
            map_type: 9,
            ..SPEC
        },
        MapSpec {
            key_size: 4,
            ..SPEC
        },
        MapSpec {
            value_size: 40,
            ..SPEC
        },
        MapSpec {
            max_entries: 4096,
            ..SPEC
        },
        MapSpec {
            flags: 0x8000_0000,
            ..SPEC
        },
    ];
    for pinned in candidates {
        match plan_map(SPEC, Some(pinned), Owner::Agent) {
            MapPlan::Replace {
                changed,
                replacement,
                ..
            } => {
                assert_eq!(changed, SPEC.differences(pinned));
                let count = [
                    changed.map_type,
                    changed.key_size,
                    changed.value_size,
                    changed.max_entries,
                    changed.flags,
                ]
                .into_iter()
                .filter(|v| *v)
                .count();
                assert_eq!(count, 1);
                assert_eq!(replacement, Replacement::EmptyAgentMap);
            }
            other => panic!("incompatibility must replace: {other:?}"),
        }
    }
}

#[test]
fn read_only_relaxation_cannot_hide_other_mismatches() {
    let desired = MapSpec {
        flags: RDONLY_PROG,
        ..SPEC
    };
    for pinned in [
        MapSpec {
            value_size: 40,
            ..SPEC
        },
        MapSpec { flags: 1, ..SPEC },
    ] {
        match plan_map(desired, Some(pinned), Owner::Loader) {
            MapPlan::Replace {
                spec,
                existing,
                changed,
                replacement,
            } => {
                assert_eq!(spec, desired);
                assert_eq!(existing, pinned);
                assert!(changed.flags);
                assert_eq!(replacement, Replacement::AtLoaderCommit);
            }
            other => panic!("relaxation must not hide incompatibility: {other:?}"),
        }
    }
}
