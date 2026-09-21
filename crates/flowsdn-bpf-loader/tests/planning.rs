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
                relaxed_program_read_only: false,
                retained_capacity: None
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
                relaxed_program_read_only: true,
                retained_capacity: None
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

#[test]
fn lru_capacity_changes_preserve_contents_and_report_effective_capacity() {
    use flowsdn_bpf_loader::{LRU_HASH, LRU_PERCPU_HASH, RetainedCapacity};
    for map_type in [LRU_HASH, LRU_PERCPU_HASH] {
        for (requested, pinned) in [(1024, 4096), (4096, 1024)] {
            let spec = MapSpec {
                map_type,
                max_entries: requested,
                ..SPEC
            };
            let existing = MapSpec {
                max_entries: pinned,
                ..spec
            };
            for owner in [Owner::Agent, Owner::Loader] {
                assert_eq!(
                    plan_map(spec, Some(existing), owner),
                    MapPlan::Reuse {
                        effective_spec: existing,
                        relaxed_program_read_only: false,
                        retained_capacity: Some(RetainedCapacity { requested, pinned }),
                    }
                );
            }
        }
    }
}

#[test]
fn lru_capacity_tolerance_cannot_hide_schema_flags_or_zero_capacity() {
    let spec = MapSpec {
        map_type: flowsdn_bpf_loader::LRU_HASH,
        ..SPEC
    };
    for existing in [
        MapSpec {
            max_entries: 2048,
            key_size: 4,
            ..spec
        },
        MapSpec {
            max_entries: 2048,
            value_size: 40,
            ..spec
        },
        MapSpec {
            max_entries: 2048,
            flags: 2,
            ..spec
        },
        MapSpec {
            max_entries: 2048,
            map_type: 1,
            ..spec
        },
        MapSpec {
            max_entries: 0,
            ..spec
        },
    ] {
        assert!(matches!(
            plan_map(spec, Some(existing), Owner::Agent),
            MapPlan::Replace { .. }
        ));
    }
    assert!(matches!(
        plan_map(
            MapSpec {
                max_entries: 0,
                ..spec
            },
            Some(spec),
            Owner::Agent
        ),
        MapPlan::Replace { .. }
    ));
}

#[test]
fn node_ids_cannot_be_silently_discarded_by_any_replacement() {
    use flowsdn_bpf_loader::plan_node_id_map;
    let spec = MapSpec {
        map_type: 1,
        key_size: 20,
        value_size: 4,
        max_entries: 16384,
        flags: RDONLY_PROG | 1,
    };
    for owner in [Owner::Agent, Owner::Loader] {
        assert_eq!(
            plan_node_id_map(spec, None, owner),
            Ok(MapPlan::Create { spec })
        );
        assert!(matches!(
            plan_node_id_map(spec, Some(spec), owner),
            Ok(MapPlan::Reuse { .. })
        ));
        // The read-write upgrade exception preserves the original contents.
        assert!(matches!(
            plan_node_id_map(spec, Some(MapSpec { flags: 1, ..spec }), owner),
            Ok(MapPlan::Reuse {
                relaxed_program_read_only: true,
                ..
            })
        ));
        for existing in [
            MapSpec {
                key_size: 24,
                ..spec
            },
            MapSpec {
                value_size: 8,
                ..spec
            },
            MapSpec {
                max_entries: 32768,
                ..spec
            },
            MapSpec {
                flags: spec.flags | 2,
                ..spec
            },
        ] {
            let refused =
                plan_node_id_map(spec, Some(existing), owner).expect_err("migration required");
            assert_eq!(refused.changed, spec.differences(existing));
        }
    }
}
