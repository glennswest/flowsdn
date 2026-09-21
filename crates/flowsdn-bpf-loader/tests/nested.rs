use flowsdn_bpf_loader::{MapSpec, Owner, Replacement, RDONLY_PROG, LRU_HASH};
use flowsdn_bpf_loader::nested::{self, Features, NestedSpec, Plan, Purpose, Error, ARRAY_OF_MAPS, HASH_OF_MAPS};

const MAGLEV: NestedSpec = NestedSpec {
    outer: MapSpec { map_type: HASH_OF_MAPS, key_size: 2, value_size: 4, max_entries: 65536, flags: RDONLY_PROG },
    inner: MapSpec { map_type: 2, key_size: 4, value_size: 65524, max_entries: 1, flags: 0 },
};
const CT: NestedSpec = NestedSpec {
    outer: MapSpec { map_type: ARRAY_OF_MAPS, key_size: 4, value_size: 4, max_entries: 256, flags: 0 },
    inner: MapSpec { map_type: LRU_HASH, key_size: 14, value_size: 56, max_entries: 524288, flags: 0 },
};
const MCAST: NestedSpec = NestedSpec {
    outer: MapSpec { map_type: HASH_OF_MAPS, key_size: 4, value_size: 4, max_entries: 1024, flags: 0 },
    inner: MapSpec { map_type: 1, key_size: 4, value_size: 12, max_entries: 1024, flags: 0 },
};
const ALL: Features = Features { clustermesh: true, multicast: true, maglev: true };

#[test]
fn each_outer_family_requires_its_own_feature() {
    for (purpose, spec, features) in [
        (Purpose::Maglev, MAGLEV, Features { maglev: true, ..Features::default() }),
        (Purpose::PerClusterConntrack, CT, Features { clustermesh: true, ..Features::default() }),
        (Purpose::PerClusterNat, CT, Features { clustermesh: true, ..Features::default() }),
        (Purpose::Multicast, MCAST, Features { multicast: true, ..Features::default() }),
    ] {
        assert_eq!(nested::plan(spec, None, Owner::Agent, purpose, Features::default()), Ok(Plan::Disabled));
        assert_eq!(nested::plan(spec, Some(spec), Owner::Agent, purpose, Features::default()), Ok(Plan::Disabled));
        assert_eq!(nested::plan(spec, None, Owner::Agent, purpose, features), Ok(Plan::Create { spec }));
        for other in [Purpose::Maglev, Purpose::PerClusterConntrack, Purpose::Multicast] {
            if other != purpose && !(purpose == Purpose::PerClusterNat && other == Purpose::PerClusterConntrack) {
                assert!(!other.enabled(features));
            }
        }
    }
}

#[test]
fn identical_outer_and_template_reuse_with_outer_read_only_upgrade() {
    let pinned = NestedSpec { outer: MapSpec { flags: 0, ..MAGLEV.outer }, ..MAGLEV };
    assert_eq!(nested::plan(MAGLEV, Some(pinned), Owner::Loader, Purpose::Maglev, ALL), Ok(Plan::Reuse {
        effective_spec: pinned, relaxed_program_read_only: true,
    }));
    assert_eq!(nested::plan(CT, Some(CT), Owner::Agent, Purpose::PerClusterConntrack, ALL), Ok(Plan::Reuse {
        effective_spec: CT, relaxed_program_read_only: false,
    }));
}

#[test]
fn changed_inner_template_forces_outer_replacement_even_if_outer_matches() {
    for inner in [
        MapSpec { value_size: 1028, ..MAGLEV.inner },
        MapSpec { max_entries: 2, ..MAGLEV.inner },
        MapSpec { flags: 1, ..MAGLEV.inner },
        MapSpec { map_type: 1, ..MAGLEV.inner },
        MapSpec { key_size: 8, ..MAGLEV.inner },
    ] {
        let pinned = NestedSpec { inner, ..MAGLEV };
        for (owner, expected) in [(Owner::Agent, Replacement::EmptyAgentMap), (Owner::Loader, Replacement::AtLoaderCommit)] {
            match nested::plan(MAGLEV, Some(pinned), owner, Purpose::Maglev, ALL).expect("plan") {
                Plan::Replace { inner_changes, outer_changes, replacement, .. } => {
                    assert_eq!(inner_changes, MAGLEV.inner.differences(inner));
                    assert!(!outer_changes.any());
                    assert_eq!(replacement, expected);
                }
                other => panic!("inner mismatch was ignored: {other:?}"),
            }
        }
    }
}

#[test]
fn lru_inner_capacity_is_exact_not_the_standalone_reuse_exception() {
    let pinned = NestedSpec { inner: MapSpec { max_entries: 1024, ..CT.inner }, ..CT };
    assert!(matches!(nested::plan(CT, Some(pinned), Owner::Loader, Purpose::PerClusterConntrack, ALL), Ok(Plan::Replace {
        inner_changes: flowsdn_bpf_loader::Differences { max_entries: true, .. },
        replacement: Replacement::AtLoaderCommit, ..
    })));
}

#[test]
fn invalid_and_wrong_purpose_layouts_fail_before_creation() {
    for (spec, error) in [
        (NestedSpec { outer: MapSpec { map_type: 1, ..MAGLEV.outer }, ..MAGLEV }, Error::InvalidOuterType),
        (NestedSpec { outer: MapSpec { value_size: 8, ..MAGLEV.outer }, ..MAGLEV }, Error::InvalidOuterLayout),
        (NestedSpec { outer: MapSpec { max_entries: 0, ..MAGLEV.outer }, ..MAGLEV }, Error::InvalidOuterLayout),
        (NestedSpec { inner: MapSpec { map_type: HASH_OF_MAPS, ..MAGLEV.inner }, ..MAGLEV }, Error::UnsupportedInnerType),
        (NestedSpec { inner: MapSpec { value_size: 0, ..MAGLEV.inner }, ..MAGLEV }, Error::InvalidInnerLayout),
        (NestedSpec { inner: MapSpec { key_size: 8, ..MAGLEV.inner }, ..MAGLEV }, Error::InvalidInnerLayout),
        (MCAST, Error::WrongPurpose),
    ] {
        assert_eq!(nested::plan(spec, None, Owner::Agent, Purpose::Maglev, ALL), Err(error));
    }
    let invalid_array = NestedSpec { outer: MapSpec { key_size: 2, ..CT.outer }, ..CT };
    assert_eq!(invalid_array.validate(Purpose::PerClusterConntrack), Err(Error::InvalidOuterLayout));
}

#[test]
fn cluster_outer_array_includes_the_highest_id_and_cluster_zero() {
    assert_eq!(nested::cluster_outer_entries(255), Ok(256));
    assert_eq!(nested::cluster_outer_entries(511), Ok(512));
    for invalid in [0, 254, 256, 512, u32::MAX] {
        assert_eq!(nested::cluster_outer_entries(invalid), Err(Error::InvalidClusterMaximum));
    }
}
