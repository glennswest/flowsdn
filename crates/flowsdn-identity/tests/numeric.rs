use flowsdn_identity::*;

fn id(value: u32) -> NumericIdentity {
    NumericIdentity::new(value).expect("valid fixture")
}

#[test]
fn reserved_names_numbers_and_holes_are_distinct() {
    let names = [
        "unknown",
        "host",
        "world",
        "unmanaged",
        "health",
        "init",
        "remote-node",
        "kube-apiserver",
        "ingress",
        "world-ipv4",
        "world-ipv6",
        "aggregate-cluster",
        "aggregate-cluster-mesh",
        "aggregate-world",
        "aggregate-remote-node",
    ];
    for (number, name) in names.into_iter().enumerate() {
        let number = u32::try_from(number).expect("small fixture");
        let reserved = ReservedIdentity::from_name(name).expect("reserved name");
        assert_eq!(reserved.numeric().get(), number);
        assert_eq!(reserved.name(), name);
        assert_eq!(ReservedIdentity::from_number(number), Some(reserved));
        assert_eq!(id(number).class(), IdentityClass::Reserved(reserved));
    }
    assert_eq!(ReservedIdentity::from_name("reserved:host"), None);
    assert_eq!(ReservedIdentity::from_name("Host"), None);
    for number in [15, 99, 116, 127] {
        assert_eq!(id(number).class(), IdentityClass::UnallocatedReserved);
        assert_eq!(ReservedIdentity::from_number(number), None);
    }
    for number in [100, 101, 107, 108, 109, 115] {
        assert_eq!(id(number).class(), IdentityClass::DeprecatedReserved);
    }
    assert_eq!(
        WELL_KNOWN_IDENTITIES,
        [102, 103, 104, 105, 106, 110, 111, 112, 113, 114]
    );
    for number in WELL_KNOWN_IDENTITIES {
        assert_eq!(id(number).class(), IdentityClass::WellKnown);
    }
    for number in [128, 255] {
        assert_eq!(id(number).class(), IdentityClass::UserReserved);
    }
    assert_eq!(id(256).class(), IdentityClass::Global);
}

#[test]
fn numeric_boundaries_reject_empty_scopes_and_overflow_without_truncation() {
    for number in [
        0,
        WIRE_MAX,
        0x0100_0001,
        0x01ff_ffff,
        0x0200_0001,
        MAX_SUPPORTED_IDENTITY,
    ] {
        assert_eq!(id(number).get(), number);
    }
    for number in [0x0100_0000, 0x0200_0000] {
        assert_eq!(
            NumericIdentity::new(number),
            Err(IdentityError::EmptyScopedIdentity)
        );
    }
    for number in [0x0300_0000, u32::MAX] {
        assert_eq!(
            NumericIdentity::new(number),
            Err(IdentityError::UnsupportedScope)
        );
    }
    assert_eq!(
        NumericIdentity::try_from(0x1_0000_0001_u64),
        Err(IdentityError::ExceedsU32)
    );
    assert_eq!(
        NumericIdentity::local(0),
        Err(IdentityError::EmptyScopedIdentity)
    );
    assert_eq!(
        NumericIdentity::remote_node(0x0100_0000),
        Err(IdentityError::InvalidScopeIndex)
    );
}

#[test]
fn entire_local_scope_is_cidr_and_world_including_above_65535() {
    for index in [1, 65535, 65536, WIRE_MAX] {
        let local = NumericIdentity::local(index).expect("local");
        assert!(local.is_cidr());
        assert!(local.is_world());
        assert_eq!(local.scope(), Scope::Local);
        let node = NumericIdentity::remote_node(index).expect("node");
        assert!(!node.is_cidr());
        assert!(!node.is_world());
        assert_eq!(node.scope(), Scope::RemoteNode);
    }
    for number in [2, 9, 10] {
        assert!(id(number).is_world());
    }
    for number in [0, 1, 6, 13, WIRE_MAX] {
        assert!(!id(number).is_world());
    }
}

#[test]
fn independent_numeric_and_wire_byte_fixtures() {
    let numeric = id(0x0123_4567);
    assert_eq!(numeric.to_le_bytes(), [0x67, 0x45, 0x23, 0x01]);
    assert_eq!(numeric.to_be_bytes(), [0x01, 0x23, 0x45, 0x67]);
    assert_eq!(
        NumericIdentity::from_le_bytes([0x67, 0x45, 0x23, 1]),
        Ok(numeric)
    );
    assert_eq!(
        NumericIdentity::from_be_bytes([1, 0x23, 0x45, 0x67]),
        Ok(numeric)
    );
    assert_eq!(
        NumericIdentity::from_be_bytes([3, 0, 0, 1]),
        Err(IdentityError::UnsupportedScope)
    );
    let wire = WireIdentity::new(id(0x00ab_cdef)).expect("wire");
    assert_eq!(wire.to_be_bytes(), [0xab, 0xcd, 0xef]);
    assert_eq!(WireIdentity::from_be_bytes([0xab, 0xcd, 0xef]), wire);
    assert_eq!(
        WireIdentity::from_be_bytes([0xff, 0xff, 0xff]).get(),
        WIRE_MAX
    );
    for scoped in [numeric, id(MAX_SUPPORTED_IDENTITY)] {
        assert_eq!(
            WireIdentity::new(scoped),
            Err(IdentityError::ScopedIdentityOnWire)
        );
        assert_eq!(scoped.tunnel_id(), Err(IdentityError::ScopedIdentityOnWire));
    }
}

#[test]
fn tunnel_world_conversion_is_explicit_and_family_sensitive() {
    for number in [2, 9, 10] {
        let wire = id(number).tunnel_id().expect("tunnel");
        assert_eq!(wire.get(), 2);
        assert_eq!(wire.received(IpFamily::V4, true), id(9));
        assert_eq!(wire.received(IpFamily::V6, true), id(10));
        assert_eq!(wire.received(IpFamily::V4, false), id(2));
        assert_eq!(wire.received(IpFamily::V6, false), id(2));
        assert_eq!(
            WireIdentity::new(id(number)).expect("raw wire").get(),
            number
        );
    }
    assert_eq!(
        id(0x123456)
            .tunnel_id()
            .expect("tunnel")
            .received(IpFamily::V6, true),
        id(0x123456)
    );
}

#[test]
fn both_cluster_encodings_partition_all_global_allocation_ranges() {
    for (maximum, shift, mask) in [(255, 16, 65535), (511, 15, 32767)] {
        let encoding = ClusterEncoding::new(maximum).expect("encoding");
        assert_eq!(encoding.shift(), shift);
        assert_eq!(encoding.index_mask(), mask);
        let mut previous_max = 255;
        for cluster in 0..=maximum {
            let range = encoding.allocation_range(cluster).expect("range");
            assert_eq!(range.min.get().checked_sub(previous_max), Some(1));
            assert_eq!(encoding.global_cluster_id(range.min), Ok(cluster));
            assert_eq!(encoding.global_cluster_id(range.max), Ok(cluster));
            let first_index = if cluster == 0 { 256 } else { 0 };
            assert_eq!(encoding.global(cluster, first_index), Ok(range.min));
            assert_eq!(encoding.global(cluster, mask), Ok(range.max));
            previous_max = range.max.get();
        }
        assert_eq!(previous_max, WIRE_MAX);
        assert_eq!(
            encoding.global(0, 255),
            Err(IdentityError::OutsideAllocationRange)
        );
        assert_eq!(
            encoding.global(1, mask.checked_add(1).expect("small fixture")),
            Err(IdentityError::OutsideAllocationRange)
        );
        assert_eq!(
            encoding.global_cluster_id(id(0x0100_0001)),
            Err(IdentityError::ScopedIdentityHasNoGlobalCluster)
        );
    }
    let wide = ClusterEncoding::new(511).expect("encoding");
    assert_eq!(wide.global(256, 0x1234), Ok(id(0x0080_1234)));
}

#[test]
fn meshing_checks_cluster_bounds_and_exact_mark_collision_bit() {
    for maximum in [0, 254, 256, 510, 512] {
        assert_eq!(
            ClusterEncoding::new(maximum),
            Err(IdentityError::InvalidClusterLimit)
        );
    }
    let narrow = ClusterEncoding::new(255).expect("encoding");
    assert_eq!(
        narrow.validate_meshing(0, false),
        Err(IdentityError::ClusterUnset)
    );
    assert_eq!(
        narrow.validate_meshing(256, false),
        Err(IdentityError::InvalidClusterId)
    );
    assert_eq!(narrow.validate_meshing(255, false), Ok(()));
    assert_eq!(narrow.validate_meshing(127, true), Ok(()));
    assert_eq!(
        narrow.validate_meshing(128, true),
        Err(IdentityError::MarkCollision)
    );
    let wide = ClusterEncoding::new(511).expect("encoding");
    assert_eq!(wide.validate_meshing(256, true), Ok(()));
    assert_eq!(
        wide.validate_meshing(384, true),
        Err(IdentityError::MarkCollision)
    );
    assert_eq!(wide.validate_meshing(511, false), Ok(()));
}

#[test]
fn remote_allocations_and_ipcache_reserved_exceptions_are_separate() {
    let encoding = ClusterEncoding::new(255).expect("encoding");
    for number in [0, 2, 99, 100, 255] {
        assert_eq!(encoding.validate_remote_ipcache(3, id(number)), Ok(()));
        assert_eq!(
            encoding.validate_remote_allocated(3, id(number)),
            Err(IdentityError::OutsideAllocationRange)
        );
    }
    for number in [0x030000, 0x03ffff] {
        assert_eq!(encoding.validate_remote_allocated(3, id(number)), Ok(()));
        assert_eq!(encoding.validate_remote_ipcache(3, id(number)), Ok(()));
    }
    for number in [256, 0x02ffff, 0x040000, 0x0103_0001] {
        assert_eq!(
            encoding.validate_remote_ipcache(3, id(number)),
            Err(IdentityError::OutsideAllocationRange)
        );
    }
    assert_eq!(
        encoding.validate_remote_ipcache(0, id(2)),
        Err(IdentityError::ClusterUnset)
    );
}

#[test]
fn aggregation_matches_reserved_exceptions_and_scope_precedence() {
    assert_eq!(
        ALL_AGGREGATES.map(|value| value.numeric().get()),
        [0, 14, 13, 11, 12]
    );
    for maximum in [255, 511] {
        let encoding = ClusterEncoding::new(maximum).expect("encoding");
        for aggregate in ALL_AGGREGATES {
            assert_eq!(
                encoding.aggregate_for(aggregate.numeric(), 3),
                Ok(aggregate)
            );
        }
        for number in [1, 2, 9, 10, 15, 99] {
            assert_eq!(
                encoding.aggregate_for(id(number), 0),
                Ok(ReservedIdentity::Unknown)
            );
        }
        for number in [100, 102, 128, 255, 256] {
            assert_eq!(
                encoding.aggregate_for(id(number), 0),
                Ok(ReservedIdentity::AggregateCluster)
            );
            assert_eq!(
                encoding.aggregate_for(id(number), 3),
                Ok(ReservedIdentity::AggregateClusterMesh)
            );
        }
        let local_global = encoding.global(3, 0).expect("global");
        assert_eq!(
            encoding.aggregate_for(local_global, 3),
            Ok(ReservedIdentity::AggregateCluster)
        );
        assert_eq!(
            encoding.aggregate_for(local_global, 4),
            Ok(ReservedIdentity::AggregateClusterMesh)
        );
        assert_eq!(
            encoding.aggregate_for(id(0x01ff_ffff), 3),
            Ok(ReservedIdentity::AggregateWorld)
        );
        assert_eq!(
            encoding.aggregate_for(id(0x02ff_ffff), 3),
            Ok(ReservedIdentity::AggregateRemoteNode)
        );
    }
}
