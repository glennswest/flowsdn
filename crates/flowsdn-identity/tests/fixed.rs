use flowsdn_identity::{
    ReservedIdentity,
    fixed::{FixedIdentities, FixedIdentityError},
};

#[test]
fn every_reserved_and_well_known_name_is_rejected_without_partial_output() {
    for id in 0..=14 {
        let name = ReservedIdentity::from_number(id).expect("built-in").name();
        assert_eq!(
            FixedIdentities::parse([("128", "tenant-a"), ("129", name)]),
            Err(FixedIdentityError::ReservedName)
        );
    }
    for name in [
        "etcd-operator",
        "cilium-kvstore",
        "kube-dns",
        "eks-kube-dns",
        "coredns",
        "cilium-operator",
        "eks-coredns",
    ] {
        assert_eq!(
            FixedIdentities::parse([("255", name)]),
            Err(FixedIdentityError::ReservedName)
        );
    }
}

#[test]
fn user_range_duplicate_ids_and_duplicate_names_are_validated() {
    for id in [
        "",
        "0",
        "127",
        "256",
        "4294967296",
        "-128",
        "+128",
        "0x80",
        " 128",
    ] {
        assert_eq!(
            FixedIdentities::parse([(id, "tenant")]),
            Err(FixedIdentityError::InvalidId)
        );
    }
    assert_eq!(
        FixedIdentities::parse([("128", "")]),
        Err(FixedIdentityError::EmptyName)
    );
    assert_eq!(
        FixedIdentities::parse([("0128", "one"), ("128", "two")]),
        Err(FixedIdentityError::DuplicateId)
    );
    assert_eq!(
        FixedIdentities::parse([("128", "one"), ("255", "one")]),
        Err(FixedIdentityError::DuplicateName)
    );
    let map = FixedIdentities::parse([("128", "tenant"), ("255", "Host")]).expect("user names");
    assert_eq!(map.len(), 2);
    assert!(!map.is_empty());
    assert_eq!(map.id("tenant"), Some(128));
    assert_eq!(map.name(255), Some("Host"));
    assert_eq!(map.id("host"), None);
    assert_eq!(map.name(129), None);
    assert!(FixedIdentities::parse([]).expect("empty").is_empty());
}
