use flowsdn_clustermesh::{config::*, ownership::*, prefixes::*, topology::PodCidrs};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
#[test]
fn identity_defaults_and_explicit_backend_restrictions() {
    assert_eq!(IdentityMode::default(), IdentityMode::Crd);
    assert_eq!(IdentityMode::parse("crd", ""), Ok(IdentityMode::Crd));
    assert_eq!(IdentityMode::parse("crd", "etcd"), Ok(IdentityMode::Crd));
    assert_eq!(
        IdentityMode::parse("kvstore", "etcd"),
        Ok(IdentityMode::Kvstore)
    );
    for mode in [
        "kvstore",
        "doublewrite-readkvstore",
        "doublewrite-readcrd",
        "unknown",
    ] {
        assert!(IdentityMode::parse(mode, "").is_err());
    }
    assert!(IdentityMode::parse("doublewrite-readkvstore", "etcd").is_err());
    assert!(IdentityMode::parse("doublewrite-readcrd", "etcd").is_err());
    assert!(IdentityMode::parse("crd", "redis").is_err());
}
#[test]
fn service_resync_and_deferred_features_are_explicit() {
    assert_eq!(
        service_plan("prefer-legacy").expect("plan"),
        ServicePlan {
            export_legacy: true,
            export_slices: true,
            import_legacy: true,
            import_slices: false
        }
    );
    for mode in ["prefer-endpointslice", "only-endpointslice", ""] {
        assert!(service_plan(mode).is_err());
    }
    assert!(validate_peer_service_export(None).is_ok());
    assert!(validate_peer_service_export(Some("")).is_ok());
    assert!(validate_peer_service_export(Some("services-and-endpointslices")).is_ok());
    assert!(validate_peer_service_export(Some("endpointslices-only")).is_err());
    assert!(validate_peer_service_export(Some("unknown")).is_err());
    assert_eq!(resync_interval(None), Duration::from_secs(300));
    assert_eq!(resync_interval(Some(Duration::ZERO)), Duration::ZERO);
    assert_eq!(
        resync_interval(Some(Duration::from_secs(42))),
        Duration::from_secs(42)
    );
    assert_eq!(
        DeferredFeatures::default().warnings(),
        vec!["clustermesh-mcs-api-install-crds is not implemented"]
    );
    assert!(
        DeferredFeatures {
            mcs_api: false,
            mcs_install_crds: false,
            endpoint_sync: false
        }
        .warnings()
        .is_empty()
    );
    assert_eq!(
        DeferredFeatures {
            mcs_api: true,
            mcs_install_crds: true,
            endpoint_sync: true
        }
        .warnings()
        .len(),
        3
    );
}
#[test]
fn cidr_replacement_is_atomic_and_family_aware() {
    let mut mesh = PodCidrs::default();
    mesh.replace(
        "east",
        vec![
            "10.0.0.9/24".parse().expect("cidr"),
            "fd00::/64".parse().expect("cidr"),
        ],
    )
    .expect("east");
    mesh.replace("west", vec!["10.1.0.0/16".parse().expect("cidr")])
        .expect("west");
    let before = mesh.clone();
    for cidr in ["10.0.0.128/25", "10.0.0.0/8", "fd00::1/128", "::/0"] {
        assert!(
            mesh.replace("west", vec![cidr.parse().expect("cidr")])
                .is_err()
        );
        assert_eq!(mesh, before);
    }
    mesh.replace("west", vec!["::ffff:10.0.0.9/128".parse().expect("cidr")])
        .expect("mapped remains IPv6");
    mesh.replace(
        "east",
        vec![
            "10.0.0.0/16".parse().expect("cidr"),
            "10.0.0.0/24".parse().expect("cidr"),
        ],
    )
    .expect("same cluster nested");
    mesh.remove("east");
    mesh.replace("west", vec!["0.0.0.0/0".parse().expect("cidr")])
        .expect("removed ownership");
}
#[test]
fn remote_ranges_reject_escape_boundaries_and_mutations() {
    let front = FrontPolicy::for_role(Role::Remote, "east").expect("front");
    assert!(front.permits(Rpc::Range, b"cilium/cluster-config/east", None));
    assert!(!front.permits(Rpc::Range, b"cilium/cluster-config/east-evil", None));
    assert!(!front.permits(Rpc::Range, b"cilium/cluster-config/west", None));
    assert!(front.permits(Rpc::Watch, b"cilium/state/", Some(b"cilium/state0")));
    assert!(!front.permits(Rpc::Watch, b"cilium/state/", Some(b"cilium/state1")));
    assert!(!front.permits(Rpc::Watch, b"cilium/state/", Some(&[0])));
    assert!(!front.permits(Rpc::Range, b"", None));
    assert!(!front.permits(Rpc::Range, b"cilium/synced/east-evil/x", None));
    assert!(front.permits(Rpc::Range, b"cilium/synced/east/x", None));
    assert!(front.permits(Rpc::Range, b"cilium/.heartbeat-suffix", None)); // reference grants prefix
    assert!(!front.permits(Rpc::Range, b"flowsdn/cluster-owners/east", None));
    for rpc in [
        Rpc::Put,
        Rpc::Delete,
        Rpc::Txn,
        Rpc::Lease,
        Rpc::Auth,
        Rpc::Other,
    ] {
        assert!(!front.permits(rpc, b"cilium/state/x", None));
    }
    assert!(FrontPolicy::for_role(Role::Remote, "east/../../west").is_err());
    assert!(ReadRange::prefix(&[255, 255]).is_err());
}
#[test]
fn local_ranges_are_read_only_and_distinct() {
    let front = FrontPolicy::for_role(Role::Local, "east").expect("front");
    assert!(front.permits(Rpc::Range, b"cilium/cache/", Some(b"cilium/cache0")));
    assert!(front.permits(Rpc::Range, b"cilium/cluster-config/west", None));
    assert!(!front.permits(Rpc::Range, b"cilium/state/x", None));
    assert!(!front.permits(Rpc::Range, b"cilium/cache/", Some(b"cilium/synced0")));
}
fn instance() -> InstanceUuid {
    InstanceUuid::parse("7beea67f-6435-4f2a-9d80-c6c9c18e0f01").expect("uuid")
}
fn apply(store: &mut BTreeMap<String, Record>, plan: &ClaimPlan, revision: u64) -> bool {
    if !plan
        .guards
        .iter()
        .all(|guard| store.get(&guard.key) == guard.expected.as_ref())
    {
        return false;
    }
    let mut next = store.clone();
    for put in &plan.puts {
        next.insert(
            put.key.clone(),
            Record {
                value: put.value.clone(),
                mod_revision: revision,
                lease_id: match put.lease {
                    Lease::None => None,
                    Lease::Config(id) => Some(id),
                },
            },
        );
    }
    *store = next;
    true
}
#[test]
fn ownership_claim_is_atomic_and_restart_stable() {
    let desired = json!({"id":3,"capabilities":{"cached":true,"unknownFutureField":"preserved"}});
    let uuid = instance();
    let first = plan_claim("east", &uuid, None, None, &desired, 1).expect("new");
    assert_eq!(first.puts.len(), 2);
    let mut store = BTreeMap::new();
    assert!(apply(&mut store, &first, 1));
    let owner = store.get("flowsdn/cluster-owners/east");
    let config = store.get("cilium/cluster-config/east");
    let replay = plan_claim(
        "east",
        &InstanceUuid::parse(uuid.as_str()).expect("restart"),
        owner,
        config,
        &desired,
        1,
    )
    .expect("same");
    assert!(replay.puts.is_empty());
    let rebound = plan_claim("east", &uuid, owner, config, &desired, 2).expect("new lease");
    assert_eq!(rebound.puts.len(), 1);
    assert_eq!(
        rebound.puts.first().map(|put| &put.lease),
        Some(&Lease::Config(2))
    );
    assert_eq!(
        rebound.puts.first().map(|put| put.value.as_slice()),
        config.map(|record| record.value.as_slice())
    );
    assert!(plan_claim("east", &uuid, owner, config, &desired, 0).is_err());
    let mut rebound_store = store.clone();
    assert!(apply(&mut rebound_store, &rebound, 2));
    assert_eq!(
        rebound_store
            .get("cilium/cluster-config/east")
            .and_then(|record| record.lease_id),
        Some(2)
    );
    assert_eq!(rebound_store.get("flowsdn/cluster-owners/east"), owner);
    let value: serde_json::Value =
        serde_json::from_slice(&config.expect("config").value).expect("json");
    assert_eq!(
        value.pointer("/capabilities/unknownFutureField"),
        Some(&json!("preserved"))
    );
    assert_eq!(
        value.pointer("/capabilities/flowsdnInstanceUUID"),
        Some(&json!(uuid.as_str()))
    );
    let other = InstanceUuid::parse("11111111-2222-4333-8444-555555555555").expect("other");
    assert!(plan_claim("east", &other, owner, config, &desired, 1).is_err());
    store.remove("cilium/cluster-config/east"); // leased config expires, durable owner does not
    assert!(
        plan_claim(
            "east",
            &other,
            store.get("flowsdn/cluster-owners/east"),
            None,
            &desired,
            1
        )
        .is_err()
    );
    let repair = plan_claim(
        "east",
        &uuid,
        store.get("flowsdn/cluster-owners/east"),
        None,
        &desired,
        1,
    )
    .expect("repair");
    assert_eq!(repair.puts.len(), 1);
    assert!(apply(&mut store, &repair, 2));
}
#[test]
fn competing_claims_and_stale_revisions_cannot_overwrite() {
    let desired = json!({"id":3});
    let first = plan_claim("east", &instance(), None, None, &desired, 1).expect("plan");
    let other = InstanceUuid::parse("11111111-2222-4333-8444-555555555555").expect("other");
    let competitor = plan_claim("east", &other, None, None, &desired, 1).expect("plan");
    let mut store = BTreeMap::new();
    assert!(apply(&mut store, &first, 1));
    let before = store.clone();
    assert!(!apply(&mut store, &competitor, 2));
    assert_eq!(store, before);
    let updated = plan_claim(
        "east",
        &instance(),
        store.get("flowsdn/cluster-owners/east"),
        store.get("cilium/cluster-config/east"),
        &json!({"id":4}),
        1,
    )
    .expect("updated");
    store
        .get_mut("cilium/cluster-config/east")
        .expect("config")
        .mod_revision = 3;
    let before = store.clone();
    assert!(!apply(&mut store, &updated, 4));
    assert_eq!(store, before);
}
#[test]
fn legacy_and_malformed_ownership_fail_closed() {
    let legacy = Record {
        value: br#"{"id":3}"#.to_vec(),
        mod_revision: 1,
        lease_id: Some(1),
    };
    assert!(
        plan_claim(
            "east",
            &instance(),
            None,
            Some(&legacy),
            &json!({"id":3}),
            1
        )
        .is_err()
    );
    let leased_owner = Record {
        value: instance().as_str().as_bytes().to_vec(),
        mod_revision: 1,
        lease_id: Some(1),
    };
    assert!(
        plan_claim(
            "east",
            &instance(),
            Some(&leased_owner),
            None,
            &json!({"id":3}),
            1
        )
        .is_err()
    );
    for value in [
        "",
        "00000000-0000-0000-0000-000000000000",
        "7BEEA67F-6435-4F2A-9D80-C6C9C18E0F01",
    ] {
        assert!(InstanceUuid::parse(value).is_err());
    }
    assert!(plan_claim("east", &instance(), None, None, &json!({"id":0}), 1).is_err());
    assert!(
        plan_claim(
            "east",
            &instance(),
            None,
            None,
            &json!({"id":3,"capabilities":[]}),
            1
        )
        .is_err()
    );
}
