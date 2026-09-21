use flowsdn_agent::state::{IdPool, Record, Store};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "flowsdn-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("temp");
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn record(id: u16, cid: &str) -> Record {
    Record::parse(json!({"ID":id,"dockerID":cid,"ContainerIfName":"eth0","IPv4":"198.18.0.1","unknown-future-metadata":{"keep":true}})).expect("record")
}
#[test]
fn publication_survives_reopen_and_preserves_unknown_fields() {
    let temp = Temp::new();
    let store = Store::open(&temp.0).expect("store");
    let record = record(7, "container");
    store
        .stage(&record)
        .expect("stage")
        .publish()
        .expect("publish");
    assert!(store.stage(&record).is_err());
    drop(store);
    let store = Store::open(&temp.0).expect("reopen");
    let restored = store.restore().expect("restore");
    assert_eq!(restored.first().expect("record").document, record.document);
    store.remove(7).expect("delete");
    store.remove(7).expect("duplicate delete");
    assert!(store.restore().expect("empty").is_empty());
}
#[test]
fn failed_creation_drops_only_its_staging_directory() {
    let temp = Temp::new();
    let store = Store::open(&temp.0).expect("store");
    let staged = store.stage(&record(1, "one")).expect("stage");
    assert!(store.restore().expect("unpublished").is_empty());
    drop(staged);
    assert!(!temp.0.join("1_next").exists());
    fs::create_dir(temp.0.join("2_next")).expect("stale");
    fs::write(temp.0.join("2_next/evidence"), "retained").expect("evidence");
    assert!(store.stage(&record(2, "two")).is_err());
    assert!(temp.0.join("2_next/evidence").exists());
}
#[test]
fn concurrent_agent_is_excluded_until_owner_drops() {
    let temp = Temp::new();
    let owner = Store::open(&temp.0).expect("owner");
    assert!(Store::open(&temp.0).is_err());
    drop(owner);
    Store::open(&temp.0).expect("new owner");
}
#[test]
fn duplicate_attachment_and_directory_record_mismatch_fail_restore() {
    let temp = Temp::new();
    let store = Store::open(&temp.0).expect("store");
    store
        .stage(&record(1, "same"))
        .expect("stage")
        .publish()
        .expect("publish");
    store
        .stage(&record(2, "same"))
        .expect("stage")
        .publish()
        .expect("publish");
    assert!(store.restore().is_err());
    store.remove(2).expect("remove duplicate");
    fs::rename(temp.0.join("1"), temp.0.join("3")).expect("mismatch");
    assert!(store.restore().is_err());
}
#[test]
fn unexpected_resources_and_symlinks_are_preserved_without_partial_delete() {
    let temp = Temp::new();
    let store = Store::open(&temp.0).expect("store");
    store
        .stage(&record(1, "one"))
        .expect("stage")
        .publish()
        .expect("publish");
    fs::write(temp.0.join("1/other-resource"), "owned elsewhere").expect("resource");
    assert!(store.remove(1).is_err());
    assert!(temp.0.join("1/ep_config.json").exists());
    std::os::unix::fs::symlink(temp.0.join("1"), temp.0.join("2")).expect("symlink");
    assert!(store.restore().is_err());
    assert!(store.remove(2).is_err());
    assert!(temp.0.join("1/ep_config.json").exists());
}
#[test]
fn lowest_free_ids_exhaust_and_restore_supports_historical_high_ids() {
    let mut pool = IdPool::default();
    pool.reserve(65535).expect("historical");
    assert!(pool.reserve(65535).is_err());
    assert!(pool.reserve(0).is_err());
    for id in 1..=4095 {
        assert_eq!(pool.allocate().expect("allocate"), id);
    }
    assert!(pool.allocate().is_err());
    pool.release(17);
    assert_eq!(pool.allocate().expect("reuse"), 17);
}

#[test]
fn configured_id_limits_validate_and_exhaust_at_the_inclusive_bound() {
    for invalid in [0, 65536, u32::MAX] {
        assert!(IdPool::new(invalid).is_err(), "accepted {invalid}");
    }
    let mut single = IdPool::new(1).expect("smallest pool");
    assert_eq!(single.allocate().expect("only ID"), 1);
    assert!(single.allocate().is_err());
    single.release(1);
    assert_eq!(single.allocate().expect("released ID"), 1);

    let mut pool = IdPool::new(3).expect("small pool");
    pool.reserve(2).expect("restored within bound");
    pool.reserve(65535).expect("restored above bound");
    assert_eq!(pool.allocate().expect("lowest gap"), 1);
    assert_eq!(pool.allocate().expect("upper bound"), 3);
    assert!(pool.allocate().is_err());
    pool.release(65535);
    assert!(pool.allocate().is_err(), "high release must not widen pool");
    pool.release(2);
    assert_eq!(pool.allocate().expect("recycled gap"), 2);
    assert!(pool.allocate().is_err());
}

#[test]
fn widened_id_pool_allocates_above_legacy_limit_and_at_u16_max() {
    for maximum in [4096u16, u16::MAX] {
        let mut pool = IdPool::new(u32::from(maximum)).expect("widened pool");
        // Reserve the prefix efficiently; this tests allocation boundaries,
        // not creation or live networking at this endpoint count.
        for id in 1..maximum {
            pool.reserve(id).expect("reserved prefix");
        }
        assert_eq!(pool.allocate().expect("inclusive upper bound"), maximum);
        assert!(pool.allocate().is_err());
        assert!(pool.reserve(maximum).is_err(), "allocated ID is reserved");
        pool.release(maximum);
        assert_eq!(pool.allocate().expect("upper bound recycled"), maximum);
        pool.release(1);
        assert_eq!(pool.allocate().expect("lowest ID recycled"), 1);
        assert!(pool.allocate().is_err());
    }
}

#[test]
fn restored_high_ids_survive_reopen_with_a_lower_allocation_limit() {
    let temp = Temp::new();
    let store = Store::open(&temp.0).expect("store");
    for (id, cid) in [(1, "one"), (4096, "above-default"), (65535, "maximum")] {
        store
            .stage(&record(id, cid))
            .expect("stage")
            .publish()
            .expect("publish");
    }
    drop(store);
    let store = Store::open(&temp.0).expect("reopen");
    let records = store.restore().expect("restore full u16 namespace");
    assert_eq!(
        records.iter().map(|record| record.id).collect::<Vec<_>>(),
        vec![1, 4096, 65535]
    );
    let mut pool = IdPool::new(2).expect("lowered limit");
    for record in records {
        pool.reserve(record.id).expect("restore ID above new limit");
        assert!(pool.reserve(record.id).is_err(), "duplicate restored ID");
    }
    assert_eq!(pool.allocate().expect("remaining low ID"), 2);
    assert!(pool.allocate().is_err());
    pool.release(4096);
    assert!(
        pool.allocate().is_err(),
        "released high ID stays out of range"
    );
}

#[test]
fn manager_rejects_invalid_id_limit_before_opening_state_or_loading_bpf() {
    let temp = Temp::new();
    let state = temp.0.join("unopened-state");
    let object = temp.0.join("missing-object");
    for maximum in [0, 65536] {
        let scope = flowsdn_ipam::HostScope::new(
            "198.18.0.0".parse().expect("pool address"),
            24,
            Default::default(),
        )
        .expect("scope");
        let ipam = flowsdn_ipam::Ipam::new(Some(scope), None).expect("IPAM");
        let error =
            flowsdn_agent::endpoints::Manager::restore_with_id_max(&state, &object, ipam, maximum)
                .err()
                .expect("invalid bound");
        assert_eq!(error.to_string(), "endpoint-id-max must be in 1..=65535");
        assert!(!state.exists(), "invalid config must not create state");
    }
}

#[test]
fn incompatible_persisted_datapath_mode_is_rejected() {
    let original = record(1, "mode").document;
    for mode in [serde_json::Value::Null, json!("netkit"), json!("unknown"), json!(3)] {
        let mut value = original.clone();
        value.as_object_mut().expect("object").insert("DatapathMode".into(), mode);
        assert!(Record::parse(value).is_err());
    }
    let mut value = original.clone();
    value.as_object_mut().expect("object").insert("DatapathMode".into(), json!("veth"));
    Record::parse(value).expect("explicit veth");
    Record::parse(original).expect("historical veth");
}
