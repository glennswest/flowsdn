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
