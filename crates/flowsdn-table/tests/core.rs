#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
use flowsdn_table::{Index, Key, Keyed, Row, Table, TableError, TableRender, key};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Item {
    id: u32,
    name: String,
    labels: Vec<String>,
    value: u64,
}
impl Keyed for Item {
    fn primary_key(&self) -> Key {
        key::u32be(self.id)
    }
}
impl TableRender for Item {
    fn headers() -> &'static [&'static str] {
        &["ID", "Name", "Value"]
    }
    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.name.clone(),
            self.value.to_string(),
        ]
    }
}
fn row(id: u32, name: &str, labels: &[&str]) -> Item {
    Item {
        id,
        name: name.to_owned(),
        labels: labels.iter().map(|s| (*s).to_owned()).collect(),
        value: 0,
    }
}
fn table() -> Table<Item> {
    Table::new(vec![
        Index::new("name", true, |r: &Item| vec![r.name.as_bytes().to_vec()]),
        Index::new("label", false, |r: &Item| {
            r.labels.iter().map(|s| s.as_bytes().to_vec()).collect()
        }),
    ])
    .unwrap()
}
fn ids(rows: impl IntoIterator<Item = Row<Item>>) -> Vec<u32> {
    rows.into_iter().map(|(r, _)| r.id).collect()
}

#[tokio::test]
async fn revisions_upserts_and_failed_conditions() {
    let t = table();
    assert_eq!(t.snapshot().revision(), 0);
    assert_eq!(t.insert(row(1, "one", &[])).await.unwrap().revision, 1);
    assert_eq!(
        t.insert_if_revision(row(1, "new", &[]), 99)
            .await
            .unwrap_err(),
        TableError::RevisionMismatch { current: Some(1) }
    );
    assert_eq!(t.snapshot().revision(), 1);
    let result = t.insert_if_revision(row(1, "new", &[]), 1).await.unwrap();
    assert_eq!(result.previous.unwrap().name, "one");
    assert_eq!(result.revision, 2);
    assert!(t.snapshot().get("name", b"one").unwrap().is_none());
    assert_eq!(
        t.delete_if_revision(&key::u32be(1), 1).await.unwrap_err(),
        TableError::RevisionMismatch { current: Some(2) }
    );
    assert_eq!(
        t.delete_if_revision(&key::u32be(1), 2)
            .await
            .unwrap()
            .revision,
        3
    );
    assert_eq!(t.delete(&key::u32be(99)).await.unwrap().revision, 4);
    assert!(t.snapshot().is_empty());
    assert_eq!(
        t.insert_if_revision(row(2, "two", &[]), 0)
            .await
            .unwrap_err(),
        TableError::RevisionMismatch { current: None }
    );
}
#[tokio::test]
async fn unique_violation_preserves_all_indexes() {
    let t = table();
    t.insert(row(1, "one", &["a"])).await.unwrap();
    t.insert(row(2, "two", &["b"])).await.unwrap();
    let before = t.snapshot();
    assert_eq!(
        t.insert(row(2, "one", &["a", "c"])).await.unwrap_err(),
        TableError::UniqueViolation {
            index: "name",
            key: b"one".to_vec()
        }
    );
    let after = t.snapshot();
    assert_eq!(before.revision(), after.revision());
    assert_eq!(ids(after.list("label", b"b").unwrap()), [2]);
    assert!(after.list("label", b"c").unwrap().is_empty());
    assert_eq!(after.get("name", b"two").unwrap().unwrap().0.id, 2);
}
#[tokio::test]
async fn indexes_are_ordered_and_duplicate_keys_are_deduplicated() {
    let t = table();
    for (id, name, labels) in [
        (9, "z", vec!["ab", "ab", "a"]),
        (1, "b", vec!["a"]),
        (4, "a", vec!["ab"]),
    ] {
        t.insert(row(id, name, &labels)).await.unwrap();
    }
    let s = t.snapshot();
    assert_eq!(ids(s.all()), [1, 4, 9]);
    assert_eq!(ids(s.list("label", b"a").unwrap()), [1, 9]);
    assert_eq!(ids(s.list("label", b"ab").unwrap()), [4, 9]);
    assert_eq!(ids(s.prefix("label", b"a").unwrap()), [1, 9, 4, 9]);
    assert_eq!(ids(s.lower_bound("name", b"b").unwrap()), [1, 9]);
    assert_eq!(ids(s.by_revision(2)), [1, 4]);
    assert!(matches!(
        s.get("label", b"a"),
        Err(TableError::NonUniqueIndex(_))
    ));
    assert!(matches!(
        s.list("missing", b""),
        Err(TableError::UnknownIndex(_))
    ));
}
#[tokio::test]
async fn zero_bytes_do_not_alias_secondary_keys() {
    let t = table();
    t.insert(row(1, "x", &["a\0b"])).await.unwrap();
    t.insert(row(2, "y", &["a"])).await.unwrap();
    assert_eq!(ids(t.snapshot().list("label", b"a").unwrap()), [2]);
    assert_eq!(ids(t.snapshot().list("label", b"a\0b").unwrap()), [1]);
}
#[tokio::test]
async fn held_snapshot_survives_ten_thousand_writes() {
    let t = table();
    t.insert(row(0, "old", &["before"])).await.unwrap();
    let old = t.snapshot();
    for id in 1..=10_000 {
        t.insert(row(id, &id.to_string(), &["after"]))
            .await
            .unwrap();
    }
    assert_eq!(old.len(), 1);
    assert_eq!(old.revision(), 1);
    assert!(old.list("label", b"after").unwrap().is_empty());
    assert_eq!(t.snapshot().len(), 10_001);
}
#[tokio::test]
async fn modify_delete_all_and_batch_failure_semantics() {
    let t = table();
    assert_eq!(t.modify(b"absent", |_| None).await.unwrap().revision, 0);
    assert_eq!(
        t.modify(&key::u32be(1), |_| Some(row(2, "bad", &[])))
            .await
            .unwrap_err(),
        TableError::PrimaryKeyChanged
    );
    let result: Result<(), TableError> = t
        .batch(move |w| {
            w.insert(row(1, "one", &[]))?;
            w.insert(row(2, "one", &[]))?;
            Ok(())
        })
        .await;
    assert!(result.is_err());
    assert_eq!(t.snapshot().len(), 1);
    assert_eq!(t.snapshot().revision(), 1);
    t.modify(&key::u32be(1), |old| {
        let mut row = old.unwrap().clone();
        row.value = 42;
        Some(row)
    })
    .await
    .unwrap();
    assert_eq!(
        t.snapshot()
            .get("primary", &key::u32be(1))
            .unwrap()
            .unwrap()
            .0
            .value,
        42
    );
    t.insert(row(2, "two", &[])).await.unwrap();
    assert_eq!(t.delete_all().await.unwrap(), 2);
    assert_eq!(t.snapshot().revision(), 5);
    assert!(t.snapshot().by_revision(0).next().is_none());
    assert!(t.snapshot().list("name", b"one").unwrap().is_empty());
    assert_eq!(t.delete_all().await.unwrap(), 0);
    assert_eq!(t.snapshot().revision(), 5);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_modify_has_no_lost_updates() {
    let t = Arc::new(table());
    t.insert(row(1, "counter", &[])).await.unwrap();
    let mut workers = Vec::new();
    for _ in 0..4 {
        let t = t.clone();
        workers.push(tokio::spawn(async move {
            for _ in 0..250 {
                t.modify(&key::u32be(1), |old| {
                    let mut row = old.unwrap().clone();
                    row.value += 1;
                    Some(row)
                })
                .await
                .unwrap();
            }
        }));
    }
    for worker in workers {
        worker.await.unwrap();
    }
    let s = t.snapshot();
    assert_eq!(
        s.get("primary", &key::u32be(1)).unwrap().unwrap().0.value,
        1000
    );
    assert_eq!(s.revision(), 1001);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readers_do_not_block_and_batches_publish_together() {
    let t = Arc::new(table());
    let old = t.snapshot();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer = t.clone();
    let task = tokio::spawn(async move {
        writer
            .batch(move |w| {
                w.insert(row(1, "one", &["a"])).unwrap();
                entered_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                w.insert(row(2, "two", &["a"])).unwrap();
            })
            .await;
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    assert_eq!(t.snapshot().len(), 0);
    release_tx.send(()).unwrap();
    task.await.unwrap();
    assert!(old.is_empty());
    let now = t.snapshot();
    assert_eq!(ids(now.all()), [1, 2]);
    assert_eq!(ids(now.list("label", b"a").unwrap()), [1, 2]);
}
#[tokio::test]
async fn random_operations_match_independent_model() {
    let t = table();
    let mut model = BTreeMap::new();
    let mut state = 29u64;
    let mut revision = 0;
    for _ in 0..1500 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let id = (state % 53) as u32;
        if state.is_multiple_of(4) {
            t.delete(&key::u32be(id)).await.unwrap();
            model.remove(&id);
        } else {
            let item = row(
                id,
                &format!("row-{id}"),
                &[if state.is_multiple_of(2) {
                    "even"
                } else {
                    "odd"
                }],
            );
            t.insert(item.clone()).await.unwrap();
            model.insert(id, item);
        }
        revision += 1;
        let s = t.snapshot();
        assert_eq!(s.revision(), revision);
        let actual: Vec<_> = s.all().map(|(r, _)| r.as_ref().clone()).collect();
        assert_eq!(actual, model.values().cloned().collect::<Vec<_>>());
        for label in ["even", "odd"] {
            let expected: Vec<_> = model
                .values()
                .filter(|r| r.labels.iter().any(|s| s == label))
                .map(|r| r.id)
                .collect();
            assert_eq!(ids(s.list("label", label.as_bytes()).unwrap()), expected);
        }
    }
}
#[test]
fn key_encodings_and_render_contract() {
    assert!(key::u32be(255) < key::u32be(256));
    assert!(key::u64be(65535) < key::u64be(65536));
    assert_eq!(
        key::addr("192.0.2.1".parse().unwrap()),
        key::addr("::ffff:192.0.2.1".parse().unwrap())
    );
    let r = row(7, "seven", &[]);
    assert_eq!(Item::headers(), ["ID", "Name", "Value"]);
    assert_eq!(r.cells(), ["7", "seven", "0"]);
    assert!(Table::<Item>::new(vec![Index::new("primary", true, |_| vec![])]).is_err());
}

#[tokio::test]
async fn replacement_deletion_and_late_multikey_collision_preserve_revision_index() {
    let table = Table::new(vec![Index::new("labels", true, |item: &Item| {
        item.labels
            .iter()
            .map(|label| label.as_bytes().to_vec())
            .collect()
    })])
    .unwrap();
    table.insert(row(1, "one", &["a", "z"])).await.unwrap();
    table.insert(row(2, "two", &["b"])).await.unwrap();
    // "c" validates before "z" collides. Neither new nor old indexes may move.
    assert!(table.insert(row(2, "bad", &["c", "z"])).await.is_err());
    let snapshot = table.snapshot();
    assert_eq!(snapshot.get("labels", b"b").unwrap().unwrap().0.name, "two");
    assert!(snapshot.get("labels", b"c").unwrap().is_none());
    assert_eq!(
        snapshot
            .by_revision(0)
            .map(|(r, rev)| (r.id, rev))
            .collect::<Vec<_>>(),
        [(1, 1), (2, 2)]
    );
    table.insert(row(1, "replacement", &["d"])).await.unwrap();
    table.delete(&key::u32be(2)).await.unwrap();
    assert_eq!(
        table
            .snapshot()
            .by_revision(0)
            .map(|(r, rev)| (r.id, rev))
            .collect::<Vec<_>>(),
        [(1, 3)]
    );
    assert_eq!(
        snapshot
            .by_revision(0)
            .map(|(r, rev)| (r.id, rev))
            .collect::<Vec<_>>(),
        [(1, 1), (2, 2)]
    );
}

#[tokio::test]
async fn empty_binary_primary_and_secondary_keys_are_valid() {
    #[derive(Clone)]
    struct Binary(Key);
    impl Keyed for Binary {
        fn primary_key(&self) -> Key {
            self.0.clone()
        }
    }
    let table = Table::new(vec![Index::new("empty", false, |_: &Binary| vec![vec![]])]).unwrap();
    table.insert(Binary(vec![])).await.unwrap();
    table.insert(Binary(vec![0])).await.unwrap();
    let snapshot = table.snapshot();
    assert!(snapshot.get("primary", b"").unwrap().is_some());
    assert_eq!(snapshot.list("empty", b"").unwrap().len(), 2);
    assert_eq!(snapshot.prefix("primary", b"").unwrap().len(), 2);
    table.delete(b"").await.unwrap();
    assert_eq!(table.snapshot().list("empty", b"").unwrap().len(), 1);
    assert_eq!(snapshot.list("empty", b"").unwrap().len(), 2);
}
