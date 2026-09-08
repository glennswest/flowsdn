#![allow(clippy::unwrap_used)]

use flowsdn_config::immutable;
use flowsdn_config::runtime::{self, Metadata};
use flowsdn_config::{Class, Entry, KeySpec, Kind, Registry, Source, Value};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "flowsdn-runtime-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn metadata(version: &str) -> Metadata {
    Metadata {
        version: version.into(),
        written_at: "2026-09-08T21:16:40Z".into(),
    }
}

fn schema() -> Registry {
    let mut immutable = KeySpec::new(
        "routing-mode",
        Kind::Enum(vec!["native".into(), "tunnel".into()]),
        "tunnel",
    );
    immutable.class = Class::Immutable;
    let mut script = KeySpec::new("script-option", Kind::String, "excluded");
    script.class = Class::Script;
    let mut ignored = KeySpec::new("ignored-option", Kind::String, "retained");
    ignored.class = Class::Ignored;
    Registry::new([
        immutable,
        script,
        ignored,
        KeySpec::new("flag", Kind::Bool, "true"),
        KeySpec::new("signed", Kind::Int { bits: 64 }, "-9223372036854775808"),
        KeySpec::new("unsigned", Kind::UInt { bits: 64 }, "18446744073709551615"),
        KeySpec::new("ratio", Kind::Float { bits: 64 }, "0.0025"),
        KeySpec::new("delay", Kind::Duration, "-1.5s"),
        KeySpec::new("devices", Kind::List, "eth0,eth1 eth2"),
        KeySpec::new("labels", Kind::Map, "a=x=y,b= spaced "),
        KeySpec::new("address", Kind::Ip, "::1"),
        KeySpec::new("cidr", Kind::Cidr, "2001:db8::1/64"),
        KeySpec::new("server", Kind::HostPort, "[::1]:1234"),
    ])
    .unwrap()
}

#[test]
fn snapshot_roundtrip_preserves_typed_values_sources_and_unknown_raw_values() {
    let registry = schema();
    let resolved = registry
        .resolve([
            Entry::new(Source::File, "unknown_key", "old"),
            Entry::new(Source::Env, "UNKNOWN-KEY", " raw, value \n"),
            Entry::new(Source::Flag, "routing-mode", "native"),
        ])
        .unwrap();
    assert_eq!(
        resolved.unknown_values().get("unknown-key").unwrap().source,
        Source::Env
    );
    let encoded = runtime::encode(&resolved, &metadata("one")).unwrap();
    let decoded = runtime::decode(&encoded, &registry).unwrap();
    assert_eq!(decoded.metadata, metadata("one"));
    for (key, effective) in resolved.values() {
        if effective.class == Class::Script {
            assert!(decoded.resolved.get(key).is_none());
        } else {
            assert_eq!(decoded.resolved.get(key), Some(effective), "{key}");
        }
    }
    assert_eq!(decoded.resolved.unknown_values(), resolved.unknown_values());
    let json: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(json.get("immutable-keys"), Some(&json!(["routing-mode"])));
    assert_eq!(
        json.get("config").unwrap().get("delay"),
        Some(&json!(-1_500_000_000_i64))
    );
    assert!(json.get("config").unwrap().get("script-option").is_none());
}

#[test]
fn decoder_validates_schema_metadata_sources_and_immutable_membership() {
    let registry = schema();
    let encoded = runtime::encode(&registry.resolve([]).unwrap(), &metadata("one")).unwrap();
    for (field, replacement) in [
        ("written-at", json!("not-a-timestamp")),
        ("flowsdn-version", json!("")),
        ("reference-compat", json!("unknown")),
        ("immutable-keys", json!(["missing"])),
        ("immutable-keys", json!(["routing-mode", "routing-mode"])),
        ("sources", json!({})),
        ("config", json!([])),
    ] {
        let mut malformed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        malformed
            .as_object_mut()
            .unwrap()
            .insert(field.into(), replacement);
        assert!(
            runtime::decode(&malformed.to_string(), &registry).is_err(),
            "{field}"
        );
    }
    let mut malformed: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    malformed
        .get_mut("config")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("unsigned".into(), json!("123"));
    assert!(runtime::decode(&malformed.to_string(), &registry).is_err());
    assert!(runtime::decode("{", &registry).is_err());
    assert!(runtime::decode("null", &registry).is_err());
}

#[test]
fn timestamps_require_real_calendar_dates_and_explicit_timezones() {
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    for timestamp in [
        "2024-02-29T23:59:59.123+05:30",
        "2026-09-08t21:16:40z",
        "2026-09-08T21:16:40-00:00",
    ] {
        assert!(
            runtime::encode(
                &resolved,
                &Metadata {
                    version: "test".into(),
                    written_at: timestamp.into()
                }
            )
            .is_ok()
        );
    }
    for timestamp in [
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-09-08T24:00:00Z",
        "2026-09-08T21:16:40",
        "2026-09-08T21:16:40+99:00",
    ] {
        assert!(
            runtime::encode(
                &resolved,
                &Metadata {
                    version: "test".into(),
                    written_at: timestamp.into()
                }
            )
            .is_err()
        );
    }
}

#[test]
fn decoding_never_fills_new_defaults_or_drops_removed_immutable_keys() {
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    let encoded = runtime::encode(&resolved, &metadata("old")).unwrap();
    let empty_schema = Registry::new([]).unwrap();
    let removed = runtime::decode(&encoded, &empty_schema).unwrap();
    assert_eq!(
        removed.resolved.get("routing-mode").unwrap().class,
        Class::Immutable
    );
    assert!(
        immutable::check(
            immutable::Previous::Parsed(&removed.resolved),
            &empty_schema.resolve([]).unwrap(),
            true,
            true
        )
        .is_err()
    );
    let empty = runtime::encode(&empty_schema.resolve([]).unwrap(), &metadata("old")).unwrap();
    let decoded = runtime::decode(&empty, &registry).unwrap();
    assert!(decoded.resolved.values().is_empty());
    assert!(
        immutable::check(
            immutable::Previous::Parsed(&decoded.resolved),
            &resolved,
            true,
            true
        )
        .is_err()
    );
}

#[test]
fn publication_rotates_three_snapshots_and_cleans_staging_files() {
    let fixture = Fixture::new();
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    for version in ["one", "two", "three", "four"] {
        let report = runtime::store(fixture.path(), &resolved, &metadata(version));
        assert!(report.published);
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }
    for (name, version) in [
        (runtime::CURRENT, "four"),
        (runtime::PREVIOUS, "three"),
        (runtime::OLDEST, "two"),
    ] {
        let snapshot = runtime::decode(
            &fs::read_to_string(fixture.path().join(name)).unwrap(),
            &registry,
        )
        .unwrap();
        assert_eq!(snapshot.metadata.version, version);
    }
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 3);
}

#[test]
fn store_failures_are_nonfatal_and_leave_no_partial_snapshot() {
    let fixture = Fixture::new();
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    let missing = runtime::store(
        &fixture.path().join("missing"),
        &resolved,
        &metadata("test"),
    );
    assert!(!missing.published);
    assert!(!missing.warnings.is_empty());
    fs::create_dir(fixture.path().join(runtime::CURRENT)).unwrap();
    let failure = runtime::store(fixture.path(), &resolved, &metadata("test"));
    assert!(!failure.published);
    assert!(fixture.path().join(runtime::CURRENT).is_dir());
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 1);
}

#[test]
fn rotation_failure_preserves_current_publication_and_reports_history_problem() {
    let fixture = Fixture::new();
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    assert!(runtime::store(fixture.path(), &resolved, &metadata("one")).published);
    fs::create_dir(fixture.path().join(runtime::PREVIOUS)).unwrap();
    fs::write(
        fixture.path().join(runtime::PREVIOUS).join("keep"),
        "other content",
    )
    .unwrap();
    let report = runtime::store(fixture.path(), &resolved, &metadata("two"));
    assert!(report.published);
    assert!(!report.warnings.is_empty());
    assert_eq!(
        fs::read_to_string(fixture.path().join(runtime::PREVIOUS).join("keep")).unwrap(),
        "other content"
    );
    assert_eq!(
        runtime::decode(
            &fs::read_to_string(fixture.path().join(runtime::CURRENT)).unwrap(),
            &registry
        )
        .unwrap()
        .metadata
        .version,
        "two"
    );
    assert_eq!(fs::read_dir(fixture.path()).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn snapshot_symlinks_never_overwrite_their_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    let target = fixture.path().join("external");
    fs::write(&target, "keep").unwrap();
    symlink(&target, fixture.path().join(runtime::CURRENT)).unwrap();
    let registry = schema();
    let report = runtime::store(
        fixture.path(),
        &registry.resolve([]).unwrap(),
        &metadata("new"),
    );
    assert!(report.published);
    assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    assert!(
        fs::symlink_metadata(fixture.path().join(runtime::CURRENT))
            .unwrap()
            .is_file()
    );
    assert_eq!(
        fs::metadata(fixture.path().join(runtime::CURRENT))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn concurrent_readers_always_see_a_complete_current_snapshot() {
    let fixture = Fixture::new();
    let registry = schema();
    let resolved = registry.resolve([]).unwrap();
    assert!(runtime::store(fixture.path(), &resolved, &metadata("initial")).published);
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = stop.clone();
    let path = fixture.path().join(runtime::CURRENT);
    let (started, ready) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let registry = schema();
        runtime::decode(&fs::read_to_string(&path).unwrap(), &registry).unwrap();
        let mut reads = 1_u64;
        started.send(()).unwrap();
        while !reader_stop.load(Ordering::Acquire) {
            let text = fs::read_to_string(&path).unwrap();
            runtime::decode(&text, &registry).unwrap();
            reads = reads.saturating_add(1);
        }
        reads
    });
    ready.recv().unwrap();
    for version in 0..20 {
        assert!(
            runtime::store(fixture.path(), &resolved, &metadata(&version.to_string())).published
        );
    }
    stop.store(true, Ordering::Release);
    assert!(reader.join().unwrap() > 0);
}

#[test]
fn previous_file_validation_feeds_restart_immutability_without_failing_bad_history() {
    let fixture = Fixture::new();
    let registry = schema();
    let original = registry.resolve([]).unwrap();
    let changed = registry
        .resolve([Entry::new(Source::Flag, "routing-mode", "native")])
        .unwrap();
    let path = fixture.path().join(runtime::CURRENT);
    assert!(
        runtime::check_previous(&path, &registry, &changed, true, true)
            .unwrap()
            .warnings
            .is_empty()
    );
    fs::write(&path, "invalid JSON").unwrap();
    assert_eq!(
        runtime::check_previous(&path, &registry, &changed, true, true)
            .unwrap()
            .warnings,
        [immutable::Warning::PreviousUnparseable]
    );
    assert!(runtime::store(fixture.path(), &original, &metadata("old")).published);
    assert!(runtime::check_previous(&path, &registry, &changed, true, true).is_err());
    assert_eq!(
        runtime::check_previous(&path, &registry, &changed, false, true)
            .unwrap()
            .changes
            .first()
            .unwrap()
            .current,
        Some(Value::Enum("native".into()))
    );
}

#[cfg(unix)]
#[test]
fn previous_special_files_and_symlinks_are_nonfatal_without_blocking() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let fixture = Fixture::new();
    let registry = schema();
    let current = registry.resolve([]).unwrap();
    let ordinary = fixture.path().join("regular.json");
    fs::write(
        &ordinary,
        runtime::encode(&current, &metadata("old")).unwrap(),
    )
    .unwrap();
    let link = fixture.path().join("link.json");
    symlink(&ordinary, &link).unwrap();
    let dangling = fixture.path().join("dangling.json");
    symlink("missing", &dangling).unwrap();
    let fifo = fixture.path().join("fifo.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let socket = fixture.path().join("socket.json");
    let _listener = UnixListener::bind(&socket).unwrap();
    // A timeout reports regression rather than hanging the complete test run
    // if a special-file open accidentally loses its nonblocking flag.
    let (send, receive) = std::sync::mpsc::channel();
    let paths = [link, dangling, fifo, socket, fixture.path().to_owned()];
    let worker = std::thread::spawn(move || {
        for path in paths {
            let report = runtime::check_previous(&path, &registry, &current, true, true).unwrap();
            assert_eq!(report.warnings, [immutable::Warning::PreviousUnparseable]);
        }
        send.send(()).unwrap();
    });
    receive
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn oversized_previous_snapshots_are_bounded_and_empty_map_keys_are_invalid() {
    let fixture = Fixture::new();
    let registry = schema();
    let current = registry.resolve([]).unwrap();
    let path = fixture.path().join("oversized.json");
    fs::File::create(&path)
        .unwrap()
        .set_len((runtime::MAX_SNAPSHOT_BYTES as u64).saturating_add(1))
        .unwrap();
    assert_eq!(
        runtime::check_previous(&path, &registry, &current, true, true)
            .unwrap()
            .warnings,
        [immutable::Warning::PreviousUnparseable]
    );
    let mut document: serde_json::Value =
        serde_json::from_str(&runtime::encode(&current, &metadata("old")).unwrap()).unwrap();
    document
        .get_mut("config")
        .unwrap()
        .get_mut("labels")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(String::new(), json!("invalid"));
    assert!(runtime::decode(&document.to_string(), &registry).is_err());
    // The same map constraint applies to removed keys without a current schema.
    assert!(runtime::decode(&document.to_string(), &Registry::new([]).unwrap()).is_err());
}
