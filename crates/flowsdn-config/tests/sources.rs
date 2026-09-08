#![allow(clippy::unwrap_used)]

use flowsdn_config::{Entry, Kind, KeySpec, Registry, Source, Value};
use flowsdn_config::sources::{self, EnvironmentAlias};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("flowsdn-config-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path { &self.0 }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn variables(items: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    items.iter().map(|(key, value)| (OsString::from(key), OsString::from(value))).collect()
}

#[test]
fn yaml_preserves_scalar_values_and_registry_types_them() {
    let loaded = sources::yaml(r#"
enable_ipv4: true
capacity: 18446744073709551615
ratio: 1.25e-2
devices: 'eth0,eth1 eth2'
name: " spaces stay "
multiline: |
  first
  second
shared: &value 'off'
copy: *value
"#).unwrap();
    let registry = Registry::new([
        KeySpec::new("enable-ipv4", Kind::Bool, "false"),
        KeySpec::new("capacity", Kind::UInt { bits: 64 }, "0"),
        KeySpec::new("ratio", Kind::Float { bits: 64 }, "0"),
        KeySpec::new("devices", Kind::List, ""),
        KeySpec::new("name", Kind::String, ""),
        KeySpec::new("multiline", Kind::String, ""),
        KeySpec::new("shared", Kind::Bool, "true"),
        KeySpec::new("copy", Kind::Bool, "true"),
    ]).unwrap();
    let resolved = registry.resolve(loaded.entries).unwrap();
    assert_eq!(resolved.get("capacity").unwrap().value, Value::UInt(u64::MAX));
    assert_eq!(resolved.get("ratio").unwrap().value, Value::Float(0.0125));
    assert_eq!(resolved.get("name").unwrap().value, Value::String(" spaces stay ".into()));
    assert_eq!(resolved.get("multiline").unwrap().value, Value::String("first\nsecond\n".into()));
    assert_eq!(resolved.get("copy").unwrap().value, Value::Bool(false));
    assert_eq!(resolved.get("devices").unwrap().value, Value::List(vec!["eth0".into(), "eth1 eth2".into()]));
    assert!(resolved.values().values().all(|value| value.source == Source::File));
}

#[test]
fn yaml_rejects_ambiguous_or_non_scalar_documents() {
    for text in [
        "key: 1\nKEY: 2\n", "key_name: 1\nkey-name: 2\n", "key: 1\nkey: 2\n",
        "key: [a, b]\n", "key: {nested: value}\n", "[a, b]", "scalar",
        "key: null", "key: ~", "key:", "key: !!str value", "key: 'unterminated",
        "key: one\n---\nkey: two\n", "'': value", "key: *missing",
    ] { assert!(sources::yaml(text).is_err(), "{text}"); }
    for text in ["", "  \n", "# comment only\n", "{}", "key: ''", "key: 'null'"] {
        assert!(sources::yaml(text).is_ok(), "{text}");
    }
}

#[test]
fn file_selection_distinguishes_explicit_and_optional_defaults() {
    let fixture = Fixture::new();
    assert!(sources::file(None, None).unwrap().entries.is_empty());
    assert!(sources::file(None, Some(fixture.path())).unwrap().entries.is_empty());
    let explicit = fixture.path().join("chosen.yaml");
    assert!(sources::file(Some(&explicit), Some(fixture.path())).is_err());
    fs::write(fixture.path().join("ciliumd.yaml"), "name: default-file\n").unwrap();
    fs::write(&explicit, "name: explicit\n").unwrap();
    let default = sources::file(None, Some(fixture.path())).unwrap();
    assert_eq!(default.entries.first().unwrap().value, "default-file");
    let chosen = sources::file(Some(&explicit), Some(fixture.path())).unwrap();
    assert_eq!(chosen.entries.first().unwrap().value, "explicit");
    fs::write(&explicit, "name: [bad]\n").unwrap();
    assert_eq!(sources::file(Some(&explicit), None).unwrap_err().location, explicit.display().to_string());
    assert!(sources::file(Some(fixture.path()), None).is_err());
}

#[test]
fn directory_sorts_trims_and_warns_on_invalid_utf8() {
    let fixture = Fixture::new();
    fs::write(fixture.path().join("Z_NAME"), "  final \n\t").unwrap();
    fs::write(fixture.path().join("A_NAME"), "first").unwrap();
    fs::write(fixture.path().join("broken"), [0xff, 0xfe]).unwrap();
    fs::create_dir(fixture.path().join("nested")).unwrap();
    fs::write(fixture.path().join("nested/ignored"), "unused").unwrap();
    let loaded = sources::directory(fixture.path()).unwrap();
    assert_eq!(loaded.entries.len(), 2);
    assert_eq!(loaded.entries.first().unwrap().key, "A_NAME");
    assert_eq!(loaded.entries.last().unwrap().value, "final");
    assert_eq!(loaded.warnings.len(), 1);
    assert!(loaded.warnings.first().unwrap().location.ends_with("broken"));
    assert!(sources::directory(&fixture.path().join("missing")).is_err());
}

#[cfg(unix)]
#[test]
fn projected_configmap_symlinks_load_and_special_files_never_open() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    let fixture = Fixture::new();
    fs::create_dir(fixture.path().join("..generation")).unwrap();
    fs::write(fixture.path().join("..generation/enable_ipv4"), "\n true \n").unwrap();
    symlink("..generation", fixture.path().join("..data")).unwrap();
    symlink("..data/enable_ipv4", fixture.path().join("enable_ipv4")).unwrap();
    symlink("missing", fixture.path().join("broken-link")).unwrap();
    let _socket = UnixListener::bind(fixture.path().join("socket")).unwrap();
    let loaded = sources::directory(fixture.path()).unwrap();
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries.first().unwrap().key, "enable_ipv4");
    assert_eq!(loaded.entries.first().unwrap().value, "true");
    assert_eq!(loaded.warnings.len(), 2);
}

#[test]
fn environment_reserves_process_variables_and_prefers_canonical_even_empty() {
    let alias = EnvironmentAlias { variable: "LEGACY_NAME".into(), key: "name".into() };
    let loaded = sources::environment(variables(&[
        ("LEGACY_NAME", "fallback"), ("CILIUM_NAME", ""),
        ("CILIUM_SOCK", "socket"), ("CILIUM_HEALTH_SOCK", "socket"),
        ("CILIUM_K8S_NAMESPACE", "ns"), ("K8S_NODE_NAME", "node"), ("UNRELATED", "value"),
    ]), std::slice::from_ref(&alias)).unwrap();
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries.first().unwrap().value, "");
    let fallback = sources::environment(variables(&[("LEGACY_NAME", "fallback")]), &[alias]).unwrap();
    assert_eq!(fallback.entries.first().unwrap().key, "name");
    assert_eq!(fallback.entries.first().unwrap().value, "fallback");
    let registry = Registry::new([]).unwrap();
    let unknown = sources::environment(variables(&[("CILIUM_NEW_KEY", "future")]), &[]).unwrap();
    assert!(registry.resolve(unknown.entries).unwrap().unknown_keys().contains("new-key"));
    for aliases in [
        vec![EnvironmentAlias { variable: "CILIUM_NAME".into(), key: "name".into() }],
        vec![EnvironmentAlias { variable: "CILIUM_SOCK".into(), key: "name".into() }],
        vec![EnvironmentAlias { variable: "OLD_NAME".into(), key: "name".into() }, EnvironmentAlias { variable: "OTHER_NAME".into(), key: "NAME".into() }],
    ] { assert!(sources::environment([], &aliases).is_err()); }
}

#[cfg(unix)]
#[test]
fn invalid_environment_bytes_fail_only_for_configuration_variables() {
    use std::os::unix::ffi::OsStringExt;
    let bad = OsString::from_vec(vec![0xff]);
    assert!(sources::environment([(OsString::from("CILIUM_NAME"), bad.clone())], &[]).is_err());
    assert!(sources::environment([(OsString::from("UNRELATED"), bad.clone()), (bad.clone(), bad)], &[]).is_ok());
}

#[test]
fn file_directory_environment_and_flags_layer_without_losing_unrelated_keys() {
    let fixture = Fixture::new();
    fs::write(fixture.path().join("name"), "directory\n").unwrap();
    let registry = Registry::new([
        KeySpec::new("name", Kind::String, "default"),
        KeySpec::new("file-only", Kind::Bool, "false"),
    ]).unwrap();
    let mut entries = sources::yaml("name: file\nfile-only: true\n").unwrap().entries;
    entries.extend(sources::directory(fixture.path()).unwrap().entries);
    assert_eq!(registry.resolve(entries.clone()).unwrap().get("name").unwrap().value, Value::String("directory".into()));
    entries.extend(sources::environment(variables(&[("CILIUM_NAME", "environment")]), &[]).unwrap().entries);
    assert_eq!(registry.resolve(entries.clone()).unwrap().get("name").unwrap().source, Source::Env);
    entries.push(Entry::new(Source::Flag, "name", "flag"));
    let resolved = registry.resolve(entries).unwrap();
    assert_eq!(resolved.get("name").unwrap().value, Value::String("flag".into()));
    assert_eq!(resolved.get("file-only").unwrap().value, Value::Bool(true));
    assert_eq!(resolved.get("file-only").unwrap().source, Source::File);
}
