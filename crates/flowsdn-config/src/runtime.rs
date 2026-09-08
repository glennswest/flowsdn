//! Runtime snapshots in the spec 00 §4.5 JSON format. Snapshots contain the
//! caller's registered schema; this module does not supply the agent catalogue.

use crate::{Class, Effective, Kind, Registry, Resolved, Source, UnknownValue, Value, immutable, normalize};
use serde_json::{Map, Value as Json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const CURRENT: &str = "agent-runtime-config.json";
pub const PREVIOUS: &str = "agent-runtime-config-1.json";
pub const OLDEST: &str = "agent-runtime-config-2.json";
pub const REFERENCE_COMPAT: &str = "cilium-1.20.1";
/// Bound both persisted output and previous-snapshot input to 16 MiB.
pub const MAX_SNAPSHOT_BYTES: usize = 16_777_216;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub version: String,
    /// Caller-supplied RFC3339 timestamp; this module never reads a clock.
    pub written_at: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub metadata: Metadata,
    pub resolved: Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(pub String);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for Error {}

fn invalid(message: &str) -> Error { Error(message.into()) }

fn timestamp(text: &str) -> bool {
    fn number(text: &str, width: usize) -> Option<u32> {
        (text.len() == width && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.parse().ok()).flatten()
    }
    let Some((date, clock)) = text.split_once(['T', 't']) else { return false; };
    let mut date = date.split('-');
    let Some(year) = date.next().and_then(|v| number(v, 4)) else { return false; };
    let Some(month) = date.next().and_then(|v| number(v, 2)) else { return false; };
    let Some(day) = date.next().and_then(|v| number(v, 2)) else { return false; };
    if date.next().is_some() { return false; }
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days { return false; }
    let clock = if let Some(clock) = clock.strip_suffix(['Z', 'z']) { clock }
        else if let Some(offset) = clock.rfind(['+', '-']) {
            let Some(zone) = clock.get(offset..).and_then(|s| s.get(1..)) else { return false; };
            let Some((hours, minutes)) = zone.split_once(':') else { return false; };
            if !number(hours, 2).is_some_and(|v| v <= 23) || !number(minutes, 2).is_some_and(|v| v <= 59) { return false; }
            let Some(clock) = clock.get(..offset) else { return false; };
            clock
        } else { return false; };
    let mut parts = clock.split(':');
    if !parts.next().and_then(|v| number(v, 2)).is_some_and(|v| v <= 23)
        || !parts.next().and_then(|v| number(v, 2)).is_some_and(|v| v <= 59) { return false; }
    let Some(seconds) = parts.next() else { return false; };
    if parts.next().is_some() { return false; }
    let seconds = if let Some((whole, fraction)) = seconds.split_once('.') {
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) { return false; }
        whole
    } else { seconds };
    number(seconds, 2).is_some_and(|v| v <= 60)
}

fn encoded(value: &Value) -> Result<Json, Error> {
    Ok(match value {
        Value::Bool(value) => Json::Bool(*value),
        Value::Int(value) | Value::Duration(value) => Json::from(*value),
        Value::UInt(value) => Json::from(*value),
        Value::Float(value) => Json::Number(serde_json::Number::from_f64(*value).ok_or_else(|| invalid("non-finite configuration float"))?),
        Value::String(value) | Value::Enum(value) => Json::String(value.clone()),
        Value::Ip(value) => Json::String(value.to_string()),
        Value::Cidr { address, prefix } => Json::String(format!("{address}/{prefix}")),
        Value::HostPort { host, port } => Json::String(if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }),
        Value::List(values) => Json::Array(values.iter().cloned().map(Json::String).collect()),
        Value::Map(values) => Json::Object(values.iter().map(|(key, value)| (key.clone(), Json::String(value.clone()))).collect()),
    })
}

/// Encode durations as signed nanoseconds; addresses/prefixes/hostports as
/// strings, lists as arrays and maps as objects. Unknown-key sources are kept
/// in `sources` alongside known-key sources so provenance survives a roundtrip.
pub fn encode(resolved: &Resolved, metadata: &Metadata) -> Result<String, Error> {
    if metadata.version.is_empty() || !timestamp(&metadata.written_at) { return Err(invalid("snapshot metadata requires a version and RFC3339 timestamp")); }
    let mut config = Map::new();
    let mut sources = Map::new();
    let mut immutable = Vec::new();
    for (key, effective) in resolved.values() {
        if effective.class == Class::Script { continue; }
        config.insert(key.clone(), encoded(&effective.value)?);
        sources.insert(key.clone(), Json::String(effective.source.to_string()));
        if effective.class == Class::Immutable { immutable.push(Json::String(key.clone())); }
    }
    let mut unknown = Map::new();
    for (key, value) in resolved.unknown_values() {
        unknown.insert(key.clone(), Json::String(value.raw.clone()));
        sources.insert(key.clone(), Json::String(value.source.to_string()));
    }
    let document = serde_json::json!({
        "flowsdn-version": metadata.version,
        "written-at": metadata.written_at,
        "reference-compat": REFERENCE_COMPAT,
        "config": config,
        "sources": sources,
        "unknown-keys": unknown,
        "immutable-keys": immutable,
    });
    let mut output = serde_json::to_string_pretty(&document).map_err(|_| invalid("cannot serialize runtime configuration"))?;
    output.push('\n');
    if output.len() > MAX_SNAPSHOT_BYTES { return Err(invalid("runtime snapshot exceeds the size limit")); }
    Ok(output)
}

fn object<'a>(document: &'a Map<String, Json>, key: &str) -> Result<&'a Map<String, Json>, Error> {
    document.get(key).and_then(Json::as_object).ok_or_else(|| Error(format!("snapshot field {key} must be an object")))
}

fn string<'a>(document: &'a Map<String, Json>, key: &str) -> Result<&'a str, Error> {
    document.get(key).and_then(Json::as_str).filter(|s| !s.is_empty()).ok_or_else(|| Error(format!("snapshot field {key} must be a non-empty string")))
}

fn source(value: &Json) -> Result<Source, Error> {
    match value.as_str() {
        Some("default") => Ok(Source::Default), Some("file") => Ok(Source::File),
        Some("dir") => Ok(Source::Dir), Some("env") => Ok(Source::Env), Some("flag") => Ok(Source::Flag),
        _ => Err(invalid("snapshot contains an invalid configuration source")),
    }
}

fn typed(value: &Json, kind: &Kind) -> Result<Value, Error> {
    let raw = match kind {
        Kind::List => return value.as_array().ok_or_else(|| invalid("expected a JSON array for list"))?
            .iter().map(|value| value.as_str().map(str::to_owned).ok_or_else(|| invalid("list members must be strings"))).collect::<Result<Vec<_>, _>>().map(Value::List),
        Kind::Map => return value.as_object().ok_or_else(|| invalid("expected a JSON object for map"))?
            .iter().map(|(key, value)| {
                if key.is_empty() { return Err(invalid("map key is empty")); }
                value.as_str().map(|value| (key.clone(), value.to_owned())).ok_or_else(|| invalid("map values must be strings"))
            }).collect::<Result<BTreeMap<_, _>, _>>().map(Value::Map),
        Kind::Bool => value.as_bool().ok_or_else(|| invalid("expected a JSON boolean"))?.to_string(),
        Kind::Int { .. } | Kind::Duration => value.as_i64().ok_or_else(|| invalid("expected a signed JSON integer"))?.to_string(),
        Kind::UInt { .. } => value.as_u64().ok_or_else(|| invalid("expected an unsigned JSON integer"))?.to_string(),
        Kind::Float { .. } => value.as_f64().ok_or_else(|| invalid("expected a JSON number"))?.to_string(),
        _ => value.as_str().ok_or_else(|| invalid("expected a JSON string"))?.to_owned(),
    };
    crate::parse::parse(kind, &raw).map(|(value, _)| value).map_err(|error| Error(format!("invalid typed snapshot value: {error}")))
}

// Removed keys lack a current schema kind. Preserve their JSON meaning for
// diagnostics and immutable presence comparison without inventing defaults.
fn untyped(value: &Json) -> Result<Value, Error> {
    match value {
        Json::Bool(value) => Ok(Value::Bool(*value)),
        Json::String(value) => Ok(Value::String(value.clone())),
        Json::Number(value) => {
            if let Some(value) = value.as_i64() { Ok(Value::Int(value)) }
            else if let Some(value) = value.as_u64() { Ok(Value::UInt(value)) }
            else { value.as_f64().map(Value::Float).ok_or_else(|| invalid("invalid numeric snapshot value")) }
        }
        Json::Array(_) => typed(value, &Kind::List),
        Json::Object(_) => typed(value, &Kind::Map),
        Json::Null => Err(invalid("configuration snapshot values cannot be null")),
    }
}

/// Decode prior values using the supplied schema, preserving missing/new keys
/// rather than filling defaults. A schema-incompatible prior value is an error
/// for the caller to report as an unparseable previous snapshot.
pub fn decode(text: &str, registry: &Registry) -> Result<Snapshot, Error> {
    if text.len() > MAX_SNAPSHOT_BYTES { return Err(invalid("runtime snapshot exceeds the size limit")); }
    let json: Json = serde_json::from_str(text).map_err(|_| invalid("invalid runtime configuration JSON"))?;
    let document = json.as_object().ok_or_else(|| invalid("runtime configuration must be an object"))?;
    let metadata = Metadata { version: string(document, "flowsdn-version")?.into(), written_at: string(document, "written-at")?.into() };
    if !timestamp(&metadata.written_at) { return Err(invalid("snapshot written-at must be RFC3339")); }
    if string(document, "reference-compat")? != REFERENCE_COMPAT { return Err(invalid("unsupported reference compatibility version")); }
    let config = object(document, "config")?;
    let sources = object(document, "sources")?;
    let unknown = object(document, "unknown-keys")?;
    let immutable = document.get("immutable-keys").and_then(Json::as_array).ok_or_else(|| invalid("immutable-keys must be an array"))?;
    let mut immutable_keys = BTreeSet::new();
    for key in immutable {
        let key = key.as_str().ok_or_else(|| invalid("immutable keys must be strings"))?;
        if !config.contains_key(key) || !immutable_keys.insert(key) { return Err(invalid("immutable key is missing or duplicated")); }
    }
    let expected_sources: BTreeSet<_> = config.keys().chain(unknown.keys()).collect();
    if sources.keys().collect::<BTreeSet<_>>() != expected_sources { return Err(invalid("snapshot sources do not match configuration keys")); }
    let mut resolved = Resolved { values: BTreeMap::new(), warnings: Vec::new(), unknown_keys: BTreeSet::new(), unknown_values: BTreeMap::new() };
    for (key, value) in config {
        if key.is_empty() || normalize(key) != *key || unknown.contains_key(key) { return Err(invalid("snapshot keys must be canonical and disjoint")); }
        let spec = registry.specs.get(key);
        if spec.is_some_and(|spec| spec.class == Class::Script) { return Err(invalid("script keys cannot appear in runtime configuration")); }
        let value = match spec { Some(spec) => typed(value, &spec.kind)?, None => untyped(value)? };
        let class = if immutable_keys.contains(key.as_str()) { Class::Immutable }
            else if spec.is_some_and(|spec| spec.class == Class::Ignored) { Class::Ignored } else { Class::Active };
        let source = source(sources.get(key).ok_or_else(|| invalid("missing configuration source"))?)?;
        resolved.values.insert(key.clone(), Effective { value, source, class });
    }
    for (key, value) in unknown {
        if key.is_empty() || normalize(key) != *key { return Err(invalid("unknown snapshot keys must be canonical")); }
        let raw = value.as_str().ok_or_else(|| invalid("unknown snapshot values must be strings"))?;
        let source = source(sources.get(key).ok_or_else(|| invalid("missing unknown configuration source"))?)?;
        resolved.unknown_keys.insert(key.clone());
        resolved.unknown_values.insert(key.clone(), UnknownValue { raw: raw.into(), source });
    }
    Ok(Snapshot { metadata, resolved })
}

/// Use before publication with CURRENT, or after rotation with PREVIOUS.
/// Missing state is accepted; unreadable/incompatible state is reported as the
/// immutability check's nonfatal previous-snapshot warning. Unix opens reject
/// final-component symlinks and cannot block on FIFOs. The opened descriptor
/// must be a regular file; reads are bounded even if it grows after opening.
pub fn check_previous(path: &Path, registry: &Registry, current: &Resolved, restore: bool, has_endpoint_state: bool) -> Result<immutable::Report, immutable::Incompatible> {
    match read_previous(path) {
        Ok(text) => match decode(&text, registry) {
            Ok(snapshot) => immutable::check(immutable::Previous::Parsed(&snapshot.resolved), current, restore, has_endpoint_state),
            Err(_) => immutable::check(immutable::Previous::Unparseable, current, restore, has_endpoint_state),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => immutable::check(immutable::Previous::Absent, current, restore, has_endpoint_state),
        Err(_) => immutable::check(immutable::Previous::Unparseable, current, restore, has_endpoint_state),
    }
}

fn read_previous(path: &Path) -> std::io::Result<String> {
    // No portable safe API offers no-follow/nonblocking opens on every OS.
    // This project targets Linux; other platforms report previous state as
    // unavailable rather than falling back to an unsafe path-based read.
    #[cfg(not(unix))]
    { let _ = path; Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "safe snapshot reads require Unix")) }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new().read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_SNAPSHOT_BYTES as u64 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot must be a bounded regular file"));
        }
        let mut text = String::new();
        file.take((MAX_SNAPSHOT_BYTES as u64).saturating_add(1)).read_to_string(&mut text)?;
        if text.len() > MAX_SNAPSHOT_BYTES {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot exceeds the size limit"));
        }
        Ok(text)
    }
}

#[derive(Clone, Debug)]
pub struct StoreWarning {
    pub operation: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct StoreReport {
    pub published: bool,
    pub warnings: Vec<StoreWarning>,
}

struct Temporary(PathBuf);
impl Drop for Temporary { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }

fn temporary(dir: &Path, role: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    dir.join(format!(".agent-runtime-config-{role}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)))
}

impl StoreReport {
    fn warn(&mut self, operation: &'static str, error: impl fmt::Display) {
        self.warnings.push(StoreWarning { operation, message: error.to_string() });
    }
}

/// Stage and sync JSON before rotating history, then atomically rename it over
/// CURRENT. Hard-linking the old current inode into its history staging name
/// keeps CURRENT readable throughout rotation. Rotation failures are reported
/// but do not prevent publishing the new snapshot. The caller serializes
/// writers for this directory; this is not a multiprocess coordination API.
/// All I/O failures are diagnostics, not startup errors.
pub fn store(dir: &Path, resolved: &Resolved, metadata: &Metadata) -> StoreReport {
    let mut report = StoreReport::default();
    let text = match encode(resolved, metadata) { Ok(text) => text, Err(error) => { report.warn("encode", error); return report; } };
    let staging_path = temporary(dir, "new");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(&staging_path) {
        Ok(file) => file, Err(error) => { report.warn("create", error); return report; }
    };
    let staging = Temporary(staging_path);
    if let Err(error) = file.write_all(text.as_bytes()).and_then(|()| file.sync_all()) { report.warn("write", error); return report; }
    drop(file);
    let current = dir.join(CURRENT);
    let previous = dir.join(PREVIOUS);
    let oldest = dir.join(OLDEST);
    let backup_path = temporary(dir, "history");
    let history = fs::symlink_metadata(&current).and_then(|metadata| {
        if metadata.is_file() { fs::hard_link(&current, &backup_path) }
        else { Err(std::io::Error::other("current snapshot is not a regular file")) }
    });
    match history {
        Ok(()) => {
            let backup = Temporary(backup_path);
            match fs::symlink_metadata(&previous) {
                Ok(metadata) if metadata.is_file() => {
                    if let Err(error) = fs::rename(&previous, &oldest) { report.warn("rotate-previous", error); }
                },
                Ok(_) => report.warn("rotate-previous", "previous snapshot is not a regular file"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                Err(error) => report.warn("rotate-previous", error),
            }
            if let Err(error) = fs::rename(&backup.0, &previous) { report.warn("rotate-current", error); }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => report.warn("stage-history", error),
    }
    if let Err(error) = fs::rename(&staging.0, &current) { report.warn("publish", error); return report; }
    report.published = true;
    if let Err(error) = File::open(dir).and_then(|file| file.sync_all()) { report.warn("sync-directory", error); }
    report
}
