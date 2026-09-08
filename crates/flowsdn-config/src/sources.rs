//! Source adapters. File contents and environment values flow through the same
//! registry parser as flags; these adapters do not activate or validate options.

use crate::{Entry, Source, normalize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::scanner::TScalarStyle;

#[derive(Clone, Debug, Default)]
pub struct Loaded {
    pub entries: Vec<Entry>,
    pub warnings: Vec<LoadWarning>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadWarning {
    /// File path or environment variable name, never its value.
    pub location: String,
    pub message: String,
}

impl fmt::Display for LoadWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadError {
    pub location: String,
    pub message: String,
}

impl LoadError {
    fn new(location: impl Into<String>, message: impl Into<String>) -> Self {
        Self { location: location.into(), message: message.into() }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.message)
    }
}

impl std::error::Error for LoadError {}

/// Read one file per key, following file and directory symlinks. Directory
/// entries (including a projected ConfigMap's `..data`) are skipped. Missing
/// or unreadable directories are fatal; individual unreadable files are not.
/// Entries are sorted by filename for deterministic same-layer resolution.
pub fn directory(path: &Path) -> Result<Loaded, LoadError> {
    let listing = fs::read_dir(path).map_err(|error| LoadError::new(path.display().to_string(), error.to_string()))?;
    let mut loaded = Loaded::default();
    let mut paths = Vec::new();
    for item in listing {
        match item {
            Ok(item) => paths.push(item.path()),
            Err(error) => loaded.warnings.push(LoadWarning { location: path.display().to_string(), message: error.to_string() }),
        }
    }
    paths.sort();
    for path in paths {
        let warn = |message: String| LoadWarning { location: path.display().to_string(), message };
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => { loaded.warnings.push(warn(error.to_string())); continue; }
        };
        if metadata.is_dir() { continue; }
        if !metadata.is_file() {
            loaded.warnings.push(warn("skipping non-regular configuration file".into()));
            continue;
        }
        let Some(key) = path.file_name().and_then(|name| name.to_str()) else {
            loaded.warnings.push(warn("configuration filename is not UTF-8".into()));
            continue;
        };
        match fs::read_to_string(&path) {
            Ok(value) => loaded.entries.push(Entry::new(Source::Dir, key, value.trim())),
            Err(error) => loaded.warnings.push(warn(error.to_string())),
        }
    }
    Ok(loaded)
}

/// Parse one YAML document containing a flat mapping of keys to scalar values.
/// Scalar text is preserved, avoiding float rounding and integer-width loss
/// before the registry's typed parser runs. Nested containers and YAML nulls
/// are rejected; list/map options use their specified textual representations.
pub fn yaml(text: &str) -> Result<Loaded, LoadError> {
    let mut receiver = ScalarMapping::default();
    Parser::new(text.chars()).load(&mut receiver, true).map_err(|_| LoadError::new("config YAML", "invalid YAML syntax"))?;
    if let Some(message) = receiver.error { return Err(LoadError::new("config YAML", message)); }
    if !receiver.mapping_seen && !text.trim().is_empty() && receiver.documents != 0 {
        return Err(LoadError::new("config YAML", "expected a mapping of keys to scalar values"));
    }
    Ok(Loaded { entries: receiver.entries, warnings: Vec::new() })
}

/// An explicitly selected file must exist. Without one, read `ciliumd.yaml`
/// in the supplied home directory if present; no home means no default file.
/// Supplying home explicitly makes source selection independent of global
/// process environment and straightforward to exercise in parallel tests.
pub fn file(explicit: Option<&Path>, home: Option<&Path>) -> Result<Loaded, LoadError> {
    let (path, optional): (PathBuf, bool) = match explicit {
        Some(path) => (path.into(), false),
        None => match home {
            Some(home) => (home.join("ciliumd.yaml"), true),
            None => return Ok(Loaded::default()),
        },
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(Loaded::default()),
        Err(error) => return Err(LoadError::new(path.display().to_string(), error.to_string())),
    };
    yaml(&text).map_err(|mut error| { error.location = path.display().to_string(); error })
}

/// Additional legacy names can be supplied by an area's configuration schema.
/// A present canonical variable suppresses its fallback, even if it is empty.
#[derive(Clone, Debug)]
pub struct EnvironmentAlias {
    pub variable: String,
    pub key: String,
}

/// Load an environment snapshot without mutating process environment. Standard
/// `CILIUM_` names are retained even when unknown to the schema, so the registry
/// can warn. Variables owned by other process interfaces are excluded (§6.3).
pub fn environment(
    variables: impl IntoIterator<Item = (OsString, OsString)>,
    aliases: &[EnvironmentAlias],
) -> Result<Loaded, LoadError> {
    const PROCESS_ONLY: [&str; 4] = ["CILIUM_SOCK", "CILIUM_HEALTH_SOCK", "CILIUM_K8S_NAMESPACE", "K8S_NODE_NAME"];
    let variables: BTreeMap<_, _> = variables.into_iter().collect();
    let mut loaded = Loaded::default();
    let mut seen_alias_keys = BTreeSet::new();
    let mut seen_alias_names = BTreeSet::new();
    for alias in aliases {
        let key = normalize(&alias.key);
        let canonical = format!("CILIUM_{}", key.replace('-', "_").to_ascii_uppercase());
        if key.is_empty() || alias.variable == canonical || PROCESS_ONLY.contains(&alias.variable.as_str())
            || !seen_alias_keys.insert(key) || !seen_alias_names.insert(&alias.variable)
        {
            return Err(LoadError::new(&alias.variable, "invalid or ambiguous environment alias"));
        }
    }
    // Check the complete alias schema before consuming any input. An alias
    // variable cannot also be a canonical variable for another declared key:
    // consuming it as an alias would silently discard that key's source value.
    for alias in aliases {
        if let Some(body) = alias.variable.strip_prefix("CILIUM_")
            && seen_alias_keys.contains(&normalize(body))
        {
            return Err(LoadError::new(&alias.variable, "environment alias collides with a canonical variable"));
        }
    }
    for (name, value) in &variables {
        let Some(name) = name.to_str() else { continue; };
        if PROCESS_ONLY.contains(&name) || aliases.iter().any(|alias| alias.variable == name) { continue; }
        if let Some(key) = name.strip_prefix("CILIUM_") {
            let value = value.to_str().ok_or_else(|| LoadError::new(name, "configuration environment value is not UTF-8"))?;
            loaded.entries.push(Entry::new(Source::Env, key, value));
        }
    }
    for alias in aliases {
        let key = normalize(&alias.key);
        let canonical = format!("CILIUM_{}", key.replace('-', "_").to_ascii_uppercase());
        if variables.contains_key(&OsString::from(&canonical)) { continue; }
        if let Some(value) = variables.get(&OsString::from(&alias.variable)) {
            let value = value.to_str().ok_or_else(|| LoadError::new(&alias.variable, "configuration environment value is not UTF-8"))?;
            loaded.entries.push(Entry::new(Source::Env, key, value));
        }
    }
    Ok(loaded)
}

/// Snapshot the current process environment; callers can also use `environment`
/// with an injected snapshot for tests and reproducible configuration reports.
pub fn current_environment(aliases: &[EnvironmentAlias]) -> Result<Loaded, LoadError> {
    environment(std::env::vars_os(), aliases)
}

#[derive(Default)]
struct ScalarMapping {
    documents: usize,
    mapping_seen: bool,
    in_mapping: bool,
    key: Option<String>,
    seen_keys: BTreeSet<String>,
    anchors: BTreeMap<usize, String>,
    entries: Vec<Entry>,
    error: Option<String>,
}

impl ScalarMapping {
    fn scalar(&mut self, value: String) {
        if !self.in_mapping {
            self.error = Some("expected a mapping of keys to scalar values".into());
            return;
        }
        if let Some(key) = self.key.take() {
            self.entries.push(Entry::new(Source::File, key, value));
        } else if value.is_empty() || !self.seen_keys.insert(normalize(&value)) {
            self.error = Some("empty or duplicate normalized configuration key".into());
        } else {
            self.key = Some(value);
        }
    }
}

impl EventReceiver for ScalarMapping {
    fn on_event(&mut self, event: Event) {
        if self.error.is_some() { return; }
        match event {
            Event::DocumentStart => {
                self.documents = self.documents.saturating_add(1);
                if self.documents > 1 { self.error = Some("expected a single YAML document".into()); }
            }
            Event::MappingStart(_, tag) if !self.mapping_seen && tag.is_none() => {
                self.mapping_seen = true;
                self.in_mapping = true;
            }
            Event::MappingEnd if self.in_mapping => { self.in_mapping = false; }
            Event::Scalar(value, style, anchor, tag) => {
                // Tags can redefine interpretation; the configuration schema,
                // rather than YAML type tags, owns value types.
                if tag.is_some() || (style == TScalarStyle::Plain && (value.is_empty() || value == "~" || value.eq_ignore_ascii_case("null"))) {
                    self.error = Some("YAML nulls and explicit type tags are not configuration scalar values".into());
                    return;
                }
                if anchor != 0 { self.anchors.insert(anchor, value.clone()); }
                self.scalar(value);
            }
            Event::Alias(anchor) => match self.anchors.get(&anchor).cloned() {
                Some(value) => self.scalar(value),
                None => self.error = Some("configuration aliases must refer to a scalar".into()),
            },
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd | Event::Nothing => {},
            _ => self.error = Some("expected a flat mapping of keys to scalar values".into()),
        }
    }
}
