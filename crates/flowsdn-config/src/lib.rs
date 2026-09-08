//! Typed configuration layering from foundation specification §3.3.
//!
//! Callers supply the schema and raw source entries. This core does not yet
//! supply the complete agent key catalogue or every cross-key validation rule.
//! Source adapters are available in `sources`; runtime snapshots in `runtime`.
#![forbid(unsafe_code)]

pub mod immutable;
mod parse;
pub mod runtime;
pub mod sources;
pub mod validation;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

/// Source order is the precedence order, from weakest to strongest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Source {
    Default,
    File,
    Dir,
    Env,
    Flag,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::File => "file",
            Self::Dir => "dir",
            Self::Env => "env",
            Self::Flag => "flag",
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Bool,
    Int { bits: u8 },
    UInt { bits: u8 },
    Float { bits: u8 },
    Duration,
    String,
    List,
    Map,
    Enum(Vec<String>),
    Cidr,
    Ip,
    HostPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Active,
    /// Compared with the previous run before restoring existing endpoints.
    Immutable,
    Ignored,
    Script,
}

#[derive(Clone, Debug)]
pub struct KeySpec {
    pub name: String,
    pub kind: Kind,
    pub default: String,
    pub class: Class,
}

impl KeySpec {
    pub fn new(name: impl Into<String>, kind: Kind, default: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind,
            default: default.into(),
            class: Class::Active,
        }
    }
}

/// Parsed values; signed nanoseconds preserve Go duration's range and sign.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Duration(i64),
    String(String),
    List(Vec<String>),
    Map(BTreeMap<String, String>),
    Enum(String),
    Cidr { address: IpAddr, prefix: u8 },
    Ip(IpAddr),
    HostPort { host: String, port: u16 },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Effective {
    pub value: Value,
    pub source: Source,
    /// Ignored and script keys are retained for diagnostics, not activation.
    pub class: Class,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Warning {
    UnknownKey { key: String, source: Source },
    IgnoredKey { key: String, source: Source },
    BareDuration { key: String, source: Source },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey { key, source } => {
                write!(f, "unknown configuration key {key} (source {source})")
            }
            Self::IgnoredKey { key, source } => {
                write!(f, "ignored configuration key {key} (source {source})")
            }
            Self::BareDuration { key, source } => write!(
                f,
                "bare duration for {key} interpreted as nanoseconds (source {source})"
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub key: String,
    pub message: String,
}

impl Error {
    fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "option {}: {}", self.key, self.message)
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct Entry {
    pub source: Source,
    pub key: String,
    pub value: String,
}

impl Entry {
    pub fn new(source: Source, key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            source,
            key: key.into(),
            value: value.into(),
        }
    }

    /// Returns None for environment variables outside the compatibility prefix.
    pub fn environment(name: &str, value: impl Into<String>) -> Option<Self> {
        name.strip_prefix("CILIUM_")
            .map(|key| Self::new(Source::Env, key, value))
    }
}

/// Normalize key bodies; environment prefix removal is explicit in `Entry::environment`.
pub fn normalize(key: &str) -> String {
    key.replace('_', "-").to_ascii_lowercase()
}

const ALIASES: [(&str, &str); 3] = [
    ("monitor-aggregation-level", "monitor-aggregation"),
    ("ct-global-max-entries-tcp", "bpf-ct-global-tcp-max"),
    ("ct-global-max-entries-other", "bpf-ct-global-any-max"),
];

#[derive(Clone, Debug)]
pub struct Registry {
    specs: BTreeMap<String, KeySpec>,
}

/// Immutable resolved configuration. A caller can share this with `Arc` after
/// completing its area-specific validation and derivation.
#[derive(Clone, Debug)]
pub struct Resolved {
    values: BTreeMap<String, Effective>,
    warnings: Vec<Warning>,
    unknown_keys: BTreeSet<String>,
    unknown_values: BTreeMap<String, UnknownValue>,
}

/// The effective raw value of an unregistered key, retained for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownValue {
    pub raw: String,
    pub source: Source,
}

impl Resolved {
    pub fn get(&self, key: &str) -> Option<&Effective> {
        self.values.get(&normalize(key))
    }

    pub fn values(&self) -> &BTreeMap<String, Effective> {
        &self.values
    }

    pub fn warnings(&self) -> &[Warning] {
        &self.warnings
    }

    pub fn unknown_keys(&self) -> &BTreeSet<String> {
        &self.unknown_keys
    }

    pub fn unknown_values(&self) -> &BTreeMap<String, UnknownValue> {
        &self.unknown_values
    }
}

impl Registry {
    pub fn new(specs: impl IntoIterator<Item = KeySpec>) -> Result<Self, Error> {
        let mut registry = Self {
            specs: BTreeMap::new(),
        };
        for mut spec in specs {
            let name = normalize(&spec.name);
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || name.starts_with('-')
                || name.ends_with('-')
                || name.contains("--")
            {
                return Err(Error::new(name, "invalid configuration key"));
            }
            if ALIASES.iter().any(|(alias, _)| *alias == name) {
                return Err(Error::new(
                    name,
                    "deprecated alias cannot be registered as a canonical key",
                ));
            }
            parse::parse(&spec.kind, &spec.default)
                .map_err(|message| Error::new(&name, message))?;
            spec.name = name.clone();
            if registry.specs.insert(name.clone(), spec).is_some() {
                return Err(Error::new(name, "duplicate key after normalization"));
            }
        }
        Ok(registry)
    }

    /// Parse every supplied known value, including values shadowed by a stronger
    /// layer. Explicit canonical keys suppress deprecated aliases across sources;
    /// defaults do not suppress aliases. Repeated list flags append in input order.
    pub fn resolve(&self, entries: impl IntoIterator<Item = Entry>) -> Result<Resolved, Error> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        let canonical: BTreeSet<_> = entries
            .iter()
            .filter(|e| e.source != Source::Default)
            .map(|e| normalize(&e.key))
            .filter(|k| self.specs.contains_key(k))
            .collect();
        // Stable sorting preserves repeated flag order within its source.
        entries.sort_by_key(|entry| entry.source);
        let mut resolved = Resolved {
            values: BTreeMap::new(),
            warnings: Vec::new(),
            unknown_keys: BTreeSet::new(),
            unknown_values: BTreeMap::new(),
        };
        for spec in self.specs.values() {
            self.apply(&mut resolved, spec, Source::Default, &spec.default)?;
        }
        let mut ignored = BTreeSet::new();
        for entry in entries {
            let mut key = normalize(&entry.key);
            if let Some((_, target)) = ALIASES.iter().find(|(alias, _)| *alias == key) {
                if canonical.contains(*target) {
                    continue;
                }
                key = (*target).to_owned();
            }
            let Some(spec) = self.specs.get(&key) else {
                resolved.unknown_values.insert(
                    key.clone(),
                    UnknownValue {
                        raw: entry.value,
                        source: entry.source,
                    },
                );
                if resolved.unknown_keys.insert(key.clone()) {
                    resolved.warnings.push(Warning::UnknownKey {
                        key,
                        source: entry.source,
                    });
                }
                continue;
            };
            self.apply(&mut resolved, spec, entry.source, &entry.value)?;
            if matches!(spec.class, Class::Ignored | Class::Script) && ignored.insert(key.clone()) {
                resolved.warnings.push(Warning::IgnoredKey {
                    key,
                    source: entry.source,
                });
            }
        }
        Ok(resolved)
    }

    fn apply(
        &self,
        resolved: &mut Resolved,
        spec: &KeySpec,
        source: Source,
        raw: &str,
    ) -> Result<(), Error> {
        let (mut value, bare_duration) =
            parse::parse(&spec.kind, raw).map_err(|message| Error::new(&spec.name, message))?;
        if bare_duration {
            resolved.warnings.push(Warning::BareDuration {
                key: spec.name.clone(),
                source,
            });
        }
        if source == Source::Flag
            && let Some(Effective {
                value: Value::List(previous),
                source: Source::Flag,
                ..
            }) = resolved.values.get(&spec.name)
            && let Value::List(items) = &mut value
        {
            let mut combined = previous.clone();
            combined.append(items);
            *items = combined;
        }
        resolved.values.insert(
            spec.name.clone(),
            Effective {
                value,
                source,
                class: spec.class,
            },
        );
        Ok(())
    }
}
