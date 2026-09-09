//! All 539 key declarations from foundation specification §6.4. Defaults that
//! remain symbolic after consulting owning specs are explicit gaps, never guessed literals.
//! Schema construction does not replace foundation or area-specific validation.

mod entries;
pub use entries::ENTRIES;

use crate::{Class, Entry, KeySpec, Kind, Registry, Resolved, normalize};
use std::collections::BTreeMap;
use std::fmt;

pub const SPECIFICATION: &str =
    "docs/spec/00-foundation-table-config.md#64-the-registry-key-table-539-keys";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pflag {
    Bool,
    Int,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Float32,
    Float64,
    Duration,
    String,
    StringSlice,
    StringToString,
    Var,
}

impl Pflag {
    pub fn name(self) -> &'static str {
        match self {
            Self::Bool => "Bool",
            Self::Int => "Int",
            Self::Int64 => "Int64",
            Self::Uint => "Uint",
            Self::Uint8 => "Uint8",
            Self::Uint16 => "Uint16",
            Self::Uint32 => "Uint32",
            Self::Uint64 => "Uint64",
            Self::Float32 => "Float32",
            Self::Float64 => "Float64",
            Self::Duration => "Duration",
            Self::String => "String",
            Self::StringSlice => "StringSlice",
            Self::StringToString => "StringToString",
            Self::Var => "Var",
        }
    }

    /// Native Int/Uint are 64-bit on both supported agent architectures.
    pub fn kind(self) -> Kind {
        match self {
            Self::Bool => Kind::Bool,
            Self::Int | Self::Int64 => Kind::Int { bits: 64 },
            Self::Uint | Self::Uint64 => Kind::UInt { bits: 64 },
            Self::Uint8 => Kind::UInt { bits: 8 },
            Self::Uint16 => Kind::UInt { bits: 16 },
            Self::Uint32 => Kind::UInt { bits: 32 },
            Self::Float32 => Kind::Float { bits: 32 },
            Self::Float64 => Kind::Float { bits: 64 },
            Self::Duration => Kind::Duration,
            Self::String => Kind::String,
            Self::StringSlice => Kind::List,
            Self::StringToString | Self::Var => Kind::Map,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Definition {
    pub name: &'static str,
    pub pflag: Pflag,
    /// Exact default expression recorded by the normative table.
    pub default_expression: &'static str,
    /// A literal input for the registry parser, or None for unresolved symbols.
    pub default: Option<&'static str>,
    pub class: Class,
    /// Original inventory constant name when the spec explicitly renames it.
    pub inventory_name: Option<&'static str>,
}

impl Definition {
    /// Source of the resolved parser input. Original table expressions remain
    /// available separately. None means that a production default is unresolved.
    /// Cross-spec citations name a Markdown file and its exact declaration line.
    pub fn default_provenance(self) -> Option<&'static str> {
        self.default?;
        Some(match self.name {
            "agent-not-ready-taint-key" => "docs/spec/12-operator.md:1415",
            "bpf-lb-algorithm" => "docs/spec/05-service-loadbalancing.md:926",
            "bpf-lb-dsr-dispatch" => "docs/spec/05-service-loadbalancing.md:925",
            "bpf-lb-maglev-hash-seed" => "docs/spec/05-service-loadbalancing.md:929",
            "bpf-lb-maglev-table-size" => "docs/spec/05-service-loadbalancing.md:928",
            "bpf-lb-map-max" => "docs/spec/05-service-loadbalancing.md:917",
            "bpf-lb-mode" => "docs/spec/05-service-loadbalancing.md:923",
            "bpf-map-event-buffers" => "docs/spec/03-identity-ipcache.md:924",
            "bpf-nat-global-max" => "docs/spec/04-conntrack-nat.md:804",
            "bpf-neigh-global-max" => "docs/spec/01-bpf-map-abi-loader.md:193",
            "bpf-node-map-max" => "docs/spec/14-encryption-egress.md:1715",
            "clustermesh-service-v2" => "docs/spec/20-clustermesh-kvstore.md:1548",
            "enable-bandwidth-manager" => "docs/spec/10-node-routing-nftables.md:1381",
            "enable-bbr" => "docs/spec/10-node-routing-nftables.md:1382",
            "enable-bbr-hostns-only" => "docs/spec/10-node-routing-nftables.md:1382",
            "enable-dynamic-source-lookup-nodeport" => "docs/spec/05-service-loadbalancing.md:940",
            "enable-node-ipam" => "docs/spec/12-operator.md:1452",
            "fixed-identity-mapping" => "docs/spec/03-identity-ipcache.md:909",
            "gateway-api-secrets-namespace" => "docs/spec/21-gateway-api-ingress.md:1697",
            "hubble-drop-events-reasons" => "docs/spec/11-hubble-monitor.md:2523",
            "hubble-event-buffer-capacity" => "docs/spec/11-hubble-monitor.md:2474",
            "hubble-lost-event-send-interval" => "docs/spec/11-hubble-monitor.md:2477",
            "hubble-socket-path" => "docs/spec/11-hubble-monitor.md:2472",
            "hubble-tls-cert-file" => "docs/spec/11-hubble-monitor.md:2480",
            "hubble-tls-client-ca-files" => "docs/spec/11-hubble-monitor.md:2482",
            "hubble-tls-key-file" => "docs/spec/11-hubble-monitor.md:2481",
            "ingress-secrets-namespace" => "docs/spec/21-gateway-api-ingress.md:1714",
            "ipam-multi-pool-pre-allocation" => "docs/spec/07-ipam.md:1247",
            "kvstore" => "docs/spec/20-clustermesh-kvstore.md:1507",
            "node-port-range" => "docs/spec/05-service-loadbalancing.md:919",
            "policy-secrets-namespace" => "docs/spec/12-operator.md:1449",
            "policy-secrets-only-from-secrets-namespace" => "docs/spec/16-l7-envoy-dns.md:1479",
            "socket-path" => "docs/spec/08-endpoint-agent-api.md:1319",
            _ => SPECIFICATION,
        })
    }
    /// The table does not supply help text or hidden-flag metadata.
    pub fn help(self) -> Option<&'static str> {
        None
    }
    pub fn hidden(self) -> Option<bool> {
        None
    }
    pub fn needs_area_validator(self) -> bool {
        self.pflag == Pflag::Var
    }
    pub fn aliases(self) -> impl Iterator<Item = &'static str> {
        crate::ALIASES
            .iter()
            .filter_map(move |(alias, target)| (*target == self.name).then_some(*alias))
    }
    fn spec(self, default: &str) -> KeySpec {
        KeySpec {
            name: self.name.into(),
            kind: self.pflag.kind(),
            default: default.into(),
            class: self.class,
        }
    }
}

pub fn get(name: &str) -> Option<&'static Definition> {
    let name = normalize(name);
    let canonical = crate::ALIASES
        .iter()
        .find(|(alias, _)| *alias == name)
        .map_or(name.as_str(), |(_, key)| *key);
    ENTRIES.iter().find(|entry| entry.name == canonical)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coverage {
    pub declared: usize,
    pub literal_defaults: usize,
    pub unresolved_defaults: Vec<&'static str>,
    pub area_validators_required: Vec<&'static str>,
    pub help_metadata_missing: usize,
    pub hidden_metadata_missing: usize,
}

pub fn coverage() -> Coverage {
    Coverage {
        declared: ENTRIES.len(),
        literal_defaults: ENTRIES
            .iter()
            .filter(|entry| entry.default.is_some())
            .count(),
        unresolved_defaults: ENTRIES
            .iter()
            .filter(|entry| entry.default.is_none())
            .map(|entry| entry.name)
            .collect(),
        area_validators_required: ENTRIES
            .iter()
            .filter(|entry| entry.needs_area_validator())
            .map(|entry| entry.name)
            .collect(),
        help_metadata_missing: ENTRIES.len(),
        hidden_metadata_missing: ENTRIES.len(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultGap {
    pub key: &'static str,
    pub expression: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    UnknownOverride(String),
    DuplicateOverride(String),
    MissingProvenance(String),
    UnresolvedDefaults(Vec<DefaultGap>),
    OmittedKey(String),
    InvalidValue(crate::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOverride(key) => write!(f, "unknown catalogue default override {key}"),
            Self::DuplicateOverride(key) => {
                write!(f, "duplicate normalized default override {key}")
            }
            Self::MissingProvenance(key) => write!(f, "default override {key} requires provenance"),
            Self::UnresolvedDefaults(keys) => {
                write!(f, "{} configuration defaults remain unresolved", keys.len())
            }
            Self::OmittedKey(key) => write!(
                f,
                "option {key} has an unresolved default and was omitted from the partial registry"
            ),
            Self::InvalidValue(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {}

/// An explicitly supplied default resolution, with a spec/decision provenance
/// supplied by the caller. This is schema input, not a runtime source layer.
pub struct DefaultOverride<'a> {
    pub key: &'a str,
    pub value: &'a str,
    pub provenance: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedDefault {
    pub key: String,
    pub value: String,
    pub provenance: String,
}

#[derive(Clone, Debug)]
pub struct BuiltRegistry {
    pub registry: Registry,
    /// Explicit overrides retained for callers' schema audit records.
    pub default_overrides: Vec<AppliedDefault>,
}

/// Construct a 539-key typed schema only when every default is resolved.
/// Area validators, cross-key validation, hidden metadata and help generation
/// remain separate requirements; success is not a production-readiness claim.
pub fn complete_registry(overrides: &[DefaultOverride<'_>]) -> Result<BuiltRegistry, Error> {
    let mut supplied = BTreeMap::new();
    let mut applied = Vec::new();
    for value in overrides {
        let definition = get(value.key).ok_or_else(|| Error::UnknownOverride(value.key.into()))?;
        if value.provenance.trim().is_empty() {
            return Err(Error::MissingProvenance(definition.name.into()));
        }
        if supplied.insert(definition.name, value.value).is_some() {
            return Err(Error::DuplicateOverride(definition.name.into()));
        }
        applied.push(AppliedDefault {
            key: definition.name.into(),
            value: value.value.into(),
            provenance: value.provenance.into(),
        });
    }
    let gaps: Vec<_> = ENTRIES
        .iter()
        .filter(|entry| entry.default.is_none() && !supplied.contains_key(entry.name))
        .map(|entry| DefaultGap {
            key: entry.name,
            expression: entry.default_expression,
        })
        .collect();
    if !gaps.is_empty() {
        return Err(Error::UnresolvedDefaults(gaps));
    }
    let specs = ENTRIES.iter().map(|entry| {
        entry.spec(
            supplied
                .get(entry.name)
                .copied()
                .or(entry.default)
                .expect("all missing defaults checked"),
        )
    });
    let registry = Registry::new(specs).map_err(Error::InvalidValue)?;
    applied.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(BuiltRegistry {
        registry,
        default_overrides: applied,
    })
}

/// Explicitly incomplete schema for focused foundation tests and staged owners.
/// Input for any omitted known key is rejected, never treated as unknown.
pub struct PartialKnownDefaultsRegistry {
    registry: Registry,
    omitted: Vec<DefaultGap>,
}

impl PartialKnownDefaultsRegistry {
    pub fn omitted(&self) -> &[DefaultGap] {
        &self.omitted
    }

    pub fn resolve(&self, entries: impl IntoIterator<Item = Entry>) -> Result<Resolved, Error> {
        let entries: Vec<_> = entries.into_iter().collect();
        for entry in &entries {
            if let Some(definition) = get(&entry.key)
                && definition.default.is_none()
            {
                return Err(Error::OmittedKey(definition.name.into()));
            }
        }
        self.registry.resolve(entries).map_err(Error::InvalidValue)
    }
}

pub fn partial_known_defaults_registry() -> Result<PartialKnownDefaultsRegistry, Error> {
    let registry = Registry::new(
        ENTRIES
            .iter()
            .filter_map(|entry| entry.default.map(|default| entry.spec(default))),
    )
    .map_err(Error::InvalidValue)?;
    let omitted = ENTRIES
        .iter()
        .filter(|entry| entry.default.is_none())
        .map(|entry| DefaultGap {
            key: entry.name,
            expression: entry.default_expression,
        })
        .collect();
    Ok(PartialKnownDefaultsRegistry { registry, omitted })
}
