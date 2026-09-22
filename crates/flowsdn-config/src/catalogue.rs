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

/// flowsdn-only keys, deliberately excluded from reference catalogue coverage.
pub const EXTENSIONS: &[Definition] = &[
    Definition {
        name: "egress-gateway-selection",
        pflag: Pflag::String,
        default_expression: "modulo",
        default: Some("modulo"),
        class: Class::Immutable,
        inventory_name: None,
    },
    Definition {
        name: "egress-gateway-legacy-map",
        pflag: Pflag::Bool,
        default_expression: "false",
        default: Some("false"),
        class: Class::Immutable,
        inventory_name: None,
    },
    Definition {
        name: "bgp-strict-update-errors",
        pflag: Pflag::Bool,
        default_expression: "false",
        default: Some("false"),
        class: Class::Immutable,
        inventory_name: None,
    },
    Definition {
        name: "bgp-status-report-prefixes",
        pflag: Pflag::Bool,
        default_expression: "false",
        default: Some("false"),
        class: Class::Active,
        inventory_name: None,
    },
    Definition {
        name: "force-config-change",
        pflag: Pflag::Bool,
        default_expression: "false",
        default: Some("false"),
        class: Class::Active,
        inventory_name: None,
    },
    Definition {
        name: "bpf-ipcache-map-max",
        pflag: Pflag::Uint,
        default_expression: "512000",
        default: Some("512000"),
        class: Class::Immutable,
        inventory_name: None,
    },
    Definition {
        name: "strict-config",
        pflag: Pflag::Bool,
        default_expression: "false",
        default: Some("false"),
        class: Class::Active,
        inventory_name: None,
    },
    Definition {
        name: "endpoint-id-max",
        pflag: Pflag::Uint,
        default_expression: "4095",
        default: Some("4095"),
        class: Class::Active,
        inventory_name: None,
    },
];

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
            "strict-config"
            | "endpoint-id-max"
            | "force-config-change"
            | "bpf-ipcache-map-max"
            | "egress-gateway-selection"
            | "egress-gateway-legacy-map"
            | "bgp-strict-update-errors"
            | "bgp-status-report-prefixes" => {
                "docs/spec/00-foundation-table-config.md#flowsdn-extension-keys"
            }
            "envoy-access-log-buffer-size" => "docs/spec/16-l7-envoy-dns.md:1500",
            "identity-allocation-mode" => "docs/spec/20-clustermesh-kvstore.md:1575",
            "agent-not-ready-taint-key" => "docs/spec/12-operator.md:1434",
            "bpf-lb-algorithm" => "docs/spec/05-service-loadbalancing.md:943",
            "bpf-lb-dsr-dispatch" => "docs/spec/05-service-loadbalancing.md:942",
            "bpf-lb-maglev-hash-seed" => "docs/spec/05-service-loadbalancing.md:946",
            "bpf-lb-maglev-table-size" => "docs/spec/05-service-loadbalancing.md:945",
            "bpf-lb-map-max" => "docs/spec/05-service-loadbalancing.md:934",
            "bpf-lb-mode" => "docs/spec/05-service-loadbalancing.md:940",
            "bpf-map-event-buffers" => "docs/spec/03-identity-ipcache.md:965",
            "bpf-nat-global-max" => "docs/spec/04-conntrack-nat.md:807",
            "bpf-neigh-global-max" => "docs/spec/01-bpf-map-abi-loader.md:1064",
            "bpf-node-map-max" => "docs/spec/14-encryption-egress.md:1749",
            "clustermesh-service-v2" => "docs/spec/20-clustermesh-kvstore.md:1574",
            "enable-bandwidth-manager" => "docs/spec/10-node-routing-nftables.md:1382",
            "enable-bbr" => "docs/spec/10-node-routing-nftables.md:1383",
            "enable-bbr-hostns-only" => "docs/spec/10-node-routing-nftables.md:1383",
            "enable-dynamic-source-lookup-nodeport" => "docs/spec/05-service-loadbalancing.md:957",
            "enable-node-ipam" => "docs/spec/12-operator.md:1471",
            "fixed-identity-mapping" => "docs/spec/03-identity-ipcache.md:950",
            "gateway-api-secrets-namespace" => "docs/spec/21-gateway-api-ingress.md:1736",
            "hubble-drop-events-reasons" => "docs/spec/11-hubble-monitor.md:2548",
            "hubble-event-buffer-capacity" => "docs/spec/11-hubble-monitor.md:2499",
            "hubble-lost-event-send-interval" => "docs/spec/11-hubble-monitor.md:2502",
            "hubble-socket-path" => "docs/spec/11-hubble-monitor.md:2497",
            "hubble-tls-cert-file" => "docs/spec/11-hubble-monitor.md:2505",
            "hubble-tls-client-ca-files" => "docs/spec/11-hubble-monitor.md:2507",
            "hubble-tls-key-file" => "docs/spec/11-hubble-monitor.md:2506",
            "ingress-secrets-namespace" => "docs/spec/21-gateway-api-ingress.md:1753",
            "ipam-multi-pool-pre-allocation" => "docs/spec/07-ipam.md:1265",
            "kvstore" => "docs/spec/20-clustermesh-kvstore.md:1533",
            "node-port-range" => "docs/spec/05-service-loadbalancing.md:936",
            "policy-secrets-namespace" => "docs/spec/12-operator.md:1468",
            "policy-secrets-only-from-secrets-namespace" => "docs/spec/16-l7-envoy-dns.md:1523",
            "socket-path" => "docs/spec/08-endpoint-agent-api.md:1338",
            _ => SPECIFICATION,
        })
    }
    /// The table does not supply help text or hidden-flag metadata.
    pub fn help(self) -> Option<&'static str> {
        match self.name {
            "egress-gateway-selection" => {
                Some("Gateway selection: modulo or homogeneous-cluster rendezvous")
            }
            "egress-gateway-legacy-map" => {
                Some("Plan legacy IPv4 egress map mirroring during migration")
            }
            "bgp-strict-update-errors" => Some("Reset the BGP session on malformed UPDATE content"),
            "bgp-status-report-prefixes" => {
                Some("Report acknowledged advertised BGP prefixes in status")
            }
            "force-config-change" => {
                Some("Allow immutable configuration changes during endpoint restoration")
            }
            "bpf-ipcache-map-max" => Some("Maximum ipcache map entries (1 through 4294967295)"),
            "strict-config" => {
                Some("Reject unknown configuration keys after resolving source precedence")
            }
            "endpoint-id-max" => Some("Maximum newly allocated endpoint ID (1 through 65535)"),
            _ => None,
        }
    }
    pub fn hidden(self) -> Option<bool> {
        matches!(
            self.name,
            "strict-config"
                | "endpoint-id-max"
                | "force-config-change"
                | "bpf-ipcache-map-max"
                | "egress-gateway-selection"
                | "egress-gateway-legacy-map"
                | "bgp-strict-update-errors"
                | "bgp-status-report-prefixes"
        )
        .then_some(false)
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
    ENTRIES
        .iter()
        .chain(EXTENSIONS)
        .find(|entry| entry.name == canonical)
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

/// Construct the 539 reference keys plus flowsdn extensions only when every
/// default is resolved.
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
    let specs = ENTRIES.iter().chain(EXTENSIONS).map(|entry| {
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
            .chain(EXTENSIONS)
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
