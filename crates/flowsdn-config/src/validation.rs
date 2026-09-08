//! Foundation checks over a caller's schema. Rules apply when their triggering
//! keys are present; an enabled feature with a missing dependency is rejected.
//! This is not a declaration of the complete agent configuration catalogue.

use crate::{Class, Resolved, Value};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub key: String,
    pub message: String,
}

impl Error {
    fn new(key: &str, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "--{}: {}", self.key, self.message)
    }
}

impl std::error::Error for Error {}

// Ignored/script options are parsed for compatibility diagnostics but cannot
// activate a feature or satisfy one of its runtime configuration dependencies.
fn effective<'a>(config: &'a Resolved, key: &str) -> Option<&'a Value> {
    config
        .get(key)
        .filter(|entry| matches!(entry.class, Class::Active | Class::Immutable))
        .map(|entry| &entry.value)
}

fn boolean(config: &Resolved, key: &str) -> Result<Option<bool>, Error> {
    match effective(config, key) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(Error::new(key, "expected a boolean in the schema")),
    }
}

fn text<'a>(config: &'a Resolved, key: &str) -> Result<Option<&'a str>, Error> {
    match effective(config, key) {
        None => Ok(None),
        Some(Value::String(value) | Value::Enum(value)) => Ok(Some(value)),
        Some(_) => Err(Error::new(key, "expected a string or enum in the schema")),
    }
}

fn integer(config: &Resolved, key: &str) -> Result<Option<i128>, Error> {
    match effective(config, key) {
        None => Ok(None),
        Some(Value::Int(value)) => Ok(Some(i128::from(*value))),
        Some(Value::UInt(value)) => Ok(Some(i128::from(*value))),
        Some(_) => Err(Error::new(key, "expected an integer in the schema")),
    }
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, Error> {
    value.ok_or_else(|| Error::new(key, "required dependency is missing from the schema"))
}

fn enum_value(config: &Resolved, key: &str, allowed: &[&str]) -> Result<(), Error> {
    if let Some(value) = text(config, key)?
        && !allowed.contains(&value)
    {
        return Err(Error::new(
            key,
            format!("expected one of {}", allowed.join(", ")),
        ));
    }
    Ok(())
}

/// Validate the foundation rules whose bounds are concrete in spec 00 and its
/// area references. Native-routing CIDR derivation and map-specific sizing
/// outside the policy map remain area responsibilities.
pub fn foundation(config: &Resolved) -> Result<(), Error> {
    enum_value(config, "routing-mode", &["tunnel", "native"])?;
    enum_value(config, "allow-localhost", &["auto", "always", "policy"])?;
    let ipv4 = boolean(config, "enable-ipv4")?;
    let ipv6 = boolean(config, "enable-ipv6")?;
    if ipv4.is_some() || ipv6.is_some() {
        let ipv4 = required(ipv4, "enable-ipv4")?;
        let ipv6 = required(ipv6, "enable-ipv6")?;
        if !ipv4 && !ipv6 {
            return Err(Error::new(
                "enable-ipv4",
                "at least one of --enable-ipv4 and --enable-ipv6 must be enabled",
            ));
        }
    }
    if boolean(config, "enable-ipv6-ndp")? == Some(true) {
        if !required(ipv6, "enable-ipv6")? {
            return Err(Error::new("enable-ipv6-ndp", "requires --enable-ipv6"));
        }
        if required(text(config, "ipv6-mcast-device")?, "ipv6-mcast-device")?
            .trim()
            .is_empty()
        {
            return Err(Error::new(
                "ipv6-mcast-device",
                "must be non-empty when --enable-ipv6-ndp is enabled",
            ));
        }
    }
    if let Some(metric) = integer(config, "route-metric")?
        && metric < 0
    {
        return Err(Error::new("route-metric", "must be non-negative"));
    }
    if let Some(value) = effective(config, "ipv6-cluster-alloc-cidr") {
        let valid = match value {
            Value::Cidr {
                address: IpAddr::V6(_),
                prefix: 64,
            } => true,
            Value::String(value) => matches!(
                crate::parse::parse(&crate::Kind::Cidr, value),
                Ok((
                    Value::Cidr {
                        address: IpAddr::V6(_),
                        prefix: 64
                    },
                    _
                ))
            ),
            _ => false,
        };
        if !valid {
            return Err(Error::new(
                "ipv6-cluster-alloc-cidr",
                "must be an IPv6 /64 prefix",
            ));
        }
    }
    if let Some(name) = text(config, "cluster-name")? {
        let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if name.is_empty()
            || name.len() > 32
            || !name.bytes().all(|byte| alnum(byte) || byte == b'-')
            || !name.bytes().next().is_some_and(alnum)
            || !name.bytes().next_back().is_some_and(alnum)
        {
            return Err(Error::new(
                "cluster-name",
                "must contain 1–32 lowercase ASCII letters, digits or hyphens, with alphanumeric ends",
            ));
        }
    }
    let maximum = integer(config, "max-connected-clusters")?;
    if maximum.is_some_and(|value| value != 255 && value != 511) {
        return Err(Error::new("max-connected-clusters", "must be 255 or 511"));
    }
    if let Some(cluster) = integer(config, "cluster-id")? {
        let maximum = required(maximum, "max-connected-clusters")?;
        if cluster < 0 || cluster > maximum {
            return Err(Error::new(
                "cluster-id",
                "must be between zero and --max-connected-clusters",
            ));
        }
    }
    if let Some(ratio) = effective(config, "bpf-map-dynamic-size-ratio") {
        match ratio {
            Value::Float(value) if value.is_finite() && *value > 0.0 && *value <= 1.0 => {}
            _ => {
                return Err(Error::new(
                    "bpf-map-dynamic-size-ratio",
                    "must be a float greater than zero and at most one",
                ));
            }
        }
    }
    map_sizes(
        config,
        &[MapBounds {
            key: "bpf-policy-map-max",
            minimum: 256,
            maximum: 65_536,
        }],
    )?;
    if text(config, "ipam")? == Some("delegated-plugin") {
        for key in ["enable-ipv4-masquerade", "enable-endpoint-health-checking"] {
            if required(boolean(config, key)?, key)? {
                return Err(Error::new(
                    key,
                    "must be disabled with --ipam=delegated-plugin",
                ));
            }
        }
        if !required(
            boolean(config, "enable-endpoint-routes")?,
            "enable-endpoint-routes",
        )? {
            return Err(Error::new(
                "enable-endpoint-routes",
                "must be enabled with --ipam=delegated-plugin",
            ));
        }
    }
    if boolean(config, "enable-vtep")? == Some(true) {
        let mask = required(text(config, "vtep-mask")?, "vtep-mask")?;
        if mask.parse::<Ipv4Addr>().is_err() {
            return Err(Error::new("vtep-mask", "must parse as an IPv4 mask"));
        }
    }
    // Spec 20 §3.6/§6.2 narrows the identity modes; double-write modes are not supported.
    enum_value(config, "identity-allocation-mode", &["crd", "kvstore"])?;
    if text(config, "identity-allocation-mode")? == Some("kvstore")
        && required(text(config, "kvstore")?, "kvstore")?
            .trim()
            .is_empty()
    {
        return Err(Error::new(
            "kvstore",
            "must be set with --identity-allocation-mode=kvstore",
        ));
    }
    Ok(())
}

/// Bounds from a map owner's ABI specification. Defaults and zero-as-auto
/// interpretation must be derived before calling this strict bounds check.
#[derive(Clone, Copy, Debug)]
pub struct MapBounds<'a> {
    pub key: &'a str,
    pub minimum: u64,
    pub maximum: u64,
}

pub fn map_sizes(config: &Resolved, bounds: &[MapBounds<'_>]) -> Result<(), Error> {
    for bounds in bounds {
        if bounds.minimum > bounds.maximum {
            return Err(Error::new(
                bounds.key,
                "invalid map bounds: minimum exceeds maximum",
            ));
        }
        if let Some(value) = integer(config, bounds.key)?
            && (value < i128::from(bounds.minimum) || value > i128::from(bounds.maximum))
        {
            return Err(Error::new(
                bounds.key,
                format!("must be within {}..={}", bounds.minimum, bounds.maximum),
            ));
        }
    }
    Ok(())
}
