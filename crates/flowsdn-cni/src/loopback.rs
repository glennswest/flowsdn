//! Rust loopback entry point shared by the primary CNI executable (spec 09).
use crate::{CniError, Result};
use flowsdn_connector::{Connector, in_namespace};
use serde_json::{Value, json};
use std::{collections::BTreeMap, ffi::OsStr, fs::File, path::Path};

fn is_loopback(name: &str) -> bool {
    matches!(name, "loopback" | "flowsdn-loopback")
}

/// Invocation aliases and configuration type both select the loopback adapter.
pub fn dispatch(
    executable: &OsStr,
    command: &str,
    input: &[u8],
    env: &BTreeMap<String, String>,
) -> Result<Option<Value>> {
    let name = Path::new(executable)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("");
    let conf: Value = serde_json::from_slice(input).unwrap_or_default();
    if is_loopback(name)
        || conf.get("type").and_then(Value::as_str).is_some_and(is_loopback)
    {
        run(command, input, env)
    } else {
        crate::runtime::run(command, input, env)
    }
}

fn validate_previous(value: &Value, version: &str) -> Result<()> {
    let invalid = || CniError::internal("invalid prevResult: expected a compatible CNI result");
    if !value.is_object() || value.get("cniVersion").and_then(Value::as_str) != Some(version) {
        return Err(invalid());
    }
    for field in ["interfaces", "ips", "routes"] {
        if value.get(field).is_some_and(|v| !v.is_array()) {
            return Err(invalid());
        }
    }
    let interfaces = value.get("interfaces").and_then(Value::as_array);
    for interface in interfaces.into_iter().flatten() {
        if !interface.is_object()
            || interface.get("name").and_then(Value::as_str).is_none_or(str::is_empty)
            || ["mac", "sandbox"].iter().any(|key| interface.get(key).is_some_and(|v| !v.is_string()))
        {
            return Err(invalid());
        }
    }
    let cidr = |v: &Value| -> Option<std::net::IpAddr> {
        let (address, prefix) = v.as_str()?.split_once('/')?;
        let ip: std::net::IpAddr = address.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        (prefix <= if ip.is_ipv4() { 32 } else { 128 }).then_some(ip)
    };
    for (field, address_key, gateway_key) in [("ips", "address", "gateway"), ("routes", "dst", "gw")] {
        for entry in value.get(field).and_then(Value::as_array).into_iter().flatten() {
            let address = entry.get(address_key).and_then(cidr).ok_or_else(invalid)?;
            if let Some(gateway) = entry.get(gateway_key) {
                let gateway = gateway.as_str().and_then(|s| s.parse::<std::net::IpAddr>().ok()).ok_or_else(invalid)?;
                if gateway.is_ipv4() != address.is_ipv4() {
                    return Err(invalid());
                }
            }
            if field == "ips" {
                if let Some(index) = entry.get("interface").filter(|v| !v.is_null()) {
                    let index = index.as_u64().and_then(|i| usize::try_from(i).ok()).ok_or_else(invalid)?;
                    if index >= interfaces.map_or(0, Vec::len) {
                        return Err(invalid());
                    }
                }
            } else {
                for key in ["mtu", "advmss", "priority", "table", "scope"] {
                    if entry.get(key).is_some_and(|v| v.as_u64().is_none_or(|n| n > u64::from(u32::MAX))) {
                        return Err(invalid());
                    }
                }
            }
        }
    }
    if let Some(dns) = value.get("dns") {
        if !dns.is_object() || dns.get("domain").is_some_and(|v| !v.is_string()) {
            return Err(invalid());
        }
        for key in ["nameservers", "search", "options"] {
            if let Some(items) = dns.get(key) {
                let items = items.as_array().ok_or_else(invalid)?;
                if items.iter().any(|v| !v.is_string()) {
                    return Err(invalid());
                }
            }
        }
    }
    Ok(())
}

pub fn run(command: &str, input: &[u8], env: &BTreeMap<String, String>) -> Result<Option<Value>> {
    if command == "VERSION" {
        return Ok(Some(json!({
            "cniVersion": "1.1.0", "supportedVersions": ["1.0.0", "1.1.0"]
        })));
    }
    let conf: Value = serde_json::from_slice(input).map_err(|e| CniError {
        code: 6,
        message: "invalid loopback configuration".into(),
        details: e.to_string(),
    })?;
    let version = conf.get("cniVersion").and_then(Value::as_str).unwrap_or("");
    if !matches!(version, "1.0.0" | "1.1.0") {
        return Err(CniError {
            code: 1,
            message: "unsupported CNI version".into(),
            details: String::new(),
        });
    }
    match command {
        "STATUS" => Ok(None),
        "DEL" => {
            let Some(path) = env.get("CNI_NETNS").filter(|s| !s.is_empty()) else {
                return Ok(None);
            };
            let namespace = match File::open(path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(CniError::internal(e.to_string())),
            };
            in_namespace(namespace, move || Connector::open()?.loopback(Some(false)))
                .map_err(|e| CniError::internal(e.to_string()))?;
            Ok(None)
        }
        "ADD" | "CHECK" => {
            for key in ["CNI_CONTAINERID", "CNI_NETNS", "CNI_IFNAME", "CNI_PATH"] {
                if env.get(key).is_none_or(String::is_empty) {
                    return Err(CniError::internal(format!("missing {key}")));
                }
            }
            if conf.get("name").and_then(Value::as_str).is_none_or(str::is_empty) {
                return Err(CniError::internal("missing network name"));
            }
            let previous = conf.get("prevResult").filter(|v| !v.is_null());
            if let Some(previous) = previous {
                validate_previous(previous, version)?;
            }
            let namespace = File::open(&env["CNI_NETNS"])
                .map_err(|e| CniError::internal(e.to_string()))?;
            let bring_up = command == "ADD";
            let addresses = in_namespace(namespace, move || {
                Connector::open()?.loopback(if bring_up { Some(true) } else { None })
            }).map_err(|e| CniError::internal(e.to_string()))?;
            if bring_up {
                if let Some(previous) = previous {
                    return Ok(Some(previous.clone()));
                }
                let mut ips = Vec::new();
                for ipv4 in [true, false] {
                    if let Some((ip, prefix)) = addresses.iter().find(|(ip, _)| ip.is_ipv4() == ipv4) {
                        ips.push(json!({"address": format!("{ip}/{prefix}"), "interface": 0}));
                    }
                }
                Ok(Some(json!({
                    "cniVersion": version,
                    "interfaces": [{"name": "lo", "sandbox": env["CNI_NETNS"]}],
                    "ips": ips
                })))
            } else {
                Ok(None)
            }
        }
        _ => Err(CniError {
            code: 4,
            message: "unsupported loopback command".into(),
            details: command.into(),
        }),
    }
}
