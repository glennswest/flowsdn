//! Validation of a defaulted CiliumGatewayClassConfig resource. Unknown fields
//! are left untouched; CRD admission remains responsible for the full schema.
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub path: String,
    pub message: String,
}
fn reject(errors: &mut Vec<Violation>, path: &str, message: &str) {
    errors.push(Violation {
        path: path.into(),
        message: message.into(),
    });
}
fn present(value: &Value, name: &str) -> bool {
    value.get(name).is_some_and(|v| !v.is_null())
}
/// Input is the full resource, after Kubernetes schema defaulting. Omitted
/// service.type/ipFamilyPolicy use LoadBalancer/SingleStack for validation.
pub fn validate(resource: &Value) -> Vec<Violation> {
    let mut errors = Vec::new();
    let Some(spec) = resource.get("spec").filter(|v| v.is_object()) else {
        reject(&mut errors, "spec", "must be an object");
        return errors;
    };
    if let Some(service) = spec.get("service").filter(|v| !v.is_null()) {
        if !service.is_object() {
            reject(&mut errors, "spec.service", "must be an object");
        } else {
            validate_service(service, &mut errors);
        }
    }
    if let Some(telemetry) = spec.get("telemetry").filter(|v| !v.is_null()) {
        if !telemetry.is_object() {
            reject(&mut errors, "spec.telemetry", "must be an object");
        } else if let Some(logs) = telemetry.get("accessLogs").filter(|v| !v.is_null()) {
            match logs.as_array() {
                Some(logs) => {
                    if !(1..=8).contains(&logs.len()) {
                        reject(
                            &mut errors,
                            "spec.telemetry.accessLogs",
                            "requires 1 through 8 entries",
                        );
                    }
                    for (index, log) in logs.iter().enumerate() {
                        validate_log(
                            log,
                            &format!("spec.telemetry.accessLogs[{index}]"),
                            &mut errors,
                        );
                    }
                }
                None => reject(&mut errors, "spec.telemetry.accessLogs", "must be an array"),
            }
        }
    }
    errors
}
fn validate_service(service: &Value, errors: &mut Vec<Violation>) {
    let service_type = if present(service, "type") {
        service.get("type").and_then(Value::as_str)
    } else {
        Some("LoadBalancer")
    };
    if !matches!(service_type, Some("LoadBalancer" | "NodePort")) {
        reject(
            errors,
            "spec.service.type",
            "must be LoadBalancer or NodePort",
        );
    }
    for field in [
        "loadBalancerClass",
        "loadBalancerSourceRanges",
        "allocateLoadBalancerNodePorts",
    ] {
        if present(service, field) && service_type != Some("LoadBalancer") {
            reject(
                errors,
                &format!("spec.service.{field}"),
                "requires service.type LoadBalancer",
            );
        }
    }
    if present(service, "loadBalancerClass")
        && !service
            .get("loadBalancerClass")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    {
        reject(
            errors,
            "spec.service.loadBalancerClass",
            "must be a nonempty string",
        );
    }
    if present(service, "allocateLoadBalancerNodePorts")
        && service
            .get("allocateLoadBalancerNodePorts")
            .and_then(Value::as_bool)
            .is_none()
    {
        reject(
            errors,
            "spec.service.allocateLoadBalancerNodePorts",
            "must be boolean",
        );
    }
    if let Some(ranges) = service
        .get("loadBalancerSourceRanges")
        .filter(|v| !v.is_null())
    {
        match ranges.as_array() {
            Some(ranges) => {
                for (index, range) in ranges.iter().enumerate() {
                    if !range.as_str().is_some_and(valid_cidr) {
                        reject(
                            errors,
                            &format!("spec.service.loadBalancerSourceRanges[{index}]"),
                            "must be an IPv4 or IPv6 CIDR",
                        );
                    }
                }
            }
            None => reject(
                errors,
                "spec.service.loadBalancerSourceRanges",
                "must be an array",
            ),
        }
    }
    let policy = if present(service, "ipFamilyPolicy") {
        service.get("ipFamilyPolicy").and_then(Value::as_str)
    } else {
        Some("SingleStack")
    };
    if !matches!(
        policy,
        Some("SingleStack" | "PreferDualStack" | "RequireDualStack")
    ) {
        reject(
            errors,
            "spec.service.ipFamilyPolicy",
            "must be SingleStack, PreferDualStack or RequireDualStack",
        );
    }
    if let Some(families) = service.get("ipFamilies").filter(|v| !v.is_null()) {
        match families.as_array() {
            Some(families) => {
                let mut seen = BTreeSet::new();
                for (index, family) in families.iter().enumerate() {
                    match family.as_str() {
                        Some("IPv4" | "IPv6") => {
                            if !seen.insert(family.as_str()) {
                                reject(
                                    errors,
                                    &format!("spec.service.ipFamilies[{index}]"),
                                    "duplicate address family",
                                );
                            }
                        }
                        _ => reject(
                            errors,
                            &format!("spec.service.ipFamilies[{index}]"),
                            "must be IPv4 or IPv6",
                        ),
                    }
                }
                // Empty/omitted families delegate allocation to the API server.
                // Dual-stack policies may specify only the primary family;
                // Kubernetes supplies the secondary family where supported.
                if families.len() > 2 || (policy == Some("SingleStack") && families.len() > 1) {
                    reject(
                        errors,
                        "spec.service.ipFamilies",
                        "address-family count conflicts with ipFamilyPolicy",
                    );
                }
            }
            None => reject(errors, "spec.service.ipFamilies", "must be an array"),
        }
    }
}
fn valid_cidr(value: &str) -> bool {
    let Some((address, bits)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    if bits.is_empty() || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    bits.parse::<u8>()
        .ok()
        .is_some_and(|bits| bits <= if address.is_ipv4() { 32 } else { 128 })
}
fn validate_log(log: &Value, path: &str, errors: &mut Vec<Violation>) {
    if !log.is_object() {
        reject(errors, path, "must be an object");
        return;
    }
    match log.get("format").and_then(Value::as_str) {
        Some("Text") => {
            if !log
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|s| (1..=4096).contains(&s.chars().count()))
            {
                reject(
                    errors,
                    &format!("{path}.text"),
                    "Text format requires text of 1 through 4096 characters",
                );
            }
        }
        Some("JSON") => {
            if !log
                .get("json")
                .and_then(Value::as_object)
                .is_some_and(|m| (1..=64).contains(&m.len()) && m.values().all(Value::is_string))
            {
                reject(
                    errors,
                    &format!("{path}.json"),
                    "JSON format requires a map of 1 through 64 string values",
                );
            }
        }
        _ => reject(errors, &format!("{path}.format"), "must be Text or JSON"),
    }
}
/// Condition projection for the caller's status writer. Caller owns transition
/// timestamps and resourceVersion-guarded publication; validation is read-only.
pub fn accepted_condition(resource: &Value, observed_generation: u64) -> Value {
    let valid = validate(resource).is_empty();
    json!({"type":"Accepted", "status":if valid {"True"} else {"False"},
        "reason":if valid {"Accepted"} else {"InvalidParameters"},
        "message":if valid {"Valid GatewayClassConfig"} else {"Invalid GatewayClassConfig"},
        "observedGeneration":observed_generation})
}
