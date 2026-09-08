use crate::{Kind, Value};
use std::collections::BTreeMap;

pub(super) fn parse(kind: &Kind, raw: &str) -> Result<(Value, bool), String> {
    let invalid = || format!("invalid {kind:?} value");
    let value = match kind {
        Kind::Bool => Value::Bool(match raw.to_ascii_lowercase().as_str() {
            "true" | "1" | "t" | "yes" | "on" => true,
            "false" | "0" | "f" | "no" | "off" => false,
            _ => return Err(invalid()),
        }),
        Kind::Int { bits } => {
            let number: i64 = raw.parse().map_err(|_| invalid())?;
            let valid = match bits {
                8 => i8::try_from(number).is_ok(),
                16 => i16::try_from(number).is_ok(),
                32 => i32::try_from(number).is_ok(),
                64 => true,
                _ => return Err("integer width must be 8, 16, 32 or 64".into()),
            };
            if !valid {
                return Err("integer out of range".into());
            }
            Value::Int(number)
        }
        Kind::UInt { bits } => {
            if !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let number: u64 = raw.parse().map_err(|_| invalid())?;
            let valid = match bits {
                8 => u8::try_from(number).is_ok(),
                16 => u16::try_from(number).is_ok(),
                32 => u32::try_from(number).is_ok(),
                64 => true,
                _ => return Err("integer width must be 8, 16, 32 or 64".into()),
            };
            if !valid {
                return Err("integer out of range".into());
            }
            Value::UInt(number)
        }
        Kind::Float { bits } => {
            let number = match bits {
                32 => f64::from(raw.parse::<f32>().map_err(|_| invalid())?),
                64 => raw.parse::<f64>().map_err(|_| invalid())?,
                _ => return Err("float width must be 32 or 64".into()),
            };
            if !number.is_finite() {
                return Err("float must be finite and in range".into());
            }
            Value::Float(number)
        }
        Kind::Duration => {
            let (nanos, bare) = duration(raw)?;
            return Ok((Value::Duration(nanos), bare));
        }
        Kind::String => Value::String(raw.into()),
        Kind::List => Value::List(if raw.contains(',') {
            raw.split(',').map(str::to_owned).collect()
        } else {
            raw.split_whitespace().map(str::to_owned).collect()
        }),
        Kind::Map => {
            let mut map = BTreeMap::new();
            if !raw.is_empty() {
                for item in raw.split(',') {
                    let (key, value) = item.split_once('=').ok_or_else(invalid)?;
                    if key.is_empty() {
                        return Err("map key is empty".into());
                    }
                    map.insert(key.into(), value.into());
                }
            }
            Value::Map(map)
        }
        Kind::Enum(values) => {
            if !values.iter().any(|v| v == raw) {
                return Err(format!("expected one of {}", values.join(", ")));
            }
            Value::Enum(raw.into())
        }
        Kind::Ip => Value::Ip(raw.parse().map_err(|_| invalid())?),
        Kind::Cidr => {
            let (address, prefix) = raw.split_once('/').ok_or_else(invalid)?;
            let address: std::net::IpAddr = address.parse().map_err(|_| invalid())?;
            if !prefix.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
            if prefix > if address.is_ipv4() { 32 } else { 128 } {
                return Err("CIDR prefix out of range".into());
            }
            Value::Cidr { address, prefix }
        }
        Kind::HostPort => {
            let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
                let (host, port) = rest.split_once("]:").ok_or_else(invalid)?;
                host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
                (host, port)
            } else {
                let (host, port) = raw.rsplit_once(':').ok_or_else(invalid)?;
                if host.contains([':', '[', ']']) {
                    return Err(invalid());
                }
                (host, port)
            };
            if host.is_empty()
                || host.chars().any(char::is_whitespace)
                || !port.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid());
            }
            Value::HostPort {
                host: host.into(),
                port: port.parse().map_err(|_| invalid())?,
            }
        }
    };
    Ok((value, false))
}

fn duration(raw: &str) -> Result<(i64, bool), String> {
    let invalid = || "invalid duration or duration out of range".to_owned();
    if let Ok(nanos) = raw.parse::<i64>() {
        return Ok((nanos, raw != "0"));
    }
    let (negative, body) = match raw.chars().next() {
        Some('-') => (true, raw.strip_prefix('-').ok_or_else(invalid)?),
        Some('+') => (false, raw.strip_prefix('+').ok_or_else(invalid)?),
        _ => (false, raw),
    };
    if body.is_empty() {
        return Err(invalid());
    }
    let mut chars = body.chars().peekable();
    let mut total = 0_u128;
    while chars.peek().is_some() {
        let mut integer = 0_u128;
        let mut has_digit = false;
        while let Some(digit) = chars.peek().copied().filter(char::is_ascii_digit) {
            chars.next();
            has_digit = true;
            integer = integer
                .checked_mul(10)
                .and_then(|n| n.checked_add(u128::from(digit.to_digit(10)?)))
                .ok_or_else(invalid)?;
        }
        let mut fraction = String::new();
        if chars.peek() == Some(&'.') {
            chars.next();
            while let Some(digit) = chars.peek().copied().filter(char::is_ascii_digit) {
                chars.next();
                has_digit = true;
                fraction.push(digit);
            }
        }
        if !has_digit {
            return Err(invalid());
        }
        let mut unit = String::new();
        while let Some(ch) = chars
            .peek()
            .copied()
            .filter(|ch| !ch.is_ascii_digit() && *ch != '.')
        {
            unit.push(ch);
            chars.next();
        }
        let multiplier: u128 = match unit.as_str() {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return Err(invalid()),
        };
        // Work backwards so arbitrarily long fractions cannot overflow an
        // integer denominator. Sub-nanosecond contributions truncate exactly.
        let mut fractional_nanos = 0_u128;
        for digit in fraction.chars().rev() {
            fractional_nanos = u128::from(digit.to_digit(10).ok_or_else(invalid)?)
                .checked_mul(multiplier)
                .and_then(|n| n.checked_add(fractional_nanos))
                .and_then(|n| n.checked_div(10))
                .ok_or_else(invalid)?;
        }
        total = integer
            .checked_mul(multiplier)
            .and_then(|n| n.checked_add(fractional_nanos))
            .and_then(|n| total.checked_add(n))
            .ok_or_else(invalid)?;
    }
    let magnitude = i128::try_from(total).map_err(|_| invalid())?;
    let signed = if negative {
        magnitude.checked_neg().ok_or_else(invalid)?
    } else {
        magnitude
    };
    Ok((i64::try_from(signed).map_err(|_| invalid())?, false))
}
