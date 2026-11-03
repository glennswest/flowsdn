//! Request canonicalisation for replay matching (spec 07 §9.1: method, path
//! and canonicalized body). Query strings and form bodies compare as sorted,
//! percent-decoded pairs without the per-request signing parameters; JSON
//! bodies compare as values with sorted keys; anything else compares trimmed.
use crate::rules::SIGNING_PARAMS;

/// Parameters that differ on every request by design: signing parameters,
/// timestamps and idempotency tokens.
fn volatile(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    SIGNING_PARAMS.contains(&name.as_str())
        || matches!(name.as_str(), "timestamp" | "x-amz-date" | "clienttoken")
}

fn hex(b: u8) -> Option<u8> {
    char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decodes, with `+` as a space; an invalid escape stays literal.
pub fn decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let mut rest = s.as_bytes();
    while let Some((&b, tail)) = rest.split_first() {
        rest = tail;
        match b {
            b'+' => out.push(b' '),
            b'%' => match (
                tail.first().copied().and_then(hex),
                tail.get(1).copied().and_then(hex),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h.wrapping_shl(4) | l);
                    rest = tail.get(2..).unwrap_or_default();
                }
                _ => out.push(b'%'),
            },
            _ => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Sorted, decoded `k=v` pairs joined by `&`, without volatile parameters.
pub fn pairs(s: &str) -> String {
    let mut pairs: Vec<(String, String)> = s
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .filter(|(k, _)| !volatile(k))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The request target with its query canonicalised; an absolute-form target
/// (`http://host/path`) is reduced to its path.
pub fn target(target: &str) -> String {
    let origin = ["http://", "https://"]
        .iter()
        .find_map(|scheme| target.strip_prefix(scheme))
        .map_or(target, |rest| rest.find('/').and_then(|i| rest.get(i..)).unwrap_or("/"));
    match origin.split_once('?') {
        Some((path, query)) => {
            let q = pairs(query);
            if q.is_empty() {
                path.to_string()
            } else {
                format!("{path}?{q}")
            }
        }
        None => origin.to_string(),
    }
}

/// The body as it is compared.
pub fn body(content_type: Option<&str>, body: &str) -> String {
    let ct = content_type.unwrap_or_default().to_ascii_lowercase();
    let trimmed = body.trim();
    if ct.contains("x-www-form-urlencoded") {
        return pairs(trimmed);
    }
    if (ct.contains("json") || trimmed.starts_with('{') || trimmed.starts_with('['))
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed)
    {
        // serde_json's map is ordered by key (no preserve_order feature).
        return value.to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_order_encoding_and_signing_do_not_matter() {
        assert_eq!(
            target("/?b=2&a=x%20y&Signature=abc&Timestamp=2026"),
            target("/?a=x+y&b=2&Signature=def&Timestamp=2027")
        );
        assert_eq!(target("http://127.0.0.1:9/x?a=1"), "/x?a=1");
        assert_eq!(target("/x?Signature=a"), "/x");
        assert_ne!(target("/?a=1"), target("/?a=2"));
        assert_eq!(decode("100%"), "100%");
        assert_eq!(decode("%zz%41"), "%zzA");
    }

    #[test]
    fn bodies() {
        assert_eq!(
            body(Some("application/json"), r#"{"b":1,"a":{"d":2,"c":3}}"#),
            body(None, "  {\"a\": {\"c\": 3, \"d\": 2}, \"b\": 1}\n")
        );
        assert_eq!(
            body(
                Some("application/x-www-form-urlencoded; charset=utf-8"),
                "Version=2016-11-15&Action=CreateNetworkInterface&ClientToken=1"
            ),
            "Action=CreateNetworkInterface&Version=2016-11-15"
        );
        assert_eq!(body(None, " plain "), "plain");
        assert_eq!(body(Some("application/json"), "{not json"), "{not json");
    }
}
