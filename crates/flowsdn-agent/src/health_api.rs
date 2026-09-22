//! Read-only health table adapter for the pinned StateDB query wire contract.
use super::*;
use flowsdn_health::{HealthStatus, Level, Registry};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct ModuleHealth {
    registry: Registry,
    runtime: tokio::runtime::Runtime,
}
impl ModuleHealth {
    pub(super) fn new() -> Result<Self> {
        let value = Self {
            registry: Registry::new(),
            runtime: tokio::runtime::Builder::new_current_thread().build()?,
        };
        value.runtime.block_on(async {
            let root = value.registry.reporter("agent")?;
            root.new_scope("api")?
                .ok("initial endpoint API listening")
                .await?;
            root.new_scope("restore")?
                .ok("endpoint restore and deletion replay completed")
                .await?;
            root.new_scope("controllers")?
                .degraded(
                    "Kubernetes, identity and policy controllers are not enabled",
                    "not implemented",
                )
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })?;
        Ok(value)
    }
    pub(super) fn query(&self, request: &Value) -> Result<Vec<u8>> {
        if !request.is_object() {
            return fail(400, "query requires a JSON object");
        }
        if string(request, "table")? != "health" {
            return fail(404, "only the health table is exposed");
        }
        if string(request, "index")? != "id" {
            return fail(400, "health query index must be id");
        }
        let encoded = request
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure {
                status: 400,
                message: "key must be a base64 string".into(),
            })?;
        let key = decode_key(encoded)?;
        let lower = request
            .get("lowerbound")
            .and_then(Value::as_bool)
            .ok_or_else(|| Failure {
                status: 400,
                message: "lowerbound must be boolean".into(),
            })?;
        let snapshot = self.registry.snapshot();
        let rows = if lower {
            snapshot.lower_bound("primary", &key)?
        } else {
            snapshot.list("primary", &key)?
        };
        let mut bytes = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut bytes, &json!({"rev":row.1,"obj":wire_status(&row.0)?}))?;
            bytes.push(b'\n');
            if bytes.len() > BODY_LIMIT {
                return fail(413, "health query response exceeds limit");
            }
        }
        Ok(bytes)
    }
    pub(super) fn modules(&self) -> Result<Value> {
        self.registry
            .snapshot()
            .all()
            .map(|row| wire_status(&row.0))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array)
    }
}
fn wire_status(status: &HealthStatus) -> Result<Value> {
    let mut parts = status.id.split('.');
    let module = parts.next().ok_or("empty health ID")?;
    let components: Vec<_> = parts.collect();
    Ok(json!({"ID":{"Module":[module],"Component":components},
        "Level":match status.level {Level::Ok=>"OK",Level::Degraded=>"Degraded",Level::Stopped=>"Stopped"},
        "Message":status.message,"Error":status.error,"LastOK":timestamp(status.last_ok)?,
        "Updated":timestamp(Some(status.updated))?,"Stopped":timestamp(status.stopped)?,
        "Final":status.final_message,"Count":status.count}))
}
#[allow(unsafe_code)]
fn timestamp(value: Option<SystemTime>) -> Result<String> {
    let Some(value) = value else {
        return Ok("0001-01-01T00:00:00Z".into());
    };
    let duration = value.duration_since(UNIX_EPOCH)?;
    let seconds: nix::libc::time_t = duration.as_secs().try_into()?;
    let mut utc = std::mem::MaybeUninit::<nix::libc::tm>::uninit();
    // SAFETY: both pointers are valid for their types; gmtime_r initializes
    // the complete tm on success, which is checked before assume_init.
    if unsafe { nix::libc::gmtime_r(&seconds, utc.as_mut_ptr()) }.is_null() {
        return Err("health timestamp is out of range".into());
    }
    let utc = unsafe { utc.assume_init() };
    let year = utc.tm_year.checked_add(1900).ok_or("year overflow")?;
    if !(1..=9999).contains(&year) {
        return Err("health timestamp year is out of range".into());
    }
    let month = utc.tm_mon.checked_add(1).ok_or("month overflow")?;
    let fraction = if duration.subsec_nanos() == 0 {
        String::new()
    } else {
        format!(".{:09}", duration.subsec_nanos())
            .trim_end_matches('0')
            .to_owned()
    };
    Ok(format!(
        "{year:04}-{month:02}-{:02}T{:02}:{:02}:{:02}{fraction}Z",
        utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec
    ))
}
fn decode_key(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len() > 1024 || !encoded.len().is_multiple_of(4) {
        return fail(400, "invalid base64 query key");
    }
    let digit = |byte: u8| -> Result<u8> {
        match byte {
            b'A'..=b'Z' => Ok(byte.saturating_sub(b'A')),
            b'a'..=b'z' => Ok(byte.saturating_sub(b'a').saturating_add(26)),
            b'0'..=b'9' => Ok(byte.saturating_sub(b'0').saturating_add(52)),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => fail(400, "invalid base64 query key"),
        }
    };
    let mut decoded = Vec::new();
    let mut padded = false;
    for chunk in encoded.as_bytes().chunks_exact(4) {
        if padded {
            return fail(400, "base64 padding must be final");
        }
        let [a, b, c, d]: [u8; 4] = chunk.try_into()?;
        let (a, b) = (digit(a)?, digit(b)?);
        decoded.push((a << 2) | (b >> 4));
        if c == b'=' {
            if d != b'=' || b & 15 != 0 {
                return fail(400, "invalid base64 padding");
            }
            padded = true;
            continue;
        }
        let c = digit(c)?;
        decoded.push((b << 4) | (c >> 2));
        if d == b'=' {
            if c & 3 != 0 {
                return fail(400, "invalid base64 padding");
            }
            padded = true;
            continue;
        }
        decoded.push((c << 6) | digit(d)?);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn state_db_query_is_ordered_ndjson_with_reference_identifier_and_time_shapes() {
        let health = ModuleHealth::new().expect("registry");
        let body = health
            .query(&json!({"table":"health","index":"id","key":"YWdlbnQ=","lowerbound":true}))
            .expect("query");
        let rows: Vec<Value> = String::from_utf8(body)
            .expect("UTF8")
            .lines()
            .map(|s| serde_json::from_str(s).expect("row"))
            .collect();
        assert_eq!(rows.len(), 3);
        let first = rows.first().expect("first");
        assert_eq!(first.pointer("/obj/ID/Module"), Some(&json!(["agent"])));
        assert_eq!(first.pointer("/obj/ID/Component"), Some(&json!(["api"])));
        assert_eq!(
            first.pointer("/obj/Stopped"),
            Some(&json!("0001-01-01T00:00:00Z"))
        );
        assert!(
            first
                .get("rev")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0)
        );
        assert!(
            first
                .pointer("/obj/Updated")
                .and_then(Value::as_str)
                .is_some_and(|s| s.ends_with('Z') && s.contains('T'))
        );
        assert!(
            health
                .query(&json!({"table":"health","index":"id","key":"YWdlbnQ=","lowerbound":false}))
                .expect("exact absent")
                .is_empty()
        );
        assert!(
            !health
                .query(&json!({"table":"health","index":"id","key":"","lowerbound":true}))
                .expect("empty lower bound")
                .is_empty()
        );
        assert_eq!(
            health
                .modules()
                .expect("modules")
                .as_array()
                .expect("array")
                .len(),
            3
        );
    }
    #[test]
    fn health_queries_validate_scope_and_base64_before_reading_rows() {
        let health = ModuleHealth::new().expect("registry");
        for (body, expected) in [
            (
                json!({"table":"secrets","index":"id","key":"","lowerbound":true}),
                404,
            ),
            (
                json!({"table":"health","index":"revision","key":"","lowerbound":true}),
                400,
            ),
            (
                json!({"table":"health","index":"id","key":"YWdlbnQ=","lowerbound":"yes"}),
                400,
            ),
        ] {
            let error = health.query(&body).expect_err("reject");
            assert_eq!(
                error.downcast_ref::<Failure>().expect("HTTP").status,
                expected
            );
        }
        for key in [
            "a", "====", "YQ=A", "YQ==AAAA", "YR==", "YWdlbnQ", "YWdlbnR=",
        ] {
            assert!(decode_key(key).is_err(), "{key}");
        }
        assert_eq!(decode_key("YQ==").expect("a"), b"a");
        assert_eq!(decode_key("YWc=").expect("ag"), b"ag");
        assert_eq!(decode_key("YWdl").expect("age"), b"age");
        assert_eq!(
            timestamp(Some(UNIX_EPOCH)).expect("epoch"),
            "1970-01-01T00:00:00Z"
        );
    }
}
