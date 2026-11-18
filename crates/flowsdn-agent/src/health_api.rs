//! Read-only health table adapter for the pinned StateDB query wire contract.
use super::*;
use flowsdn_health::{HealthStatus, Level, Registry};
use std::time::{SystemTime, UNIX_EPOCH};

/// What the health rows are made from, read from the agent's live state on
/// every health request (#418): nothing is reported that was not observed.
pub(super) struct Facts {
    /// Endpoints the API holds.
    pub endpoints: usize,
    /// The `kubernetes` member of `/v1/healthz` (state, msg), when the
    /// Kubernetes controller runs.
    pub kubernetes: Option<Value>,
    /// Why the policy maps could not be shared with the policy thread.
    pub policy_maps: Option<String>,
}
impl Facts {
    pub(super) fn of(api: &Api) -> Self {
        Self {
            endpoints: api.manager.records().count(),
            kubernetes: api
                .kubernetes
                .as_ref()
                .map(|view| crate::kubernetes::lock(view).health()),
            policy_maps: api.policy_maps_error.clone(),
        }
    }
    /// (scope under `agent`, level, message, error) for each row.
    fn rows(&self) -> Vec<(&'static str, Level, String, String)> {
        let mut rows = vec![
            (
                "api",
                Level::Ok,
                format!("endpoint API listening; {} endpoints", self.endpoints),
                String::new(),
            ),
            (
                "restore",
                Level::Ok,
                "endpoint restore and deletion replay completed".into(),
                String::new(),
            ),
        ];
        if let Some(kubernetes) = &self.kubernetes {
            let text = |key: &str| {
                kubernetes
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            rows.push(if text("state") == "Ok" {
                ("kubernetes", Level::Ok, text("msg"), String::new())
            } else {
                (
                    "kubernetes",
                    Level::Degraded,
                    "Kubernetes controller is not ready".into(),
                    text("msg"),
                )
            });
            if let Some(error) = &self.policy_maps {
                rows.push((
                    "policy",
                    Level::Degraded,
                    "policy maps unavailable, NetworkPolicy is not enforced".into(),
                    error.clone(),
                ));
            }
        }
        rows
    }
}

pub(super) struct ModuleHealth {
    registry: Registry,
    runtime: tokio::runtime::Runtime,
}
impl ModuleHealth {
    /// Empty until the first [`Self::refresh`]: unknown is absent, not OK.
    pub(super) fn new() -> Result<Self> {
        Ok(Self {
            registry: Registry::new(),
            runtime: tokio::runtime::Builder::new_current_thread().build()?,
        })
    }
    /// Bring the rows to `facts`. A row is written only when its level,
    /// message or error changed, so `Count` and `Updated` mean real changes;
    /// a scope no longer reported is removed.
    pub(super) fn refresh(&self, facts: &Facts) -> Result<()> {
        let root = self.registry.reporter("agent")?;
        let snapshot = self.registry.snapshot();
        let rows = facts.rows();
        self.runtime.block_on(async {
            for (scope, level, message, error) in &rows {
                let reporter = root.new_scope(scope)?;
                let current = snapshot.get("primary", reporter.id().as_bytes())?;
                if current.is_some_and(|(row, _)| {
                    row.level == *level && row.message == *message && row.error == *error
                }) {
                    continue;
                }
                match level {
                    Level::Degraded => reporter.degraded(message.clone(), error.clone()).await?,
                    _ => reporter.ok(message.clone()).await?,
                }
            }
            for (row, _) in snapshot.all() {
                let scope = row.id.strip_prefix("agent.").unwrap_or_default();
                if !rows.iter().any(|(name, ..)| *name == scope) {
                    root.new_scope(scope)?.close().await?;
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })?;
        Ok(())
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
fn timestamp(value: Option<SystemTime>) -> Result<String> {
    let Some(value) = value else {
        return Ok("0001-01-01T00:00:00Z".into());
    };
    let duration = value.duration_since(UNIX_EPOCH)?;
    if duration.as_secs() > crate::log::LAST_SECOND {
        return Err("health timestamp year is out of range".into());
    }
    let fraction = if duration.subsec_nanos() == 0 {
        String::new()
    } else {
        format!(".{:09}", duration.subsec_nanos())
            .trim_end_matches('0')
            .to_owned()
    };
    Ok(format!(
        "{}{fraction}Z",
        crate::log::civil(duration.as_secs())
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
        health
            .refresh(&Facts {
                endpoints: 2,
                kubernetes: Some(json!({"state":"Ok","msg":"1 nodes, 3 pods"})),
                policy_maps: None,
            })
            .expect("refresh");
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
    fn levels(health: &ModuleHealth) -> Vec<(String, String, String, String, u64)> {
        health
            .modules()
            .expect("modules")
            .as_array()
            .expect("array")
            .iter()
            .map(|row| {
                let text = |p: &str| row.pointer(p).and_then(Value::as_str).unwrap_or_default().to_owned();
                (
                    text("/ID/Component/0"),
                    text("/Level"),
                    text("/Message"),
                    text("/Error"),
                    row.get("Count").and_then(Value::as_u64).unwrap_or_default(),
                )
            })
            .collect()
    }
    #[test]
    fn rows_follow_the_live_state_and_change_only_when_it_does() {
        let health = ModuleHealth::new().expect("registry");
        assert!(levels(&health).is_empty(), "nothing before the first look");
        let alone = Facts {
            endpoints: 0,
            kubernetes: None,
            policy_maps: None,
        };
        health.refresh(&alone).expect("refresh");
        health.refresh(&alone).expect("same facts");
        let rows = levels(&health);
        assert_eq!(rows.len(), 2, "no Kubernetes row without the controller: {rows:?}");
        assert!(rows.iter().all(|r| r.1 == "OK" && r.4 == 1), "{rows:?}");
        let waiting = Facts {
            endpoints: 1,
            kubernetes: Some(json!({"state":"Warning","msg":"waiting for the initial Kubernetes lists"})),
            policy_maps: Some("map pin missing".into()),
        };
        health.refresh(&waiting).expect("refresh");
        let rows = levels(&health);
        assert_eq!(rows.len(), 4, "{rows:?}");
        let row = |name: &str| rows.iter().find(|r| r.0 == name).expect(name).clone();
        assert_eq!(row("api").2, "endpoint API listening; 1 endpoints");
        assert_eq!(row("api").4, 2);
        assert_eq!(row("restore").4, 1, "unchanged rows are not rewritten");
        assert_eq!(row("kubernetes").1, "Degraded");
        assert_eq!(row("kubernetes").3, "waiting for the initial Kubernetes lists");
        assert_eq!(row("policy").1, "Degraded");
        assert_eq!(row("policy").3, "map pin missing");
        health
            .refresh(&Facts {
                endpoints: 1,
                kubernetes: Some(json!({"state":"Ok","msg":"2 nodes, 5 pods"})),
                policy_maps: None,
            })
            .expect("refresh");
        let rows = levels(&health);
        assert_eq!(rows.len(), 3, "the policy row goes when its cause does: {rows:?}");
        let kubernetes = rows.iter().find(|r| r.0 == "kubernetes").expect("kubernetes");
        assert_eq!((kubernetes.1.as_str(), kubernetes.2.as_str(), kubernetes.3.as_str()), ("OK", "2 nodes, 5 pods", ""));
        assert!(
            rows.iter().all(|r| !r.2.contains("implement") && !r.3.contains("implement")),
            "{rows:?}"
        );
    }
}
