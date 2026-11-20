//! `flowsdn-perf operator` (#446): is the flowsdn operator up on this
//! cluster? Read through the apiserver with the suite's declared cluster
//! reads (`test/requires.toml`): the Lease `kube-system/flowsdn-operator`
//! has a holder that renewed it within a few lease durations, and the
//! operator's CRD registration has made `flowsdnidentities.flowsdn.io`
//! Established. Prints one line; exit 0 when both hold. `flowsdn-test`'s
//! node probe runs it as `node-operator` on flowsdn-flavor nodes.
use crate::kube::Kube;
use http::Method;
use serde_json::Value;
use std::process::ExitCode;
use std::time::SystemTime;

pub const LEASE: &str = "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases/flowsdn-operator";
pub const CRD: &str =
    "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/flowsdnidentities.flowsdn.io";
/// The holder may be this many lease durations stale (clock skew between
/// the node and the operator's node, a renewal in flight).
const STALE_DURATIONS: f64 = 3.0;

/// Seconds since the Unix epoch of `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
pub fn unix_seconds(text: &str) -> Option<f64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date = date.split('-').map(|p| p.parse::<i64>().ok());
    let (year, month, day) = (date.next()??, date.next()??, date.next()??);
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = clock.split(':').map(|p| p.parse::<i64>().ok());
    let (hour, minute, second) = (clock.next()??, clock.next()??, clock.next()??);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm), checked arithmetic.
    let y = if month <= 2 { year.checked_sub(1)? } else { year };
    let era = y.div_euclid(400);
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let shifted = if month > 2 {
        month.checked_sub(3)?
    } else {
        month.checked_add(9)?
    };
    let doy = shifted
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(day)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    let days = era.checked_mul(146_097)?.checked_add(doe)?.checked_sub(719_468)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    let fraction = if fraction.is_empty() {
        0.0
    } else {
        format!("0.{fraction}").parse::<f64>().ok()?
    };
    Some(seconds as f64 + fraction)
}

/// The verdict on the Lease and CRD as read, at `now` (Unix seconds).
pub fn verdict(lease: (u16, &Value), crd: (u16, &Value), now: f64) -> Result<String, String> {
    let message = |v: &Value| {
        v.get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let lease = match lease {
        (200, body) => body,
        (404, _) => return Err("no Lease kube-system/flowsdn-operator: the operator never led".into()),
        (status, body) => return Err(format!("Lease: HTTP {status} {}", message(body))),
    };
    let spec = lease.get("spec").ok_or("Lease without spec")?;
    let holder = spec
        .get("holderIdentity")
        .and_then(Value::as_str)
        .filter(|h| !h.is_empty())
        .ok_or("Lease kube-system/flowsdn-operator has no holder")?;
    let duration = spec
        .get("leaseDurationSeconds")
        .and_then(Value::as_f64)
        .unwrap_or(30.0);
    let renewed = spec
        .get("renewTime")
        .and_then(Value::as_str)
        .and_then(unix_seconds)
        .ok_or("Lease kube-system/flowsdn-operator has no readable renewTime")?;
    let age = now - renewed;
    if age > duration * STALE_DURATIONS {
        return Err(format!(
            "Lease kube-system/flowsdn-operator held by {holder} but last renewed {age:.0}s ago (duration {duration:.0}s): the operator is not running"
        ));
    }
    let crd = match crd {
        (200, body) => body,
        (404, _) => return Err("flowsdnidentities.flowsdn.io is not registered".into()),
        (status, body) => return Err(format!("CRD: HTTP {status} {}", message(body))),
    };
    let established = crd
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|c| {
            c.get("type").and_then(Value::as_str) == Some("Established")
                && c.get("status").and_then(Value::as_str) == Some("True")
        });
    if !established {
        return Err("flowsdnidentities.flowsdn.io is not Established".into());
    }
    Ok(format!(
        "operator {holder} holds kube-system/flowsdn-operator (renewed {:.0}s ago); flowsdnidentities.flowsdn.io Established",
        age.max(0.0)
    ))
}

pub fn run() -> ExitCode {
    let result = (|| -> Result<String, String> {
        let kube = Kube::connect(String::new(), String::new())?;
        let (lease_status, lease) = kube.call(Method::GET, LEASE, None)?;
        let (crd_status, crd) = kube.call(Method::GET, CRD, None)?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs_f64();
        verdict((lease_status, &lease), (crd_status, &crd), now)
    })();
    match result {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("{error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_micro_time() {
        assert_eq!(unix_seconds("1970-01-01T00:00:01.500000Z"), Some(1.5));
        assert_eq!(unix_seconds("2026-11-20T10:00:00Z"), Some(1_795_168_800.0));
        assert_eq!(unix_seconds("2000-03-01T00:00:00Z"), Some(951_868_800.0));
        assert_eq!(unix_seconds("2026-13-01T00:00:00Z"), None);
        assert_eq!(unix_seconds("2026-11-20 10:00:00"), None);
    }

    fn lease(renew: &str) -> Value {
        json!({"spec": {"holderIdentity": "flowsdn-operator-abc", "renewTime": renew,
                        "leaseDurationSeconds": 30}})
    }
    fn crd(status: &str) -> Value {
        json!({"status": {"conditions": [{"type": "Established", "status": status}]}})
    }

    #[test]
    fn a_fresh_holder_and_an_established_crd_pass() {
        let now = 1_795_168_810.0;
        let line = verdict(
            (200, &lease("2026-11-20T10:00:00.000000Z")),
            (200, &crd("True")),
            now,
        )
        .expect("up");
        assert!(line.contains("flowsdn-operator-abc"), "{line}");
        assert!(line.contains("renewed 10s ago"), "{line}");
    }

    #[test]
    fn a_stale_absent_or_unregistered_operator_fails() {
        let now = 1_795_168_800.0 + 91.0;
        let stale = verdict((200, &lease("2026-11-20T10:00:00Z")), (200, &crd("True")), now);
        assert!(stale.expect_err("stale").contains("not running"));
        let none = verdict((404, &Value::Null), (200, &crd("True")), now);
        assert!(none.expect_err("absent").contains("never led"));
        let empty = json!({"spec": {"holderIdentity": ""}});
        assert!(verdict((200, &empty), (200, &crd("True")), now).is_err());
        let fresh = lease("2026-11-20T10:01:00Z");
        let missing = verdict((200, &fresh), (404, &Value::Null), now);
        assert!(missing.expect_err("crd").contains("not registered"));
        let pending = verdict((200, &fresh), (200, &crd("False")), now);
        assert!(pending.expect_err("crd").contains("not Established"));
        let forbidden = verdict((403, &json!({"message": "no"})), (200, &crd("True")), now);
        assert!(forbidden.expect_err("rbac").contains("HTTP 403 no"));
    }
}
