//! `cni-add-timing` (#396): warm CNI ADDs one after another, and where each one's
//! time goes, from the agent's `GET /v1/cni/timing`. The numbers are the result;
//! only an ADD that fails, or a trivial request that waits, fails the test. Nothing here may be compared with a
//! node's numbers unless the state directory is on a similar disk, so the detail
//! names its filesystem.
use crate::{
    env::Env,
    lab::{Endpoint, Lab},
    report::Report,
};
use flowsdn_api_client::Method;
use serde_json::Value;
use std::time::Duration;

/// ADDs measured, after [`WARMUP`] that are not.
const ADDS: usize = 30;
const WARMUP: usize = 3;
/// Above this a request is waiting for something, not working.
const CONFIG_LIMIT_US: u64 = 10_000;

fn filesystem() -> String {
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let dir = std::env::temp_dir();
    mounts
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace().skip(1);
            Some((words.next()?, words.next()?))
        })
        .filter(|(mount, _)| dir.starts_with(mount))
        .max_by_key(|(mount, _)| mount.len())
        .map_or_else(|| "unknown".to_owned(), |(_, kind)| kind.to_owned())
}

fn steps(value: &Value) -> String {
    let Some(rows) = value.as_object() else {
        return "no steps".into();
    };
    let mut rows: Vec<(&String, u64, u64)> = rows
        .iter()
        .map(|(step, row)| {
            let at = |key: &str| row.get(key).and_then(Value::as_u64).unwrap_or(0);
            (step, at("p50-us"), at("p99-us"))
        })
        .collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1));
    rows.iter()
        .map(|(step, p50, p99)| format!("{step} {p50}/{p99}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn run(report: &mut Report, env: &Env) {
    report.check("cni-add-timing", || {
        let lab = Lab::start(env, "timing")?;
        let mut endpoints = Vec::new();
        let mut walls: Vec<Duration> = Vec::new();
        for id in 1..=ADDS.saturating_add(WARMUP) {
            let mut endpoint = Endpoint::new(id)?;
            let wall = lab.add_timed(&mut endpoint)?;
            if id > WARMUP {
                walls.push(wall);
            }
            endpoints.push(endpoint);
        }
        walls.sort_unstable();
        let at = |percent: usize| {
            let last = walls.len().saturating_sub(1);
            let index = last.saturating_mul(percent).checked_div(100).unwrap_or(0);
            walls.get(index).copied().unwrap_or_default().as_micros()
        };
        let timing = lab
            .client()
            .request(Method::Get, "/v1/cni/timing", None)
            .map_err(|e| e.to_string())?;
        let timing = timing.json.unwrap_or_default();
        // A request that does nothing costs microseconds. A wait in the agent's
        // loop shows here: a 20 ms sleep made this 17 ms, four times per ADD.
        let config = timing
            .pointer("/config/p50-us")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let detail = format!(
            "{ADDS} warm ADDs, state on {}: wall p50 {} us, p99 {} us; steps p50/p99 us: {}",
            filesystem(),
            at(50),
            at(99),
            steps(&timing)
        );
        for endpoint in &endpoints {
            lab.del(endpoint)?;
        }
        if config >= CONFIG_LIMIT_US {
            return Err(format!(
                "a GET of the agent's config took {config} us at p50: {detail}"
            ));
        }
        Ok(((), detail))
    });
}
