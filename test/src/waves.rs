//! `long` (the night window): waves of flowsdn's main workload, pod sandboxes
//! coming and going, against one agent for the whole run. Each wave ramps to a
//! size taken from the pod's own CPUs and memory limit, exercises traffic,
//! restarts the agent under load every third wave, drains, and records what
//! the drained agent still holds. A wave slower than the first, or residue
//! that does not return to the first wave's, fails even when every operation
//! passed (docs/test-standard.md, "Overnight soaks: waves").
use crate::{
    env::Env,
    lab::{Endpoint, Lab, MAX_ENDPOINTS, Residue, exchange},
    report::{Report, emit, ms},
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    time::{Duration, Instant},
};

/// Memory one sandbox may cost: its worker, veth pair, map entries and the
/// agent's records for it.
const PER_ENDPOINT_BYTES: u64 = 16 << 20;
/// Leave this much of the budget for draining and reporting.
const MARGIN: Duration = Duration::from_secs(300);
/// Pairs whose traffic each wave checks, per family.
const TRAFFIC_PAIRS: usize = 32;

fn memory_limit() -> Option<u64> {
    let cgroup = fs::read_to_string("/sys/fs/cgroup/memory.max").ok();
    if let Some(limit) = cgroup.and_then(|s| s.trim().parse::<u64>().ok()) {
        return Some(limit);
    }
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    let kib: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    kib.checked_mul(1024)
}

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}

/// The largest wave this machine is given: 16 sandboxes per CPU, half the
/// memory it may use, the endpoint map's capacity and `STORM_WAVE_MAX`.
pub fn wave_max(cpus: usize, memory: Option<u64>, cap: Option<usize>) -> usize {
    let by_cpu = cpus.saturating_mul(16);
    let by_memory = memory.map_or(usize::MAX, |bytes| {
        usize::try_from(bytes / 2 / PER_ENDPOINT_BYTES).unwrap_or(usize::MAX)
    });
    by_cpu
        .min(by_memory)
        .min(cap.unwrap_or(usize::MAX))
        .clamp(4, MAX_ENDPOINTS)
}

/// Waves vary their size: full, half, three quarters, repeating.
pub fn wave_size(max: usize, wave: usize) -> usize {
    match wave % 3 {
        0 => max,
        1 => max / 2,
        _ => max.saturating_mul(3) / 4,
    }
    .max(2)
}

struct Wave {
    size: usize,
    add_mean_us: u64,
    add_max_us: u64,
    del_mean_us: u64,
    residue: Residue,
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn mean(samples: &[Duration]) -> u64 {
    let total = samples
        .iter()
        .fold(0u64, |s, d| s.saturating_add(micros(*d)));
    total
        .checked_div(u64::try_from(samples.len()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn one_wave(lab: &mut Lab, size: usize, restart: bool) -> Result<Wave, String> {
    let mut endpoints = Vec::with_capacity(size);
    let mut adds = Vec::with_capacity(size);
    for id in 1..=size {
        let mut endpoint = Endpoint::new(id)?;
        let start = Instant::now();
        lab.add(&mut endpoint)?;
        adds.push(start.elapsed());
        endpoints.push(endpoint);
    }
    let listed = lab.endpoints()?.len();
    if listed != size {
        return Err(format!("agent lists {listed} endpoints after {size} ADDs"));
    }
    if restart {
        lab.restart_agent()?;
        let listed = lab.endpoints()?.len();
        if listed != size {
            return Err(format!("agent restored {listed} of {size} endpoints"));
        }
    }
    let pairs = size.min(TRAFFIC_PAIRS);
    for i in 0..pairs {
        let j = i.saturating_add(1).checked_rem(size).unwrap_or(0);
        for v6 in [false, true] {
            let (a, b) = pair(&mut endpoints, i, j)?;
            exchange(a, b, v6)?;
        }
    }
    let mut dels = Vec::with_capacity(size);
    for endpoint in &endpoints {
        let start = Instant::now();
        lab.del(endpoint)?;
        dels.push(start.elapsed());
    }
    drop(endpoints);
    Ok(Wave {
        size,
        add_mean_us: mean(&adds),
        add_max_us: adds.iter().map(|d| micros(*d)).max().unwrap_or(0),
        del_mean_us: mean(&dels),
        residue: lab.residue()?,
    })
}

fn pair(
    endpoints: &mut [Endpoint],
    i: usize,
    j: usize,
) -> Result<(&mut Endpoint, &mut Endpoint), String> {
    if i == j {
        return Err("a pair needs two endpoints".into());
    }
    let (low, high) = (i.min(j), i.max(j));
    let (left, right) = endpoints.split_at_mut(high);
    let a = left.get_mut(low).ok_or("pair index")?;
    let b = right.first_mut().ok_or("pair index")?;
    Ok(if i < j { (a, b) } else { (b, a) })
}

/// A wave is slower than the first when its mean ADD exceeds twice the first
/// wave's plus 5 ms (the absolute floor keeps a fast first wave from making
/// scheduler noise a regression).
pub fn slower(first_us: u64, this_us: u64) -> bool {
    this_us > first_us.saturating_mul(2).saturating_add(5_000)
}

/// Agent memory that grew by half again plus 16 MiB over the first drained
/// wave is a leak; fds may vary by a few (logs, sockets in flight).
fn leaks(first: &Residue, this: &Residue) -> Vec<String> {
    let mut found: Vec<String> = first
        .objects()
        .iter()
        .zip(this.objects())
        .filter(|(f, t)| t.1 > f.1)
        .map(|(f, t)| format!("{} {} -> {}", f.0, f.1, t.1))
        .collect();
    if this.agent_fds > first.agent_fds.saturating_add(4) {
        found.push(format!(
            "agent_fds {} -> {}",
            first.agent_fds, this.agent_fds
        ));
    }
    if this.agent_rss_kib
        > first
            .agent_rss_kib
            .saturating_add(first.agent_rss_kib / 2)
            .saturating_add(16_384)
    {
        found.push(format!(
            "agent_rss_kib {} -> {}",
            first.agent_rss_kib, this.agent_rss_kib
        ));
    }
    found
}

pub fn run(report: &mut Report, env: &Env) {
    let started = Instant::now();
    let deadline = env
        .timeout
        .saturating_sub(MARGIN)
        .max(Duration::from_secs(60));
    let max = wave_max(cpus(), memory_limit(), env.wave_max);
    let Some(mut lab) = report.check("agent-start", || {
        Ok((
            Lab::start(env, "long")?,
            format!("wave max {max} sandboxes ({} CPUs)", cpus()),
        ))
    }) else {
        for test in ["waves", "wave-slowdown", "wave-residue"] {
            report.skip(test, "agent did not start");
        }
        return;
    };
    let trend_path = env.results.join("waves.jsonl");
    let mut trend = fs::File::create(&trend_path).ok();
    let mut waves: Vec<Wave> = Vec::new();
    let mut failure = None;
    let mut wave = 0usize;
    // Each wave must fit the time left: estimate from the slowest so far.
    let mut longest = Duration::ZERO;
    while started.elapsed().saturating_add(longest) < deadline {
        let size = wave_size(max, wave);
        let start = Instant::now();
        let result = one_wave(&mut lab, size, wave % 3 == 2);
        let took = start.elapsed();
        longest = longest.max(took);
        let number = wave.saturating_add(1);
        let test = format!("wave-{number}");
        match result {
            Ok(w) => {
                let line = json!({
                    "wave": number, "size": w.size, "ms": ms(took),
                    "add_mean_us": w.add_mean_us, "add_max_us": w.add_max_us,
                    "del_mean_us": w.del_mean_us, "residue": w.residue.json(),
                });
                if let Some(file) = trend.as_mut() {
                    let _ = writeln!(file, "{line}");
                }
                report.pass(&test, took, &line.to_string());
                waves.push(w);
            }
            Err(e) => {
                report.fail(&test, took, &e);
                failure = Some(number);
                break;
            }
        }
        wave = number;
    }
    emit(&json!({"trend": trend_path, "waves": waves.len()}));
    let Some(first) = waves.first() else {
        report.skip("wave-slowdown", "no wave completed");
        report.skip("wave-residue", "no wave completed");
        return;
    };
    if waves.len() < 2 {
        let why = failure.map_or("budget allowed one wave".to_string(), |n| {
            format!("wave {n} failed")
        });
        report.skip("wave-slowdown", &why);
        report.skip("wave-residue", &why);
        return;
    }
    let elapsed = started.elapsed();
    let first_slow = waves
        .iter()
        .position(|w| slower(first.add_mean_us, w.add_mean_us));
    match first_slow {
        None => report.pass(
            "wave-slowdown",
            elapsed,
            &format!(
                "{} waves; mean ADD stayed within 2x of wave 1 ({} us)",
                waves.len(),
                first.add_mean_us
            ),
        ),
        Some(i) => report.fail(
            "wave-slowdown",
            elapsed,
            &format!(
                "wave {} mean ADD {} us vs wave 1 {} us",
                i.saturating_add(1),
                waves.get(i).map_or(0, |w| w.add_mean_us),
                first.add_mean_us
            ),
        ),
    }
    let first_leak = waves.iter().enumerate().find_map(|(i, w)| {
        let found = leaks(&first.residue, &w.residue);
        (!found.is_empty()).then(|| (i.saturating_add(1), found))
    });
    match first_leak {
        None => report.pass(
            "wave-residue",
            elapsed,
            &format!(
                "every drained wave returned to wave 1's: {}",
                first.residue.json()
            ),
        ),
        Some((n, found)) => report.fail(
            "wave-residue",
            elapsed,
            &format!("wave {n}: {}", found.join(", ")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_max_follows_the_machine() {
        assert_eq!(wave_max(1, None, None), 16);
        assert_eq!(wave_max(64, None, None), MAX_ENDPOINTS);
        // 512 MiB: half of it at 16 MiB each.
        assert_eq!(wave_max(8, Some(512 << 20), None), 16);
        assert_eq!(wave_max(8, Some(1 << 20), None), 4);
        assert_eq!(wave_max(8, None, Some(10)), 10);
    }

    #[test]
    fn waves_vary_in_size() {
        assert_eq!([0, 1, 2, 3].map(|w| wave_size(100, w)), [100, 50, 75, 100]);
        assert_eq!(wave_size(4, 1), 2);
    }

    #[test]
    fn slowdown_needs_double_and_a_floor() {
        assert!(!slower(1_000, 6_999));
        assert!(slower(1_000, 7_001));
        assert!(slower(100_000, 205_001));
    }
}
