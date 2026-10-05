//! What the suite reads from the node through the host PID namespace
//! (`host_pid` in requires.toml): which CNI agent runs (the flavor), its CPU
//! and memory, and the host network namespace's netfilter conntrack count.
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

/// Agent process names (`comm`, at most 15 bytes) and the flavor each means.
const AGENTS: [(&str, &str); 2] = [("flowsdn-agent", "flowsdn"), ("cilium-agent", "cilium")];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Agent {
    pub pid: u32,
    pub flavor: &'static str,
}

/// The CNI agent among `/proc`'s processes, the first by PID.
pub fn find_agent(proc_root: &Path) -> Option<Agent> {
    let mut found: Vec<Agent> = Vec::new();
    for entry in fs::read_dir(proc_root).ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if let Some((_, flavor)) = AGENTS.iter().find(|(name, _)| *name == comm.trim()) {
            found.push(Agent { pid, flavor });
        }
    }
    found.into_iter().min_by_key(|a| a.pid)
}

/// utime + stime in clock ticks, from `/proc/<pid>/stat` (fields 14 and 15,
/// counted after the parenthesised command, which may contain spaces).
pub fn cpu_ticks(stat: &str) -> Option<u64> {
    let rest = stat.get(stat.rfind(')')?.checked_add(2)?..)?;
    let mut fields = rest.split_whitespace();
    // `rest` starts at field 3 (state); utime is field 14.
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    utime.checked_add(stime)
}
/// VmRSS in KiB from `/proc/<pid>/status`.
pub fn rss_kib(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

#[allow(unsafe_code)]
fn ticks_per_second() -> f64 {
    // SAFETY: sysconf takes a constant and has no memory effects.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

/// One CPU/memory sample window of a process.
pub struct Usage {
    pid: u32,
    proc_root: std::path::PathBuf,
    ticks: u64,
    begun: Instant,
}
impl Usage {
    pub fn start(proc_root: &Path, pid: u32) -> Option<Self> {
        let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
        Some(Self {
            pid,
            proc_root: proc_root.to_owned(),
            ticks: cpu_ticks(&stat)?,
            begun: Instant::now(),
        })
    }
    /// (CPU percent of one core over the window, RSS MiB now).
    pub fn finish(&self) -> Option<(f64, f64)> {
        let dir = self.proc_root.join(self.pid.to_string());
        let ticks = cpu_ticks(&fs::read_to_string(dir.join("stat")).ok()?)?;
        let rss = rss_kib(&fs::read_to_string(dir.join("status")).ok()?)?;
        let used = ticks.checked_sub(self.ticks)? as f64 / ticks_per_second();
        let seconds = self.begun.elapsed().max(Duration::from_millis(1)).as_secs_f64();
        let percent = (used / seconds * 1000.0).round() / 10.0;
        Some((percent, (rss as f64 / 1024.0 * 10.0).round() / 10.0))
    }
}

/// Netfilter conntrack entries in PID 1's (the host's) network namespace,
/// from `/proc/1/net/stat/nf_conntrack` (hex `entries`, same on every CPU
/// row). None when nf_conntrack is not loaded.
pub fn conntrack_entries(proc_root: &Path) -> Option<u64> {
    let text = fs::read_to_string(proc_root.join("1/net/stat/nf_conntrack")).ok()?;
    parse_conntrack(&text)
}
pub fn parse_conntrack(text: &str) -> Option<u64> {
    let row = text.lines().nth(1)?;
    u64::from_str_radix(row.split_whitespace().next()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_status_and_conntrack_parsing() {
        let stat = "4242 (cilium agent) S 1 4242 4242 0 -1 4194560 52360 0 1 0 1500 250 0 0 20 0 30 0 123 0 0";
        assert_eq!(cpu_ticks(stat), Some(1750));
        assert_eq!(cpu_ticks("garbage"), None);
        assert_eq!(rss_kib("Name:\tx\nVmRSS:\t  51200 kB\n"), Some(51200));
        assert_eq!(rss_kib("Name:\tx\n"), None);
        let conntrack = "entries  clashres found     new invalid\n0000002a 00000000 00000000 00000000\n0000002a 00000001 00000000 00000000\n";
        assert_eq!(parse_conntrack(conntrack), Some(42));
        assert_eq!(parse_conntrack("entries\n"), None);
    }

    #[test]
    fn agent_is_found_by_comm() {
        let root = std::env::temp_dir().join(format!("flowsdn-perf-proc-{}", std::process::id()));
        for (pid, comm) in [("1", "systemd"), ("900", "flowsdn-agent"), ("77", "bash"), ("x", "flowsdn-agent")] {
            fs::create_dir_all(root.join(pid)).expect("dir");
            fs::write(root.join(pid).join("comm"), format!("{comm}\n")).expect("comm");
        }
        assert_eq!(
            find_agent(&root),
            Some(Agent {
                pid: 900,
                flavor: "flowsdn"
            })
        );
        fs::write(root.join("900").join("stat"), "900 (flowsdn-agent) S 1 1 1 0 -1 0 0 0 0 0 10 5 0 0 20 0 1 0 1 0 0")
            .expect("stat");
        fs::write(root.join("900").join("status"), "VmRSS:\t2048 kB\n").expect("status");
        let usage = Usage::start(&root, 900).expect("start");
        let (cpu, rss) = usage.finish().expect("finish");
        assert_eq!(cpu, 0.0);
        assert_eq!(rss, 2.0);
        let _ = fs::remove_dir_all(&root);
        assert_eq!(find_agent(&root), None);
    }
}
